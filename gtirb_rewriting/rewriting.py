# GTIRB-Rewriting Rewriting API for GTIRB
# Copyright (C) 2021 GrammaTech, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# This project is sponsored by the Office of Naval Research, One Liberty
# Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
# N68335-17-C-0700.  The content of the information does not necessarily
# reflect the position or policy of the Government and no official
# endorsement should be inferred.
import contextlib
import dataclasses
import itertools
import logging
import pathlib
import uuid
import warnings
from collections import defaultdict
from typing import (
    Dict,
    Iterable,
    Iterator,
    List,
    NamedTuple,
    Optional,
    Sequence,
    Tuple,
    Union,
    overload,
)

import gtirb
import gtirb_functions
import gtirb_rewriting._auxdata as _auxdata
import mcasm
from gtirb_capstone.instructions import GtirbInstructionDecoder

from .abi import ABI
from .assembler import Assembler
from .modify import (
    _delete_code,
    _make_return_cache,
    _modify_block_insert,
    _ModifyCache,
)
from .patch import InsertionContext, Patch
from .prepare import prepare_for_rewriting
from .scopes import Scope, _SpecificLocationScope
from .utils import (
    _block_fallthrough_targets,
    _is_partial_disassembly,
    _text_section_name,
    decorate_extern_symbol,
    show_block_asm,
)


class UnresolvableScopeError(ValueError):
    """
    The scope passed to register_insert cannot be resolved or is invalid.
    """

    pass


@dataclasses.dataclass
class _Modification:
    id: int
    scope: Scope


@dataclasses.dataclass
class _InsertionOrReplacement(_Modification):
    patch: Patch


@dataclasses.dataclass
class _Deletion(_Modification):
    retarget_to_proxy: bool


class _FunctionInsertion(NamedTuple):
    symbol: gtirb.Symbol
    block: gtirb.CodeBlock
    patch: Patch


class _ModificationStore:
    """
    Maintains the list of modifications and resolves them to concrete offsets
    when applying them.
    """

    def __init__(self):
        self._scope_changes: List[_Modification] = []
        self._block_changes: Dict[
            gtirb.ByteBlock, List[_Modification]
        ] = defaultdict(list)

    def add(self, modification: _Modification) -> None:
        """
        Registers a modification.
        """

        known_targets = modification.scope._known_targets()
        if known_targets is not None:
            for target in known_targets:
                self._block_changes[target].append(modification)
        else:
            self._scope_changes.append(modification)

    def modifications_for_block(
        self,
        module: gtirb.Module,
        block: gtirb.CodeBlock,
        func: Optional[gtirb_functions.Function],
    ) -> List[_Modification]:
        """
        Finds all modifications that apply to a given block.
        """

        results = []

        if block in self._block_changes:
            results.extend(self._block_changes[block])

        for scope_change in self._scope_changes:
            if scope_change.scope._block_matches(module, func, block):
                results.append(scope_change)

        return results

    def resolve_offsets(
        self,
        block: gtirb.CodeBlock,
        decoder: GtirbInstructionDecoder,
        modifications: Iterable[_Modification],
    ) -> List[Tuple[_Modification, int]]:
        """
        Determines the concrete offsets into the block that each modification
        should be applied. The returned list will be in the order that the
        patches should be applied.
        """

        instructions = None
        if any(
            modification.scope._needs_disassembly()
            for modification in modifications
        ):
            instructions = tuple(decoder.get_instructions(block))

        # Determine the insertion location for each patch.
        # TODO: This is where bubbling will get hooked in, but for now
        #       always insert at the first potential offset.
        modifications_and_offsets: List[Tuple[_Modification, int]] = []
        for modification in modifications:
            offset = next(
                modification.scope._potential_offsets(block, instructions)
            )
            modifications_and_offsets.append((modification, offset))

        # Now sort all of the insertions by their offsets and then IDs. This
        # ensures modifications at the same offset are performed in the order
        # they were registered.
        modifications_and_offsets.sort(
            key=lambda mod_and_off: (mod_and_off[1], mod_and_off[0].id)
        )

        # Assert that we don't have any modifications that conflict.
        last_end = 0
        for modification, offset in modifications_and_offsets:
            assert offset >= last_end, "modifications overlap"
            last_end = offset + modification.scope._replacement_length()

        return modifications_and_offsets


class RewritingContext:
    """
    A rewriting context manages insertions and modifications on a single
    module. It takes care of resolving insertion scopes to concrete positions,
    potentially trying to bubble multiple insertions together for performance.
    """

    def __init__(
        self,
        module: gtirb.Module,
        functions: Sequence[gtirb_functions.Function],
        logger=logging.getLogger("gtirb_rewriting"),
        expensive_assertions=True,
    ):
        """
        :param module: The module to rewrite.
        :param functions: The list of functions in the module.
        :param logger: The logger to log to when rewriting.
        :param expensive_assertions: If enabled, extra assertions will be
        enabled that may have noticable run-time overhead.
        """
        self._module = module
        self._functions = functions
        self._decoder = GtirbInstructionDecoder(self._module.isa)
        self._abi = ABI.get(module)
        self._modifications = _ModificationStore()
        self._modification_id = itertools.count()
        self._function_insertions: List[_FunctionInsertion] = []
        self._logger = logger
        self._patch_id = 0
        self._expensive_assertions = expensive_assertions
        self._leaf_functions = self._update_leaf_functions()

    def _might_be_leaf_function(self, func: gtirb_functions.Function) -> bool:
        """
        Determines if a function might be a leaf function by the absence of
        calls in the CFG. This should only be used _before_ applying rewrites
        because the status may change if a patch inserts a call.
        """
        return all(
            not edge.label or edge.label.type != gtirb.Edge.Type.Call
            for block in func.get_all_blocks()
            for edge in block.outgoing_edges
        )

    def _update_leaf_functions(self) -> Dict[uuid.UUID, int]:
        """
        Updates the leafFunctions aux data table, creating it if needed, in
        order to track leaf functions across multiple rewritings (which may
        add new calls to the functions).
        """

        # GTIRB doesn't have a "bool" aux data type, so we'll use uint8 and
        # only store 0/1.
        leaf_functions = _auxdata.leaf_functions.get_or_insert(self._module)
        for func in self._functions:
            if func.uuid not in leaf_functions:
                leaf_functions[func.uuid] = int(
                    self._might_be_leaf_function(func)
                )

        return leaf_functions

    def _log_patch_error(
        self,
        asm: str,
        patch: Patch,
        patch_id: int,
        err: mcasm.assembler.AsmSyntaxError,
    ) -> None:
        """
        Logs an assembly syntax error to our logger.
        """
        lines = asm.splitlines()
        self._logger.error("error in %s (#%i): %s", patch, patch_id, err)
        for line in lines[: err.lineno]:
            self._logger.error("%s", line)
        # LLVM only stores the start column in its diagnostic object.
        self._logger.error(" " * err.column + "^")
        for line in lines[err.lineno :]:
            self._logger.error("%s", line)

    @contextlib.contextmanager
    def _log_patch_changes(
        self, patch: Patch, block: gtirb.CodeBlock, offset: int
    ) -> Iterator[None]:
        """
        Log before/after state when applying a patch.
        """

        if self._logger.isEnabledFor(logging.DEBUG):
            self._logger.debug("Applying %s at %s+%s", patch, block, offset)
            self._logger.debug("  Before:")
            show_block_asm(block, decoder=self._decoder, logger=self._logger)

            bi = block.byte_interval
            assert bi

            before_blocks = set(bi.blocks)

            yield

            new_blocks = set(bi.blocks) - before_blocks
            log_blocks = sorted(
                itertools.chain((block,), new_blocks), key=lambda b: b.offset
            )

            self._logger.debug("  After:")
            for log_block in log_blocks:
                show_block_asm(
                    log_block, decoder=self._decoder, logger=self._logger
                )

        else:
            yield

    def _invoke_patch(
        self,
        modify_cache: _ModifyCache,
        func: Optional[gtirb_functions.Function],
        block: gtirb.CodeBlock,
        offset: int,
        replacement_length: int,
        patch: Patch,
        context: InsertionContext,
    ) -> Tuple[gtirb.CodeBlock, int]:
        """
        Invokes a patch at a concrete location and applies its results to the
        target module.
        :param modify_cache: The modify cache, which should be reused across
                             multiple modifications.
        :param func: The function to insert at.
        :param block: The block to insert at.
        :param offset: The offset within the block to insert at.
        :param patch: The patch to invoke.
        :param context: The InsertionContext to pass to the patch.
        :returns: A tuple with: the block that ends the patch and the number
                  of bytes inserted.
        """

        # Assume that any block not in a function could be a leaf function
        is_leaf = not func or bool(self._leaf_functions.get(func.uuid, 1))

        registers = self._abi._allocate_patch_registers(patch.constraints)
        (
            prologue,
            epilogue,
            stack_adjustment,
        ) = self._abi._create_prologue_and_epilogue(
            patch.constraints,
            registers,
            is_leaf,
        )

        asm = patch.get_asm(
            dataclasses.replace(context, stack_adjustment=stack_adjustment),
            *registers.scratch_registers,
        )
        if not asm:
            return block, 0

        self._patch_id += 1

        is_trivially_unreachable = False
        if offset == block.size:
            is_trivially_unreachable = not any(
                _block_fallthrough_targets(block)
            )

        assembler = Assembler(
            self._module,
            temp_symbol_suffix=f"_{self._patch_id}",
            module_symbols=self._symbols_by_name,
            trivially_unreachable=is_trivially_unreachable,
        )
        for snippet in prologue:
            assembler.assemble(snippet.code, snippet.x86_syntax)
        try:
            assembler.assemble(asm, patch.constraints.x86_syntax)
        except mcasm.assembler.AsmSyntaxError as err:
            self._log_patch_error(asm, patch, self._patch_id, err)
            raise
        for snippet in epilogue:
            assembler.assemble(snippet.code, snippet.x86_syntax)
        assembler_result = assembler.finalize()

        with self._log_patch_changes(patch, block, offset):
            new_end = _modify_block_insert(
                modify_cache,
                block,
                offset,
                replacement_length,
                assembler_result,
            )

        self._symbols_by_name.update(
            {sym.name: sym for sym in assembler_result.symbols}
        )

        return (
            new_end,
            len(assembler_result.text_section.data),
        )

    def get_or_insert_extern_symbol(
        self,
        name: str,
        libname: str,
        preload: bool = False,
        libpath: Union[str, pathlib.Path, None] = None,
    ) -> gtirb.Symbol:
        """
        Gets a symbol by name, creating it as an extern symbol if it isn't
        already in the module.
        :param name: The name of the symbol.
        :param libname: The name of the shared library the symbol is from.
        :param preload: Insert the library dependency at the beginning of the
                        libraries aux data table, similar to LD_PRELOAD. ELF
                        only, optional.
        :param libpath: Additional path to search for libname at runtime.
        """
        name = decorate_extern_symbol(self._module, name)

        sym = next(
            (sym for sym in self._module.symbols if sym.name == name), None
        )
        if sym:
            return sym

        proxy = gtirb.ProxyBlock()
        sym = gtirb.Symbol(name, payload=proxy)
        self._module.symbols.add(sym)
        self._module.proxies.add(proxy)

        if self._module.file_format == gtirb.Module.FileFormat.PE:
            # The pprinter uses symbol forwarding to figure out
            # how to pprint imported symbols.  The fact that it has an entry in
            # the symbolForwarding table will trigger this.  Typically I think
            # the local symbol (pre-forwarding) is something generated by
            # ddisasm, with the proper import name being in the forwarding
            # table.  Here, for a new symbol, having it forward to itself is
            # what we actually want.
            _auxdata.symbol_forwarding.get_or_insert(self._module)[sym] = sym
            # May not be neccessary, but should be done for IR consistency
            _auxdata.pe_imported_symbols.get_or_insert(self._module).append(
                sym
            )
            _auxdata.pe_import_entries.get_or_insert(self._module).append(
                (0, -1, name, libname)
            )
        elif self._module.file_format == gtirb.Module.FileFormat.ELF:
            # This is required for gtirb-pprinter's dummy-so option to
            # understand this is an undefined function.
            symbol_info = _auxdata.elf_symbol_info.get_or_insert(self._module)
            symbol_info[sym] = (
                0,
                "FUNC",
                "GLOBAL",
                "DEFAULT",
                0,
            )

        libraries = _auxdata.libraries.get_or_insert(self._module)
        if preload:
            libraries.insert(0, libname)
        else:
            libraries.append(libname)

        if libpath is not None:
            library_paths = _auxdata.library_paths.get_or_insert(self._module)
            if preload:
                library_paths.insert(0, str(libpath))
            else:
                library_paths.append(str(libpath))

        return sym

    def _apply_modifications(
        self,
        modify_cache: _ModifyCache,
        modifications: Sequence[_Modification],
        func: Optional[gtirb_functions.Function],
        block: gtirb.CodeBlock,
    ) -> None:
        """
        Applies all of the patches that apply to a single block.
        """

        actual_block = block
        total_insert_len = 0
        for modification, offset in self._modifications.resolve_offsets(
            block, self._decoder, modifications
        ):
            assert isinstance(actual_block, gtirb.CodeBlock)

            block_delta = actual_block.offset - block.offset
            if isinstance(modification, _InsertionOrReplacement):
                actual_block, insert_len = self._invoke_patch(
                    modify_cache,
                    func,
                    actual_block,
                    offset + total_insert_len - block_delta,
                    modification.scope._replacement_length(),
                    modification.patch,
                    InsertionContext(self._module, func, block, offset),
                )
                total_insert_len += (
                    insert_len - modification.scope._replacement_length()
                )
            elif isinstance(modification, _Deletion):
                if not modification.retarget_to_proxy:
                    successors = modify_cache.original_successors.get(block)
                    if successors:
                        if len(successors) > 1:
                            self._logger.warning(
                                "successor to %s is ambiguous", block
                            )
                        next_block = successors[0]
                    else:
                        next_block = None
                else:
                    next_block = gtirb.ProxyBlock()
                    self._module.proxies.add(next_block)

                actual_block = _delete_code(
                    modify_cache,
                    actual_block,
                    offset + total_insert_len - block_delta,
                    modification.scope._replacement_length(),
                    next_block,
                )
                total_insert_len -= modification.scope._replacement_length()

    def _insert_function_stub(
        self,
        modify_cache: _ModifyCache,
        sym: gtirb.Symbol,
        block: gtirb.CodeBlock,
    ) -> None:
        """
        Inserts a stub that just contains a return instruction and
        corresponding return edge.
        """
        assert sym.referent == block
        assert block.size == 0
        assert self._module.ir

        func_uuid = uuid.uuid4()

        # Our code block needs something in it for now, along with a return
        # edge for callers to update. The actual instruction in the block
        # doesn't matter, so we'll use a nop.
        nop_encoding = self._abi.nop()
        block.size = len(nop_encoding)

        bi = gtirb.ByteInterval(contents=nop_encoding, blocks=[block])
        sect = next(
            sect
            for sect in self._module.sections
            if sect.name == _text_section_name(self._module)
        )
        sect.byte_intervals.add(bi)

        return_proxy = gtirb.ProxyBlock()
        self._module.proxies.add(return_proxy)

        self._module.ir.cfg.add(
            gtirb.Edge(
                source=block,
                target=return_proxy,
                label=gtirb.Edge.Label(type=gtirb.Edge.Type.Return),
            )
        )

        # TODO: Should there be a mechanism for configuring this?
        if self._module.file_format == gtirb.Module.FileFormat.ELF:
            symbol_info = _auxdata.elf_symbol_info.get_or_insert(self._module)
            symbol_info[sym] = (
                0,
                "FUNC",
                "GLOBAL",
                "DEFAULT",
                0,
            )

        function_entries = _auxdata.function_entries.get_or_insert(
            self._module
        )
        function_entries[func_uuid] = {block}

        function_blocks = _auxdata.function_blocks.get_or_insert(self._module)
        function_blocks[func_uuid] = {block}

        function_names = _auxdata.function_names.get_or_insert(self._module)
        function_names[func_uuid] = sym

        modify_cache.functions_by_block[block] = func_uuid

    def _apply_function_insertion(
        self,
        modify_cache: _ModifyCache,
        sym: gtirb.Symbol,
        block: gtirb.CodeBlock,
        patch: Patch,
    ) -> None:
        assert sym.referent == block
        assert (
            not patch.constraints.clobbers_registers
        ), "function patches should not set clobbers_registers"
        assert (
            not patch.constraints.scratch_registers
        ), "function patches should not set scratch_registers"
        assert (
            not patch.constraints.preserve_caller_saved_registers
        ), "function patches should not set preserve_caller_saved_registers"
        assert (
            not patch.constraints.clobbers_flags
        ), "function patches should not set clobbers_flags"
        assert (
            not patch.constraints.align_stack
        ), "function patches should not set align_stack"

        func = gtirb_functions.Function(
            modify_cache.functions_by_block[block],
            {block},
            {block},
            {sym},
            set(),
        )
        context = InsertionContext(self._module, func, block, 0)

        self._invoke_patch(
            modify_cache, func, block, 0, block.size, patch, context
        )

    def _validate_offset_and_length(
        self, block: gtirb.CodeBlock, offset: int, length: int
    ) -> None:
        """
        Validate that an offset and length fall within a code block and, if
        expensive assertions are enabled, verify that they fall on instruction
        boundaries.
        """
        assert 0 <= offset <= block.size
        assert length >= 0
        assert offset + length <= block.size

        if self._expensive_assertions:
            disassembly = tuple(self._decoder.get_instructions(block))
            if not _is_partial_disassembly(block, disassembly):
                legal_offsets = {
                    0,
                    *itertools.accumulate(inst.size for inst in disassembly),
                }
                assert (
                    offset in legal_offsets
                ), f"offset {offset} is not an instruction boundary"
                assert (
                    offset + length in legal_offsets
                ), f"offset {offset}+{length} is not an instruction boundary"

    def register_insert(self, scope: Scope, patch: Patch) -> None:
        """
        Registers a patch to be inserted.
        :param scope: Where should the patch be placed?
        :param patch: The patch to be inserted.
        """

        if not self._functions and scope._needs_functions():
            raise UnresolvableScopeError(
                "this scope requires function information, which the target "
                "module lacks"
            )

        self._modifications.add(
            _InsertionOrReplacement(next(self._modification_id), scope, patch)
        )

    def register_insert_function(
        self, name: str, patch: Patch
    ) -> gtirb.Symbol:
        """
        Registers a patch to be inserted as a function.
        :param name: The name of the function to be inserted.
        :param patch: The patch to be inserted.
        :returns: The new function symbol.
        """
        block = gtirb.CodeBlock()
        # TODO: This assumes the symbol isn't present already in the module,
        #       which may be a problem if you have an existing external
        #       symbol that you want to provide a definition for.
        sym = gtirb.Symbol(name, payload=block)
        sym.referent = block
        # TODO: Should we be adding the symbol here?
        self._module.symbols.add(sym)
        self._function_insertions.append(_FunctionInsertion(sym, block, patch))
        return sym

    @overload
    def insert_at(
        self,
        block: gtirb.CodeBlock,
        offset: int,
        patch: Patch,
    ) -> None:
        """
        Inserts a patch at a specific location in the binary. This is not
        subject to bubbling.
        """
        ...

    @overload
    def insert_at(
        self,
        function: gtirb_functions.Function,
        block: gtirb.CodeBlock,
        offset: int,
        patch: Patch,
    ) -> None:
        "Deprecated variant of insert_at that takes a function."
        ...

    def insert_at(self, *args, **kwargs) -> None:
        def unpack_new(
            block: gtirb.CodeBlock,
            offset: int,
            patch: Patch,
        ):
            return block, offset, patch

        def unpack_old(
            function: gtirb_functions.Function,
            block: gtirb.CodeBlock,
            offset: int,
            patch: Patch,
        ):
            warnings.warn(
                "passing a function to insert_at is deprecated",
                DeprecationWarning,
                stacklevel=3,
            )
            return block, offset, patch

        try:
            block, offset, patch = unpack_new(*args, **kwargs)
        except TypeError:
            block, offset, patch = unpack_old(*args, **kwargs)

        self._validate_offset_and_length(block, offset, 0)
        self.register_insert(_SpecificLocationScope(block, offset), patch)

    @overload
    def replace_at(
        self,
        block: gtirb.CodeBlock,
        offset: int,
        length: int,
        patch: Patch,
    ) -> None:
        """
        Inserts a patch at a specific code block in the binary, replacing the
        instructions as specified. This is not subject to bubbling.
        """
        ...

    @overload
    def replace_at(
        self,
        function: gtirb_functions.Function,
        block: gtirb.CodeBlock,
        offset: int,
        length: int,
        patch: Patch,
    ) -> None:
        """
        Deprecated variant of replace_at that takes a function.
        """
        ...

    def replace_at(
        self,
        *args,
        **kwargs,
    ) -> None:
        def unpack_new(
            block: gtirb.CodeBlock,
            offset: int,
            length: int,
            patch: Patch,
        ):
            return block, offset, length, patch

        def unpack_old(
            function: gtirb_functions.Function,
            block: gtirb.CodeBlock,
            offset: int,
            length: int,
            patch: Patch,
        ):
            warnings.warn(
                "passing a function to replace_at is deprecated",
                DeprecationWarning,
                stacklevel=3,
            )
            return block, offset, length, patch

        try:
            block, offset, length, patch = unpack_new(*args, **kwargs)
        except TypeError:
            block, offset, length, patch = unpack_old(*args, **kwargs)

        self._validate_offset_and_length(block, offset, length)
        self._modifications.add(
            _InsertionOrReplacement(
                next(self._modification_id),
                _SpecificLocationScope(block, offset, length),
                patch,
            )
        )

    def delete_function(
        self,
        function: gtirb_functions.Function,
    ):
        """
        Deletes an entire function, replacing references to its blocks with
        references to proxy blocks.
        """

        for block in function.get_all_blocks():
            self.delete_at(block, 0, block.size, retarget_to_proxy=True)

    def delete_at(
        self,
        block: gtirb.CodeBlock,
        offset: int,
        length: int,
        *,
        retarget_to_proxy: bool = False,
    ):
        """
        Deletes part or all of a block. If deleting a whole block, labels and
        control flow referring to the deleted block will be changed to refer
        to the 'next' block.

        The next block is calculated from a combination of the CFG and block
        addresses. If the block has an outgoing fallthrough edge, the edge's
        target is used. Otherwise the code block with the next address after
        the end of this block is used. If no block can be found, an exception
        is raised.

        Alternatively, specifying retarget_to_proxy when deleting a whole
        block will make the 'next' block just be a proxy block. Specifying
        retarget_to_proxy in other situations will raise a ValueError.
        """

        self._validate_offset_and_length(block, offset, length)
        if retarget_to_proxy and (offset != 0 or length != block.size):
            raise ValueError(
                "retarget_to_proxy can only be specified when deleting a "
                "whole block"
            )

        self._modifications.add(
            _Deletion(
                next(self._modification_id),
                _SpecificLocationScope(block, offset, length),
                retarget_to_proxy=retarget_to_proxy,
            )
        )

    def apply(self) -> None:
        """
        Applies all of the patches to the module.
        """

        assert self._module.ir

        with prepare_for_rewriting(
            self._module, self._abi.nop()
        ), _make_return_cache(self._module.ir) as return_cache:
            self._symbols_by_name = {s.name: s for s in self._module.symbols}
            modify_cache = _ModifyCache(
                self._module, self._functions, return_cache
            )

            functions_by_uuid = {func.uuid: func for func in self._functions}
            sorted_blocks = sorted(
                self._module.code_blocks, key=lambda b: b.address or 0
            )

            for func in self._function_insertions:
                self._insert_function_stub(
                    modify_cache, func.symbol, func.block
                )

            for func in self._function_insertions:
                self._apply_function_insertion(
                    modify_cache, func.symbol, func.block, func.patch
                )

            for block in sorted_blocks:
                func = None
                func_uuid = modify_cache.functions_by_block.get(block)
                if func_uuid:
                    func = functions_by_uuid.get(func_uuid)

                modifications = self._modifications.modifications_for_block(
                    self._module, block, func
                )
                if not modifications:
                    continue

                self._apply_modifications(
                    modify_cache, modifications, func, block
                )

        # Remove CFI directives, since we will most likely be invalidating
        # most (or all) of them.
        # TODO: can we not do this?
        _auxdata.cfi_directives.remove(self._module)
