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
import dataclasses
import itertools
import logging
import operator
import uuid
from typing import List, NamedTuple, Sequence, Tuple

import gtirb
import gtirb_functions
import mcasm
from gtirb_capstone.instructions import GtirbInstructionDecoder

from .assembler import _Assembler
from .assembly import InsertionContext, Patch
from .isa import _get_isa
from .prepare import prepare_for_rewriting
from .scopes import Scope, _SpecificLocationScope
from .utils import (
    _is_partial_disassembly,
    _modify_block_insert,
    _text_section_name,
    decorate_extern_symbol,
    show_block_asm,
)


class _Insertion(NamedTuple):
    scope: Scope
    patch: Patch


class _FunctionInsertion(NamedTuple):
    symbol: gtirb.Symbol
    block: gtirb.CodeBlock
    patch: Patch


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
        self._symbols_by_name = {s.name: s for s in module.symbols}
        self._functions = functions
        self._decoder = GtirbInstructionDecoder(self._module.isa)
        self._isa = _get_isa(module)
        self._insertions: List[_Insertion] = []
        self._function_insertions: List[_FunctionInsertion] = []
        self._logger = logger
        self._patch_id = 0
        self._expensive_assertions = expensive_assertions
        self._leaf_functions = {
            f.uuid: self._might_be_leaf_function(f) for f in self._functions
        }

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
        self._logger.error("error in %s (#%i): %s", patch, self._patch_id, err)
        for line in lines[: err.lineno]:
            self._logger.error("%s", line)
        # LLVM only stores the start column in its diagnostic object, so we'll
        # highlight the whole rest of the line as the error.
        self._logger.error(
            " " * err.column + "^" + "~" * (len(line) - err.column - 1)
        )
        for line in lines[err.lineno :]:
            self._logger.error("%s", line)

    def _invoke_patch(
        self,
        func: gtirb_functions.Function,
        block: gtirb.CodeBlock,
        offset: int,
        replacement_length: int,
        patch: Patch,
        context: InsertionContext,
    ) -> Tuple[gtirb.CodeBlock, int]:
        """
        Invokes a patch at a concrete location and applies its results to the
        target module.
        :param func: The function to insert at.
        :param block: The block to insert at.
        :param offset: The offset within the block to insert at.
        :param patch: The patch to invoke.
        :param context: The InsertionContext to pass to the patch.
        :returns: A tuple with: the block that ends the patch and the number
                  of bytes inserted.
        """

        available_registers = list(self._isa.all_registers())
        clobbered_registers = set()
        snippets = []
        stack_adjustment = 0

        for clobber in patch.constraints.clobbers_registers:
            reg = self._isa.get_register(clobber)
            available_registers.remove(reg)
            clobbered_registers.add(reg)

        scratch_registers = available_registers[
            : patch.constraints.scratch_registers
        ]
        clobbered_registers.update(scratch_registers)

        if patch.constraints.preserve_caller_saved_registers:
            clobbered_registers.update(self._isa.caller_saved_registers())

        # TODO: If align_stack was set too, we're going to end up doing
        #       some redundant work.
        if clobbered_registers or patch.constraints.clobbers_flags:
            if self._isa.red_zone_size() and self._leaf_functions[func.uuid]:
                stack_adjustment += self._isa.red_zone_size()
                snippets.append(self._isa.preserve_red_zone())

        if patch.constraints.clobbers_flags:
            stack_adjustment += self._isa.pointer_size()
            snippets.append(self._isa.save_flags())

        for reg in sorted(clobbered_registers, key=lambda reg: reg.name):
            stack_adjustment += self._isa.pointer_size()
            snippets.append(self._isa.save_register(reg))

        if patch.constraints.align_stack:
            # TODO: We don't know how much the stack may be adjusted by the
            #       snippet.
            stack_adjustment = None
            snippets.append(self._isa.align_stack())

        asm = patch.get_asm(
            dataclasses.replace(context, stack_adjustment=stack_adjustment),
            *scratch_registers,
        )
        if not asm:
            return block, 0

        self._patch_id += 1

        assembler = _Assembler(
            self._module, self._patch_id, self._symbols_by_name
        )
        for snippet in snippets:
            assembler.assemble(snippet[0].code, snippet[0].x86_syntax)
        try:
            assembler.assemble(asm, patch.constraints.x86_syntax)
        except mcasm.assembler.AsmSyntaxError as err:
            self._log_patch_error(asm, patch, self._patch_id, err)
            raise
        for snippet in reversed(snippets):
            assembler.assemble(snippet[1].code, snippet[1].x86_syntax)
        assembler.finalize()

        if self._logger.isEnabledFor(logging.DEBUG):
            self._logger.debug("Applying %s at %s+%s", patch, block, offset)
            self._logger.debug("  Before:")
            show_block_asm(block, decoder=self._decoder, logger=self._logger)

        _modify_block_insert(
            block,
            offset,
            replacement_length,
            bytes(assembler.data),
            assembler.blocks,
            assembler.cfg,
            assembler.symbolic_expressions,
            assembler.local_symbols.values(),
            assembler.proxies,
            self._functions_by_block,
        )

        if "functionBlocks" in self._module.aux_data:
            function_blocks = self._module.aux_data["functionBlocks"].data
            if func.uuid in function_blocks:
                function_blocks[func.uuid].update(
                    b for b in assembler.blocks if b.module == self._module
                )

        self._functions_by_block.update(
            {
                b: func.uuid
                for b in assembler.blocks
                if b.module == self._module
            }
        )

        if self._logger.isEnabledFor(logging.DEBUG):
            self._logger.debug("  After:")
            show_block_asm(block, decoder=self._decoder, logger=self._logger)
            for patch_block in assembler.blocks:
                show_block_asm(
                    patch_block, decoder=self._decoder, logger=self._logger
                )

        return (
            assembler.blocks[-1] if assembler.blocks else block,
            len(assembler.data),
        )

    def get_or_insert_extern_symbol(
        self, name: str, libname: str, preload: bool = False
    ) -> gtirb.Symbol:
        """
        Gets a symbol by name, creating it as an extern symbol if it isn't
        already in the module.
        :param name: The name of the symbol.
        :param libname: The name of the shared library the symbol is from.
        :param preload: Insert the library dependency at the beginning of the
                        libraries aux data table, similar to LD_PRELOAD. ELF
                        only, optional.
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

        if self._module.file_format == gtirb.Module.FileFormat.PE:
            # The pprinter uses symbol forwarding to figure out
            # how to pprint imported symbols.  The fact that it has an entry in
            # the symbolForwarding table will trigger this.  Typically I think
            # the local symbol (pre-forwarding) is something generated by
            # ddisasm, with the proper import name being in the forwarding
            # table.  Here, for a new symbol, having it forward to itself is
            # what we actually want.
            self._module.aux_data["symbolForwarding"].data[sym] = sym
            # May not be neccessary, but should be done for IR consistency
            self._module.aux_data["peImportedSymbols"].data.append(sym)
            if "peImportEntries" in self._module.aux_data:
                self._module.aux_data["peImportEntries"].data.append(
                    (0, -1, name, libname)
                )

        if "libraries" in self._module.aux_data:
            if preload:
                self._module.aux_data["libraries"].data.insert(0, libname)
            else:
                self._module.aux_data["libraries"].data.append(libname)

        return sym

    def _apply_insertions(
        self,
        insertions: Sequence[_Insertion],
        func: gtirb_functions.Function,
        block: gtirb.CodeBlock,
    ) -> None:
        """
        Applies all of the patches that apply to a single block.
        """

        instructions = None
        if any(
            insertion.scope._needs_disassembly() for insertion in insertions
        ):
            instructions = tuple(self._decoder.get_instructions(block))

        # Determine the insertion location for each patch.
        # TODO: This is where bubbling will get hooked in, but for now
        #       always insert at the first potential offset.
        insertions_and_offsets = []
        for insertion in insertions:
            offset = next(
                insertion.scope._potential_offsets(func, block, instructions)
            )
            insertions_and_offsets.append((insertion, offset))

        # Now sort all of the insertions by their offsets. Python uses a
        # stable sort so that this will still be deterministic for ties.
        insertions_and_offsets.sort(key=operator.itemgetter(1))

        # Assert that we don't have any replacements and insertions that
        # overlap.
        last_end = 0
        for insertion, offset in insertions_and_offsets:
            assert offset >= last_end, "Insertions and replacements overlap"
            last_end = offset + insertion.scope._replacement_length()

        actual_block = block
        total_insert_len = 0
        for insertion, offset in insertions_and_offsets:
            block_delta = actual_block.offset - block.offset
            actual_block, insert_len = self._invoke_patch(
                func,
                actual_block,
                offset + total_insert_len - block_delta,
                insertion.scope._replacement_length(),
                insertion.patch,
                InsertionContext(self._module, func, block, offset),
            )
            total_insert_len += (
                insert_len - insertion.scope._replacement_length()
            )

    def _insert_function_stub(
        self, sym: gtirb.Symbol, block: gtirb.CodeBlock
    ) -> None:
        """
        Inserts a stub that just contains a return instruction and
        corresponding return edge.
        """
        assert sym.referent == block
        assert block.size == 0

        func_uuid = uuid.uuid4()

        # Our code block needs something in it for now, along with a return
        # edge for callers to update. The actual instruction in the block
        # doesn't matter, so we'll use a nop.
        nop_encoding = self._isa.nop()
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
        if "elfSymbolInfo" in self._module.aux_data:
            self._module.aux_data["elfSymbolInfo"].data[sym] = (
                0,
                "FUNC",
                "GLOBAL",
                "DEFAULT",
                0,
            )

        if "functionEntries" in self._module.aux_data:
            self._module.aux_data["functionEntries"].data[func_uuid] = {block}

        if "functionBlocks" in self._module.aux_data:
            self._module.aux_data["functionBlocks"].data[func_uuid] = {block}

        if "functionNames" in self._module.aux_data:
            self._module.aux_data["functionNames"].data[func_uuid] = sym

        self._functions_by_block[block] = func_uuid

    def _apply_function_insertion(
        self, sym: gtirb.Symbol, block: gtirb.CodeBlock, patch: Patch
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
            self._functions_by_block[block], {block}, {block}, {sym}, set()
        )
        context = InsertionContext(self._module, func, block, 0)

        self._invoke_patch(func, block, 0, block.size, patch, context)

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
        self._insertions.append(_Insertion(scope, patch))

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
        self._symbols_by_name[sym.name] = sym
        self._function_insertions.append(_FunctionInsertion(sym, block, patch))
        return sym

    def insert_at(
        self,
        function: gtirb_functions.Function,
        block: gtirb.CodeBlock,
        offset: int,
        patch: Patch,
    ) -> None:
        """
        Inserts a patch at a specific location in the binary. This is not
        subject to bubbling.
        """
        self._validate_offset_and_length(block, offset, 0)
        self.register_insert(
            _SpecificLocationScope(function, block, offset), patch
        )

    def replace_at(
        self,
        function: gtirb_functions.Function,
        block: gtirb.CodeBlock,
        offset: int,
        length: int,
        patch: Patch,
    ) -> None:
        """
        Inserts a patch at a specific location in the binary, replacing the
        instructions as specified. This is not subject to bubbling.
        """
        self._validate_offset_and_length(block, offset, length)
        self.register_insert(
            _SpecificLocationScope(function, block, offset, length), patch
        )

    def apply(self) -> None:
        """
        Applies all of the patches to the module.
        """

        with prepare_for_rewriting(self._module, self._isa.nop()):
            self._functions_by_block = {
                block: func.uuid
                for func in self._functions
                for block in func.get_all_blocks()
            }

            for func in self._function_insertions:
                self._insert_function_stub(func.symbol, func.block)

            for func in self._function_insertions:
                self._apply_function_insertion(
                    func.symbol, func.block, func.patch
                )

            for f in self._functions:
                func_insertions = [
                    insertion
                    for insertion in self._insertions
                    if insertion.scope._function_matches(self._module, f)
                ]
                if not func_insertions:
                    continue

                # Iterate over initial function blocks; ignore added blocks
                # from patches.
                for b in tuple(f.get_all_blocks()):
                    block_insertions = [
                        insertion
                        for insertion in func_insertions
                        if insertion.scope._block_matches(self._module, f, b)
                    ]
                    if not block_insertions:
                        continue

                    self._apply_insertions(block_insertions, f, b)

        # Remove CFI directives, since we will most likely be invalidating
        # most (or all) of them.
        # TODO: can we not do this?
        if "cfiDirectives" in self._module.aux_data:
            del self._module.aux_data["cfiDirectives"]
