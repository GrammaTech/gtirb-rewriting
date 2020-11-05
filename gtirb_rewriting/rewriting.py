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
import logging
from typing import (
    Dict,
    Iterator,
    List,
    Mapping,
    MutableMapping,
    NamedTuple,
    Sequence,
    Tuple,
)

import gtirb
import gtirb_functions
import mcasm
from gtirb_capstone.instructions import GtirbInstructionDecoder

from .assembly import InsertionContext, Patch, X86Syntax, _AsmSnippet
from .isa import _get_isa
from .scopes import Scope, _SpecificLocationScope
from .utils import (
    OffsetMapping,
    _modify_block_insert,
    _target_triple,
    align_address,
    decorate_extern_symbol,
    effective_alignment,
    show_block_asm,
)


class _Insertion(NamedTuple):
    scope: Scope
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
        logger=logging.Logger("null"),
    ):
        self._module = module
        self._symbols_by_name = {s.name: s for s in module.symbols}
        self._functions = functions
        self._isa = _get_isa(module.isa)
        self._insertions: List[_Insertion] = []
        self._logger = logger

    def _invoke_patch(self, context: InsertionContext, patch: Patch) -> None:
        """
        Invokes a patch at a concrete location and applies its results to the
        target module.
        """
        scratch_registers = self._isa.all_registers()[
            : patch.constraints.scratch_registers
        ]
        asm = patch.get_asm(context, *scratch_registers)
        if not asm:
            return

        snippets = []

        if patch.constraints.clobbers_flags:
            snippets.append(self._isa.save_flags())

        for reg in scratch_registers:
            snippets.append(self._isa.save_register(reg))

        if patch.constraints.align_stack:
            snippets.append(self._isa.align_stack())

        # Transform all the prefixes/suffixes into a flat list of assembly
        flat_snippets: List[_AsmSnippet] = []
        flat_snippets.extend(snippet[0] for snippet in snippets)
        flat_snippets.append(_AsmSnippet(asm, patch.constraints.x86_syntax))
        flat_snippets.extend(snippet[1] for snippet in snippets[::-1])

        chunks = [
            self._assemble(context.module, snippet.code, snippet.x86_syntax)
            for snippet in flat_snippets
        ]
        chunks_encoded = b"".join(chunk[0] for chunk in chunks)

        if self._logger.isEnabledFor(logging.DEBUG):
            self._logger.debug(
                "Applying %s at %s+%s", patch, context.block, context.offset
            )
            self._logger.debug("  Before:")
            show_block_asm(context.block, logger=self._logger)

        _modify_block_insert(
            context.block, chunks_encoded, context.offset,
        )

        start = context.block.offset + context.offset
        for encoding, fixups in chunks:
            for rel_offset, sym in fixups.items():
                offset = start + rel_offset
                assert context.block.byte_interval
                assert (
                    offset
                    not in context.block.byte_interval.symbolic_expressions
                )
                context.block.byte_interval.symbolic_expressions[offset] = sym
            start += len(encoding)

        if self._logger.isEnabledFor(logging.DEBUG):
            self._logger.debug("  After:")
            show_block_asm(context.block, logger=self._logger)

    def get_or_insert_extern_symbol(
        self, name: str, libname: str
    ) -> gtirb.Symbol:
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
            # TODO: This feels gross. but it does get gtirb-pprint to print the
            # extern symbol.
            dummy_symbol = gtirb.Symbol("")
            self._module.aux_data["symbolForwarding"].data[dummy_symbol] = sym
            # TODO: Check if this is necessary once we're able to link programs
            # module.aux_data['peImportedSymbols'].data.append(sym)
        elif self._module.file_format == gtirb.Module.FileFormat.ELF:
            self._module.aux_data["libraries"].data.append(libname)

        return sym

    def _fixup_to_symbolic_operand(
        self, module: gtirb.Module, fixup: dict, encoding: bytes
    ) -> gtirb.SymAddrConst:
        """
        Converts an LLVM fixup to a GTIRB SymbolicExpression.
        """
        expr = fixup["value"]

        # LLVM will automatically add a negative value to make the expression
        # be PC-relative. We don't care about that and just want to unwrap it.
        if (
            "IsPCRel" in fixup["flags"]
            and expr["kind"] == "binaryExpr"
            and expr["opcode"] == "Add"
            and expr["rhs"]["kind"] == "constant"
            and fixup["offset"] - expr["rhs"]["value"] == len(encoding)
        ):
            expr = expr["lhs"]

        # TODO: Do we need to support more fixup types? GTIRB only supports
        #       two forms:
        #       - Sym + Offset
        #       - (Sym1 - Sym2) / Scale + Offset
        assert (
            expr["kind"] == "symbolRef"
        ), "Only simple simple references are currently supported"

        name = expr["symbol"]["name"]
        if "variantKind" in expr:
            name += "@" + expr["variantKind"]

        sym = self._symbols_by_name.get(name, None)
        if not sym or sym.module != module:
            sym = next(
                (sym for sym in module.symbols if sym.name == name), None
            )
        assert sym, "Referencing a symbol not present in the module"

        return gtirb.SymAddrConst(0, sym)

    def _assemble(
        self, module: gtirb.Module, asm: str, x86_syntax: X86Syntax
    ) -> Tuple[bytes, Dict[int, gtirb.SymAddrConst]]:
        assembler = mcasm.Assembler(_target_triple(module))
        assembler.x86_syntax = x86_syntax

        data = b""
        symbolic_expressions = {}
        for event in assembler.assemble(asm):
            if event["kind"] == "instruction":
                encoding = bytes.fromhex(event["data"])
                for fixup in event["fixups"]:
                    pos = len(data) + fixup["offset"]
                    symbolic_expressions[
                        pos
                    ] = self._fixup_to_symbolic_operand(
                        module, fixup, encoding
                    )
                data += encoding
                # TODO: We need to update the CFG if the instruction was a call
                #       or branch.
            elif event["kind"] == "bytes":
                data += bytes.fromhex(event["data"])
            elif event["kind"] == "changeSection":
                assert event["section"]["kind"][
                    "isText"
                ], "Sections other than .text are not supported"
            else:
                assert False, f"Unsupported assembler event: {event['kind']}"

        return data, symbolic_expressions

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
            instructions = tuple(
                GtirbInstructionDecoder(self._module.isa).get_instructions(
                    block
                )
            )

        for insertion in insertions:
            # TODO: This is where bubbling will get hooked in, but for now
            #       always insert at the first potential offset.
            offset = next(
                insertion.scope._potential_offsets(func, block, instructions)
            )
            self._invoke_patch(
                InsertionContext(self._module, func, block, offset),
                insertion.patch,
            )

    def register_insert(self, scope: Scope, patch: Patch) -> None:
        """
        Registers a patch to be inserted.
        :param scope: Where should the patch be placed?
        :param patch: The patch to be inserted.
        """
        self._insertions.append(_Insertion(scope, patch))

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
        self.register_insert(
            _SpecificLocationScope(function, block, offset), patch
        )

    def _partition_interval(
        self, interval: gtirb.ByteInterval, tables: List[OffsetMapping[object]]
    ) -> List[gtirb.ByteBlock]:
        """Create a new interval for every block in the ByteInterval."""
        # Last table holds symbolic expressions.
        tables[-1][interval] = interval.symbolic_expressions

        # We will walk through the blocks and the associated info in the aux
        # data/symbolic expression tables in order to avoid needing multiple
        # scans. The aux data/symbolic expression info is reversed to
        # facilitate poping from the back of the lists.

        old_items: List[List[Tuple[int, object]]] = [
            sorted(table.get(interval, {}).items(), reverse=True)
            for table in tables
        ]

        blocks = sorted(interval.blocks, key=lambda b: b.offset)
        for block in blocks:
            new_interval = gtirb.ByteInterval(
                size=block.size, contents=block.contents
            )
            new_interval.section = interval.section

            # Transfer aux data/symbolic expressions to the new interval.

            begin, end = block.offset, block.offset + block.size
            for table, items in zip(tables, old_items):
                while items != [] and items[-1][0] < begin:
                    items.pop()
                while items != [] and items[-1][0] < end:
                    off, value = items.pop()
                    del table[gtirb.Offset(interval, off)]
                    off -= block.offset
                    table[gtirb.Offset(new_interval, off)] = value

            if new_interval in tables[-1]:
                new_interval.symbolic_expressions = tables[-1][new_interval]
            new_interval.address = block.address
            block.byte_interval = new_interval
            block.offset = 0
        interval.section = None
        return blocks

    def _partition_byte_intervals(
        self,
        alignment: MutableMapping[gtirb.Node, int],
        tables: List[OffsetMapping[object]],
    ) -> List[List[gtirb.ByteBlock]]:
        """Create new byte intervals for every block in the module."""
        for block in self._module.byte_blocks:
            if block not in alignment:
                if block.address is None:
                    # Align the offset, since we don't know the actual address
                    alignment[block] = effective_alignment(block.offset)
                else:
                    alignment[block] = effective_alignment(block.address)

        partitions = []
        for interval in tuple(self._module.byte_intervals):
            if any(isinstance(b, gtirb.CodeBlock) for b in interval.blocks):
                partitions.append(self._partition_interval(interval, tables))
        return partitions

    def _rejoin_byte_intervals(
        self,
        partitions: List[List[gtirb.ByteBlock]],
        alignment: Mapping[gtirb.Node, int],
        tables: List[OffsetMapping[object]],
    ) -> None:
        """Recombine blocks that originally shared the same byte intervals."""
        nop = self._assemble(self._module, "nop", X86Syntax.INTEL)[0]

        for partition in partitions:
            block = partition[0]

            offset = 0
            address = block.address
            if address is not None:
                address = align_address(address, alignment[block])

            new_interval = gtirb.ByteInterval(address=address)
            new_interval.section = block.section

            contents = bytearray()
            for block in partition:
                if address is None:
                    padding = align_address(offset, alignment[block]) - offset
                else:
                    padding = align_address(address + offset, alignment[block])
                    padding -= address + offset
                if padding != 0:
                    # The pretty-printer won't print the padding bytes unless
                    # they are contained in blocks.
                    if isinstance(block, gtirb.DataBlock):
                        contents += b"\x00" * padding
                        pad = gtirb.DataBlock(offset=offset, size=padding)
                    else:
                        q, r = divmod(padding, len(nop))
                        assert r == 0, "nop does not fit evenly in padding"
                        contents += nop * q
                        pad = gtirb.CodeBlock(offset=offset, size=padding)
                    pad.byte_interval = new_interval
                    offset += padding
                contents += block.contents

                # Re-sync the symbolic expressions table with the byte interval
                # in case the patches added new symbolic expressions.
                old_interval = block.byte_interval
                tables[-1].pop(old_interval, None)
                tables[-1][old_interval] = old_interval.symbolic_expressions

                # Transfer aux data/symbolic expressions to the new interval.
                for table in tables:
                    table[new_interval] = {
                        k + offset: v
                        for k, v in table.get(old_interval, {}).items()
                    }
                    table.pop(old_interval, None)
                block.byte_interval = new_interval
                block.offset = offset
                offset += block.size

            new_interval.contents = contents
            new_interval.size = len(contents)
            new_interval.initialized_size = len(contents)
            new_interval.symbolic_expressions = tables[-1][new_interval]

    @contextlib.contextmanager
    def _prepare_for_rewriting(self, module: gtirb.Module) -> Iterator[None]:
        """Pre-compute data structure to accelerate rewriting."""

        def cast_to_offset_mapping(name):
            table = module.aux_data[name]
            if not isinstance(table.data, OffsetMapping):
                table.data = OffsetMapping(table.data)
            return table.data

        alignment = {}
        if "alignment" in module.aux_data:
            alignment = module.aux_data["alignment"].data
        tables = [
            cast_to_offset_mapping(name)
            for name in ("comments", "padding", "symbolicExpressionSizes")
            if name in module.aux_data
        ]
        # Add an OffsetMapping for symbolic expressions
        tables.append(OffsetMapping())

        partitions = self._partition_byte_intervals(alignment, tables)

        yield

        self._rejoin_byte_intervals(partitions, alignment, tables)

    def apply(self) -> None:
        """
        Applies all of the patches to the module.
        """

        with self._prepare_for_rewriting(self._module):
            for f in self._functions:
                func_insertions = [
                    insertion
                    for insertion in self._insertions
                    if insertion.scope._function_matches(self._module, f)
                ]
                if not func_insertions:
                    continue

                for b in f.get_all_blocks():
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
