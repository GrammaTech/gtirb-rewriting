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
import logging
from typing import Dict, List, NamedTuple, Sequence, Tuple

import gtirb
import gtirb_functions
import mcasm
from gtirb_capstone.instructions import GtirbInstructionDecoder

from .assembly import InsertionContext, Patch, X86Syntax, _AsmSnippet
from .isa import _get_isa
from .prepare import prepare_for_rewriting
from .scopes import Scope, _SpecificLocationScope
from .utils import (
    _modify_block_insert,
    _target_triple,
    decorate_extern_symbol,
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
        self._decoder = GtirbInstructionDecoder(self._module.isa)
        self._isa = _get_isa(module)
        self._insertions: List[_Insertion] = []
        self._logger = logger

    def _might_be_leaf_function(self, func: gtirb_functions.Function) -> bool:
        return all(
            not edge.label or edge.label.type != gtirb.Edge.Type.Call
            for block in func.get_all_blocks()
            for edge in block.outgoing_edges
        )

    def _invoke_patch(
        self,
        func: gtirb_functions.Function,
        block: gtirb.CodeBlock,
        offset: int,
        patch: Patch,
    ) -> None:
        """
        Invokes a patch at a concrete location and applies its results to the
        target module.
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
            if self._isa.red_zone_size() and self._might_be_leaf_function(
                func
            ):
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
            InsertionContext(
                self._module, func, block, offset, stack_adjustment
            ),
            *scratch_registers,
        )
        if not asm:
            return

        # Transform all the prefixes/suffixes into a flat list of assembly
        flat_snippets: List[_AsmSnippet] = []
        flat_snippets.extend(snippet[0] for snippet in snippets)
        flat_snippets.append(_AsmSnippet(asm, patch.constraints.x86_syntax))
        flat_snippets.extend(snippet[1] for snippet in snippets[::-1])

        chunks = [
            self._assemble(self._module, snippet.code, snippet.x86_syntax)
            for snippet in flat_snippets
        ]
        chunks_encoded = b"".join(chunk[0] for chunk in chunks)

        if self._logger.isEnabledFor(logging.DEBUG):
            self._logger.debug("Applying %s at %s+%s", patch, block, offset)
            self._logger.debug("  Before:")
            show_block_asm(block, decoder=self._decoder, logger=self._logger)

        _modify_block_insert(
            block, chunks_encoded, offset,
        )

        start = block.offset + offset
        for encoding, fixups in chunks:
            for rel_offset, sym in fixups.items():
                fixup_offset = start + rel_offset
                assert block.byte_interval
                assert (
                    fixup_offset
                    not in block.byte_interval.symbolic_expressions
                )
                block.byte_interval.symbolic_expressions[fixup_offset] = sym
            start += len(encoding)

        if self._logger.isEnabledFor(logging.DEBUG):
            self._logger.debug("  After:")
            show_block_asm(block, decoder=self._decoder, logger=self._logger)

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
            instructions = tuple(self._decoder.get_instructions(block))

        for insertion in insertions:
            # TODO: This is where bubbling will get hooked in, but for now
            #       always insert at the first potential offset.
            offset = next(
                insertion.scope._potential_offsets(func, block, instructions)
            )
            self._invoke_patch(
                func, block, offset, insertion.patch,
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

    def apply(self) -> None:
        """
        Applies all of the patches to the module.
        """

        with prepare_for_rewriting(self._module, self._isa.nop()):
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
