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
import itertools
from typing import Dict, List, Optional

import gtirb
import mcasm

from .assembly import X86Syntax
from .utils import _is_elf_pie, _target_triple


class _Assembler:
    """
    Assembles the assembly from a patch and its prologue/epilogue, creating
    control flow graph as it goes.

    :ivar ~.data: The encoded instructions from assembling the patch.
    :ivar ~.cfg: The control flow graph for the patch.
    :ivar ~.blocks: All code blocks, in order, for the patch.
    :ivar ~.symbolic_expressions: A map of offset to symbolic expression,
                                  relative to the data position.
    :ivar ~.local_symbols: Symbols that were created in the patch.
    :ivar ~.proxies: Proxy blocks that represent unknown targets.
    """

    def __init__(
        self,
        module: gtirb.Module,
        patch_id: int,
        module_symbols: Dict[str, gtirb.Symbol],
    ) -> None:
        """
        :param module: The module the patch will be inserted into.
        :param patch_id: A unique integer for this patch to avoid ambiguous
                         symbol names.
        :param module_symbols: A map from symbol name to symbol, to speed up
                               name lookups. This may be updated by the
                               assembler upon cache misses.
        """
        self._module = module
        self._patch_id = patch_id
        self.data = bytearray()
        self.cfg = gtirb.CFG()
        self.blocks = [gtirb.CodeBlock()]
        self.symbolic_expressions = {}
        self.local_symbols = {}
        self._module_symbols = module_symbols
        self.section_name = None
        self.proxies = set()

    @property
    def entry_block(self) -> gtirb.CodeBlock:
        return self.blocks[0]

    @property
    def current_block(self) -> gtirb.CodeBlock:
        return self.blocks[-1]

    def assemble(self, asm: str, x86_syntax: X86Syntax) -> None:
        """
        Assembles additional assembly into this chunk, continuing where the
        last call to assemble left off.
        """
        assembler = mcasm.Assembler(_target_triple(self._module))
        assembler.x86_syntax = x86_syntax

        events = assembler.assemble(asm)

        for event in events:
            if event["kind"] == "label":
                self._precreate_defined_label(event["symbol"])

        for event in events:
            if event["kind"] == "instruction":
                self._assemble_instruction(
                    bytes.fromhex(event["data"]),
                    event["inst"],
                    event["fixups"],
                )
            elif event["kind"] == "label":
                self._assemble_label(event["symbol"])
            elif event["kind"] == "changeSection":
                self._assemble_change_section(event["section"])
            else:
                assert False, f"Unsupported assembler event: {event['kind']}"

    def _precreate_defined_label(self, symbol: dict) -> None:
        label_name = symbol["name"]

        # If the symbol is temporary in LLVM's eyes, we will append our patch
        # id to it in order to make the symbol name unique.
        symbol_name = label_name
        if symbol["isTemporary"]:
            symbol_name += f"_{self._patch_id}"

        assert (
            label_name not in self.local_symbols
            and symbol_name not in self._module_symbols
        ), f"{symbol_name} defined multiple times"

        label_sym = gtirb.Symbol(name=symbol_name, payload=gtirb.CodeBlock())
        self.local_symbols[label_name] = label_sym

    def _assemble_label(self, symbol: dict) -> None:
        label_sym = self.local_symbols[symbol["name"]]
        label_block = label_sym.referent
        assert label_block

        label_block.offset = (
            self.current_block.offset + self.current_block.size
        )
        self.cfg.add(
            gtirb.Edge(
                source=self.current_block,
                target=label_block,
                label=gtirb.Edge.Label(type=gtirb.Edge.Type.Fallthrough),
            )
        )

        self.blocks.append(label_block)

    def _assemble_change_section(self, section: dict) -> None:
        # We don't have any work to do here, but we want to make sure that
        # patches don't try to insert anywhere except the text section.
        assert section["kind"][
            "isText"
        ], "Sections other than .text are not supported"
        self.section_name = section["name"]

    def _assemble_instruction(
        self, data: bytes, inst: dict, fixups: List[dict]
    ) -> None:
        for fixup in fixups:
            pos = len(self.data) + fixup["offset"]
            self.symbolic_expressions[pos] = self._fixup_to_symbolic_operand(
                fixup, data
            )

        self.data += data
        self.current_block.size += len(data)

        if inst["desc"]["isReturn"]:
            proxy = gtirb.ProxyBlock()
            self.proxies.add(proxy)
            self.cfg.add(
                gtirb.Edge(
                    source=self.current_block,
                    target=proxy,
                    label=gtirb.Edge.Label(type=gtirb.Edge.Type.Return),
                )
            )

            next_block = gtirb.CodeBlock(
                offset=self.current_block.offset + self.current_block.size
            )
            self.blocks.append(next_block)

        elif inst["desc"]["isCall"] or inst["desc"]["isBranch"]:
            assert not inst["desc"][
                "isIndirectBranch"
            ], "Indirect branches are not yet supported"

            assert len(fixups) == 1
            target_fixup = self._fixup_to_symbolic_operand(fixups[0], data)
            assert isinstance(target_fixup, gtirb.SymAddrConst)
            assert target_fixup.offset == 0

            next_block = gtirb.CodeBlock(
                offset=self.current_block.offset + self.current_block.size
            )

            if isinstance(target_fixup.symbol.referent, gtirb.CfgNode):
                if inst["desc"]["isCall"]:
                    edge_label = gtirb.Edge.Label(type=gtirb.Edge.Type.Call)
                elif inst["desc"]["isBranch"]:
                    edge_label = gtirb.Edge.Label(
                        type=gtirb.Edge.Type.Branch,
                        conditional=inst["desc"]["isConditionalBranch"],
                    )

                self.cfg.add(
                    gtirb.Edge(
                        source=self.current_block,
                        target=target_fixup.symbol.referent,
                        label=edge_label,
                    )
                )

            # Currently we assume that all calls can return and that they need
            # a fallthrough edge.
            if inst["desc"]["isCall"] or inst["desc"]["isConditionalBranch"]:
                self.cfg.add(
                    gtirb.Edge(
                        source=self.current_block,
                        target=next_block,
                        label=gtirb.Edge.Label(
                            type=gtirb.Edge.Type.Fallthrough
                        ),
                    )
                )

            self.blocks.append(next_block)

    def _fixup_to_symbolic_operand(
        self, fixup: dict, encoding: bytes
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
        sym = self._symbol_lookup(name)
        assert sym, f"{name} is an undefined symbol reference"

        attributes = set()
        if "variantKind" in expr:
            if expr["variantKind"] == "PLT":
                attributes.add(gtirb.SymbolicExpression.Attribute.PltRef)
            else:
                assert False, f"Unsupported variantKind: {expr['variantKind']}"
        elif _is_elf_pie(self._module) and isinstance(
            sym.referent, gtirb.ProxyBlock
        ):
            attributes.add(gtirb.SymbolicExpression.Attribute.PltRef)

        return gtirb.SymAddrConst(0, sym, attributes)

    def _symbol_lookup(self, name: str) -> Optional[gtirb.Symbol]:
        """
        Looks up a symbol by name.

        :param name: The symbol's name.
        """

        sym = self.local_symbols.get(name, None)
        if sym:
            return sym

        sym = self._module_symbols.get(name, None)
        if sym and sym.module == self._module:
            return sym

        sym = next(
            (sym for sym in self._module.symbols if sym.name == name), None
        )
        if sym:
            self._module_symbols[sym.name] = sym
            return sym

        return None

    def _remove_empty_blocks(self) -> None:
        final_blocks = []
        for _, group in itertools.groupby(self.blocks, key=lambda b: b.offset):
            *extra_blocks, main_block = group
            assert main_block.size or main_block == self.blocks[-1]

            for extra_block in extra_blocks:
                assert not extra_block.size

                for edge in list(self.cfg.in_edges(extra_block)):
                    self.cfg.discard(edge)
                    if edge.source not in extra_blocks:
                        assert edge.source != main_block
                        self.cfg.add(edge._replace(target=main_block))

                # Our extra block should only have a single fallthrough edge
                # that is to another extra block or the main block.
                for edge in list(self.cfg.out_edges(extra_block)):
                    assert edge.label.type == gtirb.Edge.Type.Fallthrough
                    assert (
                        edge.target in extra_blocks
                        or edge.target == main_block
                    )
                    self.cfg.discard(edge)

                for sym in self.local_symbols.values():
                    if sym.referent == extra_block:
                        sym.referent = main_block

            final_blocks.append(main_block)

        self.blocks = final_blocks

    def finalize(self) -> None:
        """
        Finalizes the assembly contents and validates that there are no
        undefined symbols referenced.
        """

        self._remove_empty_blocks()
