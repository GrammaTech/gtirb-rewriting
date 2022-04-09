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
from typing import Dict, List, Optional, Set, Tuple

import gtirb
import mcasm

from .assembly import X86Syntax
from .utils import (
    _is_elf_pie,
    _is_fallthrough_edge,
    _target_triple,
    is_gtirb_at_least_version,
)


class UndefSymbolError(ValueError):
    """
    A symbol was referenced that was not defined.
    """

    pass


class UnsupportedAssemblyError(ValueError):
    """
    The assembly is valid but uses a feature not supported by the Assembler
    class.
    """

    pass


class Assembler:
    """
    Assembles chunks of assembly, creating a control flow graph and other
    GTIRB structures as it goes.
    """

    def __init__(
        self,
        module: gtirb.Module,
        *,
        temp_symbol_suffix: str = None,
        module_symbols: Dict[str, gtirb.Symbol] = None,
        trivially_unreachable: bool = False,
        allow_undef_symbols: bool = False,
    ) -> None:
        """
        :param module: The module the patch will be inserted into.
        :param temp_symbol_suffix: A suffix to use for local symbols that are
               considered temporary. Passing in a unique suffix to each
               assembler that targets the same module means that the assembly
               itself does not have to be concerned with having unique
               temporary symbol names.
        :param module_symbols: A map from symbol name to symbol, to speed up
                               name lookups. This must be in sync with the
                               module's symbols.
        :param trivially_unreachable: Is the entry block of the patch
                                      obviously unreachable? For example,
                                      inserting after a ret instruction.
        :param allow_undef_symbols: Allows the assembly to refer to undefined
                                    symbols. Such symbols will be created and
                                    set to refer to a proxy block.
        """
        self._module = module
        self._temp_symbol_suffix = temp_symbol_suffix
        self._cfg = gtirb.CFG()
        self._local_symbols: Dict[str, gtirb.Symbol] = {}
        if module_symbols is not None:
            self._module_symbols = module_symbols
        else:
            self._module_symbols = {sym.name: sym for sym in module.symbols}
        self._trivially_unreachable = trivially_unreachable
        self._allow_undef_symbols = allow_undef_symbols
        self._proxies = set()
        self._blocks_with_code = set()
        # This isn't set until the assembler runs, but will exist after that
        # point. Code should use _current_section instead of this, which takes
        # care of removing the optional-ness.
        self._optional_current_section: Optional[
            "Assembler.Result.Section"
        ] = None
        self._sections: Dict[str, "Assembler.Result.Section"] = {}

    @property
    def _current_section(self) -> "Assembler.Result.Section":
        assert self._optional_current_section, "not in a section yet"
        return self._optional_current_section

    @property
    def _current_block(self) -> gtirb.CodeBlock:
        result = self._current_section.blocks[-1]
        assert isinstance(
            result, gtirb.CodeBlock
        ), "current block should be a code block"
        return result

    def assemble(
        self, asm: str, x86_syntax: X86Syntax = X86Syntax.ATT
    ) -> None:
        """
        Assembles additional assembly, continuing where the last call to
        assemble left off.
        """
        assembler = mcasm.Assembler(_target_triple(self._module))

        # X86 is hopefully the only ISA with more than one syntax mode that
        # is widely used. If other targets do come up, we may simply choose
        # a blessed syntax and avoid the additional complexity.
        if self._module.isa in (gtirb.Module.ISA.IA32, gtirb.Module.ISA.X64):
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
            elif event["kind"] == "bytes":
                self._assemble_bytes(bytes.fromhex(event["data"]))
            elif event["kind"] == "emitValue":
                self._assemble_emit_value(event["value"], event["size"])
            elif event["kind"] == "emitValueToAlignment":
                self._emit_alignment(
                    event["alignment"],
                    event["value"],
                    event["valueSize"],
                    event["maxBytes"],
                )
            elif event["kind"] == "emitCodeAlignment":
                # We currently handle this the same as the previous case, so
                # just call the same function.
                self._emit_alignment(
                    event["alignment"], 0, 0, event["maxBytes"]
                )
            else:
                assert False, f"Unsupported assembler event: {event['kind']}"

    def _precreate_defined_label(self, symbol: dict) -> None:
        label_name = symbol["name"]

        # If the symbol is temporary in LLVM's eyes and our client has given
        # us a suffix to use for temporary symbols, tack it on. This allows
        # clients to use the same assembly multiple times without worrying
        # about duplicate symbol names, as long as they pass a different
        # suffix each time.
        symbol_name = label_name
        if symbol["isTemporary"] and self._temp_symbol_suffix is not None:
            symbol_name += self._temp_symbol_suffix

        assert (
            label_name not in self._local_symbols
            and symbol_name not in self._module_symbols
        ), f"{symbol_name} defined multiple times"

        label_sym = gtirb.Symbol(name=symbol_name, payload=gtirb.CodeBlock())
        self._local_symbols[label_name] = label_sym

    def _assemble_label(self, symbol: dict) -> None:
        label_sym = self._local_symbols[symbol["name"]]
        label_block = label_sym.referent
        assert label_block

        label_block.offset = (
            self._current_block.offset + self._current_block.size
        )
        self._cfg.add(
            gtirb.Edge(
                source=self._current_block,
                target=label_block,
                label=gtirb.Edge.Label(type=gtirb.Edge.Type.Fallthrough),
            )
        )

        self._current_section.blocks.append(label_block)

    def _assemble_change_section(self, section: dict) -> None:
        name = section["name"]

        # LLVM validates that flags don't change when it sees the same section
        # multiple times, so we don't need to do that here.
        result = self._sections.get(name)
        if not result:
            flags: Set[gtirb.Section.Flag] = set()
            elf_flags: Optional[int] = None
            elf_type: Optional[int] = None

            if section["class"] == "MCSectionELF":
                SHF_WRITE = 0x1
                SHF_ALLOC = 0x2
                SHF_EXECINSTR = 0x4
                SHT_NOBITS = 8

                elf_flags = section["flags"]
                elf_type = section["type"]
                assert elf_flags and elf_type

                if elf_flags & SHF_WRITE:
                    flags.add(gtirb.Section.Flag.Writable)

                if elf_flags & SHF_ALLOC:
                    flags.add(gtirb.Section.Flag.Loaded)
                    flags.add(gtirb.Section.Flag.Readable)
                    if elf_type != SHT_NOBITS:
                        flags.add(gtirb.Section.Flag.Initialized)

                if elf_flags & SHF_EXECINSTR:
                    flags.add(gtirb.Section.Flag.Executable)

            elif section["class"] == "MCSectionCOFF":
                IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
                IMAGE_SCN_MEM_EXECUTE = 0x20000000
                IMAGE_SCN_MEM_READ = 0x40000000
                IMAGE_SCN_MEM_WRITE = 0x80000000

                characteristics = section["characteristics"]

                if characteristics & IMAGE_SCN_MEM_READ:
                    flags.add(gtirb.Section.Flag.Loaded)
                    flags.add(gtirb.Section.Flag.Readable)

                if characteristics & IMAGE_SCN_MEM_WRITE:
                    flags.add(gtirb.Section.Flag.Writable)

                if characteristics & IMAGE_SCN_MEM_EXECUTE:
                    flags.add(gtirb.Section.Flag.Executable)

                if not characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA:
                    flags.add(gtirb.Section.Flag.Initialized)

            else:
                raise NotImplementedError(
                    f"unsupported section class {section['class']}"
                )

            result = self.Result.Section(
                name=name,
                flags=flags,
                data=b"",
                blocks=[gtirb.CodeBlock()],
                symbolic_expressions={},
                symbolic_expression_sizes={},
                alignment={},
                elf_flags=elf_flags,
                elf_type=elf_type,
            )
            self._sections[name] = result

        self._optional_current_section = result

    def _resolve_instruction_target(
        self, data: bytes, inst: dict, fixups: List[dict]
    ) -> Tuple[bool, gtirb.CfgNode]:
        """
        Resolves a call or branch instruction's target to a CFG node.
        """
        assert inst["desc"]["isCall"] or inst["desc"]["isBranch"]

        # LLVM doesn't seem to have anything to denote an indirect call, but
        # we can infer it from the lack of fixups.
        if inst["desc"]["isIndirectBranch"] or (
            inst["desc"]["isCall"] and not fixups
        ):
            proxy = gtirb.ProxyBlock()
            self._proxies.add(proxy)
            return False, proxy

        assert len(fixups) == 1
        target_expr = self._fixup_to_symbolic_operand(fixups[0], data, True)

        if not isinstance(target_expr, gtirb.SymAddrConst):
            raise UnsupportedAssemblyError(
                "Call and branch targets must be simple expressions"
            )

        if target_expr.offset != 0:
            raise UnsupportedAssemblyError(
                "Call and branch targets cannot have offsets"
            )

        if not isinstance(target_expr.symbol.referent, gtirb.CfgNode):
            raise UnsupportedAssemblyError(
                "Call and branch targets cannot be data blocks or other "
                "non-CFG elements"
            )

        return True, target_expr.symbol.referent

    def _assemble_instruction(
        self, data: bytes, inst: dict, fixups: List[dict]
    ) -> None:
        for fixup in fixups:
            pos = len(self._current_section.data) + fixup["offset"]
            self._current_section.symbolic_expressions[
                pos
            ] = self._fixup_to_symbolic_operand(
                fixup, data, inst["desc"]["isCall"] or inst["desc"]["isBranch"]
            )
            self._current_section.symbolic_expression_sizes[pos] = (
                fixup["targetSize"] // 8
            )

        self._current_section.data += data
        self._current_block.size += len(data)
        self._blocks_with_code.add(self._current_block)

        if inst["desc"]["isReturn"]:
            proxy = gtirb.ProxyBlock()
            self._proxies.add(proxy)
            self._cfg.add(
                gtirb.Edge(
                    source=self._current_block,
                    target=proxy,
                    label=gtirb.Edge.Label(type=gtirb.Edge.Type.Return),
                )
            )

            self._split_block()

        elif inst["desc"]["isCall"] or inst["desc"]["isBranch"]:
            direct, target = self._resolve_instruction_target(
                data, inst, fixups
            )

            if inst["desc"]["isCall"]:
                edge_label = gtirb.Edge.Label(
                    type=gtirb.Edge.Type.Call,
                    direct=direct,
                )
            elif inst["desc"]["isBranch"]:
                edge_label = gtirb.Edge.Label(
                    type=gtirb.Edge.Type.Branch,
                    conditional=inst["desc"]["isConditionalBranch"],
                    direct=direct,
                )
            else:
                # This if/elif exhaustively covers the cases that let us into
                # the parent block, so this is just to shut up analysis tools
                # that don't understant that this is unreachable.
                assert False

            self._cfg.add(
                gtirb.Edge(
                    source=self._current_block,
                    target=target,
                    label=edge_label,
                )
            )

            # Currently we assume that all calls can return and that they need
            # a fallthrough edge.
            add_fallthrough = (
                inst["desc"]["isCall"] or inst["desc"]["isConditionalBranch"]
            )
            self._split_block(add_fallthrough=add_fallthrough)

    def _assemble_bytes(self, data: bytes) -> None:
        self._current_section.data += data
        self._current_block.size += len(data)

    def _assemble_emit_value(self, value: dict, size: int) -> None:
        self._current_section.symbolic_expressions[
            len(self._current_section.data)
        ] = self._mcexpr_to_symbolic_operand(value, False)
        self._current_section.symbolic_expression_sizes[
            len(self._current_section.data)
        ] = size
        self._current_section.data += b"\x00" * size
        self._current_block.size += size

    def _emit_alignment(
        self, alignment: int, value: int, value_size: int, max_bytes: int
    ) -> None:
        """
        Called when the assembler handles a .align directive.
        """

        if value != 0:
            raise UnsupportedAssemblyError(
                "trying to pad with a non-zero byte"
            )

        if max_bytes != 0:
            raise UnsupportedAssemblyError("trying to pad with a fixed limit")

        # Alignment can only be applied to the start of a block, so we need
        # to split the current block.
        if self._current_block.size:
            self._split_block(add_fallthrough=True)

        self._current_section.alignment[self._current_block] = alignment

    def _split_block(self, add_fallthrough: bool = False) -> gtirb.CodeBlock:
        """
        Starts a new block, optionally adding a fallthrough edge from the
        current block.
        """

        next_block = gtirb.CodeBlock(
            offset=self._current_block.offset + self._current_block.size
        )

        if add_fallthrough:
            self._cfg.add(
                gtirb.Edge(
                    source=self._current_block,
                    target=next_block,
                    label=gtirb.Edge.Label(type=gtirb.Edge.Type.Fallthrough),
                )
            )

        self._current_section.blocks.append(next_block)
        return next_block

    def _resolve_symbol_ref(self, expr: dict) -> gtirb.Symbol:
        assert expr["kind"] == "symbolRef"

        name = expr["symbol"]["name"]
        sym = self._symbol_lookup(name)

        if not sym:
            if not self._allow_undef_symbols:
                raise UndefSymbolError(
                    f"{name} is an undefined symbol reference"
                )

            proxy = gtirb.ProxyBlock()
            sym = gtirb.Symbol(name, payload=proxy)
            self._local_symbols[name] = sym
            self._proxies.add(proxy)

        return sym

    def _get_symbol_ref_attrs(
        self, expr: dict, sym: gtirb.Symbol, is_branch: bool
    ) -> Set[gtirb.SymbolicExpression.Attribute]:
        assert expr["kind"] == "symbolRef"

        attributes = set()
        if "variantKind" in expr:
            if expr["variantKind"] == "PLT":
                attributes.add(gtirb.SymbolicExpression.Attribute.PltRef)
            elif expr["variantKind"] == "GOTPCREL":
                attributes.add(gtirb.SymbolicExpression.Attribute.GotRelPC)
            else:
                assert False, f"Unsupported variantKind: {expr['variantKind']}"
        elif (
            self._module.isa in (gtirb.Module.ISA.IA32, gtirb.Module.ISA.X64)
            and _is_elf_pie(self._module)
            and isinstance(sym.referent, gtirb.ProxyBlock)
        ):
            # These appear to only be necessary for X86 ELF, so we're limiting
            # the inference to that.
            if is_branch:
                attributes.add(gtirb.SymbolicExpression.Attribute.PltRef)
            else:
                attributes.add(gtirb.SymbolicExpression.Attribute.GotRelPC)
        return attributes

    def _mcexpr_to_symbolic_operand(
        self, expr: dict, is_branch: bool
    ) -> gtirb.SymAddrConst:
        """
        Converts an MC expression to a GTIRB SymbolicExpression.
        """
        attributes = set()

        if expr["kind"] == "targetExpr" and expr["target"] == "aarch64":
            elfName = expr["elfName"]
            if elfName == "":
                # LLVM wrapped the expression in a target-specific MCExpr, but
                # it doesn't effect the output assembly so we don't need to
                # create a symbolic expression attr for it.
                pass
            elif elfName == ":got:":
                attributes.add(gtirb.SymbolicExpression.Attribute.GotRef)
            elif elfName == ":lo12:":
                if is_gtirb_at_least_version("1.10.5-dev"):
                    attributes.add(gtirb.SymbolicExpression.Attribute.Lo12)
                else:
                    attributes.add(gtirb.SymbolicExpression.Attribute.Part0)
            elif elfName == ":got_lo12:":
                if is_gtirb_at_least_version("1.10.5-dev"):
                    attributes.add(gtirb.SymbolicExpression.Attribute.Lo12)
                    attributes.add(gtirb.SymbolicExpression.Attribute.GotRef)
                else:
                    attributes.add(gtirb.SymbolicExpression.Attribute.Part1)
            else:
                raise NotImplementedError(
                    f"unknown aarch64-specific fixup: {elfName}"
                )
            expr = expr["expr"]

        # TODO: Do we need to support SymAddrAddr fixup types?
        if (
            expr["kind"] == "binaryExpr"
            and expr["opcode"] == "Add"
            and expr["lhs"]["kind"] == "symbolRef"
            and expr["rhs"]["kind"] == "constant"
        ):
            sym = self._resolve_symbol_ref(expr["lhs"])
            attributes |= self._get_symbol_ref_attrs(
                expr["lhs"], sym, is_branch
            )
            offset = expr["rhs"]["value"]
            return gtirb.SymAddrConst(offset, sym, attributes)
        elif expr["kind"] == "symbolRef":
            sym = self._resolve_symbol_ref(expr)
            attributes |= self._get_symbol_ref_attrs(expr, sym, is_branch)
            return gtirb.SymAddrConst(0, sym, attributes)

        assert False, "Unsupported symbolic expression"

    def _fixup_to_symbolic_operand(
        self, fixup: dict, encoding: bytes, is_branch: bool
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

        return self._mcexpr_to_symbolic_operand(expr, is_branch)

    def _symbol_lookup(self, name: str) -> Optional[gtirb.Symbol]:
        """
        Looks up a symbol by name.

        :param name: The symbol's name.
        """

        sym = self._local_symbols.get(name, None)
        if sym:
            return sym

        sym = self._module_symbols.get(name, None)
        if sym and sym.module == self._module:
            return sym

        return None

    def _replace_symbol_referents(
        self, old_block: gtirb.Block, new_block: gtirb.Block
    ) -> None:
        """
        Alters all symbols referring to an old block to refer to a new block.
        """
        for sym in self._local_symbols.values():
            if sym.referent == old_block:
                sym.referent = new_block

    def _remove_empty_blocks(
        self, section: "Assembler.Result.Section"
    ) -> None:
        final_blocks = []
        for _, group in itertools.groupby(
            section.blocks, key=lambda b: b.offset
        ):
            *extra_blocks, main_block = group
            assert main_block.size or main_block == section.blocks[-1]
            max_alignment = section.alignment.get(main_block, 0)

            for extra_block in extra_blocks:
                assert isinstance(extra_block, gtirb.CodeBlock)
                assert not extra_block.size

                for edge in list(self._cfg.in_edges(extra_block)):
                    self._cfg.discard(edge)
                    if edge.source not in extra_blocks:
                        assert edge.source != main_block
                        self._cfg.add(edge._replace(target=main_block))

                # Our extra block should only have a single fallthrough edge
                # that is to another extra block or the main block.
                for edge in list(self._cfg.out_edges(extra_block)):
                    assert (
                        edge.label
                        and edge.label.type == gtirb.Edge.Type.Fallthrough
                    )
                    assert (
                        edge.target in extra_blocks
                        or edge.target == main_block
                    )
                    self._cfg.discard(edge)

                self._replace_symbol_referents(extra_block, main_block)

                if extra_block in section.alignment:
                    max_alignment = max(
                        max_alignment, section.alignment[extra_block]
                    )
                    del section.alignment[extra_block]

            if max_alignment:
                section.alignment[main_block] = max_alignment
            final_blocks.append(main_block)

        section.blocks = final_blocks

    def _convert_data_blocks(
        self, section: "Assembler.Result.Section"
    ) -> None:
        """
        Converts blocks that only have data and have no incoming control flow
        to be DataBlocks.
        """
        for i, block in enumerate(section.blocks):
            assert isinstance(block, gtirb.CodeBlock)

            if (
                block.size
                and block not in self._blocks_with_code
                and (
                    gtirb.Section.Flag.Executable not in section.flags
                    or i != 0
                    or self._trivially_unreachable
                )
                and not any(self._cfg.in_edges(block))
            ):
                new_block = gtirb.DataBlock(
                    offset=block.offset, size=block.size
                )
                self._replace_symbol_referents(block, new_block)
                for out_edge in set(self._cfg.out_edges(block)):
                    assert _is_fallthrough_edge(out_edge)
                    self._cfg.discard(out_edge)
                section.blocks[i] = new_block
                if block in section.alignment:
                    section.alignment[new_block] = section.alignment[block]
                    del section.alignment[block]

    def finalize(self) -> "Result":
        """
        Finalizes the assembly contents and returns the result.
        """

        for section in self._sections.values():
            self._remove_empty_blocks(section)
            self._convert_data_blocks(section)

        result = self.Result(
            sections=self._sections,
            cfg=self._cfg,
            symbols=list(self._local_symbols.values()),
            proxies=self._proxies,
        )

        # Reinitialize the assembler just in case someone tries to use the
        # object again.
        self.__init__(
            self._module,
            temp_symbol_suffix=self._temp_symbol_suffix,
            module_symbols=self._module_symbols,
            trivially_unreachable=self._trivially_unreachable,
            allow_undef_symbols=self._allow_undef_symbols,
        )

        return result

    @dataclasses.dataclass
    class Result:
        """
        The result of assembling an assembly patch.
        """

        @dataclasses.dataclass
        class Section:
            name: str

            flags: Set[gtirb.Section.Flag]
            """
            Section flags.
            """

            data: bytes
            """
            The encoded bytes from assembling the patch.
            """

            blocks: List[gtirb.ByteBlock]
            """
            All blocks, in order of offset, for the patch. There will be at
            most one empty block, which will be at the end of the list.
            """

            symbolic_expressions: Dict[int, gtirb.SymbolicExpression]
            """
            A map of offset to symbolic expression, with 0 being the start of
            `data`.
            """

            symbolic_expression_sizes: Dict[int, int]
            """
            A map of offset to symbolic expression size, with 0 being the
            start of `data`.
            """

            alignment: Dict[gtirb.ByteBlock, int]
            """
            A map of block to the requested alignment of the block. Padding is
            not inserted in the data, so the blocks may not currently be at
            this alignment.
            """

            elf_type: Optional[int]
            """
            The ELF section type (SHT_*) for the section. ELF-only.
            """

            elf_flags: Optional[int]
            """
            The ELF section flags (SHF_*) for the section. ELF-only.
            """

        sections: Dict[str, Section]
        """
        Sections in the patch. The first section will be the text section.
        """

        cfg: gtirb.CFG
        """
        The control flow graph for the patch.
        """

        symbols: List[gtirb.Symbol]
        """
        Symbols that were defined in the patch.
        """

        proxies: Set[gtirb.ProxyBlock]
        """
        Proxy blocks that represent unknown targets.
        """

        @property
        def text_section(self) -> Section:
            return next(iter(self.sections.values()))
