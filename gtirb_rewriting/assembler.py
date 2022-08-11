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
from typing import Dict, List, Optional, Set, Tuple, Type, TypeVar

import gtirb
import mcasm

from .assembly import X86Syntax
from .utils import _is_elf_pie, _is_fallthrough_edge, _target_triple


class AssemblerError(Exception):
    """
    Base class for assembler errors that can be associated with the input
    assembly.
    """

    def __init__(
        self,
        message: str,
        lineno: Optional[int] = None,
        offset: Optional[int] = None,
    ):
        super().__init__(message)
        self.lineno = lineno
        self.offset = offset


class AsmSyntaxError(AssemblerError):
    """
    An error was encountered parsing the assembly.
    """

    pass


class UndefSymbolError(AssemblerError):
    """
    A symbol was referenced that was not defined.
    """

    pass


class UnsupportedAssemblyError(AssemblerError):
    """
    The assembly is valid but uses a feature not supported by the Assembler
    class.
    """

    pass


class MultipleDefinitionsError(AssemblerError):
    """
    A symbol was defined multiple times.
    """

    pass


_ErrorT = TypeVar("_ErrorT", bound=AssemblerError)


def _make_error(
    err_type: Type[_ErrorT],
    message: str,
    loc: Optional[mcasm.mc.SourceLocation],
) -> _ErrorT:
    """
    Makes an instance of the requested error with the correct location info.
    """
    if loc:
        return err_type(message, loc.lineno, loc.offset)
    else:
        return err_type(message, None, None)


class Assembler:
    """
    Assembles chunks of assembly, creating a control flow graph and other
    GTIRB structures as it goes.
    """

    def __init__(
        self,
        module: gtirb.Module,
        *,
        temp_symbol_suffix: Optional[str] = None,
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
        :param trivially_unreachable: Is the entry block of the patch
                                      obviously unreachable? For example,
                                      inserting after a ret instruction.
        :param allow_undef_symbols: Allows the assembly to refer to undefined
                                    symbols. Such symbols will be created and
                                    set to refer to a proxy block.
        """
        self._state = _State(
            module,
            temp_symbol_suffix,
            trivially_unreachable,
            allow_undef_symbols,
        )

    def assemble(
        self, asm: str, x86_syntax: X86Syntax = X86Syntax.ATT
    ) -> None:
        """
        Assembles additional assembly, continuing where the last call to
        assemble left off.
        """
        assembler = mcasm.Assembler(_target_triple(self._state.module))

        # X86 is hopefully the only ISA with more than one syntax mode that
        # is widely used. If other targets do come up, we may simply choose
        # a blessed syntax and avoid the additional complexity.
        if self._state.module.isa in (
            gtirb.Module.ISA.IA32,
            gtirb.Module.ISA.X64,
        ):
            assembler.x86_syntax = x86_syntax

        assembler.assemble(_SymbolCreator(self._state), asm)

        assembler.assemble(_Streamer(self._state), asm)

    def _replace_symbol_referents(
        self, old_block: gtirb.Block, new_block: gtirb.Block
    ) -> None:
        """
        Alters all symbols referring to an old block to refer to a new block.
        """
        for sym in self._state.local_symbols.values():
            if sym.referent == old_block:
                sym.referent = new_block

    def _remove_empty_blocks(
        self, section: "Assembler.Result.Section"
    ) -> None:
        final_blocks: List[gtirb.ByteBlock] = []
        for _, group in itertools.groupby(
            section.blocks, key=lambda b: b.offset
        ):
            *extra_blocks, main_block = group
            assert main_block.size or main_block == section.blocks[-1]
            assert isinstance(main_block, gtirb.CodeBlock)

            max_alignment = section.alignment.get(main_block, 0)

            for extra_block in extra_blocks:
                assert isinstance(extra_block, gtirb.CodeBlock)
                assert not extra_block.size

                for edge in list(self._state.cfg.in_edges(extra_block)):
                    self._state.cfg.discard(edge)
                    if edge.source not in extra_blocks:
                        assert edge.source != main_block
                        self._state.cfg.add(edge._replace(target=main_block))

                # Our extra block should only have a single fallthrough edge
                # that is to another extra block or the main block.
                for edge in list(self._state.cfg.out_edges(extra_block)):
                    assert (
                        edge.label
                        and edge.label.type == gtirb.Edge.Type.Fallthrough
                    )
                    assert (
                        edge.target in extra_blocks
                        or edge.target == main_block
                    )
                    self._state.cfg.discard(edge)

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
                and block not in self._state.blocks_with_code
                and (
                    gtirb.Section.Flag.Executable not in section.flags
                    or i != 0
                    or self._state.trivially_unreachable
                )
                and not any(self._state.cfg.in_edges(block))
            ):
                new_block = gtirb.DataBlock(
                    offset=block.offset, size=block.size
                )
                self._replace_symbol_referents(block, new_block)
                for out_edge in set(self._state.cfg.out_edges(block)):
                    assert _is_fallthrough_edge(out_edge)
                    self._state.cfg.discard(out_edge)
                section.blocks[i] = new_block
                if block in section.alignment:
                    section.alignment[new_block] = section.alignment[block]
                    del section.alignment[block]

    def finalize(self) -> "Result":
        """
        Finalizes the assembly contents and returns the result.
        """

        for section in self._state.sections.values():
            self._remove_empty_blocks(section)
            self._convert_data_blocks(section)

        result = self.Result(
            sections=self._state.sections,
            cfg=self._state.cfg,
            symbols=list(self._state.local_symbols.values()),
            proxies=self._state.proxies,
        )

        # Reinitialize the assembler just in case someone tries to use the
        # object again.
        self._state = _State(
            self._state.module,
            temp_symbol_suffix=self._state.temp_symbol_suffix,
            trivially_unreachable=self._state.trivially_unreachable,
            allow_undef_symbols=self._state.allow_undef_symbols,
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

            image_type: int
            """
            The ELF type for the section. For ELF this is SHT_* values. For PE
            this is ignored.
            """

            image_flags: int
            """
            The ELF/PE flags for the section. For ELF this is SHF_* flags, for
            PE this is IMAGE_SCN_* flags.
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


@dataclasses.dataclass
class _State:
    """
    All of the state that the assembler accumulates across calls to assemble
    and is used by the streamer classes.
    """

    module: gtirb.Module
    temp_symbol_suffix: Optional[str]
    trivially_unreachable: bool
    allow_undef_symbols: bool
    cfg: gtirb.CFG = dataclasses.field(default_factory=gtirb.CFG)
    local_symbols: Dict[str, gtirb.Symbol] = dataclasses.field(
        default_factory=dict
    )
    proxies: Set[gtirb.ProxyBlock] = dataclasses.field(default_factory=set)
    optional_current_section: Optional["Assembler.Result.Section"] = None
    sections: Dict[str, "Assembler.Result.Section"] = dataclasses.field(
        default_factory=dict
    )
    blocks_with_code: Set[gtirb.ByteBlock] = dataclasses.field(
        default_factory=set
    )

    @property
    def current_section(self) -> "Assembler.Result.Section":
        assert self.optional_current_section, "not in a section yet"
        return self.optional_current_section

    @property
    def current_block(self) -> gtirb.CodeBlock:
        result = self.current_section.blocks[-1]
        assert isinstance(
            result, gtirb.CodeBlock
        ), "current block should be a code block"
        return result


class _SymbolCreator(mcasm.Streamer):
    """
    A streamer that just takes care of precreating defined symbols.
    """

    def __init__(self, state: "_State"):
        self._state = state
        super().__init__()

    def emit_label(self, parser_state, label, loc):
        # If the symbol is temporary in LLVM's eyes and our client has
        # given us a suffix to use for temporary symbols, tack it on. This
        # allows clients to use the same assembly multiple times without
        # worrying about duplicate symbol names, as long as they pass a
        # different suffix each time.
        symbol_name = label.name
        if label.is_temporary and self._state.temp_symbol_suffix is not None:
            symbol_name += self._state.temp_symbol_suffix

        if label.name in self._state.local_symbols or any(
            self._state.module.symbols_named(label.name)
        ):
            raise _make_error(
                MultipleDefinitionsError,
                f"{symbol_name} defined multiple times",
                parser_state.loc,
            )

        label_sym = gtirb.Symbol(name=symbol_name, payload=gtirb.CodeBlock())
        self._state.local_symbols[label.name] = label_sym
        return label_sym


class _Streamer(mcasm.Streamer):
    """
    Handles streamer callbacks and generates GTIRB IR as needed.
    """

    _ELF_VARIANT_KINDS = {
        mcasm.mc.SymbolRefExpr.VariantKind.PLT: {
            gtirb.SymbolicExpression.Attribute.PltRef
        },
        mcasm.mc.SymbolRefExpr.VariantKind.GOTNTPOFF: {
            gtirb.SymbolicExpression.Attribute.GotOff,
            gtirb.SymbolicExpression.Attribute.NtpOff,
        },
        mcasm.mc.SymbolRefExpr.VariantKind.GOT: {
            gtirb.SymbolicExpression.Attribute.GotOff,
            gtirb.SymbolicExpression.Attribute.GotRef,
        },
        mcasm.mc.SymbolRefExpr.VariantKind.GOTOFF: {
            gtirb.SymbolicExpression.Attribute.GotOff
        },
        mcasm.mc.SymbolRefExpr.VariantKind.GOTTPOFF: {
            gtirb.SymbolicExpression.Attribute.GotRelPC,
            gtirb.SymbolicExpression.Attribute.TpOff,
        },
        mcasm.mc.SymbolRefExpr.VariantKind.GOTPCREL: {
            gtirb.SymbolicExpression.Attribute.GotRelPC
        },
        mcasm.mc.SymbolRefExpr.VariantKind.TPOFF: {
            gtirb.SymbolicExpression.Attribute.TpOff
        },
        mcasm.mc.SymbolRefExpr.VariantKind.NTPOFF: {
            gtirb.SymbolicExpression.Attribute.NtpOff
        },
        mcasm.mc.SymbolRefExpr.VariantKind.DTPOFF: {
            gtirb.SymbolicExpression.Attribute.DtpOff
        },
        mcasm.mc.SymbolRefExpr.VariantKind.TLSGD: {
            gtirb.SymbolicExpression.Attribute.TlsGd
        },
    }

    def __init__(self, state: "_State"):
        self._state = state
        super().__init__()

    def emit_label(self, parser_state, label, loc):
        label_sym = self._state.local_symbols[label.name]
        label_block = label_sym.referent
        assert isinstance(label_block, gtirb.CodeBlock)

        label_block.offset = (
            self._state.current_block.offset + self._state.current_block.size
        )
        self._state.cfg.add(
            gtirb.Edge(
                source=self._state.current_block,
                target=label_block,
                label=gtirb.Edge.Label(type=gtirb.Edge.Type.Fallthrough),
            )
        )

        self._state.current_section.blocks.append(label_block)

    def change_section(self, parser_state, section, subsection):
        name = section.name

        # LLVM validates that flags don't change when it sees the same section
        # multiple times, so we don't need to do that here.
        result = self._state.sections.get(name)
        if not result:
            flags: Set[gtirb.Section.Flag] = set()
            image_flags = 0
            image_type = 0

            if isinstance(section, mcasm.mc.SectionELF):
                SHF_WRITE = 0x1
                SHF_ALLOC = 0x2
                SHF_EXECINSTR = 0x4
                SHT_NOBITS = 8

                image_flags = section.flags
                image_type = section.type
                assert image_flags and image_type

                if image_flags & SHF_WRITE:
                    flags.add(gtirb.Section.Flag.Writable)

                if image_flags & SHF_ALLOC:
                    flags.add(gtirb.Section.Flag.Loaded)
                    flags.add(gtirb.Section.Flag.Readable)
                    if image_type != SHT_NOBITS:
                        flags.add(gtirb.Section.Flag.Initialized)

                if image_flags & SHF_EXECINSTR:
                    flags.add(gtirb.Section.Flag.Executable)

            elif isinstance(section, mcasm.mc.SectionCOFF):
                IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
                IMAGE_SCN_MEM_EXECUTE = 0x20000000
                IMAGE_SCN_MEM_READ = 0x40000000
                IMAGE_SCN_MEM_WRITE = 0x80000000

                image_flags = section.characteristics

                if image_flags & IMAGE_SCN_MEM_READ:
                    flags.add(gtirb.Section.Flag.Loaded)
                    flags.add(gtirb.Section.Flag.Readable)

                if image_flags & IMAGE_SCN_MEM_WRITE:
                    flags.add(gtirb.Section.Flag.Writable)

                if image_flags & IMAGE_SCN_MEM_EXECUTE:
                    flags.add(gtirb.Section.Flag.Executable)

                if not image_flags & IMAGE_SCN_CNT_UNINITIALIZED_DATA:
                    flags.add(gtirb.Section.Flag.Initialized)

            else:
                raise NotImplementedError(
                    f"unsupported section class {type(section)}"
                )

            result = Assembler.Result.Section(
                name=name,
                flags=flags,
                data=b"",
                blocks=[gtirb.CodeBlock()],
                symbolic_expressions={},
                symbolic_expression_sizes={},
                alignment={},
                image_flags=image_flags,
                image_type=image_type,
            )
            self._state.sections[name] = result

        self._state.optional_current_section = result
        super().change_section(parser_state, section, subsection)

    def emit_instruction(
        self,
        parser_state,
        inst: mcasm.mc.Instruction,
        data: bytes,
        fixups: List[mcasm.mc.Fixup],
    ) -> None:
        for fixup in fixups:
            pos = len(self._state.current_section.data) + fixup.offset
            self._state.current_section.symbolic_expressions[
                pos
            ] = self._fixup_to_symbolic_operand(
                fixup, data, inst.desc.is_call or inst.desc.is_branch
            )
            self._state.current_section.symbolic_expression_sizes[pos] = (
                fixup.kind_info.bit_size // 8
            )

        self._state.current_section.data += data
        self._state.current_block.size += len(data)
        self._state.blocks_with_code.add(self._state.current_block)

        if inst.desc.is_return:
            proxy = gtirb.ProxyBlock()
            self._state.proxies.add(proxy)
            self._state.cfg.add(
                gtirb.Edge(
                    source=self._state.current_block,
                    target=proxy,
                    label=gtirb.Edge.Label(type=gtirb.Edge.Type.Return),
                )
            )

            self._split_block()

        elif inst.desc.is_call or inst.desc.is_branch:
            direct, target = self._resolve_instruction_target(
                data, inst, fixups, parser_state.loc
            )

            if inst.desc.is_call:
                edge_label = gtirb.Edge.Label(
                    type=gtirb.Edge.Type.Call,
                    direct=direct,
                )
            elif inst.desc.is_branch:
                edge_label = gtirb.Edge.Label(
                    type=gtirb.Edge.Type.Branch,
                    conditional=inst.desc.is_conditional_branch,
                    direct=direct,
                )
            else:
                # This if/elif exhaustively covers the cases that let us into
                # the parent block, so this is just to shut up analysis tools
                # that don't understant that this is unreachable.
                assert False

            self._state.cfg.add(
                gtirb.Edge(
                    source=self._state.current_block,
                    target=target,
                    label=edge_label,
                )
            )

            # Currently we assume that all calls can return and that they need
            # a fallthrough edge.
            add_fallthrough = (
                inst.desc.is_call or inst.desc.is_conditional_branch
            )
            self._split_block(add_fallthrough=add_fallthrough)

    def emit_value_impl(self, parser_state, value, size, loc):
        self._state.current_section.symbolic_expressions[
            len(self._state.current_section.data)
        ] = self._mcexpr_to_symbolic_operand(value, False, loc)
        self._state.current_section.symbolic_expression_sizes[
            len(self._state.current_section.data)
        ] = size
        self._state.current_section.data += b"\x00" * size
        self._state.current_block.size += size

    def emit_bytes(self, parser_state, value):
        self._state.current_section.data += value
        self._state.current_block.size += len(value)

    def emit_value_to_alignment(
        self, parser_state, alignment, value, value_size, max_bytes
    ):
        self._emit_alignment(
            parser_state, alignment, value, value_size, max_bytes
        )

    def emit_code_alignment(self, parser_state, alignment, max_bytes):
        self._emit_alignment(parser_state, alignment, 0, 0, max_bytes)

    def _emit_alignment(
        self,
        parser_state: mcasm.ParserState,
        alignment: int,
        value: int,
        value_size: int,
        max_bytes: int,
    ) -> None:
        """
        Called when the assembler handles a .align directive.
        """

        if value != 0:
            raise _make_error(
                UnsupportedAssemblyError,
                "trying to pad with a non-zero byte",
                parser_state.loc,
            )

        if max_bytes != 0:
            raise _make_error(
                UnsupportedAssemblyError,
                "trying to pad with a fixed limit",
                parser_state.loc,
            )

        # The assembly parser usually checks this on our behalf, but be
        # cautious in case we ever add support for an architecture where
        # LLVM allows it.
        is_power_of_two = (alignment & (alignment - 1) == 0) and alignment > 0
        if not is_power_of_two:
            raise _make_error(
                UnsupportedAssemblyError,
                "alignment values must be powers of 2",
                parser_state.loc,
            )

        # Alignment can only be applied to the start of a block, so we need
        # to split the current block.
        if self._state.current_block.size:
            self._split_block(add_fallthrough=True)

        self._state.current_section.alignment[
            self._state.current_block
        ] = alignment

    def diagnostic(self, state, diag):
        if diag.kind == mcasm.mc.Diagnostic.Kind.Error:
            raise AsmSyntaxError(diag.message, diag.lineno, diag.offset)

    def unhandled_event(self, name, base_impl, *args, **kwargs):
        if name in {
            "init_sections",
            "add_explicit_comment",
            "emit_int_value",
        }:
            return super().unhandled_event(name, base_impl, *args, **kwargs)

        parser_state = args[0]
        raise _make_error(
            UnsupportedAssemblyError,
            f"{name} was not handled",
            parser_state.loc,
        )

    def _resolve_instruction_target(
        self,
        data: bytes,
        inst: mcasm.mc.Instruction,
        fixups: List[mcasm.mc.Fixup],
        loc: mcasm.mc.SourceLocation,
    ) -> Tuple[bool, gtirb.CfgNode]:
        """
        Resolves a call or branch instruction's target to a CFG node.
        """
        assert inst.desc.is_call or inst.desc.is_branch

        # LLVM doesn't seem to have anything to denote an indirect call, but
        # we can infer it from the lack of fixups.
        if inst.desc.is_indirect_branch or (inst.desc.is_call and not fixups):
            proxy = gtirb.ProxyBlock()
            self._state.proxies.add(proxy)
            return False, proxy

        assert len(fixups) == 1
        target_expr = self._fixup_to_symbolic_operand(fixups[0], data, True)

        if not isinstance(target_expr, gtirb.SymAddrConst):
            raise _make_error(
                UnsupportedAssemblyError,
                "Call and branch targets must be simple expressions",
                loc,
            )

        if target_expr.offset != 0:
            raise _make_error(
                UnsupportedAssemblyError,
                "Call and branch targets cannot have offsets",
                loc,
            )

        if not isinstance(target_expr.symbol.referent, gtirb.CfgNode):
            raise _make_error(
                UnsupportedAssemblyError,
                "Call and branch targets cannot be data blocks or other "
                "non-CFG elements",
                loc,
            )

        return True, target_expr.symbol.referent

    def _split_block(self, add_fallthrough: bool = False) -> gtirb.CodeBlock:
        """
        Starts a new block, optionally adding a fallthrough edge from the
        current block.
        """

        next_block = gtirb.CodeBlock(
            offset=self._state.current_block.offset
            + self._state.current_block.size
        )

        if add_fallthrough:
            self._state.cfg.add(
                gtirb.Edge(
                    source=self._state.current_block,
                    target=next_block,
                    label=gtirb.Edge.Label(type=gtirb.Edge.Type.Fallthrough),
                )
            )

        self._state.current_section.blocks.append(next_block)
        return next_block

    def _resolve_symbol(
        self, sym: mcasm.mc.Symbol, loc: Optional[mcasm.mc.SourceLocation]
    ) -> gtirb.Symbol:
        gt_sym = self._symbol_lookup(sym.name)

        if not gt_sym:
            if not self._state.allow_undef_symbols:
                raise _make_error(
                    UndefSymbolError,
                    f"{sym.name} is an undefined symbol reference",
                    loc,
                )

            proxy = gtirb.ProxyBlock()
            gt_sym = gtirb.Symbol(sym.name, payload=proxy)
            self._state.local_symbols[sym.name] = gt_sym
            self._state.proxies.add(proxy)

        return gt_sym

    def _resolve_symbol_ref(
        self, expr: mcasm.mc.SymbolRefExpr
    ) -> gtirb.Symbol:
        return self._resolve_symbol(expr.symbol, expr.location)

    def _get_symbol_ref_attrs(
        self,
        expr: mcasm.mc.SymbolRefExpr,
        sym: gtirb.Symbol,
        is_branch: bool,
    ) -> Set[gtirb.SymbolicExpression.Attribute]:
        attributes = set()
        if expr.variant_kind != mcasm.mc.SymbolRefExpr.VariantKind.None_:
            variant_attrs = self._ELF_VARIANT_KINDS.get(expr.variant_kind)
            if variant_attrs is None:
                name = expr.variant_kind.name
                raise _make_error(
                    UnsupportedAssemblyError,
                    f"unsupported symbol variant kind '{name}'",
                    expr.location,
                )
            attributes.update(variant_attrs)

        elif (
            self._state.module.isa
            in (gtirb.Module.ISA.IA32, gtirb.Module.ISA.X64)
            and _is_elf_pie(self._state.module)
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
        self,
        expr: mcasm.mc.Expr,
        is_branch: bool,
        loc: Optional[mcasm.mc.SourceLocation] = None,
    ) -> gtirb.SymbolicExpression:
        """
        Converts an MC expression to a GTIRB SymbolicExpression.
        """
        attributes = set()

        if isinstance(expr, mcasm.mc.TargetExprAArch64):
            elfName = expr.variant_kind_name
            if elfName == "":
                # LLVM wrapped the expression in a target-specific MCExpr, but
                # it doesn't effect the output assembly so we don't need to
                # create a symbolic expression attr for it.
                pass
            elif elfName == ":got:":
                attributes.add(gtirb.SymbolicExpression.Attribute.GotRef)
            elif elfName == ":lo12:":
                attributes.add(gtirb.SymbolicExpression.Attribute.Lo12)
            elif elfName == ":got_lo12:":
                attributes.add(gtirb.SymbolicExpression.Attribute.Lo12)
                attributes.add(gtirb.SymbolicExpression.Attribute.GotRef)
            else:
                raise _make_error(
                    UnsupportedAssemblyError,
                    f"unknown aarch64-specific fixup: {elfName}",
                    expr.location or loc,
                )
            expr = expr.sub_expr

        # TODO: Do we need to support SymAddrAddr fixup types?
        if (
            isinstance(expr, mcasm.mc.BinaryExpr)
            and expr.opcode == mcasm.mc.BinaryExpr.Opcode.Add
            and isinstance(expr.lhs, mcasm.mc.SymbolRefExpr)
            and isinstance(expr.rhs, mcasm.mc.ConstantExpr)
        ):
            sym = self._resolve_symbol_ref(expr.lhs)
            attributes |= self._get_symbol_ref_attrs(expr.lhs, sym, is_branch)
            offset = expr.rhs.value
            return gtirb.SymAddrConst(offset, sym, attributes)
        elif isinstance(expr, mcasm.mc.SymbolRefExpr):
            sym = self._resolve_symbol_ref(expr)
            attributes |= self._get_symbol_ref_attrs(expr, sym, is_branch)
            return gtirb.SymAddrConst(0, sym, attributes)

        raise _make_error(
            UnsupportedAssemblyError,
            "unsupported symbolic expression",
            expr.location or loc,
        )

    def _fixup_to_symbolic_operand(
        self, fixup: mcasm.mc.Fixup, encoding: bytes, is_branch: bool
    ) -> gtirb.SymbolicExpression:
        """
        Converts an LLVM fixup to a GTIRB SymbolicExpression.
        """
        expr = fixup.value

        # LLVM will automatically add a negative value to make the expression
        # be PC-relative. We don't care about that and just want to unwrap it.
        if (
            fixup.kind_info.is_pc_rel
            and isinstance(expr, mcasm.mc.BinaryExpr)
            and expr.opcode == mcasm.mc.BinaryExpr.Opcode.Add
            and isinstance(expr.rhs, mcasm.mc.ConstantExpr)
            and fixup.offset - expr.rhs.value == len(encoding)
        ):
            expr = expr.lhs

        return self._mcexpr_to_symbolic_operand(expr, is_branch)

    def _symbol_lookup(self, name: str) -> Optional[gtirb.Symbol]:
        """
        Looks up a symbol by name.

        :param name: The symbol's name.
        """

        sym = self._state.local_symbols.get(name, None)
        if sym:
            return sym

        sym = next(self._state.module.symbols_named(name), None)
        if sym and sym.module == self._state.module:
            return sym

        return None
