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
#
# pyright: strict, reportPrivateUsage=false

import dataclasses
import enum
import functools
import itertools
import warnings
from collections import defaultdict
from contextlib import contextmanager
from typing import (
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
    TypeVar,
    Union,
)

import gtirb
import gtirb_rewriting._auxdata as _auxdata
import mcasm
from typing_extensions import Concatenate, ParamSpec, Self

from ..assembly import X86Syntax
from ..utils import (
    OffsetMapping,
    _is_elf_pie,
    _is_fallthrough_edge,
    _target_triple,
)
from ._create_gtirb import create_gtirb as _create_gtirb
from ._mc_utils import is_indirect_call as _is_indirect_call


def _null_lookup(name: str) -> Iterator[gtirb.Symbol]:
    yield from ()


def _default_diag_callback(diag: "Diagnostic") -> bool:
    """
    The default diagnostic callback, which just says that the diagnostic was
    not handled.
    """
    return False


@dataclasses.dataclass
class Diagnostic:
    """
    A diagnostic issued while assembling input.
    """

    kind: "Kind"
    message: str
    lineno: Optional[int]
    offset: Optional[int]

    Kind = mcasm.mc.Diagnostic.Kind


DiagnosticCallback = Callable[[Diagnostic], bool]

_StreamerClass = TypeVar(
    "_StreamerClass", bound=Union["_SymbolCreator", "_Streamer"]
)
_RetT = TypeVar("_RetT")
_ParamsT = ParamSpec("_ParamsT")


def _convert_errors_and_return(
    error_ret: _RetT,
) -> Callable[
    [Callable[Concatenate[_StreamerClass, _ParamsT], _RetT]],
    Callable[Concatenate[_StreamerClass, _ParamsT], _RetT],
]:
    """
    A function decorator that converts assembler errors to diagnostics, calls
    the diagnostic callback, then potentially re-raises the error.
    """

    def decorator(
        func: Callable[Concatenate[_StreamerClass, _ParamsT], _RetT]
    ) -> Callable[Concatenate[_StreamerClass, _ParamsT], _RetT]:
        @functools.wraps(func)
        def impl(
            self: _StreamerClass,
            *args: _ParamsT.args,
            **kwargs: _ParamsT.kwargs,
        ) -> _RetT:
            try:
                return func(self, *args, **kwargs)
            except AssemblerError as exc:
                diag = Diagnostic(
                    Diagnostic.Kind.Error, str(exc), exc.lineno, exc.offset
                )
                if self._state.issue_diagnostic(diag):
                    return error_ret

                raise

        return impl

    return decorator


_convert_errors = _convert_errors_and_return(None)


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

    @classmethod
    def _make(
        cls, message: str, loc: Optional[mcasm.mc.SourceLocation]
    ) -> Self:
        """
        Makes an instance of the requested error with the right location info.
        """

        if loc:
            return cls(message, loc.lineno, loc.offset)
        else:
            return cls(message)


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


class IgnoredCFIDirectiveWarning(Warning):
    """
    A CFI directive was ignored.
    """

    pass


class IgnoredSymverDirectiveWarning(Warning):
    """
    A .symver directive was ignored.
    """

    pass


class Assembler:
    """
    Assembles chunks of assembly, creating a control flow graph and other
    GTIRB structures as it goes.
    """

    @dataclasses.dataclass
    class Target:
        """
        A description of the assembler's target.
        """

        isa: gtirb.Module.ISA
        file_format: gtirb.Module.FileFormat
        binary_type: List[str]
        is_elf_dynamic: bool
        symbol_lookup: Callable[[str], Iterator[gtirb.Symbol]] = _null_lookup

    class ModuleTarget(Target):
        """
        A target that references an existing module, with the intent being
        that the assembler result will be compatible with this module.
        """

        def __init__(self, module: gtirb.Module, detached: bool = False):
            binary_type = _auxdata.binary_type.get(module) or []
            super().__init__(
                isa=module.isa,
                file_format=module.file_format,
                binary_type=binary_type,
                is_elf_dynamic=any(
                    sect.name == ".dynamic" for sect in module.sections
                ),
                symbol_lookup=(
                    module.symbols_named if not detached else _null_lookup
                ),
            )

    def __init__(
        self,
        target: Union[gtirb.Module, Target],
        *,
        diagnostic_callback: Optional[DiagnosticCallback] = None,
        temp_symbol_suffix: Optional[str] = None,
        trivially_unreachable: bool = False,
        allow_undef_symbols: bool = False,
        ignore_cfi_directives: bool = False,
        ignore_symver_directives: bool = False,
    ) -> None:
        """
        :param target: The module the patch will be inserted into or a Target
                       object describing the target to assemble for.
        :param diagnostic_callback: A callable invoked when there is a
               Diagnostic issued. If the diagnostic's kind is an error,
               returning False from the callback will result in it being
               raised as an exception (the same behavior as when this callback
               is not specified).
        :param temp_symbol_suffix: A suffix to use for local symbols that are
               considered temporary. Passing in a unique suffix to each
               assembler that targets the same module allows the same assembly
               to be used each time without worrying about duplicate symbol
               names.
        :param trivially_unreachable: Is the entry block of the patch
                                      obviously unreachable? For example,
                                      inserting after a ret instruction.
        :param allow_undef_symbols: Allows the assembly to refer to undefined
                                    symbols. Such symbols will be created and
                                    set to refer to a proxy block.
        :param ignore_cfi_directives: Ignore CFI directives instead of issuing
                                      an error.
        :param ignore_symver_directives: Ignore symver directives instead of
                                         issuing an error.
        """

        if isinstance(target, gtirb.Module):
            target = self.ModuleTarget(target)

        self._state = _State(
            target,
            diagnostic_callback or _default_diag_callback,
            temp_symbol_suffix,
            trivially_unreachable,
            allow_undef_symbols,
            ignore_cfi_directives,
            ignore_symver_directives,
        )

    def assemble(
        self, asm: str, x86_syntax: X86Syntax = X86Syntax.ATT
    ) -> bool:
        """
        Assembles additional assembly, continuing where the last call to
        assemble left off.
        """

        self._state.had_error = False

        assembler = mcasm.Assembler(
            _target_triple(
                self._state.target.isa, self._state.target.file_format
            )
        )

        # X86 is hopefully the only ISA with more than one syntax mode that
        # is widely used. If other targets do come up, we may simply choose
        # a blessed syntax and avoid the additional complexity.
        if self._state.target.isa in (
            gtirb.Module.ISA.IA32,
            gtirb.Module.ISA.X64,
        ):
            assembler.x86_syntax = x86_syntax

        assembler.assemble(_SymbolCreator(self._state), asm)

        assembler.assemble(_Streamer(self._state), asm)

        return not self._state.had_error

    def _make_referent_index(self) -> Dict[gtirb.Block, Set[gtirb.Symbol]]:
        """
        Creates a map of blocks to their symbols.
        """

        result: Dict[gtirb.Block, Set[gtirb.Symbol]] = defaultdict(set)
        for sym in self._state.local_symbols.values():
            if sym.referent:
                result[sym.referent].add(sym)

        return result

    def _replace_symbol_referents(
        self,
        index: Dict[gtirb.Block, Set[gtirb.Symbol]],
        old_block: gtirb.Block,
        new_block: gtirb.Block,
        make_at_end: bool = False,
    ) -> None:
        """
        Alters all symbols referring to an old block to refer to a new block.
        """
        sym_set = index[old_block]
        for sym in sym_set:
            sym.referent = new_block
            if make_at_end:
                sym.at_end = True
        index[new_block].update(sym_set)
        sym_set.clear()

    def _remove_empty_blocks(
        self,
        section: "Assembler.Result.Section",
        index: Dict[gtirb.Block, Set[gtirb.Symbol]],
    ) -> None:
        """
        Cleans up all the empty blocks we may have generated during assembly.

        For example, this code generates an empty block for the 'foo' label:
            foo:
            bar:
                ud2
        """

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
                assert extra_block not in self._state.block_types

                for edge in list(self._state.cfg.in_edges(extra_block)):
                    assert isinstance(edge.source, gtirb.CodeBlock)

                    self._state.cfg.discard(edge)
                    if edge.source not in extra_blocks:
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

                self._replace_symbol_referents(index, extra_block, main_block)

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
        self,
        section: "Assembler.Result.Section",
        index: Dict[gtirb.Block, Set[gtirb.Symbol]],
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
                    offset=block.offset, size=block.size, uuid=block.uuid
                )
                self._replace_symbol_referents(index, block, new_block)
                for out_edge in set(self._state.cfg.out_edges(block)):
                    assert _is_fallthrough_edge(out_edge)
                    self._state.cfg.discard(out_edge)
                section.blocks[i] = new_block
                if block in section.alignment:
                    section.alignment[new_block] = section.alignment[block]
                    del section.alignment[block]

                if block in self._state.block_types:
                    section.block_types[new_block] = self._state.block_types[
                        block
                    ]

                if block in section.line_map:
                    section.line_map[new_block] = section.line_map[block]
                    del section.line_map[block]

            else:
                # If we're not replacing the code block with a data block and
                # it had a specific block type, this is a problem. It's too
                # late to issue a specific error here but we can at least
                # catch the problem.
                block_type = self._state.block_types.get(block)
                if block_type and self._is_required_block_type(block_type):
                    raise UnsupportedAssemblyError(
                        "A code block was given a data type (e.g. via uleb128)"
                    )

    def _is_required_block_type(
        self, type: "Assembler.Result.DataType"
    ) -> bool:
        """
        Is this block type required for correctness or can it be dropped?
        """
        return type in {
            Assembler.Result.DataType.ULEB128,
            Assembler.Result.DataType.SLEB128,
        }

    def _remove_trailing_empty_block(
        self,
        section: "Assembler.Result.Section",
        index: Dict[gtirb.Block, Set[gtirb.Symbol]],
    ) -> None:
        """
        Attempt to remove an empty block at the end of the section.
        """

        def drop_block():
            last_block = section.blocks.pop()
            section.alignment.pop(last_block, None)
            # Empty blocks shouldn't be able to be in any of these
            assert last_block not in section.line_map
            assert last_block not in section.block_types
            assert not index.get(last_block)

        is_empty = not section.blocks[-1].size
        is_reachable = isinstance(section.blocks[-1], gtirb.CodeBlock) and any(
            self._state.cfg.in_edges(section.blocks[-1])
        )
        is_referenced = index.get(section.blocks[-1]) is not None
        has_other_blocks = len(section.blocks) >= 2

        if is_empty and not is_reachable and not is_referenced:
            # If there's nothing reaching or referring to this, we can just
            # drop it.
            drop_block()
        elif is_empty and not is_reachable and has_other_blocks:
            # Otherwise, if nothing reaches this but it has a symbol, make the
            # symbol be an at_end symbol for the previous block.
            self._replace_symbol_referents(
                index, section.blocks[-1], section.blocks[-2], make_at_end=True
            )
            drop_block()

    def finalize(self) -> "Result":
        """
        Finalizes the assembly contents and returns the result.
        """

        index = self._make_referent_index()
        for section in self._state.sections.values():
            self._remove_empty_blocks(section, index)
            self._convert_data_blocks(section, index)
            self._remove_trailing_empty_block(section, index)

        result = self.Result(
            target=self._state.target,
            sections=self._state.sections,
            cfg=self._state.cfg,
            symbols=list(self._state.local_symbols.values()),
            proxies=self._state.proxies,
            elf_symbol_attributes=self._state.elf_symbol_attributes,
        )

        # Reinitialize the assembler just in case someone tries to use the
        # object again.
        self._state = _State(
            self._state.target,
            diagnostic_callback=self._state.diagnostic_callback,
            temp_symbol_suffix=self._state.temp_symbol_suffix,
            trivially_unreachable=self._state.trivially_unreachable,
            allow_undef_symbols=self._state.allow_undef_symbols,
            ignore_cfi_directives=self._state.ignore_cfi_directives,
            ignore_symver_directives=self._state.ignore_symver_directives,
        )

        return result

    @dataclasses.dataclass
    class Result:
        """
        The result of assembling an assembly patch.
        """

        class DataType(str, enum.Enum):
            ULEB128 = "uleb128"
            SLEB128 = "sleb128"
            String = "string"
            ASCII = "ascii"

        @dataclasses.dataclass
        class Section:
            name: str

            flags: Set[gtirb.Section.Flag] = dataclasses.field(
                default_factory=set
            )
            """
            Section flags.
            """

            data: bytes = b""
            """
            The encoded bytes from assembling the patch.
            """

            blocks: List[gtirb.ByteBlock] = dataclasses.field(
                default_factory=list
            )
            """
            All blocks, in order of offset, for the patch. There will be at
            most one empty block, which will be at the end of the list.
            """

            symbolic_expressions: Dict[
                int, gtirb.SymbolicExpression
            ] = dataclasses.field(default_factory=dict)
            """
            A map of offset to symbolic expression, with 0 being the start of
            `data`.
            """

            symbolic_expression_sizes: Dict[int, int] = dataclasses.field(
                default_factory=dict
            )
            """
            A map of offset to symbolic expression size, with 0 being the
            start of `data`.
            """

            alignment: Dict[gtirb.ByteBlock, int] = dataclasses.field(
                default_factory=dict
            )
            """
            A map of block to the requested alignment of the block. Padding is
            not inserted in the data, so the blocks may not currently be at
            this alignment.
            """

            image_type: int = 0
            """
            The ELF type for the section. For ELF this is SHT_* values. For PE
            this is ignored.
            """

            image_flags: int = 0
            """
            The ELF/PE flags for the section. For ELF this is SHF_* flags, for
            PE this is IMAGE_SCN_* flags.
            """

            block_types: Dict[
                gtirb.DataBlock, "Assembler.Result.DataType"
            ] = dataclasses.field(default_factory=dict)
            """
            The types for data blocks that must be rendered a certain way.
            """

            line_map: OffsetMapping[int] = dataclasses.field(
                default_factory=OffsetMapping
            )
            """
            A mapping of byte offset to the line of assembly that produced it.
            """

        @dataclasses.dataclass
        class ElfSymbolAttributes:
            type: str = "NOTYPE"
            binding: str = "LOCAL"
            visibility: str = "DEFAULT"

        target: "Assembler.Target"
        """
        The target that this result was created for.
        """

        sections: Dict[str, Section]
        """
        Sections in the patch. The first section will be the text section.
        """

        cfg: gtirb.CFG = dataclasses.field(default_factory=gtirb.CFG)
        """
        The control flow graph for the patch.
        """

        symbols: List[gtirb.Symbol] = dataclasses.field(default_factory=list)
        """
        Symbols that were defined in the patch.
        """

        proxies: Set[gtirb.ProxyBlock] = dataclasses.field(default_factory=set)
        """
        Proxy blocks that represent unknown targets.
        """

        elf_symbol_attributes: Dict[
            gtirb.Symbol, ElfSymbolAttributes
        ] = dataclasses.field(default_factory=dict)
        """
        ELF symbol type and binding information.
        """

        @property
        def text_section(self) -> Section:
            return next(iter(self.sections.values()))

        def create_ir(self) -> gtirb.IR:
            """
            Creates a new GTIRB IR with the contents of this result.
            """
            return _create_gtirb(self)


@dataclasses.dataclass
class _State:
    """
    All of the state that the assembler accumulates across calls to assemble
    and is used by the streamer classes.
    """

    target: Assembler.Target
    diagnostic_callback: DiagnosticCallback
    temp_symbol_suffix: Optional[str]
    trivially_unreachable: bool
    allow_undef_symbols: bool
    ignore_cfi_directives: bool
    ignore_symver_directives: bool
    had_error: bool = False
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
    elf_symbol_attributes: Dict[
        gtirb.Symbol, "Assembler.Result.ElfSymbolAttributes"
    ] = dataclasses.field(
        default_factory=lambda: defaultdict(
            Assembler.Result.ElfSymbolAttributes
        )
    )
    block_types: Dict[
        gtirb.ByteBlock, "Assembler.Result.DataType"
    ] = dataclasses.field(default_factory=dict)

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

    def issue_diagnostic(self, diag: Diagnostic) -> bool:
        if diag.kind == Diagnostic.Kind.Error:
            self.had_error = True

        return self.diagnostic_callback(diag)


class _SymbolCreator(mcasm.Streamer):
    """
    A streamer that just takes care of precreating defined symbols.
    """

    def __init__(self, state: "_State"):
        self._state = state
        super().__init__()

    @_convert_errors
    def emit_label(
        self,
        state: mcasm.ParserState,
        symbol: mcasm.mc.Symbol,
        loc: mcasm.mc.SourceLocation,
    ) -> None:
        self._precreate_label(state, symbol)

    @_convert_errors
    def emit_assignment(
        self,
        state: mcasm.ParserState,
        symbol: mcasm.mc.Symbol,
        value: mcasm.mc.Expr,
    ) -> None:
        if isinstance(value, mcasm.mc.ConstantExpr):
            gt_sym = self._precreate_label(state, symbol)
            gt_sym.value = value.value
        else:
            # There are interesting uses of assignments that would be nice to
            # support but that GTIRB cannot represent. For example:
            #   .data
            #   str1:
            #   .string "Hello"
            #   str1_len = (. - str1)
            #   .text
            #   movl $str1_len, %eax
            raise UnsupportedAssemblyError._make(
                "only constant expressions can be used in assignments",
                value.location or state.loc,
            )

    def _precreate_label(
        self, parser_state: mcasm.ParserState, label: mcasm.mc.Symbol
    ) -> gtirb.Symbol:
        # If the symbol is temporary in LLVM's eyes and our client has
        # given us a suffix to use for temporary symbols, tack it on. This
        # allows clients to use the same assembly multiple times without
        # worrying about duplicate symbol names, as long as they pass a
        # different suffix each time.
        symbol_name = label.name
        if label.is_temporary and self._state.temp_symbol_suffix is not None:
            symbol_name += self._state.temp_symbol_suffix

        if label.name in self._state.local_symbols or any(
            self._state.target.symbol_lookup(label.name)
        ):
            raise MultipleDefinitionsError._make(
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
    _ELF_BINDINGS = {
        mcasm.mc.SymbolAttr.Global: "GLOBAL",
        mcasm.mc.SymbolAttr.Weak: "WEAK",
        mcasm.mc.SymbolAttr.Local: "LOCAL",
        mcasm.mc.SymbolAttr.ELF_TypeGnuUniqueObject: "GNU_UNIQUE",
    }
    _ELF_VISIBILITIES = {
        mcasm.mc.SymbolAttr.Hidden: "HIDDEN",
        mcasm.mc.SymbolAttr.Protected: "PROTECTED",
        mcasm.mc.SymbolAttr.Internal: "INTERNAL",
    }
    _ELF_TYPES = {
        mcasm.mc.SymbolAttr.ELF_TypeFunction: "FUNC",
        mcasm.mc.SymbolAttr.ELF_TypeIndFunction: "GNU_IFUNC",
        mcasm.mc.SymbolAttr.ELF_TypeNoType: "NOTYPE",
        mcasm.mc.SymbolAttr.ELF_TypeObject: "OBJECT",
        mcasm.mc.SymbolAttr.ELF_TypeTLS: "TLS",
    }

    def __init__(self, state: "_State"):
        self._state = state
        self._prevent_print_as_string_count = 0
        super().__init__()

    def _append_data(self, data: bytes, loc: mcasm.mc.SourceLocation) -> None:
        """
        Appends data to the current block. This should be the only way that
        the section's data is modified.
        """
        offset = len(self._state.current_section.data)
        self._state.current_section.line_map[
            gtirb.Offset(
                self._state.current_block,
                offset - self._state.current_block.offset,
            )
        ] = loc.lineno
        self._state.current_section.data += data
        self._state.current_block.size += len(data)

    @_convert_errors
    def emit_label(
        self,
        state: mcasm.ParserState,
        symbol: mcasm.mc.Symbol,
        loc: mcasm.mc.SourceLocation,
    ) -> None:
        label_sym = self._state.local_symbols[symbol.name]
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

    @_convert_errors
    def change_section(
        self,
        state: mcasm.ParserState,
        section: mcasm.mc.Section,
        subsection: Optional[mcasm.mc.Expr],
    ) -> None:
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
                block_types={},
                line_map=OffsetMapping(),
            )
            self._state.sections[name] = result

        self._state.optional_current_section = result
        super().change_section(
            state,
            section,
            subsection,
        )

    @_convert_errors
    def emit_instruction(
        self,
        state: mcasm.ParserState,
        inst: mcasm.mc.Instruction,
        data: bytes,
        fixups: List[mcasm.mc.Fixup],
    ) -> None:
        for fixup in fixups:
            pos = len(self._state.current_section.data) + fixup.offset
            self._state.current_section.symbolic_expressions[
                pos
            ] = self._fixup_to_symbolic_operand(
                fixup,
                data,
                inst.desc.is_call or inst.desc.is_branch,
                state.loc,
            )
            self._state.current_section.symbolic_expression_sizes[pos] = (
                fixup.kind_info.bit_size // 8
            )

        self._append_data(data, state.loc)
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
                data, inst, fixups, state.loc
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

    @_convert_errors
    def emit_value_impl(
        self,
        state: mcasm.ParserState,
        value: mcasm.mc.Expr,
        size: int,
        loc: mcasm.mc.SourceLocation,
    ) -> None:
        self._state.current_section.symbolic_expressions[
            len(self._state.current_section.data)
        ] = self._mcexpr_to_symbolic_operand(value, False, loc)
        self._state.current_section.symbolic_expression_sizes[
            len(self._state.current_section.data)
        ] = size
        self._append_data(b"\x00" * size, state.loc)

    def _emit_value_with_encoding(
        self,
        parser_state: mcasm.ParserState,
        value: Union[mcasm.mc.Expr, bytes],
        type: Assembler.Result.DataType,
    ) -> None:
        # gtirb can only apply an encoding to a data block, so we need for
        # this value to be in its own block.
        self._split_block()
        if isinstance(value, mcasm.mc.Expr):
            self.emit_value_impl(parser_state, value, 1, parser_state.loc)
        else:
            self._append_data(value, parser_state.loc)
        self._state.block_types[self._state.current_block] = type
        self._split_block()

    @_convert_errors
    def emit_uleb128_value(
        self, state: mcasm.ParserState, value: mcasm.mc.Expr
    ) -> None:
        self._emit_value_with_encoding(
            state, value, Assembler.Result.DataType.ULEB128
        )

    @_convert_errors
    def emit_sleb128_value(
        self, state: mcasm.ParserState, value: mcasm.mc.Expr
    ) -> None:
        self._emit_value_with_encoding(
            state, value, Assembler.Result.DataType.SLEB128
        )

    @contextmanager
    def _prevent_print_as_string(self):
        """
        A context manager that prevents emit_bytes from printing a value as
        a string.
        """

        self._prevent_print_as_string_count += 1
        try:
            yield
        finally:
            self._prevent_print_as_string_count -= 1

    def _try_terminate_previous_ascii_block(
        self, parser_state: mcasm.ParserState, value: bytes
    ) -> bool:
        """
        Attempt to terminate the previous string block. This is required
        because LLVM's string parser calls emit_bytes twice for a
        NUL-terminated string -- once for the contents and once for the NUL.
        """

        # We required that:
        # - the value is a NUL
        # - the current block is empty
        # - we have a previous block
        # - the previous block's type is ASCII
        if value != b"\x00":
            return False

        if self._state.current_block.size:
            return False

        if len(self._state.current_section.blocks) < 2:
            return False

        prev_block = self._state.current_section.blocks[-2]
        prev_block_type = self._state.block_types.get(prev_block)
        if prev_block_type != Assembler.Result.DataType.ASCII:
            return False

        current_block = self._state.current_section.blocks.pop()
        self._append_data(b"\x00", parser_state.loc)
        self._state.block_types[prev_block] = Assembler.Result.DataType.String

        current_block.offset += 1
        self._state.current_section.blocks.append(current_block)

        return True

    @_convert_errors
    def emit_bytes(self, state: mcasm.ParserState, data: bytes) -> None:
        if not self._prevent_print_as_string_count:
            if self._try_terminate_previous_ascii_block(state, data):
                return

            self._emit_value_with_encoding(
                state, data, Assembler.Result.DataType.ASCII
            )
        else:
            self._append_data(data, state.loc)

    @_convert_errors
    def emit_int_value(
        self, state: mcasm.ParserState, value: int, size: int
    ) -> None:
        # emit_int_value ends up calling emit_bytes, but we don't want it to
        # print the int bytes as a string.
        with self._prevent_print_as_string():
            super().emit_int_value(state, value, size)

    @_convert_errors
    def emit_value_fill(
        self,
        state: mcasm.ParserState,
        num_bytes: mcasm.mc.Expr,
        fill_value: int,
        loc: mcasm.mc.SourceLocation,
    ) -> None:
        if not isinstance(num_bytes, mcasm.mc.ConstantExpr):
            raise UnsupportedAssemblyError._make(
                "only constant integers are supported for fill sizes",
                num_bytes.location,
            )

        # By limiting the fill value to 0, we avoid questions about what to
        # do if the fill value is multi-byte. This restriction could be lifted
        # later.
        if fill_value != 0:
            raise UnsupportedAssemblyError._make(
                "only 0 is supported for a fill value",
                num_bytes.location,
            )

        self._append_data(bytes(num_bytes.value), state.loc)

    @_convert_errors
    def emit_value_to_alignment(
        self,
        state: mcasm.ParserState,
        byte_alignment: int,
        value: int,
        value_size: int,
        max_bytes_to_emit: int,
    ) -> None:
        self._emit_alignment(
            state, byte_alignment, value, value_size, max_bytes_to_emit
        )

    @_convert_errors
    def emit_code_alignment(
        self,
        state: mcasm.ParserState,
        byte_alignment: int,
        max_bytes_to_emit: int,
    ) -> None:
        self._emit_alignment(state, byte_alignment, 0, 0, max_bytes_to_emit)

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
            raise UnsupportedAssemblyError._make(
                "trying to pad with a non-zero byte",
                parser_state.loc,
            )

        if max_bytes != 0:
            raise UnsupportedAssemblyError._make(
                "trying to pad with a fixed limit",
                parser_state.loc,
            )

        # The assembly parser usually checks this on our behalf, but be
        # cautious in case we ever add support for an architecture where
        # LLVM allows it.
        is_power_of_two = (alignment & (alignment - 1) == 0) and alignment > 0
        if not is_power_of_two:
            raise UnsupportedAssemblyError._make(
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

    @_convert_errors_and_return(True)
    def emit_symbol_attribute(
        self,
        state: mcasm.ParserState,
        symbol: mcasm.mc.Symbol,
        attribute: mcasm.mc.SymbolAttr,
    ) -> bool:
        if self._state.target.file_format == gtirb.Module.FileFormat.ELF:
            return self._emit_elf_symbol_attribute(
                self._resolve_symbol(symbol, state.loc), attribute
            )

        # Returning False here will result in LLVM issuing a diagnostic about
        # the unsupported symbol attribute, so we don't need to raise an error.
        return False

    def _emit_elf_symbol_attribute(
        self, symbol: gtirb.Symbol, attribute: mcasm.mc.SymbolAttr
    ) -> bool:
        if attribute in self._ELF_BINDINGS:
            self._state.elf_symbol_attributes[
                symbol
            ].binding = self._ELF_BINDINGS[attribute]
            return True

        if attribute in self._ELF_VISIBILITIES:
            self._state.elf_symbol_attributes[
                symbol
            ].visibility = self._ELF_VISIBILITIES[attribute]
            return True

        if attribute in self._ELF_TYPES:
            self._state.elf_symbol_attributes[symbol].type = self._ELF_TYPES[
                attribute
            ]
            return True

        if attribute == mcasm.mc.SymbolAttr.NoDeadStrip:
            return True

        return False

    def diagnostic(
        self, state: mcasm.ParserState, diag: mcasm.mc.Diagnostic
    ) -> None:
        handled = self._state.issue_diagnostic(
            Diagnostic(diag.kind, diag.message, diag.lineno, diag.offset)
        )

        if not handled and diag.kind == mcasm.mc.Diagnostic.Kind.Error:
            raise AsmSyntaxError(diag.message, diag.lineno, diag.offset)

    @_convert_errors
    def unhandled_event(
        self, name: str, base_impl: Any, *args: Any, **kwargs: Any
    ) -> Any:
        if "cfi" in name and self._state.ignore_cfi_directives:
            warnings.warn(f"{name} was ignored", IgnoredCFIDirectiveWarning)
            return super().unhandled_event(  # pyright: ignore
                name, base_impl, *args, **kwargs
            )

        if (
            name == "emit_elf_symver_directive"
            and self._state.ignore_symver_directives
        ):
            warnings.warn(f"{name} was ignored", IgnoredSymverDirectiveWarning)
            return super().unhandled_event(  # pyright: ignore
                name, base_impl, *args, **kwargs
            )

        if name in {
            "init_sections",
            "add_explicit_comment",
            "emit_int_value",
            "emit_assignment",
        }:
            return super().unhandled_event(  # pyright: ignore
                name, base_impl, *args, **kwargs
            )

        parser_state: mcasm.ParserState = args[0]
        raise UnsupportedAssemblyError._make(
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

        if inst.desc.is_indirect_branch or _is_indirect_call(
            self._state.target.isa, inst
        ):
            proxy = gtirb.ProxyBlock()
            self._state.proxies.add(proxy)
            return False, proxy

        assert len(fixups) == 1
        target_expr = self._fixup_to_symbolic_operand(
            fixups[0], data, True, loc
        )

        if not isinstance(target_expr, gtirb.SymAddrConst):
            raise UnsupportedAssemblyError._make(
                "Call and branch targets must be simple expressions",
                loc,
            )

        if target_expr.offset != 0:
            raise UnsupportedAssemblyError._make(
                "Call and branch targets cannot have offsets",
                loc,
            )

        if not isinstance(target_expr.symbol.referent, gtirb.CfgNode):
            raise UnsupportedAssemblyError._make(
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
                raise UndefSymbolError._make(
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
        attributes: Set[gtirb.SymbolicExpression.Attribute] = set()
        if expr.variant_kind != mcasm.mc.SymbolRefExpr.VariantKind.None_:
            variant_attrs = self._ELF_VARIANT_KINDS.get(expr.variant_kind)
            if variant_attrs is None:
                name = expr.variant_kind.name
                raise UnsupportedAssemblyError._make(
                    f"unsupported symbol variant kind '{name}'",
                    expr.location,
                )
            attributes.update(variant_attrs)

        elif (
            self._state.target.isa
            in (gtirb.Module.ISA.IA32, gtirb.Module.ISA.X64)
            and _is_elf_pie(
                self._state.target.file_format, self._state.target.binary_type
            )
            and isinstance(sym.referent, gtirb.ProxyBlock)
            and is_branch
        ):
            # These appear to only be necessary for X86 ELF, so we're limiting
            # the inference to that.
            attributes.add(gtirb.SymbolicExpression.Attribute.PltRef)

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
        attributes: Set[gtirb.SymbolicExpression.Attribute] = set()

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
                raise UnsupportedAssemblyError._make(
                    f"unknown aarch64-specific fixup: {elfName}",
                    expr.location or loc,
                )
            expr = expr.sub_expr

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
        elif (
            isinstance(expr, mcasm.mc.BinaryExpr)
            and expr.opcode == mcasm.mc.BinaryExpr.Opcode.Sub
            and isinstance(expr.lhs, mcasm.mc.SymbolRefExpr)
            and isinstance(expr.rhs, mcasm.mc.SymbolRefExpr)
        ):
            sym1 = self._resolve_symbol_ref(expr.lhs)
            if (
                expr.lhs.variant_kind
                != mcasm.mc.SymbolRefExpr.VariantKind.None_
            ):
                raise UnsupportedAssemblyError._make(
                    "cannot have a binary expression with variant kinds",
                    expr.lhs.location or loc,
                )

            sym2 = self._resolve_symbol_ref(expr.rhs)
            if (
                expr.rhs.variant_kind
                != mcasm.mc.SymbolRefExpr.VariantKind.None_
            ):
                raise UnsupportedAssemblyError._make(
                    "cannot have a binary expression with variant kinds",
                    expr.rhs.location or loc,
                )

            return gtirb.SymAddrAddr(1, 0, sym1, sym2, set())
        elif isinstance(expr, mcasm.mc.SymbolRefExpr):
            sym = self._resolve_symbol_ref(expr)
            attributes |= self._get_symbol_ref_attrs(expr, sym, is_branch)
            return gtirb.SymAddrConst(0, sym, attributes)

        raise UnsupportedAssemblyError._make(
            "unsupported symbolic expression",
            expr.location or loc,
        )

    def _fixup_to_symbolic_operand(
        self,
        fixup: mcasm.mc.Fixup,
        encoding: bytes,
        is_branch: bool,
        loc: mcasm.mc.SourceLocation,
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

        return self._mcexpr_to_symbolic_operand(expr, is_branch, loc)

    def _symbol_lookup(self, name: str) -> Optional[gtirb.Symbol]:
        """
        Looks up a symbol by name.

        :param name: The symbol's name.
        """

        sym = self._state.local_symbols.get(name, None)
        if sym:
            return sym

        sym = next(self._state.target.symbol_lookup(name), None)
        if sym:
            return sym

        return None
