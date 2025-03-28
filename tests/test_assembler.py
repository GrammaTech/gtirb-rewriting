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

import pathlib
import textwrap
from contextlib import contextmanager
from enum import Enum, auto
from typing import Iterator, Tuple, Type
from unittest.mock import Mock

import gtirb
import pytest
from gtirb_test_helpers import (
    add_data_block,
    add_proxy_block,
    add_symbol,
    add_text_section,
    create_test_module,
)

import gtirb_rewriting
from gtirb_rewriting._auxdata import NULL_UUID
from gtirb_rewriting.assembler.__main__ import main as gtirb_as

if gtirb.version.PROTOBUF_VERSION < 4:
    import gtirb_rewriting.gtirb_protobuf_compat.proto_3 as compat_proto
else:
    import gtirb_rewriting.gtirb_protobuf_compat.proto_4 as compat_proto


def test_return_edges():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64, binary_type=["DYN"]
    )

    assembler = gtirb_rewriting.Assembler(m)
    assembler.assemble(
        "ret",
        gtirb_rewriting.X86Syntax.INTEL,
    )
    result = assembler.finalize()
    text_section = result.text_section

    assert len(text_section.blocks) == 1
    assert text_section.blocks[0].offset == 0
    assert text_section.blocks[0].size == 1

    edges = list(result.cfg.out_edges(text_section.blocks[0]))
    assert len(edges) == 1
    assert edges[0].label.type == gtirb.Edge.Type.Return
    assert isinstance(edges[0].target, gtirb.ProxyBlock)
    assert edges[0].target in result.proxies

    assert text_section.data == b"\xC3"


def test_empty_label():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )

    assembler = gtirb_rewriting.Assembler(m, implicit_cfi_procedure=True)
    assembler.assemble(
        """
            foo:
                .cfi_undefined 0
            bar:
                jmp foo
                ud2
        """
    )
    result = assembler.finalize()

    assert len(result.symbols) == 2
    foo_sym = next(sym for sym in result.symbols if sym.name == "foo")
    bar_sym = next(sym for sym in result.symbols if sym.name == "bar")

    assert len(result.text_section.blocks) == 2
    b, _ = result.text_section.blocks
    assert isinstance(b, gtirb.CodeBlock)
    assert foo_sym.referent is bar_sym.referent is b

    assert result.text_section.blocks[0].size
    assert set(result.cfg) == {
        gtirb.Edge(
            b,
            b,
            gtirb.Edge.Label(gtirb.Edge.Type.Branch),
        )
    }
    assert result.text_section.cfi_procedures == [
        gtirb_rewriting.Assembler.Result.CFIProcedure(
            is_implicit=True,
            start_offset=None,
            end_offset=None,
            instructions=gtirb_rewriting.OffsetMapping(
                {
                    gtirb.Offset(b, 0): [(".cfi_undefined", [0], NULL_UUID)],
                }
            ),
        )
    ]


def test_empty_blocks():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    add_symbol(m, "foo", add_proxy_block(m))

    assembler = gtirb_rewriting.Assembler(m)
    assembler.assemble(
        """
                jmp foo
            bar:
                .align 8
                # This block has no control flow or contents, but a label.

            .data
            .string "hi"
                # This block will be empty and can be removed.

            .bss
                call foo
                # This empty block will have incoming control flow and we need
                # to preserve that.
        """
    )
    result = assembler.finalize()

    assert len(result.symbols) == 1
    bar_sym = next(sym for sym in result.symbols if sym.name == "bar")

    text_section = result.text_section
    assert len(text_section.blocks) == 1
    assert bar_sym.referent is text_section.blocks[0]
    assert bar_sym.at_end
    assert text_section.blocks[0].size == 2
    assert not text_section.alignment

    data_section = result.sections[".data"]
    assert len(data_section.blocks) == 1
    assert data_section.blocks[0].size == 3

    bss_section = result.sections[".bss"]
    assert len(bss_section.blocks) == 2
    assert bss_section.blocks[0].size == 5
    assert not bss_section.blocks[1].size


def test_symbolic_expr():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64, binary_type=["DYN"]
    )
    puts_sym = add_symbol(m, "puts", add_proxy_block(m))

    assembler = gtirb_rewriting.Assembler(m)
    assembler.assemble(
        "call puts",
        gtirb_rewriting.X86Syntax.INTEL,
    )
    result = assembler.finalize()
    text_section = result.text_section

    assert len(text_section.symbolic_expressions) == 1
    sym_expr = text_section.symbolic_expressions[1]
    assert isinstance(sym_expr, gtirb.SymAddrConst)
    assert sym_expr.symbol == puts_sym
    assert sym_expr.offset == 0
    assert sym_expr.attributes == {compat_proto.PLT}
    assert text_section.symbolic_expression_sizes == {1: 4}


def test_symbolic_expr_sym_offset():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64, binary_type=["DYN"]
    )
    puts_sym = add_symbol(m, "puts", add_proxy_block(m))

    assembler = gtirb_rewriting.Assembler(m)
    assembler.assemble(
        "inc byte ptr [puts + 42]",
        gtirb_rewriting.X86Syntax.INTEL,
    )
    result = assembler.finalize()
    text_section = result.text_section

    assert len(text_section.symbolic_expressions) == 1
    sym_expr = text_section.symbolic_expressions[3]
    assert isinstance(sym_expr, gtirb.SymAddrConst)
    assert sym_expr.symbol == puts_sym
    assert sym_expr.offset == 42
    assert not sym_expr.attributes


def test_byte_directive_as_code_due_to_entrypoint():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )

    assembler = gtirb_rewriting.Assembler(m)
    assembler.assemble(
        """
        .byte 0x66
        .byte 0x90
        """,
        gtirb_rewriting.X86Syntax.INTEL,
    )
    result = assembler.finalize()
    text_section = result.text_section

    assert len(text_section.blocks) == 1
    assert isinstance(text_section.blocks[0], gtirb.CodeBlock)
    assert text_section.blocks[0].size == 2
    assert text_section.data == b"\x66\x90"


def test_byte_directive_as_code_due_to_cfg():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64, binary_type=["DYN"]
    )

    # This gets treated as code because control flow can execute it.
    assembler = gtirb_rewriting.Assembler(m)
    assembler.assemble(
        """
        jne .L_foo
        .byte 0x66
        .byte 0x90
        .L_foo:
        """,
        gtirb_rewriting.X86Syntax.INTEL,
    )
    result = assembler.finalize()
    text_section = result.text_section

    assert len(text_section.blocks) == 3
    assert isinstance(text_section.blocks[0], gtirb.CodeBlock)
    assert text_section.blocks[0].offset == 0
    assert text_section.blocks[0].size == 2

    assert isinstance(text_section.blocks[1], gtirb.CodeBlock)
    assert text_section.blocks[1].offset == 2
    assert text_section.blocks[1].size == 2

    assert isinstance(text_section.blocks[2], gtirb.CodeBlock)
    assert text_section.blocks[2].offset == 4
    assert text_section.blocks[2].size == 0

    assert text_section.data == b"\x75\x00\x66\x90"


def test_byte_directive_as_code_due_to_mixing():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64, binary_type=["DYN"]
    )

    # This gets treated as code because it has other code in the block.
    assembler = gtirb_rewriting.Assembler(m)
    assembler.assemble(
        """
        jmp .L_foo
        .byte 0x66
        .byte 0x90
        inc eax
        .L_foo:
        """,
        gtirb_rewriting.X86Syntax.INTEL,
    )
    result = assembler.finalize()
    text_section = result.text_section

    assert len(text_section.blocks) == 3
    assert isinstance(text_section.blocks[0], gtirb.CodeBlock)
    assert text_section.blocks[0].offset == 0
    assert text_section.blocks[0].size == 2

    assert isinstance(text_section.blocks[1], gtirb.CodeBlock)
    assert text_section.blocks[1].offset == 2
    assert text_section.blocks[1].size == 4

    assert isinstance(text_section.blocks[2], gtirb.CodeBlock)
    assert text_section.blocks[2].offset == 6
    assert text_section.blocks[2].size == 0

    assert text_section.data == b"\xEB\x00\x66\x90\xFF\xC0"


def test_byte_directive_as_code_due_to_cfi():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64, binary_type=["DYN"]
    )

    # This gets treated as code because it has a CFI directive
    assembler = gtirb_rewriting.Assembler(m, implicit_cfi_procedure=True)
    assembler.assemble(
        """
        jmp .L_foo
        .byte 0x66
        .cfi_undefined 0
        .byte 0x90
        .L_foo:
        """,
        gtirb_rewriting.X86Syntax.INTEL,
    )
    result = assembler.finalize()
    text_section = result.text_section

    assert len(text_section.blocks) == 3
    assert isinstance(text_section.blocks[0], gtirb.CodeBlock)
    assert text_section.blocks[0].offset == 0
    assert text_section.blocks[0].size == 2

    assert isinstance(text_section.blocks[1], gtirb.CodeBlock)
    assert text_section.blocks[1].offset == 2
    assert text_section.blocks[1].size == 2

    assert isinstance(text_section.blocks[2], gtirb.CodeBlock)
    assert text_section.blocks[2].offset == 4
    assert text_section.blocks[2].size == 0

    assert text_section.data == b"\xEB\x00\x66\x90"


def test_byte_directive_as_data():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64, binary_type=["DYN"]
    )

    assembler = gtirb_rewriting.Assembler(m)
    assembler.assemble(
        """
        jmp .L_foo
        .byte 0x66
        .byte 0x90
        .L_foo:
        """,
        gtirb_rewriting.X86Syntax.INTEL,
    )
    result = assembler.finalize()
    text_section = result.text_section

    assert len(text_section.blocks) == 3
    assert isinstance(text_section.blocks[0], gtirb.CodeBlock)
    assert text_section.blocks[0].offset == 0
    assert text_section.blocks[0].size == 2

    assert isinstance(text_section.blocks[1], gtirb.DataBlock)
    assert text_section.blocks[1].offset == 2
    assert text_section.blocks[1].size == 2

    assert isinstance(text_section.blocks[2], gtirb.CodeBlock)
    assert text_section.blocks[2].offset == 4
    assert text_section.blocks[2].size == 0

    assert text_section.data == b"\xEB\x00\x66\x90"


def test_asciz_directive_as_data():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64, binary_type=["DYN"]
    )

    assembler = gtirb_rewriting.Assembler(m)
    assembler.assemble(
        """
        jmp .L_foo
        .L_my_str:
        .asciz "hello"
        .L_foo:
        """,
        gtirb_rewriting.X86Syntax.INTEL,
    )
    result = assembler.finalize()
    text_section = result.text_section

    assert len(text_section.blocks) == 3
    assert isinstance(text_section.blocks[0], gtirb.CodeBlock)
    assert text_section.blocks[0].offset == 0
    assert text_section.blocks[0].size == 2

    assert isinstance(text_section.blocks[1], gtirb.DataBlock)
    assert text_section.blocks[1].offset == 2
    assert text_section.blocks[1].size == 6
    sym = next(sym for sym in result.symbols if sym.name == ".L_my_str")
    assert sym.referent == text_section.blocks[1]

    assert isinstance(text_section.blocks[2], gtirb.CodeBlock)
    assert text_section.blocks[2].offset == 8
    assert text_section.blocks[2].size == 0

    assert text_section.data == b"\xEB\x00hello\x00"

    for edge in result.cfg:
        assert edge.source in text_section.blocks
        assert edge.target in text_section.blocks


def test_byte_directive_as_data_due_to_unreachable_entrypoint():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64, binary_type=["DYN"]
    )

    assembler = gtirb_rewriting.Assembler(m, trivially_unreachable=True)
    assembler.assemble(
        """
        .byte 0x66
        .byte 0x90
        """,
        gtirb_rewriting.X86Syntax.INTEL,
    )
    result = assembler.finalize()
    text_section = result.text_section

    assert len(text_section.blocks) == 1
    assert isinstance(text_section.blocks[0], gtirb.DataBlock)
    assert text_section.blocks[0].size == 2
    assert text_section.data == b"\x66\x90"


def test_multiple_data_labels():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64, binary_type=["DYN"]
    )

    assembler = gtirb_rewriting.Assembler(m)
    assembler.assemble(
        """
        jmp .L_foo
        .L_my_str:
        .byte 0
        .L_my_str_2:
        .byte 1
        .L_foo:
        """,
        gtirb_rewriting.X86Syntax.INTEL,
    )
    result = assembler.finalize()
    text_section = result.text_section

    assert len(text_section.blocks) == 4
    assert isinstance(text_section.blocks[0], gtirb.CodeBlock)
    assert text_section.blocks[0].offset == 0
    assert text_section.blocks[0].size == 2

    assert isinstance(text_section.blocks[1], gtirb.DataBlock)
    assert text_section.blocks[1].offset == 2
    assert text_section.blocks[1].size == 1
    sym1 = next(sym for sym in result.symbols if sym.name == ".L_my_str")
    assert sym1.referent == text_section.blocks[1]

    assert isinstance(text_section.blocks[2], gtirb.DataBlock)
    assert text_section.blocks[2].offset == 3
    assert text_section.blocks[2].size == 1
    sym2 = next(sym for sym in result.symbols if sym.name == ".L_my_str_2")
    assert sym2.referent == text_section.blocks[2]

    assert isinstance(text_section.blocks[3], gtirb.CodeBlock)
    assert text_section.blocks[3].offset == 4
    assert text_section.blocks[3].size == 0

    assert text_section.data == b"\xEB\x00\x00\x01"

    for edge in result.cfg:
        assert edge.source in text_section.blocks
        assert edge.target in text_section.blocks


def test_sym_expr_in_data():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64, binary_type=["DYN"]
    )

    assembler = gtirb_rewriting.Assembler(m)
    assembler.assemble(
        """
        str:
        .string "hello"
        strptr:
        .quad str
        """
    )
    result = assembler.finalize()
    text_section = result.text_section

    str_sym = next(sym for sym in result.symbols if sym.name == "str")
    assert text_section.data == b"hello\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    assert set(text_section.symbolic_expressions.keys()) == {6}
    assert text_section.symbolic_expressions[6] == gtirb.SymAddrConst(
        0, str_sym
    )
    assert set(text_section.symbolic_expression_sizes.keys()) == {6}
    assert text_section.symbolic_expression_sizes[6] == 8


@pytest.mark.parametrize(
    "isa",
    (gtirb.Module.ISA.IA32, gtirb.Module.ISA.X64, gtirb.Module.ISA.ARM64),
)
def test_indirect_call(isa):
    _, m = create_test_module(gtirb.Module.FileFormat.ELF, isa)

    assembler = gtirb_rewriting.Assembler(m)
    if isa in {gtirb.Module.ISA.IA32, gtirb.Module.ISA.X64}:
        assembler.assemble(
            """
            # This call needs to be treated as indirect instead of directly
            # calling foo.
            call *foo

            .data
            foo:
            .quad 0
            """
        )
    elif isa == gtirb.Module.ISA.ARM64:
        assembler.assemble(
            """
            blr x1

            .data
            foo:
            .quad 0
            """
        )
    result = assembler.finalize()
    text_section = result.text_section

    assert len(result.proxies) == 1
    (proxy,) = result.proxies

    assert len(text_section.blocks)
    b1, b2 = text_section.blocks
    assert isinstance(b1, gtirb.CodeBlock)
    assert isinstance(b2, gtirb.CodeBlock)
    assert set(result.cfg) == {
        gtirb.Edge(
            b1,
            proxy,
            gtirb.Edge.Label(gtirb.Edge.Type.Call, direct=False),
        ),
        gtirb.Edge(
            b1,
            b2,
            gtirb.Edge.Label(gtirb.Edge.Type.Fallthrough),
        ),
    }

    assert ".data" in result.sections
    data = result.sections[".data"]
    assert len(data.blocks) == 1
    assert isinstance(data.blocks[0], gtirb.DataBlock)


def test_temp_symbol_suffix():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64, binary_type=["DYN"]
    )

    assembler = gtirb_rewriting.Assembler(m, temp_symbol_suffix="_1")
    assembler.assemble(
        """
        .L_foo:
        nop
        bar:
        ud2
        """
    )
    result = assembler.finalize()

    temp_sym = next(sym for sym in result.symbols if sym.name == ".L_foo_1")
    assert isinstance(temp_sym.referent, gtirb.CodeBlock)
    assert temp_sym.referent.offset == 0
    assert temp_sym.referent.size == 1

    bar_sym = next(sym for sym in result.symbols if sym.name == "bar")
    assert isinstance(bar_sym.referent, gtirb.CodeBlock)
    assert bar_sym.referent.offset == 1
    assert bar_sym.referent.size == 2


@pytest.mark.parametrize(
    "variant_entry",
    gtirb_rewriting.assembler.assembler._Streamer._ELF_VARIANT_KINDS.items(),
    ids=lambda item: item[0].name,
)
def test_elf_sym_attrs(variant_entry):
    variant, attrs = variant_entry

    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF,
        gtirb.Module.ISA.X64,
        binary_type=["DYN"],
    )
    sym = add_symbol(m, "foo", add_proxy_block(m))

    assembler = gtirb_rewriting.Assembler(m)
    assembler.assemble(
        f"mov rax, {sym.name}@{variant.name}",
        x86_syntax=gtirb_rewriting.X86Syntax.INTEL,
    )
    result = assembler.finalize()

    assert len(result.text_section.symbolic_expressions) == 1
    (expr,) = result.text_section.symbolic_expressions.values()
    assert isinstance(expr, gtirb.SymAddrConst)
    assert expr.attributes == attrs


def test_arm64_sym_attribute_lo12():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF,
        gtirb.Module.ISA.ARM64,
        binary_type=["DYN"],
    )
    sym = add_symbol(m, "foo", add_proxy_block(m))

    assembler = gtirb_rewriting.Assembler(m)
    assembler.assemble(
        """
        adrp x0, foo
        add x0, x0, :lo12:foo
        """
    )
    result = assembler.finalize()
    text_section = result.text_section

    assert 0 in text_section.symbolic_expressions
    assert isinstance(text_section.symbolic_expressions[0], gtirb.SymAddrConst)
    assert text_section.symbolic_expressions[0].symbol is sym
    assert text_section.symbolic_expressions[0].offset == 0
    assert not text_section.symbolic_expressions[0].attributes

    assert 4 in text_section.symbolic_expressions
    assert isinstance(text_section.symbolic_expressions[4], gtirb.SymAddrConst)
    assert text_section.symbolic_expressions[4].symbol is sym
    assert text_section.symbolic_expressions[4].offset == 0
    assert text_section.symbolic_expressions[4].attributes == {
        compat_proto.LO12
    }


def test_arm64_sym_attribute_got():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF,
        gtirb.Module.ISA.ARM64,
        binary_type=["DYN"],
    )
    sym = add_symbol(m, "foo", add_proxy_block(m))

    assembler = gtirb_rewriting.Assembler(m)
    assembler.assemble(
        """
        adrp x0, :got:foo
        ldr x0, [x0, :got_lo12:foo]
        """
    )
    result = assembler.finalize()
    text_section = result.text_section

    assert 0 in text_section.symbolic_expressions
    assert isinstance(text_section.symbolic_expressions[0], gtirb.SymAddrConst)
    assert text_section.symbolic_expressions[0].symbol is sym
    assert text_section.symbolic_expressions[0].offset == 0
    assert text_section.symbolic_expressions[0].attributes == {
        compat_proto.GOT
    }

    assert 4 in text_section.symbolic_expressions
    assert isinstance(text_section.symbolic_expressions[4], gtirb.SymAddrConst)
    assert text_section.symbolic_expressions[4].symbol is sym
    assert text_section.symbolic_expressions[4].offset == 0
    assert text_section.symbolic_expressions[4].attributes == {
        compat_proto.LO12,
        compat_proto.GOT,
    }


def test_undef_symbols():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF,
        gtirb.Module.ISA.X64,
    )

    assembler = gtirb_rewriting.Assembler(m)
    with pytest.raises(gtirb_rewriting.UndefSymbolError) as exc:
        assembler.assemble("call does_not_exist")
    assert exc.value.lineno == 1
    assert exc.value.offset == 6

    # Now try again with the flag enabled
    assembler = gtirb_rewriting.Assembler(m, allow_undef_symbols=True)
    assembler.assemble("call does_not_exist")
    result = assembler.finalize()

    assert len(result.symbols) == 1
    assert result.symbols[0].name == "does_not_exist"
    assert isinstance(result.symbols[0].referent, gtirb.ProxyBlock)
    assert result.symbols[0].referent in result.proxies


def test_multiple_symbol_definitions():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF,
        gtirb.Module.ISA.X64,
    )

    assembler = gtirb_rewriting.Assembler(m)
    with pytest.raises(gtirb_rewriting.MultipleDefinitionsError) as exc:
        assembler.assemble(".Lblah:\n.Lblah:")
    assert exc.value.lineno == 2
    assert exc.value.offset == 1


def test_indirect_jumps():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF,
        gtirb.Module.ISA.X64,
    )

    assembler = gtirb_rewriting.Assembler(m)
    assembler.assemble("jmp [rax]", gtirb_rewriting.X86Syntax.INTEL)
    result = assembler.finalize()
    text_section = result.text_section

    (proxy,) = result.proxies
    assert set(result.cfg) == {
        gtirb.Edge(
            text_section.blocks[0],
            proxy,
            gtirb.Edge.Label(gtirb.Edge.Type.Branch, direct=False),
        )
    }
    assert text_section.symbolic_expressions == {}


def test_direct_calls():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF,
        gtirb.Module.ISA.X64,
    )
    exit_sym = add_symbol(m, "exit", add_proxy_block(m))

    assembler = gtirb_rewriting.Assembler(m)
    assembler.assemble("call exit", gtirb_rewriting.X86Syntax.INTEL)
    result = assembler.finalize()
    text_section = result.text_section

    assert set(result.cfg) == {
        gtirb.Edge(
            text_section.blocks[0],
            exit_sym.referent,
            gtirb.Edge.Label(gtirb.Edge.Type.Call, direct=True),
        ),
        gtirb.Edge(
            text_section.blocks[0],
            text_section.blocks[1],
            gtirb.Edge.Label(gtirb.Edge.Type.Fallthrough),
        ),
    }
    assert text_section.symbolic_expressions == {
        1: gtirb.SymAddrConst(0, exit_sym)
    }


def test_indirect_calls():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF,
        gtirb.Module.ISA.X64,
    )

    assembler = gtirb_rewriting.Assembler(m)
    assembler.assemble("call [rax]", gtirb_rewriting.X86Syntax.INTEL)
    result = assembler.finalize()
    text_section = result.text_section

    (proxy,) = result.proxies
    assert set(result.cfg) == {
        gtirb.Edge(
            text_section.blocks[0],
            proxy,
            gtirb.Edge.Label(gtirb.Edge.Type.Call, direct=False),
        ),
        gtirb.Edge(
            text_section.blocks[0],
            text_section.blocks[1],
            gtirb.Edge.Label(gtirb.Edge.Type.Fallthrough),
        ),
    }
    assert text_section.symbolic_expressions == {}


class DiagHandlerBehavior(Enum):
    NoCallback = auto()
    Handled = auto()
    Unhandled = auto()


@pytest.mark.parametrize("handler_behavior", DiagHandlerBehavior)
def test_assembler_errors(handler_behavior: DiagHandlerBehavior):
    @contextmanager
    def expect_error(
        cls: Type, message: str, loc: Tuple[int, int]
    ) -> Iterator[None]:
        lineno, offset = loc
        if handler_behavior != DiagHandlerBehavior.Handled:
            with pytest.raises(cls) as exc:
                yield

            assert str(exc.value) == message
            assert exc.value.lineno == lineno
            assert exc.value.offset == offset
        else:
            yield

        if handler_behavior != DiagHandlerBehavior.NoCallback:
            assert diagnostic_mock.assert_called
            (diag,) = diagnostic_mock.call_args[0]
            assert diag.message == message
            assert diag.lineno == lineno
            assert diag.offset == offset
            diagnostic_mock.reset_mock()

    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF,
        gtirb.Module.ISA.X64,
    )
    _, bi = add_text_section(m, address=0x1000)
    add_symbol(m, "blah", add_proxy_block(m))
    add_symbol(m, "data", add_data_block(bi, b"\xFF"))

    diagnostic_mock = Mock(
        return_value=(handler_behavior == DiagHandlerBehavior.Handled)
    )
    if handler_behavior != DiagHandlerBehavior.NoCallback:
        diagnostic_callback = diagnostic_mock
    else:
        diagnostic_callback = None

    assembler = gtirb_rewriting.Assembler(
        m,
        diagnostic_callback=diagnostic_callback,
        allow_undef_symbols=True,
        implicit_cfi_procedure=True,
    )

    assert assembler.assemble("nop")

    with expect_error(
        gtirb_rewriting.UnsupportedAssemblyError,
        "Call and branch targets cannot have offsets",
        (1, 1),
    ):
        assert not assembler.assemble(
            "call blah+1", gtirb_rewriting.X86Syntax.INTEL
        )

    with expect_error(
        gtirb_rewriting.UnsupportedAssemblyError,
        "Call and branch targets cannot be data blocks or other non-CFG "
        "elements",
        (1, 1),
    ):
        assert not assembler.assemble(
            "call data", gtirb_rewriting.X86Syntax.INTEL
        )

    with expect_error(
        gtirb_rewriting.UnsupportedAssemblyError,
        "trying to pad with a non-zero byte",
        (1, 1),
    ):
        assert not assembler.assemble(
            ".align 2, 0xFF", gtirb_rewriting.X86Syntax.INTEL
        )

    with expect_error(
        gtirb_rewriting.UnsupportedAssemblyError,
        "trying to pad with a fixed limit",
        (1, 1),
    ):
        assert not assembler.assemble(
            ".align 2, 0, 1", gtirb_rewriting.X86Syntax.INTEL
        )

    with expect_error(
        gtirb_rewriting.UnsupportedAssemblyError,
        "unsupported symbol variant kind 'PAGEOFF'",
        (1, 6),
    ):
        assert not assembler.assemble(
            "call blah@PAGEOFF", gtirb_rewriting.X86Syntax.INTEL
        )

    with expect_error(
        gtirb_rewriting.UnsupportedAssemblyError,
        "only constant expressions can be used in assignments",
        # Points to the -, which isn't ideal
        (4, 19),
    ):
        # This would be nice to support, but we don't right now.
        assert not assembler.assemble(
            textwrap.dedent(
                """\
                .data
                str1:
                    .string "Hello"
                    str1_len = (. - str1)
                .text
                    movl $str1_len, %eax
                """
            )
        )

    with expect_error(
        gtirb_rewriting.UnsupportedAssemblyError,
        "cannot end an implicit CFI procedure",
        (1, 1),
    ):
        assert not assembler.assemble(
            ".cfi_endproc", gtirb_rewriting.X86Syntax.INTEL
        )


@pytest.mark.parametrize(
    "file_format",
    (
        gtirb.Module.FileFormat.ELF,
        gtirb.Module.FileFormat.PE,
    ),
)
def test_assembler_sections(file_format: gtirb.Module.FileFormat):
    if file_format == gtirb.Module.FileFormat.ELF:
        rdata_name = ".rodata"
    elif file_format == gtirb.Module.FileFormat.PE:
        rdata_name = ".rdata"
    else:
        assert False

    _, m = create_test_module(file_format, gtirb.Module.ISA.X64)

    assembler = gtirb_rewriting.Assembler(m)
    assembler.assemble(
        f"""
        .data
        .ascii "hello"

        .section {rdata_name}
        .ascii "world"

        .section my_text, "ax"
        ud2
        """
    )
    result = assembler.finalize()

    assert set(result.sections) == {".text", ".data", rdata_name, "my_text"}

    text_section = result.text_section
    assert result.text_section is text_section
    assert text_section.flags == {
        gtirb.Section.Flag.Executable,
        gtirb.Section.Flag.Initialized,
        gtirb.Section.Flag.Loaded,
        gtirb.Section.Flag.Readable,
    }
    assert not text_section.blocks
    assert not text_section.data

    data_section = result.sections[".data"]
    assert data_section.flags == {
        gtirb.Section.Flag.Initialized,
        gtirb.Section.Flag.Loaded,
        gtirb.Section.Flag.Readable,
        gtirb.Section.Flag.Writable,
    }
    assert len(data_section.blocks) == 1
    assert isinstance(data_section.blocks[0], gtirb.DataBlock)
    assert data_section.blocks[0].offset == 0
    assert data_section.blocks[0].size == 5
    assert data_section.data == b"hello"

    rdata_section = result.sections[rdata_name]
    assert rdata_section.flags == {
        gtirb.Section.Flag.Initialized,
        gtirb.Section.Flag.Loaded,
        gtirb.Section.Flag.Readable,
    }
    assert len(rdata_section.blocks) == 1
    assert isinstance(rdata_section.blocks[0], gtirb.DataBlock)
    assert rdata_section.blocks[0].offset == 0
    assert rdata_section.blocks[0].size == 5
    assert rdata_section.data == b"world"

    mytext_section = result.sections["my_text"]
    assert mytext_section.flags == {
        gtirb.Section.Flag.Executable,
        gtirb.Section.Flag.Initialized,
        gtirb.Section.Flag.Loaded,
        gtirb.Section.Flag.Readable,
    }
    assert len(mytext_section.blocks) == 1
    assert isinstance(mytext_section.blocks[0], gtirb.CodeBlock)
    assert mytext_section.blocks[0].offset == 0
    assert mytext_section.blocks[0].size == 2
    assert mytext_section.data == b"\x0F\x0B"


def test_alignment():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF,
        gtirb.Module.ISA.X64,
    )

    assembler = gtirb_rewriting.Assembler(m)
    assembler.assemble(
        """
        .align 4
        nop
        .align 8
        nop
    """,
        gtirb_rewriting.X86Syntax.INTEL,
    )
    result = assembler.finalize()
    text_section = result.text_section

    assert text_section.data == b"\x90\x90"
    assert len(text_section.blocks) == 2

    b1, b2 = text_section.blocks

    assert text_section.alignment == {
        b1: 4,
        b2: 8,
    }


def test_elf_symbol_attributes():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF,
        gtirb.Module.ISA.X64,
    )

    assembler = gtirb_rewriting.Assembler(m)
    assembler.assemble(
        """
            .hidden foo
            .globl foo
            .type foo, @function
        foo:
            nop
        """,
        gtirb_rewriting.X86Syntax.INTEL,
    )

    result = assembler.finalize()

    assert len(result.symbols) == 1
    assert result.symbols[0].name == "foo"
    assert result.elf_symbol_attributes[
        result.symbols[0]
    ] == gtirb_rewriting.Assembler.Result.ElfSymbolAttributes(
        "FUNC", "GLOBAL", "HIDDEN"
    )


def test_fill():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF,
        gtirb.Module.ISA.X64,
    )

    assembler = gtirb_rewriting.Assembler(m)
    assembler.assemble(
        """
        .zero 42
        """,
        gtirb_rewriting.X86Syntax.ATT,
    )

    result = assembler.finalize()

    assert result.text_section.data == b"\x00" * 42


def test_sym_minus_sym():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF,
        gtirb.Module.ISA.X64,
    )
    foo = add_symbol(m, "foo", add_proxy_block(m))
    foo2 = add_symbol(m, "foo2", add_proxy_block(m))

    assembler = gtirb_rewriting.Assembler(m)
    assembler.assemble(
        """
        .data
        .byte foo - foo2
        """,
        gtirb_rewriting.X86Syntax.ATT,
    )

    result = assembler.finalize()

    assert result.sections[".data"].data == b"\x00"
    assert result.sections[".data"].symbolic_expressions[
        0
    ] == gtirb.SymAddrAddr(1, 0, foo, foo2)


def test_assignments():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF,
        gtirb.Module.ISA.X64,
    )

    assembler = gtirb_rewriting.Assembler(m)
    assembler.assemble(
        """
        .set .L_0, 0
        """,
        gtirb_rewriting.X86Syntax.ATT,
    )

    result = assembler.finalize()

    assert len(result.symbols) == 1
    assert result.symbols[0].name == ".L_0"
    assert result.symbols[0].value == 0


@pytest.mark.parametrize("signed", (False, True))
def test_uleb128_and_sleb128(signed):
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF,
        gtirb.Module.ISA.X64,
    )
    start = add_symbol(m, "start")
    end = add_symbol(m, "end")

    us = "u" if not signed else "s"

    assembler = gtirb_rewriting.Assembler(m)
    assembler.assemble(
        f"""
        .data
        .{us}leb128 start - end
        """,
        gtirb_rewriting.X86Syntax.ATT,
    )
    result = assembler.finalize()

    data_sect = result.sections[".data"]
    assert data_sect.data == b"\x00"

    data_block = data_sect.blocks[0]
    assert isinstance(data_block, gtirb.DataBlock)
    assert data_block.size == 1
    if signed:
        assert (
            data_sect.block_types[data_block]
            == gtirb_rewriting.Assembler.Result.DataType.SLEB128
        )
    else:
        assert (
            data_sect.block_types[data_block]
            == gtirb_rewriting.Assembler.Result.DataType.ULEB128
        )
    assert data_sect.symbolic_expressions[0] == gtirb.SymAddrAddr(
        1, 0, start, end
    )


@pytest.mark.parametrize("nul_terminate", (False, True))
def test_string_and_ascii(nul_terminate):
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF,
        gtirb.Module.ISA.X64,
    )
    directive = "string" if nul_terminate else "ascii"

    assembler = gtirb_rewriting.Assembler(m)
    assembler.assemble(
        f"""
        .data
        .{directive} "hi"
        .byte 0
        .byte 42
        """,
        gtirb_rewriting.X86Syntax.ATT,
    )
    result = assembler.finalize()

    data_sect = result.sections[".data"]
    str_block, byte_block = data_sect.blocks
    assert isinstance(str_block, gtirb.DataBlock)
    assert isinstance(byte_block, gtirb.DataBlock)

    if nul_terminate:
        assert data_sect.data == b"hi\x00\x00\x2A"
        assert (
            data_sect.block_types[str_block]
            == gtirb_rewriting.Assembler.Result.DataType.String
        )
    else:
        assert data_sect.data == b"hi\x00\x2A"
        assert (
            data_sect.block_types[str_block]
            == gtirb_rewriting.Assembler.Result.DataType.ASCII
        )

    assert set(data_sect.block_types) == {str_block}


def test_cfi_procedure_implicit():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF,
        gtirb.Module.ISA.X64,
    )

    assembler = gtirb_rewriting.Assembler(m, implicit_cfi_procedure=True)

    assembler.assemble(
        """
        nop
        .cfi_undefined 15
        """
    )

    result = assembler.finalize()
    (b1,) = result.text_section.blocks

    assert result.text_section.cfi_procedures == [
        gtirb_rewriting.Assembler.Result.CFIProcedure(
            is_implicit=True,
            start_offset=None,
            end_offset=None,
            instructions=gtirb_rewriting.OffsetMapping(
                {
                    gtirb.Offset(b1, 1): [
                        (".cfi_undefined", [15], NULL_UUID),
                    ]
                }
            ),
        )
    ]


def test_cfi_instructions():
    """
    Test that the assembler accepts CFI assembly directives that do not map
    directly to DWARF CFI instructions (e.g. factored instructions).
    """
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF,
        gtirb.Module.ISA.X64,
    )

    assembler = gtirb_rewriting.Assembler(m, implicit_cfi_procedure=True)

    assembler.assemble(
        """
        nop

        # DW_CFA_def_cfa takes two unsigned LEB128 operands, so this would
        # need to be represented as DW_CFA_def_cfa_sf.
        .cfi_def_cfa 7, -8

        # DW_CFA_offset takes two unsigned ULEB128 operands. The operand in
        # the assembly directive can be negative because of the data alignment
        # factor.
        .cfi_offset 16, -8

        # .cfi_rel_offset is not an actual CFI instruction and gets lowered
        # into one by the assembler.
        .cfi_rel_offset 16, -8

        # .cfi_def_cfa_offset is not an actual CFI instruction and gets
        # lowered into one by the assembler.
        .cfi_def_cfa_offset -8
        """
    )

    result = assembler.finalize()
    (b1,) = result.text_section.blocks

    assert result.text_section.cfi_procedures == [
        gtirb_rewriting.Assembler.Result.CFIProcedure(
            is_implicit=True,
            start_offset=None,
            end_offset=None,
            instructions=gtirb_rewriting.OffsetMapping(
                {
                    gtirb.Offset(b1, 1): [
                        (".cfi_def_cfa", [7, -8], NULL_UUID),
                        (".cfi_offset", [16, -8], NULL_UUID),
                        (".cfi_rel_offset", [16, -8], NULL_UUID),
                        (".cfi_def_cfa_offset", [-8], NULL_UUID),
                    ]
                }
            ),
        )
    ]


def test_cfi_procedure_explicit():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF,
        gtirb.Module.ISA.X64,
    )

    assembler = gtirb_rewriting.Assembler(m, implicit_cfi_procedure=False)

    assembler.assemble(
        """
        .cfi_startproc
        nop
        .cfi_undefined 15
        .cfi_endproc
        """
    )

    result = assembler.finalize()
    (b1,) = result.text_section.blocks

    assert result.text_section.cfi_procedures == [
        gtirb_rewriting.Assembler.Result.CFIProcedure(
            is_implicit=False,
            start_offset=gtirb.Offset(b1, 0),
            end_offset=gtirb.Offset(b1, 1),
            instructions=gtirb_rewriting.OffsetMapping(
                {
                    gtirb.Offset(b1, 1): [
                        (".cfi_undefined", [15], NULL_UUID),
                    ]
                }
            ),
        )
    ]


@pytest.mark.parametrize("ignore", (True, False))
def test_ignore_symver_directives(ignore: bool):
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF,
        gtirb.Module.ISA.X64,
    )

    assembler = gtirb_rewriting.Assembler(m, ignore_symver_directives=ignore)
    if ignore:
        filter = pytest.warns(
            gtirb_rewriting.assembler.IgnoredSymverDirectiveWarning
        )
    else:
        filter = pytest.raises(gtirb_rewriting.UnsupportedAssemblyError)
    with filter:
        assembler.assemble(".symver a, a@@1.2.0")


def test_line_numbers():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF,
        gtirb.Module.ISA.X64,
    )

    assembler = gtirb_rewriting.Assembler(m, trivially_unreachable=True)
    assembler.assemble(
        textwrap.dedent(
            """\
            .byte 42   # one byte
            .quad 4    # eight bytes

            label:
            ud2        # two bytes
            nop
            """
        )
    )
    result = assembler.finalize()

    assert len(result.text_section.blocks) == 2
    block1, block2 = result.text_section.blocks
    assert isinstance(block1, gtirb.DataBlock)
    assert block1.size == 9
    assert isinstance(block2, gtirb.CodeBlock)
    assert block2.size == 3

    assert result.text_section.line_map == {
        gtirb.Offset(block1, 0): 1,
        gtirb.Offset(block1, 1): 2,
        gtirb.Offset(block2, 0): 5,
        gtirb.Offset(block2, 2): 6,
    }


@pytest.mark.parametrize("use_gtirb_as", (False, True))
def test_create_ir(use_gtirb_as: bool, tmp_path: pathlib.Path):
    asm = textwrap.dedent(
        """\
        .cfi_startproc
        .cfi_personality 0, personality
        .cfi_lsda 0, lsda
        .cfi_return_column 1
        ud2
        .cfi_undefined 15
        .cfi_endproc

        .data
        lsda:
        personality:
        .byte 42
        """
    )

    if use_gtirb_as:
        asm_dest = tmp_path / "asm.s"
        asm_dest.write_text(asm)

        ir_dest = tmp_path / "out.gtirb"
        gtirb_as(
            [
                str(asm_dest),
                str(ir_dest),
                "--file-format",
                "elf",
                "--isa",
                "x64",
                "--pie",
            ]
        )

        ir = gtirb.IR.load_protobuf(str(ir_dest))

    else:
        assembler = gtirb_rewriting.Assembler(
            gtirb_rewriting.Assembler.Target(
                gtirb.Module.ISA.X64,
                gtirb.Module.FileFormat.ELF,
                ["DYN"],
                True,
            )
        )
        assembler.assemble(asm)
        result = assembler.finalize()
        ir = result.create_ir()

    assert len(ir.modules) == 1
    (m,) = ir.modules

    assert m.isa == gtirb.Module.ISA.X64
    assert m.file_format == gtirb.Module.FileFormat.ELF

    assert "binaryType" in m.aux_data
    assert m.aux_data["binaryType"].data == ["DYN"]

    assert set(s.name for s in m.sections) == {".text", ".data", ".dynamic"}

    text = next(s for s in m.sections if s.name == ".text")
    assert len(text.byte_intervals) == 1
    (text_bi,) = text.byte_intervals
    assert text_bi.contents == b"\x0F\x0B"
    (text_block,) = text_bi.blocks

    data = next(s for s in m.sections if s.name == ".data")
    assert len(data.byte_intervals) == 1
    (data_bi,) = data.byte_intervals
    assert data_bi.contents == b"\x2A"

    (personality_sym,) = m.symbols_named("personality")
    (lsda_sym,) = m.symbols_named("lsda")

    assert m.aux_data["cfiDirectives"].data == {
        gtirb.Offset(text_block, 0): [
            (".cfi_startproc", [], NULL_UUID),
            (".cfi_lsda", [0], lsda_sym),
            (".cfi_personality", [0], personality_sym),
            (".cfi_return_column", [1], NULL_UUID),
        ],
        gtirb.Offset(text_block, 2): [
            (".cfi_undefined", [15], NULL_UUID),
            (".cfi_endproc", [], NULL_UUID),
        ],
    }
