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

import gtirb
import gtirb_rewriting
from helpers import add_proxy_block, add_symbol, create_test_module


def test_return_edges():
    m = gtirb.Module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
        name="test",
    )
    assembler = gtirb_rewriting.Assembler(m)
    assembler.assemble(
        "ret", gtirb_rewriting.X86Syntax.INTEL,
    )
    result = assembler.finalize()

    assert len(result.blocks) == 2
    assert result.blocks[0].offset == 0
    assert result.blocks[0].size == 1
    assert result.blocks[1].offset == 1
    assert result.blocks[1].size == 0

    edges = list(result.cfg.out_edges(result.blocks[0]))
    assert len(edges) == 1
    assert edges[0].label.type == gtirb.Edge.Type.Return
    assert isinstance(edges[0].target, gtirb.ProxyBlock)
    assert edges[0].target in result.proxies

    assert result.data == b"\xC3"


def test_symbolic_expr():
    ir, m, bi = create_test_module()
    puts_sym = add_symbol(m, "puts", add_proxy_block(m))

    assembler = gtirb_rewriting.Assembler(m)
    assembler.assemble(
        "call puts", gtirb_rewriting.X86Syntax.INTEL,
    )
    result = assembler.finalize()

    assert len(result.symbolic_expressions) == 1
    sym_expr = result.symbolic_expressions[1]
    assert isinstance(sym_expr, gtirb.SymAddrConst)
    assert sym_expr.symbol == puts_sym
    assert sym_expr.offset == 0
    assert sym_expr.attributes == {gtirb.SymbolicExpression.Attribute.PltRef}


def test_symbolic_expr_sym_offset():
    ir, m, bi = create_test_module()
    puts_sym = add_symbol(m, "puts", add_proxy_block(m))

    assembler = gtirb_rewriting.Assembler(m)
    assembler.assemble(
        "inc byte ptr [puts + 42]", gtirb_rewriting.X86Syntax.INTEL,
    )
    result = assembler.finalize()

    assert len(result.symbolic_expressions) == 1
    sym_expr = result.symbolic_expressions[3]
    assert isinstance(sym_expr, gtirb.SymAddrConst)
    assert sym_expr.symbol == puts_sym
    assert sym_expr.offset == 42
    assert sym_expr.attributes == {gtirb.SymbolicExpression.Attribute.GotRelPC}


def test_byte_directive_as_code_due_to_entrypoint():
    m = gtirb.Module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
        name="test",
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

    assert len(result.blocks) == 1
    assert isinstance(result.blocks[0], gtirb.CodeBlock)
    assert result.blocks[0].size == 2
    assert result.data == b"\x66\x90"


def test_byte_directive_as_code_due_to_cfg():
    m = gtirb.Module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
        name="test",
    )
    m.aux_data["binaryType"] = gtirb.AuxData(
        type_name="vector<string>", data=["DYN"]
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

    assert len(result.blocks) == 3
    assert isinstance(result.blocks[0], gtirb.CodeBlock)
    assert result.blocks[0].offset == 0
    assert result.blocks[0].size == 2

    assert isinstance(result.blocks[1], gtirb.CodeBlock)
    assert result.blocks[1].offset == 2
    assert result.blocks[1].size == 2

    assert isinstance(result.blocks[2], gtirb.CodeBlock)
    assert result.blocks[2].offset == 4
    assert result.blocks[2].size == 0

    assert result.data == b"\x75\x00\x66\x90"


def test_byte_directive_as_code_due_to_mixing():
    m = gtirb.Module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
        name="test",
    )
    m.aux_data["binaryType"] = gtirb.AuxData(
        type_name="vector<string>", data=["DYN"]
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

    assert len(result.blocks) == 3
    assert isinstance(result.blocks[0], gtirb.CodeBlock)
    assert result.blocks[0].offset == 0
    assert result.blocks[0].size == 2

    assert isinstance(result.blocks[1], gtirb.CodeBlock)
    assert result.blocks[1].offset == 2
    assert result.blocks[1].size == 4

    assert isinstance(result.blocks[2], gtirb.CodeBlock)
    assert result.blocks[2].offset == 6
    assert result.blocks[2].size == 0

    assert result.data == b"\xEB\x00\x66\x90\xFF\xC0"


def test_byte_directive_as_data():
    m = gtirb.Module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
        name="test",
    )
    m.aux_data["binaryType"] = gtirb.AuxData(
        type_name="vector<string>", data=["DYN"]
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

    assert len(result.blocks) == 3
    assert isinstance(result.blocks[0], gtirb.CodeBlock)
    assert result.blocks[0].offset == 0
    assert result.blocks[0].size == 2

    assert isinstance(result.blocks[1], gtirb.DataBlock)
    assert result.blocks[1].offset == 2
    assert result.blocks[1].size == 2

    assert isinstance(result.blocks[2], gtirb.CodeBlock)
    assert result.blocks[2].offset == 4
    assert result.blocks[2].size == 0

    assert result.data == b"\xEB\x00\x66\x90"


def test_asciz_directive_as_data():
    m = gtirb.Module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
        name="test",
    )
    m.aux_data["binaryType"] = gtirb.AuxData(
        type_name="vector<string>", data=["DYN"]
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

    assert len(result.blocks) == 3
    assert isinstance(result.blocks[0], gtirb.CodeBlock)
    assert result.blocks[0].offset == 0
    assert result.blocks[0].size == 2

    assert isinstance(result.blocks[1], gtirb.DataBlock)
    assert result.blocks[1].offset == 2
    assert result.blocks[1].size == 6
    sym = next(sym for sym in result.symbols if sym.name == ".L_my_str")
    assert sym.referent == result.blocks[1]

    assert isinstance(result.blocks[2], gtirb.CodeBlock)
    assert result.blocks[2].offset == 8
    assert result.blocks[2].size == 0

    assert result.data == b"\xEB\x00hello\x00"

    for edge in result.cfg:
        assert edge.source in result.blocks
        assert edge.target in result.blocks


def test_byte_directive_as_data_due_to_unreachable_entrypoint():
    m = gtirb.Module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
        name="test",
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

    assert len(result.blocks) == 1
    assert isinstance(result.blocks[0], gtirb.DataBlock)
    assert result.blocks[0].size == 2
    assert result.data == b"\x66\x90"


def test_multiple_data_labels():
    m = gtirb.Module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
        name="test",
    )
    m.aux_data["binaryType"] = gtirb.AuxData(
        type_name="vector<string>", data=["DYN"]
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

    assert len(result.blocks) == 4
    assert isinstance(result.blocks[0], gtirb.CodeBlock)
    assert result.blocks[0].offset == 0
    assert result.blocks[0].size == 2

    assert isinstance(result.blocks[1], gtirb.DataBlock)
    assert result.blocks[1].offset == 2
    assert result.blocks[1].size == 1
    sym1 = next(sym for sym in result.symbols if sym.name == ".L_my_str")
    assert sym1.referent == result.blocks[1]

    assert isinstance(result.blocks[2], gtirb.DataBlock)
    assert result.blocks[2].offset == 3
    assert result.blocks[2].size == 1
    sym2 = next(sym for sym in result.symbols if sym.name == ".L_my_str_2")
    assert sym2.referent == result.blocks[2]

    assert isinstance(result.blocks[3], gtirb.CodeBlock)
    assert result.blocks[3].offset == 4
    assert result.blocks[3].size == 0

    assert result.data == b"\xEB\x00\x00\x01"

    for edge in result.cfg:
        assert edge.source in result.blocks
        assert edge.target in result.blocks


def test_temp_symbol_suffix():
    m = gtirb.Module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
        name="test",
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
    assert temp_sym.referent.offset == 0
    assert temp_sym.referent.size == 1

    bar_sym = next(sym for sym in result.symbols if sym.name == "bar")
    assert bar_sym.referent.offset == 1
    assert bar_sym.referent.size == 2
