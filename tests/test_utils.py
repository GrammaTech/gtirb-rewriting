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
import unittest.mock
import uuid

import capstone
import gtirb
import gtirb_rewriting.utils
import pytest


def test_offset_mapping():
    m = gtirb_rewriting.utils.OffsetMapping()
    assert len(m) == 0
    assert gtirb.Offset(element_id=0, displacement=0) not in m

    m[gtirb.Offset(element_id=0, displacement=0)] = "A"
    assert len(m) == 1
    assert gtirb.Offset(element_id=0, displacement=0) in m
    assert m[gtirb.Offset(element_id=0, displacement=0)] == "A"
    assert m[0] == {0: "A"}
    assert list(m.items()) == [
        (gtirb.Offset(element_id=0, displacement=0), "A")
    ]

    m[1] = {0: "B", 23: "C"}
    assert len(m) == 3
    assert gtirb.Offset(element_id=1, displacement=23) in m
    assert m[gtirb.Offset(element_id=1, displacement=23)] == "C"
    assert m == {
        gtirb.Offset(element_id=0, displacement=0): "A",
        gtirb.Offset(element_id=1, displacement=0): "B",
        gtirb.Offset(element_id=1, displacement=23): "C",
    }

    m[1] = {15: "D", 23: "E"}
    assert len(m) == 4
    assert m == {
        gtirb.Offset(element_id=0, displacement=0): "A",
        gtirb.Offset(element_id=1, displacement=0): "B",
        gtirb.Offset(element_id=1, displacement=15): "D",
        gtirb.Offset(element_id=1, displacement=23): "E",
    }

    del m[gtirb.Offset(element_id=1, displacement=23)]
    assert len(m) == 3
    assert m == {
        gtirb.Offset(element_id=0, displacement=0): "A",
        gtirb.Offset(element_id=1, displacement=0): "B",
        gtirb.Offset(element_id=1, displacement=15): "D",
    }

    key = gtirb.Offset(element_id=1, displacement=23)
    with pytest.raises(KeyError) as excinfo:
        del m[key]
    assert str(key) == str(excinfo.value)

    del m[1]
    assert len(m) == 1
    assert m == {gtirb.Offset(element_id=0, displacement=0): "A"}

    with pytest.raises(ValueError) as excinfo:
        m[2] = "F"
    assert "not a mapping" in str(excinfo.value)


def test_triples():
    mod = gtirb.Module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
        name="test",
    )
    assert gtirb_rewriting.utils._target_triple(mod) == "x86_64-pc-linux"

    mod = gtirb.Module(
        isa=gtirb.Module.ISA.IA32,
        file_format=gtirb.Module.FileFormat.ELF,
        name="test",
    )
    assert gtirb_rewriting.utils._target_triple(mod) == "i386-pc-linux"

    mod = gtirb.Module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.PE,
        name="test",
    )
    assert gtirb_rewriting.utils._target_triple(mod) == "x86_64-pc-win32"

    mod = gtirb.Module(
        isa=gtirb.Module.ISA.IA32,
        file_format=gtirb.Module.FileFormat.PE,
        name="test",
    )
    assert gtirb_rewriting.utils._target_triple(mod) == "i386-pc-win32"


def test_nonterminator_instructions():
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    # xor %eax, %eax; ret
    disasm = tuple(cs.disasm(b"\x31\xC0\xC3", 0))
    assert len(disasm) == 2

    edge = unittest.mock.MagicMock(spec=gtirb.Edge)
    edge.label = gtirb.Edge.Label(gtirb.Edge.Type.Return)

    block = unittest.mock.MagicMock(spec=gtirb.CodeBlock)
    block.outgoing_edges = [edge]

    nonterm = tuple(
        gtirb_rewriting.utils._nonterminator_instructions(block, disasm)
    )
    assert len(nonterm) == 1


def test_nonterminator_instructions_fallthrough():
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    # xor %eax, %eax; xor %ecx, %ecx
    disasm = tuple(cs.disasm(b"\x31\xC0\x31\xC9", 0))
    assert len(disasm) == 2

    edge = unittest.mock.MagicMock(spec=gtirb.Edge)
    edge.label = gtirb.Edge.Label(gtirb.Edge.Type.Fallthrough)

    block = unittest.mock.MagicMock(spec=gtirb.CodeBlock)
    block.outgoing_edges = [edge]

    nonterm = tuple(
        gtirb_rewriting.utils._nonterminator_instructions(block, disasm)
    )
    assert len(nonterm) == 2


def test_show_block_asm(caplog):
    mod = gtirb.Module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
        name="test",
    )
    # pushfq; popfq
    raw_data = b"\x9C\x9D"
    block = gtirb.CodeBlock(size=len(raw_data))
    interval = gtirb.ByteInterval(contents=raw_data, blocks=[block])
    sect = gtirb.Section(
        name=".text",
        byte_intervals=[interval],
        flags={
            gtirb.Section.Flag.Loaded,
            gtirb.Section.Flag.Initialized,
            gtirb.Section.Flag.Readable,
        },
    )
    mod.sections.add(sect)

    with caplog.at_level(logging.DEBUG):
        gtirb_rewriting.utils.show_block_asm(block)
        assert "pushfq" in caplog.text
        assert "popfq" in caplog.text


def test_insert_bytes():
    ir = gtirb.IR()
    m = gtirb.Module(isa=gtirb.Module.ISA.X64, name="test")
    m.ir = ir
    s = gtirb.Section(name=".text")
    s.module = m
    bi = gtirb.ByteInterval(
        contents=b"\x00\x01\x02\x03\x04\x05\x06\x07", address=0x1000
    )
    bi.section = s
    b = gtirb.CodeBlock(offset=2, size=2)
    b.byte_interval = bi
    b2 = gtirb.DataBlock(offset=6, size=2)
    b2.byte_interval = bi
    bi.symbolic_expressions[6] = gtirb.SymAddrConst(0, None)
    new_block = gtirb.CodeBlock(size=2)
    gtirb_rewriting.utils._modify_block_insert(
        block=b,
        offset=1,
        replacement_length=0,
        new_bytes=b"\x08\x09",
        new_blocks=[new_block],
        new_cfg=gtirb.CFG(),
        new_symbolic_expressions={},
        new_symbols=[],
        new_proxy_blocks=set(),
        functions_by_block={},
    )
    assert bi.address == 0x1000
    assert bi.size == 10
    assert bi.contents == b"\x00\x01\x02\x08\x09\x03\x04\x05\x06\x07"
    assert b.offset == 2
    assert b.size == 4
    assert new_block.byte_interval is None
    assert b2.offset == 8
    assert b2.size == 2
    assert 6 not in bi.symbolic_expressions
    assert 8 in bi.symbolic_expressions


def test_insert_bytes_offset0():
    ir = gtirb.IR()
    m = gtirb.Module(isa=gtirb.Module.ISA.X64, name="test")
    m.ir = ir
    s = gtirb.Section(name=".text")
    s.module = m
    bi = gtirb.ByteInterval(
        contents=b"\x00\x01\x02\x03\x04\x05\x06\x07", address=0x1000
    )
    bi.section = s
    b = gtirb.CodeBlock(offset=2, size=2)
    b.byte_interval = bi
    b2 = gtirb.DataBlock(offset=6, size=2)
    b2.byte_interval = bi
    bi.symbolic_expressions[6] = gtirb.SymAddrConst(0, None)
    new_block = gtirb.CodeBlock(size=2)
    sym = gtirb.Symbol(name="hi", payload=new_block)
    gtirb_rewriting.utils._modify_block_insert(
        block=b,
        offset=0,
        replacement_length=0,
        new_bytes=b"\x08\x09",
        new_blocks=[new_block],
        new_cfg=gtirb.CFG(),
        new_symbolic_expressions={},
        new_symbols=[sym],
        new_proxy_blocks=set(),
        functions_by_block={},
    )
    assert bi.address == 0x1000
    assert bi.size == 10
    assert bi.contents == b"\x00\x01\x08\x09\x02\x03\x04\x05\x06\x07"
    assert b.offset == 2
    assert b.size == 4
    assert new_block.byte_interval is None
    assert sym.referent == b
    assert b2.offset == 8
    assert b2.size == 2
    assert 6 not in bi.symbolic_expressions
    assert 8 in bi.symbolic_expressions


def test_insert_bytes_last():
    ir = gtirb.IR()
    m = gtirb.Module(isa=gtirb.Module.ISA.X64, name="test")
    m.ir = ir
    s = gtirb.Section(name=".text")
    s.module = m
    # this mimics:
    #   jne foo
    #   push %rax
    # foo:
    #   push %rcx
    bi = gtirb.ByteInterval(contents=b"\x75\x00\x50\x51", address=0x1000)
    bi.section = s
    foo_sym = gtirb.Symbol("foo")
    m.symbols.add(foo_sym)
    b = gtirb.CodeBlock(offset=0, size=2)
    b.byte_interval = bi
    b2 = gtirb.CodeBlock(offset=2, size=1)
    b2.byte_interval = bi
    b3 = gtirb.CodeBlock(offset=3, size=1)
    b3.byte_interval = bi
    ir.cfg.add(
        gtirb.Edge(
            source=b,
            target=b3,
            label=gtirb.Edge.Label(
                type=gtirb.Edge.Type.Branch, conditional=True
            ),
        )
    )
    ir.cfg.add(
        gtirb.Edge(
            source=b,
            target=b2,
            label=gtirb.Edge.Label(type=gtirb.Edge.Type.Fallthrough),
        )
    )
    ir.cfg.add(
        gtirb.Edge(
            source=b2,
            target=b3,
            label=gtirb.Edge.Label(type=gtirb.Edge.Type.Fallthrough),
        )
    )

    new_block = gtirb.CodeBlock(size=1)
    gtirb_rewriting.utils._modify_block_insert(
        block=b,
        offset=2,
        replacement_length=0,
        new_bytes=b"\x90",
        new_blocks=[new_block],
        new_cfg=gtirb.CFG(),
        new_symbolic_expressions={},
        new_symbols=[],
        new_proxy_blocks=set(),
        functions_by_block={},
    )
    assert bi.address == 0x1000
    assert bi.contents == b"\x75\x00\x90\x50\x51"
    assert bi.size == 5
    assert b.offset == 0
    assert b.size == 2
    assert new_block.byte_interval is bi
    assert new_block.offset == 2
    assert new_block.size == 1
    assert b2.offset == 3
    assert b2.size == 1
    assert b3.offset == 4
    assert b3.size == 1

    edges = sorted(b.outgoing_edges, key=lambda e: e.label.type.value)
    assert len(edges) == 2
    assert edges[0].label.type == gtirb.Edge.Type.Branch
    assert edges[0].target == b3
    assert edges[1].label.type == gtirb.Edge.Type.Fallthrough
    assert edges[1].target == new_block

    edges = list(new_block.outgoing_edges)
    assert len(edges) == 1
    assert edges[0].label.type == gtirb.Edge.Type.Fallthrough
    assert edges[0].target == b2

    edges = list(b2.outgoing_edges)
    assert len(edges) == 1
    assert edges[0].label.type == gtirb.Edge.Type.Fallthrough
    assert edges[0].target == b3


def test_insert_bytes_last_no_fallthrough():
    ir = gtirb.IR()
    m = gtirb.Module(isa=gtirb.Module.ISA.X64, name="test")
    m.ir = ir
    s = gtirb.Section(name=".text")
    s.module = m
    bi = gtirb.ByteInterval(
        contents=b"\xB8\x2A\x00\x00\x00\xC3", address=0x1000
    )
    bi.section = s
    return_proxy = gtirb.ProxyBlock()
    m.proxies.add(return_proxy)
    b = gtirb.CodeBlock(offset=0, size=6)
    b.byte_interval = bi
    ir.cfg.add(
        gtirb.Edge(
            source=b,
            target=return_proxy,
            label=gtirb.Edge.Label(type=gtirb.Edge.Type.Return),
        )
    )
    new_block = gtirb.CodeBlock(size=1)
    gtirb_rewriting.utils._modify_block_insert(
        block=b,
        offset=6,
        replacement_length=0,
        new_bytes=b"\x90",
        new_blocks=[new_block],
        new_cfg=gtirb.CFG(),
        new_symbolic_expressions={},
        new_symbols=[],
        new_proxy_blocks=set(),
        functions_by_block={},
    )
    assert bi.address == 0x1000
    assert bi.contents == b"\xB8\x2A\x00\x00\x00\xC3\x90"
    assert bi.size == 7
    assert b.offset == 0
    assert b.size == 6
    assert new_block.byte_interval is bi
    assert new_block.offset == 6
    assert new_block.size == 1

    edges = list(b.outgoing_edges)
    assert len(edges) == 1
    assert edges[0].label.type == gtirb.Edge.Type.Return
    assert edges[0].target == return_proxy

    in_edges = list(new_block.incoming_edges)
    assert not in_edges

    edges = list(new_block.outgoing_edges)
    assert not edges


def test_replace_bytes_offset0():
    ir = gtirb.IR()
    m = gtirb.Module(isa=gtirb.Module.ISA.X64, name="test")
    m.ir = ir
    s = gtirb.Section(name=".text")
    s.module = m
    bi = gtirb.ByteInterval(
        contents=b"\x00\x01\x02\x03\x04\x05\x06\x07", address=0x1000
    )
    bi.section = s
    b = gtirb.CodeBlock(offset=2, size=2)
    b.byte_interval = bi
    b2 = gtirb.DataBlock(offset=6, size=2)
    b2.byte_interval = bi
    bi.symbolic_expressions[2] = gtirb.SymAddrConst(0, None)
    bi.symbolic_expressions[3] = gtirb.SymAddrConst(0, None)
    bi.symbolic_expressions[6] = gtirb.SymAddrConst(0, None)
    new_block = gtirb.CodeBlock(size=1)
    sym = gtirb.Symbol(name="hi", payload=new_block)
    gtirb_rewriting.utils._modify_block_insert(
        block=b,
        offset=0,
        replacement_length=1,
        new_bytes=b"\x08",
        new_blocks=[new_block],
        new_cfg=gtirb.CFG(),
        new_symbolic_expressions={},
        new_symbols=[sym],
        new_proxy_blocks=set(),
        functions_by_block={},
    )
    assert bi.address == 0x1000
    assert bi.contents == b"\x00\x01\x08\x03\x04\x05\x06\x07"
    assert bi.size == 8
    assert b.offset == 2
    assert b.size == 2
    assert new_block.byte_interval is None
    assert sym.referent == b
    assert b2.offset == 6
    assert b2.size == 2
    assert list(bi.symbolic_expressions.keys()) == [3, 6]


def test_replace_bytes_last():
    ir = gtirb.IR()
    m = gtirb.Module(isa=gtirb.Module.ISA.X64, name="test")
    m.ir = ir
    s = gtirb.Section(name=".text")
    s.module = m
    bi = gtirb.ByteInterval(
        contents=b"\x57\xE8\x00\x00\x00\x00\x0f\x0b", address=0x1000
    )
    bi.section = s
    extern_func_proxy = gtirb.ProxyBlock()
    extern_func_sym = gtirb.Symbol("puts", payload=extern_func_proxy)
    m.symbols.add(extern_func_sym)
    b = gtirb.CodeBlock(offset=0, size=6)
    b.byte_interval = bi
    b2 = gtirb.DataBlock(offset=6, size=2)
    b2.byte_interval = bi
    ir.cfg.add(
        gtirb.Edge(
            source=b,
            target=b2,
            label=gtirb.Edge.Label(type=gtirb.Edge.Type.Fallthrough),
        )
    )
    ir.cfg.add(
        gtirb.Edge(
            source=b,
            target=extern_func_proxy,
            label=gtirb.Edge.Label(type=gtirb.Edge.Type.Call),
        )
    )
    bi.symbolic_expressions[2] = gtirb.SymAddrConst(0, extern_func_sym)
    new_block = gtirb.CodeBlock(size=1)
    gtirb_rewriting.utils._modify_block_insert(
        block=b,
        offset=1,
        replacement_length=5,
        new_bytes=b"\x90",
        new_blocks=[new_block],
        new_cfg=gtirb.CFG(),
        new_symbolic_expressions={},
        new_symbols=[],
        new_proxy_blocks=set(),
        functions_by_block={},
    )
    assert bi.address == 0x1000
    assert bi.contents == b"\x57\x90\x0f\x0b"
    assert bi.size == 4
    assert b.offset == 0
    assert b.size == 1
    assert new_block.byte_interval is bi
    assert new_block.offset == 1
    assert new_block.size == 1
    assert b2.offset == 2
    assert b2.size == 2
    assert set(bi.symbolic_expressions.keys()) == set()
    assert set(bi.blocks) == {b, new_block, b2}

    edges = list(b.outgoing_edges)
    assert len(edges) == 1
    assert edges[0].label.type == gtirb.Edge.Type.Fallthrough
    assert edges[0].target == new_block

    edges = list(new_block.outgoing_edges)
    assert len(edges) == 1
    assert edges[0].label.type == gtirb.Edge.Type.Fallthrough
    assert edges[0].target == b2


def test_replace_bytes_all():
    ir = gtirb.IR()
    m = gtirb.Module(isa=gtirb.Module.ISA.X64, name="test")
    m.ir = ir
    s = gtirb.Section(name=".text")
    s.module = m
    bi = gtirb.ByteInterval(
        contents=b"\x57\xE8\x00\x00\x00\x00\x0f\x0b", address=0x1000
    )
    bi.section = s
    extern_func_proxy = gtirb.ProxyBlock()
    extern_func_sym = gtirb.Symbol("puts", payload=extern_func_proxy)
    m.symbols.add(extern_func_sym)
    b = gtirb.CodeBlock(offset=0, size=6)
    b.byte_interval = bi
    b2 = gtirb.DataBlock(offset=6, size=2)
    b2.byte_interval = bi
    ir.cfg.add(
        gtirb.Edge(
            source=b,
            target=b2,
            label=gtirb.Edge.Label(type=gtirb.Edge.Type.Fallthrough),
        )
    )
    ir.cfg.add(
        gtirb.Edge(
            source=b,
            target=extern_func_proxy,
            label=gtirb.Edge.Label(type=gtirb.Edge.Type.Call),
        )
    )
    bi.symbolic_expressions[2] = gtirb.SymAddrConst(0, extern_func_sym)
    new_block = gtirb.CodeBlock(size=1)
    gtirb_rewriting.utils._modify_block_insert(
        block=b,
        offset=0,
        replacement_length=b.size,
        new_bytes=b"\x90",
        new_blocks=[new_block],
        new_cfg=gtirb.CFG(),
        new_symbolic_expressions={},
        new_symbols=[],
        new_proxy_blocks=set(),
        functions_by_block={},
    )
    assert bi.address == 0x1000
    assert bi.contents == b"\x90\x0f\x0b"
    assert bi.size == 3
    assert b.offset == 0
    assert b.size == 1
    assert new_block.byte_interval is None
    assert b2.offset == 1
    assert b2.size == 2
    assert set(bi.symbolic_expressions.keys()) == set()
    assert set(bi.blocks) == {b, b2}

    edges = list(b.outgoing_edges)
    assert len(edges) == 1
    assert edges[0].label.type == gtirb.Edge.Type.Fallthrough
    assert edges[0].target == b2


def test_replace_bytes_with_trailing_zerosized_block():
    ir = gtirb.IR()
    m = gtirb.Module(isa=gtirb.Module.ISA.X64, name="test")
    m.ir = ir
    s = gtirb.Section(name=".text")
    s.module = m
    bi = gtirb.ByteInterval(
        contents=b"\x57\xE8\x00\x00\x00\x00\x0f\x0b", address=0x1000
    )
    bi.section = s
    extern_func_proxy = gtirb.ProxyBlock()
    extern_func_sym = gtirb.Symbol("puts", payload=extern_func_proxy)
    m.symbols.add(extern_func_sym)
    b = gtirb.CodeBlock(offset=0, size=6)
    b.byte_interval = bi
    b2 = gtirb.DataBlock(offset=6, size=2)
    b2.byte_interval = bi
    ir.cfg.add(
        gtirb.Edge(
            source=b,
            target=b2,
            label=gtirb.Edge.Label(type=gtirb.Edge.Type.Fallthrough),
        )
    )
    ir.cfg.add(
        gtirb.Edge(
            source=b,
            target=extern_func_proxy,
            label=gtirb.Edge.Label(type=gtirb.Edge.Type.Call),
        )
    )
    bi.symbolic_expressions[2] = gtirb.SymAddrConst(0, extern_func_sym)
    # This mimics a patch of:
    #   jmp foo
    #   foo:
    new_block = gtirb.CodeBlock(size=5)
    new_block2 = gtirb.CodeBlock(size=0)
    foo_symbol = gtirb.Symbol("foo", payload=new_block2)
    new_cfg = gtirb.CFG()
    new_cfg.add(
        gtirb.Edge(
            source=new_block,
            target=new_block2,
            label=gtirb.Edge.Label(type=gtirb.Edge.Type.Branch),
        )
    )
    gtirb_rewriting.utils._modify_block_insert(
        block=b,
        offset=1,
        replacement_length=5,
        new_bytes=b"\xEB\x00\x00\x00\x00",
        new_blocks=[new_block, new_block2],
        new_cfg=new_cfg,
        new_symbolic_expressions={1: gtirb.SymAddrConst(0, foo_symbol)},
        new_symbols=[foo_symbol],
        new_proxy_blocks=set(),
        functions_by_block={},
    )
    assert bi.address == 0x1000
    assert bi.contents == b"\x57\xEB\x00\x00\x00\x00\x0f\x0b"
    assert bi.size == 8
    assert b.offset == 0
    assert b.size == 1
    assert new_block.byte_interval == bi
    assert new_block.offset == 1
    assert new_block.size == 5
    assert new_block2.byte_interval is None
    assert b2.offset == 6
    assert b2.size == 2
    assert set(bi.symbolic_expressions.keys()) == {2}
    assert bi.symbolic_expressions[2].symbol == foo_symbol
    assert foo_symbol.referent is b2

    edges = list(b.outgoing_edges)
    assert len(edges) == 1
    assert edges[0].label.type == gtirb.Edge.Type.Fallthrough
    assert edges[0].target == new_block

    edges = list(new_block.outgoing_edges)
    assert len(edges) == 1
    assert edges[0].label.type == gtirb.Edge.Type.Branch
    assert edges[0].target == b2


def test_replace_bytes_in_place_no_symbol():
    ir = gtirb.IR()
    m = gtirb.Module(isa=gtirb.Module.ISA.X64, name="test")
    m.ir = ir
    s = gtirb.Section(name=".text")
    s.module = m
    bi = gtirb.ByteInterval(contents=b"\x50\x51\x52", address=0x1000)
    bi.section = s

    b = gtirb.CodeBlock(offset=0, size=3)
    b.byte_interval = bi
    new_block = gtirb.CodeBlock(size=1)
    gtirb_rewriting.utils._modify_block_insert(
        block=b,
        offset=1,
        replacement_length=1,
        new_bytes=b"\x57",
        new_blocks=[new_block],
        new_cfg=gtirb.CFG(),
        new_symbolic_expressions={},
        new_symbols=[],
        new_proxy_blocks=set(),
        functions_by_block={},
    )
    assert bi.address == 0x1000
    assert bi.contents == bytearray(b"\x50\x57\x52")
    assert bi.size == 3
    assert b.offset == 0
    assert b.size == 3
    assert new_block.byte_interval is None  # discarded
    assert set(bi.symbolic_expressions.keys()) == set()
    assert set(bi.blocks) == {b}
    assert len(list(b.outgoing_edges)) == 0


def test_replace_bytes_in_place_with_symbol():
    # in place replacement is expected not to happen because of the symbol
    ir = gtirb.IR()
    m = gtirb.Module(isa=gtirb.Module.ISA.X64, name="test")
    m.ir = ir
    s = gtirb.Section(name=".text")
    s.module = m
    bi = gtirb.ByteInterval(contents=b"\x50\x51\x52", address=0x1000)
    bi.section = s

    b = gtirb.CodeBlock(offset=0, size=3)
    b.byte_interval = bi
    new_block = gtirb.CodeBlock(size=1)
    new_sym = gtirb.Symbol("new", payload=new_block)
    gtirb_rewriting.utils._modify_block_insert(
        block=b,
        offset=1,
        replacement_length=1,
        new_bytes=b"\x57",
        new_blocks=[new_block],
        new_cfg=gtirb.CFG(),
        new_symbolic_expressions={},
        new_symbols=[new_sym],
        new_proxy_blocks=set(),
        functions_by_block={},
    )
    assert bi.address == 0x1000
    assert bi.contents == bytearray(b"\x50\x57\x52")
    assert bi.size == 3
    assert b.offset == 0
    assert b.size == 1
    assert new_block.byte_interval is bi
    assert new_block.offset == 1
    assert new_block.size == 2
    assert set(bi.symbolic_expressions.keys()) == set()
    assert set(bi.blocks) == {b, new_block}
    assert new_sym in m.symbols

    edges = list(b.outgoing_edges)
    assert len(edges) == 1
    assert edges[0].label.type == gtirb.Edge.Type.Fallthrough
    assert edges[0].target == new_block


def test_insert_call_edges():
    ir = gtirb.IR()
    m = gtirb.Module(isa=gtirb.Module.ISA.X64, name="test")
    m.ir = ir
    s = gtirb.Section(name=".text")
    s.module = m
    bi = gtirb.ByteInterval(address=0x1000)
    bi.section = s

    # This mimics a function that's present in the binary but not called
    func1_block_content = b"\xC3"
    func1_block = gtirb.CodeBlock(offset=0, size=len(func1_block_content))
    func1_block.byte_interval = bi
    bi.contents += func1_block_content
    bi.size += len(func1_block_content)

    return_proxy = gtirb.ProxyBlock()
    m.proxies.add(return_proxy)
    ir.cfg.add(
        gtirb.Edge(
            source=func1_block,
            target=return_proxy,
            label=gtirb.Edge.Label(type=gtirb.Edge.Type.Return),
        )
    )
    func1_sym = gtirb.Symbol(name="func1", payload=func1_block)
    m.symbols.add(func1_sym)

    # We need functions because that's how we determine which return edges to
    # update.
    func_uuid = uuid.uuid4()
    m.aux_data["functionNames"] = gtirb.AuxData(
        type_name="mapping<uuid,uuid>", data={func_uuid: func1_sym}
    )
    m.aux_data["functionEntries"] = gtirb.AuxData(
        type_name="mapping<uuid,set<uuid>>", data={func_uuid: {func1_block}}
    )
    m.aux_data["functionBlocks"] = gtirb.AuxData(
        type_name="mapping<uuid,set<uuid>>", data={func_uuid: {func1_block}}
    )
    functions_by_block = {func1_block: func_uuid}

    # Now another block that's just a nop for us to insert into
    b_content = b"\x90"
    b = gtirb.CodeBlock(offset=bi.size, size=len(b_content))
    b.byte_interval = bi
    bi.contents += b_content
    bi.size += len(b_content)

    # This mimics a patch of:
    #   call func1
    #   nop
    new_block = gtirb.CodeBlock(size=5)
    new_block2 = gtirb.CodeBlock(size=1)
    new_cfg = gtirb.CFG()
    new_cfg.add(
        gtirb.Edge(
            source=new_block,
            target=func1_block,
            label=gtirb.Edge.Label(type=gtirb.Edge.Type.Call),
        )
    )
    new_cfg.add(
        gtirb.Edge(
            source=new_block,
            target=new_block2,
            label=gtirb.Edge.Label(type=gtirb.Edge.Type.Fallthrough),
        )
    )
    gtirb_rewriting.utils._modify_block_insert(
        block=b,
        offset=0,
        replacement_length=0,
        new_bytes=b"\xEB\x00\x00\x00\x00\x90",
        new_blocks=[new_block, new_block2],
        new_cfg=new_cfg,
        new_symbolic_expressions={},
        new_symbols=[],
        new_proxy_blocks=set(),
        functions_by_block=functions_by_block,
    )

    assert bi.contents == b"\xc3\xEB\x00\x00\x00\x00\x90\x90"

    return_edges = [
        edge for edge in ir.cfg if edge.label.type == gtirb.Edge.Type.Return
    ]
    assert len(return_edges) == 1
    assert return_edges[0].source == func1_block
    assert return_edges[0].target == new_block2


def test_remove_call_edges():
    ir = gtirb.IR()
    m = gtirb.Module(isa=gtirb.Module.ISA.X64, name="test")
    m.ir = ir
    s = gtirb.Section(name=".text")
    s.module = m
    bi = gtirb.ByteInterval(address=0x1000)
    bi.section = s

    # This mimics a function that's present in the binary and has one caller
    func1_block_content = b"\xC3"
    func1_block = gtirb.CodeBlock(
        offset=bi.size, size=len(func1_block_content)
    )
    func1_block.byte_interval = bi
    bi.contents += func1_block_content
    bi.size += len(func1_block_content)

    func1_sym = gtirb.Symbol(name="func1", payload=func1_block)
    m.symbols.add(func1_sym)

    # We need functions because that's how we determine which return edges to
    # update.
    func_uuid = uuid.uuid4()
    m.aux_data["functionNames"] = gtirb.AuxData(
        type_name="mapping<uuid,uuid>", data={func_uuid: func1_sym}
    )
    m.aux_data["functionEntries"] = gtirb.AuxData(
        type_name="mapping<uuid,set<uuid>>", data={func_uuid: {func1_block}}
    )
    m.aux_data["functionBlocks"] = gtirb.AuxData(
        type_name="mapping<uuid,set<uuid>>", data={func_uuid: {func1_block}}
    )
    functions_by_block = {func1_block: func_uuid}

    # Now another bit of code that calls it
    b_content = b"\xEB\x00\x00\x00\x00"
    b = gtirb.CodeBlock(offset=bi.size, size=len(b_content))
    b.byte_interval = bi
    bi.contents += b_content
    bi.size += len(b_content)

    b2_content = b"\x90"
    b2 = gtirb.CodeBlock(offset=bi.size, size=len(b2_content))
    b2.byte_interval = bi
    bi.contents += b2_content
    bi.size += len(b2_content)

    ir.cfg.add(
        gtirb.Edge(
            source=b,
            target=func1_block,
            label=gtirb.Edge.Label(type=gtirb.Edge.Type.Call),
        )
    )
    ir.cfg.add(
        gtirb.Edge(
            source=b,
            target=b2,
            label=gtirb.Edge.Label(type=gtirb.Edge.Type.Fallthrough),
        )
    )
    ir.cfg.add(
        gtirb.Edge(
            source=func1_block,
            target=b2,
            label=gtirb.Edge.Label(type=gtirb.Edge.Type.Return),
        )
    )

    # This mimics a patch of:
    #   nop
    new_block = gtirb.CodeBlock(size=1)
    gtirb_rewriting.utils._modify_block_insert(
        block=b,
        offset=0,
        replacement_length=5,
        new_bytes=b"\x90",
        new_blocks=[new_block],
        new_cfg=gtirb.CFG(),
        new_symbolic_expressions={},
        new_symbols=[],
        new_proxy_blocks=set(),
        functions_by_block=functions_by_block,
    )

    assert bi.contents == b"\xc3\x90\x90"

    call_edges = [
        edge for edge in ir.cfg if edge.label.type == gtirb.Edge.Type.Call
    ]
    assert not call_edges

    return_edges = [
        edge for edge in ir.cfg if edge.label.type == gtirb.Edge.Type.Return
    ]
    assert len(return_edges) == 1
    assert return_edges[0].source == func1_block
    assert isinstance(return_edges[0].target, gtirb.ProxyBlock)
    assert return_edges[0].target in m.proxies


def test_insert_after_call_edges():
    ir = gtirb.IR()
    m = gtirb.Module(isa=gtirb.Module.ISA.X64, name="test")
    m.ir = ir
    s = gtirb.Section(name=".text")
    s.module = m
    bi = gtirb.ByteInterval(address=0x1000)
    bi.section = s

    # This mimics a function that's present in the binary and has one caller
    func1_block_content = b"\xC3"
    func1_block = gtirb.CodeBlock(
        offset=bi.size, size=len(func1_block_content)
    )
    func1_block.byte_interval = bi
    bi.contents += func1_block_content
    bi.size += len(func1_block_content)

    func1_sym = gtirb.Symbol(name="func1", payload=func1_block)
    m.symbols.add(func1_sym)

    # We need functions because that's how we determine which return edges to
    # update.
    func_uuid = uuid.uuid4()
    m.aux_data["functionNames"] = gtirb.AuxData(
        type_name="mapping<uuid,uuid>", data={func_uuid: func1_sym}
    )
    m.aux_data["functionEntries"] = gtirb.AuxData(
        type_name="mapping<uuid,set<uuid>>", data={func_uuid: {func1_block}}
    )
    m.aux_data["functionBlocks"] = gtirb.AuxData(
        type_name="mapping<uuid,set<uuid>>", data={func_uuid: {func1_block}}
    )
    functions_by_block = {func1_block: func_uuid}

    # Now another bit of code that calls it
    b_content = b"\xEB\x00\x00\x00\x00"
    b = gtirb.CodeBlock(offset=bi.size, size=len(b_content))
    b.byte_interval = bi
    bi.contents += b_content
    bi.size += len(b_content)

    b2_content = b"\x90"
    b2 = gtirb.CodeBlock(offset=bi.size, size=len(b2_content))
    b2.byte_interval = bi
    bi.contents += b2_content
    bi.size += len(b2_content)

    ir.cfg.add(
        gtirb.Edge(
            source=b,
            target=func1_block,
            label=gtirb.Edge.Label(type=gtirb.Edge.Type.Call),
        )
    )
    ir.cfg.add(
        gtirb.Edge(
            source=b,
            target=b2,
            label=gtirb.Edge.Label(type=gtirb.Edge.Type.Fallthrough),
        )
    )
    ir.cfg.add(
        gtirb.Edge(
            source=func1_block,
            target=b2,
            label=gtirb.Edge.Label(type=gtirb.Edge.Type.Return),
        )
    )

    # This mimics a patch of:
    #   nop
    new_block = gtirb.CodeBlock(size=1)
    gtirb_rewriting.utils._modify_block_insert(
        block=b,
        offset=5,
        replacement_length=0,
        new_bytes=b"\x90",
        new_blocks=[new_block],
        new_cfg=gtirb.CFG(),
        new_symbolic_expressions={},
        new_symbols=[],
        new_proxy_blocks=set(),
        functions_by_block=functions_by_block,
    )

    assert bi.contents == b"\xc3\xEB\x00\x00\x00\x00\x90\x90"

    return_edges = [
        edge for edge in ir.cfg if edge.label.type == gtirb.Edge.Type.Return
    ]
    assert len(return_edges) == 1
    assert return_edges[0].source == func1_block
    assert return_edges[0].target == new_block


def test_new_return_edges():
    ir = gtirb.IR()
    m = gtirb.Module(isa=gtirb.Module.ISA.X64, name="test")
    m.ir = ir
    s = gtirb.Section(name=".text")
    s.module = m
    bi = gtirb.ByteInterval(address=0x1000)
    bi.section = s

    # This mimics a function that's present in the binary and has one caller
    func1_block_content = b"\xC3"
    func1_block = gtirb.CodeBlock(
        offset=bi.size, size=len(func1_block_content)
    )
    func1_block.byte_interval = bi
    bi.contents += func1_block_content
    bi.size += len(func1_block_content)

    func1_sym = gtirb.Symbol(name="func1", payload=func1_block)
    m.symbols.add(func1_sym)

    # We need functions because that's how we determine which return edges to
    # update.
    func_uuid = uuid.uuid4()
    m.aux_data["functionNames"] = gtirb.AuxData(
        type_name="mapping<uuid,uuid>", data={func_uuid: func1_sym}
    )
    m.aux_data["functionEntries"] = gtirb.AuxData(
        type_name="mapping<uuid,set<uuid>>", data={func_uuid: {func1_block}}
    )
    m.aux_data["functionBlocks"] = gtirb.AuxData(
        type_name="mapping<uuid,set<uuid>>", data={func_uuid: {func1_block}}
    )
    functions_by_block = {func1_block: func_uuid}

    # Now another bit of code that calls it
    b_content = b"\xEB\x00\x00\x00\x00"
    b = gtirb.CodeBlock(offset=bi.size, size=len(b_content))
    b.byte_interval = bi
    bi.contents += b_content
    bi.size += len(b_content)

    b2_content = b"\x90"
    b2 = gtirb.CodeBlock(offset=bi.size, size=len(b2_content))
    b2.byte_interval = bi
    bi.contents += b2_content
    bi.size += len(b2_content)

    ir.cfg.add(
        gtirb.Edge(
            source=b,
            target=func1_block,
            label=gtirb.Edge.Label(type=gtirb.Edge.Type.Call),
        )
    )
    ir.cfg.add(
        gtirb.Edge(
            source=b,
            target=b2,
            label=gtirb.Edge.Label(type=gtirb.Edge.Type.Fallthrough),
        )
    )
    ir.cfg.add(
        gtirb.Edge(
            source=func1_block,
            target=b2,
            label=gtirb.Edge.Label(type=gtirb.Edge.Type.Return),
        )
    )

    # This mimics a patch of:
    #   ret
    new_block = gtirb.CodeBlock(size=1)
    new_block2 = gtirb.CodeBlock(size=0)
    return_proxy = gtirb.ProxyBlock()
    new_cfg = gtirb.CFG()
    new_cfg.add(
        gtirb.Edge(
            source=new_block,
            target=return_proxy,
            label=gtirb.Edge.Label(type=gtirb.Edge.Type.Return),
        )
    )
    gtirb_rewriting.utils._modify_block_insert(
        block=func1_block,
        offset=0,
        replacement_length=0,
        new_bytes=b"\xC3",
        new_blocks=[new_block, new_block2],
        new_cfg=new_cfg,
        new_symbolic_expressions={},
        new_symbols=[],
        new_proxy_blocks={return_proxy},
        functions_by_block=functions_by_block,
    )

    assert bi.contents == b"\xC3\xC3\xEB\x00\x00\x00\x00\x90"

    return_edges = [
        edge for edge in ir.cfg if edge.label.type == gtirb.Edge.Type.Return
    ]
    assert len(return_edges) == 2
    assert return_edges[0].target == b2
    assert return_edges[1].target == b2
    assert return_proxy not in m.proxies
