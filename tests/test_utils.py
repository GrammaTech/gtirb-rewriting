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

import capstone
import gtirb
import gtirb_rewriting.utils


def test_triples():
    mod = gtirb.Module(
        isa=gtirb.Module.ISA.X64, file_format=gtirb.Module.FileFormat.ELF
    )
    assert gtirb_rewriting.utils._target_triple(mod) == "x86_64-pc-linux"

    mod = gtirb.Module(
        isa=gtirb.Module.ISA.IA32, file_format=gtirb.Module.FileFormat.ELF
    )
    assert gtirb_rewriting.utils._target_triple(mod) == "i386-pc-linux"

    mod = gtirb.Module(
        isa=gtirb.Module.ISA.X64, file_format=gtirb.Module.FileFormat.PE
    )
    assert gtirb_rewriting.utils._target_triple(mod) == "x86_64-pc-win32"

    mod = gtirb.Module(
        isa=gtirb.Module.ISA.IA32, file_format=gtirb.Module.FileFormat.PE
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
        isa=gtirb.Module.ISA.X64, file_format=gtirb.Module.FileFormat.ELF
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
    m = gtirb.Module(isa=gtirb.Module.ISA.X64)
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
    gtirb_rewriting.utils._modify_block_insert(b, b"\x08\x09", 1)
    assert bi.address == 0x1000
    assert bi.size == 10
    assert bi.contents == b"\x00\x01\x02\x08\x09\x03\x04\x05\x06\x07"
    assert b.offset == 2
    assert b.size == 4
    assert b2.offset == 8
    assert b2.size == 2
    assert 6 not in bi.symbolic_expressions
    assert 8 in bi.symbolic_expressions
