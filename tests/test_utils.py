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

import capstone_gt
import gtirb
from gtirb_test_helpers import (
    add_code_block,
    add_data_block,
    add_proxy_block,
    add_symbol,
    add_text_section,
    create_test_module,
)

import gtirb_rewriting.utils


def test_triples():
    assert (
        gtirb_rewriting.utils._target_triple(
            gtirb.Module.ISA.X64, gtirb.Module.FileFormat.ELF
        )
        == "x86_64-pc-linux"
    )

    assert (
        gtirb_rewriting.utils._target_triple(
            gtirb.Module.ISA.IA32, gtirb.Module.FileFormat.ELF
        )
        == "i386-pc-linux"
    )

    assert (
        gtirb_rewriting.utils._target_triple(
            gtirb.Module.ISA.X64, gtirb.Module.FileFormat.PE
        )
        == "x86_64-pc-win32"
    )

    assert (
        gtirb_rewriting.utils._target_triple(
            gtirb.Module.ISA.IA32, gtirb.Module.FileFormat.PE
        )
        == "i386-pc-win32"
    )


def test_nonterminator_instructions():
    cs = capstone_gt.Cs(capstone_gt.CS_ARCH_X86, capstone_gt.CS_MODE_64)
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
    cs = capstone_gt.Cs(capstone_gt.CS_ARCH_X86, capstone_gt.CS_MODE_64)
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


def test_show_code_block_asm(caplog):
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)
    sym = add_symbol(m, "puts", add_proxy_block(m))

    # pushfq; popfq; call puts+4
    block = add_code_block(
        bi, b"\x9C\x9D\xE8\x00\x00\x00\x00", {3: gtirb.SymAddrConst(4, sym)}
    )

    with caplog.at_level(logging.DEBUG):
        gtirb_rewriting.utils.show_block_asm(block)
        assert "pushfq" in caplog.text
        assert "popfq" in caplog.text
        assert "call" in caplog.text
        assert "puts + 4" in caplog.text


def test_show_data_block_asm(caplog):
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)
    block = add_data_block(bi, b"\x01\x02\x03\x04")

    with caplog.at_level(logging.DEBUG):
        gtirb_rewriting.utils.show_block_asm(block)
        assert ".byte\t1" in caplog.text
        assert ".byte\t2" in caplog.text
        assert ".byte\t3" in caplog.text
        assert ".byte\t4" in caplog.text
