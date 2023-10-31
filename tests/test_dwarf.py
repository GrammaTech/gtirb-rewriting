# GTIRB-Rewriting Rewriting API for GTIRB
# Copyright (C) 2023 GrammaTech, Inc.
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

from gtirb_rewriting._auxdata import NULL_UUID
from gtirb_rewriting.dwarf.cfi import (
    InstAdjustCFAOffset,
    InstEscape,
    InstValExpression,
)
from gtirb_rewriting.dwarf.expr import OpBra, OpBReg, OpConst, OpNot, OpReg


def test_dwarf_expr_bra():
    op = OpBra(16)
    assert op.encode("little", 8) == b"\x28\x10\x00"
    assert op.encode("big", 8) == b"\x28\x00\x10"


def test_dwarf_expr_reg():
    op = OpReg(1)
    assert op.encode("little", 8) == b"\x51"

    op = OpReg(33)
    assert op.encode("little", 8) == b"\x90\x21"


def test_dwarf_expr_breg():
    op = OpBReg(1, 1)
    assert op.encode("little", 8) == b"\x71\x01"

    op = OpBReg(33, 1)
    assert op.encode("little", 8) == b"\x92\x21\x01"


def test_dwarf_expr_const():
    op = OpConst(1)
    assert op.encode("little", 8) == b"\x31"

    op = OpConst(32)
    assert op.encode("little", 8) == b"\x08\x20"

    op = OpConst(-1)
    assert op.encode("little", 8) == b"\x09\xFF"

    op = OpConst(256)
    assert op.encode("little", 8) == b"\x0A\x00\x01"
    assert op.encode("big", 8) == b"\x0A\x01\x00"

    # Value is more compact as a ULEB128
    op = OpConst(65536)
    assert op.encode("little", 8) == b"\x10\x80\x80\x04"
    assert op.encode("big", 8) == b"\x10\x80\x80\x04"

    # Value is more compact as a SLEB128
    op = OpConst(-65536)
    assert op.encode("little", 8) == b"\x11\x80\x80\x7C"
    assert op.encode("big", 8) == b"\x11\x80\x80\x7C"

    op = OpConst(2**63)
    assert op.encode("little", 8) == b"\x0e\x00\x00\x00\x00\x00\x00\x00\x80"
    assert op.encode("big", 8) == b"\x0e\x80\x00\x00\x00\x00\x00\x00\x00"


def test_dwarf_inst_escape():
    inst = InstEscape(b"\x09\xFF")
    assert inst.assembly_string("little", 8) == ".cfi_escape 9, 255"
    assert inst.gtirb_encoding("little", 8) == (
        ".cfi_escape",
        [9, 255],
        NULL_UUID,
    )


def test_dwarf_inst_adjust_cfa_offset():
    inst = InstAdjustCFAOffset(8)
    assert inst.assembly_string("little", 8) == ".cfi_adjust_cfa_offset 8"
    assert inst.gtirb_encoding("little", 8) == (
        ".cfi_adjust_cfa_offset",
        [8],
        NULL_UUID,
    )


def test_dwarf_inst_val_expression():
    inst = InstValExpression(15, [OpConst(1), OpNot()])
    assert inst.assembly_string("little", 8) == ".cfi_escape 22, 15, 2, 49, 32"
    assert inst.gtirb_encoding("little", 8) == (
        ".cfi_escape",
        [22, 15, 2, 49, 32],
        NULL_UUID,
    )
