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

import io
from typing import Callable, Literal

import pytest

from gtirb_rewriting.dwarf.expr import (
    OpBra,
    OpBReg,
    OpBRegX,
    OpConst,
    OpConst1S,
    OpConst1U,
    OpConst2U,
    OpConst8U,
    OpConstS,
    OpConstU,
    Operation,
    OpLit,
    OpReg,
    OpRegX,
    make_const_op,
)


def check_encode_decode(
    obj: Operation,
    byteorder: Literal["big", "little"],
    ptr_size: int,
    expected: bytes,
):
    encoding = obj.encode(byteorder, ptr_size)
    assert encoding == expected

    reader = io.BytesIO(encoding + b"unread")
    decoded, decoded_len = type(obj).decode(reader, byteorder, ptr_size)
    assert decoded_len == len(encoding)
    assert obj == decoded
    assert reader.read(6) == b"unread"


def test_dwarf_expr_bra():
    op = OpBra(16)
    check_encode_decode(op, "little", 8, b"\x28\x10\x00")
    check_encode_decode(op, "big", 8, b"\x28\x00\x10")


def test_dwarf_expr_reg():
    op = OpReg(1)
    check_encode_decode(op, "little", 8, b"\x51")

    op = OpRegX(33)
    check_encode_decode(op, "little", 8, b"\x90\x21")


def test_dwarf_expr_breg():
    op = OpBReg(1, 1)
    check_encode_decode(op, "little", 8, b"\x71\x01")

    op = OpBRegX(33, 1)
    check_encode_decode(op, "little", 8, b"\x92\x21\x01")


@pytest.mark.parametrize(
    "factory",
    (
        OpConst,
        make_const_op,
    ),
    ids=lambda arg: arg.__name__,
)
def test_dwarf_expr_const(factory: Callable[[int], OpConst]):
    op = factory(1)
    assert isinstance(op, OpLit)
    check_encode_decode(op, "little", 8, b"\x31")

    op = factory(32)
    assert isinstance(op, OpConst1U)
    check_encode_decode(op, "little", 8, b"\x08\x20")

    op = factory(-1)
    assert isinstance(op, OpConst1S)
    check_encode_decode(op, "little", 8, b"\x09\xff")

    op = factory(256)
    assert isinstance(op, OpConst2U)
    check_encode_decode(op, "little", 8, b"\x0a\x00\x01")
    check_encode_decode(op, "big", 8, b"\x0a\x01\x00")

    # Value is more compact as a ULEB128
    op = factory(65536)
    assert isinstance(op, OpConstU)
    check_encode_decode(op, "little", 8, b"\x10\x80\x80\x04")
    check_encode_decode(op, "big", 8, b"\x10\x80\x80\x04")

    # Value is more compact as a SLEB128
    op = factory(-65536)
    assert isinstance(op, OpConstS)
    check_encode_decode(op, "little", 8, b"\x11\x80\x80\x7c")
    check_encode_decode(op, "big", 8, b"\x11\x80\x80\x7c")

    op = factory(2**63)
    assert isinstance(op, OpConst8U)
    check_encode_decode(
        op, "little", 8, b"\x0e\x00\x00\x00\x00\x00\x00\x00\x80"
    )
    check_encode_decode(op, "big", 8, b"\x0e\x80\x00\x00\x00\x00\x00\x00\x00")
