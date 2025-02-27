# GTIRB-Rewriting Rewriting API for GTIRB
# Copyright (C) 2024 GrammaTech, Inc.
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
from typing import Literal

import leb128
import pytest

from gtirb_rewriting.dwarf._encoders import (
    _AddToOpcodeEncoder,
    _SIntEncoder,
    _SLEB128Encoder,
    _UIntEncoder,
    _UIntPtrEncoder,
    _ULEB128Encoder,
)


@pytest.mark.parametrize("byteorder", ("little", "big"))
@pytest.mark.parametrize("size", (1, 2, 4, 8))
@pytest.mark.parametrize(
    "encoder_type", (_SIntEncoder, _UIntEncoder, _UIntPtrEncoder)
)
def test_int_encoder(
    byteorder: Literal["big", "little"], size: int, encoder_type: bool
):
    bit_size = size * 8
    if encoder_type is _SIntEncoder:
        encoder = _SIntEncoder(size)
        values = (-(2 ** (bit_size - 1)), 0, 2 ** (bit_size - 1) - 1)
        signed = True
    elif encoder_type is _UIntEncoder:
        encoder = _UIntEncoder(size)
        values = (0, (2**bit_size) - 1)
        signed = False
    elif encoder_type is _UIntPtrEncoder:
        encoder = _UIntPtrEncoder()
        values = (0, (2**bit_size) - 1)
        signed = False

    for value in values:
        encoder.validate(value)
        encoded = encoder.encode(value, byteorder, ptr_size=size)
        assert encoded == value.to_bytes(size, byteorder, signed=signed)

        stream = io.BytesIO(encoded + b"!")
        decoded_value, read = encoder.decode(stream, byteorder, ptr_size=size)
        assert decoded_value == value
        assert read == size
        assert stream.read() == b"!"

    with pytest.raises(ValueError):
        encoder.validate(values[0] - 1)
    # UIntPtrEncoder does not know its size for validation, so it can't raise
    # an error here.
    if encoder_type is not _UIntPtrEncoder:
        with pytest.raises(ValueError):
            encoder.validate(values[-1] + 1)


@pytest.mark.parametrize("signed", (True, False))
def test_leb128_encoder(signed: bool):
    if signed:
        encoder = _SLEB128Encoder()
        values = (-256, 0, 256)
        m = leb128.i
    else:
        encoder = _ULEB128Encoder()
        values = (0, 256)
        m = leb128.u

    for value in values:
        encoder.validate(value)
        encoded = encoder.encode(value, "little", 8)
        assert encoded == m.encode(value)

        stream = io.BytesIO(encoded + b"!")
        decoded_value, read = encoder.decode(stream, "little", 8)
        assert decoded_value == value
        assert read == stream.tell()
        assert stream.read() == b"!"

    if not signed:
        with pytest.raises(ValueError):
            encoder.validate(-1)


def test_add_to_opcode_encoder():
    encoder = _AddToOpcodeEncoder(0xF)
    encoder.validate(0x01)
    assert encoder.encode(0xF0, 0x01, "little", 8) == b"\xF1"
    assert encoder.decode(0xF0, 0xF1, "little", 8) == 0x01
    with pytest.raises(ValueError):
        encoder.validate(-1)
    with pytest.raises(ValueError):
        encoder.validate(0x10)


def test_low_6_bits_encoder():
    encoder = _AddToOpcodeEncoder(64)
    encoder.validate(0x01)
    assert encoder.encode(0xC0, 0x01, "little", 8) == b"\xC1"
    assert encoder.decode(0xC0, 0xC1, "little", 8) == 0x01
    with pytest.raises(ValueError):
        encoder.validate(-1)
    with pytest.raises(ValueError):
        encoder.validate(0xC0)
