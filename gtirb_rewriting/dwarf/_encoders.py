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

from abc import ABC, abstractmethod
from typing import Generic, Optional, Tuple, TypeVar, Union

import leb128
from typing_extensions import BinaryIO, Literal

_T = TypeVar("_T")

ByteOrder = Literal["little", "big"]


class _Encoder(Generic[_T]):
    """
    Base class for encoders that can be used to serialize and deserialize
    values.

    The signatures for encode and decode differ between fused encoders and
    standalone encoders. For encoding and decoding, fused encoders are given
    the registered opcode value and the value to encode/decode. Standalone
    encoders just get the value they need to encode/decode and must be
    independent of the opcode.

    Therefore the base class only handles validation for values. This allows
    for encoders to be treated uniformly, whether the encoder is fused or
    standalone.
    """

    def validate(self, value: _T, ptr_size: Optional[int]) -> None:
        """
        Validates that the value can be represented by this encoder. Raises a
        ValueError it is unrepresentable.
        """
        pass


class _FusedEncoder(ABC, _Encoder[_T]):
    """
    An encoder where the the operand is part of the opcode.
    """

    @abstractmethod
    def encode(
        self,
        opcode: int,
        value: _T,
        byteorder: ByteOrder,
        ptr_size: int,
    ) -> Union[bytes, bytearray]:
        """
        Encodes the value and the opcode to produce a 'fused' value.

        :param opcode: The opcode.
        :param value: The value to encode.
        :param byteorder: The endianness.
        :param ptr_size: The pointer size, in bytes, for the target.
        :returns: The encoded value and opcode.
        """

    @abstractmethod
    def decode(
        self,
        opcode: int,
        byte_value: int,
        byteorder: ByteOrder,
        ptr_size: int,
    ) -> _T:
        """
        Decodes a value that is mixed in with the opcode.

        :param opcode: The opcode.
        :param byte_value: The byte that's mixed with the opcode.
        :param byteorder: The endianness.
        :param ptr_size: The pointer size, in bytes, for the target.
        :returns: The decoded value.
        """


class _AddToOpcodeEncoder(_FusedEncoder[int]):
    """
    The operand value is added to the opcode.
    """

    def __init__(self, upper_bound: int) -> None:
        assert 0 < upper_bound <= 0xFF
        super().__init__()
        self.upper_bound = upper_bound

    def encode(
        self,
        opcode: int,
        value: int,
        byteorder: ByteOrder,
        ptr_size: int,
    ) -> bytes:
        return (opcode + value).to_bytes(1, byteorder)

    def decode(
        self,
        opcode: int,
        byte_value: int,
        byteorder: ByteOrder,
        ptr_size: int,
    ) -> int:
        return byte_value - opcode

    def validate(self, value: int, ptr_size: Optional[int]):
        if value < 0:
            raise ValueError("value must be positive")
        if value >= self.upper_bound:
            raise ValueError(f"value must be less than {self.upper_bound}")


class _StandaloneEncoder(ABC, _Encoder[_T]):
    """
    Encodes a value as bytes.
    """

    @abstractmethod
    def encode(
        self, value: _T, byteorder: ByteOrder, ptr_size: int
    ) -> Union[bytes, bytearray]:
        """
        Encodes a value as bytes.

        :param value: The value.
        :param byteorder: The endianness.
        :param ptr_size: The pointer size, in bytes, for the target.
        :returns: The encoded bytes.
        """

    @abstractmethod
    def decode(
        self, io: BinaryIO, byteorder: ByteOrder, ptr_size: int
    ) -> Tuple[_T, int]:
        """
        Decodes a value.

        :param io: The stream to read from.
        :param byteorder: The endianness.
        :param ptr_size: The pointer size, in bytes, for the target.
        :returns: The decoded value and the number of bytes read.
        """


class _ULEB128Encoder(_StandaloneEncoder[int]):
    def encode(
        self, value: int, byteorder: ByteOrder, ptr_size: int
    ) -> bytearray:
        return leb128.u.encode(value)

    def decode(
        self, io: BinaryIO, byteorder: ByteOrder, ptr_size: int
    ) -> Tuple[int, int]:
        return leb128.u.decode_reader(io)

    def validate(self, value: int, ptr_size: Optional[int]):
        if value < 0:
            raise ValueError("value must be positive")


class _SLEB128Encoder(_StandaloneEncoder[int]):
    def encode(
        self, value: int, byteorder: ByteOrder, ptr_size: int
    ) -> bytearray:
        return leb128.i.encode(value)

    def decode(
        self, io: BinaryIO, byteorder: ByteOrder, ptr_size: int
    ) -> Tuple[int, int]:
        return leb128.i.decode_reader(io)


class _IntEncoder(_StandaloneEncoder[int]):
    def __init__(self, byte_size: int, signed: bool):
        self.byte_size = byte_size
        self.signed = signed

    def encode(self, value: int, byteorder: ByteOrder, ptr_size: int) -> bytes:
        return value.to_bytes(self.byte_size, byteorder, signed=self.signed)

    def decode(
        self, io: BinaryIO, byteorder: ByteOrder, ptr_size: int
    ) -> Tuple[int, int]:
        return (
            int.from_bytes(
                io.read(self.byte_size), byteorder, signed=self.signed
            ),
            self.byte_size,
        )

    def validate(self, value: int, ptr_size: Optional[int]):
        size_range = _int_domain(self.byte_size * 8, signed=self.signed)

        if value not in size_range:
            name = "a signed" if self.signed else "an unsigned"
            raise ValueError(
                f"value cannot fit in {self.byte_size}-byte {name} integer"
            )


class _UIntEncoder(_IntEncoder):
    def __init__(self, byte_size: int):
        super().__init__(byte_size, signed=False)


class _SIntEncoder(_IntEncoder):
    def __init__(self, byte_size: int):
        super().__init__(byte_size, signed=True)


class _UIntPtrEncoder(_StandaloneEncoder[int]):
    def encode(self, value: int, byteorder: ByteOrder, ptr_size: int) -> bytes:
        return value.to_bytes(ptr_size, byteorder, signed=False)

    def decode(
        self, io: BinaryIO, byteorder: ByteOrder, ptr_size: int
    ) -> Tuple[int, int]:
        return (
            int.from_bytes(io.read(ptr_size), byteorder, signed=False),
            ptr_size,
        )

    def validate(self, value: int, ptr_size: Optional[int]):
        if value < 0:
            raise ValueError("value must be positive")
        if ptr_size is not None:
            size_range = _int_domain(ptr_size * 8, signed=False)

            if value not in size_range:
                raise ValueError(
                    f"value cannot fit in {ptr_size}-byte unsigned integer"
                )


def _int_domain(bit_size: int, signed: bool) -> range:
    if not signed:
        return range(0, 2**bit_size)
    else:
        return range(-(2 ** (bit_size - 1)), 2 ** (bit_size - 1))
