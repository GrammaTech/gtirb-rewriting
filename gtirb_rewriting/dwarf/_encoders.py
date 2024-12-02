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
from typing import Generic, Tuple, TypeVar, Union

import leb128
from typing_extensions import BinaryIO, Literal

_T = TypeVar("_T")

ByteOrder = Literal["little", "big"]


class _Encoder(Generic[_T]):
    def validate(self, value: _T) -> None:
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
        ...

    @abstractmethod
    def decode(
        self,
        opcode: int,
        byte_value: int,
        byteorder: ByteOrder,
        ptr_size: int,
    ) -> _T:
        ...


class _AddToOpcodeEncoder(_FusedEncoder[int]):
    """
    The operand value is added to the opcode.
    """

    def __init__(self, max_value: int) -> None:
        assert 0 < max_value <= 0xFF
        super().__init__()
        self.max_value = max_value

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

    def validate(self, value: int):
        if value < 0:
            raise ValueError("value must be positive")
        if value > self.max_value:
            raise ValueError(f"value must be less than {self.max_value+1}")


class _Low6BitsEncoder(_FusedEncoder[int]):
    """
    The operand value is stored in the low six bits of the opcode.
    """

    def __init__(self) -> None:
        super().__init__()

    def encode(
        self,
        opcode: int,
        value: int,
        byteorder: ByteOrder,
        ptr_size: int,
    ) -> bytes:
        return (opcode | value).to_bytes(1, byteorder)

    def decode(
        self,
        opcode: int,
        byte_value: int,
        byteorder: ByteOrder,
        ptr_size: int,
    ) -> int:
        return byte_value & 0b111111

    def validate(self, value: int):
        if value not in _int_domain(bit_size=6, signed=False):
            raise ValueError("value cannot fit in a 6-bit unsigned integer")


class _StandaloneEncoder(ABC, _Encoder[_T]):
    @abstractmethod
    def encode(
        self, value: _T, byteorder: ByteOrder, ptr_size: int
    ) -> Union[bytes, bytearray]:
        ...

    @abstractmethod
    def decode(
        self, io: BinaryIO, byteorder: ByteOrder, ptr_size: int
    ) -> Tuple[_T, int]:
        ...


class _ULEB128Encoder(_StandaloneEncoder[int]):
    def encode(
        self, value: int, byteorder: ByteOrder, ptr_size: int
    ) -> bytearray:
        return leb128.u.encode(value)

    def decode(
        self, io: BinaryIO, byteorder: ByteOrder, ptr_size: int
    ) -> Tuple[int, int]:
        return leb128.u.decode_reader(io)

    def validate(self, value: int):
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

    def validate(self, value: int):
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

    def validate(self, value: int):
        if value < 0:
            raise ValueError("value must be positive")


def _int_domain(bit_size: int, signed: bool) -> range:
    if not signed:
        return range(0, 2**bit_size)
    else:
        return range(-(2 ** (bit_size - 1)), 2 ** (bit_size - 1))
