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

from typing import Generic, TypeVar

import leb128
from typing_extensions import Literal

_T = TypeVar("_T")


class _Encoder(Generic[_T]):
    def encode(
        self, value: _T, byteorder: Literal["big", "little"], ptr_size: int
    ) -> bytes:
        ...


class _ULEB128Encoder(_Encoder[int]):
    def encode(
        self, value: int, byteorder: Literal["big", "little"], ptr_size: int
    ) -> bytes:
        return leb128.u.encode(value)


class _SLEB128Encoder(_Encoder[int]):
    def encode(
        self, value: int, byteorder: Literal["big", "little"], ptr_size: int
    ) -> bytes:
        return leb128.i.encode(value)


class _UIntEncoder(_Encoder[int]):
    def __init__(self, size: int):
        self.size = size

    def encode(
        self, value: int, byteorder: Literal["big", "little"], ptr_size: int
    ) -> bytes:
        return value.to_bytes(self.size, byteorder, signed=False)


class _SIntEncoder(_Encoder[int]):
    def __init__(self, size: int):
        self.size = size

    def encode(
        self, value: int, byteorder: Literal["big", "little"], ptr_size: int
    ) -> bytes:
        return value.to_bytes(self.size, byteorder, signed=True)


class _IntPtrEncoder(_Encoder[int]):
    def encode(
        self, value: int, byteorder: Literal["big", "little"], ptr_size: int
    ) -> bytes:
        return value.to_bytes(ptr_size, byteorder, signed=False)
