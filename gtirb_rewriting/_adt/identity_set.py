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

from typing import Dict, Iterator, MutableSet, TypeVar

T = TypeVar("T")


class IdentitySet(MutableSet[T]):
    """
    A set that uses object identity instead of __hash__/__eq__.
    """

    def __init__(self, iterable=()):
        self._map: Dict[int, T] = {}
        self |= iterable

    def __len__(self) -> int:
        return len(self._map)

    def __iter__(self) -> Iterator[T]:
        yield from self._map.values()

    def __contains__(self, x: object) -> bool:
        return id(x) in self._map

    def add(self, value: T) -> None:
        self._map[id(value)] = value

    def discard(self, value: T) -> None:
        self._map.pop(id(value), None)

    def __repr__(self) -> str:
        if not self:
            return "%s()" % (self.__class__.__name__,)
        return "%s(%r)" % (self.__class__.__name__, list(self))
