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

import uuid
from typing import (
    Any,
    Dict,
    Iterator,
    MutableMapping,
    TypeVar,
    Union,
    overload,
)

import gtirb

T = TypeVar("T")
ElementT = Union[uuid.UUID, gtirb.Node]
T2 = TypeVar("T2")


class OffsetMapping(MutableMapping[gtirb.Offset, T]):
    """Mapping that allows looking up groups of items by their offset element.

    The keys in this mapping are required to be Offsets. If a non-Offset is
    used as a key, it is assumed to be the element_id of an Offset. In that
    case, the corresponding element is a MutableMapping[int, T] of
    displacements to values for every Offset that has the given element_id.

    Examples:
    >>> m = OffsetMapping[str]()
    >>> m[Offset(x, 0)] = "a"     # insert an offset into the map
    >>> m[x] = {1: "b", 2: "c"}   # set all of the offsets associated with x,
    >>> 0 in m[x]                 # dropping any other values for x
    False
    >>> m[x][1] = "d"             # change the value for Offset(x, 1)
    >>> m[Offset(x, 1)]           # get the value for Offset(x, 1)
    'd'
    >>> del m[Offset(x, 2)]       # delete Offset(x, 2) from the map
    """

    def __init__(self, *args, **kw):
        """Create a new OffsetMapping from an iterable and/or keywords."""
        self._data: Dict[ElementT, MutableMapping[int, T]] = {}
        self.update(*args, **kw)

    def __bool__(self) -> bool:
        return any(subdata for subdata in self._data.values())

    def __len__(self) -> int:
        """Get the number of Offsets stored in this mapping."""
        return sum(len(subdata) for subdata in self._data.values())

    def __iter__(self) -> Iterator[gtirb.Offset]:
        """ "Yield the Offsets in this mapping."""
        for elem, subdata in self._data.items():
            for disp in subdata:
                yield gtirb.Offset(elem, disp)

    def node_keys(self) -> Iterator[ElementT]:
        yield from self._data

    @overload
    def __getitem__(self, key: gtirb.Offset) -> T:
        ...

    @overload
    def __getitem__(self, key: ElementT) -> Dict[int, T]:
        ...

    def __getitem__(self, key):
        """Get the value for an Offset or dictionary for an element_id."""
        if isinstance(key, gtirb.Offset):
            elem, disp = key
            if elem in self._data and disp in self._data[elem]:
                return self._data[elem][disp]
            raise KeyError(key)
        else:
            return self._data[key]

    @overload
    def __setitem__(self, key: gtirb.Offset, value: T) -> None:
        ...

    @overload
    def __setitem__(
        self, key: ElementT, value: MutableMapping[int, T]
    ) -> None:
        ...

    def __setitem__(self, key, value):
        """Set the value for an Offset, or all Offsets for an element."""
        if isinstance(key, gtirb.Offset):
            elem, disp = key
            if elem not in self._data:
                self._data[elem] = {}
            self._data[elem][disp] = value
        elif not isinstance(value, MutableMapping):
            raise ValueError("not a MutableMapping: %r" % value)
        else:
            self._data[key] = value

    def __delitem__(self, key: Union[gtirb.Offset, ElementT]) -> None:
        """Delete the mapping for an Offset or all Offsets given an element."""
        if isinstance(key, gtirb.Offset):
            elem, disp = key
            if elem not in self._data or disp not in self._data[elem]:
                raise KeyError(key)
            del self._data[elem][disp]
        else:
            del self._data[key]

    def __contains__(self, key: object) -> bool:
        """
        Determines if the mapping contains a given Offset or any offset for a
        given element.
        """
        if isinstance(key, gtirb.Offset):
            map = self._data.get(key.element_id)
            return map is not None and key.displacement in map
        else:
            return key in self._data

    # Mapping methods
    @overload
    def get(self, key: gtirb.Offset) -> Union[T, None]:
        ...

    @overload
    def get(self, key: gtirb.Offset, default: T2) -> Union[T, T2]:
        ...

    @overload
    def get(self, key: ElementT) -> Union[Dict[int, T], None]:
        ...

    @overload
    def get(self, key: ElementT, default: T2) -> Union[Dict[int, T], T2]:
        ...

    def get(self, *args, **kwargs) -> Any:
        return super().get(*args, **kwargs)

    # MutableMapping methods
    @overload  # type: ignore
    def pop(self, key: gtirb.Offset) -> T:
        ...

    @overload
    def pop(self, key: gtirb.Offset, default: T) -> T:
        ...

    @overload
    def pop(self, key: gtirb.Offset, default: T2) -> Union[T, T2]:
        ...

    @overload
    def pop(self, key: ElementT) -> Dict[int, T]:
        ...

    @overload
    def pop(self, key: ElementT, default: T2) -> Union[Dict[int, T], T2]:
        ...

    def pop(self, *args, **kwargs) -> Any:
        return super().pop(*args, **kwargs)

    @overload  # type: ignore
    def setdefault(self, key: gtirb.Offset, default: T) -> T:
        ...

    @overload
    def setdefault(self, key: ElementT, default: Dict[int, T]) -> Dict[int, T]:
        ...

    def setdefault(self, *args, **kwargs) -> Any:
        return super().setdefault(*args, **kwargs)

    def __repr__(self):
        return repr(dict(self))
