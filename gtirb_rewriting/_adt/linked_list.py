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

from typing import Generic, Optional, TypeVar

ValueT = TypeVar("ValueT")


class LinkedListNode(Generic[ValueT]):
    """
    A doubly linked list node.
    """

    __slots__ = ("value", "__prev", "__next")

    def __init__(self, value: ValueT):
        self.value = value
        self.__prev = None
        self.__next = None

    @property
    def next(self) -> Optional["LinkedListNode[ValueT]"]:
        return self.__next

    @property
    def prev(self) -> Optional["LinkedListNode[ValueT]"]:
        return self.__prev

    def insert_node_after(self, node: "LinkedListNode[ValueT]") -> None:
        """
        Inserts the requested node after self.
        """
        if node.__next or node.__prev:
            raise ValueError("node is already part of a linked list")

        if self.__next:
            self.__next.__prev = node
            node.__next = self.__next

        node.__prev = self
        self.__next = node

    def unlink(self) -> None:
        """
        Removes self from the linked list it is in.
        """
        if self.__prev:
            self.__prev.__next = self.__next
        if self.__next:
            self.__next.__prev = self.__prev

        self.__prev = None
        self.__next = None
