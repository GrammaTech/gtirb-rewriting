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

import pytest
from gtirb_rewriting._adt import LinkedListNode


def test_linked_list():
    root = LinkedListNode(1)
    assert root.next is None
    assert root.prev is None
    assert root.value == 1

    second = LinkedListNode(2)
    root.insert_node_after(second)
    assert root.prev is None
    assert root.next is second
    assert root.value == 1

    assert second.prev is root
    assert second.next is None
    assert second.value == 2

    with pytest.raises(ValueError):
        root.insert_node_after(second)

    with pytest.raises(ValueError):
        root.insert_node_before(second)

    third = LinkedListNode(3)
    second.insert_node_before(third)
    assert root.prev is None
    assert root.next is third
    assert root.value == 1

    assert second.prev is third
    assert second.next is None
    assert second.value == 2

    assert third.prev is root
    assert third.next is second
    assert third.value == 3

    third.unlink()

    assert root.prev is None
    assert root.next is second
    assert root.value == 1

    assert second.prev is root
    assert second.next is None
    assert second.value == 2

    assert third.prev is None
    assert third.next is None
    assert third.value == 3
