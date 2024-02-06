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

import gtirb
import pytest
from gtirb_rewriting._adt import BlockOrdering


def test_adjacent_blocksing():
    block1 = gtirb.ByteBlock()
    block2 = gtirb.ByteBlock()
    block3 = gtirb.ByteBlock()
    block4 = gtirb.ByteBlock()

    ordering = BlockOrdering((block1, block2))
    assert ordering.adjacent_blocks(block1) == (None, block2)
    assert ordering.adjacent_blocks(block2) == (block1, None)

    ordering.insert_blocks_after(block1, (block3, block4))
    assert ordering.adjacent_blocks(block1) == (None, block3)
    assert ordering.adjacent_blocks(block3) == (block1, block4)
    assert ordering.adjacent_blocks(block4) == (block3, block2)
    assert ordering.adjacent_blocks(block2) == (block4, None)

    ordering.remove_block(block3)
    assert ordering.adjacent_blocks(block1) == (None, block4)
    assert ordering.adjacent_blocks(block4) == (block1, block2)
    assert ordering.adjacent_blocks(block2) == (block4, None)

    ordering.remove_block(block4)
    assert ordering.adjacent_blocks(block1) == (None, block2)
    assert ordering.adjacent_blocks(block2) == (block1, None)

    ordering.add_detached_blocks((block3, block4))
    assert ordering.adjacent_blocks(block1) == (None, block2)
    assert ordering.adjacent_blocks(block2) == (block1, None)
    assert ordering.adjacent_blocks(block3) == (None, block4)
    assert ordering.adjacent_blocks(block4) == (block3, None)

    with pytest.raises(ValueError):
        ordering.insert_blocks_after(block1, (block2, block3))
