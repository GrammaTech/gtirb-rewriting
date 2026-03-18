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

from typing import Dict, Iterable, Optional, Tuple

import gtirb

from .linked_list import LinkedListNode


class BlockOrdering:
    """
    Maintains an ordering between blocks, allowing efficient querying of a
    block's predecessor and successor.
    """

    def __init__(self):
        self.__order: Dict[
            gtirb.ByteBlock, LinkedListNode[gtirb.ByteBlock]
        ] = {}

    def adjacent_blocks(
        self, block: gtirb.ByteBlock
    ) -> Tuple[Optional[gtirb.ByteBlock], Optional[gtirb.ByteBlock]]:
        """
        Get the blocks that come before and after the requested block.
        """
        entry = self.__order[block]
        prev_node = entry.prev
        next_node = entry.next
        return (
            prev_node.value if prev_node else None,
            next_node.value if next_node else None,
        )

    def remove_block(self, block: gtirb.ByteBlock) -> None:
        """
        Removes a block from the ordering. If it has a previous or next block,
        those orderings are updated to reflect the removal.
        """
        self.__order.pop(block).unlink()

    def add_detached_blocks(self, blocks: Iterable[gtirb.ByteBlock]) -> None:
        """
        Add blocks to the ordering. These blocks are only considered to be
        positioned relative to themselves and not any of the existing blocks
        in the ordering.
        """
        self._primitive_insert(None, blocks)

    def _primitive_insert(
        self,
        after_block: Optional[gtirb.ByteBlock],
        insert_blocks: Iterable[gtirb.ByteBlock],
    ):
        for block in insert_blocks:
            if block in self.__order:
                raise ValueError(f"{block} is already ordered")

        prev_entry = self.__order[after_block] if after_block else None
        for block in insert_blocks:
            block_entry = LinkedListNode[gtirb.ByteBlock](block)
            if prev_entry:
                prev_entry.insert_node_after(block_entry)
            self.__order[block] = block_entry
            prev_entry = block_entry

    def insert_blocks_after(
        self,
        after_block: gtirb.ByteBlock,
        insert_blocks: Iterable[gtirb.ByteBlock],
    ) -> None:
        self._primitive_insert(after_block, insert_blocks)
