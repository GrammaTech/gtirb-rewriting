# GTIRB-Rewriting Rewriting API for GTIRB
# Copyright (C) 2021 GrammaTech, Inc.
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
import dataclasses
import itertools
from typing import Iterable, List, Mapping, MutableMapping, Optional

import gtirb
import gtirb_rewriting._auxdata as _auxdata

from ._auxdata_offsetmap import OFFSETMAP_AUX_DATA_TABLES
from .abi import ABI
from .utils import OffsetMapping, align_address, effective_alignment


class PaddingError(Exception):
    """Indicates an error inserting padding to reach a desired alignment."""


@dataclasses.dataclass
class BlockGroup:
    """A group of overlapping blocks."""

    begin: int
    """Offset of the first block in the group."""
    end: int
    """First offset past the end of the last block in the group."""
    blocks: List[gtirb.ByteBlock]
    """Collection of blocks in the group."""


def split_byte_interval(
    interval: gtirb.ByteInterval,
    alignment: Optional[MutableMapping[gtirb.Node, int]] = None,
    tables: Optional[Iterable[OffsetMapping[object]]] = None,
) -> List[gtirb.ByteInterval]:
    """Split a ByteInterval to put each block in its own interval.

    After the split, the original interval will hold the first block (ordered
    by offset). Each remaining block will be in a new new byte interval. Any
    bytes outside of a block will be included in the interval containing the
    preceding block; the first interval will contain the bytes before and after
    the first block.

    Because overlapping blocks share the bytes where they overlap, some
    intervals may contain more than one block after the split. These intervals
    will contain the smallest number of blocks possible without duplicating
    bytes.

    :param interval:  byte interval to split
    :param alignment:  optional table of alignments for blocks and intervals
    :param tables:  optional collection of offset mappings to update
    :returns:  list of byte intervals containing the blocks in the original
        interval
    """
    if tables is None:
        tables = []
        module = interval.module
        if module is not None:
            for table_def in OFFSETMAP_AUX_DATA_TABLES:
                table = table_def.get(module)
                if table:
                    tables.append(table)

    # Group overlapping blocks so they can be processed as a unit.
    groups: List[BlockGroup] = []
    for block in sorted(interval.blocks, key=lambda b: b.offset):
        block_end = block.offset + block.size
        if groups == [] or groups[-1].end <= block.offset:
            groups.append(BlockGroup(block.offset, block_end, [block]))
        else:
            groups[-1].end = max(groups[-1].end, block_end)
            groups[-1].blocks.append(block)
        if alignment is not None and block not in alignment:
            if block.address is None:
                # Align the offset, since we don't know the actual address
                alignment[block] = effective_alignment(block.offset)
            else:
                alignment[block] = effective_alignment(block.address)

    # Process groups in decreasing offset order, but skip the first group
    # because it will stay in the original interval.
    if groups:
        groups.reverse()
        groups.pop()

    # Create the new byte interval for each group of blocks.
    intervals: List[gtirb.ByteInterval] = []
    offset = interval.size
    for group in groups:
        new_interval = gtirb.ByteInterval(
            contents=interval.contents[group.begin :],
            size=max(offset - group.begin, 0),
        )
        new_interval.section = interval.section

        new_interval.address = group.blocks[0].address
        for block in group.blocks:
            block.offset -= group.begin
            block.byte_interval = new_interval
        intervals.append(new_interval)

        offset = min(interval.size, group.begin)
        interval.initialized_size = min(interval.initialized_size, offset)
        interval.size = min(interval.size, offset)
    intervals.append(interval)

    # Transfer symbolic expressions and table items to the new intervals.
    symexprs = OffsetMapping()
    symexprs[interval] = interval.symbolic_expressions
    for table in itertools.chain((symexprs,), tables):
        items = sorted(table.get(interval, {}).items())
        for group, new_interval in zip(groups, intervals):
            while items != [] and items[-1][0] >= group.begin:
                off, value = items.pop()
                del table[interval][off]
                if new_interval not in table:
                    table[new_interval] = {}
                table[new_interval].update({off - group.begin: value})
    for new_interval in intervals:
        if new_interval in symexprs:
            new_interval.symbolic_expressions = symexprs[new_interval]

    intervals.reverse()
    return intervals


def join_byte_intervals(
    intervals: List[gtirb.ByteInterval],
    nop: Optional[bytes] = None,
    alignment: Optional[Mapping[gtirb.Node, int]] = None,
    tables: Optional[Iterable[OffsetMapping[object]]] = None,
) -> gtirb.ByteInterval:
    """Concatenate a list of byte intervals.

    The first interval in the given list will be trated as the destination. The
    contents (bytes and byte_blocks) of all other intervals will be
    concatenated onto the end of the destination interval in the order they
    appear in the list.

    Padding will be inserted between subsequent intervals so that the address
    of the first block of each interval (or of the interval itself if it
    contains no blocks) is properly aligned. Addresses are calculated based on
    the address of the destination block, or 0 if it has no address. If the
    alignment mapping is not specified, the "alignment" aux data for each
    interval's module, if any, will be used.

    The symbolic expressions will be transfered to the destination module,
    adjusted to retain their positions relative to their original byte
    interval. In addition, any tables given will be updated by relocating
    Offsets into each concatenated interval to refer to the corresponding
    Offset into the destination interval. If no tables are provided, a default
    set of aux data will be updated; pass an empty sequence of tables to
    prevent any tables from being updated.

    NB: This function destructively removes the blocks, bytes, and symbolic
    expressions from the other intervals when they are added to the
    destination, but it does not remove the intervals from their sections.

    :param intervals:  list of byte intervals to concatenate
    :param nop:  bytes representing a single nop instruction
    :param alignment:  table of alignments for blocks and intervals
    :param tables:  collection of offset mappings to update
    """
    if len(intervals) < 2:
        return intervals[0]

    if tables is None:
        # This is a bit hacky, but to avoid assuming that the byte intervals
        # are all in the same module, the tables are a list of dictionaries
        # that map intervals to (displacement to value) dicts. Each interval
        # added at this stage will map to the mutable mapping returned by
        # indexing an OffsetMapping, which means the original aux data will be
        # updated when modifying that sub-dict.
        tables = []
        for table_def in OFFSETMAP_AUX_DATA_TABLES:
            table = {}
            for bi in intervals:
                if bi.module is not None:
                    aux_data = table_def.get(bi.module)
                    if aux_data and bi in aux_data:
                        table[bi] = aux_data[bi]
            if len(table) > 0:
                tables.append(table)  # type: ignore # per above this is hacky

    destination = intervals[0]
    intervals = intervals[1:]

    address = 0
    if destination.address is not None:
        address = destination.address
    address += destination.size
    last_block = max(destination.blocks, key=lambda b: b.offset, default=None)
    last_module = last_block.module if last_block is not None else None

    def insert_padding(size):
        if size == 0:
            return
        if isinstance(last_block, gtirb.CodeBlock):
            BlockType = gtirb.CodeBlock
            if nop is not None:
                pad_bytes = nop
            elif last_module is not None:
                pad_bytes = ABI.get(last_module).nop()
            else:
                raise PaddingError("cannot determine nop instruction")
            size, remainder = divmod(size, len(pad_bytes))
            if remainder != 0:
                raise PaddingError("nop does not fit evenly in padding")
        else:
            BlockType = gtirb.DataBlock
            pad_bytes = b"\x00"

        destination.contents += pad_bytes * size
        # The pretty-printer won't print the padding bytes unless they
        # are contained in blocks, add a block covering anything not
        # yet covered by the last block.
        if last_block is not None:
            padding_block_offset = last_block.offset + last_block.size
            padding_block_size = (
                len(destination.contents) - padding_block_offset
            )
        else:
            padding_block_offset = 0
            padding_block_size = len(destination.contents)
        if padding_block_size > 0:
            padding = BlockType(
                offset=padding_block_offset, size=padding_block_size
            )
            padding.byte_interval = destination

    symexprs = OffsetMapping()
    deltas = {}
    for interval in intervals:
        # Fill in any uninitialized bytes before appending.
        insert_padding(destination.size - len(destination.contents))

        # Align the first block if possible, or the interval if not.
        if alignment is not None:
            module_alignment = alignment
        elif interval.module is not None and _auxdata.alignment.exists(
            interval.module
        ):
            module_alignment = _auxdata.alignment.get_or_insert(
                interval.module
            )
        else:
            module_alignment = {}
        node = min(
            (b for b in interval.blocks if b in module_alignment),
            key=lambda b: b.offset,
            default=interval,
        )
        if node == interval:
            offset = 0
        else:
            assert isinstance(node, gtirb.ByteBlock)
            offset = node.offset
        boundary = module_alignment.get(node, 1)
        size = align_address(address + offset, boundary) - (address + offset)
        insert_padding(size)
        address += size
        destination.size += size

        # Cache the delta for updating the symbolic expression offsets and the
        # new last block in case we need more padding.
        deltas[interval] = len(destination.contents)
        symexprs[interval] = interval.symbolic_expressions
        last_block = max(
            interval.blocks, default=last_block, key=lambda b: b.offset
        )
        if last_block is not None and last_block.module is not None:
            last_module = last_block.module

        # Transfer the bytes and blocks to the new intervals.
        address += interval.size
        destination.size += interval.size
        destination.contents += interval.contents
        for block in tuple(interval.blocks):
            block.offset += deltas[interval]
            block.byte_interval = destination

        interval.initialized_size = 0
        interval.symbolic_expressions.clear()

    destination.initialized_size = len(destination.contents)

    # Update offsets to refer to the destination interval.
    for table in itertools.chain((symexprs,), tables):
        for interval in intervals:
            old = table.get(interval, {})
            new_items = ((k + deltas[interval], v) for k, v in old.items())
            if destination in table:
                table[destination].update(new_items)
            else:
                table[destination] = dict(new_items)
            old.clear()
    destination.symbolic_expressions.update(symexprs[destination])

    return destination
