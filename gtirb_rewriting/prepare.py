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
import contextlib
from typing import Iterator, List, Mapping, MutableMapping, Tuple

import gtirb

from .utils import OffsetMapping, align_address, effective_alignment


@contextlib.contextmanager
def prepare_for_rewriting(module: gtirb.Module, nop: bytes) -> Iterator[None]:
    """Pre-compute data structure to accelerate rewriting."""

    def cast_to_offset_mapping(name):
        table = module.aux_data[name]
        if not isinstance(table.data, OffsetMapping):
            table.data = OffsetMapping(table.data)
        return table.data

    alignment = {}
    if "alignment" in module.aux_data:
        alignment = module.aux_data["alignment"].data
    tables = [
        cast_to_offset_mapping(name)
        for name in ("comments", "padding", "symbolicExpressionSizes")
        if name in module.aux_data
    ]
    # Add an OffsetMapping for symbolic expressions
    tables.append(OffsetMapping())

    partitions = _partition_byte_intervals(module, alignment, tables)

    yield

    _rejoin_byte_intervals(partitions, alignment, tables, nop)


def _partition_byte_intervals(
    module: gtirb.Module,
    alignment: MutableMapping[gtirb.Node, int],
    tables: List[OffsetMapping[object]],
) -> List[List[gtirb.ByteBlock]]:
    """Create new byte intervals for every block in the module."""
    for block in module.byte_blocks:
        if block not in alignment:
            if block.address is None:
                # Align the offset, since we don't know the actual address
                alignment[block] = effective_alignment(block.offset)
            else:
                alignment[block] = effective_alignment(block.address)

    partitions = []
    for interval in tuple(module.byte_intervals):
        if any(isinstance(b, gtirb.CodeBlock) for b in interval.blocks):
            partitions.append(_partition_interval(interval, tables))
    return partitions


def _partition_interval(
    interval: gtirb.ByteInterval, tables: List[OffsetMapping[object]]
) -> List[gtirb.ByteBlock]:
    """Create a new interval for every block in the ByteInterval."""
    # Last table holds symbolic expressions.
    tables[-1][interval] = interval.symbolic_expressions

    # We will walk through the blocks and the associated info in the aux
    # data/symbolic expression tables in order to avoid needing multiple
    # scans. The aux data/symbolic expression info is reversed to
    # facilitate popping from the back of the lists.

    old_items: List[List[Tuple[int, object]]] = [
        sorted(table.get(interval, {}).items(), reverse=True)
        for table in tables
    ]

    blocks = sorted(interval.blocks, key=lambda b: b.offset)
    for block in blocks:
        new_interval = gtirb.ByteInterval(
            size=block.size, contents=block.contents
        )
        new_interval.section = interval.section

        # Transfer aux data/symbolic expressions to the new interval.

        begin, end = block.offset, block.offset + block.size
        for table, items in zip(tables, old_items):
            while items != [] and items[-1][0] < begin:
                items.pop()
            while items != [] and items[-1][0] < end:
                off, value = items.pop()
                del table[gtirb.Offset(interval, off)]
                off -= block.offset
                table[gtirb.Offset(new_interval, off)] = value

        if new_interval in tables[-1]:
            new_interval.symbolic_expressions = tables[-1][new_interval]
        new_interval.address = block.address
        block.byte_interval = new_interval
        block.offset = 0
    interval.section = None
    return blocks


def _rejoin_byte_intervals(
    partitions: List[List[gtirb.ByteBlock]],
    alignment: Mapping[gtirb.Node, int],
    tables: List[OffsetMapping[object]],
    nop: bytes,
) -> None:
    """Recombine blocks that originally shared the same byte intervals."""
    for partition in partitions:
        block = partition[0]

        offset = 0
        address = block.address
        if address is not None:
            address = align_address(address, alignment[block])

        new_interval = gtirb.ByteInterval(address=address)
        new_interval.section = block.section

        contents = bytearray()
        for block in partition:
            if address is None:
                padding = align_address(offset, alignment[block]) - offset
            else:
                padding = align_address(address + offset, alignment[block])
                padding -= address + offset
            if padding != 0:
                # The pretty-printer won't print the padding bytes unless
                # they are contained in blocks.
                if isinstance(block, gtirb.DataBlock):
                    contents += b"\x00" * padding
                    pad = gtirb.DataBlock(offset=offset, size=padding)
                else:
                    q, r = divmod(padding, len(nop))
                    assert r == 0, "nop does not fit evenly in padding"
                    contents += nop * q
                    pad = gtirb.CodeBlock(offset=offset, size=padding)
                pad.byte_interval = new_interval
                offset += padding
            contents += block.contents

            # Re-sync the symbolic expressions table with the byte interval
            # in case the patches added new symbolic expressions.
            old_interval = block.byte_interval
            tables[-1].pop(old_interval, None)
            tables[-1][old_interval] = old_interval.symbolic_expressions

            # Transfer aux data/symbolic expressions to the new interval.
            for table in tables:
                table[new_interval] = {
                    k + offset: v
                    for k, v in table.get(old_interval, {}).items()
                }
                table.pop(old_interval, None)
            block.byte_interval = new_interval
            block.offset = offset
            offset += block.size

        new_interval.contents = contents
        new_interval.size = len(contents)
        new_interval.initialized_size = len(contents)
        new_interval.symbolic_expressions = tables[-1][new_interval]
