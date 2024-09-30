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

"""
Split one block into two.
"""


import logging
from typing import Optional, Tuple, TypeVar

import gtirb
from more_itertools import before_and_after

import gtirb_rewriting._auxdata_offsetmap as _auxdata_offsetmap

from .._auxdata_offsetmap import OFFSETMAP_AUX_DATA_TABLES
from ..utils import (
    _block_fallthrough_targets,
    _is_call_edge,
    _is_fallthrough_edge,
)
from .cache import ModifyCache
from .edges import (
    update_edge,
    update_return_edges_from_changing_call_fallthrough,
)
from .functions import add_function_block_aux

logger = logging.getLogger(__name__)


BlockT = TypeVar("BlockT", bound=gtirb.ByteBlock)


def split_block(
    cache: ModifyCache, block: BlockT, offset: int
) -> Tuple[BlockT, BlockT, Optional[gtirb.Edge]]:
    """
    Splits a block in two at the requested offset.
    :param cache: The modify cache.
    :param offset: The offset to split at; must be within [0, block.size].
    :return: The modified block, the newly created block, and the fallthrough
             edge created between them (if needed).
    """

    assert 0 <= offset <= block.size
    assert (
        block.module and block.ir and block.section
    ), "target block must be in a module"

    end_split = offset == block.size

    new_block = block.__class__()
    new_block.offset = block.offset + offset
    new_block.size = block.size - offset
    new_block.byte_interval = block.byte_interval
    block.size = offset

    for sym in tuple(cache.reference_cache.get_references(block)):
        if sym.at_end:
            sym.referent = new_block

    added_fallthrough = None
    if isinstance(block, gtirb.CodeBlock):
        assert isinstance(new_block, gtirb.CodeBlock)

        if not end_split:
            # If we're splitting in the middle of the block, we are going to
            # move all of the edges to the new block.
            for out_edge in tuple(block.outgoing_edges):
                update_edge(out_edge, block.ir.cfg, source=new_block)
            add_fallthrough = True
        else:
            # Otherwise we're splitting at the end of the block and all the
            # edges remain in the original block -- with the exception of
            # fallthrough edges and return edges.
            fallthrough_targets = _block_fallthrough_targets(block)
            add_fallthrough = any(fallthrough_targets)

            for out_edge in tuple(block.outgoing_edges):
                if _is_call_edge(out_edge):
                    update_return_edges_from_changing_call_fallthrough(
                        cache,
                        out_edge,
                        fallthrough_targets,
                        new_block,
                        block.ir.cfg,
                    )
                elif _is_fallthrough_edge(out_edge):
                    update_edge(out_edge, block.ir.cfg, source=new_block)

        if add_fallthrough:
            added_fallthrough = gtirb.Edge(
                source=block,
                target=new_block,
                label=gtirb.Edge.Label(type=gtirb.Edge.Type.Fallthrough),
            )
            block.ir.cfg.add(added_fallthrough)

        func_uuid = cache.functions_by_block.get(block)
        if func_uuid:
            add_function_block_aux(cache, new_block, func_uuid)

    for table_def in OFFSETMAP_AUX_DATA_TABLES:
        table_data = table_def.get(block.module)
        if table_data:
            displacement_map = table_data.get(block)
            if displacement_map:
                table_data[block] = {
                    k: v for k, v in displacement_map.items() if k < offset
                }
                table_data[new_block] = {
                    k - offset: v
                    for k, v in displacement_map.items()
                    if k >= offset
                }

    cfi_data = _auxdata_offsetmap.cfi_directives.get(block.module)
    if cfi_data:
        displacement_map = cfi_data.get(block)
        if displacement_map:
            cfi_data[block] = {
                k: v for k, v in displacement_map.items() if k < offset
            }
            cfi_data[new_block] = {
                k - offset: v
                for k, v in displacement_map.items()
                if k > offset
            }
            # For directives at the split offset, we want to put anything
            # before a .cfi_endproc in the first block and anything after,
            # including the endproc, into the second block. This allows us to
            # insert at the end of a function and have the code stay in the
            # procedure.
            items_at_offset = displacement_map.get(offset, [])
            keep, move = map(
                list,
                before_and_after(
                    lambda directive: directive[0] != ".cfi_endproc",
                    items_at_offset,
                ),
            )

            if keep:
                cfi_data[block][offset] = keep
            if move:
                cfi_data[new_block][0] = move

    cache.block_ordering[block.section].insert_blocks_after(
        block, (new_block,)
    )

    return block, new_block, added_fallthrough
