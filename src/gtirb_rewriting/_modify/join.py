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
Join two blocks, if possible.
"""

import logging
from typing import NamedTuple, TypeVar

import gtirb

import gtirb_rewriting._auxdata as _auxdata
import gtirb_rewriting._auxdata_offsetmap as _auxdata_offsetmap

from .._auxdata_offsetmap import OFFSETMAP_AUX_DATA_TABLES
from ..utils import _is_fallthrough_edge
from .cache import ModifyCache
from .edges import update_edge
from .functions import remove_function_block_aux

logger = logging.getLogger(__name__)


class UnjoinableBlocksError(RuntimeError):
    pass


BlockT = TypeVar("BlockT", bound=gtirb.ByteBlock)


class JoinableResult(NamedTuple):
    result: bool
    reason: str

    def __bool__(self) -> bool:
        return self.result


def are_joinable(
    cache: ModifyCache, block1: gtirb.ByteBlock, block2: gtirb.ByteBlock
) -> JoinableResult:
    """
    Determines if two blocks can be joined using _join_blocks.
    """

    if type(block1) is not type(block2):
        return JoinableResult(False, "block types do not match")

    if block1.byte_interval is not block2.byte_interval:
        return JoinableResult(
            False, "blocks are not in the same byte interval"
        )

    module = block1.module
    if not module:
        return JoinableResult(False, "blocks are not in a module")

    if block1.offset + block1.size != block2.offset:
        return JoinableResult(
            False, "block2 does not immediately follow block1"
        )

    if not block1.size:
        return JoinableResult(True, "block1 is empty")

    alignment_data = _auxdata.alignment.get(module)
    if alignment_data:
        alignment = alignment_data.get(block2, 1)
        if alignment != 1:
            return JoinableResult(False, "block2 has a required aligment")

    any_symbols = any(
        not sym.at_end for sym in cache.reference_cache.get_references(block2)
    )
    if any_symbols:
        return JoinableResult(False, "block2 has symbols referring to it")

    if isinstance(block1, gtirb.CodeBlock):
        assert isinstance(block2, gtirb.CodeBlock)

        any_out_edges = any(
            edge
            for edge in block1.outgoing_edges
            if not _is_fallthrough_edge(edge) or edge.target != block2
        )
        if any_out_edges and block2.size != 0:
            return JoinableResult(False, "block1 has outgoing edges")

        any_in_edges = any(
            edge
            for edge in block2.incoming_edges
            if not _is_fallthrough_edge(edge) or edge.source != block1
        )
        if any_in_edges:
            return JoinableResult(False, "block2 has incoming edges")

        if not cache.in_same_function(block1, block2):
            return JoinableResult(False, "blocks are not in the same function")

        if cache.is_entry_block(block2):
            return JoinableResult(
                False, "block2 is the entry block of the function"
            )

    return JoinableResult(True, "")


def join_blocks(
    cache: ModifyCache,
    block1: BlockT,
    block2: gtirb.ByteBlock,
) -> BlockT:
    """
    Joins two blocks, if possible, or raise _UnjoinableBlocksError.
    """

    joinable = are_joinable(cache, block1, block2)
    if not joinable:
        raise UnjoinableBlocksError(joinable.reason)

    ir = block1.ir
    module = block1.module
    assert ir and module and block2.section

    cache.reference_cache.retarget_references(
        block2, block1, bool(block1.size)
    )

    if isinstance(block2, gtirb.CodeBlock):
        assert isinstance(block1, gtirb.CodeBlock)

        for in_edge in tuple(block2.incoming_edges):
            if _is_fallthrough_edge(in_edge) and in_edge.source is block1:
                ir.cfg.discard(in_edge)

        if not block1.size:
            for in_edge in tuple(block2.incoming_edges):
                update_edge(in_edge, ir.cfg, target=block1)

        else:
            for in_edge in tuple(block2.incoming_edges):
                ir.cfg.discard(in_edge)

        for out_edge in tuple(block2.outgoing_edges):
            update_edge(out_edge, ir.cfg, source=block1)

        remove_function_block_aux(cache, block2)

    for table_def in OFFSETMAP_AUX_DATA_TABLES:
        table_data = table_def.get(module)
        if table_data:
            displacement_map = table_data.pop(block2, None)
            if displacement_map:
                new_displacement_map = table_data.setdefault(block1, {})
                new_displacement_map.update(
                    {block1.size + k: v for k, v in displacement_map.items()}
                )

    cfi_table_data = _auxdata_offsetmap.cfi_directives.get(module)
    if cfi_table_data:
        displacement_map = cfi_table_data.pop(block2, None)
        if displacement_map:
            new_displacement_map = cfi_table_data.setdefault(block1, {})
            for k, v in displacement_map.items():
                new_k = block1.size + k
                new_displacement_map.setdefault(new_k, []).extend(v)

    alignment_data = _auxdata.alignment.get(module)
    if alignment_data:
        block1_align = alignment_data.get(block1, 1)
        block2_align = alignment_data.pop(block2, 1)

        if block2_align > block1_align:
            assert not block1.size
            alignment_data[block1] = block2_align

    block1.size = block1.size + block2.size
    cache.block_ordering[block2.section].remove_block(block2)
    block2.byte_interval = None

    return block1
