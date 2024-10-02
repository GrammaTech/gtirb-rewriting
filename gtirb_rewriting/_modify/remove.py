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

"""
Remove a block from a byte interval.
"""

from typing import List, Optional

import gtirb

import gtirb_rewriting._auxdata as _auxdata
import gtirb_rewriting._auxdata_offsetmap as _auxdata_offsetmap
from gtirb_rewriting._modify.functions import remove_function_block_aux

from .._auxdata_offsetmap import OFFSETMAP_AUX_DATA_TABLES
from ..utils import (
    _block_fallthrough_targets,
    _is_call_edge,
    _is_fallthrough_edge,
)
from .cache import ModifyCache
from .edges import remove_return_edges_from_callee, update_edge


def _can_remove_block(
    cache: ModifyCache,
    block: gtirb.ByteBlock,
    retarget_to_proxy: bool,
    prev_block: Optional[gtirb.ByteBlock],
    next_block: Optional[gtirb.ByteBlock],
    cfi_directives: List[_auxdata.CFIDirectiveType],
) -> bool:
    """
    Determines if a block can be removed or needs to be kept in the IR as a
    zero-sized block.
    """
    assert block.module

    # If there are any symbols but nowhere else to attach them to, we must
    # keep the block. This can arise when trying to get rid of the last block
    # in a section.
    if (
        any(cache.reference_cache.get_references(block))
        and prev_block is None
        and next_block is None
        and not retarget_to_proxy
    ):
        return False

    # If there are any important CFI directives but no code block to attach
    # them to, we must keep the block. For example, deleting a code block that
    # has .cfi_startproc in it which is followed by a data block.
    if (
        cfi_directives
        and not isinstance(prev_block, gtirb.CodeBlock)
        and not isinstance(next_block, gtirb.CodeBlock)
    ):
        return False

    # If there are incoming control flow edges but no target for them to be
    # redirected to, we must keep the block.
    if (
        isinstance(block, gtirb.CfgNode)
        and not all(
            _is_fallthrough_edge(edge) for edge in block.incoming_edges
        )
        and not isinstance(next_block, gtirb.CfgNode)
        and not retarget_to_proxy
    ):
        return False

    # If the block is the module entrypoint and there isn't a subsequent code
    # block, we have to keep the block. Same goes for the ELF ini/fini
    # functions.
    if (
        (
            block.module.entry_point is block
            or _auxdata.elf_dynamic_fini.get(block.module) is block
            or _auxdata.elf_dynamic_fini.get(block.module) is block
        )
        and not isinstance(next_block, gtirb.CodeBlock)
        and not retarget_to_proxy
    ):
        return False

    return True


def _retarget_incoming_edges(
    block: gtirb.ByteBlock, target_node: Optional[gtirb.CfgNode]
):
    """
    Retargets all of the incoming edges to the bock to another block, or a
    newly generated proxy block if one is not supplied.
    """
    assert block.module and block.ir

    if not isinstance(block, gtirb.CodeBlock):
        return

    in_edges = set(block.incoming_edges)
    if not in_edges:
        return

    if target_node is None:
        target_node = gtirb.ProxyBlock(module=block.module)

    for edge in in_edges:
        update_edge(edge, block.ir.cfg, target=target_node)


def _remove_outgoing_edges(cache: ModifyCache, block: gtirb.ByteBlock) -> None:
    """
    Remove all outgoing edges from the block.
    """
    assert block.ir

    if not isinstance(block, gtirb.CodeBlock):
        return

    fallthrough_targets = _block_fallthrough_targets(block)
    for edge in set(block.outgoing_edges):
        if _is_call_edge(edge):
            remove_return_edges_from_callee(
                cache, edge, fallthrough_targets, block.ir.cfg
            )
        block.ir.cfg.discard(edge)


def _required_cfi_directives(
    block: gtirb.ByteBlock,
) -> List[_auxdata.CFIDirectiveType]:
    """
    Determine which CFI directives in a block must be kept for correctness.
    """
    assert block.module

    if not isinstance(block, gtirb.CodeBlock):
        return []

    cfi_table = _auxdata_offsetmap.cfi_directives.get(block.module)
    if not cfi_table:
        return []

    displacement_map = cfi_table.get(block, None)
    if not displacement_map:
        return []

    # We need to keep start/end proc directives and remember/restore state
    # directives, but we also want to drop anything between a balanced
    # start/end proc pair (including the start/end proc directives).
    results: List[_auxdata.CFIDirectiveType] = []
    procedure_directives: List[_auxdata.CFIDirectiveType] = []
    for _, directives in sorted(displacement_map.items()):
        for directive in directives:
            append_to = procedure_directives or results
            if directive[0] == ".cfi_startproc":
                procedure_directives.append(directive)
            elif directive[0] == ".cfi_endproc":
                append_to.append(directive)
                procedure_directives.clear()
            elif directive[0] in (
                ".cfi_remember_state",
                ".cfi_restore_state",
            ):
                append_to.append(directive)

    results.extend(procedure_directives)
    return results


def _remove_cfi_directives(
    block: gtirb.ByteBlock,
    keep_directives: List[_auxdata.CFIDirectiveType],
    prev_block: Optional[gtirb.ByteBlock],
    next_block: Optional[gtirb.ByteBlock],
) -> None:
    """
    Removes CFI directives that are in the block, except those specified in
    `keep_directives`. Those directives will be moved to an adjacent block, if
    one exists, or remain on the block with the expectation that the block
    will be kept as a zero-sized code block.
    """

    assert block.module

    cfi_table = _auxdata_offsetmap.cfi_directives.get(block.module)
    if not cfi_table:
        return

    if not keep_directives:
        cfi_table.pop(block, None)
        return

    if isinstance(next_block, gtirb.CodeBlock):
        next_directives = cfi_table.setdefault(next_block, {}).setdefault(
            0, []
        )
        next_directives[:0] = keep_directives
        del cfi_table[block]
    elif isinstance(prev_block, gtirb.CodeBlock):
        prev_directives = cfi_table.setdefault(prev_block, {}).setdefault(
            prev_block.size, []
        )
        prev_directives.extend(keep_directives)
        del cfi_table[block]
    else:
        cfi_table[block] = {0: keep_directives}


def _update_functions_aux_data(
    cache: ModifyCache,
    block: gtirb.ByteBlock,
    next_block: Optional[gtirb.ByteBlock],
) -> None:
    """
    Updates the aux data tables relating to functions for the removal.
    """
    assert block.module

    if not isinstance(block, gtirb.CodeBlock):
        return

    function_uuid = cache.functions_by_block.get(block, None)
    if not function_uuid:
        return

    # If it was previously a function entry block, the next block gets
    # promoted into that role -- but only if it's in the same function.
    aux_function_entries = _auxdata.function_entries.get(block.module)
    if (
        aux_function_entries
        and block in aux_function_entries[function_uuid]
        and isinstance(next_block, gtirb.CodeBlock)
        and cache.in_same_function(block, next_block)
    ):
        # TODO: If we are deleting code block B1 that is a function entry,
        #        then data block B2 that follows it, and there is a code block
        #        B3 following that, we won't promote B3 to be a function
        #        entry because we lose track of that property after the first
        #        deletion because B2 is a data block. If we want to be less
        #        lossy in this specific case we'd have to keep track of data
        #        blocks that should be considered entry blocks.
        aux_function_entries[function_uuid].add(next_block)

    remove_function_block_aux(cache, block)


def _update_module_entrypoints(
    block: gtirb.ByteBlock, next_block: Optional[gtirb.ByteBlock]
) -> None:
    """
    Update entrypoints to point to the next block. This includes ELF
    DT_INIT/DT_FINI in addition to the module entry point.
    """
    assert block.module

    if block.module.entry_point is block:
        assert next_block is None or isinstance(next_block, gtirb.CodeBlock)
        block.module.entry_point = next_block

    if _auxdata.elf_dynamic_init.get(block.module) is block:
        if next_block:
            assert isinstance(next_block, gtirb.CodeBlock)
            _auxdata.elf_dynamic_init.set(block.module, next_block)
        else:
            _auxdata.elf_dynamic_init.remove(block.module)

    if _auxdata.elf_dynamic_fini.get(block.module) is block:
        if next_block:
            assert isinstance(next_block, gtirb.CodeBlock)
            _auxdata.elf_dynamic_fini.set(block.module, next_block)
        else:
            _auxdata.elf_dynamic_fini.remove(block.module)


def _update_pe_safe_seh(
    block: gtirb.ByteBlock, next_block: Optional[gtirb.ByteBlock]
) -> None:
    """
    Update the safe SEH aux data to flag the next block as safe if the
    deleted block was.
    """

    assert block.module

    if not isinstance(block, gtirb.CodeBlock):
        return

    table = _auxdata.pe_safe_exception_handlers.get(block.module)
    if not table:
        return

    safe = block in table
    if not safe:
        return

    table.discard(block)
    if isinstance(next_block, gtirb.CodeBlock):
        table.add(next_block)


def _remove_aux_data_entries(block: gtirb.ByteBlock):
    """
    Removes the block from all associated aux data tables, except for
    alignment.
    """
    assert block.module

    for table_def in OFFSETMAP_AUX_DATA_TABLES:
        table = table_def.get(block.module)
        if table is not None and block in table:
            del table[block]

    if isinstance(block, gtirb.DataBlock):
        for table in (_auxdata.types, _auxdata.encodings):
            table = table.get(block.module)
            if table:
                table.pop(block, None)

    if isinstance(block, gtirb.CodeBlock):
        for table in (_auxdata.profile, _auxdata.sccs):
            table = table.get(block.module)
            if table:
                table.pop(block, None)


def _remove_alignment(block: gtirb.ByteBlock):
    """
    Removes alignment aux data for the block.
    """
    assert block.module

    aux_alignment = _auxdata.alignment.get(block.module)
    if aux_alignment:
        aux_alignment.pop(block, None)


def remove_block(
    cache: ModifyCache,
    block: gtirb.ByteBlock,
    retarget_to_proxy: bool = False,
) -> bool:
    """
    Removes a block and retargets any symbols or edges pointing at it to be
    to another block. This does not modify the byte interval; use delete
    instead.

    :param cache: The modify cache.
    :param block: The block to remove.
    :param retarget_to_proxy: Retarget symbols and incoming edges to a proxy
           block instead of the following block.
    :returns: Whether the block was truly able to be removed from the IR.
    """

    assert block.module and block.ir and block.section
    module = block.module

    prev_block, next_block = cache.adjacent_blocks(block)
    if retarget_to_proxy:
        proxy_block = gtirb.ProxyBlock(module=module)
    else:
        proxy_block = None

    cfi_directives = _required_cfi_directives(block)

    can_remove = _can_remove_block(
        cache,
        block,
        retarget_to_proxy,
        prev_block,
        next_block,
        cfi_directives,
    )

    if can_remove:
        sym_target = proxy_block or next_block or prev_block
        cache.reference_cache.retarget_references(
            block, sym_target, sym_target is prev_block
        )

        if proxy_block:
            _retarget_incoming_edges(block, proxy_block)
        elif isinstance(next_block, gtirb.CfgNode):
            _retarget_incoming_edges(block, next_block)
        else:
            _retarget_incoming_edges(block, None)

        if retarget_to_proxy:
            _update_functions_aux_data(cache, block, None)
            _update_module_entrypoints(block, None)
            _update_pe_safe_seh(block, None)
        else:
            _update_functions_aux_data(cache, block, next_block)
            _update_module_entrypoints(block, next_block)
            _update_pe_safe_seh(block, next_block)

        _remove_alignment(block)

    _remove_outgoing_edges(cache, block)

    _remove_aux_data_entries(block)

    _remove_cfi_directives(block, cfi_directives, prev_block, next_block)

    if can_remove:
        cache.block_ordering[block.section].remove_block(block)
        block.byte_interval = None

    else:
        block.size = 0

        # We add a fallthrough to a proxy block if we have a zero-sized code
        # block to indicate that we are unable to represent what's actually
        # happening in the program.
        if isinstance(block, gtirb.CodeBlock):
            block.ir.cfg.add(
                gtirb.Edge(
                    block,
                    gtirb.ProxyBlock(module=module),
                    gtirb.EdgeLabel(gtirb.EdgeType.Fallthrough),
                )
            )

    return can_remove
