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
Edit a single block's contents.
"""


import logging
from typing import List, MutableMapping, Optional, Set

import gtirb
from more_itertools import pairwise

import gtirb_rewriting._auxdata as _auxdata
import gtirb_rewriting._auxdata_offsetmap as _auxdata_offsetmap

from .._auxdata_offsetmap import OFFSETMAP_AUX_DATA_TABLES
from ..assembler import Assembler, UnsupportedAssemblyError
from ..utils import (
    _get_function_blocks,
    _is_call_edge,
    _is_fallthrough_edge,
    _is_return_edge,
)
from .cache import ModifyCache
from .edges import add_return_edges_to_callee, update_fallthrough_target
from .functions import add_function_block_aux
from .join import UnjoinableBlocksError, join_blocks
from .remove import remove_block
from .split import split_block


class AmbiguousIRError(RuntimeError):
    """
    The IR is ambiguous in terms of how it needs to be updated.
    """


class AmbiguousCFGError(AmbiguousIRError):
    pass


logger = logging.getLogger(__name__)


def _add_return_edges_for_patch_calls(
    cache: ModifyCache,
    module: gtirb.Module,
    new_cfg: gtirb.CFG,
) -> None:
    """
    Finds all of the call edges added by the patch and adds new return edges
    to the callee.
    """
    call_edges = {edge for edge in new_cfg if _is_call_edge(edge)}
    # Because the assembler is generating this input, we can assume that there
    # is a single fallthrough edge out of each block.
    fallthroughs_by_block = {
        edge.source: edge.target
        for edge in new_cfg
        if _is_fallthrough_edge(edge)
    }
    for call_edge in call_edges:
        if not isinstance(call_edge.target, gtirb.CodeBlock):
            continue

        func_uuid = cache.functions_by_block.get(call_edge.target, None)
        if not func_uuid:
            continue

        fallthrough_target = fallthroughs_by_block.get(call_edge.source, None)
        if not fallthrough_target:
            continue

        add_return_edges_to_callee(
            cache, module, func_uuid, fallthrough_target, new_cfg
        )


def _update_patch_return_edges_to_match(
    cache: ModifyCache,
    block: gtirb.CodeBlock,
    new_cfg: gtirb.CFG,
    new_proxy_blocks: Set[gtirb.ProxyBlock],
) -> None:
    """
    Finds all return edges in a patch and updates them to match the function
    being inserted into.
    """
    assert block.module

    patch_return_edges = {
        edge
        for edge in new_cfg
        if _is_return_edge(edge) and edge.target in new_proxy_blocks
    }
    if not patch_return_edges:
        return

    func_uuid = cache.functions_by_block.get(block, None)
    if not func_uuid:
        return

    return_targets: Set[gtirb.CfgNode] = set()
    for func_block in _get_function_blocks(block.module, func_uuid):
        return_targets.update(
            edge.target
            for edge in cache.return_cache.block_return_edges(func_block)
            if not isinstance(edge.target, gtirb.ProxyBlock)
        )

    if not return_targets:
        return

    for edge in patch_return_edges:
        assert isinstance(edge.target, gtirb.ProxyBlock)
        new_cfg.discard(edge)
        new_proxy_blocks.discard(edge.target)
        for target in return_targets:
            new_cfg.add(
                gtirb.Edge(
                    source=edge.source,
                    target=target,
                    label=gtirb.Edge.Label(type=gtirb.Edge.Type.Return),
                )
            )


def delete(
    cache: ModifyCache,
    block: gtirb.ByteBlock,
    offset: int,
    length: int,
    retarget_to_proxy: bool = False,
) -> Optional[gtirb.ByteBlock]:
    """
    Deletes code from a block, potentially deleting the whole block.
    """

    assert cache.module is block.module
    assert 0 <= offset <= block.size
    assert 0 <= offset + length <= block.size
    assert length >= 0

    bi = block.byte_interval
    assert bi

    # Specifying an empty deletion range is functionally a no-op, unless that
    # happens to be the entire block length.
    if length == 0 and block.size != 0:
        return block

    if length != block.size:
        start, end, _ = split_block(cache, block, offset)
        mid, end, _ = split_block(cache, end, length)

        remove_block(cache, mid)
        edit_byte_interval(bi, start.offset + offset, length, b"", {start})
        return _cleanup_modified_blocks(cache, [start, end])

    else:
        prev_block, next_block = cache.adjacent_blocks(block)
        deleted = remove_block(
            cache, block, retarget_to_proxy=retarget_to_proxy
        )
        edit_byte_interval(bi, block.offset + offset, length, b"", {block})
        if (
            deleted
            and prev_block
            and next_block
            and prev_block.size == 0
            and not retarget_to_proxy
        ):
            # If we were able to delete a block, see if that opens up an
            # opportunity to delete a previous zero-sized block. For example,
            # if we just deleted a data block between two code blocks.
            remove_block(cache, prev_block)

        # There is no block for subsequent insertions to be placed at, so just
        # return None.
        return None


def insert(
    cache: ModifyCache,
    block: gtirb.ByteBlock,
    offset: int,
    replacement_length: int,
    code: Assembler.Result,
) -> gtirb.ByteBlock:
    """
    Insert bytes into a block and adjusts the IR as needed.
    :param cache: The modify cache, which should be reused across multiple
                  modifications.
    :param block: The code block to insert into.
    :param offset: The byte offset into the code block.
    :param replacement_length: The number of bytes after `offset` that should
                               be removed.
    :param code: The assembled code to be inserted. It will be modified to
                 reflect what actually gets inserted in the binary.
    """

    assert cache.module is block.module
    assert block.size
    assert 0 <= offset <= block.size
    assert 0 <= offset + replacement_length <= block.size
    assert replacement_length >= 0
    assert block.byte_interval and block.section and block.module and block.ir

    text_section = code.text_section
    assert text_section.data
    assert text_section.blocks
    assert block not in text_section.blocks
    assert text_section.blocks[
        0
    ].size, "must have at least one non-empty block"
    assert all(
        new_block.size for new_block in text_section.blocks[:-1]
    ), "only the last block may be empty"
    assert isinstance(text_section.blocks[-1], gtirb.DataBlock) or (
        isinstance(text_section.blocks[-1], gtirb.CodeBlock)
        and not any(code.cfg.out_edges(text_section.blocks[-1]))
    ), "the last block cannot have outgoing cfg edges"

    bi = block.byte_interval
    module = block.module
    cfg = block.ir.cfg

    _add_return_edges_for_patch_calls(
        cache,
        module,
        code.cfg,
    )

    if isinstance(block, gtirb.CodeBlock):
        _update_patch_return_edges_to_match(
            cache, block, code.cfg, code.proxies
        )

    _, end_block, added_fallthrough = split_block(cache, block, offset)

    if replacement_length:
        mid_block, end_block, _ = split_block(
            cache, end_block, replacement_length
        )
        remove_block(cache, mid_block)

    # Stitch in the new blocks to the CFG
    if added_fallthrough:
        assert isinstance(text_section.blocks[0], gtirb.CodeBlock)
        assert isinstance(block, gtirb.CodeBlock)
        update_fallthrough_target(cache, cfg, block, text_section.blocks[0])

    if isinstance(end_block, gtirb.CodeBlock) and isinstance(
        text_section.blocks[-1], gtirb.CodeBlock
    ):
        update_fallthrough_target(
            cache, cfg, text_section.blocks[-1], end_block
        )

    # Add the patch contents and then we can add everything else from the
    # patch.
    edit_byte_interval(
        bi,
        block.offset + block.size,
        replacement_length,
        text_section.data,
        {block},
    )

    # adjust all of the new blocks to be relative to the byte interval and
    # add them to the byte interval
    for b in text_section.blocks:
        b.offset = block.offset + offset + b.offset

    for rel_offset, expr in text_section.symbolic_expressions.items():
        bi.symbolic_expressions[block.offset + offset + rel_offset] = expr

    cache.block_ordering[block.section].insert_blocks_after(
        block, text_section.blocks
    )
    bi.blocks.update(text_section.blocks)
    cfg.update(code.cfg)
    module.symbols.update(code.symbols)
    module.proxies.update(code.proxies)

    alignment_table = _auxdata.alignment.get_or_insert(module)
    alignment_table.update(text_section.alignment.items())

    encodings_table = _auxdata.encodings.get_or_insert(module)
    encodings_table.update(text_section.block_types.items())

    cfi_table = _auxdata_offsetmap.cfi_directives.get_or_insert(module)
    cfi_table.update(code.create_cfi_directives())

    # Introducing new functions would introduce ambiguity and is more hassle
    # than it is worth.
    for attrs in code.elf_symbol_attributes.values():
        if attrs.type == "FUNC":
            raise UnsupportedAssemblyError(
                "cannot introduce new functions in patches"
            )

    elf_symbol_info = _auxdata.elf_symbol_info.get_or_insert(module)
    elf_symbol_info.update(
        {
            sym: (0, attrs.type, attrs.binding, attrs.visibility, 0)
            for sym, attrs in code.elf_symbol_attributes.items()
        }
    )

    if isinstance(block, gtirb.CodeBlock):
        func_uuid = cache.functions_by_block.get(block)
        if func_uuid:
            for b in text_section.blocks:
                if isinstance(b, gtirb.CodeBlock):
                    add_function_block_aux(cache, b, func_uuid)

    sym_expr_data = _auxdata.symbolic_expression_sizes.get_or_insert(module)
    for rel_offset, size in text_section.symbolic_expression_sizes.items():
        sym_expr_data[
            gtirb.Offset(bi, block.offset + offset + rel_offset)
        ] = size

    for sect in code.sections.values():
        if sect is not code.text_section:
            _add_other_section_contents(
                cache, code, sect, module, sym_expr_data
            )

    # The block splitting from earlier might have left zero-sized blocks that
    # need to be dealt with.
    return _cleanup_modified_blocks(
        cache,
        [block, *text_section.blocks, end_block],
    )


def _cleanup_modified_blocks(
    cache: ModifyCache,
    blocks: List[gtirb.ByteBlock],
) -> gtirb.ByteBlock:
    """
    Cleans up any zero-sized blocks that might have been generated during
    modification.
    """

    assert any(b.size for b in blocks), "need at least one block with content"

    # Clean up blocks until we reach a fixed point where there's no further
    # changes to be made.
    while True:
        for (_, pred), (i, block) in pairwise(enumerate(blocks)):
            assert isinstance(pred, gtirb.ByteBlock)
            assert isinstance(block, gtirb.ByteBlock)

            try:
                join_blocks(cache, pred, block)
                del blocks[i]
                break
            except UnjoinableBlocksError:
                pass

            if not block.size and remove_block(cache, block):
                del blocks[i]
                break
        else:
            # No changes were made this iteration, we can be done.
            break

    # This allows inserting a code block at offset 0 of a data block.
    if blocks[0].size == 0 and remove_block(cache, blocks[0]):
        del blocks[0]

    # It should be impossible that we leave behind a zero-sized block, but
    # it's a very important property of this function -- assert it.
    assert all(b.size for b in blocks)

    return blocks[-1]


def _check_compatible_sections(
    module: gtirb.Module,
    gtirb_sect: gtirb.Section,
    patch_sect: Assembler.Result.Section,
):
    """
    Checks if an existing section's flags match the patch's section flags.
    """

    if patch_sect.flags != gtirb_sect.flags:
        logger.warning(
            "flags for patch section %s (%s) do not match existing section "
            "flags (%s)",
            patch_sect.name,
            patch_sect.flags,
            gtirb_sect.flags,
        )

    else:
        section_properties = _auxdata.compat_section_properties(module)
        type, flags = section_properties.get(gtirb_sect, (None, None))
        if type is not None and type != patch_sect.image_type:
            logger.warning(
                "Image type for patch section %s (%s) do not match existing "
                "section image type (%s)",
                patch_sect.name,
                patch_sect.image_type,
                type,
            )
        elif flags is not None and flags != patch_sect.image_flags:
            logger.warning(
                "Image flags for patch section %s (%X) do not match existing "
                "section image flags (%X)",
                patch_sect.name,
                patch_sect.image_flags,
                flags,
            )


def _add_other_section_contents(
    cache: ModifyCache,
    code: Assembler.Result,
    sect: Assembler.Result.Section,
    module: gtirb.Module,
    sym_expr_sizes: MutableMapping[gtirb.Offset, int],
) -> None:
    """
    Adds a non-main section from a patch. Its contents are put in a new byte
    interval in the module's section (creating the section as needed).
    """

    gtirb_sect = next(
        (s for s in module.sections if s.name == sect.name), None
    )
    if gtirb_sect:
        _check_compatible_sections(module, gtirb_sect, sect)
    else:
        gtirb_sect = gtirb.Section(
            name=sect.name, flags=sect.flags, module=module
        )

        section_properties = _auxdata.compat_section_properties(module)
        section_properties[gtirb_sect] = (
            sect.image_type,
            sect.image_flags,
        )

    bi = gtirb.ByteInterval(
        contents=sect.data, symbolic_expressions=sect.symbolic_expressions
    )

    # The assembler can leave a zero-sized block at the end, which we need to
    # deal with because zero-sided blocks cause problems.
    if not sect.blocks[-1].size:
        if isinstance(sect.blocks[-1], gtirb.CodeBlock):
            if any(code.cfg.in_edges(sect.blocks[-1])):
                raise NotImplementedError(
                    "Cannot create a zero-sized block with a incoming edges; "
                    "try adding an instruction at the end."
                )

        # If there's any symbols that reference the last block, make them be
        # at_end symbols pointing at the previous block.
        for sym in code.symbols:
            if sym.referent is sect.blocks[-1]:
                if len(sect.blocks) == 1:
                    raise NotImplementedError(
                        "Cannot create a zero-sized block with a label; try "
                        "adding data after the label."
                    )

                sym.at_end = True
                sym.referent = sect.blocks[-2]

        del sect.blocks[-1]

    cache.block_ordering[gtirb_sect].add_detached_blocks(sect.blocks)
    bi.blocks.update(sect.blocks)
    gtirb_sect.byte_intervals.add(bi)
    for rel_offset, size in sect.symbolic_expression_sizes.items():
        sym_expr_sizes[gtirb.Offset(bi, rel_offset)] = size

    alignment_table = _auxdata.alignment.get_or_insert(module)
    alignment_table.update(sect.alignment.items())

    encodings_table = _auxdata.encodings.get_or_insert(module)
    encodings_table.update(sect.block_types.items())


def edit_byte_interval(
    bi: gtirb.ByteInterval,
    offset: int,
    length: int,
    content: bytes,
    static_blocks: Set[gtirb.ByteBlock] = set(),
) -> None:
    """
    Edits a byte interval's contents, moving blocks, symbolic expressions, and
    aux data as needed.
    :param bi: The byte interval to edit.
    :param offset: The offset in the byte interval to insert at.
    :param length: The number of bytes in the byte interval to overwrite.
    :param content: The content to insert.
    :param static_blocks: Blocks whose offsets should not be updated.
    """

    assert bi.module, "byte interval must be in a module"

    size_delta = len(content) - length

    bi.size += size_delta
    bi.contents = (
        bi.contents[:offset] + content + bi.contents[offset + length :]
    )

    # adjust blocks that occur after the insertion point
    # TODO: what if blocks overlap over the insertion point?
    for b in bi.blocks:
        if b.offset >= offset and b not in static_blocks:
            b.offset += size_delta

    # adjust sym exprs that occur after the insertion point
    bi.symbolic_expressions = {
        (k + size_delta if k >= offset else k): v
        for k, v in bi.symbolic_expressions.items()
        if k < offset or k >= offset + length
    }

    # adjust aux data if present (specifically for byte interval keys)
    for table_def in OFFSETMAP_AUX_DATA_TABLES:
        table_data = table_def.get(bi.module)
        if table_data and bi in table_data:
            displacement_map = table_data[bi]
            table_data[bi] = {
                (k + size_delta if k >= offset else k): v
                for k, v in displacement_map.items()
                if k < offset or k >= offset + length
            }
