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

import uuid
from typing import Container, Dict, Iterable, Set

import gtirb

from .assembler import Assembler
from .utils import (
    OffsetMapping,
    _block_fallthrough_targets,
    _block_return_edges,
    _get_function_blocks,
    _get_or_insert_aux_data,
    _is_call_edge,
    _is_fallthrough_edge,
    _is_return_edge,
)


def _update_edge(
    edge: gtirb.Edge, old_cfg: gtirb.CFG, new_cfg: gtirb.CFG, **kwargs
) -> None:
    """
    Updates properties about an edge.
    :param edge: The edge to update.
    :param old_cfg: The CFG containing the edge. The edge will be removed.
    :param new_cfg: The CFG that the updated edge should be added to.
    :param kwargs: Properties of the edge to update.
    """

    old_cfg.discard(edge)
    new_cfg.add(edge._replace(**kwargs))


def _substitute_block(
    old_block: gtirb.CodeBlock,
    new_block: gtirb.CodeBlock,
    cfg: gtirb.CFG,
    symbols: Iterable[gtirb.Symbol],
) -> None:
    """
    Substitutes one block for another by adjusting the CFG and any symbols
    pointing at the block.
    """

    for edge in set(cfg.in_edges(old_block)):
        _update_edge(edge, cfg, cfg, target=new_block)

    for edge in set(cfg.out_edges(old_block)):
        _update_edge(edge, cfg, cfg, source=new_block)

    for sym in symbols:
        if sym.referent == old_block:
            sym.referent = new_block


def _add_return_edges_to_one_function(
    module: gtirb.Module,
    func_uuid: uuid.UUID,
    return_target: gtirb.CodeBlock,
    new_cfg: gtirb.CFG,
) -> None:
    """
    Adds a new return edge to all returns in the function.
    """
    for block in _get_function_blocks(module, func_uuid):
        return_edges = _block_return_edges(block)
        if not return_edges:
            continue

        for return_edge in return_edges:
            if isinstance(return_edge.target, gtirb.ProxyBlock):
                # We are intentionally leaving the proxy block in the module's
                # proxies.
                block.ir.cfg.discard(return_edge)

        new_cfg.add(
            gtirb.Edge(
                source=block,
                target=return_target,
                label=gtirb.Edge.Label(type=gtirb.Edge.Type.Return),
            )
        )


def _add_return_edges_for_patch_calls(
    module: gtirb.Module,
    functions_by_block: Dict[gtirb.CodeBlock, uuid.UUID],
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
        func_uuid = functions_by_block.get(call_edge.target, None)
        if not func_uuid:
            continue

        fallthrough_target = fallthroughs_by_block.get(call_edge.source, None)
        if not fallthrough_target:
            continue

        _add_return_edges_to_one_function(
            module, func_uuid, fallthrough_target, new_cfg
        )


def _update_patch_return_edges_to_match(
    block: gtirb.CodeBlock,
    functions_by_block: Dict[gtirb.CodeBlock, uuid.UUID],
    new_cfg: gtirb.CFG,
    new_proxy_blocks: Set[gtirb.ProxyBlock],
) -> None:
    """
    Finds all return edges in a patch and updates them to match the function
    being inserted into.
    """
    patch_return_edges = {
        edge
        for edge in new_cfg
        if _is_return_edge(edge) and edge.target in new_proxy_blocks
    }
    if not patch_return_edges:
        return

    func_uuid = functions_by_block.get(block, None)
    if not func_uuid:
        return

    return_targets = set()
    for func_block in _get_function_blocks(block.module, func_uuid):
        return_targets.update(
            edge.target
            for edge in func_block.outgoing_edges
            if _is_return_edge(edge)
            and not isinstance(edge.target, gtirb.ProxyBlock)
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


def _update_return_edges_from_removing_call(
    call_edge: gtirb.Edge,
    fallthrough_targets: Container[gtirb.CodeBlock],
    functions_by_block: Dict[gtirb.CodeBlock, uuid.UUID],
    new_cfg: gtirb.CFG,
) -> None:
    """
    Updates return edges due to removing a call edge.
    """
    if isinstance(call_edge.target, gtirb.ProxyBlock):
        return

    func_uuid = functions_by_block.get(call_edge.target, None)
    if not func_uuid:
        return

    for block in _get_function_blocks(call_edge.target.module, func_uuid):
        return_edges = _block_return_edges(block)
        if not return_edges:
            continue

        remaining_edges = set()
        for edge in return_edges:
            if edge.target in fallthrough_targets:
                block.ir.cfg.discard(edge)
            else:
                remaining_edges.add(edge)

        if not remaining_edges:
            proxy = gtirb.ProxyBlock()
            new_cfg.add(
                gtirb.Edge(
                    source=block,
                    target=proxy,
                    label=gtirb.Edge.Label(type=gtirb.Edge.Type.Return),
                )
            )
            block.module.proxies.add(proxy)


def _update_return_edges_from_changing_fallthrough(
    call_edge: gtirb.Edge,
    fallthrough_targets: Container[gtirb.CodeBlock],
    functions_by_block: Dict[gtirb.CodeBlock, uuid.UUID],
    new_fallthrough: gtirb.CodeBlock,
    new_cfg: gtirb.CFG,
) -> None:
    """
    Updates all return edges in a function that point to a given return target
    to point to a new target.
    """
    if isinstance(call_edge.target, gtirb.ProxyBlock):
        return

    target_func_uuid = functions_by_block.get(call_edge.target, None)
    if not target_func_uuid:
        return

    for target_block in _get_function_blocks(
        call_edge.target.module, target_func_uuid
    ):
        for edge in _block_return_edges(target_block):
            if edge.target in fallthrough_targets:
                _update_edge(
                    edge, target_block.ir.cfg, new_cfg, target=new_fallthrough
                )


def _modify_block_insert(
    block: gtirb.CodeBlock,
    offset: int,
    replacement_length: int,
    code: Assembler.Result,
    functions_by_block: Dict[gtirb.CodeBlock, uuid.UUID],
) -> None:
    """
    Insert bytes into a block and adjusts the IR as needed.
    :param block: The code block to insert into.
    :param offset: The byte offset into the code block.
    :param replacement_length: The number of bytes after `offset` that should
                               be removed.
    :param code: The assembled code to be inserted. It will be modified to
                 reflect what actually gets inserted in the binary.
    :param functions_by_block: Map from code block to containing function UUID.
    """

    assert block.size
    assert 0 <= offset <= block.size
    assert 0 <= offset + replacement_length <= block.size
    assert replacement_length >= 0
    assert code.data
    assert code.blocks
    assert block not in code.blocks
    assert code.blocks[0].size, "must have at least one non-empty block"
    assert all(
        new_block.size for new_block in code.blocks[:-1]
    ), "only the last block may be empty"
    assert isinstance(code.blocks[-1], gtirb.DataBlock) or not any(
        code.cfg.out_edges(code.blocks[-1])
    ), "the last block cannot have outgoing cfg edges"

    bi = block.byte_interval
    assert bi

    _add_return_edges_for_patch_calls(
        block.module, functions_by_block, code.cfg
    )
    _update_patch_return_edges_to_match(
        block, functions_by_block, code.cfg, code.proxies
    )

    # Adjust codeblock sizes, create CFG edges, remove 0-size blocks
    _modify_block_insert_cfg(
        block, offset, replacement_length, code, functions_by_block,
    )

    size_delta = len(code.data) - replacement_length
    offset += block.offset

    # adjust byte interval the block goes in
    bi.size += size_delta
    bi.contents = (
        bi.contents[:offset]
        + code.data
        + bi.contents[offset + replacement_length :]
    )

    # adjust blocks that occur after the insertion point
    # TODO: what if blocks overlap over the insertion point?
    for b in bi.blocks:
        if b != block and b.offset >= offset:
            b.offset += size_delta

    # adjust all of the new blocks to be relative to the byte interval and
    # add them to the byte interval
    for b in code.blocks:
        b.offset += offset

    assert block.size and all(b.size for b in code.blocks), (
        "_modify_block_insert created a zero-sized block; please file a bug "
        "report against gtirb-rewriting"
    )
    bi.blocks.update(code.blocks)

    # adjust sym exprs that occur after the insertion point
    bi.symbolic_expressions = {
        (k + size_delta if k >= offset else k): v
        for k, v in bi.symbolic_expressions.items()
        if k < offset or k >= offset + replacement_length
    }

    # add all of the symbolic expressions from the code we're inserting
    for rel_offset, expr in code.symbolic_expressions.items():
        bi.symbolic_expressions[offset + rel_offset] = expr

    bi.ir.cfg.update(code.cfg)
    bi.module.symbols.update(code.symbols)
    bi.module.proxies.update(code.proxies)

    # adjust aux data if present
    def update_aux_data_keyed_by_offset(name):
        table = bi.module.aux_data.get(name)
        if table:
            if not isinstance(table.data, OffsetMapping):
                table.data = OffsetMapping(table.data)
            if bi in table.data:
                displacement_map = table.data[bi]
                del table.data[bi]
                table.data[bi] = {
                    (k + size_delta if k >= offset else k): v
                    for k, v in displacement_map.items()
                    if k < offset or k >= offset + replacement_length
                }

    update_aux_data_keyed_by_offset("comments")
    update_aux_data_keyed_by_offset("padding")
    update_aux_data_keyed_by_offset("symbolicExpressionSizes")

    sym_expr_sizes = _get_or_insert_aux_data(
        bi.module, "symbolicExpressionSizes", "mapping<Offset,uint64_t>", dict
    )
    for rel_offset, size in code.symbolic_expression_sizes.items():
        sym_expr_sizes[gtirb.Offset(bi, offset + rel_offset)] = size


def _modify_block_insert_cfg(
    block: gtirb.CodeBlock,
    offset: int,
    replacement_length: int,
    code: Assembler.Result,
    functions_by_block: Dict[gtirb.CodeBlock, uuid.UUID],
) -> None:
    """
    Adjust codeblock sizes, create CFG edges, remove 0-size blocks.
    :param block: The code block to insert into.
    :param offset: The byte offset into the code block.
    :param replacement_length: The number of bytes after `offset` that should
                               be removed.
    :param code: The assembled code to be inserted. It will be modified to
                 reflect what actually gets inserted in the binary.
    :param functions_by_block: Map from code block to containing function UUID.
    """

    bi = block.byte_interval

    original_size = block.size
    inserts_at_end = not replacement_length and offset == block.size
    replaces_last_instruction = (
        replacement_length and offset + replacement_length == block.size
    )

    # Adjust the target codeblock and discard the new codeblock if no new CFG
    # edges are created, no new symbols are created, and the replacement is not
    # at the end of a block.
    if (
        not code.cfg
        and not code.symbols
        and not inserts_at_end
        and not replaces_last_instruction
    ):
        assert len(code.blocks) == 1
        assert isinstance(code.blocks[0], gtirb.CodeBlock)

        block.size = block.size - replacement_length + len(code.data)

        # Remove all the blocks from code.blocks so that they don't get added
        # to the byte_interval in _modify_block_insert.
        code.blocks.clear()
        return

    # If the patch ended in a data block, we need to create a new code block
    # that will contain any remaining code from the original block.
    if isinstance(code.blocks[-1], gtirb.DataBlock):
        assert code.blocks[-1].size
        code.blocks.append(gtirb.CodeBlock(offset=len(code.data)))

    # Adjust the target block to be the size of offset. Then extend the last
    # patch block to cover the remaining bytes in the original block.
    block.size = offset
    code.blocks[-1].size += original_size - offset - replacement_length

    # Now add a fallthrough edge from the original block to the first patch
    # block, unless we're inserting at the end of the block and the block has
    # no fallthrough edges. For example, inserting after a ret instruction.
    if not inserts_at_end or any(_block_fallthrough_targets(block)):
        assert isinstance(code.blocks[0], gtirb.CodeBlock)
        added_fallthrough = gtirb.Edge(
            source=block,
            target=code.blocks[0],
            label=gtirb.Edge.Label(type=gtirb.Edge.Type.Fallthrough),
        )
        code.cfg.add(added_fallthrough)

    # Alter any outgoing edges from the original block to originate from the
    # last patch block.
    if inserts_at_end:
        fallthrough_targets = _block_fallthrough_targets(block)

        for edge in set(block.outgoing_edges):
            if _is_fallthrough_edge(edge):
                _update_edge(edge, bi.ir.cfg, code.cfg, source=code.blocks[-1])
            elif _is_call_edge(edge):
                _update_return_edges_from_changing_fallthrough(
                    edge,
                    fallthrough_targets,
                    functions_by_block,
                    code.blocks[0],
                    code.cfg,
                )
    elif replaces_last_instruction:
        fallthrough_targets = _block_fallthrough_targets(block)

        for edge in set(block.outgoing_edges):
            if _is_fallthrough_edge(edge):
                _update_edge(edge, bi.ir.cfg, code.cfg, source=code.blocks[-1])
            elif _is_call_edge(edge):
                _update_return_edges_from_removing_call(
                    edge, fallthrough_targets, functions_by_block, code.cfg
                )
                bi.ir.cfg.discard(edge)
            else:
                bi.ir.cfg.discard(edge)
    else:
        for edge in set(block.outgoing_edges):
            _update_edge(edge, bi.ir.cfg, code.cfg, source=code.blocks[-1])

    # Now go back and clean up any zero-sized blocks, which trigger
    # nondeterministic behavior in the pretty printer.
    if block.size == 0:
        code.cfg.discard(added_fallthrough)

        block.size = code.blocks[0].size
        _substitute_block(
            code.blocks[0], block, code.cfg, code.symbols,
        )
        del code.blocks[0]

    if code.blocks and code.blocks[-1].size == 0:
        has_symbols = any(
            sym.referent == code.blocks[-1] for sym in code.symbols
        )
        has_incoming_edges = any(code.cfg.in_edges(code.blocks[-1]))
        fallthrough_edges = [
            edge
            for edge in code.cfg.out_edges(code.blocks[-1])
            if _is_fallthrough_edge(edge)
        ]

        if not has_symbols and not has_incoming_edges:
            # If nothing refers to the block, we can simply drop it and any
            # outgoing edges that may have been added to it from the earlier
            # steps.
            for out_edge in set(code.cfg.out_edges(code.blocks[-1])):
                code.cfg.discard(out_edge)
            del code.blocks[-1]
        elif len(fallthrough_edges) == 1:
            # If we know where the "next" block is, substitute that for our
            # last block.
            _substitute_block(
                code.blocks[-1],
                fallthrough_edges[0].target,
                code.cfg,
                code.symbols,
            )
            del code.blocks[-1]
        else:
            # We don't know where control flow goes after our patch, so we'll
            # raise an exception for now. There are other ways of resolving
            # this that we could explore (e.g. insert a nop at the end of the
            # inserted bytes to make it be a non-zero block).
            raise NotImplementedError(
                "Attempting to insert a block at the end of another "
                "block without knowing how to update control flow"
            )
