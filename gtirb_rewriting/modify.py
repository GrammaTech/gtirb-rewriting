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

import collections
import contextlib
import functools
import itertools
import logging
import operator
import uuid
from typing import (
    Container,
    Dict,
    Iterable,
    Iterator,
    List,
    MutableMapping,
    NamedTuple,
    Optional,
    Set,
    Tuple,
    TypeVar,
    Union,
)

import gtirb
import gtirb_functions
import gtirb_rewriting._auxdata as _auxdata
from more_itertools import triplewise

from ._auxdata_offsetmap import OFFSETMAP_AUX_DATA_TABLES
from .assembler import Assembler, UnsupportedAssemblyError
from .utils import (
    _block_fallthrough_targets,
    _get_function_blocks,
    _is_call_edge,
    _is_fallthrough_edge,
    _is_return_edge,
)

logger = logging.getLogger(__name__)


class AmbiguousCFGError(RuntimeError):
    pass


class CFGModifiedError(RuntimeError):
    pass


class _UnjoinableBlocksError(RuntimeError):
    pass


class _ReturnEdgeCache(gtirb.CFG):
    """
    A CFG subclass that provides a cache for return edges and proxy return
    edges.
    """

    def __init__(self, edges=None) -> None:
        self._return_edges: Dict[
            gtirb.CfgNode, Set[gtirb.Edge]
        ] = collections.defaultdict(set)
        self._proxy_return_edges: Dict[
            gtirb.CfgNode, Set[gtirb.Edge]
        ] = collections.defaultdict(set)
        super().__init__(edges)

    def add(self, edge: gtirb.Edge) -> None:
        super().add(edge)
        if _is_return_edge(edge):
            self._return_edges[edge.source].add(edge)
            if isinstance(edge.target, gtirb.ProxyBlock):
                self._proxy_return_edges[edge.source].add(edge)

    def _dict_set_discard(self, setdict, key, value):
        value_set = setdict[key]
        value_set.discard(value)
        if not value_set:
            del setdict[key]

    def clear(self) -> None:
        super().clear()
        self._return_edges.clear()
        self._proxy_return_edges.clear()

    def discard(self, edge: gtirb.Edge) -> None:
        super().discard(edge)
        if _is_return_edge(edge):
            self._dict_set_discard(self._return_edges, edge.source, edge)
            if isinstance(edge.target, gtirb.ProxyBlock):
                self._dict_set_discard(
                    self._proxy_return_edges, edge.source, edge
                )

    def any_return_edges(self, block: gtirb.CodeBlock) -> bool:
        """
        Determines if a block has any return edges.
        """
        return block in self._return_edges

    def block_return_edges(self, block: gtirb.CodeBlock) -> Set[gtirb.Edge]:
        """
        Gets the set of return edges for a block.
        """
        if block not in self._return_edges:
            return set()

        return set(self._return_edges[block])

    def block_proxy_return_edges(
        self, block: gtirb.CodeBlock
    ) -> Set[gtirb.Edge]:
        """
        Gets the set of return edges that target proxy blocks for a block.
        """
        if block not in self._proxy_return_edges:
            return set()

        return set(self._proxy_return_edges[block])


@contextlib.contextmanager
def _make_return_cache(ir: gtirb.IR) -> Iterator[_ReturnEdgeCache]:
    def _weak_cfg_hash(cfg: gtirb.CFG):
        # This is meant to be a quick and dirty hash of the CFG to detect
        # modifications.
        return functools.reduce(operator.xor, (hash(edge) for edge in cfg), 0)

    if isinstance(ir.cfg, _ReturnEdgeCache):
        yield ir.cfg
    else:
        old_cfg = ir.cfg
        cache = _ReturnEdgeCache(old_cfg)
        old_hash = _weak_cfg_hash(old_cfg)
        ir.cfg = cache

        try:
            yield cache

            # We can't catch all uses of the old CFG, but we can at least
            # error if someone modifies it.
            if _weak_cfg_hash(old_cfg) != old_hash:
                raise CFGModifiedError(
                    "original CFG object should not be modified during "
                    "rewriting; use ir.cfg instead of referring to the "
                    "original CFG"
                )

            # Also catch if ir.cfg is changed from under us.
            if ir.cfg is not cache:
                raise CFGModifiedError(
                    "ir.cfg should not be changed during rewriting"
                )
        finally:
            old_cfg.clear()
            old_cfg.update(cache)
            ir.cfg = old_cfg


class _ModifyCache:
    """
    State that should be preserved across calls to _modify_block_insert to
    improve performance.
    """

    def __init__(
        self,
        module: gtirb.Module,
        functions: Iterable[gtirb_functions.Function],
        return_cache: _ReturnEdgeCache,
    ) -> None:
        self.module = module
        self.return_cache = return_cache
        self.functions_by_block: Dict[gtirb.CodeBlock, uuid.UUID] = {
            block: func.uuid
            for func in functions
            for block in func.get_all_blocks()
        }

    def in_same_function(
        self, block1: gtirb.CodeBlock, block2: gtirb.CodeBlock
    ) -> bool:
        """
        Determines if two blocks are in the same function.
        """
        uuid1 = self.functions_by_block.get(block1)
        uuid2 = self.functions_by_block.get(block2)
        return uuid1 == uuid2 is not None

    def is_entry_block(self, block: gtirb.CodeBlock) -> bool:
        """
        Determines if a code block is a function entry.
        """
        func_uuid = self.functions_by_block.get(block)
        if not func_uuid:
            return False

        table = _auxdata.function_entries.get(self.module)
        if table is None:
            return False

        return block in table[func_uuid]


BlockT = TypeVar("BlockT", bound=gtirb.ByteBlock)


def _split_block(
    cache: _ModifyCache, block: BlockT, offset: int
) -> Tuple[BlockT, BlockT, Optional[gtirb.Edge]]:
    """
    Splits a block in two at the requested offset.
    :param cache: The modify cache.
    :param offset: The offset to split at; must be within [0, block.size].
    :return: The modified block, the newly created block, and the fallthrough
             edge created between them (if needed).
    """

    assert 0 <= offset <= block.size
    assert block.module and block.ir, "target block must be in a module"

    end_split = offset == block.size

    new_block = block.__class__()
    new_block.offset = block.offset + offset
    new_block.size = block.size - offset
    new_block.byte_interval = block.byte_interval
    block.size = offset

    for sym in tuple(block.references):
        if sym.at_end:
            sym.referent = new_block

    added_fallthrough = None
    if isinstance(block, gtirb.CodeBlock):
        assert isinstance(new_block, gtirb.CodeBlock)

        if not end_split:
            # If we're splitting in the middle of the block, we are going to
            # move all of the edges to the new block.
            for out_edge in tuple(block.outgoing_edges):
                _update_edge(
                    out_edge, block.ir.cfg, block.ir.cfg, source=new_block
                )
            add_fallthrough = True
        else:
            # Otherwise we're splitting at the end of the block and all the
            # edges remain in the original block -- with the exception of
            # fallthrough edges and return edges.
            fallthrough_targets = _block_fallthrough_targets(block)
            add_fallthrough = any(fallthrough_targets)

            for out_edge in tuple(block.outgoing_edges):
                if _is_call_edge(out_edge):
                    _update_return_edges_from_changing_fallthrough(
                        cache,
                        out_edge,
                        fallthrough_targets,
                        new_block,
                        block.ir.cfg,
                    )
                elif _is_fallthrough_edge(out_edge):
                    _update_edge(
                        out_edge, block.ir.cfg, block.ir.cfg, source=new_block
                    )

        if add_fallthrough:
            added_fallthrough = gtirb.Edge(
                source=block,
                target=new_block,
                label=gtirb.Edge.Label(type=gtirb.Edge.Type.Fallthrough),
            )
            block.ir.cfg.add(added_fallthrough)

        func_uuid = cache.functions_by_block.get(block)
        if func_uuid:
            _add_function_block_aux(cache, new_block, func_uuid)

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

    return block, new_block, added_fallthrough


def _add_function_block_aux(
    cache: _ModifyCache, new_block: gtirb.CodeBlock, func_uuid: uuid.UUID
) -> None:
    """
    Adds a block to the functionBlocks aux data table.
    """
    assert new_block.module, "block must be in a module"

    function_blocks = _auxdata.function_blocks.get(new_block.module)
    if function_blocks is not None:
        function_blocks[func_uuid].add(new_block)
    cache.functions_by_block[new_block] = func_uuid


def _remove_function_block_aux(
    cache: _ModifyCache, block: gtirb.CodeBlock
) -> None:
    """
    Removes a block from the functionBlocks aux data table.
    """
    assert block.module, "block must be in a module"

    func_uuid = cache.functions_by_block.pop(block, None)
    function_blocks_data = _auxdata.function_blocks.get(block.module)
    if func_uuid and function_blocks_data:
        function_blocks_data[func_uuid].discard(block)


class JoinableResult(NamedTuple):
    result: bool
    reason: str

    def __bool__(self) -> bool:
        return self.result


def _are_joinable(
    cache: _ModifyCache, block1: gtirb.ByteBlock, block2: gtirb.ByteBlock
) -> JoinableResult:
    """
    Determines if two blocks can be joined using _join_blocks.
    """

    if type(block1) != type(block2):
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

    any_symbols = any(not sym.at_end for sym in block2.references)
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


def _join_blocks(
    cache: _ModifyCache,
    block1: BlockT,
    block2: gtirb.ByteBlock,
) -> BlockT:
    """
    Joins two blocks, if possible, or raise _UnjoinableBlocksError.
    """

    joinable = _are_joinable(cache, block1, block2)
    if not joinable:
        raise _UnjoinableBlocksError(joinable.reason)

    ir = block1.ir
    module = block1.module
    assert ir and module

    for sym in tuple(block2.references):
        if not block1.size:
            sym.referent = block1
            sym.at_end = False
        else:
            assert sym.at_end, "cannot join blocks if the second has symbols"
            sym.referent = block1

    if isinstance(block2, gtirb.CodeBlock):
        assert isinstance(block1, gtirb.CodeBlock)

        for in_edge in tuple(block2.incoming_edges):
            if _is_fallthrough_edge(in_edge) and in_edge.source is block1:
                ir.cfg.discard(in_edge)

        if not block1.size:
            for in_edge in tuple(block2.incoming_edges):
                _update_edge(in_edge, ir.cfg, ir.cfg, target=block1)

        else:
            for in_edge in tuple(block2.incoming_edges):
                ir.cfg.discard(in_edge)

        for out_edge in tuple(block2.outgoing_edges):
            _update_edge(out_edge, ir.cfg, ir.cfg, source=block1)

        _remove_function_block_aux(cache, block2)

    for table_def in OFFSETMAP_AUX_DATA_TABLES:
        table_data = table_def.get(module)
        if table_data:
            displacement_map = table_data.pop(block2, None)
            if displacement_map:
                new_displacement_map = table_data.setdefault(block1, {})
                new_displacement_map.update(
                    {block1.size + k: v for k, v in displacement_map.items()}
                )

    alignment_data = _auxdata.alignment.get(module)
    if alignment_data:
        block1_align = alignment_data.get(block1, 1)
        block2_align = alignment_data.pop(block2, 1)

        if block2_align > block1_align:
            assert not block1.size
            alignment_data[block1] = block2_align

    block1.size = block1.size + block2.size
    block2.byte_interval = None

    return block1


def _update_edge(
    edge: gtirb.Edge,
    old_cfg: gtirb.CFG,
    new_cfg: gtirb.CFG,
    **kwargs: gtirb.CfgNode,
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


def _add_return_edges_to_one_function(
    cache: _ModifyCache,
    module: gtirb.Module,
    func_uuid: uuid.UUID,
    return_target: gtirb.CfgNode,
    new_cfg: gtirb.CFG,
) -> None:
    """
    Adds a new return edge to all returns in the function.
    """
    for block in _get_function_blocks(module, func_uuid):
        assert block.ir

        if not cache.return_cache.any_return_edges(block):
            continue

        for return_edge in cache.return_cache.block_proxy_return_edges(block):
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
    cache: _ModifyCache,
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

        _add_return_edges_to_one_function(
            cache, module, func_uuid, fallthrough_target, new_cfg
        )


def _update_patch_return_edges_to_match(
    cache: _ModifyCache,
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


def _update_return_edges_from_removing_call(
    cache: _ModifyCache,
    call_edge: gtirb.Edge,
    fallthrough_targets: Container[gtirb.CodeBlock],
    new_cfg: gtirb.CFG,
) -> None:
    """
    Updates return edges due to removing a call edge.
    """

    assert isinstance(call_edge.target, (gtirb.CodeBlock, gtirb.ProxyBlock))
    assert call_edge.target.module

    if isinstance(call_edge.target, gtirb.ProxyBlock):
        return

    func_uuid = cache.functions_by_block.get(call_edge.target, None)
    if not func_uuid:
        return

    for block in _get_function_blocks(call_edge.target.module, func_uuid):
        assert block.module and block.ir

        return_edges = cache.return_cache.block_return_edges(block)
        if not return_edges:
            continue

        remaining_edges = False
        for edge in return_edges:
            if edge.target in fallthrough_targets:
                block.ir.cfg.discard(edge)
            else:
                remaining_edges = True

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
    cache: _ModifyCache,
    call_edge: gtirb.Edge,
    fallthrough_targets: Container[gtirb.CodeBlock],
    new_fallthrough: gtirb.CodeBlock,
    new_cfg: gtirb.CFG,
) -> None:
    """
    Updates all return edges in a function that point to a given return target
    to point to a new target.
    """

    assert isinstance(call_edge.target, (gtirb.ProxyBlock, gtirb.CodeBlock))
    assert call_edge.target.module

    if isinstance(call_edge.target, gtirb.ProxyBlock):
        return

    target_func_uuid = cache.functions_by_block.get(call_edge.target, None)
    if not target_func_uuid:
        return

    for target_block in _get_function_blocks(
        call_edge.target.module, target_func_uuid
    ):
        assert target_block.ir

        for edge in cache.return_cache.block_return_edges(target_block):
            if edge.target in fallthrough_targets:
                _update_edge(
                    edge, target_block.ir.cfg, new_cfg, target=new_fallthrough
                )


def _update_fallthrough_target(
    cache: _ModifyCache,
    cfg: gtirb.CFG,
    source: gtirb.CodeBlock,
    new_target: gtirb.CodeBlock,
) -> None:
    """
    Retargets a block to fall through to a new target. This takes care of also
    updating the necessary return edges.
    """

    old_targets = _block_fallthrough_targets(source)

    for edge in tuple(source.outgoing_edges):
        if _is_call_edge(edge):
            _update_return_edges_from_changing_fallthrough(
                cache, edge, old_targets, new_target, cfg
            )
        elif _is_fallthrough_edge(edge):
            cfg.discard(edge)

    cfg.add(
        gtirb.Edge(
            source=source,
            target=new_target,
            label=gtirb.Edge.Label(type=gtirb.Edge.Type.Fallthrough),
        )
    )


def _remove_block(
    cache: _ModifyCache,
    block: gtirb.ByteBlock,
    next_block: Union[gtirb.ByteBlock, gtirb.ProxyBlock, None],
) -> None:
    """
    Deletes a block and retargets any symbols or edges pointing at it to be
    to another block. This does not modify the byte interval; use
    _edit_byte_interval for that.
    """

    assert block.module and block.ir

    if next_block is None and (
        any(block.references)
        or (isinstance(block, gtirb.CodeBlock) and any(block.incoming_edges))
    ):
        raise AmbiguousCFGError(
            "removing a block without knowing how to update control flow"
        )

    if (
        isinstance(block, gtirb.CodeBlock)
        and any(block.incoming_edges)
        and not isinstance(next_block, gtirb.CfgNode)
    ):
        raise AmbiguousCFGError(
            "removing a block would cause control to flow into data"
        )

    for sym in set(block.references):
        sym.referent = next_block
        sym.at_end = False

    if isinstance(block, gtirb.CodeBlock):
        for edge in set(block.incoming_edges):
            assert isinstance(next_block, gtirb.CfgNode)
            _update_edge(edge, block.ir.cfg, block.ir.cfg, target=next_block)

        fallthrough_targets = _block_fallthrough_targets(block)
        for edge in set(block.outgoing_edges):
            if _is_call_edge(edge):
                _update_return_edges_from_removing_call(
                    cache, edge, fallthrough_targets, block.ir.cfg
                )
            block.ir.cfg.discard(edge)

        function_uuid = cache.functions_by_block.get(block, None)
        if function_uuid:
            # If it was previously a function entry block, the next block gets
            # promoted into that role.
            aux_function_entries = _auxdata.function_entries.get(block.module)
            if (
                aux_function_entries
                and block in aux_function_entries[function_uuid]
            ):
                if isinstance(next_block, gtirb.CodeBlock):
                    aux_function_entries[function_uuid].add(next_block)
                aux_function_entries[function_uuid].discard(block)

            aux_function_blocks = _auxdata.function_blocks.get(block.module)
            if aux_function_blocks:
                aux_function_blocks[function_uuid].discard(block)

    for table_def in OFFSETMAP_AUX_DATA_TABLES:
        table = table_def.get(block.module)
        if table is not None and block in table:
            del table[block]

    aux_alignment = _auxdata.alignment.get(block.module)
    if aux_alignment:
        aux_alignment.pop(block, None)

    block.byte_interval = None


def _delete(
    cache: _ModifyCache,
    block: gtirb.ByteBlock,
    offset: int,
    length: int,
    next_block: Union[gtirb.ByteBlock, gtirb.ProxyBlock, None],
) -> Union[gtirb.ByteBlock, gtirb.ProxyBlock, None]:
    """
    Deletes code from a block, potentially deleting the whole block.
    """

    assert cache.module is block.module
    assert block.size
    assert 0 <= offset <= block.size
    assert 0 <= offset + length <= block.size
    assert length >= 0

    bi = block.byte_interval
    assert bi

    if not length:
        return block

    if length != block.size:
        start, end, _ = _split_block(cache, block, offset)
        mid, end, _ = _split_block(cache, end, length)

        _remove_block(cache, mid, end)
        _edit_byte_interval(bi, start.offset + offset, length, b"", {start})
        return _cleanup_modified_blocks(cache, start, [], end, next_block)

    else:
        _remove_block(cache, block, next_block)
        _edit_byte_interval(bi, block.offset + offset, length, b"")
        return next_block


def _modify_block_insert(
    cache: _ModifyCache,
    block: gtirb.ByteBlock,
    offset: int,
    replacement_length: int,
    code: Assembler.Result,
    next_block: Optional[gtirb.ByteBlock],
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
    assert block.byte_interval and block.module and block.ir

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

    _, end_block, added_fallthrough = _split_block(cache, block, offset)

    if replacement_length:
        mid_block, end_block, _ = _split_block(
            cache, end_block, replacement_length
        )
        _remove_block(cache, mid_block, end_block)

    # Stitch in the new blocks to the CFG
    if added_fallthrough:
        assert isinstance(text_section.blocks[0], gtirb.CodeBlock)
        assert isinstance(block, gtirb.CodeBlock)
        _update_fallthrough_target(cache, cfg, block, text_section.blocks[0])

    if isinstance(end_block, gtirb.CodeBlock) and isinstance(
        text_section.blocks[-1], gtirb.CodeBlock
    ):
        _update_fallthrough_target(
            cache, cfg, text_section.blocks[-1], end_block
        )

    # Add the patch contents and then we can add everything else from the
    # patch.
    _edit_byte_interval(
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

    bi.blocks.update(text_section.blocks)
    cfg.update(code.cfg)
    module.symbols.update(code.symbols)
    module.proxies.update(code.proxies)

    alignment_table = _auxdata.alignment.get_or_insert(module)
    alignment_table.update(text_section.alignment.items())

    encodings_table = _auxdata.encodings.get_or_insert(module)
    encodings_table.update(text_section.block_types.items())

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
                    _add_function_block_aux(cache, b, func_uuid)

    sym_expr_data = _auxdata.symbolic_expression_sizes.get_or_insert(module)
    for rel_offset, size in text_section.symbolic_expression_sizes.items():
        sym_expr_data[
            gtirb.Offset(bi, block.offset + offset + rel_offset)
        ] = size

    for sect in code.sections.values():
        if sect is not code.text_section:
            _add_other_section_contents(code, sect, module, sym_expr_data)

    # The block splitting from earlier might have left zero-sized blocks that
    # need to be dealt with.
    return _cleanup_modified_blocks(
        cache,
        block,
        text_section.blocks,
        end_block,
        next_block,
    )


def _cleanup_modified_blocks(
    cache: _ModifyCache,
    start_block: gtirb.ByteBlock,
    patch_blocks: List[gtirb.ByteBlock],
    end_block: gtirb.ByteBlock,
    next_block: Union[gtirb.ByteBlock, gtirb.ProxyBlock, None],
) -> gtirb.ByteBlock:
    """
    Cleans up any zero-sized blocks that might have been generated during
    modification.
    """

    blocks = [start_block, *patch_blocks, end_block]
    assert any(b.size for b in blocks), "need at least one block with content"

    def iter_blocks() -> Iterator[
        Union[gtirb.ByteBlock, gtirb.ProxyBlock, None]
    ]:
        return itertools.chain(blocks, (next_block,))

    # Clean up blocks until we reach a fixed point where there's no further
    # changes to be made.
    while True:
        for (_, pred), (i, block), (_, succ) in triplewise(
            enumerate(iter_blocks())
        ):
            assert isinstance(pred, gtirb.ByteBlock)
            assert isinstance(block, gtirb.ByteBlock)

            try:
                _join_blocks(cache, pred, block)
                del blocks[i]
                break
            except _UnjoinableBlocksError:
                pass

            if not block.size:
                _remove_block(cache, block, succ)
                del blocks[i]
                break
        else:
            # No changes were made this iteration, we can be done.
            break

    # This allows inserting a code block at offset 0 of a data block.
    if blocks[0].size == 0:
        to_remove = blocks[0]
        del blocks[0]

        _remove_block(cache, to_remove, next(iter_blocks()))

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

    bi.blocks.update(sect.blocks)
    gtirb_sect.byte_intervals.add(bi)
    for rel_offset, size in sect.symbolic_expression_sizes.items():
        sym_expr_sizes[gtirb.Offset(bi, rel_offset)] = size

    alignment_table = _auxdata.alignment.get_or_insert(module)
    alignment_table.update(sect.alignment.items())

    encodings_table = _auxdata.encodings.get_or_insert(module)
    encodings_table.update(sect.block_types.items())


def _edit_byte_interval(
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

    # adjust aux data if present
    for table_def in OFFSETMAP_AUX_DATA_TABLES:
        table_data = table_def.get(bi.module)
        if table_data and bi in table_data:
            displacement_map = table_data[bi]
            table_data[bi] = {
                (k + size_delta if k >= offset else k): v
                for k, v in displacement_map.items()
                if k < offset or k >= offset + length
            }
