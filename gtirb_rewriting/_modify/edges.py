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
Functions for manipulating edges in the CFG.
"""

import uuid
from typing import Container, Optional, overload

import gtirb
from typing_extensions import NotRequired, TypedDict, Unpack

from ..utils import (
    _block_fallthrough_targets,
    _get_function_blocks,
    _is_call_edge,
    _is_fallthrough_edge,
)
from .cache import ModifyCache


class _EdgeKWArgs(TypedDict):
    source: NotRequired[gtirb.CfgNode]
    target: NotRequired[gtirb.CfgNode]


@overload
def update_edge(
    edge: gtirb.Edge,
    new_cfg: gtirb.CFG,
    **kwargs: Unpack[_EdgeKWArgs],
) -> None:
    ...


@overload
def update_edge(
    edge: gtirb.Edge,
    new_cfg: gtirb.CFG,
    old_cfg: gtirb.CFG,
    **kwargs: Unpack[_EdgeKWArgs],
) -> None:
    ...


def update_edge(
    edge: gtirb.Edge,
    new_cfg: gtirb.CFG,
    old_cfg: Optional[gtirb.CFG] = None,
    **kwargs: Unpack[_EdgeKWArgs],
) -> None:
    """
    Updates properties about an edge.
    :param edge: The edge to update.
    :param old_cfg: The CFG containing the edge. The edge will be removed.
    :param new_cfg: The CFG that the updated edge should be added to.
    :param kwargs: Properties of the edge to update.
    """

    if old_cfg is None:
        old_cfg = new_cfg

    old_cfg.discard(edge)
    new_cfg.add(edge._replace(**kwargs))


def update_return_edges_from_changing_call_fallthrough(
    cache: ModifyCache,
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
                update_edge(
                    edge, target_block.ir.cfg, new_cfg, target=new_fallthrough
                )


def update_fallthrough_target(
    cache: ModifyCache,
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
            update_return_edges_from_changing_call_fallthrough(
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


def add_return_edges_to_callee(
    cache: ModifyCache,
    module: gtirb.Module,
    func_uuid: uuid.UUID,
    return_target: gtirb.CfgNode,
    cfg: gtirb.CFG,
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

        cfg.add(
            gtirb.Edge(
                source=block,
                target=return_target,
                label=gtirb.Edge.Label(type=gtirb.Edge.Type.Return),
            )
        )


def remove_return_edges_from_callee(
    cache: ModifyCache,
    call_edge: gtirb.Edge,
    fallthrough_targets: Container[gtirb.CodeBlock],
    cfg: gtirb.CFG,
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
            cfg.add(
                gtirb.Edge(
                    source=block,
                    target=proxy,
                    label=gtirb.Edge.Label(type=gtirb.Edge.Type.Return),
                )
            )
            block.module.proxies.add(proxy)
