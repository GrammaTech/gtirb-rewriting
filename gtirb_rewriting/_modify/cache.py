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
Caches to make repeated modifications faster.
"""

import collections
import contextlib
import functools
import logging
import operator
import uuid
from typing import Dict, Iterable, Iterator, Optional, Set, Tuple, cast

import gtirb
import gtirb_functions
import gtirb_rewriting._auxdata as _auxdata

from .._adt import BlockOrdering
from ..utils import _is_return_edge

logger = logging.getLogger(__name__)


class CFGModifiedError(RuntimeError):
    pass


class ReturnEdgeCache(gtirb.CFG):
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
def make_return_cache(ir: gtirb.IR) -> Iterator[ReturnEdgeCache]:
    def _weak_cfg_hash(cfg: gtirb.CFG):
        # This is meant to be a quick and dirty hash of the CFG to detect
        # modifications.
        return functools.reduce(operator.xor, (hash(edge) for edge in cfg), 0)

    if isinstance(ir.cfg, ReturnEdgeCache):
        yield ir.cfg
    else:
        old_cfg = ir.cfg
        cache = ReturnEdgeCache(old_cfg)
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


class ModifyCache:
    """
    State that should be preserved across calls to _modify_block_insert to
    improve performance.
    """

    def __init__(
        self,
        module: gtirb.Module,
        functions: Iterable[gtirb_functions.Function],
        return_cache: ReturnEdgeCache,
    ) -> None:
        self.module = module
        self.return_cache = return_cache
        self.functions_by_block: Dict[gtirb.CodeBlock, uuid.UUID] = {
            block: func.uuid
            for func in functions
            for block in func.get_all_blocks()
        }

        for block in module.byte_blocks:
            if block.address is None:
                raise ValueError("all blocks must have addresses")

        self.block_ordering = collections.defaultdict(BlockOrdering)
        for sect in module.sections:
            self.block_ordering[sect].add_detached_blocks(
                sorted(
                    sect.byte_blocks,
                    key=lambda b: (cast(int, b.address), b.size != 0),
                )
            )

    def adjacent_blocks(
        self, block: gtirb.ByteBlock
    ) -> Tuple[Optional[gtirb.ByteBlock], Optional[gtirb.ByteBlock]]:
        """
        Get the blocks that come before and after the requested block in the
        block's section.
        """
        assert block.section
        return self.block_ordering[block.section].adjacent_blocks(block)

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
