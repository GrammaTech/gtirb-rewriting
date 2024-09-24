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
import dataclasses
import functools
import logging
import operator
import uuid
from typing import Dict, Iterable, Iterator, Optional, Set, Tuple, Union, cast

import gtirb
import gtirb_functions
import more_itertools as mi
from typing_extensions import Self

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


@dataclasses.dataclass(eq=False)
class RefNode:
    """A node in a ReferenceCache tree."""

    parent: Union[gtirb.Block, "RefNode"]
    """The parent of this node, or the referent block if this is the root."""

    symbols: Set[gtirb.Symbol] = dataclasses.field(default_factory=set)
    """The indirect symbols assigned to this node."""

    children: Set["RefNode"] = dataclasses.field(default_factory=set)
    """The subtrees of this node."""


class ReferenceCache:
    """
    A data structure for efficiently updating many symbol referents.

    The cache introduces a distinction between "direct" and "indirect" symbol
    references. "Direct" references are the references provided by GTIRB,
    accessed using symbol.referent and block.references. "Indirect" references
    are managed by this cache and enable efficient bulk retargeting. Although
    the cache operations should be preferred in most cases to account for
    indirect references, it is safe to assign a referent when creating a
    symbol since that symbol cannot yet have an indirect reference.

    The get_referent() and get_references() methods convert indirect references
    to direct references. This ensures the referent and at_end properties are
    consistent for the affected symbol after calling one of these methods.

    Note that converting between direct and indirect references limits how
    efficiently bulk retargeting can be performed. Iterating over references
    should therefore be avoided when possible. To make this easier,
    get_references() converts symbols lazily, converting each immediately
    before yielding.
    """

    def __init__(self):
        # Indirect references are implemented using two trees of RefNodes, one
        # for references to the start of the referent and another for
        # references to the end.

        self._referents: Dict[gtirb.Symbol, RefNode] = {}

        # By convention, the first tree points to the start.
        self._references: Dict[gtirb.Block, Tuple[RefNode, RefNode]] = {}

    def __enter__(self) -> Self:
        """
        Enter the cache's context.

        ReferenceCache is not currently reentrant.
        """
        return self

    def __exit__(self, typ, value, trace) -> None:
        """Leave the cache context and apply changes."""
        self.apply()

    def retarget_references(
        self,
        block: gtirb.Block,
        to_block: Optional[gtirb.Block],
        at_end: bool,
    ) -> None:
        """Retarget all block references to point to to_block instead.

        Performance is proportional to the number of direct references to the
        block.

        :param block: block to move references from
        :param to_block: block to move references to
        :param at_end: whether to move references to the start or end of
             to_block
        """
        if not any(block.references) and block not in self._references:
            # No direct or indirect references, so nothing to retarget.
            return
        assert to_block

        # Get indirect references and detach them from the block.
        if block in self._references:
            start_refs, end_refs = self._references.pop(block)
        else:
            start_refs, end_refs = RefNode(block), RefNode(block)

        # Convert any direct references into indirect references.
        for symbol in tuple(block.references):
            # The only way for a symbol to be in self._referents is to call
            # this method. For it to be in block.references as well means that
            # the client set `symbol.referent = block` afterwards without using
            # set_referent, get_referent, get_references, or apply to make the
            # reference direct first.
            assert (
                symbol not in self._referents
            ), "symbol has both direct and indirect references"

            if symbol.at_end:
                end_refs.symbols.add(symbol)
                self._referents[symbol] = end_refs
            else:
                start_refs.symbols.add(symbol)
                self._referents[symbol] = start_refs
            symbol.referent = None

        # Get indirect references to the target block.
        if to_block not in self._references:
            self._references[to_block] = RefNode(to_block), RefNode(to_block)
        if at_end:
            target_ref = self._references[to_block][1]
        else:
            target_ref = self._references[to_block][0]

        # Point source-block references to the target block.
        target_ref.children.add(start_refs)
        target_ref.children.add(end_refs)
        start_refs.parent = target_ref
        end_refs.parent = target_ref

    def get_references(self, block: gtirb.Block) -> Iterator[gtirb.Symbol]:
        """
        Get all symbols referring to the block.

        This includes both direct and indirect references, which will be
        converted to direct references when each is yielded.
        """
        yield from block.references

        if block not in self._references:
            return

        start_refs, end_refs = self._references[block]
        yield from self._make_direct_refs(block, start_refs, False)
        yield from self._make_direct_refs(block, end_refs, True)

        # _make_direct_refs() converts indirect into direct references. If we
        # got here, this block has no indirect references left.
        del self._references[block]

    def _make_direct_refs(
        self, referent: gtirb.Block, root: RefNode, at_end: bool
    ) -> Iterator[gtirb.Symbol]:
        """
        Convert indirect references to direct references pointing to block.
        """
        worklist = [root]
        while worklist:
            node = worklist.pop()
            for child in tuple(node.children):
                node.children.remove(child)
                child.parent = root
                root.children.add(child)
                worklist.append(child)
            for symbol in tuple(node.symbols):
                node.symbols.remove(symbol)
                del self._referents[symbol]
                symbol.referent = referent
                symbol.at_end = at_end
                yield symbol
            if node.parent is root:
                # The node.children loop above removes children from this node
                # and reassigns them to the root. That means this node should
                # not have any children unless it's also the root.
                assert not node.children, "cycle in reference tree"
                root.children.remove(node)

    def apply(self) -> None:
        """
        Convert all indirect references to direct, clearing the cache.
        """
        for block, (start_refs, end_refs) in self._references.items():
            mi.consume(self._make_direct_refs(block, start_refs, False))
            mi.consume(self._make_direct_refs(block, end_refs, True))
        # _make_direct_refs() will have cleared the referents table already
        assert not self._referents
        self._references.clear()

    def set_referent(
        self,
        symbol: gtirb.Symbol,
        referent: Optional[gtirb.Block],
        at_end: bool,
    ) -> None:
        """
        Set the referent for a symbol.

        After this call, the symbol will have a direct referent.
        """
        if symbol in self._referents:
            ref = self._referents.pop(symbol)
            ref.symbols.remove(symbol)
        symbol.referent = referent
        symbol.at_end = at_end

    def get_referent(self, symbol: gtirb.Symbol) -> Optional[gtirb.Block]:
        """
        Get the referent for a symbol.

        After this call, the symbol will have a direct referent.
        """
        if symbol not in self._referents:
            return symbol.referent

        # We will make symbol into a direct reference, so we can remove it from
        # the referents table and from its RefNode's children.

        ref = self._referents.pop(symbol)
        ref.symbols.remove(symbol)

        # As we walk up to the root, we move the intermediate nodes closer so
        # future lookups have don't have to walk as far. Along the way, we can
        # also remove any nodes without children.

        parent = ref.parent
        while isinstance(parent, RefNode):
            grandparent = parent.parent
            if not ref.children and not ref.symbols:
                parent.children.remove(ref)
            elif isinstance(grandparent, RefNode):
                parent.children.remove(ref)
                grandparent.children.add(ref)
                ref.parent = grandparent
            ref, parent = parent, grandparent

        # Update the symbol and return the referent.

        symbol.referent = parent
        symbol.at_end = ref is self._references[parent][1]
        return parent


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
        reference_cache: ReferenceCache,
    ) -> None:
        self.module = module
        self.return_cache = return_cache
        self.reference_cache = reference_cache
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


@contextlib.contextmanager
def make_modify_cache(
    module: gtirb.Module, functions: Iterable[gtirb_functions.Function]
) -> Iterator[ModifyCache]:
    """Make a ModifyCache with a temporary ReturnCache and ReferenceCahe."""
    assert module.ir
    with make_return_cache(module.ir) as return_cache:
        with ReferenceCache() as reference_cache:
            yield ModifyCache(module, functions, return_cache, reference_cache)
