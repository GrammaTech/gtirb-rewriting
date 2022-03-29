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
import logging
import operator
import uuid
from typing import Container, Dict, Iterable, Iterator, Set

import gtirb
import gtirb_functions

from .assembler import Assembler
from .utils import (
    OffsetMapping,
    _block_fallthrough_targets,
    _get_function_blocks,
    _get_or_insert_aux_data,
    _is_call_edge,
    _is_fallthrough_edge,
    _is_return_edge,
)

logger = logging.getLogger(__name__)


class CFGModifiedError(RuntimeError):
    pass


class _ReturnEdgeCache(gtirb.CFG):
    """
    A CFG subclass that provides a cache for return edges and proxy return
    edges.
    """

    def __init__(self, edges=None) -> None:
        self._return_edges = collections.defaultdict(set)
        self._proxy_return_edges = collections.defaultdict(set)
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
    def _weak_cfg_hash(cfg):
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
    cache: _ModifyCache,
    module: gtirb.Module,
    func_uuid: uuid.UUID,
    return_target: gtirb.CodeBlock,
    new_cfg: gtirb.CFG,
) -> None:
    """
    Adds a new return edge to all returns in the function.
    """
    for block in _get_function_blocks(module, func_uuid):
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

    return_targets = set()
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
    if isinstance(call_edge.target, gtirb.ProxyBlock):
        return

    func_uuid = cache.functions_by_block.get(call_edge.target, None)
    if not func_uuid:
        return

    for block in _get_function_blocks(call_edge.target.module, func_uuid):
        return_edges = cache.return_cache.block_return_edges(block)
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
    if isinstance(call_edge.target, gtirb.ProxyBlock):
        return

    target_func_uuid = cache.functions_by_block.get(call_edge.target, None)
    if not target_func_uuid:
        return

    for target_block in _get_function_blocks(
        call_edge.target.module, target_func_uuid
    ):
        for edge in cache.return_cache.block_return_edges(target_block):
            if edge.target in fallthrough_targets:
                _update_edge(
                    edge, target_block.ir.cfg, new_cfg, target=new_fallthrough
                )


def _modify_block_insert(
    cache: _ModifyCache,
    block: gtirb.CodeBlock,
    offset: int,
    replacement_length: int,
    code: Assembler.Result,
) -> None:
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
    assert isinstance(text_section.blocks[-1], gtirb.DataBlock) or not any(
        code.cfg.out_edges(text_section.blocks[-1])
    ), "the last block cannot have outgoing cfg edges"

    bi = block.byte_interval
    assert bi

    module = block.module
    assert module

    _add_return_edges_for_patch_calls(
        cache,
        module,
        code.cfg,
    )
    _update_patch_return_edges_to_match(cache, block, code.cfg, code.proxies)

    # Adjust codeblock sizes, create CFG edges, remove 0-size blocks
    _modify_block_insert_cfg(cache, block, offset, replacement_length, code)

    size_delta = len(text_section.data) - replacement_length
    offset += block.offset

    # adjust byte interval the block goes in
    bi.size += size_delta
    bi.contents = (
        bi.contents[:offset]
        + text_section.data
        + bi.contents[offset + replacement_length :]
    )

    # adjust blocks that occur after the insertion point
    # TODO: what if blocks overlap over the insertion point?
    for b in bi.blocks:
        if b != block and b.offset >= offset:
            b.offset += size_delta

    # adjust all of the new blocks to be relative to the byte interval and
    # add them to the byte interval
    for b in text_section.blocks:
        b.offset += offset

    assert block.size and all(b.size for b in text_section.blocks), (
        "_modify_block_insert created a zero-sized block; please file a bug "
        "report against gtirb-rewriting"
    )
    bi.blocks.update(text_section.blocks)

    # adjust sym exprs that occur after the insertion point
    bi.symbolic_expressions = {
        (k + size_delta if k >= offset else k): v
        for k, v in bi.symbolic_expressions.items()
        if k < offset or k >= offset + replacement_length
    }

    # add all of the symbolic expressions from the code we're inserting
    for rel_offset, expr in text_section.symbolic_expressions.items():
        bi.symbolic_expressions[offset + rel_offset] = expr

    bi.ir.cfg.update(code.cfg)
    bi.module.symbols.update(code.symbols)
    bi.module.proxies.update(code.proxies)

    # Add new blocks to the functionBlocks aux data and our cache
    func_uuid = cache.functions_by_block.get(block)
    if func_uuid:
        if "functionBlocks" in module.aux_data:
            function_blocks = module.aux_data["functionBlocks"].data
            if func_uuid in function_blocks:
                function_blocks[func_uuid].update(
                    b
                    for b in text_section.blocks
                    if isinstance(b, gtirb.CodeBlock)
                )

        cache.functions_by_block.update(
            {
                b: func_uuid
                for b in text_section.blocks
                if isinstance(b, gtirb.CodeBlock)
            }
        )

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
    for rel_offset, size in text_section.symbolic_expression_sizes.items():
        sym_expr_sizes[gtirb.Offset(bi, offset + rel_offset)] = size

    for sect in code.sections.values():
        if sect is not code.text_section:
            _add_other_section_contents(code, sect, module, sym_expr_sizes)


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

    elif module.file_format == gtirb.Module.FileFormat.ELF:
        elf_section_properties = _get_or_insert_aux_data(
            module,
            "elfSectionProperties",
            "mapping<UUID,tuple<uint64_t,uint64_t>>",
            dict,
        )
        type, flags = elf_section_properties.get(gtirb_sect, (None, None))
        if type and type != patch_sect.elf_type:
            logger.warning(
                "ELF type for patch section %s (%s) do not match existing "
                "section ELF type (%s)",
                patch_sect.name,
                patch_sect.elf_type,
                type,
            )
        elif flags and flags != patch_sect.elf_flags:
            logger.warning(
                "ELF flags for patch section %s (%X) do not match existing "
                "section ELF flags (%X)",
                patch_sect.name,
                patch_sect.elf_flags,
                flags,
            )


def _add_other_section_contents(
    code: Assembler.Result,
    sect: Assembler.Result.Section,
    module: gtirb.Module,
    sym_expr_sizes: Dict[gtirb.Offset, int],
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

        if module.file_format == gtirb.Module.FileFormat.ELF:
            elf_section_properties = _get_or_insert_aux_data(
                module,
                "elfSectionProperties",
                "mapping<UUID,tuple<uint64_t,uint64_t>>",
                dict,
            )
            elf_section_properties[gtirb_sect] = (
                sect.elf_type,
                sect.elf_flags,
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


def _modify_block_insert_cfg(
    cache: _ModifyCache,
    block: gtirb.CodeBlock,
    offset: int,
    replacement_length: int,
    code: Assembler.Result,
) -> None:
    """
    Adjust codeblock sizes, create CFG edges, remove 0-size blocks.
    :param cache: The modify cache, which should be reused across multiple
                  modifications.
    :param block: The code block to insert into.
    :param offset: The byte offset into the code block.
    :param replacement_length: The number of bytes after `offset` that should
                               be removed.
    :param code: The assembled code to be inserted. It will be modified to
                 reflect what actually gets inserted in the binary.
    """

    bi = block.byte_interval
    text_section = code.text_section

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
        assert len(text_section.blocks) == 1
        assert isinstance(text_section.blocks[0], gtirb.CodeBlock)

        block.size = block.size - replacement_length + len(text_section.data)

        # Remove all the blocks from code.blocks so that they don't get added
        # to the byte_interval in _modify_block_insert.
        text_section.blocks.clear()
        return

    # If the patch ended in a data block, we need to create a new code block
    # that will contain any remaining code from the original block.
    if isinstance(text_section.blocks[-1], gtirb.DataBlock):
        assert text_section.blocks[-1].size
        text_section.blocks.append(
            gtirb.CodeBlock(offset=len(text_section.data))
        )

    # Adjust the target block to be the size of offset. Then extend the last
    # patch block to cover the remaining bytes in the original block.
    block.size = offset
    text_section.blocks[-1].size += original_size - offset - replacement_length

    # Now add a fallthrough edge from the original block to the first patch
    # block, unless we're inserting at the end of the block and the block has
    # no fallthrough edges. For example, inserting after a ret instruction.
    if not inserts_at_end or any(_block_fallthrough_targets(block)):
        assert isinstance(text_section.blocks[0], gtirb.CodeBlock)
        added_fallthrough = gtirb.Edge(
            source=block,
            target=text_section.blocks[0],
            label=gtirb.Edge.Label(type=gtirb.Edge.Type.Fallthrough),
        )
        code.cfg.add(added_fallthrough)

    # Alter any outgoing edges from the original block to originate from the
    # last patch block.
    if inserts_at_end:
        fallthrough_targets = _block_fallthrough_targets(block)

        for edge in set(block.outgoing_edges):
            if _is_fallthrough_edge(edge):
                _update_edge(
                    edge, bi.ir.cfg, code.cfg, source=text_section.blocks[-1]
                )
            elif _is_call_edge(edge):
                _update_return_edges_from_changing_fallthrough(
                    cache,
                    edge,
                    fallthrough_targets,
                    text_section.blocks[0],
                    code.cfg,
                )
    elif replaces_last_instruction:
        fallthrough_targets = _block_fallthrough_targets(block)

        for edge in set(block.outgoing_edges):
            if _is_fallthrough_edge(edge):
                _update_edge(
                    edge, bi.ir.cfg, code.cfg, source=text_section.blocks[-1]
                )
            elif _is_call_edge(edge):
                _update_return_edges_from_removing_call(
                    cache, edge, fallthrough_targets, code.cfg
                )
                bi.ir.cfg.discard(edge)
            else:
                bi.ir.cfg.discard(edge)
    else:
        for edge in set(block.outgoing_edges):
            _update_edge(
                edge, bi.ir.cfg, code.cfg, source=text_section.blocks[-1]
            )

    # Now go back and clean up any zero-sized blocks, which trigger
    # nondeterministic behavior in the pretty printer.
    if block.size == 0:
        code.cfg.discard(added_fallthrough)

        block.size = text_section.blocks[0].size
        _substitute_block(
            text_section.blocks[0],
            block,
            code.cfg,
            code.symbols,
        )
        del text_section.blocks[0]

    if text_section.blocks and text_section.blocks[-1].size == 0:
        has_symbols = any(
            sym.referent == text_section.blocks[-1] for sym in code.symbols
        )
        has_incoming_edges = any(code.cfg.in_edges(text_section.blocks[-1]))
        fallthrough_edges = [
            edge
            for edge in code.cfg.out_edges(text_section.blocks[-1])
            if _is_fallthrough_edge(edge)
        ]

        if not has_symbols and not has_incoming_edges:
            # If nothing refers to the block, we can simply drop it and any
            # outgoing edges that may have been added to it from the earlier
            # steps.
            for out_edge in set(code.cfg.out_edges(text_section.blocks[-1])):
                code.cfg.discard(out_edge)
            del text_section.blocks[-1]
        elif len(fallthrough_edges) == 1:
            # If we know where the "next" block is, substitute that for our
            # last block. Because the block is empty, there should be no
            # outgoing edges from it except for the fallthrough edge (which
            # we will delete).
            code.cfg.discard(fallthrough_edges[0])
            assert not any(code.cfg.out_edges(text_section.blocks[-1]))

            _substitute_block(
                text_section.blocks[-1],
                fallthrough_edges[0].target,
                code.cfg,
                code.symbols,
            )
            del text_section.blocks[-1]
        else:
            # We don't know where control flow goes after our patch, so we'll
            # raise an exception for now. There are other ways of resolving
            # this that we could explore (e.g. insert a nop at the end of the
            # inserted bytes to make it be a non-zero block).
            raise NotImplementedError(
                "Attempting to insert a block at the end of another "
                "block without knowing how to update control flow"
            )
