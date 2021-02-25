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
import logging
import uuid
from typing import (
    Container,
    Dict,
    Iterable,
    Iterator,
    List,
    Mapping,
    MutableMapping,
    Sequence,
    Set,
    TypeVar,
    Union,
    overload,
)

import capstone
import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder

T = TypeVar("T")


class OffsetMapping(MutableMapping[gtirb.Offset, T]):
    """Mapping that allows looking up groups of items by their offset element.

    The keys in this mapping are required to be Offsets. If a non-Offset is
    used as a key, it is assumed to be the element_id of an Offset. In that
    case, the corresponding element is a MutableMapping[int, T] of
    displacements to values for every Offset that has the given element_id. For
    example,
        m = OffsetMapping[str]()
        m[Offset(x, 0)] = "a"     # insert an offset into the map
        m[x] = {1: "b", 2: "c"}   # insert two offsets into the map
        m[x][0] = "d"             # change the value for Offset(x, 0)
        print(m[Offset(x, 1)])    # get the value for Offset(x, 1)
        del m[Offset(x, 2)]       # delete Offset(x, 2) from the map
    """

    def __init__(self, *args, **kw):
        """Create a new OffsetMapping from an iterable and/or keywords."""
        self._data = {}
        self.update(*args, **kw)

    def __len__(self) -> int:
        """Get the number of Offsets stored in this mapping."""
        return sum(len(subdata) for subdata in self._data.values())

    def __iter__(self) -> Iterator[gtirb.Offset]:
        """"Yield the Offsets in this mapping."""
        for elem, subdata in self._data.items():
            for disp in subdata:
                yield gtirb.Offset(elem, disp)

    @overload
    def __getitem__(self, key: gtirb.Offset) -> T:
        ...

    @overload
    def __getitem__(self, key: gtirb.Node) -> MutableMapping[int, T]:
        ...

    def __getitem__(self, key):
        """Get the value for an Offset or dictionary for an element_id."""
        if isinstance(key, gtirb.Offset):
            elem, disp = key
            if elem in self._data and disp in self._data[elem]:
                return self._data[elem][disp]
        return self._data[key]

    @overload
    def __setitem__(self, key: gtirb.Offset, value: T) -> None:
        ...

    @overload
    def __setitem__(self, key: gtirb.Node, value: Mapping[int, T]) -> None:
        ...

    def __setitem__(self, key, value):
        """Set the value for an Offset, or several Offsets given an element."""
        if isinstance(key, gtirb.Offset):
            elem, disp = key
            if elem not in self._data:
                self._data[elem] = {}
            self._data[elem][disp] = value
        elif not isinstance(value, Mapping):
            raise ValueError("not a mapping: %r" % value)
        else:
            self._data.setdefault(key, {}).update(value)

    def __delitem__(self, key: Union[gtirb.Offset, gtirb.Node]) -> None:
        """Delete the mapping for an Offset or all Offsets given an element."""
        if isinstance(key, gtirb.Offset):
            elem, disp = key
            if elem not in self._data or disp not in self._data[elem]:
                raise KeyError(key)
            del self._data[elem][disp]
        else:
            del self._data[key]


def _target_triple(module: gtirb.Module) -> str:
    """
    Generate the appropriate LLVM target triple for a GTIRB Module.
    """

    if module.isa == gtirb.Module.ISA.X64:
        arch = "x86_64"
    elif module.isa == gtirb.Module.ISA.IA32:
        arch = "i386"
    elif module.isa == gtirb.Module.ISA.ARM:
        arch = "arm"
    elif module.isa == gtirb.Module.ISA.ARM64:
        arch = "arm64"
    else:
        assert False, f"Unsupported ISA: {module.isa}"

    if module.file_format == gtirb.Module.FileFormat.ELF:
        vendor = "pc"
        os = "linux"
    elif module.file_format == gtirb.Module.FileFormat.PE:
        vendor = "pc"
        os = "win32"
    else:
        assert False, f"Unsupported file format: {module.file_format}"

    return f"{arch}-{vendor}-{os}"


def _is_partial_disassembly(
    block: gtirb.CodeBlock, disassembly: Iterable[capstone.CsInsn]
) -> bool:
    """
    Determines if disassembly of a block is complete or only partial, which
    can happen when capstone is unable to disassemble an instruction.
    """
    return sum(inst.size for inst in disassembly) != block.size


def _nonterminator_instructions(
    block: gtirb.CodeBlock, disassembly: Sequence[capstone.CsInsn]
) -> Iterator[capstone.CsInsn]:
    """
    Yields all instructions in a block of diassembly except for the terminator,
    if present.
    """
    if all(
        edge.label.type == gtirb.Edge.Type.Fallthrough
        for edge in block.outgoing_edges
    ):
        yield from disassembly
    else:
        yield from disassembly[:-1]


def show_block_asm(
    block: gtirb.CodeBlock,
    arch: gtirb.Module.ISA = None,
    logger=logging.getLogger(),
    decoder=None,
) -> None:
    """
    Disassemble and print the contents of a code block using the given
    architecture. If no architecture is given, it is taken from the block's
    module. If the block is not in a module, the function throws an error.
    """

    if decoder is None:
        if arch is None:
            if block.module is None:
                raise ValueError("Undefined architecture")
            arch = block.byte_interval.section.module.isa
        decoder = GtirbInstructionDecoder(arch)

    if block.contents:
        instructions = tuple(decoder.get_instructions(block))
        for i in instructions:
            logger.debug("\t0x%x:\t%s\t%s", i.address, i.mnemonic, i.op_str)
        if _is_partial_disassembly(block, instructions):
            logger.debug("\t<incomplete disassembly>")


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
        cfg.discard(edge)
        cfg.add(edge._replace(target=new_block))

    for edge in set(cfg.out_edges(old_block)):
        cfg.discard(edge)
        cfg.add(edge._replace(source=new_block))

    for sym in symbols:
        if sym.referent == old_block:
            sym.referent = new_block


def _is_fallthrough_edge(edge: gtirb.Edge) -> bool:
    """Determines if an edge is a fall-through edge."""
    return edge.label and edge.label.type == gtirb.Edge.Type.Fallthrough


def _is_return_edge(edge: gtirb.Edge) -> bool:
    return edge.label and edge.label.type == gtirb.Edge.Type.Return


def _is_call_edge(edge: gtirb.Edge) -> bool:
    return edge.label and edge.label.type == gtirb.Edge.Type.Call


def _block_return_edges(block: gtirb.CodeBlock) -> Set[gtirb.Edge]:
    return {edge for edge in block.outgoing_edges if _is_return_edge(edge)}


def _block_fallthrough_targets(block: gtirb.CodeBlock) -> Set[gtirb.CodeBlock]:
    return {
        edge.target
        for edge in block.outgoing_edges
        if _is_fallthrough_edge(edge)
    }


def _get_function_blocks(
    module: gtirb.Module, func_uuid: uuid.UUID
) -> Set[gtirb.CodeBlock]:
    """
    Gets all blocks associated with a function.
    """
    if "functionBlocks" in module.aux_data:
        return module.aux_data["functionBlocks"].data[func_uuid]
    else:
        return set()


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
    for call_edge in call_edges:
        func_uuid = functions_by_block.get(call_edge.target, None)
        if not func_uuid:
            continue

        fallthrough_targets = [
            edge.target
            for edge in new_cfg
            if edge.source == call_edge.source and _is_fallthrough_edge(edge)
        ]
        if not fallthrough_targets:
            continue

        # Because the assembler is generating this input, we can assert that
        # there's only the single fallthrough target.
        assert len(fallthrough_targets) == 1
        _add_return_edges_to_one_function(
            module, func_uuid, fallthrough_targets[0], new_cfg
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

    patch_return_edges = {edge for edge in new_cfg if _is_return_edge(edge)}
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
                target_block.ir.cfg.discard(edge)
                new_cfg.add(edge._replace(target=new_fallthrough))


def _modify_block_insert(
    block: gtirb.CodeBlock,
    offset: int,
    replacement_length: int,
    new_bytes: bytes,
    new_blocks: List[gtirb.CodeBlock],
    new_cfg: gtirb.CFG,
    new_symbolic_expressions: Dict[int, gtirb.SymbolicExpression],
    new_symbols: Iterable[gtirb.Symbol],
    new_proxy_blocks: Set[gtirb.ProxyBlock],
    functions_by_block: Dict[gtirb.CodeBlock, uuid.UUID],
) -> None:
    """
    Insert bytes into a block and adjusts the IR as needed.
    :param block: The code block to insert into.
    :param offset: The byte offset into the code block.
    :param replacement_length: The number of bytes after `offset` that should
                               be removed.
    :param new_bytes: The new content to be inserted.
    :param new_blocks: The blocks corresponding to the new content.
    :param new_cfg: The CFG corresponding to the new content.
    :param new_symbolic_expressions: The symbolic expressions corresponding to
                                     the new content, with the keys relative
                                     to the start of `new_bytes`.
    :param new_symbols: Any symbols that may be defined in the new content.
    :param new_proxy_blocks: All proxy blocks used by the new content.
    :param functions_by_block: Map from code block to containing function UUID.
    """

    assert block.size
    assert 0 <= offset <= block.size
    assert 0 <= offset + replacement_length <= block.size
    assert replacement_length >= 0
    assert new_bytes
    assert new_blocks
    assert block not in new_blocks
    assert new_blocks[0].size, "must have at least one non-empty block"
    assert all(
        new_block.size for new_block in new_blocks[:-1]
    ), "only the last block may be empty"
    assert not any(
        new_cfg.out_edges(new_blocks[-1])
    ), "the last block cannot have outgoing cfg edges"

    bi = block.byte_interval
    assert bi

    _add_return_edges_for_patch_calls(
        block.module, functions_by_block, new_cfg
    )
    _update_patch_return_edges_to_match(
        block, functions_by_block, new_cfg, new_proxy_blocks
    )

    # Adjust codeblock sizes, create CFG edges, remove 0-size blocks
    _modify_block_insert_cfg(
        block,
        offset,
        replacement_length,
        new_bytes,
        new_blocks,
        new_cfg,
        new_symbolic_expressions,
        new_symbols,
        functions_by_block,
    )

    size_delta = len(new_bytes) - replacement_length
    offset += block.offset

    # adjust byte interval the block goes in
    bi.size += size_delta
    bi.contents = (
        bi.contents[:offset]
        + new_bytes
        + bi.contents[offset + replacement_length :]
    )

    # adjust blocks that occur after the insertion point
    # TODO: what if blocks overlap over the insertion point?
    for b in bi.blocks:
        if b != block and b.offset >= offset:
            b.offset += size_delta

    # adjust all of the new blocks to be relative to the byte interval and
    # add them to the byte interval
    for b in new_blocks:
        b.offset += offset

    assert block.size and all(b.size for b in new_blocks), (
        "_modify_block_insert created a zero-sized block; please file a bug "
        "report against gtirb-rewriting"
    )
    bi.blocks.update(new_blocks)

    # adjust sym exprs that occur after the insertion point
    bi.symbolic_expressions = {
        (k + size_delta if k >= offset else k): v
        for k, v in bi.symbolic_expressions.items()
        if k < offset or k >= offset + replacement_length
    }

    # add all of the symbolic expressions from the code we're inserting
    for rel_offset, expr in new_symbolic_expressions.items():
        bi.symbolic_expressions[offset + rel_offset] = expr

    bi.ir.cfg.update(new_cfg)
    bi.module.symbols.update(new_symbols)
    bi.module.proxies.update(new_proxy_blocks)

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


def _modify_block_insert_cfg(
    block: gtirb.CodeBlock,
    offset: int,
    replacement_length: int,
    new_bytes: bytes,
    new_blocks: List[gtirb.CodeBlock],
    new_cfg: gtirb.CFG,
    new_symbolic_expressions: Dict[int, gtirb.SymbolicExpression],
    new_symbols: Iterable[gtirb.Symbol],
    functions_by_block: Dict[gtirb.CodeBlock, uuid.UUID],
) -> None:
    """
    Adjust codeblock sizes, create CFG edges, remove 0-size blocks.
    :param block: The code block to insert into.
    :param offset: The byte offset into the code block.
    :param replacement_length: The number of bytes after `offset` that should
                               be removed.
    :param new_bytes: The new content to be inserted.
    :param new_blocks: The blocks corresponding to the new content.
    :param new_cfg: The CFG corresponding to the new content.
    :param new_symbolic_expressions: The symbolic expressions corresponding to
                                     the new content, with the keys relative
                                     to the start of `new_bytes`.
    :param new_symbols: Any symbols that may be defined in the new content.
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
        not new_cfg
        and not new_symbols
        and not inserts_at_end
        and not replaces_last_instruction
    ):
        block.size = block.size - replacement_length + len(new_bytes)

        # Remove all the blocks from new_blocks so that they don't get added
        # to the byte_interval in _modify_block_insert.
        new_blocks.clear()
        return

    # Adjust the target block to be the size of offset. Then extend the last
    # patch block to cover the remaining bytes in the original block.
    block.size = offset
    new_blocks[-1].size += original_size - offset - replacement_length

    # Now add a fallthrough edge from the original block to the first patch
    # block, unless we're inserting at the end of the block and the block has
    # no fallthrough edges. For example, inserting after a ret instruction.
    if not inserts_at_end or any(_block_fallthrough_targets(block)):
        new_cfg.add(
            gtirb.Edge(
                source=block,
                target=new_blocks[0],
                label=gtirb.Edge.Label(type=gtirb.Edge.Type.Fallthrough),
            )
        )

    # Alter any outgoing edges from the original block to originate from the
    # last patch block.
    if inserts_at_end:
        fallthrough_targets = _block_fallthrough_targets(block)

        for edge in set(block.outgoing_edges):
            if _is_fallthrough_edge(edge):
                bi.ir.cfg.discard(edge)
                new_cfg.add(edge._replace(source=new_blocks[-1]))
            elif _is_call_edge(edge):
                _update_return_edges_from_changing_fallthrough(
                    edge,
                    fallthrough_targets,
                    functions_by_block,
                    new_blocks[-1],
                    new_cfg,
                )
    elif replaces_last_instruction:
        fallthrough_targets = _block_fallthrough_targets(block)

        for edge in set(block.outgoing_edges):
            if _is_fallthrough_edge(edge):
                bi.ir.cfg.discard(edge)
                new_cfg.add(edge._replace(source=new_blocks[-1]))
            elif _is_call_edge(edge):
                _update_return_edges_from_removing_call(
                    edge, fallthrough_targets, functions_by_block, new_cfg
                )
                bi.ir.cfg.discard(edge)
            else:
                bi.ir.cfg.discard(edge)
    else:
        for edge in set(block.outgoing_edges):
            bi.ir.cfg.discard(edge)
            new_cfg.add(edge._replace(source=new_blocks[-1]))

    # Now go back and clean up any zero-sized blocks, which trigger
    # nondeterministic behavior in the pretty printer.
    if block.size == 0:
        added_fallthrough = next(
            edge
            for edge in new_cfg.in_edges(new_blocks[0])
            if _is_fallthrough_edge(edge) and edge.source == block
        )
        new_cfg.discard(added_fallthrough)

        block.size = new_blocks[0].size
        _substitute_block(
            new_blocks[0], block, new_cfg, new_symbols,
        )
        del new_blocks[0]

    if new_blocks and new_blocks[-1].size == 0:
        has_symbols = any(
            sym.referent == new_blocks[-1] for sym in new_symbols
        )
        has_incoming_edges = any(new_cfg.in_edges(new_blocks[-1]))
        fallthrough_edges = [
            edge
            for edge in new_cfg.out_edges(new_blocks[-1])
            if _is_fallthrough_edge(edge)
        ]

        if not has_symbols and not has_incoming_edges:
            # If nothing refers to the block, we can simply drop it and any
            # outgoing edges that may have been added to it from the earlier
            # steps.
            for out_edge in set(new_cfg.out_edges(new_blocks[-1])):
                new_cfg.discard(out_edge)
            del new_blocks[-1]
        elif len(fallthrough_edges) == 1:
            # If we know where the "next" block is, substitute that for our
            # last block.
            _substitute_block(
                new_blocks[-1],
                fallthrough_edges[0].target,
                new_cfg,
                new_symbols,
            )
            del new_blocks[-1]
        else:
            # We don't know where control flow goes after our patch, so we'll
            # raise an exception for now. There are other ways of resolving
            # this that we could explore (e.g. insert a nop at the end of the
            # inserted bytes to make it be a non-zero block).
            raise NotImplementedError(
                "Attempting to insert a block at the end of another "
                "block without knowing how to update control flow"
            )


def _is_elf_pie(module: gtirb.Module) -> bool:
    return (
        module.file_format == gtirb.Module.FileFormat.ELF
        and "DYN" in module.aux_data["binaryType"].data
    )


def _text_section_name(module: gtirb.Module):
    if module.file_format == gtirb.Module.FileFormat.ELF:
        return ".text"
    elif module.file_format == gtirb.Module.FileFormat.PE:
        return ".text"
    else:
        assert False, f"unsupported file format: {module.file_format}"


def decorate_extern_symbol(module: gtirb.Module, sym: str) -> str:
    """
    Decorates a symbol as needed for the target. For example, this might
    involve adding a leading underscore on some platforms.
    """
    # TODO: 32-bit Windows uses a leading underscore. So does Mach-O.
    return sym


def effective_alignment(address: int, max_alignment: int = 8) -> int:
    """Return the largest power of two to which an address is aligned."""
    return (~address & (address - 1) & (max_alignment - 1)) + 1


def align_address(address: int, alignment: int) -> int:
    """Increase an address to the next alignment boundary, if necessary."""
    return (address + alignment - 1) & -alignment
