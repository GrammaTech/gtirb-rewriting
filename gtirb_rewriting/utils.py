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
import functools
import logging
import uuid
from typing import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    Sequence,
    Set,
    Type,
    TypeVar,
    Union,
    overload,
)

import capstone_gt
import gtirb
import packaging.version
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
    block: gtirb.CodeBlock, disassembly: Iterable[capstone_gt.CsInsn]
) -> bool:
    """
    Determines if disassembly of a block is complete or only partial, which
    can happen when capstone_gt is unable to disassemble an instruction.
    """
    return sum(inst.size for inst in disassembly) != block.size


def _nonterminator_instructions(
    block: gtirb.CodeBlock, disassembly: Sequence[capstone_gt.CsInsn]
) -> Iterator[capstone_gt.CsInsn]:
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


def _format_symbolic_expr(expr) -> str:
    if isinstance(expr, gtirb.SymAddrConst):
        result = f"SymAddrConst: {expr.symbol.name} + {expr.offset}"
    elif isinstance(expr, gtirb.SymAddrAddr):
        result = (
            f"SymAddrAddr: ({expr.symbol1.name} - {expr.symbol2.name}) "
            f"/ {expr.scale} + {expr.offset}"
        )
    else:
        result = str(expr)

    if expr.attributes:
        result += " " + str(expr.attributes)

    return result


def show_block_asm(
    block: gtirb.ByteBlock,
    arch: gtirb.Module.ISA = None,
    logger=logging.getLogger(),
    decoder=None,
) -> None:
    """
    Disassemble and print the contents of a code block using the given
    architecture. If no architecture is given, it is taken from the block's
    module. If the block is not in a module, the function throws an error.
    """

    if not block.contents:
        logger.debug("\t<empty block>")
        return

    if decoder is None:
        if arch is None:
            if block.module is None:
                raise ValueError("Undefined architecture")
            arch = block.byte_interval.section.module.isa
        decoder = GtirbInstructionDecoder(arch)

    if isinstance(block, gtirb.CodeBlock):
        offset = block.offset
        instructions = tuple(decoder.get_instructions(block))
        for i in instructions:
            logger.debug("\t0x%x:\t%s\t%s", i.address, i.mnemonic, i.op_str)
            # Print out the symbolic expression for the instruction, if any
            for expr_offset in range(i.size):
                expr = block.byte_interval.symbolic_expressions.get(
                    offset + expr_offset, None
                )
                if expr:
                    logger.debug(
                        "\t# +%i: %s",
                        expr_offset,
                        _format_symbolic_expr(expr),
                    )
            offset += i.size
        if _is_partial_disassembly(block, instructions):
            logger.debug("\t<incomplete disassembly>")

    elif isinstance(block, gtirb.DataBlock):
        for offset, byte in enumerate(block.contents):
            logger.debug("\t0x%x:\t.byte\t%i", block.address + offset, byte)
            expr = block.byte_interval.symbolic_expressions.get(
                block.offset, None
            )
            if expr:
                logger.debug("\t# +0: %s", _format_symbolic_expr(expr))


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


def _get_or_insert_aux_data(
    m: gtirb.Module, name: str, type_name: str, data_type: Type[T]
) -> T:
    """
    Gets an aux data table from a module, creating it if it does not already
    exist.
    """
    table = m.aux_data.get(name)
    if table:
        assert (
            table.type_name == type_name
        ), "existing aux data is not the right type"
        return table.data

    table = gtirb.AuxData(data_type(), type_name)
    m.aux_data[name] = table
    return table.data


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


@functools.lru_cache(maxsize=None)
def is_gtirb_at_least_version(version: str):
    """
    Determines if the version of gtirb installed is at least a given version.
    """
    return packaging.version.Version(
        gtirb.__version__
    ) >= packaging.version.Version(version)
