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
from typing import Iterable, Iterator, List, Optional, Sequence, Set

import capstone_gt
import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder

import gtirb_rewriting._auxdata as _auxdata


def _target_triple(
    isa: gtirb.Module.ISA, file_format: gtirb.Module.FileFormat
) -> str:
    """
    Generate the appropriate LLVM target triple.
    """

    if isa == gtirb.Module.ISA.X64:
        arch = "x86_64"
    elif isa == gtirb.Module.ISA.IA32:
        arch = "i386"
    elif isa == gtirb.Module.ISA.ARM:
        arch = "arm"
    elif isa == gtirb.Module.ISA.ARM64:
        arch = "arm64"
    else:
        assert False, f"Unsupported ISA: {isa}"

    if file_format == gtirb.Module.FileFormat.ELF:
        vendor = "pc"
        os = "linux"
    elif file_format == gtirb.Module.FileFormat.PE:
        vendor = "pc"
        os = "win32"
    else:
        assert False, f"Unsupported file format: {file_format}"

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
    if all(_is_fallthrough_edge(edge) for edge in block.outgoing_edges):
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
    arch: Optional[gtirb.Module.ISA] = None,
    logger=logging.getLogger(),
    decoder=None,
) -> None:
    """
    Disassemble and print the contents of a code block using the given
    architecture. If no architecture is given, it is taken from the block's
    module. If the block is not in a module, the function throws an error.
    """

    # blocks only have contents when they are in a byte interval
    if block.byte_interval is None:
        raise ValueError("block must be in a byte interval")

    if not block.contents:
        logger.debug("\t<empty block>")
        return

    if decoder is None:
        if arch is None:
            if block.module is None:
                raise ValueError("Undefined architecture")
            arch = block.module.isa
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
        block_address = block.address or 0
        for offset, byte in enumerate(block.contents):
            logger.debug("\t0x%x:\t.byte\t%i", block_address + offset, byte)
            expr = block.byte_interval.symbolic_expressions.get(
                block.offset, None
            )
            if expr:
                logger.debug("\t# +0: %s", _format_symbolic_expr(expr))


def _is_fallthrough_edge(edge: gtirb.Edge) -> bool:
    """Determines if an edge is a fall-through edge."""
    return (
        edge.label is not None
        and edge.label.type == gtirb.Edge.Type.Fallthrough
    )


def _is_return_edge(edge: gtirb.Edge) -> bool:
    return edge.label is not None and edge.label.type == gtirb.Edge.Type.Return


def _is_call_edge(edge: gtirb.Edge) -> bool:
    return edge.label is not None and edge.label.type == gtirb.Edge.Type.Call


def _block_fallthrough_targets(block: gtirb.CodeBlock) -> Set[gtirb.CodeBlock]:
    return {
        edge.target
        for edge in block.outgoing_edges
        if _is_fallthrough_edge(edge)
        and isinstance(edge.target, gtirb.CodeBlock)
    }


def _get_function_blocks(
    module: gtirb.Module, func_uuid: uuid.UUID
) -> Set[gtirb.CodeBlock]:
    """
    Gets all blocks associated with a function.
    """
    function_blocks = _auxdata.function_blocks.get(module)
    if function_blocks is not None:
        return function_blocks[func_uuid]
    else:
        return set()


def _is_elf_pie(
    file_format: gtirb.Module.FileFormat, binary_type: List[str]
) -> bool:
    return file_format == gtirb.Module.FileFormat.ELF and "DYN" in binary_type


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
