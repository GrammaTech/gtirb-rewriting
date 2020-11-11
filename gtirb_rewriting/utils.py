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
from typing import Iterator, Sequence

import capstone
import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder


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
) -> None:
    """
    Disassemble and print the contents of a code block using the given
    architecture. If no architecture is given, it is taken from the block's
    module. If the block is not in a module, the function throws an error.
    """

    if arch is None:
        if (
            block.byte_interval is not None
            and block.byte_interval.section is not None
            and block.byte_interval.section.module is not None
        ):
            arch = block.byte_interval.section.module.isa
    if arch is None:
        raise ValueError("Undefined architecture")

    for i in GtirbInstructionDecoder(arch).get_instructions(block):
        logger.debug("\t0x%x:\t%s\t%s", i.address, i.mnemonic, i.op_str)


def _modify_block_insert(
    block: gtirb.CodeBlock, new_bytes: bytes, offset: int
) -> None:
    """
    Insert bytes into a block and adjusts the IR as needed.
    """

    offset += block.offset

    n_bytes = len(new_bytes)
    bi = block.byte_interval
    assert bi

    # adjust block itself
    block.size += n_bytes

    # adjust byte interval the block goes in
    bi.size += n_bytes
    bi.contents = bi.contents[:offset] + new_bytes + bi.contents[offset:]

    # adjust blocks that occur after the insertion point
    # TODO: what if blocks overlap over the insertion point?
    for b in bi.blocks:
        if b != block and b.offset >= offset:
            b.offset += n_bytes

    # adjust sym exprs that occur after the insertion point
    bi.symbolic_expressions = {
        (k + n_bytes if k >= offset else k): v
        for k, v in bi.symbolic_expressions.items()
    }

    # adjust aux data if present
    def update_aux_data_keyed_by_offset(name):
        table = bi.module.aux_data.get(name)
        if table:
            table.data = {
                (
                    gtirb.Offset(bi, k.displacement + n_bytes)
                    if k.element_id == bi and k.displacement >= offset
                    else k
                ): v
                for k, v in table.data.items()
            }

    # TODO: It seems like we _could_ detect any aux data table that is a
    #       mapping using Offset as keys if gtirb.Serialization._parse_type
    #       were public.
    update_aux_data_keyed_by_offset("comments")
    update_aux_data_keyed_by_offset("padding")
    update_aux_data_keyed_by_offset("symbolicExpressionSizes")


def _is_elf_pie(module: gtirb.Module) -> bool:
    return (
        module.file_format == gtirb.Module.FileFormat.ELF
        and "DYN" in module.aux_data["binaryType"].data
    )


def decorate_extern_symbol(module: gtirb.Module, sym: str) -> str:
    """
    Decorates a symbol as needed for the target. For example, this might
    involve adding '@PLT' for position independent ELF executables.
    """
    # TODO: 32-bit Windows uses a leading underscore. So does Mach-O.
    if _is_elf_pie(module):
        return sym + "@PLT"
    return sym
