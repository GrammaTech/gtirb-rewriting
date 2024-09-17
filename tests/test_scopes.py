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
import re
import unittest.mock

import capstone_gt
import gtirb
import gtirb_functions
from gtirb_test_helpers import (
    add_code_block,
    add_data_section,
    add_text_section,
    create_test_module,
)
from helpers import add_function_object

import gtirb_rewriting


def test_all_block_scope_entry():
    ir, mod = create_test_module(
        file_format=gtirb.Module.FileFormat.ELF,
        isa=gtirb.Module.ISA.X64,
    )
    _, bi = add_text_section(mod, address=0x1000)
    # xor %eax, %eax; xor %ecx, %ecx
    block = add_code_block(bi, b"\x31\xC0\x31\xC9")
    func = add_function_object(mod, "func", block)

    scope = gtirb_rewriting.AllBlocksScope(
        position=gtirb_rewriting.BlockPosition.ENTRY
    )
    assert scope._known_targets() is None
    assert not scope._needs_disassembly()
    assert scope._block_matches(mod, func, block)
    offsets = list(scope._potential_offsets(block, None))
    assert offsets == [0]


def test_all_block_scope_anywhere():
    ir, mod = create_test_module(
        file_format=gtirb.Module.FileFormat.ELF,
        isa=gtirb.Module.ISA.X64,
    )
    _, bi = add_text_section(mod, address=0x1000)
    # xor %eax, %eax; xor %ecx, %ecx
    block = add_code_block(bi, b"\x31\xC0\x31\xC9")
    func = add_function_object(mod, "func", block)

    cs = capstone_gt.Cs(capstone_gt.CS_ARCH_X86, capstone_gt.CS_MODE_64)
    disasm = tuple(cs.disasm(block.contents, 0))

    func = unittest.mock.MagicMock(spec=gtirb_functions.Function)

    scope = gtirb_rewriting.AllBlocksScope(
        position=gtirb_rewriting.BlockPosition.ANYWHERE
    )
    assert scope._known_targets() is None
    assert scope._needs_disassembly()
    assert scope._block_matches(mod, func, block)
    offsets = list(scope._potential_offsets(block, disasm))
    assert offsets == [0, 2, 4]


def test_all_block_scope_exit():
    ir, mod = create_test_module(
        file_format=gtirb.Module.FileFormat.ELF,
        isa=gtirb.Module.ISA.X64,
    )
    _, bi = add_text_section(mod, address=0x1000)
    # xor %eax, %eax; xor %ecx, %ecx
    block = add_code_block(bi, b"\x31\xC0\x31\xC9")
    func = add_function_object(mod, "func", block)

    cs = capstone_gt.Cs(capstone_gt.CS_ARCH_X86, capstone_gt.CS_MODE_64)
    disasm = tuple(cs.disasm(block.contents, 0))

    func = unittest.mock.MagicMock(spec=gtirb_functions.Function)
    func.get_name.return_value = "foo"

    scope = gtirb_rewriting.AllBlocksScope(
        position=gtirb_rewriting.BlockPosition.EXIT
    )
    assert scope._known_targets() is None
    assert scope._needs_disassembly()
    assert scope._block_matches(mod, func, block)
    offsets = list(scope._potential_offsets(block, disasm))
    assert offsets == [4]


def test_all_block_scope_sections():
    ir, mod = create_test_module(
        file_format=gtirb.Module.FileFormat.ELF,
        isa=gtirb.Module.ISA.X64,
    )
    _, bi = add_data_section(mod, address=0x1000)
    # xor %eax, %eax; xor %ecx, %ecx
    block = add_code_block(bi, b"\x31\xC0\x31\xC9")

    # The block isn't in the .text section or in a function, but should still
    # match because it's a code block.
    scope = gtirb_rewriting.AllBlocksScope(
        position=gtirb_rewriting.BlockPosition.ENTRY
    )
    assert scope._block_matches(mod, None, block)


def test_single_block_scope():
    ir, mod = create_test_module(
        file_format=gtirb.Module.FileFormat.ELF,
        isa=gtirb.Module.ISA.X64,
    )
    _, bi = add_data_section(mod, address=0x1000)
    block = add_code_block(bi, b"\x90")
    block2 = add_code_block(bi, b"\x90")
    func = add_function_object(mod, "func", block, {block2})

    scope = gtirb_rewriting.SingleBlockScope(
        block, gtirb_rewriting.BlockPosition.ENTRY
    )
    assert scope._known_targets() == {block}
    assert not scope._needs_disassembly()
    assert scope._block_matches(mod, func, block)
    assert not scope._block_matches(mod, func, block2)
    offsets = list(scope._potential_offsets(block, None))
    assert offsets == [0]


def test_pattern_match():
    ir, mod = create_test_module(
        file_format=gtirb.Module.FileFormat.ELF,
        isa=gtirb.Module.ISA.X64,
    )
    _, bi = add_data_section(mod, address=0x1000)
    block = add_code_block(bi, b"\x90")
    func = add_function_object(mod, "foo", block)

    assert not gtirb_rewriting.pattern_match(mod, func, set())
    assert gtirb_rewriting.pattern_match(mod, func, {"foo"})
    assert gtirb_rewriting.pattern_match(mod, func, {re.compile("f..")})
    # Verify that only complete regex matches are considered
    assert not gtirb_rewriting.pattern_match(mod, func, {re.compile("f")})
