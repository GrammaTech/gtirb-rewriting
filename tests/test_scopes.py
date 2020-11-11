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

import capstone
import gtirb
import gtirb_functions
import gtirb_rewriting
import gtirb_rewriting.scopes


def test_all_block_scope_entry():
    mod = unittest.mock.MagicMock(spec=gtirb.Module)
    block = unittest.mock.MagicMock(spec=gtirb.CodeBlock)
    func = unittest.mock.MagicMock(spec=gtirb_functions.Function)

    # xor %eax, %eax; xor %ecx, %ecx
    code_bytes = b"\x31\xC0\x31\xC9"
    block.size = len(code_bytes)

    scope = gtirb_rewriting.AllBlocksScope(
        position=gtirb_rewriting.BlockPosition.ENTRY
    )
    assert not scope._needs_disassembly()
    assert scope._function_matches(mod, func)
    assert scope._block_matches(mod, func, block)
    offsets = list(scope._potential_offsets(func, block, None))
    assert offsets == [0]


def test_all_block_scope_anywhere():
    mod = unittest.mock.MagicMock(spec=gtirb.Module)
    block = unittest.mock.MagicMock(spec=gtirb.CodeBlock)

    # xor %eax, %eax; xor %ecx, %ecx
    code_bytes = b"\x31\xC0\x31\xC9"
    block.size = len(code_bytes)

    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    disasm = tuple(cs.disasm(code_bytes, 0))

    func = unittest.mock.MagicMock(spec=gtirb_functions.Function)

    scope = gtirb_rewriting.AllBlocksScope(
        position=gtirb_rewriting.BlockPosition.ANYWHERE
    )
    assert scope._needs_disassembly()
    assert scope._function_matches(mod, func)
    assert scope._block_matches(mod, func, block)
    offsets = list(scope._potential_offsets(func, block, disasm))
    assert offsets == [0, 2, 4]


def test_all_block_scope_exit():
    mod = unittest.mock.MagicMock(spec=gtirb.Module)
    block = unittest.mock.MagicMock(spec=gtirb.CodeBlock)

    # xor %eax, %eax; xor %ecx, %ecx
    code_bytes = b"\x31\xC0\x31\xC9"
    block.size = len(code_bytes)

    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    disasm = tuple(cs.disasm(code_bytes, 0))

    func = unittest.mock.MagicMock(spec=gtirb_functions.Function)
    func.get_name.return_value = "foo"

    scope = gtirb_rewriting.AllBlocksScope(
        position=gtirb_rewriting.BlockPosition.EXIT
    )
    assert scope._needs_disassembly()
    assert scope._function_matches(mod, func)
    assert scope._block_matches(mod, func, block)
    offsets = list(scope._potential_offsets(func, block, disasm))
    assert offsets == [4]


def test_pattern_match():
    mod = unittest.mock.MagicMock(spec=gtirb.Module)
    func = unittest.mock.MagicMock(spec=gtirb_functions.Function)
    func.get_name.return_value = "foo"

    assert not gtirb_rewriting.scopes._pattern_match(mod, func, {})
    assert gtirb_rewriting.scopes._pattern_match(mod, func, {"foo"})
    assert gtirb_rewriting.scopes._pattern_match(
        mod, func, {re.compile("f..")}
    )
    # Verify that only complete regex matches are considered
    assert not gtirb_rewriting.scopes._pattern_match(
        mod, func, {re.compile("f")}
    )
