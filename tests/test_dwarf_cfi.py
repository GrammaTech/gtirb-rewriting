# GTIRB-Rewriting Rewriting API for GTIRB
# Copyright (C) 2024 GrammaTech, Inc.
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

from dataclasses import dataclass
from typing import Tuple

import pytest

from gtirb_rewriting.dwarf.cfi import (
    InstNop,
    Instruction,
    InstValExpression,
    parse_cfi_instructions,
)
from gtirb_rewriting.dwarf.expr import OpLit


@dataclass
class CFIParseTest:
    name: str
    value: bytes
    parsed: Tuple[Instruction, ...]


@pytest.mark.parametrize(
    "test",
    (
        CFIParseTest("cfi_nop-cfi_nop", b"\x00\x00", (InstNop(), InstNop())),
        CFIParseTest(
            "cfi_val_expression",
            b"\x16\x10\x01\x31",
            #   ^   ^   ^   ^
            #   |   |   |   |- DW_OP_lit1
            #   |   |   |- expr length
            #   |   |- register
            #   |- DW_CFA_val_expression
            (InstValExpression(16, [OpLit(1)]),),
        ),
    ),
    ids=lambda test: test.name,
)
def test_parse_cfi_instructions(test: CFIParseTest):
    parsed = tuple(parse_cfi_instructions(test.value, "little", 8))
    assert parsed == test.parsed
