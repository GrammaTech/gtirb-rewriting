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

from typing import Set, Union

import gtirb
import gtirb_functions
import gtirb_rewriting
from gtirb_test_helpers import add_function


def add_function_object(
    module: gtirb.Module,
    sym_or_name: Union[str, gtirb.Symbol],
    entry_block: gtirb.CodeBlock,
    other_blocks: Set[gtirb.CodeBlock] = set(),
) -> gtirb_functions.Function:
    """
    Adds a function to all the appropriate aux data tables and creates a
    Function object.
    """

    func_uuid = add_function(module, sym_or_name, entry_block, other_blocks)
    return gtirb_functions.Function(
        func_uuid, {entry_block}, {entry_block} | other_blocks
    )


def literal_patch(asm: str) -> gtirb_rewriting.Patch:
    """
    Creates a patch from a literal string. The patch will have an empty
    constraints object.
    """

    @gtirb_rewriting.patch_constraints()
    def patch(ctx):
        return asm

    return gtirb_rewriting.Patch.from_function(patch)


def remove_indentation(s: str) -> str:
    """
    Removes indentation from the front of each line in a string, omitting any
    purely empty lines.
    """
    lines = []
    for line in s.splitlines():
        line = line.lstrip()
        if line:
            lines.append(line)
    return "\n".join(lines)
