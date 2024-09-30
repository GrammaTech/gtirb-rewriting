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

"""
Utilities for manipulating the function-related aux data tables.
"""

import uuid

import gtirb

import gtirb_rewriting._auxdata as _auxdata

from .cache import ModifyCache


def add_function_block_aux(
    cache: ModifyCache, new_block: gtirb.CodeBlock, func_uuid: uuid.UUID
) -> None:
    """
    Adds a block to the functionBlocks aux data table.
    """
    assert new_block.module, "block must be in a module"

    function_blocks = _auxdata.function_blocks.get(new_block.module)
    if function_blocks is not None:
        function_blocks[func_uuid].add(new_block)
    cache.functions_by_block[new_block] = func_uuid


def remove_function_block_aux(
    cache: ModifyCache, block: gtirb.CodeBlock
) -> None:
    """
    Removes a block from the functionBlocks aux data table. If no blocks are
    left, it will also clean up the related aux data table entries.
    """
    assert block.module, "block must be in a module"

    func_uuid = cache.functions_by_block.pop(block, None)
    if func_uuid is None:
        return

    blocks_left = False
    for table_def in (_auxdata.function_entries, _auxdata.function_blocks):
        table = table_def.get(block.module)
        if not table:
            continue

        blocks = table.get(func_uuid, None)
        if not blocks:
            continue

        blocks.discard(block)
        blocks_left = blocks_left or bool(blocks)

    if not blocks_left:
        for table_def in (
            _auxdata.function_blocks,
            _auxdata.function_entries,
            _auxdata.function_names,
        ):
            table = table_def.get(block.module)
            if table:
                table.pop(func_uuid, None)
