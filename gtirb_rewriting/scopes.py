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
from enum import Enum, auto
from typing import Iterator, Optional, Pattern, Sequence, Set, Union

import capstone
import gtirb
import gtirb_functions

from .utils import _is_partial_disassembly, _nonterminator_instructions

ENTRYPOINT_NAME = "\0"
"""
A meta-name that refers to the module's entrypoint.
"""


MAIN_NAME = "\0\0"
"""
A meta-name that refers to the module's main function. This may not always be
called "main" (e.g. on Windows).
"""


class BlockPosition(Enum):
    ENTRY = auto()
    """
    Insert the patch at the beginning of a block.
    """

    EXIT = auto()
    """
    Insert the patch at the end of the block, but before the terminator
    instruction (if there is one).
    """

    ANYWHERE = auto()
    """
    Insert the patch anywhere in the block (except after the terminator),
    allowing bubbling to occur.
    """


class Scope:
    """
    Scopes provide a declarative way to specify where in a program a patch
    should be applied.
    """

    def _function_matches(
        self, module: gtirb.Module, func: gtirb_functions.Function
    ) -> bool:
        """
        Determines if a function matches the scope. If this returns False, no
        patches in this scope will be appled to this function.
        """
        raise NotImplementedError

    def _block_matches(
        self,
        module: gtirb.Module,
        func: gtirb_functions.Function,
        block: gtirb.CodeBlock,
    ) -> bool:
        """
        Determines if a block matches the scope. If this returns False, no
        patches in this scope will be applied to this block.
        """
        raise NotImplementedError

    def _needs_disassembly(self) -> bool:
        """
        Does this scope's _potential_offsets method need the disassembly
        parameter filled out?
        """
        raise NotImplementedError

    def _replacement_length(self) -> int:
        return 0

    def _potential_offsets(
        self,
        func: gtirb_functions.Function,
        block: gtirb.CodeBlock,
        disassembly: Optional[Sequence[capstone.CsInsn]],
    ) -> Iterator[int]:
        """
        Returns an iterator of all the potential offsets in the block where
        the patch could be applied.

        Note that only one offset will be chosen, so it is not possible to
        have a scope that inserts more than once in a block.
        """
        raise NotImplementedError


class AllBlocksScope(Scope):
    """
    Specifies that an insertion should happen in all blocks of a program. The
    functions that this inserts into can be controlled with a list of names
    (or regular expressions) to check the name against.
    """

    def __init__(
        self,
        position: BlockPosition,
        exclude_functions: Optional[Set[Union[str, Pattern]]] = None,
    ):
        self.position = position
        self.exclude_functions = exclude_functions

    def _function_matches(
        self, module: gtirb.Module, func: gtirb_functions.Function
    ) -> bool:
        return self.exclude_functions is None or not pattern_match(
            module, func, self.exclude_functions
        )

    def _block_matches(
        self,
        module: gtirb.Module,
        func: gtirb_functions.Function,
        block: gtirb.CodeBlock,
    ) -> bool:
        return True

    def _needs_disassembly(self) -> bool:
        return self.position in [BlockPosition.ANYWHERE, BlockPosition.EXIT]

    def _potential_offsets(
        self,
        func: gtirb_functions.Function,
        block: gtirb.CodeBlock,
        disassembly: Optional[Sequence[capstone.CsInsn]],
    ) -> Iterator[int]:
        return _potential_offsets_in_block(self.position, block, disassembly)


class SingleBlockScope(Scope):
    """
    Specifies that an insertion should happen in a specific block of a program.
    """

    def __init__(self, block: gtirb.CodeBlock, position: BlockPosition):
        self.block = block
        self.position = position

    def _function_matches(
        self, module: gtirb.Module, func: gtirb_functions.Function
    ) -> bool:
        return self.block in func.get_all_blocks()

    def _block_matches(
        self,
        module: gtirb.Module,
        func: gtirb_functions.Function,
        block: gtirb.CodeBlock,
    ) -> bool:
        return self.block == block

    def _needs_disassembly(self) -> bool:
        return self.position in [BlockPosition.ANYWHERE, BlockPosition.EXIT]

    def _potential_offsets(
        self,
        func: gtirb_functions.Function,
        block: gtirb.CodeBlock,
        disassembly: Optional[Sequence[capstone.CsInsn]],
    ) -> Iterator[int]:
        return _potential_offsets_in_block(self.position, block, disassembly)


class FunctionPosition(Enum):
    ENTRY = auto()
    """
    Insert into function entry blocks.
    """

    EXIT = auto()
    """
    Insert into function exit blocks.
    """


class AllFunctionsScope(Scope):
    """
    Specifies that an insertion should happen either in the entry blocks or
    exit blocks of functions. The functions that this inserts into can be
    controlled with a list of names (or regular expressions) to check the name
    against.
    """

    def __init__(
        self,
        position: FunctionPosition,
        block_position: BlockPosition,
        functions: Set[Union[str, Pattern]] = None,
    ):
        self.position = position
        self.block_position = block_position
        self.functions = functions

    def _function_matches(
        self, module: gtirb.Module, func: gtirb_functions.Function
    ) -> bool:
        return self.functions is None or pattern_match(
            module, func, self.functions
        )

    def _block_matches(
        self,
        module: gtirb.Module,
        func: gtirb_functions.Function,
        block: gtirb.CodeBlock,
    ) -> bool:
        if self.position == FunctionPosition.ENTRY:
            return block in func.get_entry_blocks()
        if self.position == FunctionPosition.EXIT:
            return block in func.get_exit_blocks()
        assert False, f"Invalid position: {self.position}"

    def _needs_disassembly(self) -> bool:
        return self.block_position in [
            BlockPosition.ANYWHERE,
            BlockPosition.EXIT,
        ]

    def _potential_offsets(
        self,
        func: gtirb_functions.Function,
        block: gtirb.CodeBlock,
        disassembly: Optional[Sequence[capstone.CsInsn]],
    ) -> Iterator[int]:
        return _potential_offsets_in_block(
            self.block_position, block, disassembly
        )


class _SpecificLocationScope(Scope):
    def __init__(
        self,
        function: gtirb_functions.Function,
        block: gtirb.CodeBlock,
        offset: int,
        replacement_length: int = 0,
    ):
        self.function = function
        self.block = block
        self.offset = offset
        self.replacement_length = replacement_length

    def _function_matches(
        self, module: gtirb.Module, func: gtirb_functions.Function
    ) -> bool:
        return self.function == func

    def _block_matches(
        self,
        module: gtirb.Module,
        func: gtirb_functions.Function,
        block: gtirb.CodeBlock,
    ) -> bool:
        return self.block == block

    def _needs_disassembly(self) -> bool:
        return False

    def _replacement_length(self) -> int:
        return self.replacement_length

    def _potential_offsets(
        self,
        func: gtirb_functions.Function,
        block: gtirb.CodeBlock,
        disassembly: Optional[Sequence[capstone.CsInsn]],
    ) -> Iterator[int]:
        yield self.offset


def _potential_offsets_in_block(
    block_position: BlockPosition,
    block: gtirb.CodeBlock,
    disassembly: Optional[Sequence[capstone.CsInsn]],
) -> Iterator[int]:
    if block_position == BlockPosition.ENTRY:
        yield 0
    elif block_position == BlockPosition.ANYWHERE:
        assert disassembly is not None
        offset = 0
        for inst in _nonterminator_instructions(block, disassembly):
            yield offset
            offset += inst.size
        yield offset
    elif block_position == BlockPosition.EXIT:
        assert disassembly is not None
        assert not _is_partial_disassembly(
            block, disassembly
        ), "Capstone failed to disassemble all instructions in target block"
        yield sum(
            inst.size
            for inst in _nonterminator_instructions(block, disassembly)
        )
    else:
        assert False, "Invalid block position"


def pattern_match(
    module: gtirb.Module,
    func: gtirb_functions.Function,
    match_set: Set[Union[str, Pattern]],
) -> bool:
    """
    Determines if a function matches a set of regex patterns or literal names.

    :param module: The gtirb Module containing the Function.
    :param func: The Function to check.
    :param match_set: The names or patterns to match against.
    """
    for fname in match_set:
        if fname == MAIN_NAME:
            # TODO: Main isn't necessarily "main" on Windows.
            matches = func.get_name() == "main"
        elif fname == ENTRYPOINT_NAME:
            matches = module.entry_point in func.get_entry_blocks()
        elif isinstance(fname, Pattern):
            matches = fname.fullmatch(func.get_name()) is not None
        else:
            matches = func.get_name() == fname
        if matches:
            return True
    return False
