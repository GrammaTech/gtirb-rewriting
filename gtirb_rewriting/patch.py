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

import dataclasses
from functools import partial
from typing import Callable, List, Optional

import gtirb
import gtirb_functions

from .abi import ABI
from .assembly import Constraints, Register
from .utils import decorate_extern_symbol


@dataclasses.dataclass
class InsertionContext:
    """
    A concrete location to insert code at, plus helper utilities.
    """

    module: gtirb.Module
    function: Optional[gtirb_functions.Function]
    block: gtirb.ByteBlock
    offset: int
    """
    The byte offset of the insertion, relative to the start of the block.
    """

    stack_adjustment: Optional[int] = None
    """
    The amount that the stack has been adjusted to allow for the insertion.
    A value of None means that it is unknown how much it has been affected
    (which can happen with the align_stack constraint).
    """

    scratch_registers: List[Register] = dataclasses.field(default_factory=list)
    """
    Scratch registers, as requested by the patch's constraints.
    """

    def decorate_extern_symbol(self, name: str) -> str:
        return decorate_extern_symbol(self.module, name)

    def temporary_label(self, name: str) -> str:
        """
        Creates a temporary label based off of the given base name.
        """
        abi = ABI.get(self.module)
        return abi.temporary_label_prefix() + name


def patch_constraints(*args, **kwargs):
    """
    Associates a Constraints object with a function that is meant to be used
    as a Patch (see Patch.from_function). The arguments to the decorator are
    used when constructing the Constraints object.
    """

    def constraints_decorator(func):
        func.constraints = Constraints(*args, **kwargs)
        return func

    return constraints_decorator


def _unwrap_callable(func):
    while True:
        yield func

        if isinstance(func, partial):
            func = func.func
        elif hasattr(func, "__wrapper__"):
            func = func.__wrapper__
        else:
            break


def _find_constraints(func):
    for layer in _unwrap_callable(func):
        constraints = getattr(layer, "constraints", None)
        if constraints:
            return constraints
    return None


class Patch:
    """
    A chunk of assembly code to be inserted into a program, along with its
    constraints.
    """

    def __init__(self, constraints: Constraints):
        self.constraints = constraints

    def get_asm(self, insertion_context: InsertionContext) -> Optional[str]:
        """
        Returns the assembly string for the patch.

        If the assembly string references symbols, the GTIRB module's symbol
        table will be updated as needed and symbolic expressions will be
        created.

        If None is returned, no insertion takes place.

        :param insertion_context: The concrete location where the code will be
                                  inserted.
        """
        raise NotImplementedError

    @classmethod
    def from_function(
        cls, func: Callable, constraints: Optional[Constraints] = None
    ):
        """
        Creates a Patch from a callable that has been decorated with the
        @patch_constraints decorator.
        """

        class FuncPatch(Patch):
            def __str__(self) -> str:
                return str(func)

            def get_asm(self, insertion_context):
                return func(insertion_context)

        if not constraints:
            constraints = _find_constraints(func)
            assert (
                constraints
            ), "constraints must be specified when not using the decorator"

        return FuncPatch(constraints)
