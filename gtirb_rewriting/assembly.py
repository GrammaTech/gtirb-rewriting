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
from typing import Callable, Dict, Optional, Set

import gtirb
import gtirb_functions
import mcasm

from .utils import decorate_extern_symbol


class Register:
    """
    An architecture-specific register.

    Registers are not created directly and are instead given to patches by
    requesting scratch registers in their constraints.
    """

    def __init__(self, sizes: Dict[str, str], default_size: str):
        self.sizes = sizes
        self.default_size = default_size

    def __contains__(self, value) -> bool:
        return value in self.sizes.values()

    def __eq__(self, other) -> bool:
        return (
            self.sizes == other.sizes
            and self.default_size == other.default_size
        )

    def __hash__(self) -> int:
        return hash(self.default_size) ^ hash(
            tuple(sorted(self.sizes.items()))
        )

    def __format__(self, spec: str) -> str:
        """
        Formats the register (or subregister) as its name.

        :param spec: The format type specifier. This can control which
                     subregister name is used.
                     x86-64 supports the following sizes:
                     - 8l, 8h, 16, 32, 64
        """
        if spec:
            return self.sizes[spec]
        return self.sizes[self.default_size]

    @property
    def name(self) -> str:
        return self.sizes[self.default_size]


@dataclasses.dataclass
class InsertionContext:
    """
    A concrete location to insert code at, plus helper utilities.
    """

    module: gtirb.Module
    function: gtirb_functions.Function
    block: gtirb.CodeBlock
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

    def decorate_extern_symbol(self, name: str) -> str:
        return decorate_extern_symbol(self.module, name)


X86Syntax = mcasm.X86Syntax


@dataclasses.dataclass
class Constraints:
    """
    Constraints related to the assembly code in a patch. These can be seen as
    metadata about the actual assembly in a patch and can impact where the
    patch gets placed if bubbling is allowed.
    """

    x86_syntax: X86Syntax = X86Syntax.ATT
    """
    The syntax mode to use for x86 code. This is unused for other ISAs.
    """

    clobbers_flags: bool = False
    """
    Does the assembly clobber the flags register?
    """

    clobbers_registers: Set[str] = dataclasses.field(default_factory=set)
    """
    The general purpose registers that the assembly clobbers.
    """

    scratch_registers: int = 0
    """
    The number of scratch registers that the patch needs. When emitting the
    patch's code, the rewriting context will try to pick free registers. If no
    registers are free at the insertion point, it will generate code to spill
    the registers to the stack before/after the patch.

    The scratch registers will be passed as positional arguments to the patch's
    get_asm method.
    """

    align_stack: bool = False
    """
    Generate code to align the stack to the ABI-defined alignment before
    emitting the patch's code and restore the previous value after. This is
    useful for inserting a call into a module's entrypoint.
    """

    preserve_caller_saved_registers: bool = False
    """
    Spill all caller saved registers as per the ABI based on ISA and ouput
    format (e.g. PE vs ELF).
    """


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


@dataclasses.dataclass
class _AsmSnippet:
    code: str
    x86_syntax: X86Syntax = X86Syntax.ATT


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

    def get_asm(
        self, insertion_context: InsertionContext, *args: Register
    ) -> Optional[str]:
        """
        Returns the assembly string for the patch.

        If the assembly string references symbols, the GTIRB module's symbol
        table will be updated as needed and symbolic expressions will be
        created.

        If None is returned, no insertion takes place.

        :param insertion_context: The concrete location where the code will be
                                  inserted.
        :param args: Any scratch registers requested by the patch.
        """
        raise NotImplementedError

    @classmethod
    def from_function(cls, func: Callable, constraints: Constraints = None):
        """
        Creates a Patch from a callable that has been decorated with the
        @patch_constraints decorator.
        """

        class FuncPatch(Patch):
            def __str__(self) -> str:
                return str(func)

            def get_asm(self, insertion_context, *args):
                return func(insertion_context, *args)

        if not constraints:
            constraints = _find_constraints(func)
            assert (
                constraints
            ), "constraints must be specified when not using the decorator"

        return FuncPatch(constraints)
