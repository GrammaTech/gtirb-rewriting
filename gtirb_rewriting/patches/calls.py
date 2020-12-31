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
from typing import Callable, Iterable, List, Optional, Union

import gtirb

from ..assembly import Constraints, InsertionContext, Patch, X86Syntax
from ..isa import CallingConventionDesc, _get_isa


class CallPatch(Patch):
    """
    Inserts a call to a function with literal arguments.
    """

    ActualArgumentValue = Union[int, gtirb.Symbol]
    ArgumentValue = Union[
        Callable[[InsertionContext], "ActualArgumentValue"],
        "ActualArgumentValue",
    ]

    @dataclasses.dataclass
    class _PassedArg:
        value: "CallPatch.ArgumentValue"
        reg: Optional[str]

    def __init__(
        self,
        sym: gtirb.Symbol,
        args: Iterable["ArgumentValue"] = (),
        conv: Optional[CallingConventionDesc] = None,
        **constraint_kwargs,
    ):
        """
        Initializes a call patch.

        sym: The symbol to call.
        args: An iterable of arguments to be passed to the function. They must
              be either integers or Symbols.
        conv: The calling convention description to use for the call. If
              absent, the default ABI calling convention is used.
        constraint_kwargs: Additional keyword arguments to be passed to the
                         patch's constraints.
        """

        assert sym.module, "Symbol must be in a module"
        assert sym.module.isa in (gtirb.Module.ISA.IA32, gtirb.Module.ISA.X64)

        self._isa = _get_isa(sym.module)
        if conv:
            self._cconv = conv
        else:
            self._cconv = self._isa.calling_convention()

        self.sym = sym
        self._args = self._create_passed_args(self._cconv, args)

        super().__init__(
            Constraints(
                x86_syntax=X86Syntax.INTEL,
                clobbers_flags=True,
                clobbers_registers={arg.reg for arg in self._args if arg.reg},
                **constraint_kwargs,
            )
        )

    def _create_passed_args(
        self, conv: CallingConventionDesc, args: Iterable["ArgumentValue"]
    ) -> List["_PassedArg"]:
        """
        Assigns arguments to registers (or the stack) and creates the string
        value of the argument.
        """
        remaining_regs = list(conv.registers)

        passed_args = []
        for arg in args:
            assert (
                callable(arg)
                or isinstance(arg, gtirb.Symbol)
                or isinstance(arg, int)
            )

            passed_args.append(
                self._PassedArg(
                    arg, remaining_regs.pop(0) if remaining_regs else None
                )
            )

        return passed_args

    def get_asm(self, insertion_context: InsertionContext) -> str:
        lines = []

        stack_slot_size = self._isa.pointer_size()
        stack_reg = self._isa.stack_register()

        stack_size = sum(stack_slot_size for arg in self._args if not arg.reg)
        stack_padding = stack_size % self._cconv.stack_alignment
        if stack_padding:
            lines.append(f"sub {stack_reg}, {stack_padding}")

        for arg in reversed(self._args):
            arg_value = (
                arg.value(insertion_context)
                if callable(arg.value)
                else arg.value
            )

            if isinstance(arg_value, gtirb.Symbol):
                arg_str = arg_value.name
            elif isinstance(arg_value, int):
                arg_str = str(arg_value)

            if arg.reg:
                lines.append(f"mov {arg.reg}, {arg_str}")
            else:
                lines.append(f"push {arg_str}")

        if self._cconv.shadow_space:
            lines.append(f"sub {stack_reg}, {self._cconv.shadow_space}")

        lines.append(f"call {self.sym.name}")

        cleanup_size = self._cconv.shadow_space + stack_padding
        if self._cconv.caller_cleanup:
            cleanup_size += stack_size

        if cleanup_size:
            lines.append(f"add {stack_reg}, {cleanup_size}")

        return "\n".join(lines)
