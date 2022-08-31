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
from typing import Callable, Iterable, Iterator, List, Optional, Union

import gtirb
import more_itertools

from ..abi import ABI, CallingConventionDesc
from ..assembly import X86Syntax
from ..patch import Constraints, InsertionContext, Patch
from ..utils import align_address


class CallPatch(Patch):
    """
    Inserts a call to a function with literal arguments.
    """

    ActualArgumentValue = Union[int, gtirb.Symbol]
    ArgumentValue = Union[
        Callable[[InsertionContext], "ActualArgumentValue"],
        "ActualArgumentValue",
    ]

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

        if not conv:
            abi = ABI.get(sym.module)
            conv = abi.calling_convention()

        if sym.module.isa in (gtirb.Module.ISA.IA32, gtirb.Module.ISA.X64):
            self._imp = _CallPatchX86(sym, args, conv, **constraint_kwargs)
        elif sym.module.isa == gtirb.Module.ISA.ARM64:
            self._imp = _CallPatchARM64(sym, args, conv, **constraint_kwargs)

        self.sym = sym
        super().__init__(self._imp.constraints)

    def get_asm(self, insertion_context: InsertionContext) -> str:
        return self._imp.get_asm(insertion_context)


class _CallPatchImpl:
    @dataclasses.dataclass
    class _PassedArg:
        value: "CallPatch.ArgumentValue"
        reg: Optional[str]

    def __init__(
        self,
        sym: gtirb.Symbol,
        module: gtirb.Module,
        args: Iterable["CallPatch.ArgumentValue"],
        conv: CallingConventionDesc,
        **constraint_kwargs,
    ):
        raise NotImplementedError

    def get_asm(self, insertion_context: InsertionContext) -> str:
        raise NotImplementedError

    def _actual_value(
        self,
        arg: "_CallPatchImpl._PassedArg",
        insertion_context: InsertionContext,
    ) -> "CallPatch.ActualArgumentValue":
        return (
            arg.value(insertion_context) if callable(arg.value) else arg.value
        )

    def _create_passed_args(
        self,
        conv: CallingConventionDesc,
        args: Iterable["CallPatch.ArgumentValue"],
    ) -> List["_PassedArg"]:
        """
        Assigns arguments to registers (or the stack).
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


class _CallPatchX86(_CallPatchImpl):
    def __init__(
        self,
        sym: gtirb.Symbol,
        args: Iterable["CallPatch.ArgumentValue"],
        conv: CallingConventionDesc,
        **constraint_kwargs,
    ):
        assert sym.module
        self._abi = ABI.get(sym.module)
        self._cconv = conv
        self._sym = sym
        self._args = self._create_passed_args(self._cconv, args)

        self.constraints = Constraints(
            x86_syntax=X86Syntax.INTEL,
            clobbers_flags=True,
            clobbers_registers={arg.reg for arg in self._args if arg.reg},
            align_stack=True,
            preserve_caller_saved_registers=True,
        )
        self.constraints = dataclasses.replace(
            self.constraints, **constraint_kwargs
        )

    def get_asm(self, insertion_context: InsertionContext) -> str:
        lines = []

        stack_slot_size = self._abi.pointer_size()
        stack_reg = self._abi.stack_register()

        arg_stack_size = sum(
            stack_slot_size for arg in self._args if not arg.reg
        )
        if insertion_context.stack_adjustment is not None:
            total_stack_size = (
                insertion_context.stack_adjustment + arg_stack_size
            )
        else:
            total_stack_size = arg_stack_size

        stack_padding = (
            align_address(total_stack_size, self._cconv.stack_alignment)
            - total_stack_size
        )
        if stack_padding:
            lines.append(f"sub {stack_reg}, {stack_padding}")

        for arg in reversed(self._args):
            arg_value = self._actual_value(arg, insertion_context)

            if isinstance(arg_value, gtirb.Symbol):
                file_format = insertion_context.module.file_format
                if file_format == gtirb.Module.FileFormat.ELF:
                    arg_str = f"{arg_value.name}[rip]"
                elif file_format == gtirb.Module.FileFormat.PE:
                    arg_str = arg_value.name
                else:
                    raise NotImplementedError("unknown file format")
            elif isinstance(arg_value, int):
                arg_str = str(arg_value)
            else:
                assert False

            if arg.reg:
                lines.append(f"mov {arg.reg}, {arg_str}")
            else:
                lines.append(f"push {arg_str}")

        if self._cconv.shadow_space:
            lines.append(f"sub {stack_reg}, {self._cconv.shadow_space}")

        lines.append(f"call {self._sym.name}")

        cleanup_size = self._cconv.shadow_space + stack_padding
        if self._cconv.caller_cleanup:
            cleanup_size += arg_stack_size

        if cleanup_size:
            lines.append(f"add {stack_reg}, {cleanup_size}")

        return "\n".join(lines)


class _CallPatchARM64(_CallPatchImpl):
    """
    Inserts a call to a function with literal arguments.
    """

    def __init__(
        self,
        sym: gtirb.Symbol,
        args: Iterable["CallPatch.ArgumentValue"],
        conv: CallingConventionDesc,
        **constraint_kwargs,
    ):
        if conv.shadow_space:
            raise ValueError("shadow_space does not apply to ARM64")
        if conv.stack_alignment != 16:
            raise ValueError("ARM64 stack alignment should be 16")

        self._sym = sym
        self._args = self._create_passed_args(conv, args)
        self._cconv = conv

        clobbered_registers = {arg.reg for arg in self._args if arg.reg}
        clobbered_registers.add("x30")

        uses_stack = any(True for arg in self._args if not arg.reg)
        if uses_stack:
            clobbered_registers.add("x0")

        self.constraints = Constraints(
            clobbers_flags=True,
            clobbers_registers=clobbered_registers,
            preserve_caller_saved_registers=True,
        )
        self.constraints = dataclasses.replace(
            self.constraints, **constraint_kwargs
        )

    def _load_immediate(self, reg: str, value: int) -> Iterator[str]:
        """
        Load an immediate into a register.
        """

        # For small values, let the assembler pick the best instruction to
        # load the immediate.
        if -0xFFFF <= value <= 0xFFFF:
            yield f"mov {reg}, #0x{value:x}"
            return

        # TODO: This could be more optimal, particularly for negative numbers.
        for shift in range(0, 64, 16):
            chunk = (value >> shift) & 0xFFFF
            if shift == 0:
                yield f"movz {reg}, #0x{chunk:x}"
            elif chunk:
                yield f"movk {reg}, #0x{chunk:x}, lsl #{shift}"

    def _load_symbol(self, reg: str, sym: gtirb.Symbol) -> Iterator[str]:
        """
        Load a symbol into a register.
        """
        yield f"adrp {reg}, {sym.name}"
        yield f"add {reg}, {reg}, #:lo12:{sym.name}"

    def get_asm(self, insertion_context: InsertionContext) -> str:
        lines = []

        [*stack_args], [*reg_args] = more_itertools.partition(
            lambda arg: arg.reg, reversed(self._args)
        )

        stack_adjustment = align_address(
            len(stack_args) * 8, self._cconv.stack_alignment
        )
        if stack_adjustment:
            lines.append(f"sub sp, sp, #{stack_adjustment}")

        # Deal with stack values first because we have to use a register to
        # get the value onto the stack.
        for i, arg in enumerate(stack_args):
            arg_value = self._actual_value(arg, insertion_context)
            temp_reg = "x0"
            if isinstance(arg_value, gtirb.Symbol):
                lines.extend(self._load_symbol(temp_reg, arg_value))
            elif isinstance(arg_value, int):
                lines.extend(self._load_immediate(temp_reg, arg_value))

            slot = (len(stack_args) - i - 1) * 8
            lines.append(f"str {temp_reg}, [sp, #{slot}]")

        for arg in reg_args:
            assert arg.reg

            arg_value = self._actual_value(arg, insertion_context)
            if isinstance(arg_value, gtirb.Symbol):
                lines.extend(self._load_symbol(arg.reg, arg_value))
            elif isinstance(arg_value, int):
                lines.extend(self._load_immediate(arg.reg, arg_value))

        lines.append(f"bl {self._sym.name}")

        if stack_adjustment:
            lines.append(f"add sp, sp, #{stack_adjustment}")

        return "\n".join(lines)
