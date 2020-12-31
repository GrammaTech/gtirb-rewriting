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
from typing import List, Set, Tuple

import gtirb

from .assembly import Register, _AsmSnippet


@dataclasses.dataclass
class CallingConventionDesc:
    """
    Describes an ABI's calling convention.
    """

    registers: Tuple[str, ...]
    """
    Registers used for passing integer or pointer-like values, in the
    order they are to be used. Any remaining arguments will be passed on
    the stack.
    """

    stack_alignment: int
    """
    The required stack alignment for calling a function.
    """

    caller_cleanup: bool
    """
    Is the caller required to do cleanup for arguments pushed onto the stack?
    """

    shadow_space: int = 0
    """
    The amount of space required to be allocated on the stack before calling
    the function. This space is essentially empty can be used by the called
    function.
    """


class _ISA:
    def __init__(self) -> None:
        self._register_map = {}
        for reg in self.all_registers():
            for name in reg.sizes.values():
                self._register_map[name.lower()] = reg

    def save_register(
        self, register: Register
    ) -> Tuple[_AsmSnippet, _AsmSnippet]:
        """
        Generate code required to save a specific register.
        """
        raise NotImplementedError

    def align_stack(self) -> Tuple[_AsmSnippet, _AsmSnippet]:
        """
        Generate code to align the stack to the ABI requirements for a call.
        """
        raise NotImplementedError

    def get_register(self, name: str) -> Register:
        """
        Gets a Register object by its name (or the name of a subregister).
        """
        return self._register_map[name.lower()]

    def save_flags(self) -> Tuple[_AsmSnippet, _AsmSnippet]:
        """
        Generate code required to save the flags register.
        """
        raise NotImplementedError

    def all_registers(self) -> List[Register]:
        """
        Returns all general-purpose registers for the ISA.
        """
        raise NotImplementedError

    def nop(self) -> bytes:
        """
        Returns the encoding of a no-op instruction.
        """
        raise NotImplementedError

    def caller_saved_registers(self) -> Set[Register]:
        """
        Returns the registers that need to be saved by the caller if it wants
        the values preserved across the call.
        """
        raise NotImplementedError

    def pointer_size(self) -> int:
        """
        Returns the size of a pointer on the ISA (which is assumed to match
        the size of general purpose registers).
        """
        raise NotImplementedError

    def red_zone_size(self) -> int:
        """
        Returns the number of bytes that leaf functions are allowed to use on
        the stack (without adjusting the stack pointer).
        """
        return 0

    def preserve_red_zone(self) -> Tuple[_AsmSnippet, _AsmSnippet]:
        """
        Generate code required to preserve the contents of the red zone.
        """
        raise NotImplementedError

    def calling_convention(self) -> CallingConventionDesc:
        """
        Returns a description of the ABI's default calling convention.
        """
        raise NotImplementedError

    def stack_register(self) -> Register:
        """
        Returns the stack pointer register.
        """
        raise NotImplementedError


class _X86_64(_ISA):
    def save_register(
        self, register: Register
    ) -> Tuple[_AsmSnippet, _AsmSnippet]:
        return (
            _AsmSnippet(f"pushq %{register}"),
            _AsmSnippet(f"popq %{register}"),
        )

    def save_flags(self) -> Tuple[_AsmSnippet, _AsmSnippet]:
        # TODO: Replace this with something more efficient.
        return _AsmSnippet("pushfq"), _AsmSnippet("popfq")

    def align_stack(self) -> Tuple[_AsmSnippet, _AsmSnippet]:
        return (
            _AsmSnippet(
                """
                pushq   %rax
                movq    %rsp, %rax
                leaq    -0x80(%rsp), %rsp
                andq    $-0x10, %rsp
                pushq   %rax
                pushq   %rax
            """
            ),
            _AsmSnippet(
                """
                popq    %rax
                movq    %rax, %rsp
                popq    %rax
            """
            ),
        )

    def all_registers(self) -> List[Register]:
        return [
            Register(
                {"8l": "al", "8h": "ah", "16": "ax", "32": "eax", "64": "rax"},
                "64",
            ),
            Register(
                {"8l": "bl", "8h": "bh", "16": "bx", "32": "ebx", "64": "rbx"},
                "64",
            ),
            Register(
                {"8l": "cl", "8h": "ch", "16": "cx", "32": "ecx", "64": "rcx"},
                "64",
            ),
            Register(
                {"8l": "dl", "8h": "dh", "16": "dx", "32": "edx", "64": "rdx"},
                "64",
            ),
            Register(
                {"8l": "sil", "16": "si", "32": "esi", "64": "rsi"}, "64"
            ),
            Register(
                {"8l": "dil", "16": "di", "32": "edi", "64": "rdi"}, "64"
            ),
            Register(
                {"8l": "r8b", "16": "r8w", "32": "r8d", "64": "r8"}, "64"
            ),
            Register(
                {"8l": "r9b", "16": "r9w", "32": "r9d", "64": "r9"}, "64"
            ),
            Register(
                {"8l": "r10b", "16": "r10w", "32": "r10d", "64": "r10"}, "64"
            ),
            Register(
                {"8l": "r11b", "16": "r11w", "32": "r11d", "64": "r11"}, "64"
            ),
            Register(
                {"8l": "r12b", "16": "r12w", "32": "r12d", "64": "r12"}, "64"
            ),
            Register(
                {"8l": "r13b", "16": "r13w", "32": "r13d", "64": "r13"}, "64"
            ),
            Register(
                {"8l": "r14b", "16": "r14w", "32": "r14d", "64": "r14"}, "64"
            ),
            Register(
                {"8l": "r15b", "16": "r15w", "32": "r15d", "64": "r15"}, "64"
            ),
        ]

    def nop(self) -> bytes:
        return b"\x90"

    def pointer_size(self) -> int:
        return 8

    def stack_register(self) -> Register:
        return Register({"16": "sp", "32": "esp", "64": "rsp"}, "64",)


class _X86_64_PE(_X86_64):
    def caller_saved_registers(self) -> Set[Register]:
        return {
            self.get_register(name)
            for name in ("RAX", "RCX", "RDX", "R8", "R9", "R10", "R11")
        }

    def calling_convention(self) -> CallingConventionDesc:
        return CallingConventionDesc(
            registers=("RCX", "RDX", "R8", "R9"),
            stack_alignment=16,
            caller_cleanup=True,
            shadow_space=32,
        )


class _X86_64_ELF(_X86_64):
    def caller_saved_registers(self) -> Set[Register]:
        return {
            self.get_register(name)
            for name in (
                "RAX",
                "RCX",
                "RDX",
                "RSI",
                "RDI",
                "R8",
                "R9",
                "R10",
                "R11",
            )
        }

    def red_zone_size(self) -> int:
        return 128

    def preserve_red_zone(self) -> Tuple[_AsmSnippet, _AsmSnippet]:
        return (
            _AsmSnippet("leaq -128(%rsp), %rsp"),
            _AsmSnippet("leaq +128(%rsp), %rsp"),
        )

    def calling_convention(self) -> CallingConventionDesc:
        return CallingConventionDesc(
            registers=("RDI", "RSI", "RDX", "RCX", "R8", "R9"),
            stack_alignment=16,
            caller_cleanup=True,
        )


def _get_isa(module: gtirb.Module) -> _ISA:
    if module.isa == gtirb.Module.ISA.X64:
        if module.file_format == gtirb.Module.FileFormat.ELF:
            return _X86_64_ELF()
        elif module.file_format == gtirb.Module.FileFormat.PE:
            return _X86_64_PE()

    assert False, f"Unsupported ISA/format: {module.isa}/{module.file_format}"
