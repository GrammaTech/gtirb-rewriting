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
from typing import List, Tuple

import gtirb

from .assembly import Register, _AsmSnippet


class _ISA:
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


def _get_isa(module_isa: gtirb.Module.ISA) -> _ISA:
    if module_isa == gtirb.Module.ISA.X64:
        return _X86_64()
    else:
        assert False, f"Unsupported ISA: {module_isa}"
