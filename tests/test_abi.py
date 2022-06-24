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

import gtirb_rewriting
import pytest
from helpers import remove_indentation


def stringify_snippets(snippets):
    return "\n".join(remove_indentation(snippet.code) for snippet in snippets)


@pytest.mark.parametrize(
    "abi_class",
    (gtirb_rewriting.abi._IA32_PE,),
)
def test_ia32_clobbers_regs(abi_class):
    abi = abi_class()
    constraints = gtirb_rewriting.Constraints(
        clobbers_registers=("edx", "ecx")
    )

    registers = abi._allocate_patch_registers(constraints)
    prologue, epilogue, stack_adjustment = abi._create_prologue_and_epilogue(
        constraints, registers, False
    )
    assert stack_adjustment == 8
    assert stringify_snippets(prologue) == remove_indentation(
        """
        push %ecx
        push %edx
        """
    )
    assert stringify_snippets(epilogue) == remove_indentation(
        """
        pop %edx
        pop %ecx
        """
    )


@pytest.mark.parametrize(
    "abi_class",
    (gtirb_rewriting.abi._IA32_PE,),
)
def test_ia32_align_stack(abi_class):
    abi = abi_class()
    constraints = gtirb_rewriting.Constraints(align_stack=True)

    registers = abi._allocate_patch_registers(constraints)
    prologue, epilogue, stack_adjustment = abi._create_prologue_and_epilogue(
        constraints, registers, False
    )
    assert stack_adjustment is None
    assert stringify_snippets(prologue) == remove_indentation(
        """
        push   %eax
        mov    %esp, %eax
        lea    -0x80(%esp), %esp
        and    $-0x10, %esp
        push   %eax
        push   %eax
        """
    )
    assert stringify_snippets(epilogue) == remove_indentation(
        """
        pop    %eax
        mov    %eax, %esp
        pop    %eax
        """
    )


@pytest.mark.parametrize("abi_class", (gtirb_rewriting.abi._IA32_PE,))
def test_ia32_clobbers_flags(abi_class):
    abi = abi_class()
    constraints = gtirb_rewriting.Constraints(clobbers_flags=True)

    registers = abi._allocate_patch_registers(constraints)
    prologue, epilogue, stack_adjustment = abi._create_prologue_and_epilogue(
        constraints, registers, False
    )
    assert stack_adjustment == 4
    assert stringify_snippets(prologue) == remove_indentation(
        """
        pushfd
        """
    )
    assert stringify_snippets(epilogue) == remove_indentation(
        """
        popfd
        """
    )


@pytest.mark.parametrize(
    "abi_class",
    (gtirb_rewriting.abi._X86_64_ELF, gtirb_rewriting.abi._X86_64_PE),
)
def test_x64_clobbers_regs(abi_class):
    abi = abi_class()
    constraints = gtirb_rewriting.Constraints(
        clobbers_registers=("rdx", "rcx")
    )

    registers = abi._allocate_patch_registers(constraints)
    prologue, epilogue, stack_adjustment = abi._create_prologue_and_epilogue(
        constraints, registers, False
    )
    assert stack_adjustment == 16
    assert stringify_snippets(prologue) == remove_indentation(
        """
        pushq %rcx
        pushq %rdx
        """
    )
    assert stringify_snippets(epilogue) == remove_indentation(
        """
        popq %rdx
        popq %rcx
        """
    )


@pytest.mark.parametrize(
    "abi_class",
    (gtirb_rewriting.abi._X86_64_ELF, gtirb_rewriting.abi._X86_64_PE),
)
def test_x64_align_stack(abi_class):
    abi = abi_class()
    constraints = gtirb_rewriting.Constraints(align_stack=True)

    registers = abi._allocate_patch_registers(constraints)
    prologue, epilogue, stack_adjustment = abi._create_prologue_and_epilogue(
        constraints, registers, False
    )
    assert stack_adjustment is None
    assert stringify_snippets(prologue) == remove_indentation(
        """
        pushq   %rax
        movq    %rsp, %rax
        leaq    -0x80(%rsp), %rsp
        andq    $-0x10, %rsp
        pushq   %rax
        pushq   %rax
        """
    )
    assert stringify_snippets(epilogue) == remove_indentation(
        """
        popq    %rax
        movq    %rax, %rsp
        popq    %rax
        """
    )


@pytest.mark.parametrize(
    "abi_class",
    (gtirb_rewriting.abi._X86_64_ELF, gtirb_rewriting.abi._X86_64_PE),
)
def test_x64_clobbers_flags(abi_class):
    abi = abi_class()
    constraints = gtirb_rewriting.Constraints(clobbers_flags=True)

    registers = abi._allocate_patch_registers(constraints)
    prologue, epilogue, stack_adjustment = abi._create_prologue_and_epilogue(
        constraints, registers, False
    )
    assert stack_adjustment == 8
    assert stringify_snippets(prologue) == remove_indentation(
        """
        pushfq
        """
    )
    assert stringify_snippets(epilogue) == remove_indentation(
        """
        popfq
        """
    )


def test_x64_pe_no_red_zone():
    abi = gtirb_rewriting.abi._X86_64_PE()
    constraints = gtirb_rewriting.Constraints(clobbers_registers=("rax",))

    registers = abi._allocate_patch_registers(constraints)
    prologue, epilogue, stack_adjustment = abi._create_prologue_and_epilogue(
        constraints, registers, True
    )
    assert stack_adjustment == 8
    assert stringify_snippets(prologue) == remove_indentation(
        """
        pushq %rax
        """
    )
    assert stringify_snippets(epilogue) == remove_indentation(
        """
        popq %rax
        """
    )


def test_x64_elf_red_zone():
    abi = gtirb_rewriting.abi._X86_64_ELF()
    constraints = gtirb_rewriting.Constraints(clobbers_registers=("rax",))

    registers = abi._allocate_patch_registers(constraints)
    prologue, epilogue, stack_adjustment = abi._create_prologue_and_epilogue(
        constraints, registers, True
    )
    assert stack_adjustment == 128 + 8
    assert stringify_snippets(prologue) == remove_indentation(
        """
        leaq -128(%rsp), %rsp
        pushq %rax
        """
    )
    assert stringify_snippets(epilogue) == remove_indentation(
        """
        popq %rax
        leaq +128(%rsp), %rsp
        """
    )


def test_arm64_clobbers_registers():
    abi = gtirb_rewriting.abi._ARM64_ELF()
    constraints = gtirb_rewriting.Constraints(clobbers_registers=("x0", "x1"))

    registers = abi._allocate_patch_registers(constraints)
    prologue, epilogue, stack_adjustment = abi._create_prologue_and_epilogue(
        constraints, registers, False
    )
    assert stack_adjustment == 16
    assert stringify_snippets(prologue) == remove_indentation(
        """
        stp x0, x1, [sp, #-16]!
        """
    )
    assert stringify_snippets(epilogue) == remove_indentation(
        """
        ldp x0, x1, [sp], #16
        """
    )


def test_arm64_clobbers_flags():
    abi = gtirb_rewriting.abi._ARM64_ELF()
    constraints = gtirb_rewriting.Constraints(clobbers_flags=True)

    registers = abi._allocate_patch_registers(constraints)
    prologue, epilogue, stack_adjustment = abi._create_prologue_and_epilogue(
        constraints, registers, False
    )
    assert stack_adjustment == 32
    assert stringify_snippets(prologue) == remove_indentation(
        """
        str x0, [sp, #-16]!
        mrs x0, nzcv
        str x0, [sp, #-16]!
        """
    )
    assert stringify_snippets(epilogue) == remove_indentation(
        """
        ldr x0, [sp], #16
        msr nzcv, x0
        ldr x0, [sp], #16
        """
    )


def test_arm64_clobber_flags_and_registers():
    abi = gtirb_rewriting.abi._ARM64_ELF()
    constraints = gtirb_rewriting.Constraints(
        clobbers_flags=True,
        clobbers_registers=("x0", "x1"),
        scratch_registers=1,
    )

    registers = abi._allocate_patch_registers(constraints)
    assert len(registers.scratch_registers) == 1
    assert registers.scratch_registers[0] in registers.clobbered_registers
    assert registers.scratch_registers[0].name not in ("x0", "x1")

    prologue, epilogue, stack_adjustment = abi._create_prologue_and_epilogue(
        constraints, registers, False
    )
    assert stack_adjustment == 48
    assert stringify_snippets(prologue) == remove_indentation(
        """
        stp x0, x1, [sp, #-16]!
        str x2, [sp, #-16]!
        mrs x2, nzcv
        str x2, [sp, #-16]!
        """
    )
    assert stringify_snippets(epilogue) == remove_indentation(
        """
        ldr x2, [sp], #16
        msr nzcv, x2
        ldr x2, [sp], #16
        ldp x0, x1, [sp], #16
        """
    )


def test_arm64_stack_align():
    abi = gtirb_rewriting.abi._ARM64_ELF()
    constraints = gtirb_rewriting.Constraints(align_stack=True)

    registers = abi._allocate_patch_registers(constraints)
    assert not registers.clobbered_registers
    assert not registers.scratch_registers

    prologue, epilogue, stack_adjustment = abi._create_prologue_and_epilogue(
        constraints, registers, False
    )
    assert stack_adjustment == 0
    assert stringify_snippets(prologue) == ""
    assert stringify_snippets(epilogue) == ""


def test_arm64_caller_clobbers_fp_lr():
    abi = gtirb_rewriting.abi._ARM64_ELF()
    constraints = gtirb_rewriting.Constraints(clobbers_registers=("fp", "lr"))

    registers = abi._allocate_patch_registers(constraints)
    prologue, epilogue, stack_adjustment = abi._create_prologue_and_epilogue(
        constraints, registers, False
    )
    assert stack_adjustment == 16
    assert stringify_snippets(prologue) == remove_indentation(
        """
        stp x29, x30, [sp, #-16]!
        """
    )
    assert stringify_snippets(epilogue) == remove_indentation(
        """
        ldp x29, x30, [sp], #16
        """
    )


def test_arm64_scratch_regs():
    abi = gtirb_rewriting.abi._ARM64_ELF()

    # Try asking for too many registers
    constraints = gtirb_rewriting.Constraints(
        scratch_registers=len(abi.all_registers())
    )
    with pytest.raises(ValueError):
        registers = abi._allocate_patch_registers(constraints)

    # Now try for the max number we expect and verify that x16-x18 aren't
    # in it.
    constraints.scratch_registers = 26
    registers = abi._allocate_patch_registers(constraints)

    assert all(
        reg.name not in ("x16", "x17", "x18", "x29", "x30")
        for reg in registers.scratch_registers
    )


@pytest.mark.parametrize(
    "abi_class,skip_for_scratch",
    [
        (gtirb_rewriting.abi._IA32_PE, ("eax", "ebx")),
        (gtirb_rewriting.abi._X86_64_ELF, ("rax", "rbx")),
        (gtirb_rewriting.abi._ARM64_ELF, ("x0", "x1")),
    ],
)
def test_read_registers(abi_class, skip_for_scratch):
    abi = abi_class()
    constraints = gtirb_rewriting.Constraints(
        scratch_registers=1, reads_registers=skip_for_scratch
    )

    registers = abi._allocate_patch_registers(constraints)
    scratch = registers.scratch_registers

    assert all(reg.name not in skip_for_scratch for reg in scratch)
