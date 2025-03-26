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
import logging
from enum import Enum, auto
from typing import Dict, Iterable, List, Optional, Set, Tuple

import gtirb
import more_itertools
from typing_extensions import Literal, Protocol

from . import _auxdata
from .assembly import Constraints, Register, _AsmSnippet
from .utils import _is_elf_pie


class ABIDescriptor(Protocol):
    """
    An object that describes an ABI. This will typically be a GTIRB Module
    object.
    """

    file_format: gtirb.Module.FileFormat
    isa: gtirb.Module.ISA


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


@dataclasses.dataclass
class _SymExprAttributeRule:
    """
    A rule that describes how to convert symbolic expression attributes when
    a symbol goes from internal to external, or vice versa.
    """

    class AccessType(Enum):
        CONTROL_FLOW = auto()
        """
        The access is caused by control flow like a jump or call.
        """

        CODE_REF = auto()
        """
        The access is caused by a data access in code like a load or taking
        the address.
        """

        DATA = auto()
        """
        The access is caused by a reference in a data block.
        """

    internal_attrs: Set[gtirb.SymbolicExpression.Attribute]
    """
    The attributes for a symbolic expression targeting an internal symbol.
    """

    external_attrs: Set[gtirb.SymbolicExpression.Attribute]
    """
    The attributes for a symbolic expression targetting an external
    (undefined) symbol.
    """

    access_types: Set["_SymExprAttributeRule.AccessType"] = dataclasses.field(
        default_factory=lambda: set(_SymExprAttributeRule.AccessType)
    )
    """
    The access types that this rule applies to.
    """

    def get_relevant_attrs(
        self, internal: bool
    ) -> Set[gtirb.SymbolicExpression.Attribute]:
        return self.internal_attrs if internal else self.external_attrs


@dataclasses.dataclass
class _PatchRegisterAllocation:
    """
    The register allocation for a patch.
    """

    clobbered_registers: List[Register]
    """
    All general purpose registers that might be clobbered and need to be
    preserved. This includes the scratch registers.
    """

    scratch_registers: List[Register]
    """
    The registers that need to be pass to the patch as scratch registers.
    """

    available_registers: List[Register]
    """
    Any remaining general purpose registers that have not been allocated.
    """


class ABI:
    """
    Describes an application binary interface (ABI) and the instruction set
    architecture (ISA) beneath it.
    """

    def __init__(self) -> None:
        self._register_map: Dict[str, Register] = {}
        for reg in self.all_registers():
            for name in reg.sizes.values():
                self._register_map[name.lower()] = reg

    @classmethod
    def get(cls, format: ABIDescriptor) -> "ABI":
        """
        Gets the appropriate ABI object for a module.
        """
        result = _ABIS.get((format.isa, format.file_format))
        if result is None:
            raise NotImplementedError(
                f"Unsupported ISA/format: {format.isa}/{format.file_format}"
            )

        return result

    def _allocate_patch_registers(
        self, constraints: Constraints
    ) -> _PatchRegisterAllocation:
        """
        Allocates registers to satisfy a patch's constraints.
        """
        available_scratch_registers = list(self._scratch_registers())
        clobbered_registers: Set[Register] = set()

        for clobber in constraints.clobbers_registers:
            reg = self.get_register(clobber)
            if reg in available_scratch_registers:
                available_scratch_registers.remove(reg)
            clobbered_registers.add(reg)

        for read in constraints.reads_registers:
            reg = self.get_register(read)
            available_scratch_registers.remove(reg)

        if constraints.scratch_registers > len(available_scratch_registers):
            raise ValueError("unable to allocate enough scratch registers")

        scratch_registers = available_scratch_registers[
            : constraints.scratch_registers
        ]
        clobbered_registers.update(scratch_registers)

        if constraints.preserve_caller_saved_registers:
            clobbered_registers.update(self.caller_saved_registers())

        # We want deterministic register order out of this function, so we'll
        # sort it by the order the ABI class gave them out. This avoids
        # silliness like x1, x10, x2 that we'd get sorting by name.
        registers_indices = {
            reg: i for i, reg in enumerate(self.all_registers())
        }
        return _PatchRegisterAllocation(
            sorted(clobbered_registers, key=lambda r: registers_indices[r]),
            scratch_registers,
            available_scratch_registers,
        )

    def _create_prologue_and_epilogue(
        self,
        constraints: Constraints,
        register_use: _PatchRegisterAllocation,
        is_leaf_function: bool,
    ) -> Tuple[Iterable[_AsmSnippet], Iterable[_AsmSnippet], Optional[int]]:
        """
        Creates the prologue and epilogue needed to be able to insert a patch.
        :param constraints: The patch's constraints.
        :param registers: The register allocation for the patch.
        :param is_leaf_function: Is the patch being inserted into a potential
                                 leaf function?
        :returns: The prologue snippets, the epilogue snippets, and the amount
                  the prologue adjusted the stack (if known).
        """
        raise NotImplementedError

    def _scratch_registers(self) -> List[Register]:
        return self.all_registers()

    def get_register(self, name: str) -> Register:
        """
        Gets a Register object by its name (or the name of a subregister).
        """
        return self._register_map[name.lower()]

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

    def byteorder(self) -> Literal["little", "big"]:
        """
        The ABI's native endianness.
        """
        return "little"

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

    def temporary_label_prefix(self) -> str:
        """
        The prefix used to denote that a label is temporary.
        """
        raise NotImplementedError

    def default_dwarf_eh_return_column(self) -> int:
        """
        The default column used for the return address in the DWARF exception
        handling tables.
        """
        raise NotImplementedError

    def _sym_expr_rules(
        self, module: gtirb.Module
    ) -> Iterable[_SymExprAttributeRule]:
        return ()


class _IA32(ABI):
    def _create_prologue_and_epilogue(
        self,
        constraints: Constraints,
        register_use: _PatchRegisterAllocation,
        is_leaf_function: bool,
    ) -> Tuple[Iterable[_AsmSnippet], Iterable[_AsmSnippet], Optional[int]]:
        assert not self.red_zone_size()

        prologue: List[_AsmSnippet] = []
        epilogue: List[_AsmSnippet] = []
        stack_adjustment = 0
        knows_stack_adjustment = True

        if constraints.clobbers_flags:
            # TODO: Replace this with something more efficient.
            prologue.append(_AsmSnippet("pushfd"))
            epilogue.append(_AsmSnippet("popfd"))
            stack_adjustment += 4

        for reg in register_use.clobbered_registers:
            prologue.append(_AsmSnippet(f"push %{reg}"))
            epilogue.append(_AsmSnippet(f"pop %{reg}"))
            stack_adjustment += 4

        if constraints.align_stack:
            prologue.append(
                _AsmSnippet(
                    """
                    push   %eax
                    mov    %esp, %eax
                    lea    -0x80(%esp), %esp
                    and    $-0x10, %esp
                    push   %eax
                    push   %eax
                    """
                )
            )
            epilogue.append(
                _AsmSnippet(
                    """
                    pop    %eax
                    mov    %eax, %esp
                    pop    %eax
                    """
                )
            )
            # TODO: We don't know how much the stack may be adjusted by the
            #       snippet.
            knows_stack_adjustment = False

        return (
            prologue,
            reversed(epilogue),
            stack_adjustment if knows_stack_adjustment else None,
        )

    def all_registers(self) -> List[Register]:
        return [
            Register(
                {"8l": "al", "8h": "ah", "16": "ax", "32": "eax"},
                "32",
            ),
            Register(
                {"8l": "bl", "8h": "bh", "16": "bx", "32": "ebx"},
                "32",
            ),
            Register(
                {"8l": "cl", "8h": "ch", "16": "cx", "32": "ecx"},
                "32",
            ),
            Register(
                {"8l": "dl", "8h": "dh", "16": "dx", "32": "edx"},
                "32",
            ),
            Register({"8l": "sil", "16": "si", "32": "esi"}, "32"),
            Register({"8l": "dil", "16": "di", "32": "edi"}, "32"),
        ]

    def nop(self) -> bytes:
        return b"\x90"

    def pointer_size(self) -> int:
        return 4

    def stack_register(self) -> Register:
        return Register(
            {"16": "sp", "32": "esp"},
            "32",
        )


class _IA32_PE(_IA32):
    def caller_saved_registers(self) -> Set[Register]:
        return {self.get_register(name) for name in ("EAX", "ECX", "EDX")}

    def calling_convention(self) -> CallingConventionDesc:
        return CallingConventionDesc(
            registers=(),
            stack_alignment=4,
            caller_cleanup=True,
            shadow_space=0,
        )

    def temporary_label_prefix(self) -> str:
        return "L"


class _X86_64(ABI):
    def _create_prologue_and_epilogue(
        self,
        constraints: Constraints,
        register_use: _PatchRegisterAllocation,
        is_leaf_function: bool,
    ) -> Tuple[Iterable[_AsmSnippet], Iterable[_AsmSnippet], Optional[int]]:
        prologue: List[_AsmSnippet] = []
        epilogue: List[_AsmSnippet] = []
        stack_adjustment = 0
        knows_stack_adjustment = True

        # TODO: If align_stack was set too, we're going to end up doing
        #       some redundant work.
        if register_use.clobbered_registers or constraints.clobbers_flags:
            rz_size = self.red_zone_size()
            if rz_size and is_leaf_function:
                prologue.append(_AsmSnippet(f"leaq -{rz_size}(%rsp), %rsp"))
                epilogue.append(_AsmSnippet(f"leaq +{rz_size}(%rsp), %rsp"))
                stack_adjustment += self.red_zone_size()

        if constraints.clobbers_flags:
            # TODO: Replace this with something more efficient.
            prologue.append(_AsmSnippet("pushfq"))
            epilogue.append(_AsmSnippet("popfq"))
            stack_adjustment += 8

        for reg in register_use.clobbered_registers:
            prologue.append(_AsmSnippet(f"pushq %{reg}"))
            epilogue.append(_AsmSnippet(f"popq %{reg}"))
            stack_adjustment += 8

        if constraints.align_stack:
            prologue.append(
                _AsmSnippet(
                    """
                    pushq   %rax
                    movq    %rsp, %rax
                    leaq    -0x80(%rsp), %rsp
                    andq    $-0x10, %rsp
                    pushq   %rax
                    pushq   %rax
                    """
                )
            )
            epilogue.append(
                _AsmSnippet(
                    """
                    popq    %rax
                    movq    %rax, %rsp
                    popq    %rax
                    """
                )
            )
            # TODO: We don't know how much the stack may be adjusted by the
            #       snippet.
            knows_stack_adjustment = False

        return (
            prologue,
            reversed(epilogue),
            stack_adjustment if knows_stack_adjustment else None,
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
        return Register(
            {"16": "sp", "32": "esp", "64": "rsp"},
            "64",
        )


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

    def temporary_label_prefix(self) -> str:
        return ".L"


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

    def calling_convention(self) -> CallingConventionDesc:
        return CallingConventionDesc(
            registers=("RDI", "RSI", "RDX", "RCX", "R8", "R9"),
            stack_alignment=16,
            caller_cleanup=True,
        )

    def temporary_label_prefix(self) -> str:
        return ".L"

    def default_dwarf_eh_return_column(self) -> int:
        return 16

    def _sym_expr_rules(
        self, module: gtirb.Module
    ) -> Iterable[_SymExprAttributeRule]:
        if _is_elf_pie(
            module.file_format, _auxdata.binary_type.get_or_insert(module)
        ):
            return (
                _SymExprAttributeRule(
                    internal_attrs=set(),
                    external_attrs={
                        gtirb.SymbolicExpression.Attribute.GOT,
                        gtirb.SymbolicExpression.Attribute.PCREL,
                    },
                    access_types={_SymExprAttributeRule.AccessType.CODE_REF},
                ),
                _SymExprAttributeRule(
                    internal_attrs=set(),
                    external_attrs={gtirb.SymbolicExpression.Attribute.PLT},
                    access_types={
                        _SymExprAttributeRule.AccessType.CONTROL_FLOW,
                    },
                ),
            )
        else:
            return (
                _SymExprAttributeRule(
                    internal_attrs=set(),
                    external_attrs={gtirb.SymbolicExpression.Attribute.PLT},
                    access_types={
                        _SymExprAttributeRule.AccessType.CONTROL_FLOW,
                        _SymExprAttributeRule.AccessType.CODE_REF,
                    },
                ),
            )


class _ARM64_ELF(ABI):
    def _create_prologue_and_epilogue(
        self,
        constraints: Constraints,
        register_use: _PatchRegisterAllocation,
        is_leaf_function: bool,
    ) -> Tuple[Iterable[_AsmSnippet], Iterable[_AsmSnippet], Optional[int]]:
        prologue: List[_AsmSnippet] = []
        epilogue: List[_AsmSnippet] = []
        stack_adjustment = 0

        if constraints.align_stack:
            logging.getLogger(__name__).info(
                "align_stack is unneccessary for ARM64"
            )

        flags_reg = None
        if constraints.clobbers_flags:
            # ARM64 can't move the flags directly onto the stack, so we need
            # to have a register for this.
            if register_use.scratch_registers:
                # TODO: We could use a "reads_registers" constraint, which
                #       would allow us to repurpose any register that's
                #       clobbered for this as long as it isn't read.
                flags_reg = register_use.scratch_registers[0]
            else:
                flags_reg = register_use.available_registers.pop(0)
                register_use.clobbered_registers.append(flags_reg)

        # ARM64 requires sp be 16-byte aligned any time it is used as a base
        # register in an address operand. What we're going to do is push two
        # registers at a time.
        for reg1, reg2 in more_itertools.grouper(
            register_use.clobbered_registers, 2
        ):
            if reg2:
                prologue.append(
                    _AsmSnippet(f"stp {reg1}, {reg2}, [sp, #-16]!")
                )
                epilogue.append(_AsmSnippet(f"ldp {reg1}, {reg2}, [sp], #16"))
            else:
                prologue.append(_AsmSnippet(f"str {reg1}, [sp, #-16]!"))
                epilogue.append(_AsmSnippet(f"ldr {reg1}, [sp], #16"))
            stack_adjustment += 16

        if constraints.clobbers_flags:
            assert flags_reg is not None

            prologue.append(
                _AsmSnippet(
                    f"""
                    mrs {flags_reg}, nzcv
                    str {flags_reg}, [sp, #-16]!
                    """
                )
            )
            epilogue.append(
                _AsmSnippet(
                    f"""
                    ldr {flags_reg}, [sp], #16
                    msr nzcv, {flags_reg}
                    """
                ),
            )
            stack_adjustment += 16

        return prologue, reversed(epilogue), stack_adjustment

    def _inclusive_range(self, start: int, end: int) -> Iterable[int]:
        return range(start, end + 1)

    def _scratch_registers(self) -> List[Register]:
        # We don't consider x16, x17, and x18 as scratch registers because
        # they may be used for a specific purpose by the platform ABI. x29 and
        # x30 are used for the frame pointer and link register.
        return [
            reg
            for reg in self.all_registers()
            if reg.name not in ("x16", "x17", "x18", "x29", "x30")
        ]

    def all_registers(self) -> List[Register]:
        results = [
            Register({"64": f"x{i}", "32": f"w{i}"}, "64")
            for i in self._inclusive_range(0, 28)
        ]
        results.append(Register({"64": "x29", "32": "w29", "": "fp"}, "64"))
        results.append(Register({"64": "x30", "32": "w30", "": "lr"}, "64"))
        return results

    def nop(self) -> bytes:
        return b"\x1F\x20\x03\xD5"

    def caller_saved_registers(self) -> Set[Register]:
        results = {
            self.get_register(f"x{i}") for i in self._inclusive_range(0, 15)
        }
        results.add(self.get_register("x29"))
        results.add(self.get_register("x30"))
        return results

    def pointer_size(self) -> int:
        return 8

    def calling_convention(self) -> CallingConventionDesc:
        return CallingConventionDesc(
            registers=("x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"),
            stack_alignment=16,
            caller_cleanup=True,
            shadow_space=0,
        )

    def stack_register(self) -> Register:
        return Register({"64": "sp", "32": "wsp"}, "64")

    def temporary_label_prefix(self) -> str:
        return ".L"

    def default_dwarf_eh_return_column(self) -> int:
        return 32

    def _sym_expr_rules(
        self, module: gtirb.Module
    ) -> Iterable[_SymExprAttributeRule]:
        if _is_elf_pie(
            module.file_format, _auxdata.binary_type.get_or_insert(module)
        ):
            return (
                _SymExprAttributeRule(
                    internal_attrs={gtirb.SymbolicExpression.Attribute.LO12},
                    external_attrs={
                        gtirb.SymbolicExpression.Attribute.LO12,
                        gtirb.SymbolicExpression.Attribute.GOT,
                    },
                    access_types={_SymExprAttributeRule.AccessType.CODE_REF},
                ),
                _SymExprAttributeRule(
                    internal_attrs=set(),
                    external_attrs={gtirb.SymbolicExpression.Attribute.GOT},
                    access_types={_SymExprAttributeRule.AccessType.CODE_REF},
                ),
            )
        else:
            return ()


_ABIS: Dict[Tuple[gtirb.Module.ISA, gtirb.Module.FileFormat], ABI] = {
    (gtirb.Module.ISA.X64, gtirb.Module.FileFormat.PE): _X86_64_PE(),
    (gtirb.Module.ISA.X64, gtirb.Module.FileFormat.ELF): _X86_64_ELF(),
    (gtirb.Module.ISA.IA32, gtirb.Module.FileFormat.PE): _IA32_PE(),
    (gtirb.Module.ISA.ARM64, gtirb.Module.FileFormat.ELF): _ARM64_ELF(),
}
