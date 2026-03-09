# GTIRB-Rewriting Rewriting API for GTIRB
# Copyright (C) 2024 GrammaTech, Inc.
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

import uuid
from copy import copy
from dataclasses import dataclass, field
from typing import (
    Dict,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Tuple,
    Union,
)

import gtirb
from typing_extensions import Self

from .. import _auxdata_offsetmap
from .._auxdata import NULL_UUID
from ..abi import ABI
from . import cfi
from .dwarf2 import PointerEncodings
from .expr import Operation


class CFIStateError(Exception):
    """
    The CFI instructions created an invalid state.
    """


@dataclass(frozen=True)
class RegisterUndefined:
    """
    A register that has this rule has no recoverable value in the previous
    frame. (By convention, it is not preserved by a callee.)
    """


@dataclass(frozen=True)
class RegisterSameValue:
    """
    This register has not been modified from the previous frame. (By
    convention, it is preserved by the callee, but the callee has not modified
    it.)
    """


@dataclass(frozen=True)
class RegisterOffset:
    """
    The previous value of this register is saved at the address CFA+N where
    CFA is the current CFA value and N is a signed offset.
    """

    offset: int


@dataclass(frozen=True)
class RegValOffset:
    """
    The previous value of this register is the value CFA+N where CFA is the
    current CFA value and N is a signed offset.
    """

    offset: int


@dataclass(frozen=True)
class RegisterInRegister:
    """
    The previous value of this register is stored in another register numbered
    R.
    """

    register: int


@dataclass(frozen=True)
class RegisterAtExpression:
    """
    The previous value of this register is located at the address produced by
    executing the DWARF expression E.
    """

    expression: Tuple[Operation, ...]


@dataclass(frozen=True)
class RegisterIsExpression:
    """
    The previous value of this register is the value produced by executing the
    DWARF expression E.
    """

    expression: Tuple[Operation, ...]


@dataclass(frozen=True)
class CFARegisterOffset:
    """
    The CFA address is the value of register R and offset N.
    """

    register: int
    offset: int


@dataclass(frozen=True)
class CFAExpression:
    """
    The CFA address is the value produced by executing the DWARF expression E.
    """

    expression: Tuple[Operation, ...]


RegisterRule = Union[
    RegisterUndefined,
    RegisterSameValue,
    RegisterOffset,
    RegValOffset,
    RegisterInRegister,
    RegisterAtExpression,
    RegisterIsExpression,
]
CFARule = Union[CFARegisterOffset, CFAExpression]


@dataclass(frozen=True)
class EncodedPointer:
    encoding: PointerEncodings
    symbol: gtirb.Symbol


@dataclass
class RowState:
    """
    The row state defines the rules to restore registers at a given program
    state. This includes the return register, which may not be an
    architectural register.
    """

    registers: Dict[int, RegisterRule]
    cfa: Optional[CFARule]

    def __init__(
        self,
        registers: Mapping[int, RegisterRule] = {},
        cfa: Optional[CFARule] = None,
    ):
        self.registers = dict(registers)
        self.cfa = cfa

    def __copy__(self) -> Self:
        return type(self)(
            registers=copy(self.registers),
            cfa=self.cfa,
        )


@dataclass
class ProcedureState:
    """
    The CFI state at a given program point.
    """

    return_column: int
    """The column that stores the rule for the return address."""
    personality: Optional[EncodedPointer] = None
    """The language-specific personality function to unwind this frame."""
    lsda: Optional[EncodedPointer] = None
    """The language-specific data for the frame."""
    current: RowState = field(default_factory=RowState)
    """The current state of the registers."""
    initial: RowState = field(default_factory=RowState)
    """The initial state of the registers."""
    save_stack: List[RowState] = field(default_factory=list)
    """The saved state stack, used by remember/restore instructions."""

    def __copy__(self) -> Self:
        return type(self)(
            return_column=self.return_column,
            personality=self.personality,
            lsda=self.lsda,
            current=copy(self.current),
            initial=copy(self.initial),
            save_stack=[copy(entry) for entry in self.save_stack],
        )


def evaluate_cfi_directives(
    m: gtirb.Module, blocks: Iterable[gtirb.CodeBlock]
) -> Iterator[Tuple[gtirb.CodeBlock, int, Optional[ProcedureState]]]:
    """
    Evaluate CFI directives for the given blocks. The blocks must be
    non-overlapping and sequential (with gaps for padding being allowed).
    The blocks should have complete CFI procedures; starting evaluation mid-
    procedure will cause an exception to be raised.

    CFI states will be yielded at each place there are CFI directives in the
    aux data table.
    """

    def address_key(block: gtirb.CodeBlock) -> int:
        if block.address is None:
            raise ValueError("all blocks must have an address")
        return block.address

    abi = ABI.get(m)
    cfi_directives = _auxdata_offsetmap.cfi_directives.get(m)
    if cfi_directives is None:
        return

    state: Optional[ProcedureState] = None
    for block in sorted(blocks, key=address_key):
        block_directives = cfi_directives.get(block)
        if block_directives is None:
            continue

        for block_offset, directives in sorted(block_directives.items()):
            started_procedure = False
            for directive in directives:
                name, args, sym_or_uuid = directive

                if name == ".cfi_startproc":
                    if state is not None:
                        raise CFIStateError(
                            "encountered .cfi_startproc already inside CFI "
                            "procedure"
                        )
                    state = ProcedureState(
                        return_column=abi.default_dwarf_eh_return_column()
                    )
                    started_procedure = True
                elif state is None:
                    raise CFIStateError(
                        "encountered CFI instruction while not inside CFI "
                        "procedure"
                    )
                elif name == ".cfi_endproc":
                    state = None
                # Procedure-wide state (stored in the FDE in reality)
                elif name == ".cfi_personality":
                    (encoding,) = args
                    pointer_encoding = PointerEncodings(encoding)
                    if pointer_encoding == PointerEncodings.omit:
                        state.personality = None
                    else:
                        state.personality = EncodedPointer(
                            PointerEncodings(encoding),
                            _resolve_cfi_symbol(sym_or_uuid),
                        )
                elif name == ".cfi_lsda":
                    (encoding,) = args
                    pointer_encoding = PointerEncodings(encoding)
                    if pointer_encoding == PointerEncodings.omit:
                        state.lsda = None
                    else:
                        state.lsda = EncodedPointer(
                            PointerEncodings(encoding),
                            _resolve_cfi_symbol(sym_or_uuid),
                        )
                elif name == ".cfi_return_column":
                    (column,) = args
                    state.return_column = column
                # CFA rule instructions
                elif name == ".cfi_def_cfa":
                    register, offset = args
                    state.current.cfa = CFARegisterOffset(register, offset)
                elif name == ".cfi_def_cfa_register":
                    (register,) = args
                    if not isinstance(state.current.cfa, CFARegisterOffset):
                        raise CFIStateError(
                            ".cfi_def_cfa_register encountered when the CFA "
                            "is not a register+offset"
                        )
                    state.current.cfa = CFARegisterOffset(
                        register, state.current.cfa.offset
                    )
                elif name == ".cfi_def_cfa_offset":
                    (offset,) = args
                    if not isinstance(state.current.cfa, CFARegisterOffset):
                        raise CFIStateError(
                            ".cfi_def_cfa_offset encountered when the CFA "
                            "is not a register+offset"
                        )
                    state.current.cfa = CFARegisterOffset(
                        state.current.cfa.register, offset
                    )
                elif name == ".cfi_adjust_cfa_offset":
                    (offset,) = args
                    if not isinstance(state.current.cfa, CFARegisterOffset):
                        raise CFIStateError(
                            ".cfi_adjust_cfa_offset encountered when the "
                            "CFA is not a register+offset"
                        )
                    state.current.cfa = CFARegisterOffset(
                        state.current.cfa.register,
                        state.current.cfa.offset + offset,
                    )
                # Register rule instructions
                elif name == ".cfi_undefined":
                    (register,) = args
                    state.current.registers[register] = RegisterUndefined()
                elif name == ".cfi_same_value":
                    (register,) = args
                    state.current.registers[register] = RegisterSameValue()
                elif name == ".cfi_register":
                    register1, register2 = args
                    state.current.registers[register1] = RegisterInRegister(
                        register2
                    )
                elif name == ".cfi_restore":
                    (register,) = args
                    if register in state.initial.registers:
                        state.current.registers[
                            register
                        ] = state.initial.registers[register]
                    else:
                        state.current.registers.pop(register)
                elif name == ".cfi_val_offset":
                    register, offset = args
                    state.current.registers[register] = RegValOffset(offset)
                elif name == ".cfi_offset":
                    register, offset = args
                    state.current.registers[register] = RegisterOffset(offset)
                elif name == ".cfi_rel_offset":
                    (
                        register,
                        offset,
                    ) = args
                    current_rule = state.current.registers.get(register)
                    if not isinstance(current_rule, RegisterOffset):
                        raise CFIStateError(
                            ".cfi_rel_offset encountered when the register "
                            "is not CFA+offset"
                        )
                    state.current.registers[register] = RegisterOffset(
                        current_rule.offset + offset
                    )
                # Row state instructions
                elif name == ".cfi_remember_state":
                    state.save_stack.append(copy(state.current))
                elif name == ".cfi_restore_state":
                    if not state.save_stack:
                        raise CFIStateError(
                            ".cfi_restore_state encountered with the save "
                            "stack is empty"
                        )
                    state.current = state.save_stack.pop()
                # Instructions that are escaped. For ddisasm's output, this
                # only needs to handle instructions that aren't represented as
                # assembly directives.
                elif name == ".cfi_escape":
                    for inst in cfi.parse_cfi_instructions(
                        bytes(args), abi.byteorder(), abi.pointer_size()
                    ):
                        if isinstance(inst, cfi.InstDefCFAExpression):
                            state.current.cfa = CFAExpression(
                                tuple(inst.expression)
                            )
                        elif isinstance(inst, cfi.InstExpression):
                            state.current.registers[
                                inst.register
                            ] = RegisterAtExpression(tuple(inst.expression))
                        elif isinstance(inst, cfi.InstValExpression):
                            state.current.registers[
                                inst.register
                            ] = RegisterIsExpression(tuple(inst.expression))
                        elif isinstance(inst, cfi.InstNop):
                            pass
                        else:
                            raise NotImplementedError(
                                f"unsupported instruction: {inst}"
                            )
                else:
                    raise NotImplementedError(f"unsupported directive: {name}")

            # GTIRB does not record which instructions come from the CIE and
            # which come from the FDE, so we'll treat any instructions at the
            # same offset as the .cfi_startproc as being in the prologue. This
            # is not strictly correct but should work for compiler-generated
            # code and matches LLDB's behavior.
            if state and started_procedure:
                state.initial = copy(state.current)

            yield block, block_offset, state


def _resolve_cfi_symbol(sym: Union[uuid.UUID, gtirb.Symbol]) -> gtirb.Symbol:
    """
    Resolve the symbol or UUID that is stored in the `cfiDirectives` aux data
    table into a symbol. Any UUIDs other than the null UUID indicate a
    deserialization error (referring to a symbol that has been removed).
    """
    if isinstance(sym, uuid.UUID):
        if sym != NULL_UUID:
            raise ValueError(f"CFI directive refers to missing UUID {sym}")
        raise ValueError("CFI directive should have a symbol")

    return sym
