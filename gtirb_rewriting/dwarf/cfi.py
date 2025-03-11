# GTIRB-Rewriting Rewriting API for GTIRB
# Copyright (C) 2023 GrammaTech, Inc.
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

import io
from dataclasses import fields
from typing import BinaryIO, ClassVar, Iterator, List, Set, Tuple

import leb128

from .._auxdata import NULL_UUID, CFIDirectiveType
from ._encodable import _encoded_field, _OpcodeEncodable
from ._encoders import (
    ByteOrder,
    _AddToOpcodeEncoder,
    _SLEB128Encoder,
    _StandaloneEncoder,
    _ULEB128Encoder,
)
from .dwarf2 import CallFrameInstructions
from .expr import Operation


class _ExprEncoder(_StandaloneEncoder[List[Operation]]):
    """
    Encode a sequence of DWARF operations.
    """

    def encode(
        self,
        value: List[Operation],
        byteorder: ByteOrder,
        ptr_size: int,
    ) -> bytearray:
        encoded_expr = b"".join(op.encode(byteorder, ptr_size) for op in value)
        return leb128.u.encode(len(encoded_expr)) + encoded_expr

    def decode(
        self, io: BinaryIO, byteorder: ByteOrder, ptr_size: int
    ) -> Tuple[List[Operation], int]:
        length, len_read = leb128.u.decode_reader(io)
        ops = []
        op_bytes_read = 0
        while op_bytes_read < length:
            op, op_read = Operation.decode(io, byteorder, ptr_size)
            ops.append(op)
            op_bytes_read += op_read
        return ops, len_read + op_bytes_read


class Instruction(
    _OpcodeEncodable[CallFrameInstructions],
    opcode_type=CallFrameInstructions,
):
    """
    A DWARF CFI instruction.
    """

    _registered_directives: ClassVar[Set[str]] = set()
    _directive: ClassVar[str]

    def __init_subclass__(
        cls,
        *,
        directive: str,
        opcode: CallFrameInstructions,
    ):
        super().__init_subclass__(opcode=opcode)

        if directive != ".cfi_escape":
            if directive in cls._registered_directives:
                raise AssertionError("directive already registered")
            cls._registered_directives.add(directive)

        cls._directive = directive

    def _operands(self, byteorder: ByteOrder, ptr_size: int) -> List[int]:
        """
        Convert the instruction's fields into assembly operands.
        """
        if self._directive == ".cfi_escape":
            encoded = self.encode(byteorder, ptr_size)
            return list(encoded)

        return [getattr(self, field.name) for field in fields(self)]

    def gtirb_encoding(
        self, byteorder: ByteOrder, ptr_size: int
    ) -> CFIDirectiveType:
        return self._directive, self._operands(byteorder, ptr_size), NULL_UUID

    def assembly_string(self, byteorder: ByteOrder, ptr_size: int) -> str:
        args = self._operands(byteorder, ptr_size)
        if args:
            return self._directive + " " + ", ".join(str(arg) for arg in args)
        else:
            return self._directive


# ----------------------------------------------------------------------------
# CFA Definition Instructions
# ----------------------------------------------------------------------------
class InstDefCFA(
    Instruction,
    directive=".cfi_def_cfa",
    opcode=CallFrameInstructions.def_cfa,
):
    """
    The DW_CFA_def_cfa instruction takes two unsigned LEB128 operands
    representing a register number and a (non-factored) offset. The required
    action is to define the current CFA rule to use the provided register and
    offset.
    """

    register: int = _encoded_field(_ULEB128Encoder())
    offset: int = _encoded_field(_ULEB128Encoder())


class InstDefCFASF(
    Instruction,
    directive=".cfi_escape",
    opcode=CallFrameInstructions.def_cfa_sf,
):
    """
    The DW_CFA_def_cfa_sf instruction takes two operands: an unsigned LEB128
    value representing a register number and a signed LEB128 factored offset.
    This instruction is identical to DW_CFA_def_cfa except that the second
    operand is signed and factored. The resulting offset is factored_offset
    * data_alignment_factor.
    """

    register: int = _encoded_field(_ULEB128Encoder())
    factored_offset: int = _encoded_field(_SLEB128Encoder())


class InstDefCFARegister(
    Instruction,
    directive=".cfi_def_cfa_register",
    opcode=CallFrameInstructions.def_cfa_register,
):
    """
    The DW_CFA_def_cfa_register instruction takes a single unsigned LEB128
    operand representing a register number. The required action is to define
    the current CFA rule to use the provided register (but to keep the old
    offset). This operation is valid only if the current CFA rule is defined
    to use a register and offset.
    """

    register: int = _encoded_field(_ULEB128Encoder())


class InstDefCFAOffset(
    Instruction,
    directive=".cfi_escape",
    opcode=CallFrameInstructions.def_cfa_offset,
):
    """
    The DW_CFA_def_cfa_offset instruction takes a single unsigned LEB128
    operand representing a (non-factored) offset. The required action is to
    define the current CFA rule to use the provided offset (but to keep the
    old register). This operation is valid only if the current CFA rule is
    defined to use a register and offset.
    """

    offset: int = _encoded_field(_ULEB128Encoder())


class InstDefCFAOffsetSF(
    Instruction,
    directive=".cfi_escape",
    opcode=CallFrameInstructions.def_cfa_offset_sf,
):
    """
    The DW_CFA_def_cfa_offset_sf instruction takes a signed LEB128 operand
    representing a factored offset. This instruction is identical to
    DW_CFA_def_cfa_offset except that the operand is signed and factored. The
    resulting offset is factored_offset * data_alignment_factor. This
    operation is valid only if the current CFA rule is defined to use a
    register and offset.
    """

    factored_offset: int = _encoded_field(_SLEB128Encoder())


class InstDefCFAExpression(
    Instruction,
    directive=".cfi_escape",
    opcode=CallFrameInstructions.def_cfa_expression,
):
    """
    The DW_CFA_def_cfa_expression instruction takes a single operand encoded
    as a DW_FORM_exprloc value representing a DWARF expression. The required
    action is to establish that expression as the means by which the current
    CFA is computed.
    """

    expression: List[Operation] = _encoded_field(_ExprEncoder())


# ----------------------------------------------------------------------------
# Register Rule Instructions
# ----------------------------------------------------------------------------
class InstUndefined(
    Instruction,
    directive=".cfi_undefined",
    opcode=CallFrameInstructions.undefined,
):
    """
    The DW_CFA_undefined instruction takes a single unsigned LEB128 operand
    that represents a register number. The required action is to set the rule
    for the specified register to “undefined.”
    """

    register: int = _encoded_field(_ULEB128Encoder())


class InstSameValue(
    Instruction,
    directive=".cfi_same_value",
    opcode=CallFrameInstructions.same_value,
):
    """
    The DW_CFA_same_value instruction takes a single unsigned LEB128 operand
    that represents a register number. The required action is to set the rule
    for the specified register to “same value.”
    """

    register: int = _encoded_field(_ULEB128Encoder())


class InstOffset(
    Instruction,
    directive=".cfi_escape",
    opcode=CallFrameInstructions.offset,
):
    """
    The DW_CFA_offset instruction takes two operands: a register number
    (encoded with the opcode) and an unsigned LEB128 constant representing a
    factored offset. The required action is to change the rule for the
    register indicated by the register number to be an offset(N) rule where
    the value of N is factored offset * data_alignment_factor.
    """

    register: int = _encoded_field(_AddToOpcodeEncoder(64))
    factored_offset: int = _encoded_field(_ULEB128Encoder())


class InstOffsetExtended(
    Instruction,
    directive=".cfi_escape",
    opcode=CallFrameInstructions.offset_extended,
):
    """
    The DW_CFA_offset_extended instruction takes two unsigned LEB128 operands
    representing a register number and a factored offset. This instruction is
    identical to DW_CFA_offset except for the encoding and size of the
    register operand.
    """

    register: int = _encoded_field(_ULEB128Encoder())
    factored_offset: int = _encoded_field(_ULEB128Encoder())


class InstOffsetExtendedSF(
    Instruction,
    directive=".cfi_escape",
    opcode=CallFrameInstructions.offset_extended_sf,
):
    """
    The DW_CFA_offset_extended_sf instruction takes two operands: an unsigned
    LEB128 value representing a register number and a signed LEB128 factored
    offset. This instruction is identical to DW_CFA_offset_extended except
    that the second operand is signed and factored. The resulting offset is
    factored_offset * data_alignment_factor.
    """

    register: int = _encoded_field(_ULEB128Encoder())
    factored_offset: int = _encoded_field(_SLEB128Encoder())


class InstValOffset(
    Instruction,
    directive=".cfi_escape",
    opcode=CallFrameInstructions.val_offset,
):
    """
    The DW_CFA_val_offset instruction takes two unsigned LEB128 operands
    representing a register number and a factored offset. The required action
    is to change the rule for the register indicated by the register number to
    be a val_offset(N) rule where the value of N is
    factored_offset * data_alignment_factor.
    """

    register: int = _encoded_field(_ULEB128Encoder())
    factored_offset: int = _encoded_field(_ULEB128Encoder())


class InstValOffsetSF(
    Instruction,
    directive=".cfi_escape",
    opcode=CallFrameInstructions.val_offset_sf,
):
    """
    The DW_CFA_val_offset_sf instruction takes two operands: an unsigned
    LEB128 value representing a register number and a signed LEB128 factored
    offset. This instruction is identical to DW_CFA_val_offset except that the
    second operand is signed and factored. The resulting offset is
    factored_offset * data_alignment_factor.
    """

    register: int = _encoded_field(_ULEB128Encoder())
    factored_offset: int = _encoded_field(_SLEB128Encoder())


class InstRegister(
    Instruction,
    directive=".cfi_register",
    opcode=CallFrameInstructions.register,
):
    """
    The DW_CFA_register instruction takes two unsigned LEB128 operands
    representing register numbers. The required action is to set the rule for
    the first register to be register(R) where R is the second register.
    """

    register1: int = _encoded_field(_ULEB128Encoder())
    register2: int = _encoded_field(_ULEB128Encoder())


class InstExpression(
    Instruction,
    directive=".cfi_escape",
    opcode=CallFrameInstructions.expression,
):
    """
    The DW_CFA_expression instruction takes two operands: an unsigned LEB128
    value representing a register number, and a DW_FORM_block value
    representing a DWARF expression. The required action is to change the rule
    for the register indicated by the register number to be an expression(E)
    rule where E is the DWARF expression. That is, the DWARF expression
    computes the address. The value of the CFA is pushed on the DWARF
    evaluation stack prior to execution of the DWARF expression.
    """

    register: int = _encoded_field(_ULEB128Encoder())
    expression: List[Operation] = _encoded_field(_ExprEncoder())


class InstValExpression(
    Instruction,
    directive=".cfi_escape",
    opcode=CallFrameInstructions.val_expression,
):
    """
    The DW_CFA_val_expression instruction takes two operands: an unsigned
    LEB128 value representing a register number, and a DW_FORM_block value
    representing a DWARF expression. The required action is to change the rule
    for the register indicated by the register number to be a
    val_expression(E) rule where E is the DWARF expression. That is, the DWARF
    expression computes the value of the given register. The value of the CFA
    is pushed on the DWARF evaluation stack prior to execution of the DWARF
    expression.
    """

    register: int = _encoded_field(_ULEB128Encoder())
    expression: List[Operation] = _encoded_field(_ExprEncoder())


class InstRestore(
    Instruction,
    directive=".cfi_restore",
    opcode=CallFrameInstructions.restore,
):
    """
    The DW_CFA_restore instruction takes a single operand (encoded with the
    opcode) that represents a register number. The required action is to
    change the rule for the indicated register to the rule assigned it by the
    initial_instructions in the CIE.
    """

    register: int = _encoded_field(_AddToOpcodeEncoder(64))


class InstRestoreExtended(
    Instruction,
    directive=".cfi_escape",
    opcode=CallFrameInstructions.restore_extended,
):
    """
    The DW_CFA_restore_extended instruction takes a single unsigned LEB128
    operand that represents a register number. This instruction is identical
    to DW_CFA_restore except for the encoding and size of the register
    operand.
    """

    register: int = _encoded_field(_ULEB128Encoder())


# ----------------------------------------------------------------------------
# Row State Instructions
# ----------------------------------------------------------------------------
class InstRememberState(
    Instruction,
    directive=".cfi_remember_state",
    opcode=CallFrameInstructions.remember_state,
):
    """
    The DW_CFA_remember_state instruction takes no operands. The required
    action is to push the set of rules for every register onto an implicit
    stack.
    """


class InstRestoreState(
    Instruction,
    directive=".cfi_restore_state",
    opcode=CallFrameInstructions.restore_state,
):
    """
    The DW_CFA_restore_state instruction takes no operands. The required
    action is to pop the set of rules off the implicit stack and place them in
    the current row.
    """


# ----------------------------------------------------------------------------
# Padding Instructions
# ----------------------------------------------------------------------------
class InstNop(
    Instruction,
    directive=".cfi_escape",
    opcode=CallFrameInstructions.nop,
):
    """
    The DW_CFA_nop instruction has no operands and no required actions. It is
    used as padding to make a CIE or FDE an appropriate size.
    """


# ----------------------------------------------------------------------------
# Instruction parsing
# ----------------------------------------------------------------------------
def parse_cfi_instructions(
    value: bytes, byteorder: ByteOrder, ptr_size: int
) -> Iterator[Instruction]:
    """
    Decode CFI instructions from a byte sequence.
    """
    reader = io.BytesIO(value)
    offset = 0
    while offset < len(value):
        inst, read = Instruction.decode(reader, byteorder, ptr_size)
        offset += read
        yield inst
