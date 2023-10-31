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

import abc
from dataclasses import Field, dataclass, fields
from typing import ClassVar, List, Optional, Set, Tuple

import leb128
from typing_extensions import Literal, dataclass_transform, override

from .._auxdata import NULL_UUID, CFIDirectiveType
from ._encoders import _Encoder, _SLEB128Encoder, _ULEB128Encoder
from .dwarf2 import CallFrameInstructions
from .expr import Operation


class _ExprEncoder(_Encoder[List[Operation]]):
    def encode(
        self,
        value: List[Operation],
        byteorder: Literal["big", "little"],
        ptr_size: int,
    ) -> bytes:
        encoded_expr = b"".join(op.encode(byteorder, ptr_size) for op in value)
        return leb128.u.encode(len(encoded_expr)) + encoded_expr


_Low6Bits = _Encoder()


class Instruction:
    """
    A DWARF CFI instruction.
    """

    @abc.abstractmethod
    def assembly_string(
        self, byteorder: Literal["big", "little"], ptr_size: int
    ) -> str:
        ...

    @abc.abstractmethod
    def gtirb_encoding(
        self, byteorder: Literal["big", "little"], ptr_size: int
    ) -> CFIDirectiveType:
        ...


@dataclass_transform()
class _SimpleInstruction(Instruction):
    _registered_opcodes: ClassVar[Set[CallFrameInstructions]] = set()
    _registered_directives: ClassVar[Set[str]] = set()

    _directive: ClassVar[str]  # type: ignore
    _opcode: ClassVar[Optional[CallFrameInstructions]]  # type: ignore
    _encoding: ClassVar[List[_Encoder]]  # type: ignore

    def __init_subclass__(
        cls,
        *,
        directive: str,
        opcode: Optional[CallFrameInstructions],
        encoding: List[_Encoder],
    ):
        dataclass(cls)

        if opcode is not None:
            if opcode in _SimpleInstruction._registered_opcodes:
                raise AssertionError("instruction already registered")
            _SimpleInstruction._registered_opcodes.add(opcode)

            if len(cls._fields()) != len(encoding):
                raise AssertionError("wrong number of fields vs encoders")

        if directive != ".cfi_escape":
            if directive in _SimpleInstruction._registered_directives:
                raise AssertionError("directive already registered")
            _SimpleInstruction._registered_directives.add(directive)

        cls._directive = directive
        cls._opcode = opcode
        cls._encoding = encoding

    @classmethod
    def _fields(cls) -> Tuple[Field]:
        return fields(cls)  # type: ignore

    def _operands(
        self, byteorder: Literal["big", "little"], ptr_size: int
    ) -> List[int]:
        field_values = [getattr(self, field.name) for field in self._fields()]
        if self._directive != ".cfi_escape":
            return field_values

        assert self._opcode is not None
        result = [self._opcode.value]
        for value, encoder in zip(field_values, self._encoding):
            if encoder is _Low6Bits:
                result[0] |= value
            else:
                result.extend(encoder.encode(value, byteorder, ptr_size))

        return result

    @override
    def gtirb_encoding(
        self, byteorder: Literal["big", "little"], ptr_size: int
    ) -> CFIDirectiveType:
        return self._directive, self._operands(byteorder, ptr_size), NULL_UUID

    @override
    def assembly_string(
        self, byteorder: Literal["big", "little"], ptr_size: int
    ) -> str:
        args = self._operands(byteorder, ptr_size)
        if args:
            return self._directive + " " + ", ".join(str(arg) for arg in args)
        else:
            return self._directive


# ----------------------------------------------------------------------------
# CFA Definition Instructions
# ----------------------------------------------------------------------------
class InstDefCFA(
    _SimpleInstruction,
    directive=".cfi_def_cfa",
    opcode=CallFrameInstructions.def_cfa,
    encoding=[_ULEB128Encoder(), _ULEB128Encoder()],
):
    """
    The DW_CFA_def_cfa instruction takes two unsigned LEB128 operands
    representing a register number and a (non-factored) offset. The required
    action is to define the current CFA rule to use the provided register and
    offset.
    """

    register: int
    offset: int


class InstDefCFASF(
    _SimpleInstruction,
    directive=".cfi_escape",
    opcode=CallFrameInstructions.def_cfa_sf,
    encoding=[_ULEB128Encoder(), _SLEB128Encoder()],
):
    """
    The DW_CFA_def_cfa_sf instruction takes two operands: an unsigned LEB128
    value representing a register number and a signed LEB128 factored offset.
    This instruction is identical to DW_CFA_def_cfa except that the second
    operand is signed and factored. The resulting offset is factored_offset
    * data_alignment_factor.
    """

    register: int
    factored_offset: int


class InstDefCFARegister(
    _SimpleInstruction,
    directive=".cfi_def_cfa_register",
    opcode=CallFrameInstructions.def_cfa_register,
    encoding=[_ULEB128Encoder()],
):
    """
    The DW_CFA_def_cfa_register instruction takes a single unsigned LEB128
    operand representing a register number. The required action is to define
    the current CFA rule to use the provided register (but to keep the old
    offset). This operation is valid only if the current CFA rule is defined
    to use a register and offset.
    """

    register: int


class InstDefCFAOffset(
    _SimpleInstruction,
    directive=".cfi_def_cfa_offset",
    opcode=CallFrameInstructions.def_cfa_offset,
    encoding=[_ULEB128Encoder()],
):
    """
    The DW_CFA_def_cfa_offset instruction takes a single unsigned LEB128
    operand representing a (non-factored) offset. The required action is to
    define the current CFA rule to use the provided offset (but to keep the
    old register). This operation is valid only if the current CFA rule is
    defined to use a register and offset.
    """

    offset: int


class InstDefCFAOffsetSF(
    _SimpleInstruction,
    directive=".cfi_escape",
    opcode=CallFrameInstructions.def_cfa_expression,
    encoding=[_ExprEncoder()],
):
    """
    The DW_CFA_def_cfa_expression instruction takes a single operand encoded
    as a DW_FORM_exprloc value representing a DWARF expression. The required
    action is to establish that expression as the means by which the current
    CFA is computed.
    """

    expression: List[Operation]


# ----------------------------------------------------------------------------
# Register Rule Instructions
# ----------------------------------------------------------------------------
class InstUndefined(
    _SimpleInstruction,
    directive=".cfi_undefined",
    opcode=CallFrameInstructions.undefined,
    encoding=[_ULEB128Encoder()],
):
    """
    The DW_CFA_undefined instruction takes a single unsigned LEB128 operand
    that represents a register number. The required action is to set the rule
    for the specified register to “undefined.”
    """

    register: int


class InstSameValue(
    _SimpleInstruction,
    directive=".cfi_same_value",
    opcode=CallFrameInstructions.same_value,
    encoding=[_ULEB128Encoder()],
):
    """
    The DW_CFA_same_value instruction takes a single unsigned LEB128 operand
    that represents a register number. The required action is to set the rule
    for the specified register to “same value.”
    """

    register: int


class InstOffset(
    _SimpleInstruction,
    directive=".cfi_offset",
    opcode=CallFrameInstructions.offset,
    encoding=[_Low6Bits, _ULEB128Encoder()],
):
    """
    The DW_CFA_offset instruction takes two operands: a register number
    (encoded with the opcode) and an unsigned LEB128 constant representing a
    factored offset. The required action is to change the rule for the
    register indicated by the register number to be an offset(N) rule where
    the value of N is factored offset * data_alignment_factor.
    """

    register: int
    factored_offset: int


class InstOffsetExtended(
    _SimpleInstruction,
    directive=".cfi_escape",
    opcode=CallFrameInstructions.offset_extended,
    encoding=[_ULEB128Encoder(), _ULEB128Encoder()],
):
    """
    The DW_CFA_offset_extended instruction takes two unsigned LEB128 operands
    representing a register number and a factored offset. This instruction is
    identical to DW_CFA_offset except for the encoding and size of the
    register operand.
    """

    register: int
    factored_offset: int


class InstOffsetExtendedSF(
    _SimpleInstruction,
    directive=".cfi_escape",
    opcode=CallFrameInstructions.offset_extended_sf,
    encoding=[_ULEB128Encoder(), _SLEB128Encoder()],
):
    """
    The DW_CFA_offset_extended_sf instruction takes two operands: an unsigned
    LEB128 value representing a register number and a signed LEB128 factored
    offset. This instruction is identical to DW_CFA_offset_extended except
    that the second operand is signed and factored. The resulting offset is
    factored_offset * data_alignment_factor.
    """

    register: int
    factored_offset: int


class InstValOffset(
    _SimpleInstruction,
    directive=".cfi_val_offset",
    opcode=CallFrameInstructions.val_offset,
    encoding=[_ULEB128Encoder(), _ULEB128Encoder()],
):
    """
    The DW_CFA_val_offset instruction takes two unsigned LEB128 operands
    representing a register number and a factored offset. The required action
    is to change the rule for the register indicated by the register number to
    be a val_offset(N) rule where the value of N is
    factored_offset * data_alignment_factor.
    """

    register: int
    factored_offset: int


class InstValOffsetSF(
    _SimpleInstruction,
    directive=".cfi_escape",
    opcode=CallFrameInstructions.val_offset_sf,
    encoding=[_ULEB128Encoder(), _SLEB128Encoder()],
):
    """
    The DW_CFA_val_offset_sf instruction takes two operands: an unsigned
    LEB128 value representing a register number and a signed LEB128 factored
    offset. This instruction is identical to DW_CFA_val_offset except that the
    second operand is signed and factored. The resulting offset is
    factored_offset * data_alignment_factor.
    """

    register: int
    factored_offset: int


class InstRegister(
    _SimpleInstruction,
    directive=".cfi_register",
    opcode=CallFrameInstructions.register,
    encoding=[_ULEB128Encoder(), _SLEB128Encoder()],
):
    """
    The DW_CFA_register instruction takes two unsigned LEB128 operands
    representing register numbers. The required action is to set the rule for
    the first register to be register(R) where R is the second register.
    """

    register1: int
    register2: int


class InstExpression(
    _SimpleInstruction,
    directive=".cfi_escape",
    opcode=CallFrameInstructions.expression,
    encoding=[
        _ULEB128Encoder(),
        _ExprEncoder(),
    ],
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

    register: int
    expression: List[Operation]


class InstValExpression(
    _SimpleInstruction,
    directive=".cfi_escape",
    opcode=CallFrameInstructions.val_expression,
    encoding=[
        _ULEB128Encoder(),
        _ExprEncoder(),
    ],
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

    register: int
    expression: List[Operation]


class InstRestore(
    _SimpleInstruction,
    directive=".cfi_restore",
    opcode=CallFrameInstructions.restore,
    encoding=[_Low6Bits],
):
    """
    The DW_CFA_restore instruction takes a single operand (encoded with the
    opcode) that represents a register number. The required action is to
    change the rule for the indicated register to the rule assigned it by the
    initial_instructions in the CIE.
    """

    register: int


class InstRestoreExtended(
    _SimpleInstruction,
    directive=".cfi_escape",
    opcode=CallFrameInstructions.restore_extended,
    encoding=[_ULEB128Encoder()],
):
    """
    The DW_CFA_restore_extended instruction takes a single unsigned LEB128
    operand that represents a register number. This instruction is identical
    to DW_CFA_restore except for the encoding and size of the register
    operand.
    """

    register: int


# ----------------------------------------------------------------------------
# Row State Instructions
# ----------------------------------------------------------------------------
class InstRememberState(
    _SimpleInstruction,
    directive=".cfi_remember_state",
    opcode=CallFrameInstructions.remember_state,
    encoding=[],
):
    """
    The DW_CFA_remember_state instruction takes no operands. The required
    action is to push the set of rules for every register onto an implicit
    stack.
    """


class InstRestoreState(
    _SimpleInstruction,
    directive=".cfi_restore_state",
    opcode=CallFrameInstructions.restore_state,
    encoding=[],
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
    _SimpleInstruction,
    directive=".cfi_escape",
    opcode=CallFrameInstructions.nop,
    encoding=[],
):
    """
    The DW_CFA_nop instruction has no operands and no required actions. It is
    used as padding to make a CIE or FDE an appropriate size.
    """


# ----------------------------------------------------------------------------
# Pseudo Instructions (no DWARF representation)
# ----------------------------------------------------------------------------
class InstRelOffset(
    _SimpleInstruction, directive=".cfi_rel_offset", opcode=None, encoding=[]
):
    """
    Previous value of register is saved at offset offset from the current CFA
    register. This is transformed to .cfi_offset using the known displacement
    of the CFA register from the CFA. This is often easier to use, because the
    number will match the code it's annotating.
    """

    register: int
    offset: int


class InstAdjustCFAOffset(
    _SimpleInstruction,
    directive=".cfi_adjust_cfa_offset",
    opcode=None,
    encoding=[],
):
    """
    Same as .cfi_def_cfa_offset but offset is a relative value that is
    added/subtracted from the previous offset.
    """

    offset: int


class InstEscape(Instruction):
    """
    Allows the user to add arbitrary bytes to the unwind info. One might use
    this to add OS-specific CFI opcodes, or generic CFI opcodes that GAS does
    not yet support.
    """

    def __init__(self, values: bytes):
        self.values = values

    @override
    def gtirb_encoding(
        self, byteorder: Literal["big", "little"], ptr_size: int
    ) -> CFIDirectiveType:
        return ".cfi_escape", list(self.values), NULL_UUID

    @override
    def assembly_string(
        self, byteorder: Literal["big", "little"], ptr_size: int
    ) -> str:
        return ".cfi_escape " + ", ".join(str(arg) for arg in self.values)
