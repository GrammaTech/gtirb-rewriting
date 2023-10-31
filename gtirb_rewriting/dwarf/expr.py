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
from typing import ClassVar, List, Set, Tuple

import leb128
from typing_extensions import Literal, dataclass_transform

from ._encoders import (
    _Encoder,
    _IntPtrEncoder,
    _SIntEncoder,
    _UIntEncoder,
    _ULEB128Encoder,
)
from .dwarf2 import ExpressionOperations


class Operation(abc.ABC):
    """
    A DWARF expression operation.
    """

    @abc.abstractmethod
    def encode(
        self, byteorder: Literal["big", "little"], ptr_size: int
    ) -> bytes:
        ...


@dataclass_transform()
class _BasicOperation(Operation):
    _registered_opcodes: ClassVar[Set[ExpressionOperations]] = set()

    _opcode: ClassVar[ExpressionOperations]
    _encoding: ClassVar[List[_Encoder]]

    def __init_subclass__(
        cls,
        *,
        opcode: ExpressionOperations,
        encoding: List[_Encoder] = [],
    ):
        dataclass(cls)

        if opcode in _BasicOperation._registered_opcodes:
            raise AssertionError("instruction already registered")
        _BasicOperation._registered_opcodes.add(opcode)

        if len(cls._fields()) != len(encoding):
            raise AssertionError("wrong number of fields vs encoders")

        cls._opcode = opcode
        cls._encoding = encoding

    @classmethod
    def _fields(cls) -> Tuple[Field]:
        return fields(cls)  # type: ignore

    def encode(
        self, byteorder: Literal["big", "little"], ptr_size: int
    ) -> bytes:
        result = self._opcode.to_bytes(1, byteorder)
        for field, encoder in zip(self._fields(), self._encoding):
            value = getattr(self, field.name)
            result += encoder.encode(value, byteorder, ptr_size)
        return result


def _int_domain(bit_size: int, signed: bool) -> range:
    if not signed:
        return range(0, 2**bit_size)
    else:
        return range(-(2 ** (bit_size - 1)), 2 ** (bit_size - 1) - 1)


# ----------------------------------------------------------------------------
# Stack Operations
# ----------------------------------------------------------------------------
class OpDup(_BasicOperation, opcode=ExpressionOperations.dup):
    """
    The DW_OP_dup operation duplicates the value at the top of the stack.
    """


class OpDrop(_BasicOperation, opcode=ExpressionOperations.drop):
    """
    The DW_OP_drop operation pops the value at the top of the stack.
    """


class OpPick(
    _BasicOperation,
    opcode=ExpressionOperations.pick,
    encoding=[_UIntEncoder(1)],
):
    """
    The single operand of the DW_OP_pick operation provides a 1-byte index. A
    copy of the stack entry (including its type identifier) with the specified
    index (0 through 255, inclusive) is pushed onto the stack.
    """

    index: int


class OpOver(_BasicOperation, opcode=ExpressionOperations.over):
    """
    The DW_OP_over operation duplicates the entry currently second in the
    stack at the top of the stack. This is equivalent to a DW_OP_pick
    operation, with index 1.
    """


class OpSwap(_BasicOperation, opcode=ExpressionOperations.swap):
    """
    The DW_OP_swap operation swaps the top two stack entries. The entry at the
    top of the stack becomes the second stack entry, and the second entry
    becomes the top of the stack.
    """


class OpRot(_BasicOperation, opcode=ExpressionOperations.rot):
    """
    The DW_OP_rot operation rotates the first three stack entries. The entry
    at the top of the stack becomes the third stack entry, the second entry
    becomes the top of the stack, and the third entry becomes the second
    entry.
    """


class OpXDeref(_BasicOperation, opcode=ExpressionOperations.xderef):
    """
    The DW_OP_xderef operation provides an extended dereference mechanism.
    The entry at the top of the stack is treated as an address. The second
    stack entry is treated as an “address space identifier” for those
    architectures that support multiple address spaces.
    """


class OpDeref(_BasicOperation, opcode=ExpressionOperations.deref):
    """
    The DW_OP_deref operation pops the top stack entry and treats it as an
    address. The value retrieved from that address is pushed. The size of the
    data retrieved from the dereferenced address is the size of an address on
    the target machine.
    """


class OpDerefSize(
    _BasicOperation,
    opcode=ExpressionOperations.deref_size,
    encoding=[_UIntEncoder(1)],
):
    """
    The DW_OP_deref_size operation behaves like the DW_OP_deref operation:
    it pops the top stack entry and treats it as an address. The value
    retrieved from that address is pushed. In the DW_OP_deref_size operation,
    however, the size in bytes of the data retrieved from the dereferenced
    address is specified by the single operand. This operand is a 1-byte
    unsigned integral constant whose value may not be larger than the size of
    the generic type. The data retrieved is zero extended to the size of an
    address on the target machine before being pushed onto the expression
    stack.
    """

    size: int


# ----------------------------------------------------------------------------
# Arithmetic and Logical Operations
# ----------------------------------------------------------------------------
class OpAbs(_BasicOperation, opcode=ExpressionOperations.abs):
    """
    The DW_OP_abs operation pops the top stack entry, interprets it as a
    signed value and pushes its absolute value. If the absolute value cannot
    be represented, the result is undefined.
    """


class OpAnd(_BasicOperation, opcode=ExpressionOperations.and_):
    """
    The DW_OP_and operation pops the top two stack values, performs a bitwise
    and operation on the two, and pushes the result.
    """


class OpDiv(_BasicOperation, opcode=ExpressionOperations.div):
    """
    The DW_OP_div operation pops the top two stack values, divides the former
    second entry by the former top of the stack using signed division, and
    pushes the result.
    """


class OpMinus(_BasicOperation, opcode=ExpressionOperations.minus):
    """
    The DW_OP_minus operation pops the top two stack values, subtracts the
    former top of the stack from the former second entry, and pushes the
    result.
    """


class OpMod(_BasicOperation, opcode=ExpressionOperations.mod):
    """
    The DW_OP_mod operation pops the top two stack values and pushes the
    result of the calculation: former second stack entry modulo the former
    top of the stack.
    """


class OpMul(_BasicOperation, opcode=ExpressionOperations.mul):
    """
    The DW_OP_mul operation pops the top two stack entries, multiplies them
    together, and pushes the result.
    """


class OpNeg(_BasicOperation, opcode=ExpressionOperations.neg):
    """
    The DW_OP_neg operation pops the top stack entry, interprets it as a
    signed value and pushes its negation. If the negation cannot be
    represented, the result is undefined.
    """


class OpNot(_BasicOperation, opcode=ExpressionOperations.not_):
    """
    The DW_OP_not operation pops the top stack entry, and pushes its bitwise
    complement.
    """


class OpOr(_BasicOperation, opcode=ExpressionOperations.or_):
    """
    The DW_OP_or operation pops the top two stack entries, performs a bitwise
    or operation on the two, and pushes the result.
    """


class OpPlus(_BasicOperation, opcode=ExpressionOperations.plus):
    """
    The DW_OP_plus operation pops the top two stack entries, adds them
    together, and pushes the result.
    """


class OpPlusUConst(
    _BasicOperation,
    opcode=ExpressionOperations.plus_uconst,
    encoding=[_ULEB128Encoder()],
):
    """
    The DW_OP_plus_uconst operation pops the top stack entry, adds it to the
    unsigned LEB128 constant operand interpreted as the same type as the
    operand popped from the top of the stack and pushes the result.
    """

    const: int


class OpShl(_BasicOperation, opcode=ExpressionOperations.shl):
    """
    The DW_OP_shl operation pops the top two stack entries, shifts the former
    second entry left (filling with zero bits) by the number of bits specified
    by the former top of the stack, and pushes the result.
    """


class OpShr(_BasicOperation, opcode=ExpressionOperations.shr):
    """
    The DW_OP_shr operation pops the top two stack entries, shifts the former
    second entry right logically (filling with zero bits) by the number of
    bits specified by the former top of the stack, and pushes the result.
    """


class OpShrA(_BasicOperation, opcode=ExpressionOperations.shra):
    """
    The DW_OP_shra operation pops the top two stack entries, shifts the former
    second entry right arithmetically (divide the magnitude by 2, keep the
    same sign for the result) by the number of bits specified by the former
    top of the stack, and pushes the result.
    """


class OpXor(_BasicOperation, opcode=ExpressionOperations.xor):
    """
    The DW_OP_xor operation pops the top two stack entries, performs a bitwise
    exclusive-or operation on the two, and pushes the result.
    """


# ----------------------------------------------------------------------------
# Control Flow Operations
# ----------------------------------------------------------------------------
class OpSkip(
    _BasicOperation,
    opcode=ExpressionOperations.skip,
    encoding=[_SIntEncoder(2)],
):
    """
    DW_OP_skip is an unconditional branch. Its single operand is a 2-byte
    signed integer constant. The 2-byte constant is the number of bytes of the
    DWARF expression to skip forward or backward from the current operation,
    beginning after the 2-byte constant.
    """

    distance: int


class OpBra(
    _BasicOperation,
    opcode=ExpressionOperations.bra,
    encoding=[_SIntEncoder(2)],
):
    """
    DW_OP_bra is a conditional branch. Its single operand is a 2-byte signed
    integer constant. This operation pops the top of stack. If the value
    popped is not the constant 0, the 2-byte constant operand is the number of
    bytes of the DWARF expression to skip forward or backward from the current
    operation, beginning after the 2-byte constant.
    """

    distance: int


class OpEq(_BasicOperation, opcode=ExpressionOperations.eq):
    ...


class OpGe(_BasicOperation, opcode=ExpressionOperations.ge):
    ...


class OpGt(_BasicOperation, opcode=ExpressionOperations.gt):
    ...


class OpLe(_BasicOperation, opcode=ExpressionOperations.le):
    ...


class OpLt(_BasicOperation, opcode=ExpressionOperations.lt):
    ...


class OpNe(_BasicOperation, opcode=ExpressionOperations.ne):
    ...


# ----------------------------------------------------------------------------
# Literal Encodings
# ----------------------------------------------------------------------------
class OpAddr(
    _BasicOperation,
    opcode=ExpressionOperations.addr,
    encoding=[_IntPtrEncoder()],
):
    """
    The DW_OP_addr operation has a single operand that encodes a machine
    address and whose size is the size of an address on the target machine.
    """

    value: int


class OpConst(Operation):
    """
    Pushes a constant value onto the stack.
    """

    class _IntEncoding:
        def __init__(
            self, byte_size: int, signed: bool, op: ExpressionOperations
        ) -> None:
            self.byte_size = byte_size
            self.signed = signed
            self.op = op
            self.domain = _int_domain(byte_size * 8, signed)

    _INT_ENCODINGS = (
        _IntEncoding(1, False, ExpressionOperations.const1u),
        _IntEncoding(2, False, ExpressionOperations.const2u),
        _IntEncoding(4, False, ExpressionOperations.const4u),
        _IntEncoding(8, False, ExpressionOperations.const8u),
        _IntEncoding(1, True, ExpressionOperations.const1s),
        _IntEncoding(2, True, ExpressionOperations.const2s),
        _IntEncoding(4, True, ExpressionOperations.const4s),
        _IntEncoding(8, True, ExpressionOperations.const8s),
    )

    def __init__(self, value: int) -> None:
        super().__init__()
        self.value = value

    def encode(
        self, byteorder: Literal["big", "little"], ptr_size: int
    ) -> bytes:
        def leb_encode():
            if self.value >= 0:
                return ExpressionOperations.constu.to_bytes(
                    1, byteorder
                ) + leb128.u.encode(self.value)
            else:
                return ExpressionOperations.consts.to_bytes(
                    1, byteorder
                ) + leb128.i.encode(self.value)

        if 0 <= self.value <= 31:
            return (ExpressionOperations.lit0 + self.value).to_bytes(
                1, byteorder
            )

        for encoding in self._INT_ENCODINGS:
            if self.value in encoding.domain:
                int_encoding = encoding.op.to_bytes(
                    1, byteorder
                ) + self.value.to_bytes(
                    encoding.byte_size, byteorder, signed=encoding.signed
                )
                if encoding.byte_size >= 4:
                    leb_encoding = leb_encode()
                    if len(leb_encoding) < len(int_encoding):
                        return leb_encoding

                return int_encoding
        else:
            raise ValueError("value cannot be encoded")


# ----------------------------------------------------------------------------
# Register Values
# ----------------------------------------------------------------------------
class OpReg(Operation):
    """
    Push a value onto the stack that is the contents of a register.
    """

    def __init__(self, register: int) -> None:
        super().__init__()
        self.register = register

    def encode(
        self, byteorder: Literal["big", "little"], ptr_size: int
    ) -> bytes:
        if 0 <= self.register <= 31:
            return (ExpressionOperations.reg0 + self.register).to_bytes(
                1, byteorder
            )

        return ExpressionOperations.regx.to_bytes(
            1, byteorder
        ) + leb128.u.encode(self.register)


class OpBReg(Operation):
    """
    Push a value onto the stack that is the result of adding the contents of
    a register to a given signed offset.
    """

    def __init__(self, register: int, offset: int) -> None:
        super().__init__()
        self.register = register
        self.offset = offset

    def encode(
        self, byteorder: Literal["big", "little"], ptr_size: int
    ) -> bytes:
        if 0 <= self.register <= 31:
            return (ExpressionOperations.breg0 + self.register).to_bytes(
                1, byteorder
            ) + leb128.i.encode(self.offset)

        return (
            ExpressionOperations.bregx.to_bytes(1, byteorder)
            + leb128.u.encode(self.register)
            + leb128.i.encode(self.offset)
        )
