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


import leb128

from ._encodable import _encoded_field, _OpcodeEncodable
from ._encoders import (
    _AddToOpcodeEncoder,
    _int_domain,
    _SIntEncoder,
    _SLEB128Encoder,
    _UIntEncoder,
    _UIntPtrEncoder,
    _ULEB128Encoder,
)
from .dwarf2 import ExpressionOperations


class Operation(
    _OpcodeEncodable[ExpressionOperations],
    opcode_type=ExpressionOperations,
):
    """
    A DWARF expression operation.
    """


# ----------------------------------------------------------------------------
# Stack Operations
# ----------------------------------------------------------------------------
class OpDup(Operation, opcode=ExpressionOperations.dup):
    """
    The DW_OP_dup operation duplicates the value at the top of the stack.
    """


class OpDrop(Operation, opcode=ExpressionOperations.drop):
    """
    The DW_OP_drop operation pops the value at the top of the stack.
    """


class OpPick(
    Operation,
    opcode=ExpressionOperations.pick,
):
    """
    The single operand of the DW_OP_pick operation provides a 1-byte index. A
    copy of the stack entry (including its type identifier) with the specified
    index (0 through 255, inclusive) is pushed onto the stack.
    """

    index: int = _encoded_field(_UIntEncoder(1))


class OpOver(Operation, opcode=ExpressionOperations.over):
    """
    The DW_OP_over operation duplicates the entry currently second in the
    stack at the top of the stack. This is equivalent to a DW_OP_pick
    operation, with index 1.
    """


class OpSwap(Operation, opcode=ExpressionOperations.swap):
    """
    The DW_OP_swap operation swaps the top two stack entries. The entry at the
    top of the stack becomes the second stack entry, and the second entry
    becomes the top of the stack.
    """


class OpRot(Operation, opcode=ExpressionOperations.rot):
    """
    The DW_OP_rot operation rotates the first three stack entries. The entry
    at the top of the stack becomes the third stack entry, the second entry
    becomes the top of the stack, and the third entry becomes the second
    entry.
    """


class OpXDeref(Operation, opcode=ExpressionOperations.xderef):
    """
    The DW_OP_xderef operation provides an extended dereference mechanism.
    The entry at the top of the stack is treated as an address. The second
    stack entry is treated as an “address space identifier” for those
    architectures that support multiple address spaces.
    """


class OpDeref(Operation, opcode=ExpressionOperations.deref):
    """
    The DW_OP_deref operation pops the top stack entry and treats it as an
    address. The value retrieved from that address is pushed. The size of the
    data retrieved from the dereferenced address is the size of an address on
    the target machine.
    """


class OpDerefSize(
    Operation,
    opcode=ExpressionOperations.deref_size,
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

    size: int = _encoded_field(_UIntEncoder(1))


# ----------------------------------------------------------------------------
# Arithmetic and Logical Operations
# ----------------------------------------------------------------------------
class OpAbs(Operation, opcode=ExpressionOperations.abs):
    """
    The DW_OP_abs operation pops the top stack entry, interprets it as a
    signed value and pushes its absolute value. If the absolute value cannot
    be represented, the result is undefined.
    """


class OpAnd(Operation, opcode=ExpressionOperations.and_):
    """
    The DW_OP_and operation pops the top two stack values, performs a bitwise
    and operation on the two, and pushes the result.
    """


class OpDiv(Operation, opcode=ExpressionOperations.div):
    """
    The DW_OP_div operation pops the top two stack values, divides the former
    second entry by the former top of the stack using signed division, and
    pushes the result.
    """


class OpMinus(Operation, opcode=ExpressionOperations.minus):
    """
    The DW_OP_minus operation pops the top two stack values, subtracts the
    former top of the stack from the former second entry, and pushes the
    result.
    """


class OpMod(Operation, opcode=ExpressionOperations.mod):
    """
    The DW_OP_mod operation pops the top two stack values and pushes the
    result of the calculation: former second stack entry modulo the former
    top of the stack.
    """


class OpMul(Operation, opcode=ExpressionOperations.mul):
    """
    The DW_OP_mul operation pops the top two stack entries, multiplies them
    together, and pushes the result.
    """


class OpNeg(Operation, opcode=ExpressionOperations.neg):
    """
    The DW_OP_neg operation pops the top stack entry, interprets it as a
    signed value and pushes its negation. If the negation cannot be
    represented, the result is undefined.
    """


class OpNot(Operation, opcode=ExpressionOperations.not_):
    """
    The DW_OP_not operation pops the top stack entry, and pushes its bitwise
    complement.
    """


class OpOr(Operation, opcode=ExpressionOperations.or_):
    """
    The DW_OP_or operation pops the top two stack entries, performs a bitwise
    or operation on the two, and pushes the result.
    """


class OpPlus(Operation, opcode=ExpressionOperations.plus):
    """
    The DW_OP_plus operation pops the top two stack entries, adds them
    together, and pushes the result.
    """


class OpPlusUConst(
    Operation,
    opcode=ExpressionOperations.plus_uconst,
):
    """
    The DW_OP_plus_uconst operation pops the top stack entry, adds it to the
    unsigned LEB128 constant operand interpreted as the same type as the
    operand popped from the top of the stack and pushes the result.
    """

    const: int = _encoded_field(_ULEB128Encoder())


class OpShl(Operation, opcode=ExpressionOperations.shl):
    """
    The DW_OP_shl operation pops the top two stack entries, shifts the former
    second entry left (filling with zero bits) by the number of bits specified
    by the former top of the stack, and pushes the result.
    """


class OpShr(Operation, opcode=ExpressionOperations.shr):
    """
    The DW_OP_shr operation pops the top two stack entries, shifts the former
    second entry right logically (filling with zero bits) by the number of
    bits specified by the former top of the stack, and pushes the result.
    """


class OpShrA(Operation, opcode=ExpressionOperations.shra):
    """
    The DW_OP_shra operation pops the top two stack entries, shifts the former
    second entry right arithmetically (divide the magnitude by 2, keep the
    same sign for the result) by the number of bits specified by the former
    top of the stack, and pushes the result.
    """


class OpXor(Operation, opcode=ExpressionOperations.xor):
    """
    The DW_OP_xor operation pops the top two stack entries, performs a bitwise
    exclusive-or operation on the two, and pushes the result.
    """


# ----------------------------------------------------------------------------
# Control Flow Operations
# ----------------------------------------------------------------------------
class OpSkip(
    Operation,
    opcode=ExpressionOperations.skip,
):
    """
    DW_OP_skip is an unconditional branch. Its single operand is a 2-byte
    signed integer constant. The 2-byte constant is the number of bytes of the
    DWARF expression to skip forward or backward from the current operation,
    beginning after the 2-byte constant.
    """

    distance: int = _encoded_field(_SIntEncoder(2))


class OpBra(
    Operation,
    opcode=ExpressionOperations.bra,
):
    """
    DW_OP_bra is a conditional branch. Its single operand is a 2-byte signed
    integer constant. This operation pops the top of stack. If the value
    popped is not the constant 0, the 2-byte constant operand is the number of
    bytes of the DWARF expression to skip forward or backward from the current
    operation, beginning after the 2-byte constant.
    """

    distance: int = _encoded_field(_SIntEncoder(2))


class OpEq(Operation, opcode=ExpressionOperations.eq):
    ...


class OpGe(Operation, opcode=ExpressionOperations.ge):
    ...


class OpGt(Operation, opcode=ExpressionOperations.gt):
    ...


class OpLe(Operation, opcode=ExpressionOperations.le):
    ...


class OpLt(Operation, opcode=ExpressionOperations.lt):
    ...


class OpNe(Operation, opcode=ExpressionOperations.ne):
    ...


# ----------------------------------------------------------------------------
# Literal Encodings
# ----------------------------------------------------------------------------
class OpConst(Operation, opcode_type=ExpressionOperations):
    """
    A base class for operations that push a constant value onto the stack.
    """

    # In previous versions of gtirb-rewriting, OpConst lacked subclasses and
    # clients directly created OpConst instances. For compatibility we
    # preserve that behavior by creating the apropriate subclass.
    def __new__(cls, value: int) -> "OpConst":
        """
        Create the appropriate OpConst subclass for the given value.
        """
        if cls is not OpConst:
            return super().__new__(cls)

        return make_const_op(value)

    value: int


class OpAddr(
    OpConst,
    opcode=ExpressionOperations.addr,
):
    """
    The DW_OP_addr operation has a single operand that encodes a machine
    address and whose size is the size of an address on the target machine.
    """

    value: int = _encoded_field(_UIntPtrEncoder())


class OpConst1U(
    OpConst,
    opcode=ExpressionOperations.const1u,
):
    value: int = _encoded_field(_UIntEncoder(1))


class OpConst1S(
    OpConst,
    opcode=ExpressionOperations.const1s,
):
    value: int = _encoded_field(_SIntEncoder(1))


class OpConst2U(
    OpConst,
    opcode=ExpressionOperations.const2u,
):
    value: int = _encoded_field(_UIntEncoder(2))


class OpConst2S(
    OpConst,
    opcode=ExpressionOperations.const2s,
):
    value: int = _encoded_field(_SIntEncoder(2))


class OpConst4U(
    OpConst,
    opcode=ExpressionOperations.const4u,
):
    value: int = _encoded_field(_UIntEncoder(4))


class OpConst4S(
    OpConst,
    opcode=ExpressionOperations.const4s,
):
    value: int = _encoded_field(_SIntEncoder(4))


class OpConst8U(
    OpConst,
    opcode=ExpressionOperations.const8u,
):
    value: int = _encoded_field(_UIntEncoder(8))


class OpConst8S(
    OpConst,
    opcode=ExpressionOperations.const8s,
):
    value: int = _encoded_field(_SIntEncoder(8))


class OpConstS(
    OpConst,
    opcode=ExpressionOperations.consts,
):
    value: int = _encoded_field(_SLEB128Encoder())


class OpConstU(
    OpConst,
    opcode=ExpressionOperations.constu,
):
    value: int = _encoded_field(_ULEB128Encoder())


class OpLit(
    OpConst,
    opcode=ExpressionOperations.lit0,
):
    value: int = _encoded_field(_AddToOpcodeEncoder(32))


# ----------------------------------------------------------------------------
# Register Values
# ----------------------------------------------------------------------------
class OpReg(Operation, opcode=ExpressionOperations.reg0):
    """
    Push a value onto the stack that is the contents of a register.
    """

    register: int = _encoded_field(_AddToOpcodeEncoder(32))


class OpRegX(Operation, opcode=ExpressionOperations.regx):
    """
    Push a value onto the stack that is the contents of a register.
    """

    register: int = _encoded_field(_ULEB128Encoder())


class OpBReg(Operation, opcode=ExpressionOperations.breg0):
    """
    Push a value onto the stack that is the contents of a register.
    """

    register: int = _encoded_field(_AddToOpcodeEncoder(32))
    offset: int = _encoded_field(_SLEB128Encoder())


class OpBRegX(Operation, opcode=ExpressionOperations.bregx):
    """
    Push a value onto the stack that is the result of adding the contents of
    a register to a given signed offset.
    """

    register: int = _encoded_field(_ULEB128Encoder())
    offset: int = _encoded_field(_SLEB128Encoder())


# ----------------------------------------------------------------------------
# Helper Functions
# ----------------------------------------------------------------------------
def make_const_op(value: int) -> OpConst:
    """
    Create the smallest OpConst that can be used to encode a given constant
    value.
    """
    if 0 <= value <= 31:
        return OpLit(value)

    for bit_size, signed, cls in (
        (8, False, OpConst1U),
        (16, False, OpConst2U),
        (32, False, OpConst4U),
        (64, False, OpConst8U),
        (8, True, OpConst1S),
        (16, True, OpConst2S),
        (32, True, OpConst4S),
        (64, True, OpConst8S),
    ):
        if value in _int_domain(bit_size, signed):
            if bit_size >= 32:
                if signed:
                    leb_encoding = leb128.i.encode(value)
                    leb_cls = OpConstS
                else:
                    leb_encoding = leb128.u.encode(value)
                    leb_cls = OpConstU

                if len(leb_encoding) * 8 < bit_size:
                    return leb_cls(value)

            return cls(value)

    raise ValueError("value cannot be encoded")
