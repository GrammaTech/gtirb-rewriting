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

# flake8: noqa
# fmt: off

from enum import IntEnum, IntFlag


class PointerEncodings(IntFlag):
    """
    A description of how a pointer is encoded. The low 4 bits indicate the
    format of the data and the upper 4 bits indicate how the value is applied.
    """
    omit    = 0xFF
    # Format of the pointer
    absptr  = 0x00
    uleb128 = 0x01
    udata2  = 0x02
    udata4  = 0x03
    udata8  = 0x04
    sleb128 = 0x09
    sdata2  = 0x0A
    sdata4  = 0x0B
    sdata8  = 0x0C
    # How the value is applied
    pcrel   = 0x10
    textrel = 0x20
    datarel = 0x30
    funcrel = 0x40
    aligned = 0x50
    indirect = 0x80


class CallFrameInstructions(IntEnum):
    nop                 = 0x00
    set_loc             = 0x01
    advance_loc1        = 0x02
    advance_loc2        = 0x03
    advance_loc4        = 0x04
    offset_extended     = 0x05
    restore_extended    = 0x06
    undefined           = 0x07
    same_value          = 0x08
    register            = 0x09
    remember_state      = 0x0A
    restore_state       = 0x0B
    def_cfa             = 0x0C
    def_cfa_register    = 0x0D
    def_cfa_offset      = 0x0E
    def_cfa_expression  = 0x0F
    expression          = 0x10
    offset_extended_sf  = 0x11
    def_cfa_sf          = 0x12
    def_cfa_offset_sf   = 0x13
    val_offset          = 0x14
    val_offset_sf       = 0x15
    val_expression      = 0x16
    advance_loc         = 0x40
    offset              = 0x80
    restore             = 0xC0

    # GNU extensions
    gnu_window_save              = 0x2D
    gnu_args_size                = 0x2E
    gnu_negative_offset_extended = 0x2F

    # AARCH64 extensions
    aarch64_negate_ra_state      = 0x2D


class ExpressionOperations(IntEnum):
    addr                = 0x03
    deref               = 0x06
    const1u             = 0x08
    const1s             = 0x09
    const2u             = 0x0A
    const2s             = 0x0B
    const4u             = 0x0C
    const4s             = 0x0D
    const8u             = 0x0E
    const8s             = 0x0F
    constu              = 0x10
    consts              = 0x11
    dup                 = 0x12
    drop                = 0x13
    over                = 0x14
    pick                = 0x15
    swap                = 0x16
    rot                 = 0x17
    xderef              = 0x18
    abs                 = 0x19
    and_                = 0x1A
    div                 = 0x1B
    minus               = 0x1C
    mod                 = 0x1D
    mul                 = 0x1E
    neg                 = 0x1F
    not_                = 0x20
    or_                 = 0x21
    plus                = 0x22
    plus_uconst         = 0x23
    shl                 = 0x24
    shr                 = 0x25
    shra                = 0x26
    xor                 = 0x27
    skip                = 0x2F
    bra                 = 0x28
    eq                  = 0x29
    ge                  = 0x2A
    gt                  = 0x2B
    le                  = 0x2C
    lt                  = 0x2D
    ne                  = 0x2E
    lit0                = 0x30
    lit1                = 0x31
    lit2                = 0x32
    lit3                = 0x33
    lit4                = 0x34
    lit5                = 0x35
    lit6                = 0x36
    lit7                = 0x37
    lit8                = 0x38
    lit9                = 0x39
    lit10               = 0x3A
    lit11               = 0x3B
    lit12               = 0x3C
    lit13               = 0x3D
    lit14               = 0x3E
    lit15               = 0x3F
    lit16               = 0x40
    lit17               = 0x41
    lit18               = 0x42
    lit19               = 0x43
    lit20               = 0x44
    lit21               = 0x45
    lit22               = 0x46
    lit23               = 0x47
    lit24               = 0x48
    lit25               = 0x49
    lit26               = 0x4A
    lit27               = 0x4B
    lit28               = 0x4C
    lit29               = 0x4D
    lit30               = 0x4E
    lit31               = 0x4F
    reg0                = 0x50
    reg1                = 0x51
    reg2                = 0x52
    reg3                = 0x53
    reg4                = 0x54
    reg5                = 0x55
    reg6                = 0x56
    reg7                = 0x57
    reg8                = 0x58
    reg9                = 0x59
    reg10               = 0x5A
    reg11               = 0x5B
    reg12               = 0x5C
    reg13               = 0x5D
    reg14               = 0x5E
    reg15               = 0x5F
    reg16               = 0x60
    reg17               = 0x61
    reg18               = 0x62
    reg19               = 0x63
    reg20               = 0x64
    reg21               = 0x65
    reg22               = 0x66
    reg23               = 0x67
    reg24               = 0x68
    reg25               = 0x69
    reg26               = 0x6A
    reg27               = 0x6B
    reg28               = 0x6C
    reg29               = 0x6D
    reg30               = 0x6E
    reg31               = 0x6F
    breg0               = 0x70
    breg1               = 0x71
    breg2               = 0x72
    breg3               = 0x73
    breg4               = 0x74
    breg5               = 0x75
    breg6               = 0x76
    breg7               = 0x77
    breg8               = 0x78
    breg9               = 0x79
    breg10              = 0x7A
    breg11              = 0x7B
    breg12              = 0x7C
    breg13              = 0x7D
    breg14              = 0x7E
    breg15              = 0x7F
    breg16              = 0x80
    breg17              = 0x81
    breg18              = 0x82
    breg19              = 0x83
    breg20              = 0x84
    breg21              = 0x85
    breg22              = 0x86
    breg23              = 0x87
    breg24              = 0x88
    breg25              = 0x89
    breg26              = 0x8A
    breg27              = 0x8B
    breg28              = 0x8C
    breg29              = 0x8D
    breg30              = 0x8E
    breg31              = 0x8F
    regx                = 0x90
    fbreg               = 0x91
    bregx               = 0x92
    piece               = 0x93
    deref_size          = 0x94
    xderef_size         = 0x95
    nop                 = 0x96
    push_object_address = 0x97
    call2               = 0x98
    call4               = 0x99
    call_ref            = 0x9A
