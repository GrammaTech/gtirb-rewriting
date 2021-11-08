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

import unittest

import gtirb
import gtirb_rewriting
import pytest
from gtirb_rewriting.patches import CallPatch
from gtirb_test_helpers import add_proxy_block, add_symbol, create_test_module
from helpers import remove_indentation


def create_mock_context(m, stack_adjustment=None):
    """
    Creates a mock insertion context for a given module.
    """
    return unittest.mock.MagicMock(
        spec=gtirb_rewriting.InsertionContext,
        module=m,
        stack_adjustment=stack_adjustment,
    )


def call_patch_targets():
    """
    All ISA/file format tuples that CallPatch should be tested against.
    """
    return (
        (gtirb.Module.ISA.IA32, gtirb.Module.FileFormat.PE),
        (gtirb.Module.ISA.X64, gtirb.Module.FileFormat.PE),
        (gtirb.Module.ISA.X64, gtirb.Module.FileFormat.ELF),
        (gtirb.Module.ISA.ARM64, gtirb.Module.FileFormat.ELF),
    )


@pytest.mark.parametrize("isa,file_format", call_patch_targets())
def test_call_0_args(isa, file_format):
    _, m = create_test_module(file_format, isa)
    sym = add_symbol(m, "foo", add_proxy_block(m))

    patch = CallPatch(sym)
    asm = patch.get_asm(create_mock_context(m))

    target = (isa, file_format)
    if target == (gtirb.Module.ISA.IA32, gtirb.Module.FileFormat.PE):
        assert remove_indentation(asm) == remove_indentation(
            """
            call foo
            """
        )
    elif target == (gtirb.Module.ISA.X64, gtirb.Module.FileFormat.PE):
        assert remove_indentation(asm) == remove_indentation(
            """
            sub rsp, 32
            call foo
            add rsp, 32
            """
        )
    elif target == (gtirb.Module.ISA.X64, gtirb.Module.FileFormat.ELF):
        assert remove_indentation(asm) == remove_indentation(
            """
            call foo
            """
        )
    elif target == (gtirb.Module.ISA.ARM64, gtirb.Module.FileFormat.ELF):
        assert remove_indentation(asm) == remove_indentation(
            """
            bl foo
            """
        )
    else:
        assert False


@pytest.mark.parametrize("isa,file_format", call_patch_targets())
def test_call_3_args(isa, file_format):
    _, m = create_test_module(file_format, isa)
    sym = add_symbol(m, "foo", add_proxy_block(m))

    patch = CallPatch(sym, args=(1, 2, 3))
    asm = patch.get_asm(create_mock_context(m))

    target = (isa, file_format)
    if target == (gtirb.Module.ISA.IA32, gtirb.Module.FileFormat.PE):
        assert remove_indentation(asm) == remove_indentation(
            """
            push 3
            push 2
            push 1
            call foo
            add esp, 12
            """
        )
    elif target == (gtirb.Module.ISA.X64, gtirb.Module.FileFormat.PE):
        assert remove_indentation(asm) == remove_indentation(
            """
            mov R8, 3
            mov RDX, 2
            mov RCX, 1
            sub rsp, 32
            call foo
            add rsp, 32
            """
        )
    elif target == (gtirb.Module.ISA.X64, gtirb.Module.FileFormat.ELF):
        assert remove_indentation(asm) == remove_indentation(
            """
            mov RDX, 3
            mov RSI, 2
            mov RDI, 1
            call foo
            """
        )
    elif target == (gtirb.Module.ISA.ARM64, gtirb.Module.FileFormat.ELF):
        assert remove_indentation(asm) == remove_indentation(
            """
            mov x2, #0x3
            mov x1, #0x2
            mov x0, #0x1
            bl foo
            """
        )
    else:
        assert False


@pytest.mark.parametrize("isa,file_format", call_patch_targets())
def test_call_11_args(isa, file_format):
    _, m = create_test_module(file_format, isa)
    sym = add_symbol(m, "foo", add_proxy_block(m))

    patch = CallPatch(sym, args=(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11))
    asm = patch.get_asm(create_mock_context(m))

    target = (isa, file_format)
    if target == (gtirb.Module.ISA.IA32, gtirb.Module.FileFormat.PE):
        assert remove_indentation(asm) == remove_indentation(
            """
            push 11
            push 10
            push 9
            push 8
            push 7
            push 6
            push 5
            push 4
            push 3
            push 2
            push 1
            call foo
            add esp, 44
            """
        )
    elif target == (gtirb.Module.ISA.X64, gtirb.Module.FileFormat.PE):
        assert remove_indentation(asm) == remove_indentation(
            """
            sub rsp, 8
            push 11
            push 10
            push 9
            push 8
            push 7
            push 6
            push 5
            mov R9, 4
            mov R8, 3
            mov RDX, 2
            mov RCX, 1
            sub rsp, 32
            call foo
            add rsp, 96
            """
        )
    elif target == (gtirb.Module.ISA.X64, gtirb.Module.FileFormat.ELF):
        assert remove_indentation(asm) == remove_indentation(
            """
            sub rsp, 8
            push 11
            push 10
            push 9
            push 8
            push 7
            mov R9, 6
            mov R8, 5
            mov RCX, 4
            mov RDX, 3
            mov RSI, 2
            mov RDI, 1
            call foo
            add rsp, 48
            """
        )
    elif target == (gtirb.Module.ISA.ARM64, gtirb.Module.FileFormat.ELF):
        assert remove_indentation(asm) == remove_indentation(
            """
            sub sp, sp, #32
            mov x0, #0xb
            str x0, [sp, #16]
            mov x0, #0xa
            str x0, [sp, #8]
            mov x0, #0x9
            str x0, [sp, #0]
            mov x7, #0x8
            mov x6, #0x7
            mov x5, #0x6
            mov x4, #0x5
            mov x3, #0x4
            mov x2, #0x3
            mov x1, #0x2
            mov x0, #0x1
            bl foo
            add sp, sp, #32
            """
        )
    else:
        assert False


@pytest.mark.parametrize("isa,file_format", call_patch_targets())
def test_call_symbol_arg(isa, file_format):
    _, m = create_test_module(file_format, isa)
    sym = add_symbol(m, "foo", add_proxy_block(m))

    patch = CallPatch(sym, args=(sym,))
    asm = patch.get_asm(create_mock_context(m))

    target = (isa, file_format)
    if target == (gtirb.Module.ISA.IA32, gtirb.Module.FileFormat.PE):
        assert remove_indentation(asm) == remove_indentation(
            """
            push foo
            call foo
            add esp, 4
            """
        )
    elif target == (gtirb.Module.ISA.X64, gtirb.Module.FileFormat.PE):
        assert remove_indentation(asm) == remove_indentation(
            """
            mov RCX, foo
            sub rsp, 32
            call foo
            add rsp, 32
            """
        )
    elif target == (gtirb.Module.ISA.X64, gtirb.Module.FileFormat.ELF):
        assert remove_indentation(asm) == remove_indentation(
            """
            mov RDI, foo[rip]
            call foo
            """
        )
    elif target == (gtirb.Module.ISA.ARM64, gtirb.Module.FileFormat.ELF):
        assert remove_indentation(asm) == remove_indentation(
            """
            adrp x0, foo
            add x0, x0, #:lo12:foo
            bl foo
            """
        )
    else:
        assert False


def test_x64_stack_align():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    sym = add_symbol(m, "foo", add_proxy_block)

    patch = CallPatch(sym, align_stack=False)
    asm = patch.get_asm(create_mock_context(m, stack_adjustment=8))

    assert remove_indentation(asm) == remove_indentation(
        """
        sub rsp, 8
        call foo
        add rsp, 8
        """
    )


@pytest.mark.parametrize("isa,file_format", call_patch_targets())
def test_stack_align_opt_out(isa, file_format):
    _, m = create_test_module(file_format, isa)
    sym = add_symbol(m, "foo", add_proxy_block)

    patch = CallPatch(
        sym, align_stack=False, preserve_caller_saved_registers=False
    )
    assert not patch.constraints.align_stack
    assert not patch.constraints.preserve_caller_saved_registers


def test_call_big_imm_arm64():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.ARM64
    )
    sym = add_symbol(m, "foo", add_proxy_block(m))

    patch = CallPatch(sym, args=(0xDEADBEEFFEEDFACE,))
    asm = patch.get_asm(create_mock_context(m))

    assert remove_indentation(asm) == remove_indentation(
        """
        movz x0, #0xface
        movk x0, #0xfeed, lsl #16
        movk x0, #0xbeef, lsl #32
        movk x0, #0xdead, lsl #48
        bl foo
        """
    )
