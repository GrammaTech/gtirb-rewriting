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
import functools
import unittest.mock

import gtirb
import gtirb_functions
from gtirb_test_helpers import create_test_module

import gtirb_rewriting


def test_register_fmt():
    reg = gtirb_rewriting.Register(
        {"8l": "al", "8h": "ah", "16": "ax", "32": "eax"}, "32"
    )
    assert f"{reg}" == "eax"
    assert f"{reg:8l}" == "al"


def test_decorate_symbol_elf_pic():
    _, mod = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64, binary_type=["DYN"]
    )

    block = unittest.mock.MagicMock(spec=gtirb.CodeBlock)
    func = unittest.mock.MagicMock(spec=gtirb_functions.Function)
    context = gtirb_rewriting.InsertionContext(mod, func, block, 0)

    assert context.decorate_extern_symbol("puts") == "puts"


def test_constraints_decorator():
    @gtirb_rewriting.patch_constraints(clobbers_flags=True)
    def xtail_instrumentation(insertion_context):
        return "nop"

    context = unittest.mock.MagicMock(spec=gtirb_rewriting.InsertionContext)
    patch = gtirb_rewriting.Patch.from_function(xtail_instrumentation)
    assert patch.constraints == gtirb_rewriting.Constraints(
        clobbers_flags=True
    )
    assert patch.get_asm(context) == "nop"


def test_constraints_decorator_partial():
    @gtirb_rewriting.patch_constraints(clobbers_flags=True)
    def xtail_instrumentation(must_be_five, insertion_context):
        assert must_be_five == 5
        return "nop"

    context = unittest.mock.MagicMock(spec=gtirb_rewriting.InsertionContext)
    patch = gtirb_rewriting.Patch.from_function(
        functools.partial(xtail_instrumentation, 5)
    )
    assert patch.constraints == gtirb_rewriting.Constraints(
        clobbers_flags=True
    )
    assert patch.get_asm(context) == "nop"


def test_constraints_decorator_wrapped():
    """
    Test that Patch.from_function follows the __wrapped__ chain when looking
    for constraints.
    """

    def wrapper_decorator(fn):
        # By default, wraps will copy over the instance __dict__. Explicitly
        # opt out of that to test that gtirb-rewriting follows the __wrapped__
        # chain.
        @functools.wraps(fn, assigned=(), updated=())
        def wrapper(*args, **kwargs):
            return fn(*args, **kwargs)

        return wrapper

    @wrapper_decorator
    @gtirb_rewriting.patch_constraints(clobbers_flags=True)
    def patch_func(context, flag):
        return "nop"

    assert not hasattr(patch_func, "constraints")
    patch = gtirb_rewriting.Patch.from_function(
        functools.partial(patch_func, flag=1)
    )
    assert patch.constraints.clobbers_flags


def test_temporary_label_elf_x64():
    m = gtirb.Module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
        name="test",
    )
    func = unittest.mock.MagicMock(spec=gtirb_functions.Function)
    block = unittest.mock.MagicMock(spec=gtirb.CodeBlock)

    context = gtirb_rewriting.InsertionContext(m, func, block, 0)
    assert context.temporary_label("foo") == ".Lfoo"


def test_temporary_label_pe_ia32():
    m = gtirb.Module(
        isa=gtirb.Module.ISA.IA32,
        file_format=gtirb.Module.FileFormat.PE,
        name="test",
    )
    func = unittest.mock.MagicMock(spec=gtirb_functions.Function)
    block = unittest.mock.MagicMock(spec=gtirb.CodeBlock)

    context = gtirb_rewriting.InsertionContext(m, func, block, 0)
    assert context.temporary_label("foo") == "Lfoo"
