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

import gtirb
import gtirb_rewriting
import pytest
from gtirb_rewriting._auxdata import NULL_UUID
from gtirb_test_helpers import (
    add_code_block,
    add_edge,
    add_elf_symbol_info,
    add_function,
    add_proxy_block,
    add_symbol,
    add_text_section,
    create_test_module,
)
from helpers import (
    add_defined_elf_symbol_version,
    add_elf_base_symbol_version,
    add_needed_elf_symbol_version,
)


@pytest.mark.parametrize(
    "file_format,force",
    (
        (gtirb.Module.FileFormat.ELF, True),
        (gtirb.Module.FileFormat.ELF, False),
        (gtirb.Module.FileFormat.PE, True),
    ),
)
def test_delete_symbol(file_format: gtirb.Module.FileFormat, force: bool):
    """
    Tests that deleting symbols deletes all associated auxdata.
    """

    # This mimics:
    #   foo:
    #   ud2
    #
    #   bar:
    #   .cfi_startproc
    #   .cfi_personality 0, foo
    #   call foo
    #   .cfi_endproc
    #
    ir, m = create_test_module(file_format, gtirb.Module.ISA.X64)
    _, bi = add_text_section(m, address=0x1000)

    b1 = add_code_block(bi, b"\x0F\x0B")
    foo_sym = add_symbol(m, "foo", b1)
    add_function(m, foo_sym, b1)

    b2 = add_code_block(
        bi, b"\xE8\x00\x00\x00\x00", {(1, 4): gtirb.SymAddrConst(0, foo_sym)}
    )
    bar_sym = add_symbol(m, "bar", b2)
    bar_uuid = add_function(m, bar_sym, b2)

    add_edge(ir.cfg, b2, b1, gtirb.EdgeType.Call)

    if file_format == gtirb.Module.FileFormat.ELF:
        add_elf_symbol_info(m, foo_sym, 0, "FUNC")
        add_elf_symbol_info(m, bar_sym, 0, "FUNC")

        m.aux_data["cfiDirectives"].data = {
            gtirb.Offset(b2, 0): [
                (".cfi_startproc", [], NULL_UUID),
                (".cfi_personality", [0], foo_sym),
            ],
            gtirb.Offset(b2, b2.size): [
                (".cfi_endproc", [], NULL_UUID),
            ],
        }

        m.aux_data["elfSymbolTabIdxInfo"].data = {
            foo_sym: [(".symtab", 1)],
            bar_sym: [(".symtab", 0)],
        }
    elif file_format == gtirb.Module.FileFormat.PE:
        m.aux_data["peExportedSymbols"].data = [foo_sym]
        m.aux_data["peImportedSymbols"].data = [foo_sym]

    # This is not representative of a real world example, but tests the logic
    # correctly.
    m.aux_data["symbolForwarding"].data = {
        bar_sym: foo_sym,
        foo_sym: bar_sym,
    }

    ctx = gtirb_rewriting.RewritingContext(m, [])
    ctx.delete_symbol(foo_sym, force=force)
    if not force:
        ctx.delete_at(b2, 0, b2.size)
    ctx.apply()

    assert set(m.symbols) == {bar_sym}
    assert bi.symbolic_expressions == {}
    assert m.aux_data["functionNames"].data == {
        bar_uuid: bar_sym,
    }
    assert m.aux_data["symbolForwarding"].data == {}

    if file_format == gtirb.Module.FileFormat.ELF:
        assert m.aux_data["elfSymbolInfo"].data == {
            bar_sym: (0, "FUNC", "GLOBAL", "DEFAULT", 0),
        }
        if force:
            assert m.aux_data["cfiDirectives"].data == {
                gtirb.Offset(b2, 0): [
                    (".cfi_startproc", [], NULL_UUID),
                    (".cfi_personality", [0xFF], NULL_UUID),
                ],
                gtirb.Offset(b2, b2.size): [
                    (".cfi_endproc", [], NULL_UUID),
                ],
            }
        else:
            # If we use the delete_at path, the whole CFI procedure gets
            # removed.
            assert m.aux_data["cfiDirectives"].data == {}

        assert m.aux_data["elfSymbolTabIdxInfo"].data == {
            bar_sym: [(".symtab", 0)],
        }

    elif file_format == gtirb.Module.FileFormat.PE:
        assert m.aux_data["peExportedSymbols"].data == []
        assert m.aux_data["peImportedSymbols"].data == []


def test_delete_needed_symbol_elf_versions():
    """
    Tests that deleting a symbol updates the needed symbols in the
    elfSymbolVersions aux data table.
    """
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    strdup_sym = add_symbol(m, "strdup", add_proxy_block(m))
    add_needed_elf_symbol_version(m, strdup_sym, "libc.so.6", "GLIBC_2.2.5")

    strlen_sym = add_symbol(m, "strlen", add_proxy_block(m))
    add_needed_elf_symbol_version(m, strlen_sym, "libc.so.6", "GLIBC_2.3")

    read_sym = add_symbol(m, "read", add_proxy_block(m))
    add_needed_elf_symbol_version(
        m, read_sym, "libpthread.so.0", "GLIBC_2.2.5"
    )

    ctx = gtirb_rewriting.RewritingContext(m, [])
    ctx.delete_symbol(strlen_sym)
    ctx.delete_symbol(read_sym)
    ctx.apply()

    assert set(m.symbols) == {strdup_sym}
    assert m.aux_data["elfSymbolVersions"].data == (
        {},
        {"libc.so.6": {1: "GLIBC_2.2.5"}},
        {strdup_sym: (1, False)},
    )


def test_delete_defined_symbol_elf_versions():
    """
    Tests that deleting a symbol updates the defined symbols in the
    elfSymbolVersions aux data table.
    """
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    # Add GLIBC_2.3 version id with VER_FLG_BASE in its flags.
    add_elf_base_symbol_version(m, "GLIBC_2.3")

    strdup_sym = add_symbol(m, "strdup", add_proxy_block(m))
    add_defined_elf_symbol_version(m, strdup_sym, "GLIBC_2.2.5")

    strlen_sym = add_symbol(m, "strlen", add_proxy_block(m))
    # Add another GLIBC_2.3 version id, this time with no flags.
    add_defined_elf_symbol_version(m, strlen_sym, "GLIBC_2.3")

    ctx = gtirb_rewriting.RewritingContext(m, [])
    ctx.delete_symbol(strlen_sym)
    ctx.apply()

    assert set(m.symbols) == {strdup_sym}
    assert m.aux_data["elfSymbolVersions"].data == (
        {
            # We should delete the GLIBC_2.3 version id that has no flags
            # set, but keep the GLIBC_2.3 version id with VER_FLG_BASE set
            # because it relates to the library itself and not a symbol.
            1: (["GLIBC_2.3"], 1),
            2: (["GLIBC_2.2.5"], 0),
        },
        {},
        {strdup_sym: (2, False)},
    )
