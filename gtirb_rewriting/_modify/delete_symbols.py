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

"""
Functionality for deleting Symbols.
"""

from dataclasses import dataclass
from typing import Mapping, Set
from uuid import UUID

import gtirb

from .. import _auxdata
from ..dwarf.dwarf2 import PointerEncodings

_VER_FLG_BASE = 0x1


class SymbolUsesRemainingError(Exception):
    """
    A symbol has been requested to be deleted but still has uses in the
    program.
    """

    def __init__(self, symbol: gtirb.Symbol) -> None:
        super().__init__(f"{symbol.name} still has uses")
        self.symbol = symbol


@dataclass
class SymbolDeletionOptions:
    """
    Options that can be specified when deleting a symbol.
    """

    force: bool
    """
    When True, the symbol will be deleted even if there are symbolic
    expressions remaining that refer to the symbol. These expressions will be
    deleted.
    """


def delete_symbols(
    module: gtirb.Module, symbols: Mapping[gtirb.Symbol, SymbolDeletionOptions]
) -> None:
    """
    Delete symbols from a module and adjust all relevant aux data tables.
    """

    _delete_auxdata_entries(module, symbols)

    _delete_symbolic_expressions(module, symbols)

    for symbol in symbols:
        symbol.module = None


def _delete_auxdata_entries(
    module: gtirb.Module, symbols: Mapping[gtirb.Symbol, SymbolDeletionOptions]
) -> None:
    """
    Updates or deletes all of the aux data entries that refer to deleted
    symbols.
    """

    _update_cfi_directive_symbols(module, symbols)
    _delete_elf_symbol_info(module, symbols)
    _delete_elf_symbol_tab_idx_info(module, symbols)
    _delete_elf_symbol_versions(module, symbols)
    _delete_function_names(module, symbols)
    _delete_pe_imported_symbols(module, symbols)
    _delete_pe_exported_symbols(module, symbols)
    _delete_symbol_forwarding(module, symbols)


def _delete_elf_symbol_tab_idx_info(
    module: gtirb.Module, symbols: Mapping[gtirb.Symbol, SymbolDeletionOptions]
) -> None:
    """
    Removes symbols from the elfSymbolTabIdx aux data table.
    """
    elf_symbol_tab_idx_auxdata = _auxdata.elf_symbol_tab_idx_info.get(module)
    if not elf_symbol_tab_idx_auxdata:
        return

    for symbol in symbols:
        elf_symbol_tab_idx_auxdata.pop(symbol, None)


def _delete_pe_imported_symbols(
    module: gtirb.Module, symbols: Mapping[gtirb.Symbol, SymbolDeletionOptions]
) -> None:
    """
    Removes symbols from the peImportedSymbols aux data table.
    """
    pe_import_auxdata = _auxdata.pe_imported_symbols.get(module)
    if not pe_import_auxdata:
        return

    _auxdata.pe_imported_symbols.set(
        module,
        [
            import_symbol
            for import_symbol in pe_import_auxdata
            if import_symbol not in symbols
        ],
    )


def _delete_pe_exported_symbols(
    module: gtirb.Module, symbols: Mapping[gtirb.Symbol, SymbolDeletionOptions]
) -> None:
    """
    Removes symbols from the peExportedSymbols aux data table.
    """
    pe_export_symbols = _auxdata.pe_exported_symbols.get(module)
    if not pe_export_symbols:
        return

    _auxdata.pe_exported_symbols.set(
        module,
        [
            export_symbol
            for export_symbol in pe_export_symbols
            if export_symbol not in symbols
        ],
    )


def _delete_symbolic_expressions(
    module: gtirb.Module, symbols: Mapping[gtirb.Symbol, SymbolDeletionOptions]
) -> None:
    """
    Deletes any symbolic expressions that refer to the removed symbols.
    """
    for byte_interval in module.byte_intervals:
        to_drop = set()
        for offset, expr in byte_interval.symbolic_expressions.items():
            for sym in expr.symbols:
                opts = symbols.get(sym)
                if opts:
                    if opts.force:
                        to_drop.add(offset)
                    else:
                        raise SymbolUsesRemainingError(sym)
        for offset in to_drop:
            del byte_interval.symbolic_expressions[offset]


def _delete_elf_symbol_versions(
    module: gtirb.Module, symbols: Mapping[gtirb.Symbol, SymbolDeletionOptions]
) -> None:
    """
    Removes symbols from the elfSymbolVersions aux data table, cleaning up
    unused version ids and libraries.
    """
    symbol_versions_auxdata = _auxdata.elf_symbol_versions.get(module)
    if not symbol_versions_auxdata:
        return

    defs, reqs, entries = symbol_versions_auxdata
    for symbol in symbols:
        entries.pop(symbol, None)

    # Create a list of all Symbol IDs used
    ids_to_keep: Set[int] = set(id for id, _ in entries.values())

    # Remove ElfSymDefs which have no remaining entries
    ids_to_remove = [id for id in defs.keys() if id not in ids_to_keep]
    for id in ids_to_remove:
        # Keep library file definitions
        versions, flags = defs[id]
        if flags != _VER_FLG_BASE:
            del defs[id]

    # Remove ElfSymVerNeeded which have no remaining versions
    libs_to_remove = []
    for lib, versions in reqs.items():
        ids_to_remove = [id for id in versions.keys() if id not in ids_to_keep]
        for id in ids_to_remove:
            del versions[id]
            if not versions:
                libs_to_remove.append(lib)
    for lib in libs_to_remove:
        del reqs[lib]


def _delete_symbol_forwarding(
    module: gtirb.Module, symbols: Mapping[gtirb.Symbol, SymbolDeletionOptions]
) -> None:
    """
    Remove entries from the symbolForwarding aux data table for deleted
    symbols.
    """
    symbol_forwarding_auxdata = _auxdata.symbol_forwarding.get(module)
    if not symbol_forwarding_auxdata:
        return

    to_remove: Set[gtirb.Symbol] = set()
    for key, value in symbol_forwarding_auxdata.items():
        if key in symbols or value in symbols:
            to_remove.add(key)
    for key in to_remove:
        del symbol_forwarding_auxdata[key]


def _update_cfi_directive_symbols(
    module: gtirb.Module, symbols: Mapping[gtirb.Symbol, SymbolDeletionOptions]
) -> None:
    """
    Update any CFI directives that refer to a deleted symbol.
    """
    cfi_auxdata = _auxdata.cfi_directives.get(module)
    if not cfi_auxdata:
        return

    for directives in cfi_auxdata.values():
        for i, (directive, args, symbol) in enumerate(directives):
            if symbol in symbols:
                # These directives have an argument which is the encoding of
                # the pointer. Since we're getting rid of the value, also set
                # the pointer encoding to DW_EH_PE_OMIT.
                if directive in (".cfi_personality", ".cfi_lsda"):
                    directives[i] = (
                        directive,
                        [PointerEncodings.omit.value],
                        _auxdata.NULL_UUID,
                    )
                else:
                    directives[i] = (directive, args, _auxdata.NULL_UUID)


def _delete_elf_symbol_info(
    module: gtirb.Module, symbols: Mapping[gtirb.Symbol, SymbolDeletionOptions]
) -> None:
    """
    Remove entries from the elfSymbolInfo aux data table for deleted symbols.
    """
    elf_symbol_info_auxdata = _auxdata.elf_symbol_info.get(module)
    if not elf_symbol_info_auxdata:
        return

    for symbol in symbols:
        elf_symbol_info_auxdata.pop(symbol, None)


def _delete_function_names(
    module: gtirb.Module, symbols: Mapping[gtirb.Symbol, SymbolDeletionOptions]
) -> None:
    """
    Remove functionNames aux data entries that refer to the deleted symbols.
    """
    names_auxdata = _auxdata.function_names.get(module)
    if not names_auxdata:
        return

    remove_uuids: Set[UUID] = set()
    for uuid, name in names_auxdata.items():
        if name in symbols:
            remove_uuids.add(uuid)
    for uuid in remove_uuids:
        del names_auxdata[uuid]
