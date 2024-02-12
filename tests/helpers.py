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

import itertools
from typing import Dict, List, Sequence, Set, Tuple, Union

import gtirb
import gtirb_functions
import gtirb_rewriting
from gtirb_test_helpers import add_function

_VER_FLG_BASE = 1


def _get_or_insert_elf_symbol_versions(
    module: gtirb.Module,
) -> Tuple[
    Dict[int, Tuple[List[str], int]],
    Dict[str, Dict[int, str]],
    Dict[gtirb.Symbol, Tuple[int, bool]],
]:
    table = module.aux_data.get("elfSymbolVersions")
    if not table:
        table = module.aux_data["elfSymbolVersions"] = gtirb.AuxData(
            ({}, {}, {}),
            "tuple<mapping<uint16_t,tuple<sequence<string>,uint16_t>>,"
            "mapping<string,mapping<uint16_t,string>>,"
            "mapping<UUID,tuple<uint16_t,bool>>>",
        )
    return table.data


def _next_symbol_id(
    symver_defs: Dict[int, Tuple[List[str], int]],
    symver_needed: Dict[str, Dict[int, str]],
) -> int:
    """
    Determines the next unused version id for an elfSymbolVersions aux data
    table.
    """
    return (
        max(itertools.chain(symver_defs, *symver_needed.values()), default=0)
        + 1
    )


def add_elf_base_symbol_version(
    module: gtirb.Module,
    version: str,
) -> int:
    """
    Add or update the ELF symbol version of the module itself (i.e., the
    version definition marked as VER_FLG_BASE).

    The string value of this version is typically the name of the library,
    e.g., `libc.so.6` is used for libc.
    """
    (
        symver_defs,
        symver_needed,
        _,
    ) = _get_or_insert_elf_symbol_versions(module)

    for version_id, (_, flags) in symver_defs.items():
        if flags == _VER_FLG_BASE:
            break
    else:
        version_id = _next_symbol_id(symver_defs, symver_needed)
    symver_defs[version_id] = ([version], _VER_FLG_BASE)

    return version_id


def add_defined_elf_symbol_version(
    module: gtirb.Module,
    symbol: gtirb.Symbol,
    version: str,
    *,
    previous_versions: Sequence[str] = (),
    hidden: bool = False,
) -> int:
    """
    Adds ELF symbol versioning for a symbol defined in the module.

    :param module: The module to update aux data in.
    :param symbol: The symbol to add a version for.
    :param version: The symbol version string, e.g. "GLIBC_2.2.5".
    :param previous_versions: Older versions that this function was known by.
    :param hidden: Causes the symbol to be ignored by the static linker.
    :return: The version ID that was added to the aux data.
    """

    (
        symver_defs,
        symver_needed,
        symbol_versions,
    ) = _get_or_insert_elf_symbol_versions(module)

    if symbol in symbol_versions:
        raise ValueError(f"symbol {symbol.name} has already been versioned")

    for version_id, (versions, flags) in symver_defs.items():
        if (
            versions[0] == version
            and versions[1:] == previous_versions
            and flags != _VER_FLG_BASE
        ):
            break
    else:
        version_id = _next_symbol_id(symver_defs, symver_needed)
        symver_defs[version_id] = ([version, *previous_versions], 0)

    symbol_versions[symbol] = (version_id, hidden)
    return version_id


def add_needed_elf_symbol_version(
    module: gtirb.Module,
    symbol: gtirb.Symbol,
    library: str,
    version: str,
    *,
    hidden: bool = False,
) -> int:
    """
    Adds ELF symbol versioning for a symbol needed by the module.

    :param module: The module to update aux data in.
    :param symbol: The symbol to add a version for.
    :param library: The name of the library defining the symbol.
    :param version: The symbol version string, e.g. "GLIBC_2.2.5".
    :param hidden: Causes the symbol to be ignored by the static linker.
    :return: The version ID that was added to the aux data.
    """

    (
        symver_defs,
        symver_needed,
        symbol_versions,
    ) = _get_or_insert_elf_symbol_versions(module)

    if symbol in symbol_versions:
        raise ValueError(f"symbol {symbol.name} has already been versioned")

    library_versions = symver_needed.setdefault(library, {})
    for version_id, lib_version in library_versions.items():
        if version == lib_version:
            break
    else:
        version_id = _next_symbol_id(symver_defs, symver_needed)
        library_versions[version_id] = version

    symbol_versions[symbol] = (version_id, hidden)
    return version_id


def add_function_object(
    module: gtirb.Module,
    sym_or_name: Union[str, gtirb.Symbol],
    entry_block: gtirb.CodeBlock,
    other_blocks: Set[gtirb.CodeBlock] = set(),
) -> gtirb_functions.Function:
    """
    Adds a function to all the appropriate aux data tables and creates a
    Function object.
    """

    func_uuid = add_function(module, sym_or_name, entry_block, other_blocks)
    name_sym = module.aux_data["functionNames"].data[func_uuid]
    return gtirb_functions.Function(
        func_uuid, {entry_block}, {entry_block} | other_blocks, [name_sym]
    )


def literal_patch(asm: str) -> gtirb_rewriting.Patch:
    """
    Creates a patch from a literal string. The patch will have an empty
    constraints object.
    """

    @gtirb_rewriting.patch_constraints()
    def patch(ctx):
        return asm

    return gtirb_rewriting.Patch.from_function(patch)


def remove_indentation(s: str) -> str:
    """
    Removes indentation from the front of each line in a string, omitting any
    purely empty lines.
    """
    lines = []
    for line in s.splitlines():
        line = line.lstrip()
        if line:
            lines.append(line)
    return "\n".join(lines)
