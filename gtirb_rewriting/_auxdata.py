# GTIRB-Rewriting Rewriting API for GTIRB
# Copyright (C) 2022 GrammaTech, Inc.
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

import uuid
from typing import (
    Any,
    Callable,
    Dict,
    Generic,
    List,
    Optional,
    Set,
    Tuple,
    Type,
    TypeVar,
    cast,
    overload,
)

import gtirb
from typing_extensions import Literal

try:
    from typing_extensions import get_origin  # type: ignore
except ImportError:
    # typing_extensions does not define this on Python 3.6, but we can sort
    # of make it work in the limited situations we care about.
    def get_origin(tp: Any) -> Optional[Any]:
        origin = getattr(tp, "__origin__", None)
        if origin is Dict:
            return dict
        if origin is List:
            return list
        if origin is Set:
            return set
        if origin is Tuple:
            return tuple
        return origin


DataT = TypeVar("DataT")
ContainerT = TypeVar("ContainerT", bound=gtirb.AuxDataContainer)


class TableDefinition(Generic[ContainerT, DataT]):
    """
    An aux data table definition that provides type-safe accessors to the
    data.
    """

    def __init__(
        self,
        container_type: Type[ContainerT],
        name: str,
        type_name: str,
        static_type: Type[DataT],
        table_hook: Optional[Callable[[gtirb.AuxData], None]] = None,
    ):
        self.container_type = container_type
        self.name = name
        self.type_name = type_name
        self.static_type = static_type
        self.initializer = (
            cast(Type[DataT], get_origin(static_type)) or static_type
        )
        self.table_hook = table_hook

    @overload
    def _get_or_insert_table(
        self,
        container: ContainerT,
        create: Literal[True],
    ) -> gtirb.AuxData:
        ...

    @overload
    def _get_or_insert_table(
        self,
        container: ContainerT,
        create: bool = False,
    ) -> Optional[gtirb.AuxData]:
        ...

    def _get_or_insert_table(
        self,
        container: ContainerT,
        create: bool = False,
    ) -> Optional[gtirb.AuxData]:
        """
        Gets an aux data table from a container, potentially creating it if it
        does not already exist.
        """

        table = container.aux_data.get(self.name)
        if table is None and not create:
            return None

        if table is None:
            table = gtirb.AuxData(self.initializer(), self.type_name)
            container.aux_data[self.name] = table
        elif table.type_name != self.type_name:
            raise TypeError(
                f"existing aux data for {self.name} is not the right type"
                f"(got '{table.type_name}', expected '{self.type_name}'"
            )

        if self.table_hook:
            self.table_hook(table)

        return table

    def exists(self, container: ContainerT) -> bool:
        """
        Checks if the aux data table exists in the container.
        """
        return self.name in container.aux_data

    def get(self, container: ContainerT) -> Optional[DataT]:
        """
        Gets the aux data table's data, if it exists.
        """
        table = self._get_or_insert_table(container, False)
        return table.data if table else None

    def get_or_insert(self, container: ContainerT) -> DataT:
        """
        Gets the aux data table's data, creating it if needed.
        """
        return self._get_or_insert_table(container, True).data

    def remove(self, container: ContainerT) -> None:
        """
        Removes the aux data table form the container, if it exists.
        """
        if self.name in container.aux_data:
            del container.aux_data[self.name]


def define_table(
    container_type: Type[ContainerT],
    name: str,
    gt_type: str,
    py_type: Type[DataT],
) -> TableDefinition[ContainerT, DataT]:
    """
    Defines an aux data table.

    :param container_type: The container type, Module or IR, that the aux data
                           table can be within.
    :param name: The name of the aux data table.
    :param gt_type: The GTIRB type encoding for the aux data table.
    :param py_type: The static Python type for the data in the aux data table.
    """
    return TableDefinition[ContainerT, DataT](
        container_type, name, gt_type, py_type
    )


# Sanctioned AuxData tables

alignment = define_table(
    gtirb.Module,
    "alignment",
    "mapping<UUID,uint64_t>",
    Dict[gtirb.Node, int],
)

comments = define_table(
    gtirb.Module,
    "comments",
    "mapping<Offset,string>",
    Dict[gtirb.Offset, str],
)

function_entries = define_table(
    gtirb.Module,
    "functionEntries",
    "mapping<UUID,set<UUID>>",
    Dict[uuid.UUID, Set[gtirb.CodeBlock]],
)

function_blocks = define_table(
    gtirb.Module,
    "functionBlocks",
    "mapping<UUID,set<UUID>>",
    Dict[uuid.UUID, Set[gtirb.CodeBlock]],
)

function_names = define_table(
    gtirb.Module,
    "functionNames",
    "mapping<UUID,UUID>",
    Dict[uuid.UUID, gtirb.Symbol],
)

padding = define_table(
    gtirb.Module,
    "padding",
    "mapping<Offset,uint64_t>",
    Dict[gtirb.Offset, int],
)

symbol_forwarding = define_table(
    gtirb.Module,
    "symbolForwarding",
    "mapping<UUID,UUID>",
    Dict[gtirb.Symbol, gtirb.Symbol],
)

types = define_table(
    gtirb.Module,
    "types",
    "mapping<UUID,string>",
    Dict[gtirb.DataBlock, str],
)


# Provisional AuxData tables

binary_type = define_table(
    gtirb.Module,
    "binaryType",
    "sequence<string>",
    List[str],
)

cfi_directives = define_table(
    gtirb.Module,
    "cfiDirectives",
    "mapping<Offset,sequence<tuple<string,sequence<int64_t>,UUID>>>",
    Dict[gtirb.Offset, List[Tuple[str, List[int], Optional[gtirb.Symbol]]]],
)

elf_symbol_info = define_table(
    gtirb.Module,
    "elfSymbolInfo",
    "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>",
    Dict[gtirb.Symbol, Tuple[int, str, str, str, int]],
)

# Legacy table that's been renamed to sectionProperties
elf_section_properties = define_table(
    gtirb.Module,
    "elfSectionProperties",
    "mapping<UUID,tuple<uint64_t,uint64_t>>",
    Dict[gtirb.Section, Tuple[int, int]],
)

section_properties = define_table(
    gtirb.Module,
    "sectionProperties",
    "mapping<UUID,tuple<uint64_t,uint64_t>>",
    Dict[gtirb.Section, Tuple[int, int]],
)

encodings = define_table(
    gtirb.Module,
    "encodings",
    "mapping<UUID,string>",
    Dict[gtirb.DataBlock, str],
)

libraries = define_table(
    gtirb.Module,
    "libraries",
    "sequence<string>",
    List[str],
)

library_paths = define_table(
    gtirb.Module,
    "libraryPaths",
    "sequence<string>",
    List[str],
)

pe_import_entries = define_table(
    gtirb.Module,
    "peImportEntries",
    "sequence<tuple<uint64_t,int64_t,string,string>>",
    List[Tuple[int, int, str, str]],
)

pe_imported_symbols = define_table(
    gtirb.Module,
    "peImportedSymbols",
    "sequence<UUID>",
    List[gtirb.Symbol],
)

pe_resource = define_table(
    gtirb.Module,
    "peResource",
    "sequence<tuple<sequence<uint8>,gtirb.Offset,uint64_t>>",
    List[Tuple[List[int], gtirb.Offset, int]],
)

symbolic_expression_sizes = define_table(
    gtirb.Module,
    "symbolicExpressionSizes",
    "mapping<Offset,uint64_t>",
    Dict[gtirb.Offset, int],
)

# Module-level gtirb-rewriting tables

leaf_functions = define_table(
    gtirb.Module,
    "leafFunctions",
    "mapping<UUID,uint8_t>",
    Dict[uuid.UUID, int],
)


def compat_section_properties(
    module: gtirb.Module,
) -> Dict[gtirb.Section, Tuple[int, int]]:
    """
    Gets the sectionProperties (modern) or elfSectionProperties (older) aux
    data table, depending on which one is present. This is for backwards
    compatibility.
    """

    result = section_properties.get(module)
    if result is not None:
        return result

    if module.file_format == gtirb.Module.FileFormat.ELF:
        result = elf_section_properties.get(module)
        if result is not None:
            return result

    return section_properties.get_or_insert(module)
