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

from typing import Any, Dict, Tuple, cast

import gtirb
import gtirb_rewriting._auxdata as _auxdata

from ._auxdata import ContainerT, DataT, TableDefinition
from .utils import OffsetMapping

try:
    from typing_extensions import get_args  # type: ignore
except ImportError:
    # typing_extensions does not define this on Python 3.6, but we can sort
    # of make it work in the limited situations we care about.
    def get_args(tp: Any) -> Tuple[Any, ...]:
        return getattr(tp, "__args__", ())


def _make_offsetmap_table(
    table: TableDefinition[ContainerT, Dict[gtirb.Offset, DataT]]
) -> TableDefinition[ContainerT, OffsetMapping[DataT]]:
    """
    Creates a table definition that will ensure that the table data is an
    OffsetMapping object.
    """

    def table_hook(table: gtirb.AuxData) -> None:
        if not isinstance(table.data, OffsetMapping):
            table.data = OffsetMapping(table.data)

    _, value_type = get_args(table.static_type)

    return TableDefinition[ContainerT, OffsetMapping[DataT]](
        table.container_type,
        table.name,
        table.type_name,
        OffsetMapping[value_type],
        table_hook=table_hook,
    )


comments = _make_offsetmap_table(_auxdata.comments)
cfi_directives = _make_offsetmap_table(_auxdata.cfi_directives)
symbolic_expression_sizes = _make_offsetmap_table(
    _auxdata.symbolic_expression_sizes
)
padding = _make_offsetmap_table(_auxdata.padding)


# We want to erase the static type information for the values, so cast to a
# tuple of OffsetMapping[Any]. It's not actually the truth, but it's more
# useful and results in less noise.
OFFSETMAP_AUX_DATA_TABLES = cast(
    Tuple[TableDefinition[gtirb.Module, OffsetMapping[Any]], ...],
    (
        comments,
        cfi_directives,
        padding,
        symbolic_expression_sizes,
    ),
)
