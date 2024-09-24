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
import contextlib
from typing import Iterator

import gtirb
from gtirb_layout import (
    assign_integral_symbols,
    is_module_layout_required,
    layout_module,
)

import gtirb_rewriting._auxdata as _auxdata

from .intervalutils import join_byte_intervals, split_byte_interval


@contextlib.contextmanager
def prepare_for_rewriting(module: gtirb.Module, nop: bytes) -> Iterator[None]:
    """Pre-compute data structure to accelerate rewriting."""

    if is_module_layout_required(module):
        layout_module(module)
    else:
        assign_integral_symbols(module)

    alignment = (
        {} if module.file_format == gtirb.Module.FileFormat.ELF else None
    )
    if _auxdata.alignment.exists(module):
        alignment = _auxdata.alignment.get_or_insert(module)

    partitions = []
    for interval in tuple(module.byte_intervals):
        partitions.append(split_byte_interval(interval, alignment))

    yield

    for partition in partitions:
        join_byte_intervals(partition, nop, alignment)
        for interval in partition[1:]:
            interval.section = None

    if is_module_layout_required(module):
        layout_module(module)
