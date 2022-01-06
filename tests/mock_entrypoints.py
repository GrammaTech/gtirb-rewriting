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

# Mock utilities for the entrypoints module

import contextlib
from typing import Mapping, Sequence

import entrypoints as entrypoints_module


@contextlib.contextmanager
def mock_entrypoints(
    entrypoints: Mapping[str, Sequence[entrypoints_module.EntryPoint]]
):
    def mock_get_single(group, name, path=None):
        for ep in entrypoints.get(group, ()):
            if ep.name == name:
                return ep
        raise entrypoints_module.NoSuchEntryPoint(group, name)

    def mock_get_group_all(group, path=None):
        return entrypoints.get(group, ())

    def mock_get_group_named(group, path=None):
        result = {}
        for ep in mock_get_group_all(group, path=path):
            if ep.name not in result:
                result[ep.name] = ep
        return result

    orig_get_single = entrypoints_module.get_single
    orig_get_group_all = entrypoints_module.get_group_all
    orig_get_group_named = entrypoints_module.get_group_named

    entrypoints_module.get_single = mock_get_single
    entrypoints_module.get_group_all = mock_get_group_all
    entrypoints_module.get_group_named = mock_get_group_named

    try:
        yield
    finally:
        entrypoints_module.get_single = orig_get_single
        entrypoints_module.get_group_all = orig_get_group_all
        entrypoints_module.get_group_named = orig_get_group_named
