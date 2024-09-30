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

from typing import Dict

import gtirb
import pytest
from gtirb_test_helpers import (
    add_code_block,
    add_text_section,
    create_test_module,
)

import gtirb_rewriting._auxdata as _auxdata
import gtirb_rewriting._auxdata_offsetmap as _auxdata_offsetmap
from gtirb_rewriting import OffsetMapping


def test_auxdata_simple():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m)
    b = add_code_block(bi, b"\x90")
    m.aux_data.clear()

    assert _auxdata.comments.container_type is gtirb.Module
    assert _auxdata.comments.name == "comments"
    assert _auxdata.comments.type_name == "mapping<Offset,string>"
    assert _auxdata.comments.static_type == Dict[gtirb.Offset, str]

    assert not _auxdata.comments.exists(m)

    comments = _auxdata.comments.get(m)
    assert comments is None

    comments = _auxdata.comments.get_or_insert(m)
    assert isinstance(comments, dict)
    assert comments == {}
    assert _auxdata.comments.exists(m)

    assert "comments" in m.aux_data
    table = m.aux_data["comments"]
    assert table.data is comments
    assert table.type_name == "mapping<Offset,string>"

    table.type_name = "string"
    with pytest.raises(TypeError):
        _auxdata.comments.get(m)

    _auxdata.comments.remove(m)
    assert "comments" not in m.aux_data

    assert not _auxdata.elf_dynamic_init.exists(m)
    _auxdata.elf_dynamic_init.set(m, b)
    assert _auxdata.elf_dynamic_init.get(m) is b
    _auxdata.elf_dynamic_init.remove(m)


def test_auxdata_offsetmap():
    ir = gtirb.IR()
    m = gtirb.Module(name="test", ir=ir)

    assert _auxdata_offsetmap.comments.container_type is gtirb.Module
    assert _auxdata_offsetmap.comments.name == "comments"
    assert _auxdata_offsetmap.comments.type_name == "mapping<Offset,string>"
    assert _auxdata_offsetmap.comments.static_type == OffsetMapping[str]

    comments = _auxdata_offsetmap.comments.get(m)
    assert comments is None

    comments = _auxdata_offsetmap.comments.get_or_insert(m)
    assert isinstance(comments, OffsetMapping)
    assert comments == {}

    assert "comments" in m.aux_data
    table = m.aux_data["comments"]
    assert table.data is comments
    assert table.type_name == "mapping<Offset,string>"

    # Now make the table be a normal dict to ensure that our prepared table
    # definition converts the class.
    table.data = {}

    comments = _auxdata_offsetmap.comments.get(m)
    assert isinstance(comments, OffsetMapping)
    assert comments == {}
