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

import uuid

import gtirb
import pytest

import gtirb_rewriting


def test_offset_mapping():
    e0 = uuid.uuid4()
    e1 = uuid.uuid4()
    e2 = uuid.uuid4()

    m = gtirb_rewriting.OffsetMapping[str]()
    assert len(m) == 0
    assert gtirb.Offset(element_id=e0, displacement=0) not in m
    assert e0 not in m

    m[gtirb.Offset(element_id=e0, displacement=0)] = "A"
    assert len(m) == 1
    assert gtirb.Offset(element_id=e0, displacement=0) in m
    assert m[gtirb.Offset(element_id=e0, displacement=0)] == "A"
    assert m[e0] == {0: "A"}
    assert list(m.items()) == [
        (gtirb.Offset(element_id=e0, displacement=0), "A")
    ]

    m[e1] = {0: "B", 23: "C"}
    assert len(m) == 3
    assert gtirb.Offset(element_id=e1, displacement=23) in m
    assert e1 in m
    assert m[gtirb.Offset(element_id=e1, displacement=23)] == "C"
    assert m == {
        gtirb.Offset(element_id=e0, displacement=0): "A",
        gtirb.Offset(element_id=e1, displacement=0): "B",
        gtirb.Offset(element_id=e1, displacement=23): "C",
    }

    m[e1] = {15: "D", 23: "E"}
    assert len(m) == 3
    assert m == {
        gtirb.Offset(element_id=e0, displacement=0): "A",
        gtirb.Offset(element_id=e1, displacement=15): "D",
        gtirb.Offset(element_id=e1, displacement=23): "E",
    }

    del m[gtirb.Offset(element_id=e1, displacement=23)]
    assert len(m) == 2
    assert m == {
        gtirb.Offset(element_id=e0, displacement=0): "A",
        gtirb.Offset(element_id=e1, displacement=15): "D",
    }

    key = gtirb.Offset(element_id=e1, displacement=23)
    with pytest.raises(KeyError) as excinfo:
        del m[key]
    assert str(key) == str(excinfo.value)

    del m[e1]
    assert len(m) == 1
    assert m == {gtirb.Offset(element_id=e0, displacement=0): "A"}

    displacement_map = {}
    assert m.setdefault(e1, displacement_map) is displacement_map
    displacement_map[1] = "B"
    assert m == {
        gtirb.Offset(element_id=e0, displacement=0): "A",
        gtirb.Offset(element_id=e1, displacement=1): "B",
    }

    with pytest.raises(ValueError) as excinfo:
        m[e2] = "F"  # type: ignore (intentional)
    assert "not a MutableMapping" in str(excinfo.value)
