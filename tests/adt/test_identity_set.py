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

import gtirb_rewriting._adt


def test_identity_set():
    x1 = {}
    x2 = {}
    x3 = {}
    s = gtirb_rewriting._adt.IdentitySet[dict]()
    s.add(x1)
    s.add(x2)
    assert len(s) == 2
    assert x1 in s
    assert x2 in s
    assert x3 not in s
    s.remove(x2)
    assert len(s) == 1
    assert x1 in s
    assert x2 not in s
    assert x3 not in s
