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

import gtirb
import gtirb_rewriting
from helpers import (
    add_code_block,
    add_edge,
    add_function,
    add_proxy_block,
    add_symbol,
    create_test_module,
)


def test_modify_cache():
    ir, m, bi = create_test_module()

    # This mimics:
    #  func1:
    #  jne foo
    #  ret
    foo_sym = add_symbol(m, "foo", add_proxy_block(m))
    b1 = add_code_block(bi, b"\x75\x00", {1: gtirb.SymAddrConst(0, foo_sym)})
    b2 = add_code_block(bi, b"\xC3")
    func = add_function(m, "func", b1, {b2})
    b3 = add_code_block(bi, b"\x0F\x0B")

    return_proxy = add_proxy_block(m)
    add_edge(
        ir.cfg, b1, foo_sym.referent, gtirb.Edge.Type.Branch, conditional=True
    )
    add_edge(ir.cfg, b1, b2, gtirb.Edge.Type.Fallthrough)
    proxy_return_edge = add_edge(
        ir.cfg, b2, return_proxy, gtirb.Edge.Type.Return
    )

    with gtirb_rewriting.modify._ModifyCache(m, [func]) as cache:
        assert cache.functions_by_block[b1] == func.uuid
        assert cache.functions_by_block[b2] == func.uuid
        assert b3 not in cache.functions_by_block

        assert not cache.any_return_edges(b1)
        assert cache.block_return_edges(b1) == set()
        assert cache.block_proxy_return_edges(b1) == set()

        assert cache.any_return_edges(b2)
        assert cache.block_return_edges(b2) == {proxy_return_edge}
        assert cache.block_proxy_return_edges(b2) == {proxy_return_edge}

        # Discard the return edge and try again
        ir.cfg.discard(proxy_return_edge)

        assert not cache.any_return_edges(b2)
        assert cache.block_return_edges(b2) == set()
        assert cache.block_proxy_return_edges(b2) == set()

        # Then add a new edge that isn't a proxy block
        return_edge = add_edge(ir.cfg, b2, b1, gtirb.Edge.Type.Return)

        assert cache.any_return_edges(b2)
        assert cache.block_return_edges(b2) == {return_edge}
        assert cache.block_proxy_return_edges(b2) == set()
