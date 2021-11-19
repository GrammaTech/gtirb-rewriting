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
import pytest
from gtirb_test_helpers import (
    add_code_block,
    add_edge,
    add_proxy_block,
    add_symbol,
    add_text_section,
    create_test_module,
)
from helpers import add_function_object


def test_return_cache():
    ir, m = create_test_module(
        isa=gtirb.Module.ISA.X64, file_format=gtirb.Module.FileFormat.ELF,
    )
    _, bi = add_text_section(m)

    # This mimics:
    #  func1:
    #  jne foo
    #  ret
    foo_sym = add_symbol(m, "foo", add_proxy_block(m))
    b1 = add_code_block(bi, b"\x75\x00", {1: gtirb.SymAddrConst(0, foo_sym)})
    b2 = add_code_block(bi, b"\xC3")

    return_proxy = add_proxy_block(m)
    add_edge(
        ir.cfg, b1, foo_sym.referent, gtirb.Edge.Type.Branch, conditional=True
    )
    add_edge(ir.cfg, b1, b2, gtirb.Edge.Type.Fallthrough)
    proxy_return_edge = add_edge(
        ir.cfg, b2, return_proxy, gtirb.Edge.Type.Return
    )

    with gtirb_rewriting.modify._make_return_cache(ir) as return_cache:
        assert not return_cache.any_return_edges(b1)
        assert return_cache.block_return_edges(b1) == set()
        assert return_cache.block_proxy_return_edges(b1) == set()

        assert return_cache.any_return_edges(b2)
        assert return_cache.block_return_edges(b2) == {proxy_return_edge}
        assert return_cache.block_proxy_return_edges(b2) == {proxy_return_edge}

        # Discard the return edge and try again
        ir.cfg.discard(proxy_return_edge)

        assert not return_cache.any_return_edges(b2)
        assert return_cache.block_return_edges(b2) == set()
        assert return_cache.block_proxy_return_edges(b2) == set()

        # Then add a new edge that isn't a proxy block
        return_edge = add_edge(ir.cfg, b2, b1, gtirb.Edge.Type.Return)

        assert return_cache.any_return_edges(b2)
        assert return_cache.block_return_edges(b2) == {return_edge}
        assert return_cache.block_proxy_return_edges(b2) == set()


def test_return_cache_decorator():
    ir, m = create_test_module(
        isa=gtirb.Module.ISA.X64, file_format=gtirb.Module.FileFormat.ELF,
    )
    _, bi = add_text_section(m)
    orig_cfg = ir.cfg

    b1 = add_code_block(bi, b"\x90")
    b2 = add_code_block(bi, b"\xC3")
    edge1 = add_edge(ir.cfg, b1, b2, gtirb.Edge.Type.Fallthrough)

    with gtirb_rewriting.modify._make_return_cache(ir) as return_cache:
        with gtirb_rewriting.modify._make_return_cache(ir) as return_cache2:
            assert return_cache is return_cache2
            assert ir.cfg is return_cache

        assert ir.cfg is return_cache
        assert set(ir.cfg) == {edge1}

        edge2 = add_edge(ir.cfg, b2, b1, gtirb.Edge.Type.Return)
        ir.cfg.discard(edge1)

    assert ir.cfg is orig_cfg
    assert set(ir.cfg) == {edge2}

    # Now test that we catch modifications to the original CFG
    with pytest.raises(gtirb_rewriting.CFGModifiedError):
        with gtirb_rewriting.modify._make_return_cache(ir) as return_cache:
            orig_cfg.discard(edge2)
            orig_cfg.add(edge1)
    assert ir.cfg is orig_cfg

    with pytest.raises(gtirb_rewriting.CFGModifiedError):
        with gtirb_rewriting.modify._make_return_cache(ir) as return_cache:
            ir.cfg = gtirb.CFG()
    assert ir.cfg is orig_cfg

    # And that we restore the old CFG correctly with exceptions
    with pytest.raises(ZeroDivisionError):
        with gtirb_rewriting.modify._make_return_cache(ir) as return_cache:
            raise ZeroDivisionError()
    assert ir.cfg is orig_cfg


def test_modify_cache():
    ir, m = create_test_module(
        isa=gtirb.Module.ISA.X64, file_format=gtirb.Module.FileFormat.ELF,
    )
    _, bi = add_text_section(m)

    # This mimics:
    #  ret
    #  ud2
    b1 = add_code_block(bi, b"\xC3")
    b2 = add_code_block(bi, b"\x0F\x0B")
    func = add_function_object(m, "func", b1)

    modify_cache = gtirb_rewriting.modify._ModifyCache(
        m, [func], gtirb_rewriting.modify._ReturnEdgeCache(ir.cfg)
    )

    assert modify_cache.functions_by_block[b1] == func.uuid
    assert b2 not in modify_cache.functions_by_block
