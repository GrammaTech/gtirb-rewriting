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
import pytest
from gtirb_capstone.instructions import GtirbInstructionDecoder
from gtirb_rewriting import RewritingContext
from gtirb_rewriting._modify import retarget_symbols
from gtirb_test_helpers import (
    add_code_block,
    add_edge,
    add_proxy_block,
    add_symbol,
    add_text_section,
    create_test_module,
)


@pytest.mark.parametrize("use_rwc", (True, False))
def test_retarget_intern_symbol_to_extern_symbol(use_rwc: bool):
    # This mimics:
    # main:
    # mov rax, local_func
    # call local_func
    # ret
    #
    # local_func:
    # ud2
    #
    #

    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    main_sym = add_symbol(m, "main")
    local_func_sym = add_symbol(m, "local_func")

    b1 = add_code_block(
        bi,
        b"\x48\x8B\x04\x25\x00\x00\x00\x00\xE8\x00\x00\x00\x00",
        {
            (4, 4): gtirb.SymAddrConst(0, local_func_sym),
            (9, 4): gtirb.SymAddrConst(0, local_func_sym),
        },
    )
    main_sym.referent = b1
    b2 = add_code_block(bi, b"\xC3")
    b3 = add_code_block(bi, b"\x0F\x0B")
    local_func_sym.referent = b3

    fallthrough_edge = add_edge(ir.cfg, b1, b2, gtirb.EdgeType.Fallthrough)
    add_edge(ir.cfg, b1, b3, gtirb.EdgeType.Call)
    return_edge = add_edge(
        ir.cfg, b2, add_proxy_block(m), gtirb.EdgeType.Return
    )

    extern_proxy = add_proxy_block(m)
    extern_sym = add_symbol(m, "external_func", extern_proxy)

    if use_rwc:
        ctx = RewritingContext(m, [])
        ctx.retarget_symbol_uses(local_func_sym, extern_sym)
        ctx.apply()
    else:
        retarget_symbols(
            m, {local_func_sym: extern_sym}, GtirbInstructionDecoder(m.isa)
        )

    assert local_func_sym.module is m
    assert local_func_sym.referent is b3

    assert not set(b3.incoming_edges)
    assert set(ir.cfg) == {
        fallthrough_edge,
        return_edge,
        gtirb.Edge(b1, extern_proxy, gtirb.EdgeLabel(gtirb.EdgeType.Call)),
    }

    assert dict(bi.symbolic_expressions) == {
        4: gtirb.SymAddrConst(
            0, extern_sym, {gtirb.SymbolicExpression.Attribute.PLT}
        ),
        9: gtirb.SymAddrConst(
            0, extern_sym, {gtirb.SymbolicExpression.Attribute.PLT}
        ),
    }


@pytest.mark.parametrize("use_rwc", (True, False))
def test_retarget_extern_symbol_to_intern_symbol(use_rwc: bool):
    # This mimics:
    # main:
    # mov rax, extern_func@PLT
    # call extern_func@PLT
    # ret
    # local_func:
    # ud2
    #

    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    extern_func_sym = add_symbol(m, "extern_func", add_proxy_block(m))
    main_sym = add_symbol(m, "main")
    local_func_sym = add_symbol(m, "local_func")

    b1 = add_code_block(
        bi,
        b"\x48\x8B\x04\x25\x00\x00\x00\x00\xE8\x00\x00\x00\x00",
        {
            (4, 4): gtirb.SymAddrConst(
                0, extern_func_sym, {gtirb.SymbolicExpression.Attribute.PLT}
            ),
            (9, 4): gtirb.SymAddrConst(
                0, extern_func_sym, {gtirb.SymbolicExpression.Attribute.PLT}
            ),
        },
    )
    main_sym.referent = b1
    b2 = add_code_block(bi, b"\xC3")
    b3 = add_code_block(bi, b"\x0F\x0B")
    local_func_sym.referent = b3

    add_edge(ir.cfg, b1, extern_func_sym.referent, gtirb.EdgeType.Call)
    fallthrough_edge = add_edge(ir.cfg, b1, b2, gtirb.EdgeType.Fallthrough)
    return_edge = add_edge(
        ir.cfg, b2, add_proxy_block(m), gtirb.EdgeType.Return
    )

    if use_rwc:
        ctx = RewritingContext(m, [])
        ctx.retarget_symbol_uses(extern_func_sym, local_func_sym)
        ctx.apply()
    else:
        retarget_symbols(
            m,
            {extern_func_sym: local_func_sym},
            GtirbInstructionDecoder(m.isa),
        )

    assert set(ir.cfg) == {
        fallthrough_edge,
        return_edge,
        gtirb.Edge(b1, b3, gtirb.EdgeLabel(gtirb.EdgeType.Call)),
    }

    assert dict(bi.symbolic_expressions) == {
        4: gtirb.SymAddrConst(0, local_func_sym),
        9: gtirb.SymAddrConst(0, local_func_sym),
    }
