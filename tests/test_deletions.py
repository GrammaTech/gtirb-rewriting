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
    add_data_block,
    add_edge,
    add_proxy_block,
    add_symbol,
    add_text_section,
    create_test_module,
    set_all_blocks_alignment,
)
from helpers import add_function_object, literal_patch


def test_multiple_deletions():
    # This mimics:
    #     b1:
    #         push r8
    #         jmp b3
    #     b2:
    #         push r9
    #     b3:
    #         push r11
    #

    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    b1_sym = add_symbol(m, "b1")
    b2_sym = add_symbol(m, "b2")
    b3_sym = add_symbol(m, "b3")

    b1 = add_code_block(
        bi, b"\x41\x50\xEB\x00", {(3, 1): gtirb.SymAddrConst(0, b3_sym)}
    )
    b1_sym.referent = b1
    b2 = add_code_block(bi, b"\x41\x51")
    b2_sym.referent = b2
    b3 = add_code_block(bi, b"\x41\x53")
    b3_sym.referent = b3

    add_edge(ir.cfg, b1, b3, gtirb.cfg.EdgeType.Branch)
    add_edge(ir.cfg, b2, b3, gtirb.cfg.EdgeType.Fallthrough)
    func = add_function_object(m, "foo", b1, {b2, b3})
    set_all_blocks_alignment(m, 1)

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.delete_at(func, b1, 0, 2)
    ctx.delete_at(func, b1, 2, 2)
    # This has a zero length and should not have any impact.
    ctx.delete_at(func, b2, 2, 0)
    ctx.apply()

    assert set(bi.blocks) == {b2, b3}
    assert b1_sym.referent is b2

    expected_cfg = gtirb.CFG()
    add_edge(expected_cfg, b2, b3, gtirb.cfg.EdgeType.Fallthrough)
    assert set(ir.cfg) == set(expected_cfg)
    assert not m.proxies


def test_insert_and_delete():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    puts_sym = add_symbol(m, "puts", add_proxy_block(m))

    b = add_code_block(bi, b"\x50\x51")
    b2 = add_code_block(bi, b"\x52")
    b_func = add_function_object(m, "b", b, {b2})
    add_edge(ir.cfg, b, b2, gtirb.Edge.Type.Fallthrough)
    set_all_blocks_alignment(m, 1)

    ctx = gtirb_rewriting.RewritingContext(m, [b_func])
    ctx.replace_at(b_func, b, 0, 1, literal_patch("call puts"))
    ctx.delete_at(b_func, b, 1, 1)
    ctx.apply()

    assert bi.contents == b"\xE8\x00\x00\x00\x00\x52"

    call_edges = [
        edge for edge in ir.cfg if edge.label.type == gtirb.Edge.Type.Call
    ]
    assert len(call_edges) == 1
    assert call_edges[0].source == b
    assert call_edges[0].target == puts_sym.referent

    fallthrough_edges = [
        edge
        for edge in ir.cfg
        if edge.label.type == gtirb.Edge.Type.Fallthrough
    ]
    assert len(fallthrough_edges) == 1
    assert fallthrough_edges[0].source == b
    assert fallthrough_edges[0].target == b2


def test_delete_last_instruction_call():
    ir, module = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(module, address=0x1000)

    # This mimics:
    #   ret
    bar_block = add_code_block(bi, b"\xC3")
    bar_sym = add_symbol(module, "bar", bar_block)
    bar_func = add_function_object(module, bar_sym, bar_block)

    # This mimics:
    #   pushq %rax
    #   call foo
    #   nop
    foo_block1 = add_code_block(
        bi, b"\x50\xE8\x00\x00\x00\x00", {2: gtirb.SymAddrConst(0, bar_sym)}
    )
    foo_block2 = add_code_block(bi, b"\x90")
    foo_func = add_function_object(
        module,
        "foo",
        foo_block1,
        {foo_block2},
    )

    add_edge(ir.cfg, foo_block1, bar_block, gtirb.Edge.Type.Call)
    add_edge(ir.cfg, foo_block1, foo_block2, gtirb.Edge.Type.Fallthrough)
    add_edge(ir.cfg, bar_block, foo_block2, gtirb.Edge.Type.Return)

    # Delete the call instruction
    ctx = gtirb_rewriting.RewritingContext(module, [bar_func, foo_func])
    ctx.delete_at(foo_func, foo_block1, 1, 5)
    ctx.apply()

    assert bi.contents == b"\xC3\x50\x90"

    call_edges = [
        edge for edge in ir.cfg if edge.label.type == gtirb.Edge.Type.Call
    ]
    assert not call_edges

    fallthrough_edges = [
        edge
        for edge in ir.cfg
        if edge.label.type == gtirb.Edge.Type.Fallthrough
    ]
    assert len(fallthrough_edges) == 1
    assert fallthrough_edges[0].source == foo_block1
    assert fallthrough_edges[0].target == foo_block2

    return_edges = [
        edge for edge in ir.cfg if edge.label.type == gtirb.Edge.Type.Return
    ]
    assert len(return_edges) == 1
    assert return_edges[0].source == bar_block
    assert isinstance(return_edges[0].target, gtirb.ProxyBlock)
    assert return_edges[0].target in module.proxies

    assert not bi.symbolic_expressions


def test_delete_whole_block_no_fallthrough():
    ir, module = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(module, address=0x1000)

    puts_proxy = add_proxy_block(module)
    puts_sym = add_symbol(module, "puts", puts_proxy)

    # This mimics:
    #   foo:
    #   pushq %rax
    #   jmp puts
    #   nop
    foo_block1 = add_code_block(
        bi, b"\x50\xEB\x00", {2: gtirb.SymAddrConst(0, puts_sym)}
    )
    foo_block2 = add_code_block(bi, b"\x90")
    foo_sym = add_symbol(module, "foo", foo_block1)
    foo_func = add_function_object(module, foo_sym, foo_block1, {foo_block2})
    add_edge(ir.cfg, foo_block1, puts_proxy, gtirb.Edge.Type.Branch)

    # This mimics:
    #   bar:
    #   jmp foo
    bar_block1 = add_code_block(
        bi, b"\xEB\x00", {1: gtirb.SymAddrConst(0, foo_sym)}
    )
    bar_func = add_function_object(module, "bar", bar_block1)
    add_edge(ir.cfg, bar_block1, foo_block1, gtirb.Edge.Type.Branch)
    set_all_blocks_alignment(module, 1)

    # Delete the whole first block of foo
    ctx = gtirb_rewriting.RewritingContext(module, [bar_func, foo_func])
    ctx.delete_at(foo_func, foo_block1, 0, foo_block1.size)
    ctx.apply()

    assert bi.contents == b"\x90\xEB\x00"
    assert foo_block1.byte_interval is None

    assert module.aux_data["functionEntries"].data[foo_func.uuid] == {
        foo_block2
    }
    assert module.aux_data["functionBlocks"].data[foo_func.uuid] == {
        foo_block2
    }
    assert foo_block1 not in module.aux_data["alignment"].data
    assert foo_sym.referent == foo_block2

    assert set(bi.symbolic_expressions.keys()) == {2}
    assert bi.symbolic_expressions[2].symbol == foo_sym

    edges = list(bar_block1.outgoing_edges)
    assert len(edges) == 1
    assert edges[0].target == foo_block2


@pytest.mark.parametrize("retarget", (False, True))
def test_delete_whole_block_followed_by_data(retarget):
    ir, module = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(module, address=0x1000)

    puts_proxy = add_proxy_block(module)
    puts_sym = add_symbol(module, "puts", puts_proxy)

    # This mimics:
    #   foo:
    #   pushq %rax
    #   jmp puts
    #   .byte FF
    foo_block1 = add_code_block(
        bi, b"\x50\xEB\x00", {2: gtirb.SymAddrConst(0, puts_sym)}
    )
    add_data_block(bi, b"\xFF")
    foo_sym = add_symbol(module, "foo", foo_block1)
    foo_func = add_function_object(module, foo_sym, foo_block1)
    add_edge(ir.cfg, foo_block1, puts_proxy, gtirb.Edge.Type.Branch)

    # This mimics:
    #   bar:
    #   jmp foo
    bar_block1 = add_code_block(
        bi, b"\xEB\x00", {1: gtirb.SymAddrConst(0, foo_sym)}
    )
    bar_func = add_function_object(module, "bar", bar_block1)
    add_edge(ir.cfg, bar_block1, foo_block1, gtirb.Edge.Type.Branch)
    set_all_blocks_alignment(module, 1)

    # Delete the whole first block of foo
    ctx = gtirb_rewriting.RewritingContext(module, [bar_func, foo_func])
    ctx.delete_at(
        foo_func, foo_block1, 0, foo_block1.size, retarget_to_proxy=retarget
    )

    if not retarget:
        with pytest.raises(gtirb_rewriting.AmbiguousCFGError):
            ctx.apply()

    else:
        ctx.apply()

        assert bi.contents == b"\xFF\xEB\x00"
        assert foo_block1.byte_interval is None

        assert not module.aux_data["functionEntries"].data[foo_func.uuid]
        assert not module.aux_data["functionBlocks"].data[foo_func.uuid]
        assert foo_block1 not in module.aux_data["alignment"].data
        assert isinstance(foo_sym.referent, gtirb.ProxyBlock)

        assert set(bi.symbolic_expressions.keys()) == {2}
        assert bi.symbolic_expressions[2].symbol == foo_sym

        edges = list(bar_block1.outgoing_edges)
        assert len(edges) == 1
        assert isinstance(edges[0].target, gtirb.ProxyBlock)


def test_delete_whole_function():
    # This mimics:
    #   foo:
    #   ret
    #
    #   bar:
    #   call foo
    #   ret
    #
    ir, m = create_test_module(
        gtirb.module.Module.FileFormat.ELF, gtirb.module.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    foo_sym = add_symbol(m, "foo")
    bar_sym = add_symbol(m, "bar")
    return_proxy = add_proxy_block(m)

    foo_b1 = add_code_block(bi, b"\xC3")
    foo_sym.referent = foo_b1
    bar_b1 = add_code_block(
        bi, b"\xE8\x00\x00\x00\x00", {(1, 4): gtirb.SymAddrConst(0, foo_sym)}
    )
    bar_sym.referent = bar_b1
    bar_b2 = add_code_block(bi, b"\xC3")

    add_edge(ir.cfg, foo_b1, bar_b2, gtirb.cfg.EdgeType.Return)
    add_edge(ir.cfg, bar_b1, foo_b1, gtirb.cfg.EdgeType.Call)
    add_edge(ir.cfg, bar_b1, bar_b2, gtirb.cfg.EdgeType.Fallthrough)
    add_edge(ir.cfg, bar_b2, return_proxy, gtirb.cfg.EdgeType.Return)

    foo_func = add_function_object(m, foo_sym, foo_b1)
    bar_func = add_function_object(m, bar_sym, bar_b1, {bar_b2})

    # Delete all of function foo
    ctx = gtirb_rewriting.RewritingContext(m, [bar_func, foo_func])
    ctx.delete_function(foo_func)
    ctx.apply()

    assert isinstance(foo_sym.referent, gtirb.ProxyBlock)
    assert foo_sym.referent in m.proxies

    assert foo_b1.byte_interval is None

    assert m.aux_data["functionEntries"].data[foo_func.uuid] == set()
    assert m.aux_data["functionBlocks"].data[foo_func.uuid] == set()

    # Check that we removed the return edge from the block and updated the
    # call into it to be to the proxy block.
    expected_cfg = gtirb.CFG()
    add_edge(expected_cfg, bar_b1, foo_sym.referent, gtirb.cfg.EdgeType.Call)
    add_edge(expected_cfg, bar_b1, bar_b2, gtirb.cfg.EdgeType.Fallthrough)
    add_edge(expected_cfg, bar_b2, return_proxy, gtirb.cfg.EdgeType.Return)
    assert set(ir.cfg) == set(expected_cfg)


def test_deletion_with_ambiguous_address():
    # This mimics:
    #   push r8
    # b2:
    #   jmp b3
    # b3:
    #   push r9
    #

    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    b2_sym = add_symbol(m, "b2")
    b3_sym = add_symbol(m, "b3")

    b1 = add_code_block(bi, b"\x41\x50")
    b2 = add_code_block(
        bi, b"\xEB\x00", {(1, 1): gtirb.SymAddrConst(0, b3_sym)}
    )
    b2_sym.referent = b2
    b3 = add_code_block(bi, b"\x41\x51")
    b3_sym.referent = b3

    add_edge(ir.cfg, b1, b2, gtirb.cfg.EdgeType.Fallthrough)
    add_edge(ir.cfg, b2, b3, gtirb.cfg.EdgeType.Branch)
    func = add_function_object(m, "func", b1, {b2, b3})
    set_all_blocks_alignment(m, 1)

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    # Force there to be new blocks introduced that has the same address as
    # b3 when processing b2's deletions.
    ctx.replace_at(
        func,
        b1,
        0,
        b1.size,
        literal_patch(
            """
            nop
            nop
            nop
            nop
            new_label:
            nop
            """
        ),
    )
    # Now delete all of b2 so that we need to determine the next block.
    ctx.delete_at(func, b2, 0, b2.size)
    ctx.apply()

    (new_sym,) = m.symbols_named("new_label")
    new_block = new_sym.referent
    assert isinstance(new_block, gtirb.CodeBlock)

    assert set(bi.blocks) == {b1, new_block, b3}
    assert b1.contents == b"\x90\x90\x90\x90"
    assert new_block.contents == b"\x90"
    assert b3.contents == b"\x41\x51"

    expected_cfg = gtirb.CFG()
    add_edge(expected_cfg, b1, new_block, gtirb.cfg.EdgeType.Fallthrough)
    add_edge(expected_cfg, new_block, b3, gtirb.cfg.EdgeType.Fallthrough)
    assert set(ir.cfg) == set(expected_cfg)
    assert not m.proxies


def test_empty_delete():
    # This mimics:
    #   jmp b2
    # b2:
    #   nop
    #

    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    b2_sym = add_symbol(m, "b2")

    b1 = add_code_block(
        bi, b"\xEB\x00", {(1, 1): gtirb.SymAddrConst(0, b2_sym)}
    )
    b2 = add_code_block(bi, b"\x90")
    b2_sym.referent = b2

    add_edge(ir.cfg, b1, b2, gtirb.cfg.EdgeType.Branch)
    func = add_function_object(m, "func", b1, {b2})
    orig_cfg = set(ir.cfg)

    # Test a zero-sized deletion
    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.delete_at(func, b1, b1.size, 0)
    ctx.apply()

    assert set(ir.cfg) == orig_cfg
    assert b1.contents == b"\xEB\x00"
    assert b2.contents == b"\x90"
