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
from gtirb_rewriting._auxdata import NULL_UUID
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
    ctx.delete_at(b1, 0, 2)
    ctx.delete_at(b1, 2, 2)
    # This has a zero length and should not have any impact.
    ctx.delete_at(b2, 2, 0)
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
    ctx.replace_at(b, 0, 1, literal_patch("call puts"))
    ctx.delete_at(b, 1, 1)
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
    ctx.delete_at(foo_block1, 1, 5)
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
    ctx.delete_at(foo_block1, 0, foo_block1.size)
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


def test_delete_data_block():
    """
    Test that deleting a data block updates symbols and aux data tables
    correctly.
    """

    # This mimics:
    #   foo:
    #   .ascii "hi"
    #   ud2

    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    b1 = add_data_block(bi, b"\x68\x69")
    b2 = add_code_block(bi, b"\x0F\x0B")
    m.aux_data["encodings"] = gtirb.AuxData(
        {b1: "ascii"}, "mapping<UUID,string>"
    )
    m.aux_data["types"] = gtirb.AuxData({b1: "string"}, "mapping<UUID,string>")
    foo_sym = add_symbol(m, "foo", b1)

    ctx = gtirb_rewriting.RewritingContext(m, [])
    ctx.delete_at(b1, 0, b1.size)
    ctx.apply()

    assert bi.blocks == {b2}
    assert foo_sym.referent is b2
    assert not m.aux_data["encodings"].data
    assert not m.aux_data["types"].data


def test_delete_whole_block_with_symbols():
    ir, module = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(module, address=0x1000)

    # This mimics:
    #   foo:
    #   nop
    #   bar:
    foo_block1 = add_code_block(bi, b"\x90")
    foo_sym = add_symbol(module, "foo", foo_block1)
    bar_sym = add_symbol(module, "bar", foo_block1)
    bar_sym.at_end = True
    foo_func = add_function_object(module, foo_sym, foo_block1)

    ctx = gtirb_rewriting.RewritingContext(module, [foo_func])
    ctx.delete_at(foo_block1, 0, foo_block1.size)
    ctx.apply()

    assert bi.contents == b""
    assert foo_block1.byte_interval is bi
    assert foo_block1.size == 0

    assert module.aux_data["functionEntries"].data[foo_func.uuid] == {
        foo_block1
    }
    assert module.aux_data["functionBlocks"].data[foo_func.uuid] == {
        foo_block1
    }
    assert foo_sym.referent == foo_block1


@pytest.mark.parametrize("block_before", (False, True))
def test_delete_block_with_cfi(block_before: bool):
    """
    Tests that deleting blocks updates CFI directives correctly.
    """
    ir, module = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(module, address=0x1000)

    # This mimics:
    #   .cfi_startproc
    #   ud2
    #   .cfi_endproc
    #   .cfi_startproc
    #   ud2
    #   .byte 42
    if block_before:
        b1 = add_code_block(bi, b"\x0F\x0B")
        module.aux_data["cfiDirectives"].data[gtirb.Offset(b1, 0)] = [
            (".cfi_startproc", [], NULL_UUID),
        ]
        module.aux_data["cfiDirectives"].data[gtirb.Offset(b1, 2)] = [
            (".cfi_endproc", [], NULL_UUID),
        ]
    else:
        b1 = None

    b2 = add_code_block(bi, b"\x0F\x0B")
    module.aux_data["cfiDirectives"].data[gtirb.Offset(b2, 0)] = [
        (".cfi_startproc", [], NULL_UUID),
    ]
    b3 = add_data_block(bi, b"\x2A")
    set_all_blocks_alignment(module, 1)

    ctx = gtirb_rewriting.RewritingContext(module, [])
    ctx.delete_at(b2, 0, b2.size)
    ctx.apply()

    if block_before:
        assert b1
        assert bi.blocks == {b1, b3}
        assert module.aux_data["cfiDirectives"].data == {
            gtirb.Offset(b1, 0): [
                (".cfi_startproc", [], NULL_UUID),
            ],
            gtirb.Offset(b1, 2): [
                (".cfi_endproc", [], NULL_UUID),
                (".cfi_startproc", [], NULL_UUID),
            ],
        }

    else:
        assert bi.blocks == {b2, b3}
        assert b2.size == 0
        assert module.aux_data["cfiDirectives"].data == {
            gtirb.Offset(b2, 0): [
                (".cfi_startproc", [], NULL_UUID),
            ],
        }


def test_delete_block_with_unimportant_cfi():
    """
    Tests that deleting blocks with unimportant CFI directives deletes them.
    """
    ir, module = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(module, address=0x1000)

    # This mimics:
    #   .cfi_undefined 1
    #   ud2
    b1 = add_code_block(bi, b"\x0F\x0B")
    module.aux_data["cfiDirectives"].data[gtirb.Offset(b1, 0)] = [
        (".cfi_undefined", [1], NULL_UUID),
    ]

    ctx = gtirb_rewriting.RewritingContext(module, [])
    ctx.delete_at(b1, 0, b1.size)
    ctx.apply()

    assert bi.blocks == set()
    assert not module.aux_data["cfiDirectives"].data


def test_delete_block_with_safe_seh():
    """
    Tests that deleting blocks updates the safe SEH aux data correctly.
    """
    ir, module = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(module, address=0x1000)

    # This mimics:
    #   nop
    #   ud2
    b1 = add_code_block(bi, b"\x90")
    b2 = add_code_block(bi, b"\x0F\x0B")

    module.aux_data["peSafeExceptionHandlers"] = gtirb.AuxData(
        {b1}, "set<UUID>"
    )

    ctx = gtirb_rewriting.RewritingContext(module, [])
    ctx.delete_at(b1, 0, b1.size)
    ctx.apply()

    assert bi.blocks == {b2}
    assert module.aux_data["peSafeExceptionHandlers"].data == {b2}


def test_delete_block_with_incoming_fallthrough():
    """
    Tests that fallthrough edges do not prevent deletion of a block and end up
    with a proxy fallthrough edge.
    """
    ir, module = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(module, address=0x1000)

    # This mimics:
    #   ud2
    #   ud2
    #   .byte 42
    b1 = add_code_block(bi, b"\x0F\x0B")
    b2 = add_code_block(bi, b"\x0F\x0B")
    b3 = add_data_block(bi, b"\x2A")
    add_edge(ir.cfg, b1, b2, gtirb.EdgeType.Fallthrough)
    set_all_blocks_alignment(module, 1)

    ctx = gtirb_rewriting.RewritingContext(module, [])
    ctx.delete_at(b2, 0, b2.size)
    ctx.apply()

    assert b1
    assert bi.blocks == {b1, b3}

    out_edges = list(b1.outgoing_edges)
    assert len(out_edges) == 1
    assert out_edges[0].source == b1
    assert isinstance(out_edges[0].target, gtirb.ProxyBlock)
    assert out_edges[0].label == gtirb.EdgeLabel(gtirb.EdgeType.Fallthrough)


@pytest.mark.parametrize("retarget", (False, True))
@pytest.mark.parametrize("multiple_blocks", (False, True))
def test_delete_entrypoint(retarget: bool, multiple_blocks: bool):
    """
    Tests that deleting the entry point of the binary updates the module and
    aux data tables correctly.
    """
    ir, module = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(module, address=0x1000)

    # This mimics:
    #   nop
    #   nop
    b1 = add_code_block(bi, b"\x90")
    if multiple_blocks:
        b2 = add_code_block(bi, b"\x90")
        add_edge(ir.cfg, b1, b2, gtirb.EdgeType.Fallthrough)
    else:
        b2 = None

    module.entry_point = b1
    module.aux_data["elfDynamicInit"] = gtirb.AuxData(b1, "UUID")
    module.aux_data["elfDynamicFini"] = gtirb.AuxData(b1, "UUID")

    ctx = gtirb_rewriting.RewritingContext(module, [])
    ctx.delete_at(b1, 0, b1.size, retarget_to_proxy=retarget)
    ctx.apply()

    if retarget:
        if multiple_blocks:
            assert bi.blocks == {b2}
        else:
            assert bi.blocks == set()
        assert module.entry_point is None
        assert "elfDynamicInit" not in module.aux_data
        assert "elfDynamicFini" not in module.aux_data

    elif multiple_blocks:
        assert bi.blocks == {b2}
        assert module.entry_point is b2
        assert module.aux_data["elfDynamicInit"].data is b2
        assert module.aux_data["elfDynamicFini"].data is b2

    else:
        assert bi.blocks == {b1}
        assert b1.size == 0
        assert module.entry_point is b1
        assert module.aux_data["elfDynamicInit"].data is b1
        assert module.aux_data["elfDynamicFini"].data is b1


def test_delete_code_and_data():
    """
    Tests that we don't leave zero-sized blocks behind when it's not strictly
    necessary.
    """

    # This mimics:
    #   foo:
    #   ud2
    #   .byte 42
    #
    #   bar:
    #   jmp bar
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    foo_sym = add_symbol(m, "foo")
    bar_sym = add_symbol(m, "bar")

    foo_b1 = add_code_block(bi, b"\x0F\x0B")
    foo_b2 = add_data_block(bi, b"\x2A")
    foo_sym.referent = foo_b1
    bar_b1 = add_code_block(
        bi, b"\xEB\x00", {(1, 1): gtirb.SymAddrConst(0, foo_sym)}
    )
    bar_sym.referent = bar_b1

    add_edge(ir.cfg, bar_b1, foo_b1, gtirb.EdgeType.Branch)

    ctx = gtirb_rewriting.RewritingContext(m, [])
    # Delete the first block, which because it has incoming control flow will
    # be kept as a zero-sized code block.
    ctx.delete_at(foo_b1, 0, foo_b1.size)
    # Then delete the data block, which gives us the chance to clean up that
    # zero-sized code block.
    ctx.delete_at(foo_b2, 0, foo_b2.size)
    ctx.apply()

    assert bi.contents == b"\xEB\x00"
    assert bi.blocks == {bar_b1}

    assert foo_sym.referent == bar_b1
    assert bar_sym.referent == bar_b1


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
    foo_block2 = add_data_block(bi, b"\xFF")
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
    ctx.delete_at(foo_block1, 0, foo_block1.size, retarget_to_proxy=retarget)

    if not retarget:
        ctx.apply()

        assert bi.contents == b"\xFF\xEB\x00"
        assert foo_block1.byte_interval is bi
        assert foo_block1.size == 0
        assert foo_block2.offset == 0

        assert module.aux_data["functionEntries"].data[foo_func.uuid] == {
            foo_block1
        }
        assert module.aux_data["functionBlocks"].data[foo_func.uuid] == {
            foo_block1
        }
        assert foo_sym.referent is foo_block1

        assert set(bi.symbolic_expressions.keys()) == {2}
        assert bi.symbolic_expressions[2].symbol == foo_sym

        edges = list(bar_block1.outgoing_edges)
        assert len(edges) == 1
        assert edges[0].target is foo_block1

        edges = list(foo_block1.outgoing_edges)
        assert len(edges) == 1
        assert isinstance(edges[0].target, gtirb.ProxyBlock)

    else:
        ctx.apply()

        assert bi.contents == b"\xFF\xEB\x00"
        assert foo_block1.byte_interval is None

        assert foo_func.uuid not in module.aux_data["functionEntries"].data
        assert foo_func.uuid not in module.aux_data["functionBlocks"].data
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

    assert foo_func.uuid not in m.aux_data["functionEntries"].data
    assert foo_func.uuid not in m.aux_data["functionBlocks"].data
    assert foo_func.uuid not in m.aux_data["functionNames"].data

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
    ctx.delete_at(b2, 0, b2.size)
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
    ctx.delete_at(b1, b1.size, 0)
    ctx.apply()

    assert set(ir.cfg) == orig_cfg
    assert b1.contents == b"\xEB\x00"
    assert b2.contents == b"\x90"
