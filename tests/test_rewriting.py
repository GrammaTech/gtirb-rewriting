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
import logging

import gtirb
import gtirb_functions
import gtirb_layout
import pytest
from gtirb_test_helpers import (
    add_code_block,
    add_data_block,
    add_data_section,
    add_edge,
    add_proxy_block,
    add_symbol,
    add_text_section,
    create_test_module,
    set_all_blocks_alignment,
)
from helpers import add_function_object, literal_patch

import gtirb_rewriting
from gtirb_rewriting._auxdata import NULL_UUID


@gtirb_rewriting.patch_constraints()
def dummy_patch(insertion_ctx):
    return """
    nop
    nop
    # This forces the start of a new block.
    .L_blah:
    """


def test_multiple_insertions():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    b = add_code_block(bi, b"\x50\x51\x52\x53\x54\x55\x56\x57")
    func = add_function_object(m, "hi", b)

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.insert_at(b, 0, gtirb_rewriting.Patch.from_function(dummy_patch))
    ctx.insert_at(b, 7, gtirb_rewriting.Patch.from_function(dummy_patch))
    ctx.apply()

    blocks = sorted(bi.blocks, key=lambda b: b.offset)

    refs = [list(b.references) for b in blocks]

    assert bi.contents == b"\x90\x90\x50\x51\x52\x53\x54\x55\x56\x90\x90\x57"

    assert len(refs[0]) == 1
    assert refs[0][0].name == "hi"
    assert blocks[0] == b
    assert blocks[0].offset == 0
    assert blocks[0].size == 2

    assert len(refs[1]) == 1
    assert refs[1][0].name == ".L_blah_1"
    assert blocks[1].offset == 2
    assert blocks[1].size == 9

    assert len(refs[2]) == 1
    assert refs[2][0].name == ".L_blah_2"
    assert blocks[2].offset == 11
    assert blocks[2].size == 1


def test_multiple_replacements():
    @gtirb_rewriting.patch_constraints()
    def nop_patch(context):
        return "nop"

    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)
    b = add_code_block(bi, b"\x50\x51\x52\x53\x54\x55\x56\x57")
    func = add_function_object(m, "hi", b)

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.replace_at(b, 0, 2, gtirb_rewriting.Patch.from_function(nop_patch))
    ctx.replace_at(b, 3, 4, gtirb_rewriting.Patch.from_function(nop_patch))
    ctx.insert_at(b, 8, gtirb_rewriting.Patch.from_function(nop_patch))
    ctx.apply()

    assert bi.contents == b"\x90\x52\x90\x57\x90"
    assert sum(b.size for b in bi.blocks) == 5


def test_added_function_blocks():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)
    b = add_code_block(bi, b"\x50\x51\x52\x53\x54\x55\x56\x57")
    func = add_function_object(m, "hi", b)

    functions = gtirb_functions.Function.build_functions(m)
    assert len(functions) == 1
    assert len(functions[0].get_all_blocks()) == 1

    ctx = gtirb_rewriting.RewritingContext(m, functions)
    ctx.insert_at(b, 7, gtirb_rewriting.Patch.from_function(dummy_patch))
    ctx.apply()

    assert len(m.aux_data["functionBlocks"].data[func.uuid]) == 2
    assert (
        sum(b.size for b in m.aux_data["functionBlocks"].data[func.uuid])
        == bi.size
        == 10
    )


def test_expensive_assertions():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)
    b = add_code_block(bi, b"\xE8\x00\x00\x00\x00\xE8\x00\x00\x00\x00")
    func = add_function_object(m, "hi", b)

    ctx = gtirb_rewriting.RewritingContext(
        m, [func], expensive_assertions=True
    )
    ctx.insert_at(b, 0, gtirb_rewriting.Patch.from_function(dummy_patch))
    ctx.insert_at(b, 5, gtirb_rewriting.Patch.from_function(dummy_patch))
    # Inserting: offset is not on an instruction boundary
    with pytest.raises(AssertionError):
        ctx.insert_at(
            b,
            1,
            gtirb_rewriting.Patch.from_function(dummy_patch),
        )
    # Replacing: offset is not on an instruction boundary
    with pytest.raises(AssertionError):
        ctx.replace_at(
            b,
            1,
            0,
            gtirb_rewriting.Patch.from_function(dummy_patch),
        )
    # Replacing: offset is valid, but end position isn't on an instruction
    # boundary
    with pytest.raises(AssertionError):
        ctx.replace_at(
            b,
            0,
            6,
            gtirb_rewriting.Patch.from_function(dummy_patch),
        )
    # Replacing: range extends out of the block's bounds
    with pytest.raises(AssertionError):
        ctx.replace_at(
            b,
            0,
            60,
            gtirb_rewriting.Patch.from_function(dummy_patch),
        )
    # Deleting: offset is not on an instruction boundary
    with pytest.raises(AssertionError):
        ctx.delete_at(b, 1, 0)
    # Deleting: offset is valid, but end position isn't on an instruction
    # boundary
    with pytest.raises(AssertionError):
        ctx.delete_at(b, 0, 6)
    # Deleting: range extends out of the block's bounds
    with pytest.raises(AssertionError):
        ctx.delete_at(b, 0, 60)
    ctx.apply()


def test_conflicting_insertion_replacement():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)
    b = add_code_block(bi, b"\x90\x90\x90\x90\x90\x90\x90\x90")
    func = add_function_object(m, "hi", b)

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.insert_at(b, 7, gtirb_rewriting.Patch.from_function(dummy_patch))
    ctx.replace_at(
        b,
        0,
        bi.size,
        gtirb_rewriting.Patch.from_function(dummy_patch),
    )
    with pytest.raises(AssertionError):
        ctx.apply()


def test_inserting_function_and_call():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)
    main_block = add_code_block(bi, b"\x90")
    func = add_function_object(m, "main", main_block)

    @gtirb_rewriting.patch_constraints()
    def function_patch(ctx):
        return """
            .cfi_startproc
            .cfi_lsda 0, target
            mov $42, %eax
            ret
            .cfi_endproc
            """

    @gtirb_rewriting.patch_constraints()
    def call_patch(ctx):
        return "call target"

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    target_sym = ctx.register_insert_function(
        "target", gtirb_rewriting.Patch.from_function(function_patch)
    )
    ctx.insert_at(
        main_block,
        0,
        gtirb_rewriting.Patch.from_function(call_patch),
    )
    ctx.apply()

    # Look for call edges and return edges in the CFG
    call_edges = [
        edge for edge in ir.cfg if edge.label.type == gtirb.Edge.Type.Call
    ]
    assert len(call_edges) == 1
    assert call_edges[0].source == main_block
    assert call_edges[0].target == target_sym.referent

    return_edges = [
        edge for edge in ir.cfg if edge.label.type == gtirb.Edge.Type.Return
    ]
    assert len(return_edges) == 1
    assert not isinstance(return_edges[0].target, gtirb.ProxyBlock)
    source_block = return_edges[0].source

    assert m.aux_data["cfiDirectives"].data == {
        gtirb.Offset(source_block, 0): [
            (".cfi_startproc", [], NULL_UUID),
            (".cfi_lsda", [0], target_sym),
        ],
        gtirb.Offset(source_block, 6): [
            (".cfi_endproc", [], NULL_UUID),
        ],
    }


def test_inserting_function_calling_inserted_function():
    @gtirb_rewriting.patch_constraints()
    def target_function_patch(ctx):
        return "mov $42, %eax; ret"

    @gtirb_rewriting.patch_constraints()
    def call_function_patch(ctx):
        return "call target; ud2"

    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    ctx = gtirb_rewriting.RewritingContext(m, [])
    caller_sym = ctx.register_insert_function(
        "caller", gtirb_rewriting.Patch.from_function(call_function_patch)
    )
    target_sym = ctx.register_insert_function(
        "target", gtirb_rewriting.Patch.from_function(target_function_patch)
    )
    ctx.apply()

    # Look for call edges and return edges in the CFG
    call_edges = [
        edge for edge in ir.cfg if edge.label.type == gtirb.Edge.Type.Call
    ]
    assert len(call_edges) == 1
    assert call_edges[0].source == caller_sym.referent
    assert call_edges[0].target == target_sym.referent

    return_edges = [
        edge for edge in ir.cfg if edge.label.type == gtirb.Edge.Type.Return
    ]
    assert len(return_edges) == 1
    assert not isinstance(return_edges[0].target, gtirb.ProxyBlock)

    assert m.aux_data["cfiDirectives"].data == {}


def test_insert_bytes_offset0():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)
    extern_func_sym = add_symbol(m, "puts", add_proxy_block(m))
    # This mimics:
    #   func:
    #   pushq puts
    #   pushq %rax
    b = add_code_block(
        bi,
        b"\xff\x34\x25\x00\x00\x00\x00",
        {3: gtirb.SymAddrConst(0, extern_func_sym)},
    )
    b2 = add_code_block(bi, b"\x50")
    func = add_function_object(m, "func", b, {b2})
    add_edge(ir.cfg, b, b2, gtirb.Edge.Type.Fallthrough)
    set_all_blocks_alignment(m, 1)

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.insert_at(b, 0, literal_patch("hi: nop"))
    ctx.apply()

    assert bi.address == 0x1000
    assert bi.contents == b"\x90\xff\x34\x25\x00\x00\x00\x00\x50"
    assert bi.size == 9
    assert b.offset == 0
    assert b.size == 8
    assert b2.offset == 8
    assert b2.size == 1
    assert set(bi.blocks) == {b, b2}

    new_sym = next(sym for sym in m.symbols if sym.name == "hi")
    assert new_sym.referent == b
    assert set(bi.symbolic_expressions.keys()) == {4}


def test_insert_bytes_last():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    # this mimics:
    #   jne foo
    #   push %rax
    # foo:
    #   push %rcx
    foo_sym = add_symbol(m, "foo")
    b1 = add_code_block(bi, b"\x75\x00", {1: gtirb.SymAddrConst(0, foo_sym)})
    b2 = add_code_block(bi, b"\x50")
    b3 = add_code_block(bi, b"\x51")
    foo_sym.referent = b3
    func = add_function_object(m, "func", b1, {b2, b3})

    add_edge(ir.cfg, b1, b3, gtirb.Edge.Type.Branch, conditional=True)
    add_edge(ir.cfg, b1, b2, gtirb.Edge.Type.Fallthrough)
    add_edge(ir.cfg, b2, b3, gtirb.Edge.Type.Fallthrough)
    set_all_blocks_alignment(m, 1)

    # Test inserting after the jump instruction
    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.insert_at(b1, 2, literal_patch("nop"))
    ctx.apply()

    assert bi.address == 0x1000
    assert bi.contents == b"\x75\x00\x90\x50\x51"
    assert bi.size == 5
    assert b1.offset == 0
    assert b1.size == 2
    (new_block,) = set(bi.blocks) - {b1, b2, b3}
    assert new_block.byte_interval is bi
    assert new_block.offset == 2
    assert new_block.size == 1
    assert b2.offset == 3
    assert b2.size == 1
    assert b3.offset == 4
    assert b3.size == 1

    edges = sorted(b1.outgoing_edges, key=lambda e: e.label.type.value)
    assert len(edges) == 2
    assert edges[0].label.type == gtirb.Edge.Type.Branch
    assert edges[0].target == b3
    assert edges[1].label.type == gtirb.Edge.Type.Fallthrough
    assert edges[1].target == new_block

    edges = list(new_block.outgoing_edges)
    assert len(edges) == 1
    assert edges[0].label.type == gtirb.Edge.Type.Fallthrough
    assert edges[0].target == b2

    edges = list(b2.outgoing_edges)
    assert len(edges) == 1
    assert edges[0].label.type == gtirb.Edge.Type.Fallthrough
    assert edges[0].target == b3


def test_insert_bytes_last_no_fallthrough():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)
    b = add_code_block(bi, b"\xB8\x2A\x00\x00\x00\xC3")
    return_proxy = add_proxy_block(m)
    add_edge(ir.cfg, b, return_proxy, gtirb.Edge.Type.Return)
    func = add_function_object(m, "func", b)
    set_all_blocks_alignment(m, 1)

    # Test inserting after a ret
    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.insert_at(b, b.size, literal_patch("nop"))
    ctx.apply()

    assert bi.address == 0x1000
    assert bi.contents == b"\xB8\x2A\x00\x00\x00\xC3\x90"
    assert bi.size == 7
    assert b.offset == 0
    assert b.size == 6
    (new_block,) = set(bi.blocks) - {b}
    assert new_block.byte_interval is bi
    assert new_block.offset == 6
    assert new_block.size == 1

    edges = list(b.outgoing_edges)
    assert len(edges) == 1
    assert edges[0].label.type == gtirb.Edge.Type.Return
    assert edges[0].target == return_proxy

    in_edges = list(new_block.incoming_edges)
    assert not in_edges

    edges = list(new_block.outgoing_edges)
    assert not edges


def test_replace_bytes_offset0():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)
    extern_func_sym = add_symbol(m, "puts", add_proxy_block(m))
    # This mimics:
    #   func:
    #   pushq puts
    #   pushq puts
    #   pushq %rax
    b = add_code_block(
        bi,
        b"\xff\x34\x25\x00\x00\x00\x00\xff\x34\x25\x00\x00\x00\x00",
        {
            3: gtirb.SymAddrConst(0, extern_func_sym),
            10: gtirb.SymAddrConst(0, extern_func_sym),
        },
    )
    b2 = add_code_block(bi, b"\x50")
    func = add_function_object(m, "func", b, {b2})
    add_edge(ir.cfg, b, b2, gtirb.Edge.Type.Fallthrough)
    set_all_blocks_alignment(m, 1)

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.replace_at(b, 0, 7, literal_patch("hi: nop"))
    ctx.apply()

    assert bi.address == 0x1000
    assert bi.contents == b"\x90\xff\x34\x25\x00\x00\x00\x00\x50"
    assert bi.size == 9
    assert b.offset == 0
    assert b.size == 8
    assert b2.offset == 8
    assert b2.size == 1

    new_sym = next(sym for sym in m.symbols if sym.name == "hi")
    assert new_sym.referent == b
    assert set(bi.symbolic_expressions.keys()) == {4}


def test_replace_bytes_last():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    extern_func_proxy = add_proxy_block(m)
    extern_func_sym = add_symbol(m, "puts", extern_func_proxy)

    # This mimics:
    #   func:
    #   pushq %rdi
    #   call puts
    #   ud2
    b = add_code_block(
        bi,
        b"\x57\xE8\x00\x00\x00\x00",
        {2: gtirb.SymAddrConst(0, extern_func_sym)},
    )
    b2 = add_code_block(bi, b"\x0F\x0B")
    func = add_function_object(m, "func", b, {b2})

    add_edge(ir.cfg, b, b2, gtirb.Edge.Type.Fallthrough)
    add_edge(ir.cfg, b, extern_func_proxy, gtirb.Edge.Type.Call)
    set_all_blocks_alignment(m, 1)

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.replace_at(b, 1, 5, literal_patch("nop"))
    ctx.apply()

    assert bi.address == 0x1000
    assert bi.contents == b"\x57\x90\x0f\x0b"
    assert bi.size == 4
    assert b.offset == 0
    assert b.size == 2
    assert b2.offset == 2
    assert b2.size == 2
    assert set(bi.symbolic_expressions.keys()) == set()
    assert set(bi.blocks) == {b, b2}

    edges = list(b.outgoing_edges)
    assert len(edges) == 1
    assert edges[0].label.type == gtirb.Edge.Type.Fallthrough
    assert edges[0].target == b2

    edges = list(b2.incoming_edges)
    assert len(edges) == 1
    assert edges[0].label.type == gtirb.Edge.Type.Fallthrough
    assert edges[0].source == b

    assert len(ir.cfg) == 1


def test_replace_bytes_all():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    extern_func_proxy = add_proxy_block(m)
    extern_func_sym = add_symbol(m, "puts", extern_func_proxy)

    # This mimics:
    #   func:
    #   pushq %rdi
    #   call puts
    #   ud2
    b = add_code_block(
        bi,
        b"\x57\xE8\x00\x00\x00\x00",
        {2: gtirb.SymAddrConst(0, extern_func_sym)},
    )
    b2 = add_code_block(bi, b"\x0F\x0B")
    func = add_function_object(m, "func", b, {b2})

    add_edge(ir.cfg, b, b2, gtirb.Edge.Type.Fallthrough)
    add_edge(ir.cfg, b, extern_func_proxy, gtirb.Edge.Type.Call)
    set_all_blocks_alignment(m, 1)

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.replace_at(b, 0, b.size, literal_patch("nop"))
    ctx.apply()

    assert bi.address == 0x1000
    assert bi.contents == b"\x90\x0f\x0b"
    assert bi.size == 3
    assert b.offset == 0
    assert b.size == 1
    assert b2.offset == 1
    assert b2.size == 2
    assert set(bi.symbolic_expressions.keys()) == set()
    assert set(bi.blocks) == {b, b2}

    edges = list(b.outgoing_edges)
    assert len(edges) == 1
    assert edges[0].label.type == gtirb.Edge.Type.Fallthrough
    assert edges[0].target == b2


def test_replace_bytes_with_trailing_zerosized_block():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    extern_func_proxy = add_proxy_block(m)
    extern_func_sym = add_symbol(m, "puts", extern_func_proxy)

    # This mimics:
    #   func:
    #   pushq %rdi
    #   call puts
    #   ud2
    b = add_code_block(
        bi,
        b"\x57\xE8\x00\x00\x00\x00",
        {2: gtirb.SymAddrConst(0, extern_func_sym)},
    )
    b2 = add_code_block(bi, b"\x0F\x0B")
    func = add_function_object(m, "func", b, {b2})

    add_edge(ir.cfg, b, b2, gtirb.Edge.Type.Fallthrough)
    add_edge(ir.cfg, b, extern_func_proxy, gtirb.Edge.Type.Call)
    set_all_blocks_alignment(m, 1)

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.replace_at(b, 1, 5, literal_patch("jmp foo; foo:"))
    ctx.apply()

    assert bi.contents == b"\x57\xEB\x00\x0f\x0b"
    assert bi.size == 5
    assert b.offset == 0
    assert b.size == 3
    assert b2.offset == 3
    assert b2.size == 2

    foo_symbol = next(sym for sym in m.symbols if sym.name == "foo")
    assert set(bi.symbolic_expressions.keys()) == {2}
    assert bi.symbolic_expressions[2].symbol == foo_symbol
    assert foo_symbol.referent is b2

    edges = list(b.outgoing_edges)
    assert len(edges) == 1
    assert edges[0].label.type == gtirb.Edge.Type.Branch
    assert edges[0].target == b2

    edges = list(b2.incoming_edges)
    assert len(edges) == 1
    assert edges[0].label.type == gtirb.Edge.Type.Branch
    assert edges[0].source == b


def test_replace_bytes_in_place_no_symbol():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)
    b = add_code_block(bi, b"\x50\x51\x52")
    func = add_function_object(m, "func", b)
    set_all_blocks_alignment(m, 1)

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.replace_at(
        b,
        1,
        1,
        literal_patch("pushq %rdi"),
    )
    ctx.apply()

    assert bi.address == 0x1000
    assert bi.contents == bytearray(b"\x50\x57\x52")
    assert bi.size == 3
    assert b.offset == 0
    assert b.size == 3
    assert set(bi.symbolic_expressions.keys()) == set()
    assert set(bi.blocks) == {b}
    assert len(list(b.outgoing_edges)) == 0


def test_replace_bytes_in_place_with_symbol():
    # in place replacement is expected not to happen because of the symbol
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)
    b = add_code_block(bi, b"\x50\x51\x52")
    func = add_function_object(m, "func", b)
    set_all_blocks_alignment(m, 1)

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.replace_at(
        b,
        1,
        1,
        literal_patch("new: pushq %rdi"),
    )
    ctx.apply()

    new_sym = next(sym for sym in m.symbols if sym.name == "new")
    new_block = new_sym.referent

    assert bi.address == 0x1000
    assert bi.contents == bytearray(b"\x50\x57\x52")
    assert bi.size == 3
    assert b.offset == 0
    assert b.size == 1
    assert new_block.byte_interval is bi
    assert new_block.offset == 1
    assert new_block.size == 2
    assert set(bi.symbolic_expressions.keys()) == set()
    assert set(bi.blocks) == {b, new_block}

    edges = list(b.outgoing_edges)
    assert len(edges) == 1
    assert edges[0].label.type == gtirb.Edge.Type.Fallthrough
    assert edges[0].target == new_block


def test_insert_call_edges():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    # This mimics:
    #   func1:
    #   ret
    func1_block = add_code_block(bi, b"\xC3")
    func1 = add_function_object(m, "func1", func1_block)
    add_edge(ir.cfg, func1_block, add_proxy_block(m), gtirb.Edge.Type.Return)

    # This mimics:
    #   func2:
    #   nop
    b = add_code_block(bi, b"\x90")
    func2 = add_function_object(m, "func2", b)
    set_all_blocks_alignment(m, 1)

    ctx = gtirb_rewriting.RewritingContext(m, [func1, func2])
    ctx.insert_at(b, 0, literal_patch("call func1; nop"))
    ctx.apply()

    assert bi.contents == b"\xC3\xE8\x00\x00\x00\x00\x90\x90"

    call_edges = [
        edge for edge in ir.cfg if edge.label.type == gtirb.Edge.Type.Call
    ]
    assert len(call_edges) == 1
    assert call_edges[0].source == b
    assert call_edges[0].target == func1_block

    (new_block,) = set(bi.blocks) - {func1_block, b}
    return_edges = [
        edge for edge in ir.cfg if edge.label.type == gtirb.Edge.Type.Return
    ]
    assert len(return_edges) == 1
    assert return_edges[0].source == func1_block
    assert return_edges[0].target == new_block


def test_remove_call_edges():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    # This mimics:
    #   func1:
    #   ret
    func1_block = add_code_block(bi, b"\xC3")
    func1_sym = add_symbol(m, "func1", func1_block)
    func1 = add_function_object(m, func1_sym, func1_block)

    # This mimics:
    #   func2:
    #   call func1
    #   nop
    b = add_code_block(
        bi, b"\xEB\x00\x00\x00\x00", {1: gtirb.SymAddrConst(0, func1_sym)}
    )
    b2 = add_code_block(bi, b"\x90")
    func2 = add_function_object(m, "func2", b, {b2})

    add_edge(ir.cfg, b, func1_block, gtirb.Edge.Type.Call)
    add_edge(ir.cfg, b, b2, gtirb.Edge.Type.Fallthrough)
    add_edge(ir.cfg, func1_block, b2, gtirb.Edge.Type.Return)
    set_all_blocks_alignment(m, 1)

    # Now replace the call with a nop to verify that we delete the call edge
    # and replace the return edge with one to a proxy block.
    ctx = gtirb_rewriting.RewritingContext(m, [func1, func2])
    ctx.replace_at(b, 0, 5, literal_patch("nop"))
    ctx.apply()

    assert bi.contents == b"\xc3\x90\x90"

    call_edges = [
        edge for edge in ir.cfg if edge.label.type == gtirb.Edge.Type.Call
    ]
    assert not call_edges

    return_edges = [
        edge for edge in ir.cfg if edge.label.type == gtirb.Edge.Type.Return
    ]
    assert len(return_edges) == 1
    assert return_edges[0].source == func1_block
    assert isinstance(return_edges[0].target, gtirb.ProxyBlock)
    assert return_edges[0].target in m.proxies


def test_insert_after_call_edges():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    # This mimics:
    #   func1:
    #   ret
    func1_block = add_code_block(bi, b"\xC3")
    func1_sym = add_symbol(m, "func1", func1_block)
    func1 = add_function_object(m, func1_sym, func1_block)

    # This mimics:
    #   func2:
    #   call func1
    #   nop
    b = add_code_block(
        bi, b"\xEB\x00\x00\x00\x00", {1: gtirb.SymAddrConst(0, func1_sym)}
    )
    b2 = add_code_block(bi, b"\x90")
    func2 = add_function_object(m, "func2", b, {b2})

    add_edge(ir.cfg, b, func1_block, gtirb.Edge.Type.Call)
    add_edge(ir.cfg, b, b2, gtirb.Edge.Type.Fallthrough)
    add_edge(ir.cfg, func1_block, b2, gtirb.Edge.Type.Return)

    set_all_blocks_alignment(m, 1)

    # Now insert a nop after the call to verify the call's fallthrough edge
    # was updated correctly.
    ctx = gtirb_rewriting.RewritingContext(m, [func1, func2])
    ctx.insert_at(b, 5, literal_patch("first: nop; second: nop"))
    ctx.apply()

    assert bi.contents == b"\xC3\xEB\x00\x00\x00\x00\x90\x90\x90"
    first_block = next(
        sym for sym in m.symbols if sym.name == "first"
    ).referent

    return_edges = [
        edge for edge in ir.cfg if edge.label.type == gtirb.Edge.Type.Return
    ]
    assert len(return_edges) == 1
    assert return_edges[0].source == func1_block
    assert return_edges[0].target is first_block


def test_new_return_edges():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    # This mimics:
    #   func1:
    #   ret
    func1_block = add_code_block(bi, b"\xC3")
    func1_sym = add_symbol(m, "func1", func1_block)
    func1 = add_function_object(m, func1_sym, func1_block)

    # This mimics:
    #   func2:
    #   call func1
    #   nop
    b = add_code_block(
        bi, b"\xEB\x00\x00\x00\x00", {1: gtirb.SymAddrConst(0, func1_sym)}
    )
    b2 = add_code_block(bi, b"\x90")
    func2 = add_function_object(m, "func2", b, {b2})

    add_edge(ir.cfg, b, func1_block, gtirb.Edge.Type.Call)
    add_edge(ir.cfg, b, b2, gtirb.Edge.Type.Fallthrough)
    add_edge(ir.cfg, func1_block, b2, gtirb.Edge.Type.Return)

    set_all_blocks_alignment(m, 1)

    # Now insert a ret to verify that it gets the correct return edges
    ctx = gtirb_rewriting.RewritingContext(m, [func1, func2])
    ctx.insert_at(func1_block, 0, literal_patch("ret"))
    ctx.apply()

    assert bi.contents == b"\xC3\xC3\xEB\x00\x00\x00\x00\x90"

    return_edges = [
        edge for edge in ir.cfg if edge.label.type == gtirb.Edge.Type.Return
    ]
    assert len(return_edges) == 2
    assert return_edges[0].target == b2
    assert return_edges[1].target == b2
    assert not m.proxies


def test_insert_byte_directive_as_code():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    # This mimics:
    #   func:
    #   nop
    b = add_code_block(bi, b"\x90")
    func = add_function_object(m, "func", b)
    set_all_blocks_alignment(m, 1)

    # Insert some bytes to verify we get a code block
    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.insert_at(b, 0, literal_patch(".byte 0x66; .byte 0x90"))
    ctx.apply()

    assert bi.contents == b"\x66\x90\x90"
    assert set(bi.blocks) == {b}


def test_insert_byte_directive_as_data_due_to_unreachable_entrypoint():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    # This mimics:
    #   func:
    #   ret
    b = add_code_block(bi, b"\xC3")
    func = add_function_object(m, "func", b)
    add_edge(ir.cfg, b, add_proxy_block(m), gtirb.Edge.Type.Return)
    set_all_blocks_alignment(m, 1)

    # Insert some bytes that are trivially unreachable
    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.insert_at(b, b.size, literal_patch(".byte 0x66; .byte 0x90"))
    ctx.apply()

    (new_block,) = set(bi.blocks) - {b}
    assert bi.contents == b"\xC3\x66\x90"
    assert isinstance(new_block, gtirb.DataBlock)
    assert m.aux_data["functionBlocks"].data[func.uuid] == {b}


def test_insert_cfi_directives_in_proc():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    # This mimics:
    #   func:
    #   .cfi_startproc
    #   ret
    #   .cfi_endproc
    b = add_code_block(bi, b"\xC3")
    func = add_function_object(m, "func", b)
    add_edge(ir.cfg, b, add_proxy_block(m), gtirb.Edge.Type.Return)
    set_all_blocks_alignment(m, 1)

    m.aux_data["cfiDirectives"].data = {
        gtirb.Offset(b, 0): [
            (".cfi_startproc", [], NULL_UUID),
        ],
        gtirb.Offset(b, 1): [
            (".cfi_endproc", [], NULL_UUID),
        ],
    }

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.insert_at(b, 0, literal_patch("xor %rax, %rax; .cfi_undefined 0"))
    ctx.apply()

    assert bi.contents == b"\x48\x31\xC0\xC3"
    assert m.aux_data["cfiDirectives"].data == {
        gtirb.Offset(b, 0): [
            (".cfi_startproc", [], NULL_UUID),
        ],
        gtirb.Offset(b, 3): [
            (".cfi_undefined", [0], NULL_UUID),
        ],
        gtirb.Offset(b, 4): [
            (".cfi_endproc", [], NULL_UUID),
        ],
    }


def test_insert_cfi_directives_no_proc():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    # This mimics:
    #   func:
    #   ret
    b = add_code_block(bi, b"\xC3")
    func = add_function_object(m, "func", b)
    add_edge(ir.cfg, b, add_proxy_block(m), gtirb.Edge.Type.Return)
    set_all_blocks_alignment(m, 1)

    m.aux_data["cfiDirectives"].data = {}

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.insert_at(b, 0, literal_patch("xor %rax, %rax; .cfi_undefined 0"))
    ctx.apply()

    assert bi.contents == b"\x48\x31\xC0\xC3"
    assert m.aux_data["cfiDirectives"].data == {}


def test_insert_sym_expr_in_data():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    # This mimics:
    #   func:
    #   ret
    b = add_code_block(bi, b"\xC3")
    func = add_function_object(m, "func", b)
    add_edge(ir.cfg, b, add_proxy_block(m), gtirb.Edge.Type.Return)
    set_all_blocks_alignment(m, 1)

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.insert_at(
        b,
        0,
        literal_patch(
            """
            jmp foo
            str:
            .string "*"
            strptr:
            .quad str
            foo:
            """
        ),
    )
    ctx.apply()

    str_sym = next(sym for sym in m.symbols if sym.name == "str")
    str_block = str_sym.referent
    assert isinstance(str_block, gtirb.DataBlock)
    assert str_block.contents == b"*\x00"

    strptr_sym = next(sym for sym in m.symbols if sym.name == "strptr")
    strptr_block = strptr_sym.referent
    assert isinstance(strptr_block, gtirb.DataBlock)
    assert strptr_block.contents == b"\x00\x00\x00\x00\x00\x00\x00\x00"

    assert strptr_block.offset in bi.symbolic_expressions
    assert bi.symbolic_expressions[strptr_block.offset] == gtirb.SymAddrConst(
        0, str_sym
    )

    assert "symbolicExpressionSizes" in m.aux_data
    expr_sizes = m.aux_data["symbolicExpressionSizes"].data
    assert expr_sizes[gtirb.Offset(bi, strptr_block.offset)] == 8


def test_multiple_rewrites_with_red_zone():
    @gtirb_rewriting.patch_constraints(clobbers_registers=("rax",))
    def patch(insertion_ctx):
        return "call foo"

    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)
    add_symbol(m, "foo", add_proxy_block(m))

    # This mimics:
    #   leaf_func:
    #   ret
    b1 = add_code_block(bi, b"\xC3")
    func = add_function_object(m, "leaf_func", b1)
    set_all_blocks_alignment(m, 1)

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.insert_at(b1, 0, gtirb_rewriting.Patch.from_function(patch))
    ctx.apply()
    set_all_blocks_alignment(m, 1)

    assert "leafFunctions" in m.aux_data
    assert func.uuid in m.aux_data["leafFunctions"].data
    assert m.aux_data["leafFunctions"].data[func.uuid]
    assert bi.contents == (
        # lea	rsp, [rsp - 0x80]
        b"\x48\x8D\x64\x24\x80"
        # push  rax
        b"\x50"
        # call  0
        b"\xE8\x00\x00\x00\x00"
        # pop   rax
        b"\x58"
        # lea   rsp, [rsp + 0x80]
        b"\x48\x8D\xA4\x24\x80\x00\x00\x00"
        # ret
        b"\xC3"
    )

    # Now try inserting calls again, which should still be going out of its
    # way to protect the red zone.
    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.insert_at(b1, 0, gtirb_rewriting.Patch.from_function(patch))
    ctx.apply()

    assert "leafFunctions" in m.aux_data
    assert func.uuid in m.aux_data["leafFunctions"].data
    assert m.aux_data["leafFunctions"].data[func.uuid]
    assert bi.contents == (
        # lea	rsp, [rsp - 0x80]
        b"\x48\x8D\x64\x24\x80"
        # push  rax
        b"\x50"
        # call  0
        b"\xE8\x00\x00\x00\x00"
        # pop   rax
        b"\x58"
        # lea   rsp, [rsp + 0x80]
        b"\x48\x8D\xA4\x24\x80\x00\x00\x00"
        # lea	rsp, [rsp - 0x80]
        b"\x48\x8D\x64\x24\x80"
        # push  rax
        b"\x50"
        # call  0
        b"\xE8\x00\x00\x00\x00"
        # pop   rax
        b"\x58"
        # lea   rsp, [rsp + 0x80]
        b"\x48\x8D\xA4\x24\x80\x00\x00\x00"
        # ret
        b"\xC3"
    )


def test_multiple_rewrites_without_red_zone():
    @gtirb_rewriting.patch_constraints(clobbers_registers=("rax",))
    def patch(insertion_ctx):
        return "call foo"

    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)
    foo_sym = add_symbol(m, "foo", add_proxy_block(m))

    # This mimics:
    #   nonleaf_func:
    #   call foo
    #   ret
    b1 = add_code_block(bi, b"\xE8\x00\x00\x00\x00")
    b2 = add_code_block(bi, b"\xC3")
    func = add_function_object(m, "nonleaf_func", b1, {b2})
    add_edge(ir.cfg, b1, foo_sym.referent, gtirb.Edge.Type.Call)
    add_edge(ir.cfg, b1, b2, gtirb.Edge.Type.Return)
    set_all_blocks_alignment(m, 1)

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.replace_at(b1, 0, 5, literal_patch("nop"))
    ctx.apply()
    set_all_blocks_alignment(m, 1)

    assert "leafFunctions" in m.aux_data
    assert func.uuid in m.aux_data["leafFunctions"].data
    assert not m.aux_data["leafFunctions"].data[func.uuid]
    assert bi.contents == (
        # nop
        b"\x90"
        # ret
        b"\xC3"
    )

    # Now try inserting new code and verify that we don't insert code to
    # protect the red zone.
    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.insert_at(b1, 0, gtirb_rewriting.Patch.from_function(patch))
    ctx.apply()

    assert "leafFunctions" in m.aux_data
    assert func.uuid in m.aux_data["leafFunctions"].data
    assert not m.aux_data["leafFunctions"].data[func.uuid]
    assert bi.contents == (
        # push  rax
        b"\x50"
        # call  0
        b"\xE8\x00\x00\x00\x00"
        # pop   rax
        b"\x58"
        # nop
        b"\x90"
        # ret
        b"\xC3"
    )


def test_get_or_insert_extern_symbol():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )

    ctx = gtirb_rewriting.RewritingContext(m, [])
    sym = ctx.get_or_insert_extern_symbol("blah", "libblah.so")
    ctx.apply()

    assert sym.name == "blah"
    assert sym in m.symbols
    assert sym.referent in m.proxies
    assert m.aux_data["elfSymbolInfo"].data[sym] == (
        0,
        "FUNC",
        "GLOBAL",
        "DEFAULT",
        0,
    )
    assert m.aux_data["libraries"].data == ["libblah.so"]


@pytest.mark.parametrize(
    "props_table_name", ["sectionProperties", "elfSectionProperties"]
)
def test_insert_code_other_sections(props_table_name: str):
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)
    data, _ = add_data_section(m, address=0x2000)

    m.aux_data.pop("sectionProperties", None)
    m.aux_data.pop("elfSectionProperties", None)

    m.aux_data[props_table_name] = gtirb.AuxData(
        {}, "mapping<UUID,tuple<uint64_t,uint64_t>>"
    )

    # This mimics:
    #   func:
    #   nop
    b = add_code_block(bi, b"\x90")
    func = add_function_object(m, "func", b)
    set_all_blocks_alignment(m, 1)

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.insert_at(
        b,
        b.size,
        literal_patch(
            """
            movzb (.Lmy_cstr), %edi

            .data
            .Lmy_cstr:
            .asciz "*"

            .section new, "aw"
            .align 8
            .byte 42
            at_end:
            """
        ),
    )
    ctx.apply()

    cstr_sym = next(sym for sym in m.symbols if sym.name == ".Lmy_cstr_1")
    assert isinstance(cstr_sym.referent, gtirb.DataBlock)
    assert cstr_sym.referent.section is data
    assert cstr_sym.referent.contents == b"*\x00"

    assert bi.contents == b"\x90\x0F\xB6\x3C\x25\x00\x00\x00\x00"
    assert bi.symbolic_expressions[5] == gtirb.SymAddrConst(0, cstr_sym)

    new_sect = next(sect for sect in m.sections if sect.name == "new")
    new_sect_blocks = list(new_sect.byte_blocks)
    assert len(new_sect_blocks) == 1
    assert isinstance(new_sect_blocks[0], gtirb.DataBlock)
    assert new_sect_blocks[0].contents == b"*"
    assert m.aux_data["alignment"].data[new_sect_blocks[0]] == 8

    at_end_symbol = next(sym for sym in m.symbols if sym.name == "at_end")
    assert at_end_symbol.at_end
    assert at_end_symbol.referent is new_sect_blocks[0]

    SHT_PROGBITS = 1
    SHF_WRITE = 1
    SHF_ALLOC = 2
    assert m.aux_data[props_table_name].data[new_sect] == (
        SHT_PROGBITS,
        SHF_WRITE | SHF_ALLOC,
    )


def test_align():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    b = add_code_block(bi, b"\x57\x58")
    func = add_function_object(m, "func", b)

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.insert_at(
        b,
        1,
        literal_patch(
            """
            .align 4
            nop
            """
        ),
    )
    ctx.apply()

    assert bi.contents == b"\x57\x90\x58"

    blocks = sorted(bi.blocks, key=lambda b: b.offset)
    assert len(blocks) == 2

    assert blocks[0].offset == 0
    assert blocks[0].size == 1

    assert blocks[1].offset == 1
    assert blocks[1].size == 2

    assert m.aux_data["alignment"].data[blocks[1]] == 4


def test_logging(caplog):
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    b = add_code_block(bi, b"\x90")
    func = add_function_object(m, "func", b)

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.insert_at(b, 0, literal_patch("ud2; blah:"))

    with caplog.at_level(logging.DEBUG):
        ctx.apply()

        assert "nop" in caplog.text
        assert "ud2" in caplog.text


def test_functionless():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    b = add_code_block(bi, b"\x90")

    ctx = gtirb_rewriting.RewritingContext(m, [])
    ctx.insert_at(b, 0, literal_patch("int3"))
    ctx.apply()

    assert bi.contents == b"\xCC\x90"


def test_function_scope_without_functions():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    _ = add_code_block(bi, b"\x90")

    ctx = gtirb_rewriting.RewritingContext(m, [])
    with pytest.raises(gtirb_rewriting.UnresolvableScopeError):
        ctx.register_insert(
            gtirb_rewriting.AllFunctionsScope(
                gtirb_rewriting.FunctionPosition.ENTRY,
                gtirb_rewriting.BlockPosition.ANYWHERE,
            ),
            literal_patch("int3"),
        )
    ctx.apply()

    assert bi.contents == b"\x90"


def test_function_back_compat():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    b = add_code_block(bi, b"\x90")
    func = add_function_object(m, "func", b)

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    with pytest.deprecated_call():
        ctx.insert_at(func, b, 0, literal_patch("ud2"))
    with pytest.deprecated_call():
        ctx.replace_at(func, b, 0, 1, literal_patch("int3"))
    ctx.apply()

    assert bi.contents == b"\x0F\x0B\xCC"


def test_data_rewriting():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_data_section(m, address=0x1000)

    b = add_data_block(bi, b"boring\x00")

    ctx = gtirb_rewriting.RewritingContext(m, [])
    ctx.insert_at(b, 0, b"Hello")
    ctx.replace_at(b, 0, 3, literal_patch(".byte 32"))
    ctx.replace_at(b, 3, 3, b"World")
    ctx.delete_at(b, 6, 1)
    ctx.apply()

    assert bi.contents == b"Hello World"
    assert bi.blocks == {b}
    assert b.offset == 0
    assert b.size == 11


def test_data_with_code_patch():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_data_section(m, address=0x1000)

    b = add_data_block(bi, b"\x00")

    ctx = gtirb_rewriting.RewritingContext(m, [])
    ctx.insert_at(b, 0, literal_patch("nop"))
    ctx.apply()

    assert bi.contents == b"\x90\x00"
    assert len(bi.blocks) == 2
    # This probably isn't an API contract, but it's a logical consequence of
    # needing to avoid 0-sized blocks.
    assert b.byte_interval is None


def test_data_with_symbolic_expressions():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_data_section(m, address=0x1000)

    b = add_data_block(bi, b"\xFF")
    test_sym = add_symbol(m, "test", b)

    ctx = gtirb_rewriting.RewritingContext(m, [])
    ctx.replace_at(b, 0, 1, literal_patch(".quad test"))
    ctx.apply()

    assert bi.blocks == {b}
    assert bi.contents == b"\x00" * 8
    assert bi.symbolic_expressions[0] == gtirb.SymAddrConst(0, test_sym)
    assert m.aux_data["symbolicExpressionSizes"].data[gtirb.Offset(bi, 0)] == 8


def test_retarget_and_delete():
    """
    Test that we don't raise exceptions if we can't retarget an expression
    that is scheduled to be deleted.
    """

    # This mimics:
    #   foo:
    #   nop
    #
    #   .quad foo - foo
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    b1 = add_code_block(bi, b"\x90")
    foo_sym = add_symbol(m, "foo", b1)
    undef_sym = add_symbol(m, "undef", add_proxy_block(m))
    b2 = add_data_block(
        bi, b"\x00\x00\x00\x00", {0: gtirb.SymAddrAddr(1, 0, foo_sym, foo_sym)}
    )

    rwc = gtirb_rewriting.RewritingContext(m, [])
    # This will force the SymAddrAddr to be retargeted, which we don't support
    rwc.retarget_symbol_uses(foo_sym, undef_sym)
    # But this will cause the block containing it to be deleted, so it's okay
    rwc.delete_at(b2, 0, b2.size)
    rwc.apply()

    assert bi.blocks == {b1}
    assert bi.symbolic_expressions == {}


@pytest.mark.parametrize("place_b1_before_b2", (True, False))
def test_layout_before_no_addr(place_b1_before_b2: bool):
    """
    Test that rewriting can handle inputs that lack addresses.
    """
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )

    # Create one block with an address and a second block that lacks an
    # address.
    text_section, bi1 = add_text_section(m, address=0x1000)
    b1 = add_code_block(bi1, b"\x90")
    bi2 = gtirb.ByteInterval(section=text_section)
    b2 = add_code_block(bi2, b"\x90")

    # Add a fallthrough edge so that there is a deterministic layout
    if place_b1_before_b2:
        add_edge(ir.cfg, b1, b2, gtirb.EdgeType.Fallthrough)
    else:
        add_edge(ir.cfg, b2, b1, gtirb.EdgeType.Fallthrough)

    # And add a symbol, which we'll use to track that gtirb-rewriting
    # understood the relative order between blocks correctly.
    b1_sym = add_symbol(m, "b1", b1)
    assert gtirb_layout.is_module_layout_required(m)

    # Delete b1, which will cause the symbol attached to it to move.
    rwc = gtirb_rewriting.RewritingContext(m, [])
    rwc.delete_at(b1, 0, b1.size)
    rwc.apply()

    assert b1_sym.referent is b2
    if place_b1_before_b2:
        # b1 was deleted and b2 is after it, so the symbol should not be an
        # at-end symbol since it points to the start of b2.
        assert not b1_sym.at_end
    else:
        # b1 was deleted and b2 is before it, so the symbol should be an
        # at-end symbol.
        assert b1_sym.at_end

    assert bi1.contents == b""
    assert bi2.contents == b"\x90"


def test_layout_before_integral_symbol():
    """
    Test that rewriting assigns integral symbols before rewriting.
    """
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )

    # Create an integral symbol that needs to be resolved to stay attached
    # to the block it points at.
    _, bi = add_text_section(m, address=0x1000)
    b1 = add_code_block(bi, b"\x90")
    b2 = add_code_block(bi, b"\x90")
    integral_sym = gtirb.Symbol("integral", payload=b2.address, module=m)

    # Cause b1 to grow, which would leave the integral address pointing to the
    # middle of a block.
    rwc = gtirb_rewriting.RewritingContext(m, [])
    rwc.insert_at(b1, 0, literal_patch("nop"))
    rwc.apply()

    assert integral_sym.referent is b2
    assert not integral_sym.at_end
    assert bi.contents == b"\x90\x90\x90"


def test_layout_after():
    """
    Test that the output of gtirb-rewriting does not need further layout.
    """
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)
    b1 = add_code_block(bi, b"\x90")
    add_code_block(bi, b"\x90")

    # Generate changes that result in blocks with no addresses or overlapping
    # addresses.
    rwc = gtirb_rewriting.RewritingContext(m, [])
    rwc.register_insert_function("foo", literal_patch("nop"))
    rwc.insert_at(b1, b1.size, literal_patch("nop"))
    rwc.apply()

    assert not gtirb_layout.is_module_layout_required(m)
