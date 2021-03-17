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
import gtirb_functions
import gtirb_rewriting
import pytest
from helpers import (
    add_code_block,
    add_edge,
    add_function,
    add_proxy_block,
    add_symbol,
    create_test_module,
    literal_patch,
    set_all_blocks_alignment,
)


@gtirb_rewriting.patch_constraints()
def dummy_patch(insertion_ctx):
    return """
    nop
    nop
    # This forces the start of a new block.
    .L_blah:
    """


def test_multiple_insertions():
    ir, m, bi = create_test_module()

    b = add_code_block(bi, b"\x50\x51\x52\x53\x54\x55\x56\x57")
    func = add_function(m, "hi", b)

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.insert_at(func, b, 0, gtirb_rewriting.Patch.from_function(dummy_patch))
    ctx.insert_at(func, b, 7, gtirb_rewriting.Patch.from_function(dummy_patch))
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
    assert blocks[1].size == 7

    assert len(refs[2]) == 0
    assert blocks[2].offset == 9
    assert blocks[2].size == 2

    assert len(refs[3]) == 1
    assert refs[3][0].name == ".L_blah_2"
    assert blocks[3].offset == 11
    assert blocks[3].size == 1


def test_multiple_replacements():
    @gtirb_rewriting.patch_constraints()
    def nop_patch(context):
        return "nop"

    ir, m, bi = create_test_module()
    b = add_code_block(bi, b"\x50\x51\x52\x53\x54\x55\x56\x57")
    func = add_function(m, "hi", b)

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.replace_at(
        func, b, 0, 2, gtirb_rewriting.Patch.from_function(nop_patch)
    )
    ctx.replace_at(
        func, b, 3, 4, gtirb_rewriting.Patch.from_function(nop_patch)
    )
    ctx.insert_at(func, b, 8, gtirb_rewriting.Patch.from_function(nop_patch))
    ctx.apply()

    assert bi.contents == b"\x90\x52\x90\x57\x90"
    assert sum(b.size for b in bi.blocks) == 5


def test_added_function_blocks():
    ir, m, bi = create_test_module()
    b = add_code_block(bi, b"\x50\x51\x52\x53\x54\x55\x56\x57")
    func = add_function(m, "hi", b)

    functions = gtirb_functions.Function.build_functions(m)
    assert len(functions) == 1
    assert len(functions[0].get_all_blocks()) == 1

    ctx = gtirb_rewriting.RewritingContext(m, functions)
    ctx.insert_at(
        functions[0], b, 7, gtirb_rewriting.Patch.from_function(dummy_patch)
    )
    ctx.apply()

    assert len(m.aux_data["functionBlocks"].data[func.uuid]) == 3
    assert (
        sum(b.size for b in m.aux_data["functionBlocks"].data[func.uuid])
        == bi.size
        == 10
    )


def test_expensive_assertions():
    ir, m, bi = create_test_module()
    b = add_code_block(bi, b"\xE8\x00\x00\x00\x00\xE8\x00\x00\x00\x00")
    func = add_function(m, "hi", b)

    ctx = gtirb_rewriting.RewritingContext(
        m, [func], expensive_assertions=True
    )
    ctx.insert_at(func, b, 0, gtirb_rewriting.Patch.from_function(dummy_patch))
    ctx.insert_at(func, b, 5, gtirb_rewriting.Patch.from_function(dummy_patch))
    # Offset is not on an instruction boundary
    with pytest.raises(AssertionError):
        ctx.insert_at(
            func, b, 1, gtirb_rewriting.Patch.from_function(dummy_patch),
        )
    # Offset is not on an instruction boundary
    with pytest.raises(AssertionError):
        ctx.replace_at(
            func, b, 1, 0, gtirb_rewriting.Patch.from_function(dummy_patch),
        )
    # Offset is valid, but end position isn't on an instruction boundary
    with pytest.raises(AssertionError):
        ctx.replace_at(
            func, b, 0, 6, gtirb_rewriting.Patch.from_function(dummy_patch),
        )
    # Range extends out of the block's bounds
    with pytest.raises(AssertionError):
        ctx.replace_at(
            func, b, 0, 60, gtirb_rewriting.Patch.from_function(dummy_patch),
        )
    ctx.apply()


def test_conflicting_insertion_replacement():
    ir, m, bi = create_test_module()
    b = add_code_block(bi, b"\x90\x90\x90\x90\x90\x90\x90\x90")
    func = add_function(m, "hi", b)

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.insert_at(func, b, 7, gtirb_rewriting.Patch.from_function(dummy_patch))
    ctx.replace_at(
        func, b, 0, bi.size, gtirb_rewriting.Patch.from_function(dummy_patch),
    )
    with pytest.raises(AssertionError):
        ctx.apply()


def test_inserting_function_and_call():
    ir, m, bi = create_test_module()
    main_block = add_code_block(bi, b"\x90")
    func = add_function(m, "main", main_block)

    @gtirb_rewriting.patch_constraints()
    def function_patch(ctx):
        return "mov $42, %eax; ret"

    @gtirb_rewriting.patch_constraints()
    def call_patch(ctx):
        return "call target"

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    target_sym = ctx.register_insert_function(
        "target", gtirb_rewriting.Patch.from_function(function_patch)
    )
    ctx.insert_at(
        func, main_block, 0, gtirb_rewriting.Patch.from_function(call_patch),
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


def test_inserting_function_calling_inserted_function():
    @gtirb_rewriting.patch_constraints()
    def target_function_patch(ctx):
        return "mov $42, %eax; ret"

    @gtirb_rewriting.patch_constraints()
    def call_function_patch(ctx):
        return "call target; ud2"

    ir, m, bi = create_test_module()

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


def test_insert_bytes_offset0():
    ir, m, bi = create_test_module()
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
    func = add_function(m, "func", b, {b2})
    add_edge(ir.cfg, b, b2, gtirb.Edge.Type.Fallthrough)
    set_all_blocks_alignment(m, 1)

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.insert_at(func, b, 0, literal_patch("hi: nop"))
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
    ir, m, bi = create_test_module()

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
    func = add_function(m, "func", b1, {b2, b3})

    add_edge(ir.cfg, b1, b3, gtirb.Edge.Type.Branch, conditional=True)
    add_edge(ir.cfg, b1, b2, gtirb.Edge.Type.Fallthrough)
    add_edge(ir.cfg, b2, b3, gtirb.Edge.Type.Fallthrough)
    set_all_blocks_alignment(m, 1)

    # Test inserting after the jump instruction
    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.insert_at(func, b1, 2, literal_patch("nop"))
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
    ir, m, bi = create_test_module()
    b = add_code_block(bi, b"\xB8\x2A\x00\x00\x00\xC3")
    return_proxy = add_proxy_block(m)
    add_edge(ir.cfg, b, return_proxy, gtirb.Edge.Type.Return)
    func = add_function(m, "func", b)
    set_all_blocks_alignment(m, 1)

    # Test inserting after a ret
    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.insert_at(func, b, b.size, literal_patch("nop"))
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
    ir, m, bi = create_test_module()
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
    func = add_function(m, "func", b, {b2})
    add_edge(ir.cfg, b, b2, gtirb.Edge.Type.Fallthrough)
    set_all_blocks_alignment(m, 1)

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.replace_at(func, b, 0, 7, literal_patch("hi: nop"))
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
    ir, m, bi = create_test_module()

    extern_func_proxy = add_proxy_block(m)
    extern_func_sym = add_symbol(m, "puts", extern_func_proxy)

    # This mimics:
    #   func:
    #   pushq %rdi
    #   call puts
    #   ud2
    b = add_code_block(bi, b"\x57\xE8\x00\x00\x00\x00", {2: extern_func_sym})
    b2 = add_code_block(bi, b"\x0F\x0B")
    func = add_function(m, "func", b, {b2})

    add_edge(ir.cfg, b, b2, gtirb.Edge.Type.Fallthrough)
    add_edge(ir.cfg, b, extern_func_proxy, gtirb.Edge.Type.Call)
    set_all_blocks_alignment(m, 1)

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.replace_at(func, b, 1, 5, literal_patch("nop"))
    ctx.apply()

    assert bi.address == 0x1000
    assert bi.contents == b"\x57\x90\x0f\x0b"
    assert bi.size == 4
    assert b.offset == 0
    assert b.size == 1
    (new_block,) = set(bi.blocks) - {b, b2}
    assert new_block.byte_interval is bi
    assert new_block.offset == 1
    assert new_block.size == 1
    assert b2.offset == 2
    assert b2.size == 2
    assert set(bi.symbolic_expressions.keys()) == set()
    assert set(bi.blocks) == {b, new_block, b2}

    edges = list(b.outgoing_edges)
    assert len(edges) == 1
    assert edges[0].label.type == gtirb.Edge.Type.Fallthrough
    assert edges[0].target == new_block

    edges = list(new_block.outgoing_edges)
    assert len(edges) == 1
    assert edges[0].label.type == gtirb.Edge.Type.Fallthrough
    assert edges[0].target == b2


def test_replace_bytes_all():
    ir, m, bi = create_test_module()

    extern_func_proxy = add_proxy_block(m)
    extern_func_sym = add_symbol(m, "puts", extern_func_proxy)

    # This mimics:
    #   func:
    #   pushq %rdi
    #   call puts
    #   ud2
    b = add_code_block(bi, b"\x57\xE8\x00\x00\x00\x00", {2: extern_func_sym})
    b2 = add_code_block(bi, b"\x0F\x0B")
    func = add_function(m, "func", b, {b2})

    add_edge(ir.cfg, b, b2, gtirb.Edge.Type.Fallthrough)
    add_edge(ir.cfg, b, extern_func_proxy, gtirb.Edge.Type.Call)
    set_all_blocks_alignment(m, 1)

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.replace_at(func, b, 0, b.size, literal_patch("nop"))
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
    ir, m, bi = create_test_module()

    extern_func_proxy = add_proxy_block(m)
    extern_func_sym = add_symbol(m, "puts", extern_func_proxy)

    # This mimics:
    #   func:
    #   pushq %rdi
    #   call puts
    #   ud2
    b = add_code_block(bi, b"\x57\xE8\x00\x00\x00\x00", {2: extern_func_sym})
    b2 = add_code_block(bi, b"\x0F\x0B")
    func = add_function(m, "func", b, {b2})

    add_edge(ir.cfg, b, b2, gtirb.Edge.Type.Fallthrough)
    add_edge(ir.cfg, b, extern_func_proxy, gtirb.Edge.Type.Call)
    set_all_blocks_alignment(m, 1)

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.replace_at(func, b, 1, 5, literal_patch("jmp foo; foo:"))
    ctx.apply()

    assert bi.contents == b"\x57\xEB\x00\x0f\x0b"
    assert bi.size == 5
    assert b.offset == 0
    assert b.size == 1
    (new_block,) = set(bi.blocks) - {b, b2}
    assert new_block.offset == 1
    assert new_block.size == 2
    assert b2.offset == 3
    assert b2.size == 2

    foo_symbol = next(sym for sym in m.symbols if sym.name == "foo")
    assert set(bi.symbolic_expressions.keys()) == {2}
    assert bi.symbolic_expressions[2].symbol == foo_symbol
    assert foo_symbol.referent is b2

    edges = list(b.outgoing_edges)
    assert len(edges) == 1
    assert edges[0].label.type == gtirb.Edge.Type.Fallthrough
    assert edges[0].target == new_block

    edges = list(new_block.outgoing_edges)
    assert len(edges) == 1
    assert edges[0].label.type == gtirb.Edge.Type.Branch
    assert edges[0].target == b2


def test_replace_bytes_in_place_no_symbol():
    ir, m, bi = create_test_module()
    b = add_code_block(bi, b"\x50\x51\x52")
    func = add_function(m, "func", b)
    set_all_blocks_alignment(m, 1)

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.replace_at(
        func, b, 1, 1, literal_patch("pushq %rdi"),
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
    ir, m, bi = create_test_module()
    b = add_code_block(bi, b"\x50\x51\x52")
    func = add_function(m, "func", b)
    set_all_blocks_alignment(m, 1)

    ctx = gtirb_rewriting.RewritingContext(m, [func])
    ctx.replace_at(
        func, b, 1, 1, literal_patch("new: pushq %rdi"),
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
    ir, m, bi = create_test_module()

    # This mimics:
    #   func1:
    #   ret
    func1_block = add_code_block(bi, b"\xC3")
    func1 = add_function(m, "func1", func1_block)
    add_edge(ir.cfg, func1_block, add_proxy_block(m), gtirb.Edge.Type.Return)

    # This mimics:
    #   func2:
    #   nop
    b = add_code_block(bi, b"\x90")
    func2 = add_function(m, "func2", b)
    set_all_blocks_alignment(m, 1)

    ctx = gtirb_rewriting.RewritingContext(m, [func1, func2])
    ctx.insert_at(func2, b, 0, literal_patch("call func1; nop"))
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
    ir, m, bi = create_test_module()

    # This mimics:
    #   func1:
    #   ret
    func1_block = add_code_block(bi, b"\xC3")
    func1_sym = add_symbol(m, "func1", func1_block)
    func1 = add_function(m, func1_sym, func1_block)

    # This mimics:
    #   func2:
    #   call func1
    #   nop
    b = add_code_block(
        bi, b"\xEB\x00\x00\x00\x00", {1: gtirb.SymAddrConst(0, func1_sym)}
    )
    b2 = add_code_block(bi, b"\x90")
    func2 = add_function(m, "func2", b, {b2})

    add_edge(ir.cfg, b, func1_block, gtirb.Edge.Type.Call)
    add_edge(ir.cfg, b, b2, gtirb.Edge.Type.Fallthrough)
    add_edge(ir.cfg, func1_block, b2, gtirb.Edge.Type.Return)
    set_all_blocks_alignment(m, 1)

    # Now replace the call with a nop to verify that we delete the call edge
    # and replace the return edge with one to a proxy block.
    ctx = gtirb_rewriting.RewritingContext(m, [func1, func2])
    ctx.replace_at(func2, b, 0, 5, literal_patch("nop"))
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
    ir, m, bi = create_test_module()

    # This mimics:
    #   func1:
    #   ret
    func1_block = add_code_block(bi, b"\xC3")
    func1_sym = add_symbol(m, "func1", func1_block)
    func1 = add_function(m, func1_sym, func1_block)

    # This mimics:
    #   func2:
    #   call func1
    #   nop
    b = add_code_block(
        bi, b"\xEB\x00\x00\x00\x00", {1: gtirb.SymAddrConst(0, func1_sym)}
    )
    b2 = add_code_block(bi, b"\x90")
    func2 = add_function(m, "func2", b, {b2})

    add_edge(ir.cfg, b, func1_block, gtirb.Edge.Type.Call)
    add_edge(ir.cfg, b, b2, gtirb.Edge.Type.Fallthrough)
    add_edge(ir.cfg, func1_block, b2, gtirb.Edge.Type.Return)

    set_all_blocks_alignment(m, 1)

    # Now insert a nop after the call to verify the call's fallthrough edge
    # was updated correctly.
    ctx = gtirb_rewriting.RewritingContext(m, [func1, func2])
    ctx.insert_at(func2, b, 5, literal_patch("nop"))
    ctx.apply()

    assert bi.contents == b"\xC3\xEB\x00\x00\x00\x00\x90\x90"

    return_edges = [
        edge for edge in ir.cfg if edge.label.type == gtirb.Edge.Type.Return
    ]
    assert len(return_edges) == 1
    assert return_edges[0].source == func1_block
    assert return_edges[0].target not in {func1_block, b, b2}


def test_new_return_edges():
    ir, m, bi = create_test_module()

    # This mimics:
    #   func1:
    #   ret
    func1_block = add_code_block(bi, b"\xC3")
    func1_sym = add_symbol(m, "func1", func1_block)
    func1 = add_function(m, func1_sym, func1_block)

    # This mimics:
    #   func2:
    #   call func1
    #   nop
    b = add_code_block(
        bi, b"\xEB\x00\x00\x00\x00", {1: gtirb.SymAddrConst(0, func1_sym)}
    )
    b2 = add_code_block(bi, b"\x90")
    func2 = add_function(m, "func2", b, {b2})

    add_edge(ir.cfg, b, func1_block, gtirb.Edge.Type.Call)
    add_edge(ir.cfg, b, b2, gtirb.Edge.Type.Fallthrough)
    add_edge(ir.cfg, func1_block, b2, gtirb.Edge.Type.Return)

    set_all_blocks_alignment(m, 1)

    # Now insert a ret to verify that it gets the correct return edges
    ctx = gtirb_rewriting.RewritingContext(m, [func1, func2])
    ctx.insert_at(func1, func1_block, 0, literal_patch("ret"))
    ctx.apply()

    assert bi.contents == b"\xC3\xC3\xEB\x00\x00\x00\x00\x90"

    return_edges = [
        edge for edge in ir.cfg if edge.label.type == gtirb.Edge.Type.Return
    ]
    assert len(return_edges) == 2
    assert return_edges[0].target == b2
    assert return_edges[1].target == b2
    assert not m.proxies
