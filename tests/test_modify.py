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
)
from helpers import add_function_object


def test_return_cache():
    ir, m = create_test_module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
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

    with gtirb_rewriting._modify.make_return_cache(ir) as return_cache:
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
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
    )
    _, bi = add_text_section(m)
    orig_cfg = ir.cfg

    b1 = add_code_block(bi, b"\x90")
    b2 = add_code_block(bi, b"\xC3")
    edge1 = add_edge(ir.cfg, b1, b2, gtirb.Edge.Type.Fallthrough)

    with gtirb_rewriting._modify.make_return_cache(ir) as return_cache:
        with gtirb_rewriting._modify.make_return_cache(ir) as return_cache2:
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
        with gtirb_rewriting._modify.make_return_cache(ir) as return_cache:
            orig_cfg.discard(edge2)
            orig_cfg.add(edge1)
    assert ir.cfg is orig_cfg

    with pytest.raises(gtirb_rewriting.CFGModifiedError):
        with gtirb_rewriting._modify.make_return_cache(ir) as return_cache:
            ir.cfg = gtirb.CFG()
    assert ir.cfg is orig_cfg

    # And that we restore the old CFG correctly with exceptions
    with pytest.raises(ZeroDivisionError):
        with gtirb_rewriting._modify.make_return_cache(ir) as return_cache:
            raise ZeroDivisionError()
    assert ir.cfg is orig_cfg


def test_modify_cache():
    ir, m = create_test_module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
    )
    _, bi = add_text_section(m)

    # This mimics:
    #  ret
    #  ud2
    b1 = add_code_block(bi, b"\xC3")
    b2 = add_code_block(bi, b"\x0F\x0B")
    func = add_function_object(m, "func", b1)

    modify_cache = gtirb_rewriting._modify.ModifyCache(
        m, [func], gtirb_rewriting._modify.ReturnEdgeCache(ir.cfg)
    )

    assert modify_cache.functions_by_block[b1] == func.uuid
    assert b2 not in modify_cache.functions_by_block


def test_split_block_simple():
    """
    Tests basic properties about splitting a block.
    """

    ir, m = create_test_module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
    )
    _, bi = add_text_section(m)

    b1 = add_code_block(bi, b"\x90\xC3")
    b2 = add_code_block(bi, b"\x90")
    begin_sym = gtirb.Symbol("begin_sym", payload=b1, at_end=False, module=m)
    end_sym = gtirb.Symbol("end_sym", payload=b1, at_end=True, module=m)

    add_edge(ir.cfg, b1, b2, gtirb.EdgeType.Fallthrough)
    func = add_function_object(m, begin_sym, b1)

    m.aux_data["comments"].data[gtirb.Offset(b1, 0)] = "0"
    m.aux_data["comments"].data[gtirb.Offset(b1, 1)] = "1"

    modify_cache = gtirb_rewriting._modify.ModifyCache(
        m, [func], gtirb_rewriting._modify.ReturnEdgeCache(ir.cfg)
    )
    b1_start, b1_end, fallthrough = gtirb_rewriting._modify.split_block(
        modify_cache, b1, 1
    )

    assert b1_start is b1
    assert b1.offset == 0
    assert b1.size == 1
    assert b1.byte_interval is bi

    assert isinstance(b1_end, gtirb.CodeBlock)
    assert b1_end.offset == 1
    assert b1_end.size == 1
    assert b1_end.byte_interval is bi

    assert fallthrough is not None
    assert fallthrough.source is b1
    assert fallthrough.target is b1_end
    assert (
        fallthrough.label
        and fallthrough.label.type == gtirb.EdgeType.Fallthrough
    )

    (b1_b2_fallthrough,) = set(ir.cfg) - {fallthrough}
    assert b1_b2_fallthrough.source == b1_end
    assert b1_b2_fallthrough.target == b2
    assert (
        b1_b2_fallthrough.label
        and b1_b2_fallthrough.label.type == gtirb.EdgeType.Fallthrough
    )

    assert begin_sym.referent is b1
    assert not begin_sym.at_end

    assert end_sym.referent is b1_end
    assert end_sym.at_end

    assert m.aux_data["comments"].data == {
        gtirb.Offset(b1, 0): "0",
        gtirb.Offset(b1_end, 0): "1",
    }

    assert m.aux_data["functionEntries"].data == {func.uuid: {b1}}
    assert m.aux_data["functionBlocks"].data == {func.uuid: {b1, b1_end}}


def test_split_block_begin():
    ir, m = create_test_module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
    )
    _, bi = add_text_section(m)

    b1 = add_code_block(bi, b"\x90\xC3")
    func = add_function_object(m, "b1", b1)

    m.aux_data["alignment"].data[b1] = 4

    m.aux_data["cfiDirectives"].data[gtirb.Offset(b1, 0)] = [
        (".cfi_startproc", [], NULL_UUID),
        (".cfi_personality", [], NULL_UUID),
    ]
    m.aux_data["cfiDirectives"].data[gtirb.Offset(b1, 2)] = [
        (".cfi_endproc", [], NULL_UUID)
    ]

    modify_cache = gtirb_rewriting._modify.ModifyCache(
        m, [func], gtirb_rewriting._modify.ReturnEdgeCache(ir.cfg)
    )
    b1_start, b1_end, fallthrough = gtirb_rewriting._modify.split_block(
        modify_cache, b1, 0
    )

    assert b1_start is b1
    assert b1_start.offset == 0
    assert b1_start.size == 0
    assert b1_start.byte_interval is bi

    assert b1_end.offset == 0
    assert b1_end.size == 2
    assert b1_end.byte_interval is bi

    assert fallthrough is not None
    assert fallthrough.source is b1_start
    assert fallthrough.target is b1_end
    assert (
        fallthrough.label
        and fallthrough.label.type == gtirb.EdgeType.Fallthrough
    )

    assert m.aux_data["alignment"].data == {b1_start: 4}

    assert m.aux_data["cfiDirectives"].data == {
        gtirb.Offset(b1_start, 0): [
            (".cfi_startproc", [], NULL_UUID),
            (".cfi_personality", [], NULL_UUID),
        ],
        gtirb.Offset(b1_end, 2): [
            (".cfi_endproc", [], NULL_UUID),
        ],
    }


def test_split_block_end_with_call():
    """
    Test that splitting a block at the end when has a call and a fallthrough
    edge generates the correct fallthrough edges and updates the return edge.
    """

    # This mimics:
    # func1:
    # ret
    #
    # func2:
    # call func1
    # ud2

    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m)

    func1_b1 = add_code_block(bi, b"\xC3")
    func2_b1 = add_code_block(bi, b"\xE8\x00\x00\x00\x00")
    func2_b2 = add_code_block(bi, b"\x0F\x0B")
    func1 = add_function_object(m, "func1", func1_b1)
    func2 = add_function_object(m, "func2", func2_b1, {func2_b2})

    add_edge(ir.cfg, func1_b1, func2_b2, gtirb.EdgeType.Return)
    add_edge(ir.cfg, func2_b1, func1_b1, gtirb.EdgeType.Call)
    add_edge(ir.cfg, func2_b1, func2_b2, gtirb.EdgeType.Fallthrough)

    modify_cache = gtirb_rewriting._modify.ModifyCache(
        m, [func1, func2], gtirb_rewriting._modify.ReturnEdgeCache(ir.cfg)
    )
    split_start, split_end, fallthrough = gtirb_rewriting._modify.split_block(
        modify_cache, func2_b1, func2_b1.size
    )

    assert split_start is func2_b1
    assert split_start.offset == 1
    assert split_start.size == 5
    assert split_end.offset == 6
    assert split_end.size == 0
    assert fallthrough

    assert set(ir.cfg) == {
        gtirb.Edge(
            func1_b1, split_end, gtirb.EdgeLabel(gtirb.EdgeType.Return)
        ),
        gtirb.Edge(func2_b1, func1_b1, gtirb.EdgeLabel(gtirb.EdgeType.Call)),
        gtirb.Edge(
            func2_b1, split_end, gtirb.EdgeLabel(gtirb.EdgeType.Fallthrough)
        ),
        gtirb.Edge(
            split_end, func2_b2, gtirb.EdgeLabel(gtirb.EdgeType.Fallthrough)
        ),
    }


def test_split_block_end_with_jump():
    """
    Test that splitting a block at the end when it only has a branch as a
    out edge does not generate new fallthrough edges.
    """

    # This mimics:
    #     jmp next
    #   next:
    #     nop
    #

    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m)

    b1 = add_code_block(bi, b"\xEB\x00")
    b2 = add_code_block(bi, b"\x90")
    add_symbol(m, "next", b2)

    add_edge(ir.cfg, b1, b2, gtirb.EdgeType.Branch)
    func = add_function_object(m, "func", b1, {b2})

    modify_cache = gtirb_rewriting._modify.ModifyCache(
        m, [func], gtirb_rewriting._modify.ReturnEdgeCache(ir.cfg)
    )
    split_start, split_end, fallthrough = gtirb_rewriting._modify.split_block(
        modify_cache, b1, b1.size
    )

    assert split_start is b1
    assert split_start.offset == 0
    assert split_start.size == 2
    assert split_end.offset == 2
    assert split_end.size == 0
    assert fallthrough is None

    assert set(ir.cfg) == {
        gtirb.Edge(b1, b2, gtirb.EdgeLabel(gtirb.EdgeType.Branch)),
    }


def test_split_blocks_proc_begin():
    """
    Test that splitting a block at the beginning leaves the .cfi_start_proc
    directive in the first block.
    """

    # This mimics:
    #     .cfi_startproc
    #     ret
    #     .cfi_endproc

    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m)

    b1 = add_code_block(bi, b"\xC3")

    add_edge(ir.cfg, b1, add_proxy_block(m), gtirb.EdgeType.Return)
    func = add_function_object(m, "func", b1, {b1})

    m.aux_data["cfiDirectives"].data[gtirb.Offset(b1, 0)] = [
        (".cfi_startproc", [], NULL_UUID),
    ]
    m.aux_data["cfiDirectives"].data[gtirb.Offset(b1, 1)] = [
        (".cfi_endproc", [], NULL_UUID),
    ]

    modify_cache = gtirb_rewriting._modify.ModifyCache(
        m, [func], gtirb_rewriting._modify.ReturnEdgeCache(ir.cfg)
    )
    split_start, split_end, fallthrough = gtirb_rewriting._modify.split_block(
        modify_cache, b1, 0
    )

    assert split_start is b1
    assert split_start.offset == 0
    assert split_start.size == 0
    assert split_end.offset == 0
    assert split_end.size == 1

    assert m.aux_data["cfiDirectives"].data == {
        gtirb.Offset(split_start, 0): [
            (".cfi_startproc", [], NULL_UUID),
        ],
        gtirb.Offset(split_end, 1): [
            (".cfi_endproc", [], NULL_UUID),
        ],
    }


def test_split_blocks_proc_end():
    """
    Test that splitting a block at the end puts the .cfi_end_proc in the
    second block.
    """

    # This mimics:
    #     .cfi_startproc
    #     ret
    #     .cfi_undefined 0
    #     .cfi_endproc

    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m)

    b1 = add_code_block(bi, b"\xC3")

    add_edge(ir.cfg, b1, add_proxy_block(m), gtirb.EdgeType.Return)
    func = add_function_object(m, "func", b1, {b1})

    m.aux_data["cfiDirectives"].data[gtirb.Offset(b1, 0)] = [
        (".cfi_startproc", [], NULL_UUID),
    ]
    m.aux_data["cfiDirectives"].data[gtirb.Offset(b1, 1)] = [
        (".cfi_undefined", [0], NULL_UUID),
        (".cfi_endproc", [], NULL_UUID),
    ]

    modify_cache = gtirb_rewriting._modify.ModifyCache(
        m, [func], gtirb_rewriting._modify.ReturnEdgeCache(ir.cfg)
    )
    split_start, split_end, fallthrough = gtirb_rewriting._modify.split_block(
        modify_cache, b1, b1.size
    )

    assert split_start is b1
    assert split_start.offset == 0
    assert split_start.size == 1
    assert split_end.offset == 1
    assert split_end.size == 0
    assert fallthrough is None

    assert m.aux_data["cfiDirectives"].data == {
        gtirb.Offset(split_start, 0): [
            (".cfi_startproc", [], NULL_UUID),
        ],
        gtirb.Offset(split_start, 1): [
            (".cfi_undefined", [0], NULL_UUID),
        ],
        gtirb.Offset(split_end, 0): [
            (".cfi_endproc", [], NULL_UUID),
        ],
    }


def test_join_blocks_procs_end():
    """
    Test that CFI directives are joined in the correct order when the first
    block is empty.
    """
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m)

    b1 = add_code_block(bi, b"")
    b2 = add_code_block(bi, b"\xC3")

    add_edge(ir.cfg, b1, b2, gtirb.EdgeType.Fallthrough)
    add_edge(ir.cfg, b2, add_proxy_block(m), gtirb.EdgeType.Return)
    func = add_function_object(m, "func", b1, {b1, b2})

    m.aux_data["cfiDirectives"].data[gtirb.Offset(b1, 0)] = [
        (".cfi_startproc", [], NULL_UUID),
    ]
    m.aux_data["cfiDirectives"].data[gtirb.Offset(b2, 0)] = [
        (".cfi_undefined", [0], NULL_UUID),
    ]
    m.aux_data["cfiDirectives"].data[gtirb.Offset(b2, 1)] = [
        (".cfi_endproc", [], NULL_UUID),
    ]

    modify_cache = gtirb_rewriting._modify.ModifyCache(
        m, [func], gtirb_rewriting._modify.ReturnEdgeCache(ir.cfg)
    )
    assert gtirb_rewriting._modify.are_joinable(modify_cache, b1, b2)

    joined_block = gtirb_rewriting._modify.join_blocks(modify_cache, b1, b2)
    assert joined_block is b1

    assert m.aux_data["cfiDirectives"].data == {
        gtirb.Offset(b1, 0): [
            (".cfi_startproc", [], NULL_UUID),
            (".cfi_undefined", [0], NULL_UUID),
        ],
        gtirb.Offset(b1, 1): [
            (".cfi_endproc", [], NULL_UUID),
        ],
    }


def test_join_blocks_procs_begin():
    """
    Test that CFI directives are joined in the correct order when the second
    block is empty.
    """
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m)

    b1 = add_code_block(bi, b"\xC3")
    b2 = add_code_block(bi, b"")

    add_edge(ir.cfg, b1, add_proxy_block(m), gtirb.EdgeType.Return)
    add_edge(ir.cfg, b1, b2, gtirb.EdgeType.Fallthrough)
    func = add_function_object(m, "func", b1, {b1, b2})

    m.aux_data["cfiDirectives"].data[gtirb.Offset(b1, 0)] = [
        (".cfi_startproc", [], NULL_UUID),
    ]
    m.aux_data["cfiDirectives"].data[gtirb.Offset(b1, 1)] = [
        (".cfi_undefined", [0], NULL_UUID),
    ]
    m.aux_data["cfiDirectives"].data[gtirb.Offset(b2, 0)] = [
        (".cfi_endproc", [], NULL_UUID),
    ]

    modify_cache = gtirb_rewriting._modify.ModifyCache(
        m, [func], gtirb_rewriting._modify.ReturnEdgeCache(ir.cfg)
    )
    assert gtirb_rewriting._modify.are_joinable(modify_cache, b1, b2)

    joined_block = gtirb_rewriting._modify.join_blocks(modify_cache, b1, b2)
    assert joined_block is b1

    assert m.aux_data["cfiDirectives"].data == {
        gtirb.Offset(b1, 0): [
            (".cfi_startproc", [], NULL_UUID),
        ],
        gtirb.Offset(b1, 1): [
            (".cfi_undefined", [0], NULL_UUID),
            (".cfi_endproc", [], NULL_UUID),
        ],
    }


def test_join_blocks_simple():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m)

    b1 = add_code_block(bi, b"\x57")
    b2 = add_code_block(bi, b"\x58")
    b3 = add_code_block(bi, b"\x59")
    add_edge(ir.cfg, b1, b2, gtirb.EdgeType.Fallthrough)
    add_edge(ir.cfg, b2, b3, gtirb.EdgeType.Branch)
    func = add_function_object(m, "func", b1, {b2})

    m.aux_data["comments"].data[gtirb.Offset(b1, 0)] = "0"
    m.aux_data["comments"].data[gtirb.Offset(b2, 0)] = "1"

    m.aux_data["cfiDirectives"].data[gtirb.Offset(b1, 0)] = [
        (".cfi_startproc", [], NULL_UUID),
    ]
    m.aux_data["cfiDirectives"].data[gtirb.Offset(b1, 1)] = [
        (".cfi_undefined", [0], NULL_UUID),
    ]
    m.aux_data["cfiDirectives"].data[gtirb.Offset(b2, 0)] = [
        (".cfi_undefined", [1], NULL_UUID),
    ]

    modify_cache = gtirb_rewriting._modify.ModifyCache(
        m, [func], gtirb_rewriting._modify.ReturnEdgeCache(ir.cfg)
    )
    assert gtirb_rewriting._modify.are_joinable(modify_cache, b1, b2)

    joined_block = gtirb_rewriting._modify.join_blocks(modify_cache, b1, b2)

    assert bi.blocks == {b1, b3}
    assert joined_block is b1
    assert joined_block.offset == 0
    assert joined_block.size == 2

    assert m.aux_data["comments"].data == {
        gtirb.Offset(b1, 0): "0",
        gtirb.Offset(b1, 1): "1",
    }

    assert m.aux_data["cfiDirectives"].data == {
        gtirb.Offset(b1, 0): [
            (".cfi_startproc", [], NULL_UUID),
        ],
        gtirb.Offset(b1, 1): [
            (".cfi_undefined", [0], NULL_UUID),
            (".cfi_undefined", [1], NULL_UUID),
        ],
    }

    assert set(ir.cfg) == {
        gtirb.Edge(b1, b3, gtirb.EdgeLabel(gtirb.EdgeType.Branch)),
    }

    assert m.aux_data["functionEntries"].data == {func.uuid: {b1}}
    assert m.aux_data["functionBlocks"].data == {func.uuid: {b1}}


def test_join_blocks_zero_sized():
    """
    Test that joining into a zero-sized block is always allowed, even if it
    normally wouldn't qualify.
    """
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m)

    b0 = add_code_block(bi, b"\xE8\x00")
    b1 = add_code_block(bi, b"")
    b2 = add_code_block(bi, b"\xE8\x00")
    b3 = add_code_block(bi, b"\x59")
    add_edge(ir.cfg, b0, b2, gtirb.EdgeType.Branch)
    add_edge(ir.cfg, b1, b2, gtirb.EdgeType.Fallthrough)
    add_edge(ir.cfg, b2, b3, gtirb.EdgeType.Branch)
    b2_symbol = add_symbol(m, "b2", b2)
    func = add_function_object(m, "func", b0, {b1, b2, b3})

    m.aux_data["alignment"].data[b2] = 4

    modify_cache = gtirb_rewriting._modify.ModifyCache(
        m, [func], gtirb_rewriting._modify.ReturnEdgeCache(ir.cfg)
    )
    assert gtirb_rewriting._modify.are_joinable(modify_cache, b1, b2)
    joined_block = gtirb_rewriting._modify.join_blocks(modify_cache, b1, b2)

    assert joined_block is b1
    assert joined_block.offset == 2
    assert joined_block.size == 2

    assert b2_symbol.referent == b1
    assert not b2_symbol.at_end

    assert set(ir.cfg) == {
        gtirb.Edge(b0, b1, gtirb.EdgeLabel(gtirb.EdgeType.Branch)),
        gtirb.Edge(b1, b3, gtirb.EdgeLabel(gtirb.EdgeType.Branch)),
    }

    assert m.aux_data["alignment"].data == {b1: 4}


def test_unjoinable_due_to_symbol():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m)

    b1 = add_code_block(bi, b"\x57")
    b2 = add_code_block(bi, b"\x58")
    add_symbol(m, "b2", b2)
    func = add_function_object(m, "func", b1, {b2})

    modify_cache = gtirb_rewriting._modify.ModifyCache(
        m, [func], gtirb_rewriting._modify.ReturnEdgeCache(ir.cfg)
    )
    assert not gtirb_rewriting._modify.are_joinable(modify_cache, b1, b2)


def test_unjoinable_due_to_edges():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m)

    b1 = add_code_block(bi, b"\x57")
    b2 = add_code_block(bi, b"\x58")
    add_edge(ir.cfg, b1, b2, gtirb.EdgeType.Return)
    func = add_function_object(m, "func", b1, {b2})

    modify_cache = gtirb_rewriting._modify.ModifyCache(
        m, [func], gtirb_rewriting._modify.ReturnEdgeCache(ir.cfg)
    )
    assert not gtirb_rewriting._modify.are_joinable(modify_cache, b1, b2)


def test_unjoinable_due_to_different_type():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m)

    b1 = add_code_block(bi, b"\x57")
    b2 = add_data_block(bi, b"\x58")
    func = add_function_object(m, "func", b1)

    modify_cache = gtirb_rewriting._modify.ModifyCache(
        m, [func], gtirb_rewriting._modify.ReturnEdgeCache(ir.cfg)
    )
    assert not gtirb_rewriting._modify.are_joinable(modify_cache, b1, b2)


def test_unjoinable_due_to_alignment():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m)

    b1 = add_code_block(bi, b"\x57")
    b2 = add_code_block(bi, b"\x58")
    func = add_function_object(m, "func", b1, {b2})

    m.aux_data["alignment"].data[b2] = 8

    modify_cache = gtirb_rewriting._modify.ModifyCache(
        m, [func], gtirb_rewriting._modify.ReturnEdgeCache(ir.cfg)
    )
    assert not gtirb_rewriting._modify.are_joinable(modify_cache, b1, b2)


def test_remove_blocks_simple():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m)

    b1 = add_code_block(bi, b"\x57")
    b2 = add_code_block(bi, b"\x58")
    b3 = add_code_block(bi, b"\x59")
    add_edge(ir.cfg, b1, b2, gtirb.EdgeType.Fallthrough)
    add_edge(ir.cfg, b2, b3, gtirb.EdgeType.Branch)
    b2_sym = add_symbol(m, "b2", b2)
    func = add_function_object(m, "func", b1, {b2, b3})

    m.aux_data["comments"].data[gtirb.Offset(b1, 0)] = "0"
    m.aux_data["comments"].data[gtirb.Offset(b2, 0)] = "1"
    m.aux_data["comments"].data[gtirb.Offset(b3, 0)] = "2"

    m.aux_data["cfiDirectives"].data = {
        gtirb.Offset(b1, 0): [
            (".cfi_startproc", [], NULL_UUID),
        ],
        gtirb.Offset(b1, 1): [
            (".cfi_remember_state", [], NULL_UUID),
        ],
        gtirb.Offset(b2, 1): [
            (".cfi_undef", [0], NULL_UUID),
            (".cfi_restore_state", [], NULL_UUID),
        ],
        gtirb.Offset(b3, 1): [
            (".cfi_endproc", [], NULL_UUID),
        ],
    }

    modify_cache = gtirb_rewriting._modify.ModifyCache(
        m, [func], gtirb_rewriting._modify.ReturnEdgeCache(ir.cfg)
    )
    gtirb_rewriting._modify.edit._remove_block(modify_cache, b2, b3)

    # _remove_block doesn't actually update the byte interval contents
    assert bi.blocks == {b1, b3}
    assert bi.size == 3
    assert b1.offset == 0
    assert b1.size == 1
    assert b3.offset == 2
    assert b3.size == 1

    assert b2_sym.referent is b3

    assert m.aux_data["comments"].data == {
        gtirb.Offset(b1, 0): "0",
        gtirb.Offset(b3, 0): "2",
    }

    assert m.aux_data["cfiDirectives"].data == {
        gtirb.Offset(b1, 0): [
            (".cfi_startproc", [], NULL_UUID),
        ],
        gtirb.Offset(b1, 1): [
            (".cfi_remember_state", [], NULL_UUID),
        ],
        gtirb.Offset(b3, 0): [
            (".cfi_restore_state", [], NULL_UUID),
        ],
        gtirb.Offset(b3, 1): [
            (".cfi_endproc", [], NULL_UUID),
        ],
    }

    assert set(ir.cfg) == {
        gtirb.Edge(b1, b3, gtirb.EdgeLabel(gtirb.EdgeType.Fallthrough)),
    }

    assert m.aux_data["functionEntries"].data == {func.uuid: {b1}}
    assert m.aux_data["functionBlocks"].data == {func.uuid: {b1, b3}}


def test_remove_blocks_invalid():
    """
    Test that we reject deleting a block where the CFI directives would be
    lost.
    """
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m)

    b1 = add_code_block(bi, b"\x90")
    b2 = add_code_block(bi, b"\xC3")
    add_edge(ir.cfg, b1, b2, gtirb.EdgeType.Fallthrough)
    func = add_function_object(m, "func", b1, {b2})

    m.aux_data["cfiDirectives"].data = {
        gtirb.Offset(b1, 0): [
            (".cfi_startproc", [], NULL_UUID),
        ],
        gtirb.Offset(b2, 1): [
            (".cfi_endproc", [], NULL_UUID),
        ],
    }

    modify_cache = gtirb_rewriting._modify.ModifyCache(
        m, [func], gtirb_rewriting._modify.ReturnEdgeCache(ir.cfg)
    )
    with pytest.raises(gtirb_rewriting.AmbiguousIRError):
        gtirb_rewriting._modify.edit._remove_block(modify_cache, b2, None)


def test_edit_byte_interval_simple():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m)

    sym = add_symbol(m, "sym")

    b1 = add_code_block(bi, b"\xE8\x00", {1: gtirb.SymAddrConst(0, sym)})
    b2 = add_code_block(bi, b"")
    b3 = add_code_block(bi, b"")
    b4 = add_code_block(bi, b"\xE8\x00", {1: gtirb.SymAddrConst(0, sym)})
    m.aux_data["comments"].data[gtirb.Offset(bi, 0)] = "0"
    m.aux_data["comments"].data[gtirb.Offset(bi, 2)] = "2"

    gtirb_rewriting._modify.edit_byte_interval(bi, 2, 0, b"\x90\x90", {b2})

    assert bi.contents == b"\xE8\x00\x90\x90\xE8\x00"
    assert bi.size == 6

    assert b1.offset == 0
    assert b1.size == 2
    assert b2.offset == 2
    assert b2.size == 0
    assert b3.offset == 4
    assert b3.size == 0
    assert b4.offset == 4
    assert b4.size == 2

    assert bi.symbolic_expressions == {
        1: gtirb.SymAddrConst(0, sym),
        5: gtirb.SymAddrConst(0, sym),
    }

    assert m.aux_data["comments"].data == {
        gtirb.Offset(bi, 0): "0",
        gtirb.Offset(bi, 4): "2",
    }


def test_edit_byte_interval_replace():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m)

    sym1 = add_symbol(m, "sym1")
    sym2 = add_symbol(m, "sym2")

    b1 = add_code_block(bi, b"\xE8\x00", {1: gtirb.SymAddrConst(0, sym1)})
    b2 = add_code_block(bi, b"\xEB\x00", {1: gtirb.SymAddrConst(0, sym2)})
    m.aux_data["comments"].data[gtirb.Offset(bi, 0)] = "0"
    m.aux_data["comments"].data[gtirb.Offset(bi, 2)] = "2"

    gtirb_rewriting._modify.edit_byte_interval(bi, 0, 2, b"", {b1})

    assert bi.contents == b"\xEB\x00"
    assert bi.size == 2

    assert b1.offset == 0
    assert b1.size == 2
    assert b2.offset == 0
    assert b2.size == 2

    assert bi.symbolic_expressions == {
        1: gtirb.SymAddrConst(0, sym2),
    }

    assert m.aux_data["comments"].data == {
        gtirb.Offset(bi, 0): "2",
    }
