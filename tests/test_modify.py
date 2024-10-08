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

from typing import Dict, List, Set, Tuple

import gtirb
import more_itertools as mi
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
)
from helpers import add_function_object

import gtirb_rewriting
from gtirb_rewriting._auxdata import NULL_UUID


def test_return_cache():
    ir, m = create_test_module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
    )
    _, bi = add_text_section(m, address=0x1000)

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
    _, bi = add_text_section(m, address=0x1000)
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


@pytest.mark.parametrize("apply_first", [True, False])
@pytest.mark.parametrize(
    "names, targets, expected",
    [
        (
            # Retarget b1 -> start of b2, then b2 -> start of b3
            {"b1", "b2", "b3"},
            [("b1", "b2", False), ("b2", "b3", False)],
            {"b3": ({"b1", "b2", "b3"}, set())},
        ),
        (
            # Retarget b1 -> start of b2, then b1 -> start of b3
            {"b1", "b2", "b3"},
            [("b1", "b2", False), ("b1", "b2", False)],
            {
                "b2": ({"b1", "b2"}, set()),
                "b3": ({"b3"}, set()),
            },
        ),
        (
            # Retarget b1 -> end of b2, then b2 -> start of b3
            {"b1", "b2", "b3"},
            [("b1", "b2", True), ("b2", "b3", False)],
            {"b3": ({"b1", "b2", "b3"}, set())},
        ),
        (
            # Retarget b1 -> start of b2, then b2 -> end of b3
            {"b1", "b2", "b3"},
            [("b1", "b2", False), ("b2", "b3", True)],
            {"b3": ({"b3"}, {"b1", "b2"})},
        ),
        (
            # Retarget b2 -> end of b3, then b1 -> start of b2
            {"b1", "b2", "b3"},
            [("b2", "b3", True), ("b1", "b2", False)],
            {"b2": ({"b1"}, set()), "b3": ({"b3"}, {"b2"})},
        ),
        (
            # Retarget b1 and b2 -> start of b3, then b3 -> start of b4
            {"b1", "b2", "b3", "b4"},
            [("b1", "b3", False), ("b2", "b3", False), ("b3", "b4", False)],
            {"b4": ({"b1", "b2", "b3", "b4"}, set())},
        ),
    ],
)
def test_reference_cache(
    names: Set[str],
    targets: List[Tuple[str, str, bool]],
    expected: Dict[str, Tuple[Set[str], Set[str]]],
    apply_first: bool,
):
    """
    Test that the reference cache retargets references correctly.
    """
    _, m = create_test_module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
    )
    _, bi = add_text_section(m, address=0x1000)

    # Create the named blocks and assign each a symbol with the same name.
    blocks = {}
    for name in names:
        blocks[name] = add_data_block(bi, b"\x00")
        add_symbol(m, name, blocks[name])

    # Retarget the block references.
    cache = gtirb_rewriting._modify.ReferenceCache()
    for from_name, to_name, at_end in targets:
        cache.retarget_references(blocks[from_name], blocks[to_name], at_end)

    if apply_first:
        # Check that applying the cache updates block references.
        cache.apply()
        # E731: use a def instead of a lambda expression
        references = lambda block: block.references  # noqa: E731
    else:
        # Check that we retrieve the correct references from the cache.
        references = cache.get_references

    # Check that the final references are what we expect.
    for block_name, block in blocks.items():
        at_start_names, at_end_names = expected.get(block_name, (set(), set()))
        at_start, at_end = mi.partition(lambda s: s.at_end, references(block))
        assert {sym.name for sym in at_start} == at_start_names, block_name
        assert {sym.name for sym in at_end} == at_end_names, block_name


def test_reference_cache_get_referent():
    """
    Test that get_referent works on both direct and indirect references.
    """
    _, m = create_test_module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
    )
    _, bi = add_text_section(m, address=0x1000)

    b1 = add_data_block(bi, b"\x00")
    b2 = add_data_block(bi, b"\x00")
    b3 = add_data_block(bi, b"\x00")
    b4 = add_data_block(bi, b"\x00")
    s1 = add_symbol(m, "b1", b1)
    s2 = add_symbol(m, "b2", b2)
    s3 = add_symbol(m, "b3", b3)
    add_symbol(m, "b4", b4)

    cache = gtirb_rewriting._modify.ReferenceCache()

    # Make s1 an indirect reference to b2; s2 remains a direct reference to b2.

    cache.retarget_references(b1, b2, False)

    for sym in [s1, s2]:
        assert cache.get_referent(sym) == b2
        assert sym.referent == b2
        assert not sym.at_end

    # Make s1, s2, and s3 indirect reference to b4. Check that s1 and s2 point
    # to the correct end of b4 after indirectly pointing to the other end of b3

    cache.retarget_references(b2, b3, False)
    cache.retarget_references(b3, b4, True)

    for sym in [s1, s2, s3]:
        assert cache.get_referent(sym) == b4
        assert sym.referent == b4
        assert sym.at_end


def test_reference_cache_set_referent():
    """
    Test that set_referent reassigns in/direct references correctly.
    """
    _, m = create_test_module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
    )
    _, bi = add_text_section(m, address=0x1000)

    b1 = add_data_block(bi, b"\x00")
    b2 = add_data_block(bi, b"\x00")
    b3 = add_data_block(bi, b"\x00")
    s1 = add_symbol(m, "b1", b1)
    add_symbol(m, "b2", b2)
    add_symbol(m, "b3", b3)

    cache = gtirb_rewriting._modify.ReferenceCache()

    # Make s1 an indirect reference to b2.

    cache.retarget_references(b1, b2, False)

    # Reassign s1 an indirect reference to b3.

    cache.set_referent(s1, b3, True)

    assert s1.referent == b3
    assert s1.at_end

    # Reassigning b2's references (just s2 now) to b1 does not affect s1.

    cache.retarget_references(b2, b1, False)

    assert s1.referent == b3
    assert s1.at_end

    # Reassign s1 (currently a direct reference) to b1.

    cache.set_referent(s1, b1, False)

    assert s1.referent == b1
    assert not s1.at_end


def test_reference_cache_contextmanager():
    """
    Test that exiting the ReferenceCache context restores direct references.
    """
    _, m = create_test_module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
    )
    _, bi = add_text_section(m, address=0x1000)

    b1 = add_data_block(bi, b"\x00")
    b2 = add_data_block(bi, b"\x00")
    b3 = add_data_block(bi, b"\x00")
    add_symbol(m, "b1", b1)
    add_symbol(m, "b2", b2)
    add_symbol(m, "b3", b3)

    # Check direct references are updated after exiting normally.

    with gtirb_rewriting._modify.ReferenceCache() as cache:
        cache.retarget_references(b1, b2, False)
    assert {sym.name for sym in b2.references} == {"b1", "b2"}

    # Check direct references are updated after exiting via exception.

    with pytest.raises(ZeroDivisionError):
        with gtirb_rewriting._modify.ReferenceCache() as cache:
            cache.retarget_references(b2, b3, False)
            raise ZeroDivisionError()
    assert {sym.name for sym in b3.references} == {"b1", "b2", "b3"}


def test_modify_cache():
    ir, m = create_test_module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
    )
    _, bi = add_text_section(m, address=0x1000)

    # This mimics:
    #  ret
    #  ud2
    b1 = add_code_block(bi, b"\xC3")
    b2 = add_code_block(bi, b"\x0F\x0B")
    func = add_function_object(m, "func", b1)

    with gtirb_rewriting._modify.make_modify_cache(m, [func]) as modify_cache:
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
    _, bi = add_text_section(m, address=0x1000)

    b1 = add_code_block(bi, b"\x90\xC3")
    b2 = add_code_block(bi, b"\x90")
    begin_sym = gtirb.Symbol("begin_sym", payload=b1, at_end=False, module=m)
    end_sym = gtirb.Symbol("end_sym", payload=b1, at_end=True, module=m)

    add_edge(ir.cfg, b1, b2, gtirb.EdgeType.Fallthrough)
    func = add_function_object(m, begin_sym, b1)

    m.aux_data["comments"].data[gtirb.Offset(b1, 0)] = "0"
    m.aux_data["comments"].data[gtirb.Offset(b1, 1)] = "1"

    with gtirb_rewriting._modify.make_modify_cache(m, [func]) as modify_cache:
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
    _, bi = add_text_section(m, address=0x1000)

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

    with gtirb_rewriting._modify.make_modify_cache(m, [func]) as modify_cache:
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
    _, bi = add_text_section(m, address=0x1000)

    func1_b1 = add_code_block(bi, b"\xC3")
    func2_b1 = add_code_block(bi, b"\xE8\x00\x00\x00\x00")
    func2_b2 = add_code_block(bi, b"\x0F\x0B")
    func1 = add_function_object(m, "func1", func1_b1)
    func2 = add_function_object(m, "func2", func2_b1, {func2_b2})

    add_edge(ir.cfg, func1_b1, func2_b2, gtirb.EdgeType.Return)
    add_edge(ir.cfg, func2_b1, func1_b1, gtirb.EdgeType.Call)
    add_edge(ir.cfg, func2_b1, func2_b2, gtirb.EdgeType.Fallthrough)

    with gtirb_rewriting._modify.make_modify_cache(
        m, [func1, func2]
    ) as modify_cache:
        (
            split_start,
            split_end,
            fallthrough,
        ) = gtirb_rewriting._modify.split_block(
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
    _, bi = add_text_section(m, address=0x1000)

    b1 = add_code_block(bi, b"\xEB\x00")
    b2 = add_code_block(bi, b"\x90")
    add_symbol(m, "next", b2)

    add_edge(ir.cfg, b1, b2, gtirb.EdgeType.Branch)
    func = add_function_object(m, "func", b1, {b2})

    with gtirb_rewriting._modify.make_modify_cache(m, [func]) as modify_cache:
        (
            split_start,
            split_end,
            fallthrough,
        ) = gtirb_rewriting._modify.split_block(modify_cache, b1, b1.size)

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
    _, bi = add_text_section(m, address=0x1000)

    b1 = add_code_block(bi, b"\xC3")

    add_edge(ir.cfg, b1, add_proxy_block(m), gtirb.EdgeType.Return)
    func = add_function_object(m, "func", b1, {b1})

    m.aux_data["cfiDirectives"].data[gtirb.Offset(b1, 0)] = [
        (".cfi_startproc", [], NULL_UUID),
    ]
    m.aux_data["cfiDirectives"].data[gtirb.Offset(b1, 1)] = [
        (".cfi_endproc", [], NULL_UUID),
    ]

    with gtirb_rewriting._modify.make_modify_cache(m, [func]) as modify_cache:
        (
            split_start,
            split_end,
            fallthrough,
        ) = gtirb_rewriting._modify.split_block(modify_cache, b1, 0)

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
    _, bi = add_text_section(m, address=0x1000)

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

    with gtirb_rewriting._modify.make_modify_cache(m, [func]) as modify_cache:
        (
            split_start,
            split_end,
            fallthrough,
        ) = gtirb_rewriting._modify.split_block(modify_cache, b1, b1.size)

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
    _, bi = add_text_section(m, address=0x1000)

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

    with gtirb_rewriting._modify.make_modify_cache(m, [func]) as modify_cache:
        assert gtirb_rewriting._modify.are_joinable(modify_cache, b1, b2)

        joined_block = gtirb_rewriting._modify.join_blocks(
            modify_cache, b1, b2
        )
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
    _, bi = add_text_section(m, address=0x1000)

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

    with gtirb_rewriting._modify.make_modify_cache(m, [func]) as modify_cache:
        assert gtirb_rewriting._modify.are_joinable(modify_cache, b1, b2)

        joined_block = gtirb_rewriting._modify.join_blocks(
            modify_cache, b1, b2
        )
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
    _, bi = add_text_section(m, address=0x1000)

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

    with gtirb_rewriting._modify.make_modify_cache(m, [func]) as modify_cache:
        assert gtirb_rewriting._modify.are_joinable(modify_cache, b1, b2)

        joined_block = gtirb_rewriting._modify.join_blocks(
            modify_cache, b1, b2
        )

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
    _, bi = add_text_section(m, address=0x1000)

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

    with gtirb_rewriting._modify.make_modify_cache(m, [func]) as modify_cache:
        assert gtirb_rewriting._modify.are_joinable(modify_cache, b1, b2)
        joined_block = gtirb_rewriting._modify.join_blocks(
            modify_cache, b1, b2
        )

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
    _, bi = add_text_section(m, address=0x1000)

    b1 = add_code_block(bi, b"\x57")
    b2 = add_code_block(bi, b"\x58")
    add_symbol(m, "b2", b2)
    func = add_function_object(m, "func", b1, {b2})

    with gtirb_rewriting._modify.make_modify_cache(m, [func]) as modify_cache:
        assert not gtirb_rewriting._modify.are_joinable(modify_cache, b1, b2)


def test_unjoinable_due_to_edges():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    b1 = add_code_block(bi, b"\x57")
    b2 = add_code_block(bi, b"\x58")
    add_edge(ir.cfg, b1, b2, gtirb.EdgeType.Return)
    func = add_function_object(m, "func", b1, {b2})

    with gtirb_rewriting._modify.make_modify_cache(m, [func]) as modify_cache:
        assert not gtirb_rewriting._modify.are_joinable(modify_cache, b1, b2)


def test_unjoinable_due_to_different_type():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    b1 = add_code_block(bi, b"\x57")
    b2 = add_data_block(bi, b"\x58")
    func = add_function_object(m, "func", b1)

    with gtirb_rewriting._modify.make_modify_cache(m, [func]) as modify_cache:
        assert not gtirb_rewriting._modify.are_joinable(modify_cache, b1, b2)


def test_unjoinable_due_to_alignment():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    b1 = add_code_block(bi, b"\x57")
    b2 = add_code_block(bi, b"\x58")
    func = add_function_object(m, "func", b1, {b2})

    m.aux_data["alignment"].data[b2] = 8

    with gtirb_rewriting._modify.make_modify_cache(m, [func]) as modify_cache:
        assert not gtirb_rewriting._modify.are_joinable(modify_cache, b1, b2)


def test_remove_blocks_simple():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

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

    with gtirb_rewriting._modify.make_modify_cache(m, [func]) as modify_cache:
        gtirb_rewriting._modify.remove_block(modify_cache, b2, False)

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


def test_remove_blocks_with_important_cfi_directives():
    """
    Test that we reject deleting a block where the CFI directives would be
    lost.
    """
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

    b1 = add_code_block(bi, b"\x90")
    b2 = add_data_block(bi, b"\x90")
    b3 = add_code_block(bi, b"\xC3")
    func = add_function_object(m, "func", b1, {b3})

    m.aux_data["cfiDirectives"].data = {
        gtirb.Offset(b1, 0): [
            (".cfi_startproc", [], NULL_UUID),
        ],
        gtirb.Offset(b3, 1): [
            (".cfi_endproc", [], NULL_UUID),
        ],
    }

    with gtirb_rewriting._modify.make_modify_cache(m, [func]) as modify_cache:
        gtirb_rewriting._modify.remove_block(modify_cache, b3, False)

    assert bi.blocks == {b1, b2, b3}
    assert b3.size == 0

    assert m.aux_data["cfiDirectives"].data == {
        gtirb.Offset(b1, 0): [
            (".cfi_startproc", [], NULL_UUID),
        ],
        gtirb.Offset(b3, 0): [
            (".cfi_endproc", [], NULL_UUID),
        ],
    }


def test_remove_all_blocks_in_section_no_references():
    """
    Test removing all blocks in a section when none have references.
    """
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    s, bi = add_data_section(m, address=0x1000)

    # If no blocks have references, they are all removed.

    b1 = add_data_block(bi, b"\x01")
    b2 = add_data_block(bi, b"\x02")

    with gtirb_rewriting._modify.make_modify_cache(m, []) as modify_cache:
        gtirb_rewriting._modify.delete(modify_cache, b1, 0, b1.size)
        gtirb_rewriting._modify.delete(modify_cache, b2, 0, b2.size)

    assert s.size == 0
    assert sum(1 for _ in s.byte_blocks) == 0


def test_remove_all_blocks_in_section_direct_references():
    """
    Test removing all blocks in a section with direct references.
    """
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    s, bi = add_data_section(m, address=0x1000)

    # If the block has a reference, we leave an empty block to serve as the
    # referent.

    b1 = add_data_block(bi, b"\x02")
    foo = add_symbol(m, "foo", b1)

    with gtirb_rewriting._modify.make_modify_cache(m, []) as modify_cache:
        gtirb_rewriting._modify.delete(modify_cache, b1, 0, b1.size)

    assert s.size == 0
    assert sum(1 for _ in s.byte_blocks) == 1
    assert isinstance(foo.referent, gtirb.DataBlock)
    assert foo.referent.section is s


def test_remove_all_blocks_in_section_indirect_references():
    """
    Test removing all blocks in a section with indirect references.
    """
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    s, bi = add_data_section(m, address=0x1000)

    # We leave an empty block even if the referent is transferred to the final
    # block as an indirect referent.

    b1 = add_data_block(bi, b"\x03")
    b2 = add_data_block(bi, b"\x04")
    foo = add_symbol(m, "foo", b1)

    with gtirb_rewriting._modify.make_modify_cache(m, []) as modify_cache:
        gtirb_rewriting._modify.delete(modify_cache, b1, 0, b1.size)
        gtirb_rewriting._modify.delete(modify_cache, b2, 0, b2.size)

    assert s.size == 0
    assert sum(1 for _ in s.byte_blocks) == 1
    assert isinstance(foo.referent, gtirb.DataBlock)
    assert foo.referent.section is s


def test_edit_byte_interval_simple():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)

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
    _, bi = add_text_section(m, address=0x1000)

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
