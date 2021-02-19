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
import uuid

import gtirb
import gtirb_functions
import gtirb_rewriting
import pytest


@gtirb_rewriting.patch_constraints()
def dummy_patch(insertion_ctx):
    return """
    nop
    nop
    # This forces the start of a new block.
    .L_blah:
    """


def test_multiple_insertions():
    ir = gtirb.IR()
    m = gtirb.Module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
        name="test",
    )
    m.ir = ir
    s = gtirb.Section(name=".text")
    s.module = m
    bi = gtirb.ByteInterval(
        contents=b"\x50\x51\x52\x53\x54\x55\x56\x57", address=0x1000
    )
    bi.section = s
    b = gtirb.CodeBlock(offset=0, size=bi.size)
    b.byte_interval = bi
    sym = gtirb.Symbol(name="hi", payload=b)
    m.symbols.add(sym)
    func_uuid = uuid.uuid4()
    m.aux_data["functionNames"] = gtirb.AuxData(
        type_name="mapping<uuid,uuid>", data={func_uuid: sym}
    )
    m.aux_data["functionEntries"] = gtirb.AuxData(
        type_name="mapping<uuid,set<uuid>>", data={func_uuid: {b}}
    )
    m.aux_data["functionBlocks"] = gtirb.AuxData(
        type_name="mapping<uuid,set<uuid>>", data={func_uuid: {b}}
    )

    functions = gtirb_functions.Function.build_functions(m)
    assert len(functions) == 1

    ctx = gtirb_rewriting.RewritingContext(m, functions)
    ctx.insert_at(
        functions[0], b, 0, gtirb_rewriting.Patch.from_function(dummy_patch)
    )
    ctx.insert_at(
        functions[0], b, 7, gtirb_rewriting.Patch.from_function(dummy_patch)
    )
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

    ir = gtirb.IR()
    m = gtirb.Module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
        name="test",
    )
    m.ir = ir
    s = gtirb.Section(name=".text")
    s.module = m
    bi = gtirb.ByteInterval(
        contents=b"\x50\x51\x52\x53\x54\x55\x56\x57", address=0x1000
    )
    bi.section = s
    b = gtirb.CodeBlock(offset=0, size=bi.size)
    b.byte_interval = bi
    sym = gtirb.Symbol(name="hi", payload=b)
    m.symbols.add(sym)
    func_uuid = uuid.uuid4()
    m.aux_data["functionNames"] = gtirb.AuxData(
        type_name="mapping<uuid,uuid>", data={func_uuid: sym}
    )
    m.aux_data["functionEntries"] = gtirb.AuxData(
        type_name="mapping<uuid,set<uuid>>", data={func_uuid: {b}}
    )
    m.aux_data["functionBlocks"] = gtirb.AuxData(
        type_name="mapping<uuid,set<uuid>>", data={func_uuid: {b}}
    )

    functions = gtirb_functions.Function.build_functions(m)
    assert len(functions) == 1

    ctx = gtirb_rewriting.RewritingContext(m, functions)
    ctx.replace_at(
        functions[0], b, 0, 2, gtirb_rewriting.Patch.from_function(nop_patch)
    )
    ctx.replace_at(
        functions[0], b, 3, 4, gtirb_rewriting.Patch.from_function(nop_patch)
    )
    ctx.insert_at(
        functions[0], b, 8, gtirb_rewriting.Patch.from_function(nop_patch)
    )
    ctx.apply()

    assert bi.contents == b"\x90\x52\x90\x57\x90"
    assert sum(b.size for b in bi.blocks) == 5


def test_added_function_blocks():
    ir = gtirb.IR()
    m = gtirb.Module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
        name="test",
    )
    m.ir = ir
    s = gtirb.Section(name=".text")
    s.module = m
    bi = gtirb.ByteInterval(
        contents=b"\x50\x51\x52\x53\x54\x55\x56\x57", address=0x1000
    )
    bi.section = s
    b = gtirb.CodeBlock(offset=0, size=bi.size)
    b.byte_interval = bi
    sym = gtirb.Symbol(name="hi", payload=b)
    sym.module = m

    func_uuid = uuid.uuid4()
    m.aux_data["functionNames"] = gtirb.AuxData(
        type_name="mapping<uuid,uuid>", data={func_uuid: sym}
    )
    m.aux_data["functionEntries"] = gtirb.AuxData(
        type_name="mapping<uuid,set<uuid>>", data={func_uuid: {b}}
    )
    m.aux_data["functionBlocks"] = gtirb.AuxData(
        type_name="mapping<uuid,set<uuid>>", data={func_uuid: {b}}
    )

    functions = gtirb_functions.Function.build_functions(m)
    assert len(functions) == 1
    assert len(functions[0].get_all_blocks()) == 1

    ctx = gtirb_rewriting.RewritingContext(m, functions)
    ctx.insert_at(
        functions[0], b, 7, gtirb_rewriting.Patch.from_function(dummy_patch)
    )
    ctx.apply()

    assert len(m.aux_data["functionBlocks"].data[func_uuid]) == 3
    assert (
        sum(b.size for b in m.aux_data["functionBlocks"].data[func_uuid])
        == bi.size
        == 10
    )


def test_expensive_assertions():
    ir = gtirb.IR()
    m = gtirb.Module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
        name="test",
    )
    m.ir = ir
    s = gtirb.Section(name=".text")
    s.module = m
    bi = gtirb.ByteInterval(
        contents=b"\xE8\x00\x00\x00\x00\xE8\x00\x00\x00\x00", address=0x1000
    )
    bi.section = s
    b = gtirb.CodeBlock(offset=0, size=bi.size)
    b.byte_interval = bi
    sym = gtirb.Symbol(name="hi", payload=b)
    sym.module = m

    func_uuid = uuid.uuid4()
    m.aux_data["functionNames"] = gtirb.AuxData(
        type_name="mapping<uuid,uuid>", data={func_uuid: sym}
    )
    m.aux_data["functionEntries"] = gtirb.AuxData(
        type_name="mapping<uuid,set<uuid>>", data={func_uuid: {b}}
    )
    m.aux_data["functionBlocks"] = gtirb.AuxData(
        type_name="mapping<uuid,set<uuid>>", data={func_uuid: {b}}
    )

    functions = gtirb_functions.Function.build_functions(m)
    assert len(functions) == 1
    assert len(functions[0].get_all_blocks()) == 1

    ctx = gtirb_rewriting.RewritingContext(
        m, functions, expensive_assertions=True
    )
    ctx.insert_at(
        functions[0], b, 0, gtirb_rewriting.Patch.from_function(dummy_patch)
    )
    ctx.insert_at(
        functions[0], b, 5, gtirb_rewriting.Patch.from_function(dummy_patch)
    )
    # Offset is not on an instruction boundary
    with pytest.raises(AssertionError):
        ctx.insert_at(
            functions[0],
            b,
            1,
            gtirb_rewriting.Patch.from_function(dummy_patch),
        )
    # Offset is not on an instruction boundary
    with pytest.raises(AssertionError):
        ctx.replace_at(
            functions[0],
            b,
            1,
            0,
            gtirb_rewriting.Patch.from_function(dummy_patch),
        )
    # Offset is valid, but end position isn't on an instruction boundary
    with pytest.raises(AssertionError):
        ctx.replace_at(
            functions[0],
            b,
            0,
            6,
            gtirb_rewriting.Patch.from_function(dummy_patch),
        )
    # Range extends out of the block's bounds
    with pytest.raises(AssertionError):
        ctx.replace_at(
            functions[0],
            b,
            0,
            60,
            gtirb_rewriting.Patch.from_function(dummy_patch),
        )
    ctx.apply()


def test_conflicting_insertion_replacement():
    ir = gtirb.IR()
    m = gtirb.Module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
        name="test",
    )
    m.ir = ir
    s = gtirb.Section(name=".text")
    s.module = m
    bi = gtirb.ByteInterval(
        contents=b"\x09\x90\x90\x90\x90\x90\x90\x90", address=0x1000
    )
    bi.section = s
    b = gtirb.CodeBlock(offset=0, size=bi.size)
    b.byte_interval = bi
    sym = gtirb.Symbol(name="hi", payload=b)
    sym.module = m

    func_uuid = uuid.uuid4()
    m.aux_data["functionNames"] = gtirb.AuxData(
        type_name="mapping<uuid,uuid>", data={func_uuid: sym}
    )
    m.aux_data["functionEntries"] = gtirb.AuxData(
        type_name="mapping<uuid,set<uuid>>", data={func_uuid: {b}}
    )
    m.aux_data["functionBlocks"] = gtirb.AuxData(
        type_name="mapping<uuid,set<uuid>>", data={func_uuid: {b}}
    )

    functions = gtirb_functions.Function.build_functions(m)
    assert len(functions) == 1
    assert len(functions[0].get_all_blocks()) == 1

    ctx = gtirb_rewriting.RewritingContext(m, functions)
    ctx.insert_at(
        functions[0], b, 7, gtirb_rewriting.Patch.from_function(dummy_patch)
    )
    ctx.replace_at(
        functions[0],
        b,
        0,
        bi.size,
        gtirb_rewriting.Patch.from_function(dummy_patch),
    )
    with pytest.raises(AssertionError):
        ctx.apply()


def test_inserting_function_and_call():
    ir = gtirb.IR()
    m = gtirb.Module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
        name="test",
    )
    m.ir = ir
    s = gtirb.Section(name=".text")
    s.module = m
    bi = gtirb.ByteInterval(contents=b"\x90", address=0x1000)
    bi.section = s
    main_block = gtirb.CodeBlock(offset=0, size=bi.size)
    main_block.byte_interval = bi
    main_sym = gtirb.Symbol(name="main", payload=main_block)
    m.symbols.add(main_sym)
    func_uuid = uuid.uuid4()
    m.aux_data["functionNames"] = gtirb.AuxData(
        type_name="mapping<uuid,uuid>", data={func_uuid: main_sym}
    )
    m.aux_data["functionEntries"] = gtirb.AuxData(
        type_name="mapping<uuid,set<uuid>>", data={func_uuid: {main_block}}
    )
    m.aux_data["functionBlocks"] = gtirb.AuxData(
        type_name="mapping<uuid,set<uuid>>", data={func_uuid: {main_block}}
    )
    m.aux_data["binaryType"] = gtirb.AuxData(
        type_name="vector<string>", data=["DYN"]
    )

    functions = gtirb_functions.Function.build_functions(m)
    assert len(functions) == 1

    @gtirb_rewriting.patch_constraints()
    def function_patch(ctx):
        return "mov $42, %eax; ret"

    @gtirb_rewriting.patch_constraints()
    def call_patch(ctx):
        return "call target"

    ctx = gtirb_rewriting.RewritingContext(m, functions)
    target_sym = ctx.register_insert_function(
        "target", gtirb_rewriting.Patch.from_function(function_patch)
    )
    ctx.insert_at(
        functions[0],
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


def test_inserting_function_calling_inserted_function():
    ir = gtirb.IR()
    m = gtirb.Module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
        name="test",
    )
    m.ir = ir
    s = gtirb.Section(name=".text")
    s.module = m
    bi = gtirb.ByteInterval(contents=b"", address=0x1000)
    bi.section = s
    m.aux_data["functionNames"] = gtirb.AuxData(
        type_name="mapping<uuid,uuid>", data={}
    )
    m.aux_data["functionEntries"] = gtirb.AuxData(
        type_name="mapping<uuid,set<uuid>>", data={}
    )
    m.aux_data["functionBlocks"] = gtirb.AuxData(
        type_name="mapping<uuid,set<uuid>>", data={}
    )
    m.aux_data["binaryType"] = gtirb.AuxData(
        type_name="vector<string>", data=["DYN"]
    )

    @gtirb_rewriting.patch_constraints()
    def target_function_patch(ctx):
        return "mov $42, %eax; ret"

    @gtirb_rewriting.patch_constraints()
    def call_function_patch(ctx):
        return "call target; ud2"

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
