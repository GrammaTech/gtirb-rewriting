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
        contents=b"\x00\x01\x02\x03\x04\x05\x06\x07", address=0x1000
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

    assert bi.contents == b"\x90\x90\x00\x01\x02\x03\x04\x05\x06\x90\x90\x07"

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
        contents=b"\x00\x01\x02\x03\x04\x05\x06\x07", address=0x1000
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

    assert len(functions[0].get_all_blocks()) == 3
    assert sum(b.size for b in functions[0].get_all_blocks()) == bi.size == 10
