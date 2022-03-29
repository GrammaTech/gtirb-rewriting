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


def test_split_byte_interval_no_tables():
    b1 = gtirb.CodeBlock(offset=1, size=2)
    b2 = gtirb.DataBlock(offset=4, size=2)
    s1 = gtirb.Symbol(name="s1")
    s2 = gtirb.Symbol(name="s2")
    bi = gtirb.ByteInterval(
        address=0x1000,
        blocks=[b1, b2],
        #              |- b1 -|    |- b2 -|
        contents=b"\x00\x01\x02\x03\x04\x05\x06\x07",
        #                  |s1|    |s2|        |s1-s2|
        size=16,
        symbolic_expressions={
            2: gtirb.SymAddrConst(symbol=s1, offset=0),
            4: gtirb.SymAddrConst(symbol=s2, offset=0),
            7: gtirb.SymAddrAddr(symbol1=s1, symbol2=s2, scale=1, offset=0),
        },
    )

    intervals = gtirb_rewriting.split_byte_interval(bi)
    assert len(intervals) == 2

    assert intervals[0] == bi
    assert intervals[0].address == 0x1000
    assert intervals[0].blocks == {b1}
    assert intervals[0].contents == b"\x00\x01\x02\x03"
    assert intervals[0].size == 4
    assert intervals[0].symbolic_expressions == {
        2: gtirb.SymAddrConst(symbol=s1, offset=0)
    }
    assert b1.offset == 1

    assert intervals[1] != bi
    assert intervals[1].address == 0x1004
    assert intervals[1].blocks == {b2}
    assert intervals[1].contents == b"\x04\x05\x06\x07"
    assert intervals[1].size == 12
    assert intervals[1].symbolic_expressions == {
        0: gtirb.SymAddrConst(symbol=s2, offset=0),
        3: gtirb.SymAddrAddr(symbol1=s1, symbol2=s2, scale=1, offset=0),
    }
    assert b2.offset == 0


def test_split_byte_interval_default_tables():
    b1 = gtirb.CodeBlock(offset=0, size=2)
    b2 = gtirb.CodeBlock(offset=2, size=2)
    bi1 = gtirb.ByteInterval(
        address=0x1000, blocks=[b1, b2], contents=b"\x00\x01\x02\x03"
    )
    bi2 = gtirb.ByteInterval(
        address=0x2000, blocks=[], contents=b"\xff\xff\xff\xff"
    )
    s = gtirb.Section(name=".test", byte_intervals=[bi1, bi2])
    m = gtirb.Module(name="test", sections=[s])

    m.aux_data["comments"] = gtirb.AuxData(
        type_name="mapping<Offset,string>",
        data={
            gtirb.Offset(element_id=bi1, displacement=0): "x",
            gtirb.Offset(element_id=bi1, displacement=3): "y",
            gtirb.Offset(element_id=bi2, displacement=2): "z",
        },
    )
    m.aux_data["padding"] = gtirb.AuxData(
        type_name="mapping<Offset,uint64_t>",
        data=gtirb_rewriting.OffsetMapping(
            {
                gtirb.Offset(element_id=bi1, displacement=1): 0,
                gtirb.Offset(element_id=bi1, displacement=2): 1,
                gtirb.Offset(element_id=bi2, displacement=0): 2,
            }
        ),
    )

    intervals = gtirb_rewriting.split_byte_interval(bi1)
    assert len(intervals) == 2

    assert intervals[0] == bi1
    assert intervals[0].address == 0x1000
    assert intervals[0].blocks == {b1}
    assert intervals[0].contents == b"\x00\x01"
    assert intervals[0].size == 2
    assert intervals[0].symbolic_expressions == {}

    assert intervals[1] != bi1
    assert intervals[1].address == 0x1002
    assert intervals[1].blocks == {b2}
    assert intervals[1].contents == b"\x02\x03"
    assert intervals[1].size == 2
    assert intervals[1].symbolic_expressions == {}

    comments = m.aux_data["comments"].data
    assert len(comments) == 3
    assert comments[gtirb.Offset(bi1, 0)] == "x"
    assert gtirb.Offset(bi1, 3) not in comments
    assert comments[gtirb.Offset(intervals[1], 1)] == "y"
    assert comments[gtirb.Offset(bi2, 2)] == "z"

    padding = m.aux_data["padding"].data
    assert len(padding) == 3
    assert padding[gtirb.Offset(bi1, 1)] == 0
    assert padding[gtirb.Offset(intervals[1], 0)] == 1
    assert padding[gtirb.Offset(bi2, 0)] == 2


def test_split_byte_interval_custom_tables():
    b1 = gtirb.CodeBlock(offset=0, size=2)
    b2 = gtirb.CodeBlock(offset=2, size=2)
    bi1 = gtirb.ByteInterval(
        address=0x1000, blocks=[b1, b2], contents=b"\x00\x01\x02\x03"
    )
    bi2 = gtirb.ByteInterval(
        address=0x2000, blocks=[], contents=b"\xff\xff\xff\xff"
    )
    s = gtirb.Section(name=".test", byte_intervals=[bi1, bi2])
    m = gtirb.Module(name="test", sections=[s])

    m.aux_data["comments"] = gtirb.AuxData(
        type_name="mapping<Offset,string>",
        data={
            gtirb.Offset(element_id=bi1, displacement=0): "x",
            gtirb.Offset(element_id=bi1, displacement=3): "y",
            gtirb.Offset(element_id=bi2, displacement=2): "z",
        },
    )
    table = gtirb_rewriting.OffsetMapping(
        {
            gtirb.Offset(element_id=bi1, displacement=1): 0,
            gtirb.Offset(element_id=bi1, displacement=2): 1,
            gtirb.Offset(element_id=bi2, displacement=0): 2,
        }
    )

    intervals = gtirb_rewriting.split_byte_interval(bi1, tables=[table])
    assert intervals[0] == bi1

    comments = m.aux_data["comments"].data
    assert len(comments) == 3
    assert comments[gtirb.Offset(bi1, 0)] == "x"
    assert comments[gtirb.Offset(bi1, 3)] == "y"
    assert comments[gtirb.Offset(bi2, 2)] == "z"

    assert len(table) == 3
    assert table[gtirb.Offset(intervals[0], 1)] == 0
    assert table[gtirb.Offset(intervals[1], 0)] == 1
    assert table[gtirb.Offset(bi2, 0)] == 2


def test_split_byte_interval_overlapping_blocks():
    b1 = gtirb.CodeBlock(offset=1, size=4)
    b2 = gtirb.CodeBlock(offset=1, size=2)
    b3 = gtirb.CodeBlock(offset=6, size=4)
    b4 = gtirb.CodeBlock(offset=8, size=4)
    b5 = gtirb.CodeBlock(offset=10, size=4)
    b6 = gtirb.CodeBlock(offset=16, size=2)
    b7 = gtirb.CodeBlock(offset=17, size=1)

    bi = gtirb.ByteInterval(blocks=[b1, b2, b3, b4, b5, b6, b7])

    alignment = {b3: 4, b4: 4}
    intervals = gtirb_rewriting.split_byte_interval(bi, alignment=alignment)
    assert len(intervals) == 3
    assert len(set(intervals)) == 3

    assert intervals[0] == bi
    assert intervals[0].blocks == {b1, b2}
    assert intervals[1].blocks == {b3, b4, b5}
    assert intervals[2].blocks == {b6, b7}

    assert b1.offset == 1
    assert b2.offset == 1
    assert b3.offset == 0
    assert b4.offset == 2
    assert b5.offset == 4
    assert b6.offset == 0
    assert b7.offset == 1

    assert alignment[b1] == 1
    assert alignment[b2] == 1
    assert alignment[b3] == 4
    assert alignment[b4] == 4
    assert alignment[b5] == 2
    assert alignment[b6] == 8
    assert alignment[b7] == 1


def test_join_byte_intervals_no_tables():
    b1 = gtirb.DataBlock(offset=1, size=2)
    b2 = gtirb.DataBlock(offset=0, size=4)
    b3 = gtirb.DataBlock(offset=2, size=2)
    s1 = gtirb.Symbol(name="s1")
    s2 = gtirb.Symbol(name="s2")
    bi1 = gtirb.ByteInterval(
        address=0x100,
        blocks=[b1],
        contents=b"\x00\x01\x02\x03",
        symbolic_expressions={3: gtirb.SymAddrConst(symbol=s1, offset=0)},
    )
    bi2 = gtirb.ByteInterval(
        address=0x104,
        blocks=[b2, b3],
        contents=b"\x10\x11\x12\x13",
    )
    bi3 = gtirb.ByteInterval(
        contents=b"\x20\x21\x22",
        size=6,
        symbolic_expressions={
            1: gtirb.SymAddrConst(symbol=s2, offset=0),
            2: gtirb.SymAddrConst(symbol=s2, offset=12),
        },
    )

    bi = gtirb_rewriting.join_byte_intervals([bi1, bi2, bi3])
    assert bi == bi1
    assert bi.address == 0x100
    assert bi.blocks == {b1, b2, b3}
    assert bi.contents == b"\x00\x01\x02\x03\x10\x11\x12\x13\x20\x21\x22"
    assert bi.size == 14
    assert bi.symbolic_expressions == {
        3: gtirb.SymAddrConst(symbol=s1, offset=0),
        9: gtirb.SymAddrConst(symbol=s2, offset=0),
        10: gtirb.SymAddrConst(symbol=s2, offset=12),
    }

    assert b1.address == 0x101
    assert b2.address == 0x104
    assert b3.address == 0x106

    assert len(bi2.blocks) == 0
    assert len(bi2.contents) == 0
    assert len(bi2.symbolic_expressions) == 0

    assert len(bi3.blocks) == 0
    assert len(bi3.contents) == 0
    assert len(bi3.symbolic_expressions) == 0


def test_join_byte_intervals_padding():
    b1 = gtirb.CodeBlock(offset=1, size=2)
    b2 = gtirb.DataBlock(offset=0, size=1)
    b3 = gtirb.CodeBlock(offset=1, size=1)
    bi1 = gtirb.ByteInterval(
        address=0x100,
        blocks=[b1],
        contents=b"\x00\x01\x02\x03",
    )
    bi2 = gtirb.ByteInterval(
        address=0x200,
        blocks=[b2],
        contents=b"\x10\x11",
    )
    bi3 = gtirb.ByteInterval(
        address=0x300,
        blocks=[b3],
        contents=b"\x20\x21\x22\x23",
    )

    bi = gtirb_rewriting.join_byte_intervals(
        [bi1, bi2, bi3], nop=b"\xff", alignment={b1: 2, b3: 4, bi2: 8}
    )
    assert bi == bi1
    assert bi.address == 0x100
    assert len(bi.blocks) == 5
    assert b1 in bi.blocks
    assert b2 in bi.blocks
    assert b3 in bi.blocks
    assert (
        bi.contents
        == b"\x00\x01\x02\x03\xff\xff\xff\xff\x10\x11\x00\x20\x21\x22\x23"
    )
    assert bi.size == 15

    assert b1.address == 0x101
    assert b2.address == 0x108
    assert b3.address == 0x10C


def test_join_byte_intervals_default_tables():
    b1 = gtirb.CodeBlock(offset=0, size=2)
    b2 = gtirb.CodeBlock(offset=0, size=2)
    bi1 = gtirb.ByteInterval(blocks=[b1], contents=b"\x00\x01")
    bi2 = gtirb.ByteInterval(blocks=[b2], contents=b"\x02\x03")
    bi3 = gtirb.ByteInterval(blocks=[], contents=b"\xff\xff")
    s = gtirb.Section(name=".test", byte_intervals=[bi1, bi2, bi3])
    m = gtirb.Module(
        name="test",
        sections=[s],
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
    )

    m.aux_data["alignment"] = gtirb.AuxData(
        type_name="mapping<UUID,uint64_t>",
        data={b2: 4},
    )
    m.aux_data["comments"] = gtirb.AuxData(
        type_name="mapping<Offset,string>",
        data={
            gtirb.Offset(element_id=bi1, displacement=0): "x",
            gtirb.Offset(element_id=bi2, displacement=1): "y",
            gtirb.Offset(element_id=bi3, displacement=2): "z",
        },
    )
    m.aux_data["padding"] = gtirb.AuxData(
        type_name="mapping<Offset,uint64_t>",
        data=gtirb_rewriting.OffsetMapping(
            {
                gtirb.Offset(element_id=bi1, displacement=1): 0,
                gtirb.Offset(element_id=bi2, displacement=0): 1,
                gtirb.Offset(element_id=bi3, displacement=0): 2,
            }
        ),
    )

    bi = gtirb_rewriting.join_byte_intervals([bi1, bi2])
    assert bi == bi1
    assert bi1.section == s
    assert bi2.section == s
    assert bi3.section == s

    comments = m.aux_data["comments"].data
    assert len(comments) == 3
    assert comments[gtirb.Offset(bi1, 0)] == "x"
    assert comments[gtirb.Offset(bi1, 5)] == "y"
    assert comments[gtirb.Offset(bi3, 2)] == "z"

    padding = m.aux_data["padding"].data
    assert len(padding) == 3
    assert padding[gtirb.Offset(bi1, 1)] == 0
    assert padding[gtirb.Offset(bi1, 4)] == 1
    assert padding[gtirb.Offset(bi3, 0)] == 2


def test_join_byte_intervals_custom_tables():
    b1 = gtirb.DataBlock(offset=0, size=2)
    b2 = gtirb.DataBlock(offset=2, size=2)
    bi1 = gtirb.ByteInterval(blocks=[b1], contents=b"\x00\x01")
    bi2 = gtirb.ByteInterval(blocks=[b2], contents=b"\x02\x03")
    bi3 = gtirb.ByteInterval(blocks=[], contents=b"\xff\xff")
    s = gtirb.Section(name=".test", byte_intervals=[bi1, bi2, bi3])
    m = gtirb.Module(name="test", sections=[s])

    m.aux_data["comments"] = gtirb.AuxData(
        type_name="mapping<Offset,string>",
        data={
            gtirb.Offset(element_id=bi1, displacement=0): "x",
            gtirb.Offset(element_id=bi2, displacement=1): "y",
            gtirb.Offset(element_id=bi3, displacement=2): "z",
        },
    )
    table = gtirb_rewriting.OffsetMapping(
        {
            gtirb.Offset(element_id=bi1, displacement=1): 0,
            gtirb.Offset(element_id=bi2, displacement=0): 1,
            gtirb.Offset(element_id=bi3, displacement=0): 2,
        }
    )

    bi = gtirb_rewriting.join_byte_intervals([bi1, bi2], tables=[table])
    assert bi == bi1

    comments = m.aux_data["comments"].data
    assert len(comments) == 3
    assert comments[gtirb.Offset(bi1, 0)] == "x"
    assert comments[gtirb.Offset(bi2, 1)] == "y"
    assert comments[gtirb.Offset(bi3, 2)] == "z"

    assert len(table) == 3
    assert table[gtirb.Offset(bi1, 1)] == 0
    assert table[gtirb.Offset(bi1, 2)] == 1
    assert table[gtirb.Offset(bi3, 0)] == 2


def test_join_byte_intervals_bad_padding():
    b = gtirb.CodeBlock(offset=0, size=1)
    bi1 = gtirb.ByteInterval(contents=b"\x00", blocks=[b])
    bi2 = gtirb.ByteInterval(contents=b"\xff")

    with pytest.raises(gtirb_rewriting.PaddingError):
        gtirb_rewriting.join_byte_intervals(
            [bi1, bi2], nop="\x66\x90", alignment={bi2: 2}
        )


def test_join_byte_intervals_no_nop():
    b = gtirb.CodeBlock(offset=0, size=1)
    bi1 = gtirb.ByteInterval(contents=b"\x00", blocks=[b])
    bi2 = gtirb.ByteInterval(contents=b"\xff")

    with pytest.raises(gtirb_rewriting.PaddingError):
        gtirb_rewriting.join_byte_intervals([bi1, bi2], alignment={bi2: 2})


def test_split_byte_interval_no_blocks():
    contents = b"abc123"
    bi = gtirb.ByteInterval(contents=contents)
    intervals = gtirb_rewriting.split_byte_interval(bi)
    assert len(intervals) == 1
    assert intervals[0].contents == contents
