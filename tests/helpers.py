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

"""
Helper utilities for GTIRB-based tests.
"""

import uuid
from typing import Dict, Set, Tuple, Type, TypeVar, Union

import gtirb
import gtirb_functions
import gtirb_rewriting


def create_test_module(
    isa: gtirb.Module.ISA = gtirb.Module.ISA.X64,
    file_format: gtirb.Module.FileFormat = gtirb.Module.FileFormat.ELF,
) -> Tuple[gtirb.IR, gtirb.Module, gtirb.ByteInterval]:
    """
    Creates a test GTIRB module and returns the IR object, the module object,
    and the byte interval representing the text section.
    """
    ir = gtirb.IR()
    m = gtirb.Module(isa=isa, file_format=file_format, name="test")
    m.ir = ir
    s = gtirb.Section(
        name=".text",
        flags={
            gtirb.Section.Flag.Readable,
            gtirb.Section.Flag.Executable,
            gtirb.Section.Flag.Loaded,
            gtirb.Section.Flag.Initialized,
        },
    )
    s.module = m
    bi = gtirb.ByteInterval(contents=b"", address=0x1000)
    bi.section = s

    m.aux_data["binaryType"] = gtirb.AuxData(
        type_name="vector<string>", data=["DYN"]
    )
    m.aux_data["functionNames"] = gtirb.AuxData(
        type_name="mapping<uuid,uuid>", data={}
    )
    m.aux_data["functionEntries"] = gtirb.AuxData(
        type_name="mapping<uuid,set<uuid>>", data={}
    )
    m.aux_data["functionBlocks"] = gtirb.AuxData(
        type_name="mapping<uuid,set<uuid>>", data={}
    )
    m.aux_data["alignment"] = gtirb.AuxData(
        type_name="mapping<uuid,int>", data={s: 16}
    )

    return ir, m, bi


def add_proxy_block(m: gtirb.Module) -> gtirb.ProxyBlock:
    """
    Creates a proxy block and adds it to the module.
    """
    b = gtirb.ProxyBlock()
    m.proxies.add(b)
    return b


BlockT = TypeVar("BlockT", bound=gtirb.ByteBlock)


def add_byte_block(
    byte_interval: gtirb.ByteInterval,
    block_type: Type[BlockT],
    content: bytes,
    symbolic_expressions: Dict[int, gtirb.SymbolicExpression] = None,
) -> BlockT:
    """
    Adds a block to a byte interval, setting up its contents and optionally
    its symbolic expressions.
    """
    b = block_type(offset=byte_interval.size, size=len(content))
    b.byte_interval = byte_interval
    byte_interval.contents += content
    if symbolic_expressions:
        for off, expr in symbolic_expressions.items():
            byte_interval.symbolic_expressions[byte_interval.size + off] = expr
    byte_interval.size += len(content)
    return b


def add_code_block(
    byte_interval: gtirb.ByteInterval,
    content: bytes,
    symbolic_expressions: Dict[int, gtirb.SymbolicExpression] = None,
) -> gtirb.CodeBlock:
    """
    Adds a code block to a byte interval, setting up its contents and
    optionally its symbolic expressions.
    """
    return add_byte_block(
        byte_interval, gtirb.CodeBlock, content, symbolic_expressions
    )


def add_data_block(
    byte_interval: gtirb.ByteInterval,
    content: bytes,
    symbolic_expressions: Dict[int, gtirb.SymbolicExpression] = None,
) -> gtirb.DataBlock:
    """
    Adds a data block to a byte interval, setting up its contents and
    optionally its symbolic expressions.
    """
    return add_byte_block(
        byte_interval, gtirb.DataBlock, content, symbolic_expressions
    )


def add_symbol(
    module: gtirb.Module, name: str, payload: gtirb.Block = None
) -> gtirb.Symbol:
    """
    Creates a symbol and adds it to the module.
    """
    sym = gtirb.Symbol(name, payload=payload)
    module.symbols.add(sym)
    return sym


def add_function(
    module: gtirb.Module,
    sym_or_name: Union[str, gtirb.Symbol],
    entry_block: gtirb.CodeBlock,
    other_blocks: Set[gtirb.CodeBlock] = set(),
) -> gtirb_functions.Function:
    """
    Adds a function to all the appropriate aux data tables and creates a
    Function object.
    """
    if isinstance(sym_or_name, str):
        func_sym = add_symbol(module, sym_or_name, entry_block)
    elif isinstance(sym_or_name, gtirb.Symbol):
        func_sym = sym_or_name
    else:
        assert False, "Invalid symbol name"

    entry_blocks = {entry_block}
    all_blocks = entry_blocks | other_blocks

    func_uuid = uuid.uuid4()
    module.aux_data["functionNames"].data[func_uuid] = func_sym
    module.aux_data["functionEntries"].data[func_uuid] = entry_blocks
    module.aux_data["functionBlocks"].data[func_uuid] = all_blocks
    return gtirb_functions.Function(func_uuid, entry_blocks, all_blocks)


def add_edge(
    cfg: gtirb.CFG,
    source: gtirb.CfgNode,
    target: gtirb.CfgNode,
    edge_type: gtirb.Edge.Type,
    *,
    conditional: bool = False,
) -> gtirb.Edge:
    """
    Creates and adds an edge to a CFG.
    """
    edge = gtirb.Edge(
        source=source,
        target=target,
        label=gtirb.Edge.Label(type=edge_type, conditional=conditional),
    )
    cfg.add(edge)
    return edge


def set_all_blocks_alignment(module: gtirb.Module, alignment: int) -> None:
    """
    Sets the alignment of all blocks in a module to a specific value.
    """
    for block in module.byte_blocks:
        module.aux_data["alignment"].data[block] = alignment


def literal_patch(asm: str) -> gtirb_rewriting.Patch:
    """
    Creates a patch from a literal string. The patch will have an empty
    constraints object.
    """

    @gtirb_rewriting.patch_constraints()
    def patch(ctx):
        return asm

    return gtirb_rewriting.Patch.from_function(patch)


def remove_indentation(s: str) -> str:
    """
    Removes indentation from the front of each line in a string, omitting any
    purely empty lines.
    """
    lines = []
    for line in s.splitlines():
        line = line.lstrip()
        if line:
            lines.append(line)
    return "\n".join(lines)
