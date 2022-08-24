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

from typing import TYPE_CHECKING, Dict, Tuple

import gtirb
import gtirb_rewriting._auxdata as auxdata

if TYPE_CHECKING:
    from .assembler import Assembler


def _verify_independence(result: "Assembler.Result"):
    """
    Verify that the assembler result does not refer to another IR object's
    contents.
    """

    def check_node(node: gtirb.CfgNode):
        if (
            isinstance(node, (gtirb.CodeBlock, gtirb.ProxyBlock))
            and node.module
        ):
            raise ValueError(
                "CFG refers to blocks outside of the result and cannot be "
                "made into its own IR"
            )

    for edge in result.cfg:
        check_node(edge.source)
        check_node(edge.target)

    for sect in result.sections.values():
        for sym_expr in sect.symbolic_expressions.values():
            for sym in sym_expr.symbols:
                if sym.module:
                    raise ValueError(
                        "result refers to symbols outside of the result and "
                        "cannot be made into its own IR"
                    )


def _add_empty_dynamic_section(
    module: gtirb.Module,
    section_properties: Dict[gtirb.Section, Tuple[int, int]],
) -> None:
    """
    Adds an empty .dynamic section to the binary, which is required to tell
    the pretty-printer that this is not a statically linked executable.
    """
    SHT_DYNAMIC = 6
    SHF_WRITE = 1
    SHF_ALLOC = 2

    sect = gtirb.Section(
        name=".dynamic",
        flags={
            gtirb.Section.Flag.Initialized,
            gtirb.Section.Flag.Loaded,
            gtirb.Section.Flag.Readable,
            gtirb.Section.Flag.Writable,
        },
        module=module,
    )
    section_properties[sect] = (SHT_DYNAMIC, SHF_WRITE | SHF_ALLOC)


def create_gtirb(result: "Assembler.Result") -> gtirb.IR:
    """
    Creates a GTIRB IR for an assembler result. Internal implementation, do
    not call.
    """

    _verify_independence(result)

    ir = gtirb.IR()
    module = gtirb.Module(
        name="asm",
        isa=result.target.isa,
        file_format=result.target.file_format,
        ir=ir,
    )

    # Add all of the aux data tables we'll need
    binary_type = auxdata.binary_type.get_or_insert(module)
    symbolic_expr_sizes = auxdata.symbolic_expression_sizes.get_or_insert(
        module
    )
    alignment = auxdata.alignment.get_or_insert(module)
    sect_props = auxdata.section_properties.get_or_insert(module)
    elf_sym_info = auxdata.elf_symbol_info.get_or_insert(module)
    encodings = auxdata.encodings.get_or_insert(module)

    # We don't (currently) populate these, but they need to exist in the
    # module for the pretty-printer to function.
    auxdata.function_entries.get_or_insert(module)
    auxdata.function_names.get_or_insert(module)
    auxdata.function_blocks.get_or_insert(module)

    binary_type[:] = result.target.binary_type

    # Copy over the section contents
    for sect in result.sections.values():
        gt_sect = gtirb.Section(
            name=sect.name, flags=sect.flags, module=module
        )
        # TODO: In real programs, we might have uninitialized data that takes
        # no space in the IR. The assembler currently doesn't generate this.
        bi = gtirb.ByteInterval(
            size=len(sect.data),
            contents=sect.data,
            blocks=sect.blocks,
            symbolic_expressions=sect.symbolic_expressions,
            section=gt_sect,
        )

        for off, size in sect.symbolic_expression_sizes.items():
            symbolic_expr_sizes[gtirb.Offset(bi, off)] = size

        sect_props[gt_sect] = (sect.image_type, sect.image_flags)
        alignment.update(sect.alignment.items())
        encodings.update(sect.block_types.items())

    # If we need to be a dynamic binary and don't have a .dynamic section,
    # we need to add one.
    if result.target.is_elf_dynamic and ".dynamic" not in result.sections:
        _add_empty_dynamic_section(module, sect_props)

    for sym, attrs in result.elf_symbol_attributes.items():
        elf_sym_info[sym] = (0, attrs.type, attrs.binding, attrs.visibility, 0)

    module.symbols.update(result.symbols)
    module.proxies.update(result.proxies)
    ir.cfg.update(result.cfg)

    return ir
