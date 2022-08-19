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

import argparse
import sys

import gtirb
from gtirb_rewriting import Assembler, AssemblerError, X86Syntax


def enum_type(enum_type):
    def type(value: str):
        for name in dir(enum_type):
            if name.lower() == value.lower():
                return getattr(enum_type, name)

        raise argparse.ArgumentTypeError()

    return type


def enum_names(enum_type, ignore=set()):
    try:
        members = list(enum_type)
    except TypeError:
        # The pybind11 enums are not proper enums, so we need to dig for the
        # member list.
        members = enum_type.__members__.values()

    return [v.name.lower() for v in members if v not in ignore]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("asm", type=argparse.FileType("rt"))
    ap.add_argument("gtirb", type=argparse.FileType("wb"))
    ap.add_argument(
        "--file-format",
        metavar=",".join(
            enum_names(
                gtirb.Module.FileFormat,
                ignore={gtirb.Module.FileFormat.Undefined},
            )
        ),
        type=enum_type(gtirb.Module.FileFormat),
        required=True,
    )
    ap.add_argument(
        "--isa",
        metavar=",".join(
            enum_names(
                gtirb.Module.ISA,
                ignore={
                    gtirb.Module.ISA.Undefined,
                    gtirb.Module.ISA.ValidButUnsupported,
                },
            )
        ),
        type=enum_type(gtirb.Module.ISA),
        required=True,
    )
    ap.add_argument(
        "--syntax",
        metavar=",".join(enum_names(X86Syntax)),
        type=enum_type(X86Syntax),
        default=X86Syntax.ATT,
    )
    ap.add_argument("--pie", action="store_true")
    ap.add_argument("--static", action="store_true")
    args = ap.parse_args()

    with args.asm:
        asm: str = args.asm.read()

    # TODO: This is temporary until the gtirb-pprinter stops over-escaping
    # things. This has the potential to corrupt strings (e.g. .string "\\'").
    asm = asm.replace(r"\'", "'")

    if args.file_format == gtirb.Module.FileFormat.ELF:
        if args.pie:
            binary_type = ["DYN"]
        else:
            binary_type = ["EXEC"]
    else:
        binary_type = ["EXE"]

    assembler = Assembler(
        Assembler.Target(args.isa, args.file_format, binary_type),
        trivially_unreachable=True,
        allow_undef_symbols=True,
        ignore_cfi_directives=True,
    )

    try:
        assembler.assemble(asm, args.syntax)
    except AssemblerError as err:
        lines = asm.splitlines(keepends=True)
        sys.stderr.write(
            f"{args.asm.name}:{err.lineno}:{err.offset}: error: {err}\n"
        )
        if err.lineno:
            sys.stderr.write(lines[err.lineno - 1])
            if err.offset:
                # LLVM only stores the start column in its diagnostic object.
                sys.stderr.write(" " * (err.offset) + "^\n")
            else:
                sys.stderr.write("^\n")
        sys.exit(1)

    result = assembler.finalize()

    # In order for the binary to be printed correctly, we need to have a
    # .dynamic section (assuming we aren't making a static binary).
    # TODO: This should probably live in create_gtirb, which means that Target
    # needs to know static vs dynamic.
    if not args.static and ".dynamic" not in result.sections:
        SHT_DYNAMIC = 6
        SHF_WRITE = 1
        SHF_ALLOC = 2

        result.sections[".dynamic"] = Assembler.Result.Section(
            name=".dynamic",
            flags={
                gtirb.Section.Flag.Initialized,
                gtirb.Section.Flag.Loaded,
                gtirb.Section.Flag.Readable,
                gtirb.Section.Flag.Writable,
            },
            data=b"",
            blocks=[],
            symbolic_expressions={},
            symbolic_expression_sizes={},
            alignment={},
            image_type=SHT_DYNAMIC,
            image_flags=SHF_WRITE | SHF_ALLOC,
            block_types={},
            line_map={},
        )

    ir = result.create_ir()
    ir.save_protobuf_file(args.gtirb)


if __name__ == "__main__":
    main()
