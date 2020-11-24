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
import pathlib
import subprocess
import sys

import gtirb
import gtirb_rewriting
import pytest


class ExitPatch(gtirb_rewriting.Patch):
    def __init__(self, exit_sym):
        super().__init__(gtirb_rewriting.Constraints(clobbers_registers={"rdi"}))
        self.exit_sym = exit_sym

    def get_asm(self, insertion_ctx):
        return f"""
            mov $42, %rdi
            call {self.exit_sym.name}
        """


class ExitPass(gtirb_rewriting.Pass):
    def begin_module(self, module, functions, rewriting_ctx):
        exit_sym = rewriting_ctx.get_or_insert_extern_symbol(
            "exit", "libc.so.6"
        )
        rewriting_ctx.register_insert(
            gtirb_rewriting.AllFunctionsScope(
                position=gtirb_rewriting.FunctionPosition.EXIT,
                block_position=gtirb_rewriting.BlockPosition.EXIT,
                functions={gtirb_rewriting.MAIN_NAME},
            ),
            ExitPatch(exit_sym),
        )


@pytest.mark.skipif(sys.platform == "win32", reason="does not run on windows")
def test_e2e(tmpdir):
    # Test that we can instrument GTIRB, reassemble it, and then run the
    # binary. Our test binary just prints a string and then exits 0. Our
    # modified binary will print out that string and then exit 42.

    ir = gtirb.IR.load_protobuf(pathlib.Path(__file__).parent / "e2e.gtirb")

    pm = gtirb_rewriting.PassManager()
    pm.add(ExitPass())
    pm.run(ir)

    ir.save_protobuf(tmpdir / "rewritten.gtirb")
    subprocess.check_call(
        [
            "gtirb-pprinter",
            tmpdir / "rewritten.gtirb",
            "--keep-all-symbols",
            "--keep-all-functions",
            "--keep-all-array-sections",
            "--skip-section",
            ".eh_frame",
            "-b",
            tmpdir / "rewritten",
            "-c",
            "-nostartfiles",
        ]
    )

    result = subprocess.run(tmpdir / "rewritten", stdout=subprocess.PIPE)
    assert result.stdout == b"hello world\n"
    assert result.returncode == 42
