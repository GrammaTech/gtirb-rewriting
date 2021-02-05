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
import gtirb_rewriting.patches
import pytest


class InsertFunctionPass(gtirb_rewriting.Pass):
    def begin_module(self, module, functions, rewriting_ctx):
        foo_sym = rewriting_ctx.register_insert_function(
            "clobber_rdi",
            gtirb_rewriting.Patch.from_function(self.func_instrumentation),
        )
        assert foo_sym.name == "clobber_rdi"
        assert foo_sym.module == module

        rewriting_ctx.register_insert(
            gtirb_rewriting.AllFunctionsScope(
                position=gtirb_rewriting.FunctionPosition.ENTRY,
                block_position=gtirb_rewriting.BlockPosition.ENTRY,
                functions={gtirb_rewriting.MAIN_NAME},
            ),
            # We're avoiding the CallPatch class because we explicitly want to
            # trample on registers.
            gtirb_rewriting.Patch.from_function(self.call_instrumentation),
        )

    @gtirb_rewriting.patch_constraints()
    def func_instrumentation(self, insertion_ctx):
        return """
        mov $42, %rdi
        ret
        """

    @gtirb_rewriting.patch_constraints()
    def call_instrumentation(self, insertion_ctx):
        return """
        call clobber_rdi
        """


@pytest.mark.skipif(sys.platform == "win32", reason="does not run on windows")
def test_insert_function(tmpdir):
    # Test that we can insert a new function into the gtirb, call it, and see
    # the side effects.

    ir = gtirb.IR.load_protobuf(pathlib.Path(__file__).parent / "e2e.gtirb")

    pm = gtirb_rewriting.PassManager()
    pm.add(InsertFunctionPass())
    pm.run(ir)

    ir.save_protobuf(tmpdir / "rewritten.gtirb")

    result = subprocess.run(
        [
            "gtirb-pprinter",
            tmpdir / "rewritten.gtirb",
            "--keep-all",
            "--skip-section",
            ".rela.plt",
            "--skip-section",
            ".rela.dyn",
            "--skip-section",
            ".eh_frame",
            "-b",
            tmpdir / "rewritten",
            "-a",
            tmpdir / "rewritten.s",
            "-c",
            "-nostartfiles",
        ],
        stderr=subprocess.PIPE,
        check=False,
    )
    sys.stderr.write(result.stderr.decode())
    assert result.returncode == 0
    assert b"WARNING" not in result.stderr

    result = subprocess.run(str(tmpdir / "rewritten"), stdout=subprocess.PIPE)
    assert result.stdout == b"42 arguments\n"
    assert result.returncode == 0
