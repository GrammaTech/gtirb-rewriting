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


class CfgPass(gtirb_rewriting.Pass):
    def begin_module(self, module, functions, rewriting_ctx):
        rewriting_ctx.register_insert(
            gtirb_rewriting.AllFunctionsScope(
                position=gtirb_rewriting.FunctionPosition.ENTRY,
                block_position=gtirb_rewriting.BlockPosition.ENTRY,
                functions={gtirb_rewriting.MAIN_NAME},
            ),
            gtirb_rewriting.Patch.from_function(self.cfg_patch),
        )

    @gtirb_rewriting.patch_constraints()
    def cfg_patch(self, insertion_ctx):
        # We're inserting into the start of main, so we have argc in %rdi and
        # in this nonsense patch we're just going to set argc to 0 by
        # decrementing it one at a time.
        return """
        .L_head:
            cmp $0, %rdi
            je .L_end
            dec %rdi
            jmp .L_head
        .L_end:
        """


@pytest.mark.skipif(sys.platform == "win32", reason="does not run on windows")
def test_cfg(tmpdir):
    ir = gtirb.IR.load_protobuf(pathlib.Path(__file__).parent / "e2e.gtirb")

    pm = gtirb_rewriting.PassManager()
    pm.add(CfgPass())
    pm.run(ir)

    ir.save_protobuf(tmpdir / "rewritten.gtirb")

    result = subprocess.run(
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
            "-a",
            tmpdir / "rewritten.s",
            "-c",
            "-nostartfiles",
        ],
        stderr=subprocess.PIPE,
        check=True,
    )
    sys.stderr.write(result.stderr.decode())
    assert b"WARNING" not in result.stderr

    result = subprocess.run(str(tmpdir / "rewritten"), stdout=subprocess.PIPE)
    assert result.stdout == b"0 arguments\n"
    assert result.returncode == 0
