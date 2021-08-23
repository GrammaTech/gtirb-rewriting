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
import warnings

import gtirb
import gtirb_rewriting
import gtirb_rewriting.patches
import pytest


class E2EPass(gtirb_rewriting.Pass):
    def begin_module(self, module, functions, rewriting_ctx):
        global_sym = next(
            sym for sym in module.symbols if sym.name == "global_int"
        )
        print_sym = next(
            sym for sym in module.symbols if sym.name == "print_integers"
        )
        rewriting_ctx.register_insert(
            gtirb_rewriting.AllFunctionsScope(
                position=gtirb_rewriting.FunctionPosition.ENTRY,
                block_position=gtirb_rewriting.BlockPosition.ENTRY,
                functions={gtirb_rewriting.ENTRYPOINT_NAME},
            ),
            gtirb_rewriting.patches.CallPatch(
                print_sym,
                args=(1, 2, 3, 4, 5, 6, 7, global_sym),
                align_stack=True,
                preserve_caller_saved_registers=True,
            ),
        )

        exit_sym = rewriting_ctx.get_or_insert_extern_symbol(
            "exit", "libc.so.6"
        )
        rewriting_ctx.register_insert(
            gtirb_rewriting.AllFunctionsScope(
                position=gtirb_rewriting.FunctionPosition.EXIT,
                block_position=gtirb_rewriting.BlockPosition.EXIT,
                functions={gtirb_rewriting.MAIN_NAME},
            ),
            gtirb_rewriting.patches.CallPatch(
                exit_sym, args=(self.dynamic_arg_value,)
            ),
        )

    def dynamic_arg_value(self, insertion_ctx):
        # We can't verify many properties about the context
        assert isinstance(insertion_ctx, gtirb_rewriting.InsertionContext)
        return 42


@pytest.mark.skipif(sys.platform == "win32", reason="does not run on windows")
def test_e2e(tmpdir):
    # Test that we can instrument GTIRB, reassemble it, and then run the
    # binary. Our test binary just prints a string and then exits 0. Our
    # modified binary will print out integers, the original string and then
    # exit 42.

    test_dir = pathlib.Path(__file__).parent

    subprocess.run(
        ["ddisasm", test_dir / "e2e", "--ir", tmpdir / "e2e.gtirb", "-j1"],
        check=True,
    )
    ir = gtirb.IR.load_protobuf(tmpdir / "e2e.gtirb")

    pm = gtirb_rewriting.PassManager()
    pm.add(E2EPass())
    pm.run(ir)

    ir.save_protobuf(tmpdir / "rewritten.gtirb")

    result = subprocess.run(
        [
            "gtirb-pprinter",
            tmpdir / "rewritten.gtirb",
            "--policy=complete",
            "-b",
            tmpdir / "rewritten",
            "-a",
            tmpdir / "rewritten.s",
        ],
        stderr=subprocess.PIPE,
        check=False,
    )
    sys.stderr.write(result.stderr.decode())
    assert result.returncode == 0
    if b"WARNING" in result.stderr:
        # We specifically want to make sure gtirb-rewriting didn't generate
        # overlapping blocks. Other warnings are interesting but non-fatal.
        assert b"WARNING: found overlapping" not in result.stderr
        warnings.warn(UserWarning(result.stderr.decode()))

    result = subprocess.run(str(tmpdir / "rewritten"), stdout=subprocess.PIPE)
    assert (
        result.stdout
        == b"print_integers: 1, 2, 3, 4, 5, 6, 7, 100\n1 arguments\n"
    )
    assert result.returncode == 42
