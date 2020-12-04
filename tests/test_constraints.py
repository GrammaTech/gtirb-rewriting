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

import gtirb
import gtirb_rewriting


class RedZonePass(gtirb_rewriting.Pass):
    def begin_module(self, module, functions, rewriting_ctx):
        rewriting_ctx.register_insert(
            gtirb_rewriting.AllFunctionsScope(
                position=gtirb_rewriting.FunctionPosition.ENTRY,
                block_position=gtirb_rewriting.BlockPosition.ENTRY,
                functions={"leaf_function", "nonleaf_function"},
            ),
            gtirb_rewriting.Patch.from_function(self.red_zone_patch),
        )
        self.hit_count = 0

    # Clobber something so that we need to save the red zone.
    @gtirb_rewriting.patch_constraints(clobbers_flags=True)
    def red_zone_patch(self, insertion_ctx):
        if insertion_ctx.function.get_name() == "leaf_function":
            assert insertion_ctx.stack_adjustment - 8 == 128
        elif insertion_ctx.function.get_name() == "nonleaf_function":
            # 128 would be an acceptable answer here: 0 just means we were
            # able to detect that the function doesn't use the red zone, which
            # is an optimization.
            assert insertion_ctx.stack_adjustment - 8 == 0

        self.hit_count += 1
        return "nop"

    def end_module(self, module, functions):
        # The hit counter ensures we actually saw the call sites we're testing.
        assert self.hit_count == 2


def test_constraints(tmpdir):
    ir = gtirb.IR.load_protobuf(
        pathlib.Path(__file__).parent / "constraints.gtirb"
    )

    pm = gtirb_rewriting.PassManager()
    pm.add(RedZonePass())
    pm.run(ir)
