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


def test_pass_order():
    events = []

    class DummyPass(gtirb_rewriting.Pass):
        def begin_module(
            self,
            module,
            functions,
            rewriting_ctx,
        ):
            events.append((self, "begin", module))

        def end_module(self, module, functions):
            events.append((self, "end", module))

    mod1 = gtirb.Module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
        name="test",
    )
    mod1.aux_data["functionEntries"] = gtirb.AuxData(
        type_name="mapping<UUID,set<UUID>>",
        data={},
    )
    mod2 = gtirb.Module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
        name="test",
    )
    mod2.aux_data["functionEntries"] = gtirb.AuxData(
        type_name="mapping<UUID,set<UUID>>",
        data={},
    )
    ir = gtirb.IR(modules=[mod1, mod2])

    pm = gtirb_rewriting.PassManager()
    pass1 = DummyPass()
    pass2 = DummyPass()

    pm.add(pass1)
    pm.add(pass2)
    pm.run(ir)

    assert events == [
        (pass1, "begin", mod1),
        (pass2, "begin", mod1),
        (pass1, "end", mod1),
        (pass2, "end", mod1),
        (pass1, "begin", mod2),
        (pass2, "begin", mod2),
        (pass1, "end", mod2),
        (pass2, "end", mod2),
    ]
