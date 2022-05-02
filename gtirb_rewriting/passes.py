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
import logging
from typing import Sequence

import gtirb
import gtirb_functions
import gtirb_rewriting._auxdata as _auxdata

from .modify import _make_return_cache
from .rewriting import RewritingContext


class Pass:
    def begin_module(
        self,
        module: gtirb.Module,
        functions: Sequence[gtirb_functions.Function],
        rewriting_ctx: RewritingContext,
    ) -> None:
        """
        Invoked by the pass manager at the beginning of rewriting a module.
        Passes should use the rewriting context to register their insertions
        in this callback.

        :param module: The module being rewritten.
        :param functions: The calculated list of functions in the module.
        :param rewriting_context: The context to register modifications with.
        """
        pass

    def end_module(
        self,
        module: gtirb.Module,
        functions: Sequence[gtirb_functions.Function],
    ) -> None:
        """
        Invoked by the pass manager after applying rewrites to a module.

        :param module: The module being rewritten.
        :param functions: The calculated list of functions in the module.
        """
        pass


class PassManager:
    """
    Maintains a list of registered passes and runs them on IR.
    """

    def __init__(
        self,
        logger=logging.getLogger("gtirb_rewriting"),
        expensive_assertions=True,
    ):
        """
        :param logger: The logger to log to when rewriting.
        :param expensive_assertions: If enabled, extra assertions will be
        enabled that may have noticable run-time overhead.
        """
        self._logger = logger
        self._passes = []
        self._expensive_assertions = expensive_assertions

    def add(self, pass_inst: Pass) -> None:
        """
        Registers a pass with the pass manager.
        """
        self._passes.append(pass_inst)

    def run(self, ir: gtirb.IR) -> None:
        """
        Runs the passes on the GTIRB IR.
        """

        with _make_return_cache(ir):
            for mod in ir.modules:
                has_functions = _auxdata.function_entries.exists(
                    mod
                ) and _auxdata.function_blocks.exists(mod)

                if has_functions:
                    functions = gtirb_functions.Function.build_functions(mod)
                else:
                    functions = []

                context = RewritingContext(
                    mod,
                    functions,
                    logger=self._logger,
                    expensive_assertions=self._expensive_assertions,
                )

                for pass_inst in self._passes:
                    pass_inst.begin_module(mod, functions, context)

                context.apply()

                for pass_inst in self._passes:
                    pass_inst.end_module(mod, functions)
