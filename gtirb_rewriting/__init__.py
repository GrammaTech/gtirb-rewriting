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
from .assembly import (
    Constraints,
    InsertionContext,
    Patch,
    Register,
    X86Syntax,
    patch_constraints,
)
from .passes import Pass, PassManager
from .rewriting import RewritingContext
from .scopes import (
    ENTRYPOINT_NAME,
    MAIN_NAME,
    AllBlocksScope,
    AllFunctionsScope,
    BlockPosition,
    FunctionPosition,
    Scope,
)
from .utils import decorate_extern_symbol, show_block_asm
from .version import __version__

__all__ = [
    "__version__",
    "AllBlocksScope",
    "AllFunctionsScope",
    "BlockPosition",
    "Constraints",
    "decorate_extern_symbol",
    "ENTRYPOINT_NAME",
    "FunctionPosition",
    "InsertionContext",
    "MAIN_NAME",
    "Pass",
    "PassManager",
    "patch_constraints",
    "Patch",
    "Register",
    "RewritingContext",
    "Scope",
    "show_block_asm",
    "X86Syntax",
]
