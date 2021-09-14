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
from .abi import ABI, CallingConventionDesc
from .assembler import Assembler
from .assembly import Constraints, Register, X86Syntax
from .intervalutils import (
    PaddingError,
    join_byte_intervals,
    split_byte_interval,
)
from .passes import Pass, PassManager
from .patch import InsertionContext, Patch, patch_constraints
from .rewriting import RewritingContext
from .scopes import (
    ENTRYPOINT_NAME,
    MAIN_NAME,
    AllBlocksScope,
    AllFunctionsScope,
    BlockPosition,
    FunctionPosition,
    Scope,
    SingleBlockScope,
    pattern_match,
)
from .utils import (
    OffsetMapping,
    decorate_extern_symbol,
    is_gtirb_at_least_version,
    show_block_asm,
)
from .version import __version__

__all__ = [
    "__version__",
    "ABI",
    "AllBlocksScope",
    "AllFunctionsScope",
    "Assembler",
    "BlockPosition",
    "CallingConventionDesc",
    "Constraints",
    "decorate_extern_symbol",
    "ENTRYPOINT_NAME",
    "FunctionPosition",
    "InsertionContext",
    "is_gtirb_at_least_version",
    "join_byte_intervals",
    "MAIN_NAME",
    "OffsetMapping",
    "PaddingError",
    "Pass",
    "PassManager",
    "patch_constraints",
    "pattern_match",
    "Patch",
    "Register",
    "RewritingContext",
    "Scope",
    "SingleBlockScope",
    "show_block_asm",
    "split_byte_interval",
    "X86Syntax",
]
