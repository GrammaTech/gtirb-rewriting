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

import dataclasses
from typing import Dict

import mcasm


class Register:
    """
    An architecture-specific register.

    Registers are not created directly and are instead given to patches by
    requesting scratch registers in their constraints.
    """

    def __init__(self, sizes: Dict[str, str], default_size: str):
        self.sizes = sizes
        self.default_size = default_size

    def __contains__(self, value) -> bool:
        return value in self.sizes.values()

    def __eq__(self, other) -> bool:
        return (
            self.sizes == other.sizes
            and self.default_size == other.default_size
        )

    def __hash__(self) -> int:
        return hash(self.default_size) ^ hash(
            tuple(sorted(self.sizes.items()))
        )

    def __format__(self, spec: str) -> str:
        """
        Formats the register (or subregister) as its name.

        :param spec: The format type specifier. This can control which
                     subregister name is used.
                     x86-64 supports the following sizes:
                     - 8l, 8h, 16, 32, 64
        """
        if spec:
            return self.sizes[spec]
        return self.sizes[self.default_size]

    @property
    def name(self) -> str:
        return self.sizes[self.default_size]


X86Syntax = mcasm.X86Syntax


@dataclasses.dataclass
class _AsmSnippet:
    code: str
    x86_syntax: X86Syntax = X86Syntax.ATT
