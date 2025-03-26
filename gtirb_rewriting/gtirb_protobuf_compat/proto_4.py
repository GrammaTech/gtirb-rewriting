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


from typing import Dict, Set

import gtirb
import mcasm

PLT: gtirb.SymbolicExpression.Attribute = (
    gtirb.SymbolicExpression.Attribute.PLT
)
GOT: gtirb.SymbolicExpression.Attribute = (
    gtirb.SymbolicExpression.Attribute.GOT
)
LO12: gtirb.SymbolicExpression.Attribute = (
    gtirb.SymbolicExpression.Attribute.LO12
)

ELF_VARIANT_KINDS: Dict[
    mcasm.mc.SymbolRefExpr.VariantKind, Set[gtirb.SymbolicExpression.Attribute]
] = {
    mcasm.mc.SymbolRefExpr.VariantKind.PLT: {
        gtirb.SymbolicExpression.Attribute.PLT
    },
    mcasm.mc.SymbolRefExpr.VariantKind.GOTNTPOFF: {
        gtirb.SymbolicExpression.Attribute.GOT,
        gtirb.SymbolicExpression.Attribute.NTPOFF,
    },
    mcasm.mc.SymbolRefExpr.VariantKind.GOT: {
        gtirb.SymbolicExpression.Attribute.GOT,
    },
    mcasm.mc.SymbolRefExpr.VariantKind.GOTOFF: {
        gtirb.SymbolicExpression.Attribute.GOT
    },
    mcasm.mc.SymbolRefExpr.VariantKind.GOTTPOFF: {
        gtirb.SymbolicExpression.Attribute.GOT,
        gtirb.SymbolicExpression.Attribute.TPOFF,
    },
    mcasm.mc.SymbolRefExpr.VariantKind.GOTPCREL: {
        gtirb.SymbolicExpression.Attribute.GOT,
        gtirb.SymbolicExpression.Attribute.PCREL,
    },
    mcasm.mc.SymbolRefExpr.VariantKind.TPOFF: {
        gtirb.SymbolicExpression.Attribute.TPOFF
    },
    mcasm.mc.SymbolRefExpr.VariantKind.NTPOFF: {
        gtirb.SymbolicExpression.Attribute.NTPOFF
    },
    mcasm.mc.SymbolRefExpr.VariantKind.DTPOFF: {
        gtirb.SymbolicExpression.Attribute.DTPOFF
    },
    mcasm.mc.SymbolRefExpr.VariantKind.TLSGD: {
        gtirb.SymbolicExpression.Attribute.TLSGD
    },
}
