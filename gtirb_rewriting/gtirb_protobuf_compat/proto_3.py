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

# For other GTIRB versions, some symbolic expression attributes
# will not be defined and they will cause type checking errors.
# Therefore, we deactivate type checking in this file.

from typing import Dict, Set

import gtirb
import mcasm

PLT: gtirb.SymbolicExpression.Attribute = (
    gtirb.SymbolicExpression.Attribute.PltRef
)
GOT: gtirb.SymbolicExpression.Attribute = (
    gtirb.SymbolicExpression.Attribute.GotRef
)
LO12: gtirb.SymbolicExpression.Attribute = (
    gtirb.SymbolicExpression.Attribute.Lo12
)

ELF_VARIANT_KINDS: Dict[
    mcasm.mc.SymbolRefExpr.VariantKind, Set[gtirb.SymbolicExpression.Attribute]
] = {
    mcasm.mc.SymbolRefExpr.VariantKind.PLT: {
        gtirb.SymbolicExpression.Attribute.PltRef
    },
    mcasm.mc.SymbolRefExpr.VariantKind.GOTNTPOFF: {
        gtirb.SymbolicExpression.Attribute.GotOff,
        gtirb.SymbolicExpression.Attribute.NtpOff,
    },
    mcasm.mc.SymbolRefExpr.VariantKind.GOT: {
        gtirb.SymbolicExpression.Attribute.GotOff,
        gtirb.SymbolicExpression.Attribute.GotRef,
    },
    mcasm.mc.SymbolRefExpr.VariantKind.GOTOFF: {
        gtirb.SymbolicExpression.Attribute.GotOff
    },
    mcasm.mc.SymbolRefExpr.VariantKind.GOTTPOFF: {
        gtirb.SymbolicExpression.Attribute.GotRelPC,
        gtirb.SymbolicExpression.Attribute.TpOff,
    },
    mcasm.mc.SymbolRefExpr.VariantKind.GOTPCREL: {
        gtirb.SymbolicExpression.Attribute.GotRelPC,
    },
    mcasm.mc.SymbolRefExpr.VariantKind.TPOFF: {
        gtirb.SymbolicExpression.Attribute.TpOff
    },
    mcasm.mc.SymbolRefExpr.VariantKind.NTPOFF: {
        gtirb.SymbolicExpression.Attribute.NtpOff
    },
    mcasm.mc.SymbolRefExpr.VariantKind.DTPOFF: {
        gtirb.SymbolicExpression.Attribute.DtpOff
    },
    mcasm.mc.SymbolRefExpr.VariantKind.TLSGD: {
        gtirb.SymbolicExpression.Attribute.TlsGd
    },
}
