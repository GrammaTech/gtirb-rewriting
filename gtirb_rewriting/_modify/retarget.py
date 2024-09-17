# GTIRB-Rewriting Rewriting API for GTIRB
# Copyright (C) 2023 GrammaTech, Inc.
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

from typing import Dict, Iterable

import capstone_gt
import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder

from gtirb_rewriting._modify.edges import update_edge

from .. import _auxdata
from ..abi import ABI, _SymExprAttributeRule
from .edit import AmbiguousIRError


def retarget_symbol_uses(
    module: gtirb.Module,
    retargeted_symbols: Dict[gtirb.Symbol, gtirb.Symbol],
    decoder: GtirbInstructionDecoder,
) -> None:
    """
    Updates symbolic expressions that refer to one symbol to refer to another
    symbol and updates control flow accordingly.

    :param module: The module to alter.
    :param retargeted_symbols: A mapping of existing symbols to the new
                               symbols. All symbols must belong to the module.
    :param decoder: An instruction decoder appropriate for the module.
    """

    assert module.ir

    expr_attr_rules = ABI.get(module)._sym_expr_rules(module)

    cfi_auxdata = _auxdata.cfi_directives.get(module)
    if cfi_auxdata:
        for offset, directives in cfi_auxdata.items():
            for i, (directive, args, symbol) in enumerate(directives):
                if isinstance(symbol, gtirb.Symbol):
                    retarget = retargeted_symbols.get(symbol)
                    if retarget:
                        directives[i] = (directive, args, retarget)

    for byte_interval in module.byte_intervals:
        for offset, expr in byte_interval.symbolic_expressions.items():
            new_expr = expr
            for sym in expr.symbols:
                retarget = retargeted_symbols.get(sym)
                if retarget is None:
                    continue

                assert retarget.referent
                assert byte_interval.address is not None

                blocks = [
                    block
                    for block in byte_interval.byte_blocks_on(
                        byte_interval.address + offset
                    )
                    if block.size
                ]
                if len(blocks) > 1:
                    raise AmbiguousIRError(
                        "multiple blocks overlap symbolic expression"
                    )

                if blocks:
                    block = blocks[0]
                    access_type = _sym_expr_access_type(
                        block, offset - block.offset, decoder
                    )
                else:
                    access_type = _SymExprAttributeRule.AccessType.DATA
                    block = None

                new_expr = _retarget_sym_expr(
                    sym,
                    retarget,
                    byte_interval,
                    offset,
                    new_expr,
                    access_type,
                    expr_attr_rules,
                )

                if (
                    access_type
                    == _SymExprAttributeRule.AccessType.CONTROL_FLOW
                    and isinstance(block, gtirb.CfgNode)
                ):
                    _retarget_out_edges(module, sym, retarget, block)

            if new_expr is not expr:
                byte_interval.symbolic_expressions[offset] = new_expr


def _retarget_out_edges(
    module: gtirb.Module,
    sym: gtirb.Symbol,
    retarget: gtirb.Symbol,
    block: gtirb.CfgNode,
) -> None:
    """
    Update any out edges that reference one symbol to refer to another symbol.

    Because the CFG does not operate in terms of symbols, this looks for edges
    that can be caused by symbols (calls, branches) and refer to the symbol's
    referent.
    """

    assert module.ir

    for edge in tuple(block.outgoing_edges):
        if (
            edge.target is sym.referent
            and edge.label
            and edge.label.type
            in (
                gtirb.EdgeType.Branch,
                gtirb.EdgeType.Call,
            )
        ):
            if not isinstance(retarget.referent, gtirb.CfgNode):
                raise AmbiguousIRError(
                    "attempting to retarget control flow into a data block"
                )

            update_edge(edge, module.ir.cfg, target=retarget.referent)


def _retarget_sym_expr(
    old_symbol: gtirb.Symbol,
    new_symbol: gtirb.Symbol,
    byte_interval: gtirb.ByteInterval,
    expr_offset: int,
    expr: gtirb.SymbolicExpression,
    access_type: _SymExprAttributeRule.AccessType,
    expr_attr_rules: Iterable[_SymExprAttributeRule],
) -> gtirb.SymbolicExpression:
    """
    Creates a new symbolic expression by replacing the reference to one symbol
    with another symbol, updating the attributes as needed.
    """

    old_defined = isinstance(old_symbol.referent, gtirb.ByteBlock)
    new_defined = isinstance(new_symbol.referent, gtirb.ByteBlock)

    matching_rules = [
        rule
        for rule in expr_attr_rules
        if access_type in rule.access_types
        and expr.attributes == rule.get_relevant_attrs(old_defined)
    ]

    if not matching_rules:
        new_attrs = expr.attributes
    elif len(matching_rules) == 1:
        new_attrs = matching_rules[0].get_relevant_attrs(new_defined)
    else:
        assert False, f"multiple rules matched: {matching_rules}"

    if isinstance(expr, gtirb.SymAddrConst):
        return gtirb.SymAddrConst(expr.offset, new_symbol, new_attrs)
    else:
        # It's unclear if anything meaningful can be done for SymAddrAddr
        # expressions, since they usually are used for things like the
        # distance between two symbols. If this is a problem in the future,
        # this could be relaxed to just return a new SymAddrAddr where the
        # reference to the retarget symbol gets updated.
        raise NotImplementedError(
            f"attempting to retarget {expr} at byte interval "
            f"{byte_interval.uuid} + {expr_offset}"
        )


def _sym_expr_access_type(
    block: gtirb.ByteBlock,
    offset: int,
    decoder: GtirbInstructionDecoder,
) -> _SymExprAttributeRule.AccessType:
    """
    Determines how a symbol is used in a symbolic expression.
    """

    assert block.address

    expr_addr = block.address + offset
    if isinstance(block, gtirb.CodeBlock):
        instruction = next(
            inst
            for inst in decoder.get_instructions(block)
            if inst.address <= expr_addr < (inst.address + inst.size)
        )
        if instruction.group(capstone_gt.CS_GRP_JUMP) or instruction.group(
            capstone_gt.CS_GRP_CALL
        ):
            return _SymExprAttributeRule.AccessType.CONTROL_FLOW
        else:
            return _SymExprAttributeRule.AccessType.CODE_REF

    return _SymExprAttributeRule.AccessType.DATA
