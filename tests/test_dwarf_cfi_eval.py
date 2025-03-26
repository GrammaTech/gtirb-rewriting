# GTIRB-Rewriting Rewriting API for GTIRB
# Copyright (C) 2024 GrammaTech, Inc.
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

import uuid
from copy import copy
from dataclasses import dataclass
from typing import List, Tuple, Type, Union

import gtirb
import pytest
from gtirb_test_helpers import (
    add_code_block,
    add_text_section,
    create_test_module,
)

from gtirb_rewriting._auxdata import NULL_UUID, CFIDirectiveType
from gtirb_rewriting.dwarf.cfi import (
    InstDefCFAExpression,
    InstDefCFAOffsetSF,
    InstExpression,
    InstNop,
    InstValExpression,
)
from gtirb_rewriting.dwarf.cfi_eval import (
    CFAExpression,
    CFARegisterOffset,
    CFIStateError,
    EncodedPointer,
    ProcedureState,
    RegisterAtExpression,
    RegisterInRegister,
    RegisterIsExpression,
    RegisterOffset,
    RegisterSameValue,
    RegisterUndefined,
    RegValOffset,
    RowState,
    evaluate_cfi_directives,
)
from gtirb_rewriting.dwarf.dwarf2 import PointerEncodings
from gtirb_rewriting.dwarf.expr import OpConst1U

PERSONALITY_SYMBOL = gtirb.Symbol("personality")
LSDA_SYMBOL = gtirb.Symbol("lsda")


@dataclass
class CFIEvalTest:
    name: str
    rows: List[
        Tuple[
            List[CFIDirectiveType],
            Union[ProcedureState, None, Type[Exception]],
        ]
    ]


def create_ir(
    test: CFIEvalTest,
) -> Tuple[gtirb.Module, List[gtirb.CodeBlock]]:
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0)

    blocks: List[gtirb.CodeBlock] = []
    for directives, _ in test.rows:
        b = add_code_block(bi, b"\x90")
        m.aux_data["cfiDirectives"].data[gtirb.Offset(b, 0)] = directives
        blocks.append(b)

    return m, blocks


@pytest.mark.parametrize(
    "test",
    (
        # Test the procedure-wide state
        CFIEvalTest(
            "prologue",
            [
                (
                    [
                        (".cfi_startproc", [], NULL_UUID),
                        (".cfi_personality", [0], PERSONALITY_SYMBOL),
                        (".cfi_lsda", [0], LSDA_SYMBOL),
                        (".cfi_return_column", [1], NULL_UUID),
                    ],
                    ProcedureState(
                        1,
                        personality=EncodedPointer(
                            PointerEncodings.absptr, PERSONALITY_SYMBOL
                        ),
                        lsda=EncodedPointer(
                            PointerEncodings.absptr, LSDA_SYMBOL
                        ),
                    ),
                ),
                (
                    [
                        (".cfi_endproc", [], NULL_UUID),
                    ],
                    None,
                ),
            ],
        ),
        # Test handling of .cfi_personality / .cfi_lsda with DW_PE_omit.
        CFIEvalTest(
            "prologue-nosyms",
            [
                (
                    [
                        (".cfi_startproc", [], NULL_UUID),
                        (".cfi_personality", [0xFF], NULL_UUID),
                        (".cfi_lsda", [0xFF], NULL_UUID),
                    ],
                    ProcedureState(
                        16,
                        personality=None,
                        lsda=None,
                    ),
                ),
            ],
        ),
        # Test that we calculate the initial state correctly and that
        # .cfi_restore restores a register rule to the initial state _or_
        # removes any information about the register.
        CFIEvalTest(
            "cfi_restore",
            [
                (
                    [
                        (".cfi_startproc", [], NULL_UUID),
                        (".cfi_def_cfa", [7, 8], NULL_UUID),
                        (".cfi_offset", [16, -8], NULL_UUID),
                    ],
                    ProcedureState(
                        16,
                        current=RowState(
                            cfa=CFARegisterOffset(7, 8),
                            registers={16: RegisterOffset(-8)},
                        ),
                        initial=RowState(
                            cfa=CFARegisterOffset(7, 8),
                            registers={16: RegisterOffset(-8)},
                        ),
                    ),
                ),
                (
                    [
                        (".cfi_offset", [15, -8], NULL_UUID),
                        (".cfi_offset", [16, -16], NULL_UUID),
                    ],
                    ProcedureState(
                        16,
                        current=RowState(
                            cfa=CFARegisterOffset(7, 8),
                            registers={
                                15: RegisterOffset(-8),
                                16: RegisterOffset(-16),
                            },
                        ),
                        initial=RowState(
                            cfa=CFARegisterOffset(7, 8),
                            registers={16: RegisterOffset(-8)},
                        ),
                    ),
                ),
                (
                    [
                        (".cfi_restore", [15], NULL_UUID),
                        (".cfi_restore", [16], NULL_UUID),
                    ],
                    ProcedureState(
                        16,
                        current=RowState(
                            cfa=CFARegisterOffset(7, 8),
                            registers={16: RegisterOffset(-8)},
                        ),
                        initial=RowState(
                            cfa=CFARegisterOffset(7, 8),
                            registers={16: RegisterOffset(-8)},
                        ),
                    ),
                ),
            ],
        ),
        # Test the different flavors of register rules
        CFIEvalTest(
            "register-rules",
            [
                (
                    [
                        (".cfi_startproc", [], NULL_UUID),
                    ],
                    ProcedureState(16),
                ),
                (
                    [
                        (".cfi_undefined", [1], NULL_UUID),
                        (".cfi_same_value", [2], NULL_UUID),
                        (".cfi_register", [3, 4], NULL_UUID),
                        (".cfi_val_offset", [5, -8], NULL_UUID),
                        (".cfi_offset", [6, 8], NULL_UUID),
                        (".cfi_rel_offset", [6, +8], NULL_UUID),
                        InstExpression(7, [OpConst1U(42)]).gtirb_encoding(
                            "little", 8
                        ),
                        InstValExpression(8, [OpConst1U(42)]).gtirb_encoding(
                            "little", 8
                        ),
                    ],
                    ProcedureState(
                        16,
                        current=RowState(
                            registers={
                                1: RegisterUndefined(),
                                2: RegisterSameValue(),
                                3: RegisterInRegister(4),
                                5: RegValOffset(-8),
                                6: RegisterOffset(16),
                                7: RegisterAtExpression((OpConst1U(42),)),
                                8: RegisterIsExpression((OpConst1U(42),)),
                            },
                        ),
                    ),
                ),
            ],
        ),
        # Test the different CFA rules
        CFIEvalTest(
            "cfa-rules",
            [
                (
                    [
                        (".cfi_startproc", [], NULL_UUID),
                    ],
                    ProcedureState(16),
                ),
                (
                    [
                        (".cfi_def_cfa", [7, 8], NULL_UUID),
                    ],
                    ProcedureState(
                        16,
                        current=RowState(
                            cfa=CFARegisterOffset(7, 8),
                        ),
                    ),
                ),
                (
                    [
                        (".cfi_def_cfa_register", [6], NULL_UUID),
                    ],
                    ProcedureState(
                        16,
                        current=RowState(
                            cfa=CFARegisterOffset(6, 8),
                        ),
                    ),
                ),
                (
                    [
                        (".cfi_def_cfa_offset", [16], NULL_UUID),
                    ],
                    ProcedureState(
                        16,
                        current=RowState(
                            cfa=CFARegisterOffset(6, 16),
                        ),
                    ),
                ),
                (
                    [
                        (".cfi_adjust_cfa_offset", [+8], NULL_UUID),
                    ],
                    ProcedureState(
                        16,
                        current=RowState(
                            cfa=CFARegisterOffset(6, 24),
                        ),
                    ),
                ),
                (
                    [
                        InstDefCFAExpression([OpConst1U(42)]).gtirb_encoding(
                            "little", 8
                        )
                    ],
                    ProcedureState(
                        16,
                        current=RowState(
                            cfa=CFAExpression((OpConst1U(42),)),
                        ),
                    ),
                ),
            ],
        ),
        # Test state restoration
        CFIEvalTest(
            "restore-state",
            [
                (
                    [
                        (".cfi_startproc", [], NULL_UUID),
                    ],
                    ProcedureState(16),
                ),
                (
                    [
                        (".cfi_def_cfa", [7, 8], NULL_UUID),
                    ],
                    ProcedureState(
                        16,
                        current=RowState(
                            cfa=CFARegisterOffset(7, 8),
                        ),
                    ),
                ),
                (
                    [
                        (".cfi_remember_state", [], NULL_UUID),
                        (".cfi_adjust_cfa_offset", [8], NULL_UUID),
                    ],
                    ProcedureState(
                        16,
                        current=RowState(
                            cfa=CFARegisterOffset(7, 16),
                        ),
                        save_stack=[
                            RowState(
                                cfa=CFARegisterOffset(7, 8),
                            )
                        ],
                    ),
                ),
                (
                    [
                        (".cfi_restore_state", [], NULL_UUID),
                    ],
                    ProcedureState(
                        16,
                        current=RowState(
                            cfa=CFARegisterOffset(7, 8),
                        ),
                        save_stack=[],
                    ),
                ),
            ],
        ),
        # Test that the nop instruction does nothing.
        CFIEvalTest(
            "nop",
            [
                (
                    [
                        (".cfi_startproc", [], NULL_UUID),
                    ],
                    ProcedureState(16),
                ),
                (
                    [InstNop().gtirb_encoding("little", 8)],
                    ProcedureState(16),
                ),
            ],
        ),
        # Test that we error when seeing an instruction outside of a procedure
        CFIEvalTest(
            "errors-not-in-procedure",
            [
                (
                    [(".cfi_def_cfa", [7, 8], NULL_UUID)],
                    CFIStateError,
                ),
            ],
        ),
        # Test that we error if seeing a .cfi_def_cfa_register when the CFA
        # rule isn't a register+offset.
        CFIEvalTest(
            "errors-cfa-register",
            [
                (
                    [(".cfi_startproc", [], NULL_UUID)],
                    ProcedureState(16),
                ),
                (
                    [(".cfi_def_cfa_register", [8], NULL_UUID)],
                    CFIStateError,
                ),
            ],
        ),
        # Test that we error if seeing a .cfi_def_cfa_offset when the CFA rule
        # isn't a register+offset.
        CFIEvalTest(
            "errors-cfa-offset",
            [
                (
                    [(".cfi_startproc", [], NULL_UUID)],
                    ProcedureState(16),
                ),
                (
                    [(".cfi_def_cfa_offset", [8], NULL_UUID)],
                    CFIStateError,
                ),
            ],
        ),
        # Test that we error if seeing a .cfi_adjust_cfa_offset when the CFA
        # rule isn't a register+offset.
        CFIEvalTest(
            "errors-cfa-adjust-offset",
            [
                (
                    [(".cfi_startproc", [], NULL_UUID)],
                    ProcedureState(16),
                ),
                (
                    [(".cfi_adjust_cfa_offset", [8], NULL_UUID)],
                    CFIStateError,
                ),
            ],
        ),
        # Test that we error if seeing a .cfi_rel_offset when the register
        # rule isn't a CFA+offset.
        CFIEvalTest(
            "errors-register-rules",
            [
                (
                    [(".cfi_startproc", [], NULL_UUID)],
                    ProcedureState(16),
                ),
                (
                    [(".cfi_rel_offset", [8, +8], NULL_UUID)],
                    CFIStateError,
                ),
            ],
        ),
        # Test that we error when seeing an unbalanced .cfi_restore_state.
        CFIEvalTest(
            "errors-state-underflow",
            [
                (
                    [(".cfi_startproc", [], NULL_UUID)],
                    ProcedureState(16),
                ),
                (
                    [(".cfi_restore_state", [], NULL_UUID)],
                    CFIStateError,
                ),
            ],
        ),
        # Test that we error when seeing unknown CFI directives.
        CFIEvalTest(
            "errors-unknown-directive",
            [
                (
                    [(".cfi_startproc", [], NULL_UUID)],
                    ProcedureState(16),
                ),
                (
                    [(".cfi_bogus", [], NULL_UUID)],
                    NotImplementedError,
                ),
            ],
        ),
        # Test that we error when we get parsed but unhandled CFI instructions
        # in an escape.
        CFIEvalTest(
            "errors-unhandled-instruction",
            [
                (
                    [(".cfi_startproc", [], NULL_UUID)],
                    ProcedureState(16),
                ),
                (
                    [InstDefCFAOffsetSF(42).gtirb_encoding("little", 8)],
                    NotImplementedError,
                ),
            ],
        ),
        # Test that we error when we get unparsable CFI instructions in an
        # escape.
        CFIEvalTest(
            "errors-invalid-instructions",
            [
                (
                    [(".cfi_startproc", [], NULL_UUID)],
                    ProcedureState(16),
                ),
                (
                    [(".cfi_escape", [0x17], uuid.uuid4())],
                    ValueError,
                ),
            ],
        ),
        # Test that we error when unresolved UUIDs make their way into the
        # CFI directives aux data table.
        CFIEvalTest(
            "errors-unresolved-uuid",
            [
                (
                    [(".cfi_startproc", [], NULL_UUID)],
                    ProcedureState(16),
                ),
                (
                    [(".cfi_lsda", [0], uuid.uuid4())],
                    ValueError,
                ),
            ],
        ),
        # Test handling of a .cfi_lsda that says it should have a symbol but
        # lacks it.
        CFIEvalTest(
            "errors-missing-symbol",
            [
                (
                    [(".cfi_startproc", [], NULL_UUID)],
                    ProcedureState(16),
                ),
                (
                    [(".cfi_lsda", [0], NULL_UUID)],
                    ValueError,
                ),
            ],
        ),
        # Test a .cfi_startproc within a .cfi_startproc.
        CFIEvalTest(
            "errors-procedure-in-procedure",
            [
                (
                    [
                        (".cfi_startproc", [], NULL_UUID),
                        (".cfi_startproc", [], NULL_UUID),
                    ],
                    CFIStateError,
                ),
            ],
        ),
    ),
    ids=lambda test: test.name,
)
def test_cfi_eval(test: CFIEvalTest):
    m, blocks = create_ir(test)
    iter = evaluate_cfi_directives(m, blocks)

    for idx, (_, expected) in enumerate(test.rows):
        if isinstance(expected, type):
            with pytest.raises(expected):
                next(iter)
        else:
            block, offset, state = next(iter)
            assert block == blocks[idx]
            assert offset == 0
            assert state == expected


def test_cfi_eval_no_directives():
    """
    Test that we don't fall over when evaluating CFI directives in a module
    with no directives.
    """
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m, address=0x1000)
    b = add_code_block(bi, b"\x90")
    del m.aux_data["cfiDirectives"]

    assert tuple(evaluate_cfi_directives(m, [b])) == ()


def test_cfi_eval_no_addresses():
    """
    Test that we correctly fail if there are blocks without addresses.
    """
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m)
    b = add_code_block(bi, b"\x90")

    with pytest.raises(ValueError):
        _ = tuple(evaluate_cfi_directives(m, [b]))


def test_cfi_eval_copy():
    """
    Test that the procedure / row states copy correctly.
    """

    row = RowState(
        registers={1: RegisterUndefined()},
        cfa=CFARegisterOffset(7, 8),
    )
    row_copy = copy(row)
    assert row is not row_copy
    assert row.registers is not row_copy.registers
    assert row.registers == row_copy.registers
    assert row.cfa == row_copy.cfa

    state = ProcedureState(
        16,
        personality=EncodedPointer(
            PointerEncodings.absptr, PERSONALITY_SYMBOL
        ),
        lsda=EncodedPointer(PointerEncodings.absptr, LSDA_SYMBOL),
    )
    state.save_stack.append(copy(state.current))
    state_copy = copy(state)
    assert state.return_column == state_copy.return_column
    assert state.personality == state_copy.personality
    assert state.lsda == state_copy.lsda
    assert state.current is not state_copy.current
    assert state.current == state_copy.current
    assert state.initial is not state_copy.initial
    assert state.initial == state_copy.initial
    assert state.save_stack is not state_copy.save_stack
    assert state.save_stack == state_copy.save_stack
    assert all(
        entry is not entry_copy
        for entry, entry_copy in zip(state.save_stack, state_copy.save_stack)
    )
