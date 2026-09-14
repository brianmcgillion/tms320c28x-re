# SPDX-License-Identifier: MIT
"""Instruction patterns the analysis heuristics recognise.

The constants are the ISA table's, not a second opinion about the encoding:
`ADDB_SP_CONST7` in isa/instructions/arithmetic.yaml is opcode 0xFE00 mask
0xFF80, and tests/test_binja_pure.py asserts these match that row. They are
literals here rather than read from YAML because the shipped plugin should not
parse the ISA at import time.
"""

# ADDB SP, #7bit -- the C28x function prologue cl2000 emits.
ADDB_SP_OPCODE = 0xFE00
ADDB_SP_MASK = 0xFF80


def is_function_prologue(op16):
    """Does this 16-bit word start a compiler-generated function?

    `ADDB SP, #n` reserves the frame. It is the only prologue cl2000 emits, so
    a function entry without one is either hand-written assembly or -- far more
    often -- not a function at all.
    """
    return (op16 & ADDB_SP_MASK) == ADDB_SP_OPCODE
