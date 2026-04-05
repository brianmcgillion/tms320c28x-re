# SPDX-License-Identifier: MIT
"""TI C28x C/C++ compiler calling convention.

Reference: TI SPRU514 "TMS320C28x Optimizing C/C++ Compiler User's Guide"
- Arguments passed in AL, AH, XAR4, XAR5 (then stack)
- Return value in AL (16-bit) or ACC (32-bit)
- XAR1, XAR2, XAR3 are callee-saved
"""

from binaryninja import CallingConvention


class C28xCallingConvention(CallingConvention):
    name = "c28x-default"
    # TI SPRU514 Table 7-2: Register Use and Preservation Conventions
    caller_saved_regs = ["ACC", "AH", "AL", "P", "PH", "PL", "XT", "T", "TL",
                         "XAR0", "XAR4", "XAR5", "XAR6", "XAR7",
                         "ST0", "ST1", "DP",
                         "R0H", "R1H", "R2H", "R3H", "STF"]
    callee_saved_regs = ["XAR1", "XAR2", "XAR3", "R4H", "R5H", "R6H", "R7H"]
    int_arg_regs = ["AL", "AH", "XAR4", "XAR5"]
    int_return_reg = "AL"
