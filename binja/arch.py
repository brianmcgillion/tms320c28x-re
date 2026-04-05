# SPDX-License-Identifier: MIT
"""TMS320C28x Binary Ninja Architecture class.

Implements the three required methods:
- get_instruction_info: instruction length + branch info for CFG
- get_instruction_text: syntax-highlighted disassembly tokens
- get_instruction_low_level_il: LLIL lifting (incremental)
"""

from __future__ import annotations

import sys
from pathlib import Path

from binaryninja import (
    Architecture,
    BranchType as BNBranchType,
    Endianness,
    FlagRole,
    InstructionInfo,
    InstructionTextToken,
    InstructionTextTokenType as TT,
    IntrinsicInfo,
    IntrinsicInput,
    RegisterInfo,
    Type,
)

# Add project root to path so c28x package is importable
_project_root = str(Path(__file__).parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from c28x.decoder import Decoder
from c28x.types import BranchType, OperandType
from .callingconv import C28xCallingConvention
from .lifter import Lifter


class TMS320C28x(Architecture):
    name = "tms320c28x"

    # C28x uses 16-bit words, but BN works in byte space
    address_size = 4           # 22-bit addresses, padded to 4 bytes
    default_int_size = 2       # 16-bit word = native int size
    instr_alignment = 2        # Instructions are word-aligned (2 bytes)
    max_instr_length = 4       # Max 32-bit (2 words = 4 bytes)
    endianness = Endianness.LittleEndian

    stack_pointer = "SP"

    regs = {
        # 32-bit accumulator
        "ACC": RegisterInfo("ACC", 4),
        "AH":  RegisterInfo("ACC", 2, 2),
        "AL":  RegisterInfo("ACC", 2, 0),

        # 32-bit auxiliary registers
        "XAR0": RegisterInfo("XAR0", 4),
        "AR0":  RegisterInfo("XAR0", 2, 0),
        "XAR1": RegisterInfo("XAR1", 4),
        "AR1":  RegisterInfo("XAR1", 2, 0),
        "XAR2": RegisterInfo("XAR2", 4),
        "AR2":  RegisterInfo("XAR2", 2, 0),
        "XAR3": RegisterInfo("XAR3", 4),
        "AR3":  RegisterInfo("XAR3", 2, 0),
        "XAR4": RegisterInfo("XAR4", 4),
        "AR4":  RegisterInfo("XAR4", 2, 0),
        "XAR5": RegisterInfo("XAR5", 4),
        "AR5":  RegisterInfo("XAR5", 2, 0),
        "XAR6": RegisterInfo("XAR6", 4),
        "AR6":  RegisterInfo("XAR6", 2, 0),
        "XAR7": RegisterInfo("XAR7", 4),
        "AR7":  RegisterInfo("XAR7", 2, 0),

        # Product register
        "P":  RegisterInfo("P", 4),
        "PH": RegisterInfo("P", 2, 2),
        "PL": RegisterInfo("P", 2, 0),

        # Multiplicand register
        "XT": RegisterInfo("XT", 4),
        "T":  RegisterInfo("XT", 2, 2),
        "TL": RegisterInfo("XT", 2, 0),

        # System registers
        "SP":     RegisterInfo("SP", 2),
        "DP":     RegisterInfo("DP", 2),
        "PC":     RegisterInfo("PC", 4),
        "RPC":    RegisterInfo("RPC", 4),
        "ST0":    RegisterInfo("ST0", 2),
        "ST1":    RegisterInfo("ST1", 2),
        "IER":    RegisterInfo("IER", 2),
        "IFR":    RegisterInfo("IFR", 2),
        "DBGIER": RegisterInfo("DBGIER", 2),

        # FPU32 registers (32-bit float)
        "R0H": RegisterInfo("R0H", 4),
        "R1H": RegisterInfo("R1H", 4),
        "R2H": RegisterInfo("R2H", 4),
        "R3H": RegisterInfo("R3H", 4),
        "R4H": RegisterInfo("R4H", 4),
        "R5H": RegisterInfo("R5H", 4),
        "R6H": RegisterInfo("R6H", 4),
        "R7H": RegisterInfo("R7H", 4),
        "STF": RegisterInfo("STF", 4),
    }

    flags = ["N", "Z", "C", "V", "TC", "OVM"]

    flag_roles = {
        "N":   FlagRole.NegativeSignFlagRole,
        "Z":   FlagRole.ZeroFlagRole,
        "C":   FlagRole.CarryFlagRole,
        "V":   FlagRole.OverflowFlagRole,
        "TC":  FlagRole.SpecialFlagRole,
        "OVM": FlagRole.SpecialFlagRole,
    }

    flag_write_types = ["*", "nz", "nzcv"]

    flags_written_by_flag_write_type = {
        "*":    ["N", "Z", "C", "V"],
        "nz":   ["N", "Z"],
        "nzcv": ["N", "Z", "C", "V"],
    }

    # FPU intrinsics for pseudo-C decompilation
    # IntrinsicInfo(inputs: List[IntrinsicInput], outputs: List[Type])
    intrinsics = {
        # Arithmetic (2-in, 1-out float)
        "addf32":    IntrinsicInfo([IntrinsicInput(Type.float(4), "a"), IntrinsicInput(Type.float(4), "b")], [Type.float(4)]),
        "subf32":    IntrinsicInfo([IntrinsicInput(Type.float(4), "a"), IntrinsicInput(Type.float(4), "b")], [Type.float(4)]),
        "mpyf32":    IntrinsicInfo([IntrinsicInput(Type.float(4), "a"), IntrinsicInput(Type.float(4), "b")], [Type.float(4)]),
        "macf32":    IntrinsicInfo([IntrinsicInput(Type.float(4), "a"), IntrinsicInput(Type.float(4), "b")], [Type.float(4)]),
        "maxf32":    IntrinsicInfo([IntrinsicInput(Type.float(4), "a"), IntrinsicInput(Type.float(4), "b")], [Type.float(4)]),
        "minf32":    IntrinsicInfo([IntrinsicInput(Type.float(4), "a"), IntrinsicInput(Type.float(4), "b")], [Type.float(4)]),
        "cmpf32":    IntrinsicInfo([IntrinsicInput(Type.float(4), "a"), IntrinsicInput(Type.float(4), "b")], []),
        # Unary (1-in, 1-out float)
        "absf32":    IntrinsicInfo([IntrinsicInput(Type.float(4), "a")], [Type.float(4)]),
        "negf32":    IntrinsicInfo([IntrinsicInput(Type.float(4), "a")], [Type.float(4)]),
        "einvf32":   IntrinsicInfo([IntrinsicInput(Type.float(4), "a")], [Type.float(4)]),
        "eisqrtf32": IntrinsicInfo([IntrinsicInput(Type.float(4), "a")], [Type.float(4)]),
        "fracf32":   IntrinsicInfo([IntrinsicInput(Type.float(4), "a")], [Type.float(4)]),
        # Conversions
        "i16tof32":  IntrinsicInfo([IntrinsicInput(Type.int(2, True), "a")], [Type.float(4)]),
        "ui16tof32": IntrinsicInfo([IntrinsicInput(Type.int(2, False), "a")], [Type.float(4)]),
        "i32tof32":  IntrinsicInfo([IntrinsicInput(Type.int(4, True), "a")], [Type.float(4)]),
        "ui32tof32": IntrinsicInfo([IntrinsicInput(Type.int(4, False), "a")], [Type.float(4)]),
        "f32toi16":  IntrinsicInfo([IntrinsicInput(Type.float(4), "a")], [Type.int(2, True)]),
        "f32toui16": IntrinsicInfo([IntrinsicInput(Type.float(4), "a")], [Type.int(2, False)]),
        "f32toi32":  IntrinsicInfo([IntrinsicInput(Type.float(4), "a")], [Type.int(4, True)]),
        "f32toui32": IntrinsicInfo([IntrinsicInput(Type.float(4), "a")], [Type.int(4, False)]),
    }

    flags_required_for_flag_condition = {
        "ne":  ["Z"],
        "eq":  ["Z"],
        "gt":  ["Z", "N"],
        "ge":  ["N"],
        "lt":  ["N"],
        "le":  ["Z", "N"],
        "hi":  ["C", "Z"],
        "c":   ["C"],
        "nc":  ["C"],
        "ov":  ["V"],
        "nov": ["V"],
    }

    def __init__(self) -> None:
        super().__init__()
        self._decoder = Decoder(objmode=1)
        self._lifter = Lifter()

    def get_instruction_info(self, data: bytes, addr: int) -> InstructionInfo | None:
        try:
            insn = self._decoder.decode(data, addr)
            if insn is None:
                return None

            info = InstructionInfo()
            info.length = insn.size

            if insn.branch_type == BranchType.UNCONDITIONAL:
                if insn.branch_target is not None:
                    info.add_branch(BNBranchType.UnconditionalBranch, insn.branch_target)
                else:
                    info.add_branch(BNBranchType.IndirectBranch)

            elif insn.branch_type == BranchType.CONDITIONAL_TRUE:
                if insn.branch_target is not None:
                    info.add_branch(BNBranchType.TrueBranch, insn.branch_target)
                    info.add_branch(BNBranchType.FalseBranch, addr + insn.size)

            elif insn.branch_type == BranchType.CALL:
                if insn.branch_target is not None:
                    info.add_branch(BNBranchType.CallDestination, insn.branch_target)
                else:
                    info.add_branch(BNBranchType.IndirectBranch)

            elif insn.branch_type == BranchType.RETURN:
                info.add_branch(BNBranchType.FunctionReturn)

            elif insn.branch_type == BranchType.TRAP:
                info.add_branch(BNBranchType.SystemCall)

            return info
        except Exception:
            return None

    def get_instruction_text(
        self, data: bytes, addr: int
    ) -> tuple[list[InstructionTextToken], int] | None:
        try:
            insn = self._decoder.decode(data, addr)
            if insn is None:
                return None

            tokens: list[InstructionTextToken] = []

            # Mnemonic
            tokens.append(InstructionTextToken(TT.InstructionToken, insn.name))

            # Operands
            for i, op in enumerate(insn.operands):
                if i == 0:
                    tokens.append(InstructionTextToken(TT.TextToken, " "))
                else:
                    tokens.append(InstructionTextToken(TT.OperandSeparatorToken, ", "))

                if op.type == OperandType.REGISTER:
                    tokens.append(InstructionTextToken(TT.RegisterToken, op.name))

                elif op.type == OperandType.CONDITION:
                    tokens.append(InstructionTextToken(TT.TextToken, op.name))

                elif op.type in (OperandType.LOC16, OperandType.LOC32):
                    tokens.append(InstructionTextToken(
                        TT.BeginMemoryOperandToken, ""
                    ))
                    tokens.append(InstructionTextToken(TT.TextToken, op.name))
                    tokens.append(InstructionTextToken(
                        TT.EndMemoryOperandToken, ""
                    ))

                elif op.type == OperandType.IMMEDIATE:
                    if insn.is_branch and op is insn.operands[0]:
                        target = insn.branch_target or op.value
                        tokens.append(InstructionTextToken(
                            TT.PossibleAddressToken,
                            f"0x{target:X}",
                            target,
                        ))
                    elif op.signed and op.value < 0:
                        tokens.append(InstructionTextToken(
                            TT.IntegerToken, f"-0x{-op.value:X}", op.value
                        ))
                    else:
                        tokens.append(InstructionTextToken(
                            TT.IntegerToken, f"#0x{op.value:X}", op.value
                        ))

            return tokens, insn.size
        except Exception:
            return None

    def get_instruction_low_level_il(self, data: bytes, addr: int, il) -> int | None:
        try:
            insn = self._decoder.decode(data, addr)
            if insn is None:
                return None

            lifted = self._lifter.lift(insn, addr, il)
            if not lifted:
                il.append(il.nop())
            return insn.size
        except Exception:
            return None
