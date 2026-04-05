# SPDX-License-Identifier: MIT
"""Two-stage instruction decoder for TMS320C28x.

Matches the INL bn-tic28x-arch DecodeInstruction algorithm:
1. Try all 16-bit instruction patterns against the first word
2. If no match, read a second word and try all 32-bit patterns
"""

from __future__ import annotations

from c28x.isa import ISA, InstructionDef
from c28x.operands import decode_loc16, decode_loc32
from c28x.types import BranchType, DecodedInstruction, Operand, OperandType
from c28x.util import (
    bytes_to_opcode16,
    bytes_to_opcode32,
    extract_bits,
    sign_extend,
)


class Decoder:
    """C28x instruction decoder using YAML-defined ISA tables."""

    def __init__(self, isa: ISA | None = None, objmode: int = 1):
        self.isa = isa or ISA()
        self.objmode = objmode

    def decode(self, data: bytes, addr: int = 0) -> DecodedInstruction | None:
        """Decode a single instruction from raw bytes.

        Args:
            data: At least 4 bytes of instruction data.
            addr: Address of the instruction (for branch target resolution).

        Returns:
            DecodedInstruction or None if no pattern matches.
        """
        if len(data) < 2:
            return None

        opcode16 = bytes_to_opcode16(data)

        # Stage 1: try 16-bit patterns
        for idef in self.isa.instructions_16:
            if self._matches(opcode16, idef):
                return self._build(idef, opcode16, addr, 2)

        # Stage 2: try 32-bit patterns (need at least 4 bytes)
        if len(data) < 4:
            return None

        opcode32 = bytes_to_opcode32(data)

        for idef in self.isa.instructions_32:
            if self._matches(opcode32, idef):
                return self._build(idef, opcode32, addr, 4)

        return None

    def _matches(self, opcode: int, idef: InstructionDef) -> bool:
        """Check if an opcode matches an instruction definition."""
        if (opcode & idef.mask) != idef.opcode:
            return False
        if idef.objmode is not None and idef.objmode != self.objmode:
            return False
        return True

    def _build(
        self, idef: InstructionDef, opcode: int, addr: int, size: int
    ) -> DecodedInstruction:
        """Build a DecodedInstruction from a matched definition."""
        operands = []
        branch_target = None
        cond_code = None

        for op_def in idef.operands:
            op = self._decode_operand(op_def, opcode)
            operands.append(op)

            if op_def.get("type") == "cond4":
                cond_code = op.value

        # Resolve branch type and target from semantics
        branch_type = self._resolve_branch_type(idef, cond_code)

        if branch_type not in (BranchType.NONE, BranchType.RETURN):
            branch_target = self._resolve_target(idef, opcode, addr, size)

        flags = idef.semantics.get("flags", [])

        return DecodedInstruction(
            name=self._mnemonic(idef, cond_code),
            yaml_name=idef.name,
            full_name=idef.full_name,
            size=size,
            operands=operands,
            opcode=opcode,
            branch_type=branch_type,
            branch_target=branch_target,
            flags_written=flags,
            semantics=idef.semantics,
        )

    def _decode_operand(self, op_def: dict, opcode: int) -> Operand:
        """Decode a single operand from an instruction definition."""
        op_type = op_def.get("type", "")
        bits = op_def.get("bits", [0, 0])
        high, low = bits[0], bits[1]
        raw_value = extract_bits(opcode, high, low)

        if op_type in ("loc16",):
            loc = decode_loc16(raw_value)
            return Operand(
                type=OperandType.LOC16,
                value=raw_value,
                name=loc.text,
                resolved=loc,
            )

        if op_type in ("loc32",):
            loc = decode_loc32(raw_value)
            return Operand(
                type=OperandType.LOC32,
                value=raw_value,
                name=loc.text,
                size=4,
                resolved=loc,
            )

        if op_type == "ax":
            name = "AH" if raw_value else "AL"
            return Operand(type=OperandType.REGISTER, value=raw_value, name=name)

        if op_type == "cond4":
            cond = self.isa.conditions.get(raw_value)
            name = cond.name if cond else f"cond{raw_value}"
            return Operand(type=OperandType.CONDITION, value=raw_value, name=name)

        if op_type == "reg3":
            return Operand(
                type=OperandType.REGISTER,
                value=raw_value,
                name=f"XAR{raw_value}",
                size=4,
            )

        if op_type == "fpu_reg":
            return Operand(
                type=OperandType.REGISTER,
                value=raw_value,
                name=f"R{raw_value}H",
                size=4,
            )

        # Immediate values
        value = raw_value
        if op_def.get("signed", False):
            bit_width = high - low + 1
            value = sign_extend(raw_value, bit_width)

        return Operand(
            type=OperandType.IMMEDIATE,
            value=value,
            name=str(value),
            signed=op_def.get("signed", False),
        )

    def _resolve_branch_type(
        self, idef: InstructionDef, cond_code: int | None
    ) -> BranchType:
        """Determine branch type from instruction semantics."""
        sem_type = idef.semantics.get("type", "")

        if sem_type == "return":
            return BranchType.RETURN
        if sem_type == "call":
            return BranchType.CALL
        if sem_type == "trap":
            return BranchType.TRAP
        if sem_type == "branch":
            return BranchType.UNCONDITIONAL
        if sem_type == "cond_branch":
            if cond_code == 0xF:  # UNC
                return BranchType.UNCONDITIONAL
            return BranchType.CONDITIONAL_TRUE

        return BranchType.NONE

    def _resolve_target(
        self, idef: InstructionDef, opcode: int, addr: int, size: int
    ) -> int | None:
        """Resolve the branch target address."""
        for op_def in idef.operands:
            op_type = op_def.get("type", "")
            bits = op_def.get("bits", [0, 0])
            high, low = bits[0], bits[1]
            raw = extract_bits(opcode, high, low)

            if op_type in ("imm22",):
                # Absolute 22-bit address; convert word addr to byte addr
                return raw * 2

            if op_type in ("imm16", "imm8") and op_def.get("signed", False):
                bit_width = high - low + 1
                offset = sign_extend(raw, bit_width)
                # PC-relative: PC points to next instruction (word address)
                # Convert word addresses to byte addresses for BN
                next_pc_words = (addr // 2) + (size // 2)
                target_words = next_pc_words + offset
                return target_words * 2

        return None

    def _mnemonic(self, idef: InstructionDef, cond_code: int | None) -> str:
        """Generate the display mnemonic, stripping internal suffixes."""
        # Remove internal suffixes like _LOC16, _CONST22 for display
        name = idef.name
        for suffix in (
            "_LOC16", "_LOC32", "_CONST22", "_CONST16", "_CONST8",
            "_CONST7", "_CONST10", "_SHIFT", "_XARN", "_XAR7",
            "_MEM32", "_RAH", "_RBH", "_STF", "_COND", "_PMA",
            "_ABS16", "_16FHI", "_PAR", "_LOAD", "_STORE",
        ):
            name = name.replace(suffix, "")

        # Clean up double underscores from suffix removal
        while "__" in name:
            name = name.replace("__", "_")
        name = name.rstrip("_")

        return name
