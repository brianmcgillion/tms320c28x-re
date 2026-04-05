# SPDX-License-Identifier: MIT
"""loc16/loc32 addressing mode decoder.

Reference: TI SPRU430F Chapter 5; INL bn-tic28x-arch text.cpp lines 129-227.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto


class AddressingMode(Enum):
    DP_DIRECT = auto()       # @offset (DP-relative)
    SP_RELATIVE = auto()     # *-SP[offset]
    INDIRECT = auto()        # *XARn
    INDIRECT_POST_INC = auto()   # *XARn++
    INDIRECT_PRE_DEC = auto()    # *--XARn
    INDIRECT_AR0 = auto()    # *+XARn[AR0]
    INDIRECT_AR1 = auto()    # *+XARn[AR1]
    REGISTER_DIRECT = auto() # @AH, @AL, @PH, etc.
    ARP_INDIRECT = auto()    # C2xLP compatibility


@dataclass
class ResolvedOperand:
    """Result of decoding a loc16/loc32 field."""
    mode: AddressingMode
    text: str              # Disassembly text representation
    register: str | None = None   # Register name for register-direct
    xar_index: int | None = None  # XARn index for indirect modes
    offset: int = 0               # Offset for DP/SP modes


# loc16 register-direct codes (bits [7:0])
LOC16_REGS = {
    0xA8: "AH",
    0xA9: "AL",
    0xAA: "PH",
    0xAB: "PL",
    0xAC: "T",
    0xAD: "SP",
}

# loc32 register-direct codes
LOC32_REGS = {
    0xA8: "ACC",
    0xAA: "P",
    0xAC: "XT",
}


def decode_loc16(field: int) -> ResolvedOperand:
    """Decode an 8-bit loc16 addressing mode field."""
    # Check register-direct special codes first
    if field in LOC16_REGS:
        reg = LOC16_REGS[field]
        return ResolvedOperand(
            mode=AddressingMode.REGISTER_DIRECT,
            text=f"@{reg}",
            register=reg,
        )

    return _decode_loc_common(field)


def decode_loc32(field: int) -> ResolvedOperand:
    """Decode an 8-bit loc32 addressing mode field."""
    if field in LOC32_REGS:
        reg = LOC32_REGS[field]
        return ResolvedOperand(
            mode=AddressingMode.REGISTER_DIRECT,
            text=f"@{reg}",
            register=reg,
        )

    return _decode_loc_common(field)


def _decode_loc_common(field: int) -> ResolvedOperand:
    """Common decode logic for loc16/loc32 (non-register modes)."""
    category = (field >> 6) & 0x3

    if category == 0b00:
        # DP-direct: offset = bits [5:0]
        offset = field & 0x3F
        return ResolvedOperand(
            mode=AddressingMode.DP_DIRECT,
            text=f"@{offset}",
            offset=offset,
        )

    if category == 0b01:
        # SP-relative: offset = bits [5:0]
        offset = field & 0x3F
        return ResolvedOperand(
            mode=AddressingMode.SP_RELATIVE,
            text=f"*-SP[{offset}]",
            offset=offset,
        )

    if category == 0b10:
        # Indirect / register-direct (complex sub-decode)
        sub_mode = (field >> 3) & 0x1F  # bits [7:3]
        n = field & 0x7                 # bits [2:0] = XARn index

        if sub_mode == 0b10000:  # *XARn
            return ResolvedOperand(
                mode=AddressingMode.INDIRECT,
                text=f"*XAR{n}",
                xar_index=n,
            )
        if sub_mode == 0b10001:  # *XARn++
            return ResolvedOperand(
                mode=AddressingMode.INDIRECT_POST_INC,
                text=f"*XAR{n}++",
                xar_index=n,
            )
        if sub_mode == 0b10010:  # *--XARn
            return ResolvedOperand(
                mode=AddressingMode.INDIRECT_PRE_DEC,
                text=f"*--XAR{n}",
                xar_index=n,
            )
        if sub_mode == 0b10011:  # *+XARn[AR0]
            return ResolvedOperand(
                mode=AddressingMode.INDIRECT_AR0,
                text=f"*+XAR{n}[AR0]",
                xar_index=n,
            )
        if sub_mode == 0b10100:  # *+XARn[AR1]
            return ResolvedOperand(
                mode=AddressingMode.INDIRECT_AR1,
                text=f"*+XAR{n}[AR1]",
                xar_index=n,
            )
        if sub_mode == 0b10101:  # *(0:16bit) absolute addressing
            return ResolvedOperand(
                mode=AddressingMode.INDIRECT,
                text="*(0:16bit)",
            )

        # Other sub-modes in the 10xxxxx range not yet decoded
        return ResolvedOperand(
            mode=AddressingMode.INDIRECT,
            text=f"*ind(0x{field:02X})",
            xar_index=n,
        )

    # category == 0b11: ARP-based (C2xLP compatibility)
    return ResolvedOperand(
        mode=AddressingMode.ARP_INDIRECT,
        text=f"*arp(0x{field:02X})",
    )
