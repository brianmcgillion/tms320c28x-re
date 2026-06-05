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
        # Indirect (complex sub-decode). bits[5:3] = sub-mode, bits[2:0] = n.
        # Empirically derived from dis2000 (TI ground truth); the previous table
        # was shifted by one and rendered category 0b11 as a *arp() fallback.
        sub_mode = (field >> 3) & 0x1F  # bits [7:3]
        n = field & 0x7                 # bits [2:0] = XARn index

        if sub_mode == 0b10000:  # *XARn++
            return ResolvedOperand(
                mode=AddressingMode.INDIRECT_POST_INC,
                text=f"*XAR{n}++",
                xar_index=n,
            )
        if sub_mode == 0b10001:  # *--XARn
            return ResolvedOperand(
                mode=AddressingMode.INDIRECT_PRE_DEC,
                text=f"*--XAR{n}",
                xar_index=n,
            )
        if sub_mode == 0b10010:  # *+XARn[AR0]
            return ResolvedOperand(
                mode=AddressingMode.INDIRECT_AR0,
                text=f"*+XAR{n}[AR0]",
                xar_index=n,
            )
        if sub_mode == 0b10011:  # *+XARn[AR1]
            return ResolvedOperand(
                mode=AddressingMode.INDIRECT_AR1,
                text=f"*+XAR{n}[AR1]",
                xar_index=n,
            )
        if sub_mode == 0b10111:  # SP / circular / post-inc-dec specials (by n)
            specials = {
                0b001: "*++",
                0b010: "*--",
                0b011: "*0++",
                0b100: "*0--",
                0b101: "*SP++",
                0b110: "*--SP",
            }
            if n in specials:
                return ResolvedOperand(
                    mode=AddressingMode.INDIRECT,
                    text=specials[n],
                )

        # Other sub-modes in the 10xxxxx range (absolute *(0:16bit), *BR0++,
        # *ARPn, *ARn%++ ...) consume a 2nd word or are rare; leave a labelled
        # fallback so decode identity/length stay correct.
        return ResolvedOperand(
            mode=AddressingMode.INDIRECT,
            text=f"*ind(0x{field:02X})",
            xar_index=n,
        )

    # category == 0b11: *+XARn[offset], offset = bits[5:3], n = bits[2:0].
    n = field & 0x7
    offset = (field >> 3) & 0x7
    return ResolvedOperand(
        mode=AddressingMode.INDIRECT,
        text=f"*+XAR{n}[{offset}]",
        xar_index=n,
        offset=offset,
    )
