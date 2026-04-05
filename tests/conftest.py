# SPDX-License-Identifier: MIT
"""Shared test fixtures including the reference firmware assembler."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest


def _encode16(opcode: int) -> bytes:
    """Encode a 16-bit opcode to 2 little-endian bytes."""
    return struct.pack("<H", opcode)


def _encode32(opcode: int) -> bytes:
    """Encode a 32-bit opcode to 4 little-endian bytes.

    C28x byte order: first word (HIGH 16 bits of opcode) goes first in memory.
    """
    word0 = (opcode >> 16) & 0xFFFF  # HIGH half
    word1 = opcode & 0xFFFF          # LOW half
    return struct.pack("<HH", word0, word1)


# Reference firmware: minimal LED blink modeled after TI C2000Ware blinky.
#
# Each entry: (word_addr, opcode, size_bytes, yaml_name, comment)
#
# Memory layout (byte_addr = word_addr * 2):
#   0x000 (byte 0x000): _c_int00
#   0x010 (byte 0x020): main
#   0x020 (byte 0x040): init_system
#   0x02C (byte 0x058): init_gpio
#   0x038 (byte 0x070): gpio_toggle
#   0x044 (byte 0x088): delay
FIRMWARE_DEF = [
    # === _c_int00 (CRT entry) @ word 0x000 ===
    (0x000, 0x76400010, 4, "LCR",    "LCR main"),          # call main
    (0x002, 0x7625,     2, "ESTOP0", "halt if main returns"),

    # === main @ word 0x010 ===
    (0x010, 0xFE02,     2, "ADDB_SP_CONST7",  "ADDB SP,#2 (frame)"),
    (0x011, 0x76400020, 4, "LCR",             "LCR init_system"),
    (0x013, 0x7640002C, 4, "LCR",             "LCR init_gpio"),
    # loop @ word 0x015:
    (0x015, 0x76400038, 4, "LCR",             "LCR gpio_toggle"),
    (0x017, 0x9AFF,     2, "MOVB_AX_CONST8",  "MOVB AL,#0xFF (delay arg)"),
    (0x018, 0x76400044, 4, "LCR",             "LCR delay"),
    (0x01A, 0x6FFA,     2, "SB",              "SB loop(-6), UNC"),  # back to 0x015
    # (unreachable)
    (0x01B, 0xFE82,     2, "SUBB_SP_CONST7",  "SUBB SP,#2"),
    (0x01C, 0x0006,     2, "LRETR",           "return"),

    # === init_system @ word 0x020 ===
    (0x020, 0x7622,     2, "EALLOW",           "EALLOW"),
    (0x021, 0x761F01C0, 4, "MOVW_DP_CONST16",  "MOVW DP,#0x01C0"),  # DP page for WD
    (0x023, 0x9A68,     2, "MOVB_AX_CONST8",  "MOVB AL,#0x68"),     # WD disable value
    (0x024, 0x9629,     2, "MOV_LOC16_AX",    "MOV @0x29,AL"),      # write WDCR (DP+0x29)
    (0x025, 0x761A,     2, "EDIS",            "EDIS"),
    (0x026, 0x0006,     2, "LRETR",           "return"),

    # === init_gpio @ word 0x02C ===
    (0x02C, 0x7622,     2, "EALLOW",           "EALLOW"),
    (0x02D, 0x761F01F2, 4, "MOVW_DP_CONST16",  "MOVW DP,#0x01F2"),  # DP for GPIO
    (0x02F, 0x9A01,     2, "MOVB_AX_CONST8",  "MOVB AL,#0x01"),     # bit 0
    (0x030, 0x9600,     2, "MOV_LOC16_AX",    "MOV @0,AL"),          # GPADIR
    (0x031, 0x761A,     2, "EDIS",            "EDIS"),
    (0x032, 0x0006,     2, "LRETR",           "return"),

    # === gpio_toggle @ word 0x038 ===
    (0x038, 0x761F01FC, 4, "MOVW_DP_CONST16",  "MOVW DP,#0x01FC"),  # DP for toggle reg
    (0x03A, 0x9A01,     2, "MOVB_AX_CONST8",  "MOVB AL,#0x01"),
    (0x03B, 0x9606,     2, "MOV_LOC16_AX",    "MOV @6,AL"),          # GPATOGGLE
    (0x03C, 0x0006,     2, "LRETR",           "return"),

    # === delay @ word 0x044 ===
    # delay(count in AL): while (count != 0) count--;
    (0x044, 0xFE02,     2, "ADDB_SP_CONST7",  "ADDB SP,#2 (frame)"),
    (0x045, 0x9641,     2, "MOV_LOC16_AX",    "MOV *-SP[1],AL"),     # save count
    # loop @ word 0x046:
    (0x046, 0x9241,     2, "MOV_AX_LOC16",    "MOV AL,*-SP[1]"),     # load count
    (0x047, 0x5200,     2, "CMPB_AX_CONST8",  "CMPB AL,#0"),         # count == 0?
    (0x048, 0x6103,     2, "SB",              "SB done(+3), EQ"),    # if zero, exit
    (0x049, 0x0B41,     2, "DEC_LOC16",       "DEC *-SP[1]"),        # count--
    (0x04A, 0x6FFB,     2, "SB",              "SB loop(-5), UNC"),   # back to 0x046
    # done @ word 0x04B (byte 0x096):
    (0x04B, 0xFE82,     2, "SUBB_SP_CONST7",  "SUBB SP,#2"),
    (0x04C, 0x0006,     2, "LRETR",           "return"),
]

# Function table: (name, word_addr, byte_addr)
FUNCTIONS = [
    ("_c_int00",     0x000, 0x000),
    ("main",         0x010, 0x020),
    ("init_system",  0x020, 0x040),
    ("init_gpio",    0x02C, 0x058),
    ("gpio_toggle",  0x038, 0x070),
    ("delay",        0x044, 0x088),
]


def build_firmware() -> bytes:
    """Assemble the reference firmware into a raw binary blob.

    Returns bytes where byte offset = word_addr * 2.
    The binary is padded with zeros between functions.
    """
    # Find total size needed
    max_end = 0
    for word_addr, opcode, size, _, _ in FIRMWARE_DEF:
        byte_end = word_addr * 2 + size
        if byte_end > max_end:
            max_end = byte_end

    buf = bytearray(max_end)

    for word_addr, opcode, size, _, _ in FIRMWARE_DEF:
        byte_addr = word_addr * 2
        if size == 2:
            data = _encode16(opcode)
        else:
            data = _encode32(opcode)
        buf[byte_addr:byte_addr + size] = data

    return bytes(buf)


def write_firmware_bin():
    """Write the firmware to tests/fixtures/blinky.bin."""
    fw = build_firmware()
    out = Path(__file__).parent / "fixtures" / "blinky.bin"
    out.write_bytes(fw)
    return out


@pytest.fixture
def firmware_bytes():
    """The raw reference firmware binary."""
    return build_firmware()


@pytest.fixture
def firmware_def():
    """The firmware definition table."""
    return FIRMWARE_DEF


@pytest.fixture
def function_table():
    """The expected function table."""
    return FUNCTIONS
