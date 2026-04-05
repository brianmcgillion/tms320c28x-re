# SPDX-License-Identifier: MIT
"""Byte-to-opcode conversion for C28x.

The C28x uses 16-bit words in little-endian byte order. For 32-bit
instructions, the first word in memory becomes the HIGH 16 bits of
the opcode value. This matches the INL bn-tic28x-arch DataToOpcode.
"""


def bytes_to_opcode16(data: bytes) -> int:
    """Convert 2 bytes to a 16-bit opcode (little-endian word)."""
    return data[1] << 8 | data[0]


def bytes_to_opcode32(data: bytes) -> int:
    """Convert 4 bytes to a 32-bit opcode.

    First 16-bit word becomes the HIGH half:
        word0 = data[1]<<8 | data[0]  (bits [31:16])
        word1 = data[3]<<8 | data[2]  (bits [15:0])
    """
    return (data[1] << 24) | (data[0] << 16) | (data[3] << 8) | data[2]


def sign_extend(value: int, bits: int) -> int:
    """Sign-extend a value from the given bit width to Python int."""
    sign_bit = 1 << (bits - 1)
    return (value ^ sign_bit) - sign_bit


def extract_bits(value: int, high: int, low: int) -> int:
    """Extract bits [high:low] from value (inclusive)."""
    mask = (1 << (high - low + 1)) - 1
    return (value >> low) & mask
