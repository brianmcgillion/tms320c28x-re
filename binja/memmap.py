# SPDX-License-Identifier: MIT
"""The F28335 memory map, in word addresses.

This lived in both flash.py and tools.py, and had already drifted -- the flash
copy had XINTF and the tools copy did not -- so the plugin described different
memory depending on which entry point the user reached it through.

Converted to byte addresses at use: byte_addr = word_addr * 2.
"""

RAM_REGIONS = [
    ("M0_SARAM", 0x000000, 0x0400),
    ("M1_SARAM", 0x000400, 0x0400),
    ("L0_SARAM", 0x008000, 0x1000),
    ("L1_SARAM", 0x009000, 0x1000),
    ("L2_SARAM", 0x00A000, 0x1000),
    ("L3_SARAM", 0x00B000, 0x1000),
    ("L4_SARAM", 0x00C000, 0x1000),
    ("L5_SARAM", 0x00D000, 0x1000),
    ("L6_SARAM", 0x00E000, 0x1000),
    ("L7_SARAM", 0x00F000, 0x1000),
]

PERIPHERALS = [
    ("eCAN_A", 0x006000, 0x100),
    ("eCAN_B", 0x006200, 0x100),
    ("ePWM1", 0x006800, 0x040),
    ("ePWM2", 0x006840, 0x040),
    ("ePWM3", 0x006880, 0x040),
    ("ePWM4", 0x0068C0, 0x040),
    ("ePWM5", 0x006900, 0x040),
    ("ePWM6", 0x006940, 0x040),
    ("eCAP1", 0x006A00, 0x020),
    ("eCAP2", 0x006A20, 0x020),
    ("eQEP1", 0x006B00, 0x040),
    ("eQEP2", 0x006B40, 0x040),
    ("GPIO_CTRL", 0x006F80, 0x040),
    ("GPIO_DATA", 0x006FC0, 0x020),
    ("GPIO_INT", 0x007070, 0x010),
    ("SPI_A", 0x007040, 0x010),
    ("SCI_A", 0x007050, 0x010),
    ("ADC", 0x007100, 0x020),
    ("SCI_B", 0x007750, 0x010),
    ("SCI_C", 0x007770, 0x010),
    ("I2C_A", 0x007900, 0x040),
    ("DMA", 0x001000, 0x200),
    ("CPU_TIMER0", 0x000C00, 0x008),
    ("CPU_TIMER1", 0x000C08, 0x008),
    ("CPU_TIMER2", 0x000C10, 0x008),
    ("PIE_CTRL", 0x000CE0, 0x020),
    ("PIE_VECT", 0x000D00, 0x100),
    ("SYS_CTRL", 0x007010, 0x020),
    ("FLASH_REGS", 0x000A80, 0x020),
    ("CSM", 0x000AE0, 0x010),
    ("XINTF", 0x000B20, 0x040),
    ("McBSP_A", 0x005000, 0x040),
    ("McBSP_B", 0x005040, 0x040),
]
