"""TMS320C28x Flash Image BinaryView for Binary Ninja.

Auto-detects raw C28x flash dumps and creates the full F28335 memory map:
- Flash sectors H-A at correct byte addresses
- RAM regions (M0, M1, L0-L7)
- Peripheral MMIO regions with named symbols
- Entry point from reset vector
- ISR functions from PIE vector table
"""

import struct

import binaryninja
from binaryninja import (
    Architecture,
    BinaryView,
    Platform,
    SegmentFlag,
    SectionSemantics,
    SymbolType,
    Symbol,
    log_info,
    log_warn,
)

# ── F28335 Memory Map (word address, word size) ──
# Converted to byte addresses at runtime: byte_addr = word_addr * 2

FLASH_SECTORS = [
    ("FLASH_H", 0x300000, 0x8000),
    ("FLASH_G", 0x308000, 0x8000),
    ("FLASH_F", 0x310000, 0x8000),
    ("FLASH_E", 0x318000, 0x8000),
    ("FLASH_D", 0x320000, 0x8000),
    ("FLASH_C", 0x328000, 0x8000),
    ("FLASH_B", 0x330000, 0x8000),
    ("FLASH_A", 0x338000, 0x7FF8),  # ends at 0x33FFF7
]

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

# Peripheral MMIO: (name, word_base, word_size)
PERIPHERALS = [
    ("eCAN_A",       0x006000, 0x100),
    ("eCAN_B",       0x006200, 0x100),
    ("ePWM1",        0x006800, 0x040),
    ("ePWM2",        0x006840, 0x040),
    ("ePWM3",        0x006880, 0x040),
    ("ePWM4",        0x0068C0, 0x040),
    ("ePWM5",        0x006900, 0x040),
    ("ePWM6",        0x006940, 0x040),
    ("eCAP1",        0x006A00, 0x020),
    ("eCAP2",        0x006A20, 0x020),
    ("eQEP1",        0x006B00, 0x040),
    ("eQEP2",        0x006B40, 0x040),
    ("GPIO_CTRL",    0x006F80, 0x040),
    ("GPIO_DATA",    0x006FC0, 0x020),
    ("GPIO_INT",     0x007070, 0x010),
    ("SPI_A",        0x007040, 0x010),
    ("SCI_A",        0x007050, 0x010),
    ("ADC",          0x007100, 0x020),
    ("SCI_B",        0x007750, 0x010),
    ("SCI_C",        0x007770, 0x010),
    ("I2C_A",        0x007900, 0x040),
    ("DMA",          0x001000, 0x200),
    ("CPU_TIMER0",   0x000C00, 0x008),
    ("CPU_TIMER1",   0x000C08, 0x008),
    ("CPU_TIMER2",   0x000C10, 0x008),
    ("PIE_CTRL",     0x000CE0, 0x020),
    ("PIE_VECT",     0x000D00, 0x100),
    ("SYS_CTRL",     0x007010, 0x020),
    ("FLASH_REGS",   0x000A80, 0x020),
    ("CSM",          0x000AE0, 0x010),
    ("XINTF",        0x000B20, 0x040),
    ("McBSP_A",      0x005000, 0x040),
    ("McBSP_B",      0x005040, 0x040),
]

# Reset vector in word address space
RESET_VECTOR_WORD = 0x3FFFC0

# PIE vector table: 96 vectors starting at word 0x000D00
PIE_VECTOR_BASE_WORD = 0x000D00
PIE_VECTOR_COUNT = 96

# Known flash image sizes (bytes)
KNOWN_FLASH_SIZES = [
    256 * 1024,   # 256KB (128K words)
    512 * 1024,   # 512KB (256K words)
    1024 * 1024,  # 1MB
]


def _w2b(word_addr):
    """Convert word address to byte address."""
    return word_addr * 2


class TMS320C28xFlashView(BinaryView):
    name = "C28x Flash"
    long_name = "TMS320C28x Flash Image (F28335)"

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.raw = data

    @classmethod
    def is_valid_for_data(cls, data) -> bool:
        length = data.length
        if length < 64 * 1024:
            return False

        # Heuristic: check for valid C28x instructions at likely code offsets.
        # Flash H starts at word 0x300000. If file is loaded at byte 0x600000,
        # code typically starts in Flash G (offset 0x10000 bytes into the file).
        # Check for common instruction patterns at that offset.
        code_offset = 0x10000  # Flash G start relative to Flash H
        if length <= code_offset + 4:
            return False

        chunk = data.read(code_offset, 4)
        if not chunk or len(chunk) < 4:
            return False

        # Check for ADDB SP (0xFE00 mask 0xFF80) — very common function prologue
        op16 = chunk[0] | (chunk[1] << 8)
        if (op16 & 0xFF80) == 0xFE00:
            return True

        # Check for MOVW DP (0x761F) — common at function start
        if op16 == 0x761F:
            return True

        # Check for LB (0x0040 mask 0xFFC0) at code_start — boot branch
        if (op16 & 0xFFC0) == 0x0040:
            return True

        # Check for LCR (0x7640 mask 0xFFC0) — function call at code start
        if (op16 & 0xFFC0) == 0x7640:
            return True

        # Check at file start for branch instruction (Flash H, boot sector)
        chunk0 = data.read(0, 4)
        if chunk0 and len(chunk0) >= 2:
            op0 = chunk0[0] | (chunk0[1] << 8)
            # LB (long branch) or LCR (long call) at start of flash
            if (op0 & 0xFFC0) == 0x0040 or (op0 & 0xFFC0) == 0x7640:
                return True

        return False

    def init(self) -> bool:
        try:
            self.arch = Architecture["tms320c28x"]
            self.platform = self.arch.standalone_platform
        except Exception:
            return False

        file_len = self.raw.length

        # Determine base address: Flash H starts at word 0x300000 = byte 0x600000
        flash_h_byte = _w2b(0x300000)

        log_info(f"C28x Flash: loading {file_len} bytes at base 0x{flash_h_byte:X}")

        # ── Flash segments — detect erased sectors first ──
        code_flags = (
            SegmentFlag.SegmentReadable
            | SegmentFlag.SegmentExecutable
            | SegmentFlag.SegmentContainsCode
        )
        data_flags = (
            SegmentFlag.SegmentReadable
            | SegmentFlag.SegmentContainsData
        )

        file_offset = 0
        erased_count = 0
        for name, word_start, word_size in FLASH_SECTORS:
            byte_start = _w2b(word_start)
            byte_size = word_size * 2

            if file_offset + byte_size > file_len:
                remaining = file_len - file_offset
                if remaining <= 0:
                    break
                byte_size = remaining

            # Check if sector is erased (>90% of words are 0xFFFF)
            sector_data = self.raw.read(file_offset, byte_size)
            is_erased = False
            if sector_data and len(sector_data) >= 4:
                ff_words = sum(1 for i in range(0, len(sector_data) - 1, 2)
                               if sector_data[i] == 0xFF and sector_data[i + 1] == 0xFF)
                total_words = len(sector_data) // 2
                if total_words > 0 and ff_words > total_words * 9 // 10:
                    is_erased = True
                    erased_count += 1

            if is_erased:
                self.add_auto_segment(
                    byte_start, byte_size, file_offset, byte_size, data_flags
                )
                self.add_auto_section(
                    name, byte_start, byte_size,
                    SectionSemantics.ReadOnlyDataSectionSemantics,
                )
                log_info(f"C28x Flash: {name} erased — marked as data")
            else:
                self.add_auto_segment(
                    byte_start, byte_size, file_offset, byte_size, code_flags
                )
                self.add_auto_section(
                    name, byte_start, byte_size,
                    SectionSemantics.ReadOnlyCodeSectionSemantics,
                )

            file_offset += byte_size

        if erased_count:
            log_info(f"C28x Flash: {erased_count} erased sectors marked as data")

        # ── RAM segments (non-file-backed, read-write) ──
        ram_flags = (
            SegmentFlag.SegmentReadable
            | SegmentFlag.SegmentWritable
            | SegmentFlag.SegmentContainsData
        )
        for name, word_start, word_size in RAM_REGIONS:
            byte_start = _w2b(word_start)
            byte_size = word_size * 2
            self.add_auto_segment(byte_start, byte_size, 0, 0, ram_flags)
            self.add_auto_section(
                name, byte_start, byte_size, SectionSemantics.ReadWriteDataSectionSemantics
            )

        # ── Peripheral MMIO segments (non-file-backed) ──
        mmio_flags = (
            SegmentFlag.SegmentReadable
            | SegmentFlag.SegmentWritable
        )
        for name, word_start, word_size in PERIPHERALS:
            byte_start = _w2b(word_start)
            byte_size = word_size * 2
            self.add_auto_segment(byte_start, byte_size, 0, 0, mmio_flags)
            self.add_auto_section(
                name, byte_start, byte_size,
                SectionSemantics.ReadWriteDataSectionSemantics,
            )
            # Label the base address
            self.define_auto_symbol(
                Symbol(SymbolType.DataSymbol, byte_start, name)
            )

        # ── Entry point from reset vector ──
        self._find_entry_point(flash_h_byte, file_len)

        # ── Discover functions ──
        # Try PIE vector table first (works if PIE data is in flash range),
        # then scan for function pointer tables in flash data sections.
        self._find_functions_from_pie(flash_h_byte, file_len)
        self._find_functions_from_pointer_tables(flash_h_byte, file_len)

        return True

    def _find_entry_point(self, flash_base, file_len):
        """Parse reset vector to find the boot entry point."""
        reset_byte = _w2b(RESET_VECTOR_WORD)
        file_offset = reset_byte - flash_base

        if 0 <= file_offset < file_len - 3:
            data = self.raw.read(file_offset, 4)
            if data and len(data) >= 4:
                # Reset vector contains a 22-bit word address (stored as 32-bit)
                entry_word = struct.unpack_from("<I", data)[0] & 0x3FFFFF
                entry_byte = _w2b(entry_word)
                log_info(f"C28x Flash: reset vector -> entry at 0x{entry_byte:X}")
                self.add_entry_point(entry_byte)
                self.define_auto_symbol(
                    Symbol(SymbolType.FunctionSymbol, entry_byte, "_reset_entry")
                )
                return

        # Fallback: assume code starts at Flash G
        flash_g_byte = _w2b(0x308000)
        log_info(f"C28x Flash: no reset vector found, using Flash G start 0x{flash_g_byte:X}")
        self.add_entry_point(flash_g_byte)

    def _find_functions_from_pie(self, flash_base, file_len):
        """Parse PIE vector table entries and create ISR functions."""
        pie_byte = _w2b(PIE_VECTOR_BASE_WORD)
        file_offset = pie_byte - flash_base

        if file_offset < 0 or file_offset >= file_len:
            return

        # Flash code range (byte addresses)
        code_start = _w2b(0x300000)
        code_end = _w2b(0x340000)

        count = 0
        for i in range(PIE_VECTOR_COUNT):
            vec_file_off = file_offset + i * 4
            if vec_file_off + 4 > file_len:
                break

            data = self.raw.read(vec_file_off, 4)
            if not data or len(data) < 4:
                continue

            isr_word = struct.unpack_from("<I", data)[0] & 0x3FFFFF
            isr_byte = _w2b(isr_word)

            # Only create functions for vectors pointing into flash code
            if code_start <= isr_byte < code_end:
                group = (i // 8) + 1
                vector = (i % 8) + 1
                name = f"PIE_{group}_{vector}_ISR"
                self.define_auto_symbol(
                    Symbol(SymbolType.FunctionSymbol, isr_byte, name)
                )
                self.add_function(isr_byte)
                count += 1

        if count:
            log_info(f"C28x Flash: found {count} ISR functions from PIE vector table")

    def _find_functions_from_pointer_tables(self, flash_base, file_len):
        """Scan flash for function pointer tables (PIE init data, jump tables, callbacks).

        Looks for sequences of 4+ consecutive 32-bit values that are valid
        flash code addresses. These are typically ISR vector init tables or
        callback arrays stored in .const sections.
        """
        # Only accept pointers into actual flash sectors (not Boot ROM, OTP, etc.)
        code_start = flash_base  # byte addr of Flash H
        code_end = flash_base + file_len  # end of file-backed flash

        total_found = 0
        offset = 0
        while offset < file_len - 15:
            # Try to find a run of consecutive valid code pointers
            run_start = offset
            run_count = 0
            scan = offset
            while scan + 3 < file_len:
                data = self.raw.read(scan, 4)
                if not data or len(data) < 4:
                    break
                # Read full 32-bit value — don't mask to 22 bits (avoids Boot ROM aliasing)
                raw_val = struct.unpack_from("<I", data)[0]
                word_addr = raw_val & 0x3FFFFF
                byte_addr = _w2b(word_addr)
                # Reject if high bits set (not a valid 22-bit address)
                if raw_val != word_addr:
                    break
                if code_start <= byte_addr < code_end:
                    run_count += 1
                    scan += 4
                else:
                    break

            if run_count >= 4:
                # Found a pointer table — create functions only in file-backed code segments
                for i in range(run_count):
                    data = self.raw.read(run_start + i * 4, 4)
                    word_addr = struct.unpack_from("<I", data)[0] & 0x3FFFFF
                    byte_addr = _w2b(word_addr)
                    seg = self.get_segment_at(byte_addr)
                    if seg and seg.executable:
                        self.add_function(byte_addr)
                total_found += run_count
                log_info(
                    f"C28x Flash: {run_count}-entry pointer table at "
                    f"file offset 0x{run_start:X}"
                )
                offset = scan
            else:
                offset += 4

        if total_found:
            log_info(f"C28x Flash: found {total_found} functions from pointer tables")

    def _find_functions_from_prologues(self, flash_base, file_len):
        """Scan flash for ADDB SP prologues to discover functions."""
        code_start_offset = _w2b(0x308000) - flash_base  # Flash G
        code_end_offset = min(file_len, _w2b(0x340000) - flash_base)

        if code_start_offset < 0:
            code_start_offset = 0

        count = 0
        offset = code_start_offset
        while offset < code_end_offset - 1:
            data = self.raw.read(offset, 2)
            if data and len(data) >= 2:
                op16 = data[0] | (data[1] << 8)
                if (op16 & 0xFF80) == 0xFE00:
                    byte_addr = flash_base + offset
                    self.add_function(byte_addr)
                    count += 1
            offset += 2

        if count:
            log_info(f"C28x Flash: found {count} functions from ADDB_SP prologues")

    def perform_is_executable(self) -> bool:
        return True

    def perform_get_address_size(self) -> int:
        return 4

    def perform_get_entry_point(self) -> int:
        return _w2b(0x308000)  # Flash G default

    def perform_get_default_endianness(self):
        return binaryninja.Endianness.LittleEndian


TMS320C28xFlashView.register()
