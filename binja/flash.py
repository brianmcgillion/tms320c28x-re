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
    SegmentFlag,
    SectionSemantics,
    SymbolType,
    Symbol,
    Type,
    log_info,
    log_warn,
)

from .memmap import PERIPHERALS, RAM_REGIONS
from .patterns import is_function_prologue

# Padding-pattern thresholds (words).
# 0xFFFF (and 0xFFFFFFFF) decodes as `B PC, UNC` (branch-to-next-instruction) per
# isa/instructions/branch.yaml. Even a 2-word run inside a function's tail will
# pull adjacent code in via that "branch." Threshold is low (>=2 words = 4 bytes).
PAD_FFFF_MIN_WORDS = 2
# 0x7625 (ESTOP0) is the cl2000 synthetic fixture's sector filler. Phase 1
# already terminates each ESTOP0 individually via no_ret; we only mark long
# runs as data to avoid clutter and protect against any remaining edge cases.
# Threshold higher because lone ESTOP0 in real code (debug guards) is plausible.
PAD_ESTOP_MIN_WORDS = 8

# ── F28335 Memory Map (word address, word size); see binja/memmap.py ──
# Flash H is the lowest sector; file offset = (word_addr - FLASH_H_WORD) * 2.
FLASH_H_WORD = 0x300000

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


# Reset vector in word address space
RESET_VECTOR_WORD = 0x3FFFC0

# PIE vector table: 96 vectors starting at word 0x000D00
PIE_VECTOR_BASE_WORD = 0x000D00
PIE_VECTOR_COUNT = 96

# Known flash image sizes (bytes)
KNOWN_FLASH_SIZES = [
    256 * 1024,  # 256KB (128K words)
    512 * 1024,  # 512KB (256K words)
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

    @staticmethod
    def _looks_like_code(op16):
        """Words cl2000 puts at the start of a sector's first function."""
        return (
            is_function_prologue(op16)  # ADDB SP, #n
            or op16 == 0x761F  # MOVW DP, #16bit
            or (op16 & 0xFFC0) == 0x0040  # LB  — boot branch
            or (op16 & 0xFFC0) == 0x7640  # LCR — call at sector start
        )

    @classmethod
    def is_valid_for_data(cls, data) -> bool:
        """Claim whole-device flash reads of an F28335.

        This used to accept any file of 64KB or more with something
        code-shaped at the hardcoded byte offset 0x10000, or at 0 -- so it
        claimed unrelated files that happened to look right there, and rejected
        real dumps whose Flash G starts with anything else. The segment layout
        this view builds assumes the file covers flash from word 0x300000, so
        the size has to be a whole-device one; KNOWN_FLASH_SIZES was already
        written down for this and never used.
        """
        length = data.length
        if length not in KNOWN_FLASH_SIZES:
            return False

        # Code may begin in any sector, not only Flash G.
        for name, word_base, _size in FLASH_SECTORS:
            offset = (word_base - FLASH_H_WORD) * 2
            if not 0 <= offset <= length - 2:
                continue
            chunk = data.read(offset, 2)
            if (
                chunk
                and len(chunk) >= 2
                and cls._looks_like_code(chunk[0] | (chunk[1] << 8))
            ):
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
        flash_h_byte = _w2b(FLASH_H_WORD)

        log_info(f"C28x Flash: loading {file_len} bytes at base 0x{flash_h_byte:X}")

        # ── Flash segments — detect erased sectors first ──
        code_flags = (
            SegmentFlag.SegmentReadable
            | SegmentFlag.SegmentExecutable
            | SegmentFlag.SegmentContainsCode
        )
        data_flags = SegmentFlag.SegmentReadable | SegmentFlag.SegmentContainsData

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
                ff_words = sum(
                    1
                    for i in range(0, len(sector_data) - 1, 2)
                    if sector_data[i] == 0xFF and sector_data[i + 1] == 0xFF
                )
                total_words = len(sector_data) // 2
                if total_words > 0 and ff_words > total_words * 9 // 10:
                    is_erased = True
                    erased_count += 1

            if is_erased:
                self.add_auto_segment(
                    byte_start, byte_size, file_offset, byte_size, data_flags
                )
                self.add_auto_section(
                    name,
                    byte_start,
                    byte_size,
                    SectionSemantics.ReadOnlyDataSectionSemantics,
                )
                log_info(f"C28x Flash: {name} erased — marked as data")
            else:
                self.add_auto_segment(
                    byte_start, byte_size, file_offset, byte_size, code_flags
                )
                self.add_auto_section(
                    name,
                    byte_start,
                    byte_size,
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
                name,
                byte_start,
                byte_size,
                SectionSemantics.ReadWriteDataSectionSemantics,
            )

        # ── Peripheral MMIO segments (non-file-backed) ──
        mmio_flags = SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable
        for name, word_start, word_size in PERIPHERALS:
            byte_start = _w2b(word_start)
            byte_size = word_size * 2
            self.add_auto_segment(byte_start, byte_size, 0, 0, mmio_flags)
            self.add_auto_section(
                name,
                byte_start,
                byte_size,
                SectionSemantics.ReadWriteDataSectionSemantics,
            )
            # Label the base address
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, byte_start, name))

        # ── Pre-mark padding runs as data ──
        # Must run BEFORE function discovery / auto-analysis so BN never tries
        # to decode 0xFFFF or 0x7625 padding bytes as instructions.
        self._mark_padding_runs(flash_h_byte, file_len)

        # ── Entry point from reset vector ──
        self._find_entry_point(flash_h_byte, file_len)

        # ── Discover functions ──
        # Try PIE vector table first (works if PIE data is in flash range),
        # then scan for function pointer tables in flash data sections.
        self._find_functions_from_pie(flash_h_byte, file_len)
        self._find_functions_from_pointer_tables(flash_h_byte, file_len)

        return True

    def _mark_padding_runs(self, flash_base, file_len):
        """Scan executable segments for padding patterns and mark as data.

        Two patterns are pre-marked so BN's auto-analysis never decodes them:
          - 0xFFFFFFFF (32-bit) — erased flash. Decodes as `B PC, UNC` per
            isa/instructions/branch.yaml, which pulls adjacent code into the
            preceding function via "branch to next instruction" semantics.
            Threshold: >= PAD_FFFF_MIN_WORDS consecutive 0xFFFF words.
          - 0x7625 (ESTOP0) — cl2000 synthetic fixture filler. Phase 1's
            no_ret() terminates each ESTOP0 individually, but long runs in
            data segments are still better marked as data for clarity.

        Runs are recorded as int(2) data variables; existing function entries
        that overlap a detected run are removed to prevent BN from re-discovering.
        """
        ffff_count = 0
        estop_count = 0

        for seg in self.segments:
            if not seg.executable:
                continue
            seg_off_in_file = seg.start - flash_base
            if seg_off_in_file < 0 or seg_off_in_file >= file_len:
                continue
            read_len = min(seg.end, flash_base + file_len) - seg.start
            if read_len <= 0:
                continue
            data = self.raw.read(seg_off_in_file, read_len)
            if not data or len(data) < 2:
                continue

            ffff_count += self._mark_pattern_runs(
                data, seg.start, 0xFFFF, PAD_FFFF_MIN_WORDS
            )
            estop_count += self._mark_pattern_runs(
                data, seg.start, 0x7625, PAD_ESTOP_MIN_WORDS
            )

        if ffff_count or estop_count:
            log_info(
                f"C28x Flash: marked {ffff_count} 0xFFFF + "
                f"{estop_count} ESTOP0 padding runs as data"
            )

    def _mark_pattern_runs(self, data, base_addr, target_word, min_words):
        """Find runs of `target_word` in `data` and mark them as int(2) vars.

        Returns the number of runs marked.
        """
        runs_marked = 0
        i = 0
        n = len(data)
        target_lo = target_word & 0xFF
        target_hi = (target_word >> 8) & 0xFF
        while i + 1 < n:
            if data[i] == target_lo and data[i + 1] == target_hi:
                # Walk forward collecting the run
                run_start = i
                j = i
                while j + 1 < n and data[j] == target_lo and data[j + 1] == target_hi:
                    j += 2
                run_words = (j - run_start) // 2
                if run_words >= min_words:
                    # One array per run, not one call per word. The count is
                    # also only incremented on success now: the per-word
                    # `except: pass` sat inside the loop, so "marked N runs"
                    # could report N having marked nothing at all.
                    try:
                        self.define_user_data_var(
                            base_addr + run_start, Type.array(Type.int(2), run_words)
                        )
                        runs_marked += 1
                    except Exception as e:
                        log_warn(
                            f"C28x: could not mark padding run at "
                            f"{base_addr + run_start:#x}: {e}"
                        )
                i = j
            else:
                i += 2
        return runs_marked

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
        log_info(
            f"C28x Flash: no reset vector found, using Flash G start 0x{flash_g_byte:X}"
        )
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
                    # Same guard as the scan loop above; an unguarded unpack_from
                    # on a short read raises inside init() and aborts the load.
                    if not data or len(data) < 4:
                        break
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
                if is_function_prologue(op16):
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
