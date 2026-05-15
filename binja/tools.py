"""TMS320C28x: Remove false function splits.

Adds a menu item under Plugins > TMS320C28x > Remove False Functions
that identifies and removes function entries created by BN's auto-analysis
at addresses that are not call targets and lack ADDB_SP prologues.
"""

import binaryninja
from binaryninja import (
    BackgroundTaskThread,
    PluginCommand,
    SectionSemantics,
    SegmentFlag,
    Symbol,
    SymbolType,
    log_info,
    log_warn,
    interaction,
)


class CleanupTask(BackgroundTaskThread):
    def __init__(self, bv):
        super().__init__("Removing false C28x function splits...", can_cancel=True)
        self.bv = bv

    def run(self):
        bv = self.bv

        if bv.arch is None or bv.arch.name != "tms320c28x":
            log_warn("Not a TMS320C28x binary")
            return

        # Find code region bounds from executable segments
        code_start = None
        code_end = None
        for seg in bv.segments:
            if seg.executable:
                if code_start is None or seg.start < code_start:
                    code_start = seg.start
                if code_end is None or seg.end > code_end:
                    code_end = seg.end

        if code_start is None:
            log_warn("No executable segments found")
            return

        log_info(f"C28x cleanup: scanning {code_start:#x}-{code_end:#x}")

        # Pass 1: collect direct call targets by scanning all instructions
        self.progress = "Scanning for call targets..."
        call_targets = set()
        addr = code_start
        while addr < code_end:
            if self.cancelled:
                return
            info = bv.arch.get_instruction_info(bv.read(addr, 4), addr)
            if info is None or info.length == 0:
                addr += 2
                continue
            for branch in info.branches:
                if branch.type == binaryninja.BranchType.CallDestination and branch.target:
                    call_targets.add(branch.target)
            addr += info.length

        # Pass 2: collect ADDB_SP prologue addresses
        self.progress = "Scanning for prologues..."
        prologue_addrs = set()
        addr = code_start
        while addr < code_end - 1:
            data = bv.read(addr, 2)
            if data and len(data) >= 2:
                op16 = data[0] | (data[1] << 8)
                if (op16 & 0xFF80) == 0xFE00:
                    prologue_addrs.add(addr)
            addr += 2

        # Collect symbol addresses
        symbol_addrs = set()
        for sym in bv.get_symbols():
            if sym.type in (SymbolType.FunctionSymbol, SymbolType.ImportedFunctionSymbol):
                symbol_addrs.add(sym.address)

        # Identify false functions
        # A function is real if ANY of:
        #   - It's a direct call target (LCR/LC/FFC destination)
        #   - It has a user-defined or imported symbol
        #   - It's the entry point
        #   - It has ADDB_SP prologue AND at least one incoming code reference
        # Everything else is a false split from BN's orphan detection.
        self.progress = "Identifying false functions..."
        false_funcs = []
        for func in bv.functions:
            if self.cancelled:
                return
            a = func.start
            if a < code_start or a >= code_end:
                continue
            if a in call_targets:
                continue
            if a in symbol_addrs:
                continue
            if a == bv.entry_point:
                continue
            # ADDB_SP prologue + incoming references = probably real
            if a in prologue_addrs:
                if any(True for _ in bv.get_code_refs(a)):
                    continue
            false_funcs.append(func)

        if not false_funcs:
            log_info("C28x cleanup: no false functions found")
            return

        log_info(
            f"C28x cleanup: found {len(false_funcs)} false functions "
            f"(of {len(bv.functions)} total, {len(call_targets)} call targets, "
            f"{len(prologue_addrs)} prologues)"
        )

        # Remove them
        self.progress = f"Removing {len(false_funcs)} false functions..."
        removed = 0
        for func in false_funcs:
            if self.cancelled:
                break
            bv.remove_user_function(func)
            removed += 1
            if removed % 100 == 0:
                self.progress = f"Removed {removed}/{len(false_funcs)}..."

        log_info(f"C28x cleanup: removed {removed} false functions, {len(bv.functions)} remaining")

        # Re-analyze then run another pass — BN may recreate some orphans
        self.progress = "Re-analyzing..."
        bv.update_analysis_and_wait()

        # Second pass: remove any functions BN recreated during re-analysis
        second_pass = []
        for func in bv.functions:
            a = func.start
            if a < code_start or a >= code_end:
                continue
            if a in call_targets or a in symbol_addrs or a == bv.entry_point:
                continue
            if a in prologue_addrs and any(True for _ in bv.get_code_refs(a)):
                continue
            second_pass.append(func)

        if second_pass:
            self.progress = f"Second pass: removing {len(second_pass)} recreated orphans..."
            for func in second_pass:
                bv.remove_user_function(func)
            log_info(f"C28x cleanup: second pass removed {len(second_pass)} more")

        log_info(f"C28x cleanup: done, {len(bv.functions)} functions final")


def remove_false_functions(bv):
    task = CleanupTask(bv)
    task.start()


PluginCommand.register(
    r"TMS320C28x\Remove False Functions",
    "Remove function entries that lack prologues and are not call targets",
    remove_false_functions,
)


# ── Apply F28335 Memory Map ──

def _w2b(word_addr):
    return word_addr * 2

F28335_PERIPHERALS = [
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
    ("McBSP_A",      0x005000, 0x040),
    ("McBSP_B",      0x005040, 0x040),
]

F28335_RAM = [
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


class ApplyMemoryMapTask(BackgroundTaskThread):
    def __init__(self, bv):
        super().__init__("Applying F28335 memory map...", can_cancel=False)
        self.bv = bv

    def run(self):
        bv = self.bv

        mmio_flags = SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable
        ram_flags = mmio_flags | SegmentFlag.SegmentContainsData

        count = 0
        for name, word_base, word_size in F28335_PERIPHERALS:
            byte_addr = _w2b(word_base)
            byte_size = word_size * 2
            bv.add_auto_segment(byte_addr, byte_size, 0, 0, mmio_flags)
            bv.add_auto_section(name, byte_addr, byte_size,
                                SectionSemantics.ReadWriteDataSectionSemantics)
            bv.define_auto_symbol(
                Symbol(SymbolType.DataSymbol, byte_addr, name)
            )
            count += 1

        for name, word_base, word_size in F28335_RAM:
            byte_addr = _w2b(word_base)
            byte_size = word_size * 2
            bv.add_auto_segment(byte_addr, byte_size, 0, 0, ram_flags)
            bv.add_auto_section(name, byte_addr, byte_size,
                                SectionSemantics.ReadWriteDataSectionSemantics)
            count += 1

        log_info(f"C28x: applied F28335 memory map ({count} regions)")


def apply_memory_map(bv):
    ApplyMemoryMapTask(bv).start()


PluginCommand.register(
    r"TMS320C28x\Apply F28335 Memory Map",
    "Create MMIO and RAM segments with peripheral labels for TMS320F28335",
    apply_memory_map,
)


# ── Find Functions from PIE Vector Table ──

class PIEFunctionTask(BackgroundTaskThread):
    def __init__(self, bv):
        super().__init__("Scanning PIE vector table...", can_cancel=False)
        self.bv = bv

    def run(self):
        bv = self.bv
        import struct

        pie_byte = _w2b(0x000D00)
        code_start = None
        code_end = None
        for seg in bv.segments:
            if seg.executable:
                if code_start is None or seg.start < code_start:
                    code_start = seg.start
                if code_end is None or seg.end > code_end:
                    code_end = seg.end

        if code_start is None:
            log_warn("No executable segments to search")
            return

        count = 0
        for i in range(96):
            vec_addr = pie_byte + i * 4
            data = bv.read(vec_addr, 4)
            if not data or len(data) < 4:
                continue

            isr_word = struct.unpack_from("<I", data)[0] & 0x3FFFFF
            isr_byte = _w2b(isr_word)

            if code_start <= isr_byte < code_end:
                group = (i // 8) + 1
                vector = (i % 8) + 1
                name = f"PIE_{group}_{vector}_ISR"
                bv.define_auto_symbol(
                    Symbol(SymbolType.FunctionSymbol, isr_byte, name)
                )
                bv.add_function(isr_byte)
                count += 1

        if count:
            log_info(f"C28x: found {count} ISR functions from PIE vector table")
        else:
            # PIE table in RAM is empty (raw flash dump) — scan flash for
            # function pointer tables (PIE init data stored in .const)
            log_info("C28x: PIE table empty, scanning flash for pointer tables...")
            self._scan_pointer_tables(bv, code_start, code_end)

    def _scan_pointer_tables(self, bv, code_start, code_end):
        """Scan readable segments for contiguous arrays of flash code pointers."""
        import struct as _struct
        count = 0
        for seg in bv.segments:
            if not seg.readable:
                continue
            offset = seg.start
            while offset + 15 < seg.end:
                run_start = offset
                run_count = 0
                scan = offset
                while scan + 3 < seg.end:
                    data = bv.read(scan, 4)
                    if not data or len(data) < 4:
                        break
                    word_addr = _struct.unpack_from("<I", data)[0] & 0x3FFFFF
                    byte_addr = _w2b(word_addr)
                    if code_start <= byte_addr < code_end:
                        run_count += 1
                        scan += 4
                    else:
                        break
                if run_count >= 4:
                    for i in range(run_count):
                        data = bv.read(run_start + i * 4, 4)
                        word_addr = _struct.unpack_from("<I", data)[0] & 0x3FFFFF
                        byte_addr = _w2b(word_addr)
                        # Only create functions in file-backed executable segments
                        seg = bv.get_segment_at(byte_addr)
                        if seg and seg.executable:
                            bv.add_function(byte_addr)
                    count += run_count
                    offset = scan
                else:
                    offset = run_start + 4
        if count:
            log_info(f"C28x: found {count} functions from pointer tables in flash")
        else:
            log_info("C28x: no pointer tables found in flash")


def find_pie_functions(bv):
    PIEFunctionTask(bv).start()


PluginCommand.register(
    r"TMS320C28x\Find Functions from PIE Table",
    "Parse PIE vector table entries and create ISR functions",
    find_pie_functions,
)


# ── Mark Inline Data ──

class MarkInlineDataTask(BackgroundTaskThread):
    """Scan gaps between functions in flash and mark undecoded regions as data."""

    def __init__(self, bv):
        super().__init__("Marking inline data regions...", can_cancel=True)
        self.bv = bv

    def run(self):
        bv = self.bv

        # Get sorted function boundaries in executable segments
        code_start = None
        code_end = None
        for seg in bv.segments:
            if seg.executable:
                if code_start is None or seg.start < code_start:
                    code_start = seg.start
                if code_end is None or seg.end > code_end:
                    code_end = seg.end

        if code_start is None:
            log_warn("No executable segments found")
            return

        # Collect all addresses covered by functions
        func_ranges = []
        for func in bv.functions:
            for block in func.basic_blocks:
                func_ranges.append((block.start, block.end))
        func_ranges.sort()

        # Find gaps between function blocks
        covered = set()
        for start, end in func_ranges:
            for addr in range(start, end, 2):
                covered.add(addr)

        # Scan gaps: try to decode each word, if it fails → data
        self.progress = "Scanning for inline data..."
        data_regions = []
        region_start = None
        addr = code_start

        while addr < code_end:
            if self.cancelled:
                return

            if addr in covered:
                # Inside a known function block
                if region_start is not None:
                    data_regions.append((region_start, addr - region_start))
                    region_start = None
                addr += 2
                continue

            raw = bv.read(addr, 4)
            if not raw or len(raw) < 2:
                addr += 2
                continue

            info = bv.arch.get_instruction_info(raw, addr)
            if info is None or info.length == 0:
                # Can't decode — this is data
                if region_start is None:
                    region_start = addr
                addr += 2
            else:
                # Valid instruction but not in any function — probably orphan code
                if region_start is not None:
                    data_regions.append((region_start, addr - region_start))
                    region_start = None
                addr += info.length

        if region_start is not None:
            data_regions.append((region_start, code_end - region_start))

        # Also detect contiguous 0xFFFF runs inside code sectors (partial erased regions)
        addr = code_start
        ff_run_start = None
        while addr < code_end - 1:
            if self.cancelled:
                return
            if addr in covered:
                if ff_run_start is not None and addr - ff_run_start >= 8:
                    data_regions.append((ff_run_start, addr - ff_run_start))
                ff_run_start = None
                addr += 2
                continue
            raw = bv.read(addr, 2)
            if raw and len(raw) >= 2 and raw[0] == 0xFF and raw[1] == 0xFF:
                if ff_run_start is None:
                    ff_run_start = addr
                addr += 2
            else:
                if ff_run_start is not None and addr - ff_run_start >= 8:
                    data_regions.append((ff_run_start, addr - ff_run_start))
                ff_run_start = None
                addr += 2
        if ff_run_start is not None and code_end - ff_run_start >= 8:
            data_regions.append((ff_run_start, code_end - ff_run_start))

        # Filter out tiny gaps (< 4 bytes) — likely alignment padding
        data_regions = [(s, sz) for s, sz in data_regions if sz >= 4]

        if not data_regions:
            log_info("C28x: no inline data regions found")
            return

        # Mark data regions
        self.progress = f"Marking {len(data_regions)} data regions..."
        total_bytes = 0
        for start, size in data_regions:
            # Remove any auto-created functions in this range
            for func in bv.get_functions_containing(start):
                if func.start >= start and func.start < start + size:
                    bv.remove_user_function(func)

            # Define as data
            for offset in range(0, size, 2):
                bv.define_user_data_var(start + offset, binaryninja.Type.int(2))
            total_bytes += size

        log_info(
            f"C28x: marked {len(data_regions)} inline data regions "
            f"({total_bytes} bytes total)"
        )


def mark_inline_data(bv):
    MarkInlineDataTask(bv).start()


PluginCommand.register(
    r"TMS320C28x\Mark Inline Data",
    "Detect and mark inline data tables between functions in flash",
    mark_inline_data,
)
