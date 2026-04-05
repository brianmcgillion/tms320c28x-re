# SPDX-License-Identifier: MIT
"""TI COFF BinaryView for Binary Ninja.

Automatically recognizes TI COFF (.out) files produced by cl2000,
loads sections at their correct addresses, and creates functions
from the symbol table.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

from binaryninja import (
    Architecture,
    BinaryView,
    Platform,
    SegmentFlag,
    SectionSemantics,
    SymbolType,
    Symbol,
    log_info,
)

_project_root = str(Path(__file__).parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from c28x.coff import parse_coff, CoffFile, COFF_MAGIC_C2000, STYP_TEXT, STYP_DATA, STYP_BSS


class TICOFFView(BinaryView):
    name = "TI COFF"
    long_name = "TI COFF (C2000)"

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.raw = data

    @classmethod
    def is_valid_for_data(cls, data) -> bool:
        hdr = data.read(0, 2)
        if not hdr or len(hdr) < 2:
            return False
        magic = struct.unpack_from("<H", hdr)[0]
        return magic == COFF_MAGIC_C2000

    def init(self) -> bool:
        try:
            self.arch = Architecture["tms320c28x"]
            self.platform = self.arch.standalone_platform
        except Exception:
            return False

        raw_bytes = self.raw.read(0, self.raw.length)
        try:
            coff = parse_coff_from_bytes(raw_bytes)
        except Exception as e:
            log_info(f"TI COFF parse error: {e}")
            return False

        self._load_segments(coff)
        self._load_symbols(coff)

        # Define entry point
        entry = coff.get_symbol("_c_int00")
        if entry:
            self.add_entry_point(entry.byte_addr)

        return True

    def _load_segments(self, coff: CoffFile):
        for sec in coff.sections:
            if not sec.data and not (sec.flags & STYP_BSS):
                continue
            if sec.name.startswith("$") or sec.name.startswith(".debug"):
                continue

            byte_addr = sec.byte_addr
            byte_size = len(sec.data) if sec.data else sec.size * 2

            if byte_size == 0:
                continue

            # Determine segment flags
            flags = SegmentFlag.SegmentReadable
            if sec.is_text:
                flags |= SegmentFlag.SegmentExecutable | SegmentFlag.SegmentContainsCode
                semantics = SectionSemantics.ReadOnlyCodeSectionSemantics
            elif sec.is_data:
                flags |= SegmentFlag.SegmentContainsData
                semantics = SectionSemantics.ReadOnlyDataSectionSemantics
            elif sec.flags & STYP_BSS:
                flags |= SegmentFlag.SegmentWritable | SegmentFlag.SegmentContainsData
                semantics = SectionSemantics.ReadWriteDataSectionSemantics
            else:
                semantics = SectionSemantics.DefaultSectionSemantics

            if sec.data:
                self.add_auto_segment(byte_addr, byte_size, sec.data_offset,
                                      len(sec.data), flags)
            else:
                # BSS — no file data
                self.add_auto_segment(byte_addr, byte_size, 0, 0, flags)

            self.add_auto_section(sec.name, byte_addr, byte_size, semantics)

    def _load_symbols(self, coff: CoffFile):
        text_nums = {i + 1 for i, s in enumerate(coff.sections) if s.is_text}

        for sym in coff.symbols:
            if sym.value == 0:
                continue
            # Skip compiler-generated labels
            if sym.name.startswith("$C$") or sym.name.startswith("__"):
                continue

            byte_addr = sym.byte_addr

            if sym.is_function and sym.section_num in text_nums:
                # Strip leading underscore (TI convention)
                display_name = sym.name
                if display_name.startswith("_") and not display_name.startswith("__"):
                    display_name = display_name[1:]

                self.define_auto_symbol(
                    Symbol(SymbolType.FunctionSymbol, byte_addr, display_name)
                )
                self.add_function(byte_addr)
            elif sym.storage_class in (2, 3):  # C_EXT, C_STAT
                display_name = sym.name.lstrip("_")
                self.define_auto_symbol(
                    Symbol(SymbolType.DataSymbol, byte_addr, display_name)
                )

    def perform_is_executable(self) -> bool:
        return True

    def perform_get_entry_point(self) -> int:
        return 0


def parse_coff_from_bytes(data: bytes) -> CoffFile:
    """Parse COFF from raw bytes (avoids file I/O)."""
    from c28x.coff import _parse
    return _parse(data)
