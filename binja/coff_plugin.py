"""TI COFF BinaryView plugin for Binary Ninja.

Auto-detects TI COFF2 .out files from cl2000 and loads them with the
tms320c28x architecture. Handles section mapping, symbol import, and
entry point detection.

Self-contained — does not depend on the c28x Python package.
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
    log_info,
    log_warn,
)

COFF_MAGIC_C2000 = 0x00C2
STYP_TEXT = 0x0020
STYP_DATA = 0x0040
STYP_BSS = 0x0080
C_EXT = 2
C_LABEL = 6


def _read_string(data, offset):
    if offset >= len(data):
        return ""
    end = data.index(b"\x00", offset) if b"\x00" in data[offset:] else len(data)
    return data[offset:end].decode("ascii", errors="replace")


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
            log_warn("tms320c28x architecture not registered")
            return False

        raw_bytes = self.raw.read(0, self.raw.length)
        if len(raw_bytes) < 22:
            return False

        magic = struct.unpack_from("<H", raw_bytes, 0)[0]
        if magic != COFF_MAGIC_C2000:
            return False

        num_sections = struct.unpack_from("<H", raw_bytes, 2)[0]
        symtab_offset = struct.unpack_from("<I", raw_bytes, 8)[0]
        num_symbols = struct.unpack_from("<I", raw_bytes, 12)[0]
        opt_hdr_size = struct.unpack_from("<H", raw_bytes, 16)[0]
        hdr_size = 22 + opt_hdr_size

        log_info(f"TI COFF: {num_sections} sections, {num_symbols} symbols")

        # Parse sections
        text_section_nums = set()
        for i in range(num_sections):
            sh = hdr_size + i * 48
            if sh + 48 > len(raw_bytes):
                break

            raw_name = raw_bytes[sh:sh + 8]
            if raw_name[:4] == b"\x00\x00\x00\x00":
                str_off = struct.unpack_from("<I", raw_name, 4)[0]
                name = _read_string(raw_bytes, symtab_offset + num_symbols * 18 + str_off)
            else:
                name = raw_name.rstrip(b"\x00").decode("ascii", errors="replace")

            phys_addr = struct.unpack_from("<I", raw_bytes, sh + 8)[0]
            sec_size = struct.unpack_from("<I", raw_bytes, sh + 16)[0]
            data_ptr = struct.unpack_from("<I", raw_bytes, sh + 20)[0]
            sec_flags = struct.unpack_from("<I", raw_bytes, sh + 40)[0]

            byte_addr = phys_addr * 2  # word → byte
            byte_size = sec_size * 2

            if byte_size == 0:
                continue
            if name.startswith("$") or name.startswith(".debug"):
                continue

            flags = SegmentFlag.SegmentReadable
            if sec_flags & STYP_TEXT:
                flags |= SegmentFlag.SegmentExecutable | SegmentFlag.SegmentContainsCode
                semantics = SectionSemantics.ReadOnlyCodeSectionSemantics
                text_section_nums.add(i + 1)
            elif sec_flags & STYP_DATA:
                flags |= SegmentFlag.SegmentContainsData
                semantics = SectionSemantics.ReadOnlyDataSectionSemantics
            elif sec_flags & STYP_BSS:
                flags |= SegmentFlag.SegmentWritable | SegmentFlag.SegmentContainsData
                semantics = SectionSemantics.ReadWriteDataSectionSemantics
            else:
                semantics = SectionSemantics.DefaultSectionSemantics

            if data_ptr > 0 and sec_size > 0 and not (sec_flags & STYP_BSS):
                file_data_len = min(byte_size, len(raw_bytes) - data_ptr)
                if file_data_len > 0:
                    self.add_auto_segment(byte_addr, byte_size, data_ptr, file_data_len, flags)
            else:
                self.add_auto_segment(byte_addr, byte_size, 0, 0, flags)

            self.add_auto_section(name, byte_addr, byte_size, semantics)

        # Parse symbols
        if symtab_offset > 0 and num_symbols > 0:
            strtab_offset = symtab_offset + num_symbols * 18
            i = 0
            while i < num_symbols:
                so = symtab_offset + i * 18
                if so + 18 > len(raw_bytes):
                    break

                raw_name = raw_bytes[so:so + 8]
                if raw_name[:4] == b"\x00\x00\x00\x00":
                    str_off = struct.unpack_from("<I", raw_name, 4)[0]
                    name = _read_string(raw_bytes, strtab_offset + str_off)
                else:
                    name = raw_name.rstrip(b"\x00").decode("ascii", errors="replace")

                value = struct.unpack_from("<I", raw_bytes, so + 8)[0]
                sec_num = struct.unpack_from("<h", raw_bytes, so + 12)[0]
                sclass = raw_bytes[so + 16]
                num_aux = raw_bytes[so + 17]

                if name and not name.startswith(".") and value != 0:
                    byte_addr = value * 2

                    # Strip TI C underscore prefix for display
                    display_name = name
                    if display_name.startswith("_") and not display_name.startswith("__"):
                        display_name = display_name[1:]

                    if sclass in (C_EXT, C_LABEL) and sec_num in text_section_nums:
                        self.define_auto_symbol(
                            Symbol(SymbolType.FunctionSymbol, byte_addr, display_name)
                        )
                        self.add_function(byte_addr)
                    elif sclass in (C_EXT, 3):  # C_STAT
                        self.define_auto_symbol(
                            Symbol(SymbolType.DataSymbol, byte_addr, display_name)
                        )

                i += 1 + num_aux

        # Entry point: look for _c_int00 or code_start
        for f in self.functions:
            if f.name in ("c_int00", "_c_int00", "code_start"):
                self.add_entry_point(f.start)
                break

        return True

    def perform_is_executable(self) -> bool:
        return True

    def perform_get_address_size(self) -> int:
        return 4

    def perform_get_entry_point(self) -> int:
        return 0

    def perform_get_default_endianness(self):
        return binaryninja.Endianness.LittleEndian


TICOFFView.register()
