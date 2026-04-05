# SPDX-License-Identifier: MIT
"""TI COFF (Common Object File Format) parser for TMS320C28x.

Parses TI COFF2 files (.out) produced by cl2000 to extract:
- Section headers (code, data, BSS) with load addresses
- Symbol table (function names, addresses)
- Raw code bytes for disassembly

Reference: TI SPRU513 "TMS320C28x Assembly Language Tools User's Guide",
           Chapter 12 "Common Object File Format"
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path


# TI COFF magic numbers
COFF_MAGIC_C2000 = 0x00C2  # TMS320C2000

# Section type flags
STYP_TEXT = 0x0020    # Executable code
STYP_DATA = 0x0040    # Initialized data
STYP_BSS = 0x0080     # Uninitialized data
STYP_COPY = 0x0010    # Copy section (linker directives)

# Symbol storage classes
C_EXT = 2      # External symbol
C_STAT = 3     # Static
C_LABEL = 6    # Label
C_FCN = 101    # Function begin/end (.bf/.ef)


@dataclass
class Section:
    name: str
    phys_addr: int      # Physical (load) address in words
    virt_addr: int       # Virtual address in words
    size: int            # Size in bytes
    data_offset: int     # File offset to raw data
    flags: int
    data: bytes = b""

    @property
    def is_text(self) -> bool:
        return bool(self.flags & STYP_TEXT)

    @property
    def is_data(self) -> bool:
        return bool(self.flags & STYP_DATA)

    @property
    def byte_addr(self) -> int:
        """Convert word address to byte address for BN."""
        return self.phys_addr * 2


@dataclass
class Symbol:
    name: str
    value: int           # Address (word address)
    section_num: int     # 1-based section index
    storage_class: int

    @property
    def byte_addr(self) -> int:
        return self.value * 2

    @property
    def is_function(self) -> bool:
        # Heuristic: external symbols in .text sections are likely functions
        return self.storage_class in (C_EXT, C_LABEL)


@dataclass
class CoffFile:
    """Parsed TI COFF file."""
    sections: list[Section] = field(default_factory=list)
    symbols: list[Symbol] = field(default_factory=list)

    @property
    def text_sections(self) -> list[Section]:
        return [s for s in self.sections if s.is_text]

    def get_symbol(self, name: str) -> Symbol | None:
        for s in self.symbols:
            if s.name == name:
                return s
        return None

    def get_functions(self) -> list[Symbol]:
        """Return symbols that are likely functions (external, in .text)."""
        text_nums = {i + 1 for i, s in enumerate(self.sections) if s.is_text}
        return [
            s for s in self.symbols
            if s.is_function and s.section_num in text_nums and s.value != 0
        ]

    def read_at(self, word_addr: int, num_bytes: int) -> bytes | None:
        """Read bytes from the loaded image at a word address."""
        for section in self.sections:
            sec_end = section.phys_addr + len(section.data) // 2
            if section.phys_addr <= word_addr < sec_end:
                byte_offset = (word_addr - section.phys_addr) * 2
                return section.data[byte_offset:byte_offset + num_bytes]
        return None

    def extract_flat_binary(self) -> tuple[bytes, int]:
        """Extract all .text sections into a flat binary blob.

        Returns (data, base_word_addr). Byte offset into data for a given
        word address is (word_addr - base_word_addr) * 2.
        """
        text = self.text_sections
        if not text:
            return b"", 0

        base = min(s.phys_addr for s in text)
        # End = max word address + word count of section data
        end = max(s.phys_addr + len(s.data) // 2 for s in text)
        total_bytes = (end - base) * 2
        buf = bytearray(total_bytes)

        for s in text:
            byte_offset = (s.phys_addr - base) * 2
            buf[byte_offset:byte_offset + len(s.data)] = s.data

        return bytes(buf), base


def parse_coff(path: str | Path) -> CoffFile:
    """Parse a TI COFF file."""
    data = Path(path).read_bytes()
    return _parse(data)


def _parse(data: bytes) -> CoffFile:
    coff = CoffFile()

    # File header (22 bytes for COFF2)
    magic = struct.unpack_from("<H", data, 0)[0]
    if magic != COFF_MAGIC_C2000:
        raise ValueError(f"Not a TI C2000 COFF file (magic=0x{magic:04X})")

    num_sections = struct.unpack_from("<H", data, 2)[0]
    timestamp = struct.unpack_from("<I", data, 4)[0]
    symtab_offset = struct.unpack_from("<I", data, 8)[0]
    num_symbols = struct.unpack_from("<I", data, 12)[0]
    opt_hdr_size = struct.unpack_from("<H", data, 16)[0]
    flags = struct.unpack_from("<H", data, 18)[0]
    target_id = struct.unpack_from("<H", data, 20)[0]

    hdr_size = 22 + opt_hdr_size

    # Section headers (48 bytes each for COFF2)
    for i in range(num_sections):
        sh_offset = hdr_size + i * 48

        # Section name: 8 bytes, null-terminated or pointer to string table
        raw_name = data[sh_offset:sh_offset + 8]
        if raw_name[:4] == b"\x00\x00\x00\x00":
            # Long name: offset into string table
            str_offset = struct.unpack_from("<I", raw_name, 4)[0]
            name = _read_string(data, symtab_offset + num_symbols * 18 + str_offset)
        else:
            name = raw_name.rstrip(b"\x00").decode("ascii", errors="replace")

        phys_addr = struct.unpack_from("<I", data, sh_offset + 8)[0]
        virt_addr = struct.unpack_from("<I", data, sh_offset + 12)[0]
        sec_size = struct.unpack_from("<I", data, sh_offset + 16)[0]
        data_ptr = struct.unpack_from("<I", data, sh_offset + 20)[0]
        reloc_ptr = struct.unpack_from("<I", data, sh_offset + 24)[0]
        line_ptr = struct.unpack_from("<I", data, sh_offset + 28)[0]
        num_reloc = struct.unpack_from("<I", data, sh_offset + 32)[0]
        num_lines = struct.unpack_from("<I", data, sh_offset + 36)[0]
        sec_flags = struct.unpack_from("<I", data, sh_offset + 40)[0]
        reserved = struct.unpack_from("<H", data, sh_offset + 44)[0]
        mem_page = struct.unpack_from("<H", data, sh_offset + 46)[0]

        # Read section data
        # Note: sec_size is in target-addressable units (words for C28x)
        # Each word is 2 bytes in the file
        byte_size = sec_size * 2
        sec_data = b""
        if data_ptr > 0 and sec_size > 0 and not (sec_flags & STYP_BSS):
            sec_data = data[data_ptr:data_ptr + byte_size]

        coff.sections.append(Section(
            name=name,
            phys_addr=phys_addr,
            virt_addr=virt_addr,
            size=sec_size,
            data_offset=data_ptr,
            flags=sec_flags,
            data=sec_data,
        ))

    # Symbol table (18 bytes per entry for COFF2)
    if symtab_offset > 0 and num_symbols > 0:
        strtab_offset = symtab_offset + num_symbols * 18

        i = 0
        while i < num_symbols:
            sym_offset = symtab_offset + i * 18

            # Symbol name
            raw_name = data[sym_offset:sym_offset + 8]
            if raw_name[:4] == b"\x00\x00\x00\x00":
                str_off = struct.unpack_from("<I", raw_name, 4)[0]
                name = _read_string(data, strtab_offset + str_off)
            else:
                name = raw_name.rstrip(b"\x00").decode("ascii", errors="replace")

            value = struct.unpack_from("<I", data, sym_offset + 8)[0]
            sec_num = struct.unpack_from("<h", data, sym_offset + 12)[0]  # signed
            reserved = struct.unpack_from("<H", data, sym_offset + 14)[0]
            sclass = struct.unpack_from("<B", data, sym_offset + 16)[0]
            num_aux = struct.unpack_from("<B", data, sym_offset + 17)[0]

            if name and not name.startswith("."):
                coff.symbols.append(Symbol(
                    name=name,
                    value=value,
                    section_num=sec_num,
                    storage_class=sclass,
                ))

            i += 1 + num_aux  # Skip auxiliary entries

    return coff


def _read_string(data: bytes, offset: int) -> str:
    """Read a null-terminated string from data."""
    end = data.index(b"\x00", offset)
    return data[offset:end].decode("ascii", errors="replace")
