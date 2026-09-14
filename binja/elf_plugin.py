"""TMS320C28x ELF BinaryView for Binary Ninja.

The C28x is word-addressed (16-bit words). ELF files from cl2000 contain
word addresses, but Binary Ninja works in byte addresses. This view
multiplies all ELF addresses by 2 to convert word → byte space.

Without this, BN's built-in ELF loader uses word addresses as byte
addresses, causing every function, call target, and memory reference
to be at the wrong location.
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

EM_TI_C6000 = 141  # cl2000 --abi=eabi uses this
EM_TI_C2000 = 157  # older toolchains

# ELF constants
PT_LOAD = 1
PF_X = 0x1
PF_W = 0x2
PF_R = 0x4

# Symbol types
STT_FUNC = 2
STT_OBJECT = 1
STB_GLOBAL = 1
STB_WEAK = 2

SHT_SYMTAB = 2
SHT_STRTAB = 3


def _w2b(word_addr):
    """Convert word address to byte address."""
    return word_addr * 2


class C28xELFView(BinaryView):
    name = "C28x ELF"
    long_name = "TMS320C28x ELF (word→byte converted)"

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.raw = data

    @classmethod
    def is_valid_for_data(cls, data) -> bool:
        hdr = data.read(0, 20)
        if not hdr or len(hdr) < 20:
            return False
        # Check ELF magic
        if hdr[:4] != b"\x7fELF":
            return False
        # Check e_machine for TI C2000/C6000
        e_machine = struct.unpack_from("<H", hdr, 18)[0]
        return e_machine in (EM_TI_C6000, EM_TI_C2000)

    def init(self) -> bool:
        try:
            self.arch = Architecture["tms320c28x"]
            self.platform = self.arch.standalone_platform
        except Exception:
            log_warn("tms320c28x architecture not registered")
            return False

        raw = self.raw.read(0, self.raw.length)
        if len(raw) < 52:
            return False

        # Parse ELF header (32-bit little-endian)
        e_entry = struct.unpack_from("<I", raw, 24)[0]
        e_phoff = struct.unpack_from("<I", raw, 28)[0]
        e_shoff = struct.unpack_from("<I", raw, 32)[0]
        e_phentsize = struct.unpack_from("<H", raw, 42)[0]
        e_phnum = struct.unpack_from("<H", raw, 44)[0]
        e_shentsize = struct.unpack_from("<H", raw, 46)[0]
        e_shnum = struct.unpack_from("<H", raw, 48)[0]
        e_shstrndx = struct.unpack_from("<H", raw, 50)[0]

        entry_byte = _w2b(e_entry)
        log_info(f"C28x ELF: entry word=0x{e_entry:x} byte=0x{entry_byte:x}")

        # Load program segments (PT_LOAD)
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if off + 32 > len(raw):
                break
            p_type = struct.unpack_from("<I", raw, off)[0]
            if p_type != PT_LOAD:
                continue

            p_offset = struct.unpack_from("<I", raw, off + 4)[0]
            p_vaddr = struct.unpack_from("<I", raw, off + 8)[0]
            p_filesz = struct.unpack_from("<I", raw, off + 16)[0]
            p_memsz = struct.unpack_from("<I", raw, off + 20)[0]
            p_flags = struct.unpack_from("<I", raw, off + 24)[0]

            # Convert word addresses to byte addresses
            # p_vaddr and p_memsz are in words; p_filesz and p_offset are in file bytes
            byte_addr = _w2b(p_vaddr)
            byte_memsz = _w2b(p_memsz)

            flags = SegmentFlag.SegmentReadable
            if p_flags & PF_X:
                flags |= SegmentFlag.SegmentExecutable | SegmentFlag.SegmentContainsCode
            if p_flags & PF_W:
                flags |= SegmentFlag.SegmentWritable | SegmentFlag.SegmentContainsData

            if p_filesz > 0:
                # File-backed segment: p_filesz is already in file bytes
                # p_offset is the file offset in bytes
                actual_file_bytes = min(p_filesz, len(raw) - p_offset)
                self.add_auto_segment(
                    byte_addr, byte_memsz, p_offset, actual_file_bytes, flags
                )
            else:
                # BSS-like segment (no file data)
                self.add_auto_segment(byte_addr, byte_memsz, 0, 0, flags)

            semantics = SectionSemantics.DefaultSectionSemantics
            if p_flags & PF_X:
                semantics = SectionSemantics.ReadOnlyCodeSectionSemantics
            elif p_flags & PF_W:
                semantics = SectionSemantics.ReadWriteDataSectionSemantics

        # Parse section headers for names
        shstrtab_off = 0
        if e_shstrndx < e_shnum:
            shstr_hdr = e_shoff + e_shstrndx * e_shentsize
            if shstr_hdr + 40 <= len(raw):
                shstrtab_off = struct.unpack_from("<I", raw, shstr_hdr + 16)[0]

        for i in range(e_shnum):
            sh_off = e_shoff + i * e_shentsize
            if sh_off + 40 > len(raw):
                break
            sh_name_off = struct.unpack_from("<I", raw, sh_off)[0]
            sh_type = struct.unpack_from("<I", raw, sh_off + 4)[0]
            sh_addr = struct.unpack_from("<I", raw, sh_off + 12)[0]
            sh_size = struct.unpack_from("<I", raw, sh_off + 20)[0]

            if sh_type in (SHT_SYMTAB, SHT_STRTAB, 0):
                continue
            if sh_size == 0:
                continue

            # Get section name
            name = ""
            if shstrtab_off > 0 and shstrtab_off + sh_name_off < len(raw):
                end = raw.index(b"\x00", shstrtab_off + sh_name_off)
                name = raw[shstrtab_off + sh_name_off : end].decode(
                    "ascii", errors="replace"
                )

            if name and sh_addr > 0:
                byte_addr = _w2b(sh_addr)
                byte_size = sh_size * 2
                semantics = SectionSemantics.DefaultSectionSemantics
                if name in (".text", ".cinit", ".pinit", ".switch"):
                    semantics = SectionSemantics.ReadOnlyCodeSectionSemantics
                elif name in (
                    ".bss",
                    ".data",
                    ".ebss",
                    ".esysmem",
                    ".stack",
                    ".sysmem",
                ):
                    semantics = SectionSemantics.ReadWriteDataSectionSemantics
                elif name in (".const", ".econst"):
                    semantics = SectionSemantics.ReadOnlyDataSectionSemantics
                self.add_auto_section(name, byte_addr, byte_size, semantics)

        # Parse symbol table
        self._load_symbols(raw, e_shoff, e_shentsize, e_shnum)

        # Set entry point
        self.add_entry_point(entry_byte)

        return True

    def _load_symbols(self, raw, e_shoff, e_shentsize, e_shnum):
        """Parse ELF symbol table and create function/data symbols."""
        # Find .symtab and .strtab sections
        symtab_off = 0
        symtab_size = 0
        symtab_entsize = 16  # 32-bit ELF
        symtab_link = 0

        for i in range(e_shnum):
            sh_off = e_shoff + i * e_shentsize
            if sh_off + 40 > len(raw):
                break
            sh_type = struct.unpack_from("<I", raw, sh_off + 4)[0]
            if sh_type == SHT_SYMTAB:
                symtab_off = struct.unpack_from("<I", raw, sh_off + 16)[0]
                symtab_size = struct.unpack_from("<I", raw, sh_off + 20)[0]
                symtab_entsize = struct.unpack_from("<I", raw, sh_off + 36)[0]
                symtab_link = struct.unpack_from("<I", raw, sh_off + 24)[0]
                break

        if symtab_off == 0:
            return

        # Get string table for symbol names
        strtab_off = 0
        if symtab_link < e_shnum:
            str_sh = e_shoff + symtab_link * e_shentsize
            if str_sh + 40 <= len(raw):
                strtab_off = struct.unpack_from("<I", raw, str_sh + 16)[0]

        if strtab_off == 0:
            return

        # Parse symbols
        num_syms = symtab_size // symtab_entsize
        func_count = 0

        for i in range(num_syms):
            sym_off = symtab_off + i * symtab_entsize
            if sym_off + 16 > len(raw):
                break

            st_name = struct.unpack_from("<I", raw, sym_off)[0]
            st_value = struct.unpack_from("<I", raw, sym_off + 4)[0]
            _st_size = struct.unpack_from("<I", raw, sym_off + 8)[0]  # layout only
            st_info = raw[sym_off + 12]
            st_shndx = struct.unpack_from("<H", raw, sym_off + 14)[0]

            st_type = st_info & 0xF
            st_bind = st_info >> 4

            if st_value == 0 or st_shndx == 0:
                continue

            # Get name
            name = ""
            if strtab_off + st_name < len(raw):
                end = raw.index(b"\x00", strtab_off + st_name)
                name = raw[strtab_off + st_name : end].decode("ascii", errors="replace")

            if not name or name.startswith("."):
                continue
            # Skip compiler-generated internal labels
            if name.startswith("$") or name.startswith("__TI_"):
                continue

            byte_addr = _w2b(st_value)

            # Strip TI C underscore prefix for display
            display = name
            if display.startswith("_") and not display.startswith("__"):
                display = display[1:]

            if st_type == STT_FUNC or (
                st_bind in (STB_GLOBAL, STB_WEAK) and st_type == 0
            ):
                self.define_auto_symbol(
                    Symbol(SymbolType.FunctionSymbol, byte_addr, display)
                )
                self.add_function(byte_addr)
                func_count += 1
            elif st_type == STT_OBJECT:
                self.define_auto_symbol(
                    Symbol(SymbolType.DataSymbol, byte_addr, display)
                )

        log_info(f"C28x ELF: loaded {func_count} functions from symbol table")

    def perform_is_executable(self) -> bool:
        return True

    def perform_get_address_size(self) -> int:
        return 4

    def perform_get_entry_point(self) -> int:
        return 0

    def perform_get_default_endianness(self):
        return binaryninja.Endianness.LittleEndian


C28xELFView.register()
