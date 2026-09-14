"""Build a comprehensive F28335 flash image from all 4 synthetic test apps.

Compiles flash_combined.c (which includes led_blink, pid_loop, switch_table,
isr_handler with renamed mains) using cl2000 for F28335 flash addresses.
Extracts code from the ELF .out and packs into a 512KB raw flash image.

Usage: python3 tests/build_flash_fixture.py
  (requires cl2000 in PATH)
"""

import os
import shutil
import struct
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(SCRIPT_DIR, "fixtures", "src")
LINK_DIR = os.path.join(SCRIPT_DIR, "fixtures", "link")
BUILD_DIR = os.path.join(SCRIPT_DIR, "fixtures", "build")

COMBINED_SRC = os.path.join(SRC_DIR, "flash_combined.c")
LINKER_CMD = os.path.join(LINK_DIR, "f28335_flash.cmd")
COMBINED_OUT = os.path.join(BUILD_DIR, "flash_combined.out")
FLASH_BIN = os.path.join(BUILD_DIR, "flash_test.bin")

FLASH_H_WORD = 0x300000
FLASH_SIZE = 512 * 1024  # 512KB

# Known data constants embedded in Flash F for integrity checks
DATA_CONSTANTS = [0xDEADBEEF, 0xCAFE0042, 0x12345678]
DATA_FLASH_F_FILE_OFFSET = 0x20000  # Flash F starts at file offset 0x20000


def compile_combined():
    """Compile flash_combined.c with cl2000 for F28335 flash addresses."""
    cl2000 = shutil.which("cl2000")
    if not cl2000:
        print(
            "[SKIP] cl2000 not in PATH — using pre-built flash_combined.out if available"
        )
        return os.path.exists(COMBINED_OUT)

    cgt_dir = os.path.dirname(os.path.dirname(cl2000))
    os.makedirs(BUILD_DIR, exist_ok=True)

    cmd = [
        cl2000,
        "-v28",
        "--abi=eabi",
        "--float_support=fpu32",
        "-O0",
        "-g",
        f"--obj_directory={BUILD_DIR}",
        f"-I{cgt_dir}/include",
        f"-I{SRC_DIR}",
        COMBINED_SRC,
        "-z",
        "--rom_model",
        f"-i{cgt_dir}/lib",
        "-lrts2800_fpu32_eabi.lib",
        LINKER_CMD,
        f"-m{os.path.join(BUILD_DIR, 'flash_combined.map')}",
        f"-o{COMBINED_OUT}",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("[FAIL] cl2000 compilation failed:")
        print(result.stderr)
        return False

    print(f"  Compiled: {COMBINED_OUT}")
    return True


def extract_elf_sections(elf_path):
    """Extract loadable sections from ELF using readelf + objcopy."""
    # Use readelf to get section info
    result = subprocess.run(["readelf", "-S", elf_path], capture_output=True, text=True)
    if result.returncode != 0:
        return []

    sections = []
    for line in result.stdout.split("\n"):
        if "PROGBITS" not in line:
            continue
        parts = line.split()
        # Find the name, addr, offset, size fields
        # readelf output is messy — parse carefully
        for i, p in enumerate(parts):
            if p == "PROGBITS":
                # Fields before PROGBITS: [Nr] Name Type Addr Off Size
                # The addr is 2 fields before PROGBITS, offset 1 before, size right after...
                # Actually it's easier to just get them by position from the bracket
                break

        # Simpler: use objcopy to extract each section to a binary
        # But first let's use nm to get all symbols
        pass

    return sections


def extract_flash_data(elf_path):
    """Extract executable LOAD segment from ELF.

    Parses readelf -l to find the executable (R E) LOAD segment,
    then reads the raw bytes from the ELF file at the segment offset.
    Returns (raw_bytes, base_word_addr).
    """
    result = subprocess.run(["readelf", "-l", elf_path], capture_output=True, text=True)
    if result.returncode != 0:
        return b"", 0x308000

    # Find the executable LOAD segment (has 'E' flag)
    for line in result.stdout.split("\n"):
        line = line.strip()
        if not line.startswith("LOAD"):
            continue
        if "E" not in line.split()[-2:]:  # Check flags column
            continue

        parts = line.split()
        # Format: LOAD  Offset  VirtAddr  PhysAddr  FileSiz  MemSiz  Flg  Align
        file_offset = int(parts[1], 16)
        virt_addr = int(parts[2], 16)
        file_size = int(parts[4], 16)

        with open(elf_path, "rb") as f:
            f.seek(file_offset)
            data = f.read(file_size)

        return data, virt_addr

    return b"", 0x308000


def extract_flash_data_fallback(elf_path):
    """Fallback: extract section bytes using readelf and dd."""
    # Get section data via readelf hex dump
    result = subprocess.run(
        ["readelf", "-x", ".text", elf_path], capture_output=True, text=True
    )
    if result.returncode != 0:
        return b"", 0x308000

    # Parse hex dump
    data = bytearray()
    base = None
    for line in result.stdout.split("\n"):
        line = line.strip()
        if line.startswith("0x"):
            addr_str = line.split()[0]
            addr = int(addr_str, 16)
            if base is None:
                base = addr
            # Extract hex bytes
            hex_part = line[10:50]  # hex data area
            for word in hex_part.split():
                if len(word) == 8:
                    data += bytes.fromhex(word)

    return bytes(data), base or 0x308000


def get_symbol_addresses(elf_path):
    """Get function symbol addresses from the ELF."""
    result = subprocess.run(["nm", elf_path], capture_output=True, text=True)
    symbols = {}
    for line in result.stdout.split("\n"):
        parts = line.split()
        if len(parts) >= 3 and parts[1] in ("T", "t"):
            addr = int(parts[0], 16)
            name = parts[2]
            if not name.startswith("$C$") and not name.startswith("__TI_"):
                symbols[name] = addr
    return symbols


def build_flash_image():
    """Build the 512KB flash image from the compiled ELF."""
    if not os.path.exists(COMBINED_OUT):
        print("[FAIL] flash_combined.out not found")
        return False

    raw_data, base_word_addr = extract_flash_data(COMBINED_OUT)
    symbols = get_symbol_addresses(COMBINED_OUT)

    if not raw_data:
        print("[FAIL] Could not extract code from ELF")
        return False

    print(f"  Code: {len(raw_data)} bytes at base word 0x{base_word_addr:06X}")
    print(f"  Symbols: {len(symbols)} functions")

    # Build the flash image
    buf = bytearray(b"\xff" * FLASH_SIZE)

    # Map code into flash: file_offset = (word_addr - FLASH_H_WORD) * 2
    code_file_offset = (base_word_addr - FLASH_H_WORD) * 2
    if code_file_offset < 0 or code_file_offset + len(raw_data) > FLASH_SIZE:
        print(f"[FAIL] Code at 0x{base_word_addr:06X} doesn't fit in flash image")
        print(
            f"  file_offset={code_file_offset}, data_len={len(raw_data)}, flash_size={FLASH_SIZE}"
        )
        return False

    # Pre-fill entire Flash G sector with ESTOP0 (halt) instructions BEFORE
    # placing code. This ensures any gaps between functions (from linker
    # alignment) contain halt instructions rather than 0xFF, which BN
    # would decode as valid instructions and merge into adjacent functions.
    ESTOP0 = struct.pack("<H", 0x7625)
    sector_start = code_file_offset
    sector_end = min(code_file_offset + 0x10000, FLASH_SIZE)
    for off in range(sector_start, sector_end, 2):
        buf[off : off + 2] = ESTOP0

    # Now overlay the actual code
    end = min(code_file_offset + len(raw_data), FLASH_SIZE)
    buf[code_file_offset:end] = raw_data[: end - code_file_offset]

    # Add data constants in Flash F for integrity testing
    for i, val in enumerate(DATA_CONSTANTS):
        struct.pack_into("<I", buf, DATA_FLASH_F_FILE_OFFSET + i * 4, val)

    # Write flash image
    with open(FLASH_BIN, "wb") as f:
        f.write(buf)

    print(f"  Flash image: {FLASH_BIN} ({len(buf)} bytes)")

    # Report key functions
    user_funcs = [n for n in symbols if not n.startswith("_") or n in ("_c_int00",)]
    user_funcs = sorted(
        [
            n
            for n in symbols
            if n
            in (
                "main",
                "led_main",
                "pid_main",
                "switch_main",
                "isr_main",
                "delay",
                "gpio_toggle",
                "pid_init",
                "pid_compute",
                "run_pid_loop",
                "process_command",
                "run_commands",
                "buf_init",
                "buf_put",
                "buf_get",
                "sci_rx_isr",
                "process_received",
                "_c_int00",
            )
        ]
    )
    for name in user_funcs:
        word_addr = symbols[name]
        byte_addr = word_addr * 2
        print(f"    {name}: word 0x{word_addr:06X} → byte 0x{byte_addr:06X}")

    return True


def main():
    os.makedirs(BUILD_DIR, exist_ok=True)
    print("=== Building comprehensive flash test fixture ===")

    # Step 1: Compile
    if not compile_combined():
        # If cl2000 not available but .out exists, continue with extraction
        if not os.path.exists(COMBINED_OUT):
            print("[FAIL] Cannot build flash fixture without cl2000")
            sys.exit(1)

    # Step 2: Build flash image from compiled ELF
    if not build_flash_image():
        sys.exit(1)

    print("\n=== Flash fixture built successfully ===")


if __name__ == "__main__":
    main()
