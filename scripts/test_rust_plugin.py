"""Headless test for the Rust TMS320C28x Binary Ninja plugin.

Tests: plugin loading, firmware analysis, function discovery, LLIL/MLIL quality.
Run: nix develop -c python3 scripts/test_rust_plugin.py
"""

import sys
import os
import ctypes
import time

BN_DIR = "/nix/store/749lzpsig0nld4zbd0br6sk87h3i5hqh-binary-ninja-5.2.8722/opt/binaryninja"
FIRMWARE = "/home/brian/projects/re/target/107_aletihad/flash_memory_u1.bin"
BASE_ADDR = 0x600000
CODE_START = 0x610000
CODE_END = 0x64C000

sys.path.insert(0, os.path.join(BN_DIR, "python"))
os.environ["LD_LIBRARY_PATH"] = BN_DIR

# Load BN core and our plugin
core = ctypes.CDLL(os.path.join(BN_DIR, "libbinaryninjacore.so.1"))
plugin = ctypes.CDLL(os.path.expanduser("~/.binaryninja/plugins/libtms320c28x_binja.so"))
plugin.CorePluginInit.restype = ctypes.c_bool
assert plugin.CorePluginInit(), "CorePluginInit failed"

import binaryninja
from binaryninja import BinaryViewType, Architecture

# Verify architecture registered
arch = Architecture["tms320c28x"]
print(f"[OK] Architecture registered: {arch.name}")
print(f"     address_size={arch.address_size}, max_instr_length={arch.max_instr_length}")

# Test basic decode
nop_data = bytes([0x00, 0x77, 0x00, 0x00])
info = arch.get_instruction_info(nop_data, 0)
assert info and info.length == 2, f"NOP decode failed: {info}"
tokens, length = arch.get_instruction_text(nop_data, 0)
text = "".join(t.text for t in tokens)
print(f"[OK] NOP decode: '{text}' (length={length})")

# Test branch decode
lcr_data = bytes([0x40, 0x76, 0x00, 0x01])  # LCR with addr
info = arch.get_instruction_info(lcr_data, 0)
assert info and info.length == 4, f"LCR decode failed"
print(f"[OK] LCR decode: length={info.length}")

# Test LRETR decode
lretr_data = bytes([0x06, 0x00, 0x00, 0x00])
info = arch.get_instruction_info(lretr_data, 0)
assert info and info.length == 2, f"LRETR decode failed"
print(f"[OK] LRETR decode: length={info.length}")

# Load firmware
print(f"\n--- Loading firmware: {FIRMWARE} ---")
print(f"    Base address: 0x{BASE_ADDR:X}")

# Load as raw binary with our architecture
with open(FIRMWARE, "rb") as f:
    raw_data = f.read()

bv = binaryninja.BinaryView.new(raw_data)
bv.offset = BASE_ADDR

# Try to open with the Mapped file loader
bv = binaryninja.load(FIRMWARE, options={
    "files.universal.architecturePreference": ["tms320c28x"],
    "loader.imageBase": BASE_ADDR,
    "loader.platform": "tms320c28x",
})

if bv is None:
    # Fallback: manual raw binary creation
    bv = binaryninja.BinaryView.new(raw_data, file_metadata=binaryninja.FileMetadata())
    bv.platform = arch.standalone_platform
    bv.add_auto_segment(BASE_ADDR, len(raw_data), 0, len(raw_data),
        binaryninja.SegmentFlag.SegmentReadable |
        binaryninja.SegmentFlag.SegmentExecutable |
        binaryninja.SegmentFlag.SegmentContainsCode)
    bv.add_entry_point(CODE_START)

if bv is None:
    print("[FAIL] Could not load firmware")
    sys.exit(1)

print(f"[OK] Firmware loaded: {bv.length} bytes")
print(f"     Architecture: {bv.arch}")

# Wait for analysis
print("\n--- Running analysis ---")
start = time.time()
bv.update_analysis_and_wait()
elapsed = time.time() - start
print(f"[OK] Analysis complete in {elapsed:.1f}s")

# Function statistics
all_funcs = list(bv.functions)
code_funcs = [f for f in all_funcs if CODE_START <= f.start < CODE_END]
print(f"\n--- Function statistics ---")
print(f"     Total functions: {len(all_funcs)}")
print(f"     Code region functions ({CODE_START:#x}-{CODE_END:#x}): {len(code_funcs)}")

# Classify functions
with_prologue = 0
call_target_count = 0
for f in code_funcs:
    data = bv.read(f.start, 2)
    if data and len(data) >= 2:
        op16 = data[0] | (data[1] << 8)
        if (op16 & 0xFF80) == 0xFE00:
            with_prologue += 1

print(f"     With ADDB_SP prologue: {with_prologue}")

# Code coverage
total_blocks = 0
total_block_bytes = 0
for f in code_funcs:
    for block in f.basic_blocks:
        total_blocks += 1
        total_block_bytes += block.length
code_region_size = CODE_END - CODE_START
coverage_pct = total_block_bytes * 100 / code_region_size if code_region_size > 0 else 0
print(f"     Basic blocks: {total_blocks}")
print(f"     Code coverage: {total_block_bytes:,} / {code_region_size:,} bytes ({coverage_pct:.1f}%)")

# LLIL/MLIL quality check
print(f"\n--- IL quality check ---")
llil_errors = 0
mlil_errors = 0
hlil_errors = 0
llil_lifted = 0
llil_total = 0
funcs_with_llil_errors = set()
funcs_with_mlil_errors = set()

sample_count = min(len(code_funcs), 200)  # Check up to 200 functions
for f in code_funcs[:sample_count]:
    try:
        llil = f.llil
        if llil:
            for block in llil:
                for insn in block:
                    llil_total += 1
    except Exception as e:
        llil_errors += 1
        funcs_with_llil_errors.add(f.start)

    try:
        mlil = f.mlil
        if mlil:
            for block in mlil:
                for insn in block:
                    pass
    except Exception as e:
        mlil_errors += 1
        funcs_with_mlil_errors.add(f.start)

    try:
        hlil = f.hlil
        if hlil:
            pass
    except Exception:
        hlil_errors += 1

print(f"     Functions checked: {sample_count}")
print(f"     LLIL instructions: {llil_total}")
print(f"     LLIL errors: {llil_errors} ({len(funcs_with_llil_errors)} functions)")
print(f"     MLIL errors: {mlil_errors} ({len(funcs_with_mlil_errors)} functions)")
print(f"     HLIL errors: {hlil_errors}")

if funcs_with_llil_errors:
    print(f"     LLIL error functions: {[f'0x{a:x}' for a in sorted(funcs_with_llil_errors)[:10]]}")
if funcs_with_mlil_errors:
    print(f"     MLIL error functions: {[f'0x{a:x}' for a in sorted(funcs_with_mlil_errors)[:10]]}")

# Sample decompilation
print(f"\n--- Sample decompilation ---")
decompiled = 0
failed = 0
for f in code_funcs[:50]:
    try:
        hlil = f.hlil
        if hlil:
            decompiled += 1
    except Exception:
        failed += 1
print(f"     Decompiled: {decompiled}/50")
print(f"     Failed: {failed}/50")

# Check specific regions from the prompt
print(f"\n--- Region checks ---")

# PID region
pid_funcs = [f for f in code_funcs if 0x620000 <= f.start < 0x62A000]
print(f"     PID region (0x620000-0x62A000): {len(pid_funcs)} functions")

# Flight state cluster
fsc_funcs = [f for f in code_funcs if 0x618C00 <= f.start < 0x618E00]
print(f"     Flight state cluster (0x618C00-0x618E00): {len(fsc_funcs)} functions")

# Nav waypoint
nav_funcs = [f for f in code_funcs if 0x62C000 <= f.start < 0x630000]
print(f"     Nav waypoint region (0x62C000-0x630000): {len(nav_funcs)} functions")

print(f"\n{'='*60}")
print(f"SUMMARY")
print(f"{'='*60}")
print(f"  Functions: {len(code_funcs)}")
print(f"  Coverage: {coverage_pct:.1f}%")
print(f"  Analysis time: {elapsed:.1f}s")
print(f"  IL errors: LLIL={llil_errors}, MLIL={mlil_errors}, HLIL={hlil_errors}")
print(f"  Decompilation: {decompiled}/{min(50, len(code_funcs))}")
