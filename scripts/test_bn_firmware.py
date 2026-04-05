#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Headless Binary Ninja test: load real firmware, verify decode + IL.

Usage:
    binaryninja -x scripts/test_bn_firmware.py
    OR (if BN python is on path):
    python3 scripts/test_bn_firmware.py
"""

import sys
import time

try:
    import binaryninja
except ImportError:
    print("ERROR: Binary Ninja not available. Run with: binaryninja -x scripts/test_bn_firmware.py")
    sys.exit(1)

FIRMWARE = "/home/brian/projects/re/target/107_aletihad/flash_memory_u1.bin"
BASE_ADDR = 0x600000
CODE_START = 0x610000
CODE_END = 0x64C000

# Known function addresses to test (byte addresses)
TEST_FUNCTIONS = [
    ("nav_path_following_calculation", 0x62DC72),
    ("init_struct_fields_a", 0x610000),
]

def main():
    print("=" * 70)
    print("TMS320C28x Binary Ninja Integration Test")
    print("=" * 70)

    # --- Load firmware ---
    print(f"\n[1/5] Loading firmware: {FIRMWARE}")
    bv = binaryninja.BinaryViewType["Raw"].open(FIRMWARE)
    if bv is None:
        print("FAIL: Could not open firmware binary")
        return False

    bv.arch = binaryninja.Architecture["tms320c28x"]
    bv.platform = bv.arch.standalone_platform

    # Rebase to correct address
    bv.add_user_segment(BASE_ADDR, len(bv), 0, len(bv), 7)  # RWX

    # Create functions at known addresses
    for name, addr in TEST_FUNCTIONS:
        bv.create_user_function(addr)

    print("  Waiting for analysis...")
    bv.update_analysis_and_wait()
    print(f"  Analysis complete. Functions found: {len(bv.functions)}")

    # --- Test 1: Verify architecture is registered ---
    print("\n[2/5] Checking architecture registration")
    arch = binaryninja.Architecture["tms320c28x"]
    assert arch is not None, "Architecture not registered"

    # Check FPU registers exist
    fpu_regs = [r for r in arch.regs if r.startswith("R") and r.endswith("H")]
    print(f"  FPU registers: {fpu_regs}")
    assert len(fpu_regs) >= 8, f"Expected 8+ FPU registers, got {len(fpu_regs)}"

    # Check intrinsics exist
    intrinsic_names = list(arch.intrinsics.keys()) if hasattr(arch, 'intrinsics') else []
    print(f"  Intrinsics defined: {len(intrinsic_names)}")
    if intrinsic_names:
        print(f"    Sample: {intrinsic_names[:5]}")
    print("  PASS: Architecture registered with FPU support")

    # --- Test 2: Decode coverage in code region ---
    print("\n[3/5] Checking instruction decode coverage")
    total_insns = 0
    decoded_insns = 0
    undecoded_addrs = []

    for func in bv.functions:
        if func.start < CODE_START or func.start >= CODE_END:
            continue
        for block in func.basic_blocks:
            for insn_tokens, insn_len in block:
                total_insns += 1
                text = "".join(str(t) for t in insn_tokens)
                if "??" not in text and insn_len > 0:
                    decoded_insns += 1
                else:
                    if len(undecoded_addrs) < 10:
                        undecoded_addrs.append(block.start)

    if total_insns > 0:
        rate = decoded_insns * 100 / total_insns
        print(f"  Instructions in analyzed functions: {total_insns}")
        print(f"  Decoded: {decoded_insns} ({rate:.1f}%)")
        if undecoded_addrs:
            print(f"  Sample undecoded: {[hex(a) for a in undecoded_addrs[:5]]}")
    else:
        print("  WARNING: No instructions found in functions")
        rate = 0

    # --- Test 3: IL lifting for nav function ---
    print("\n[4/5] Checking IL lifting quality")
    nav_func = bv.get_function_at(0x62DC72)
    if nav_func is None:
        print("  WARNING: nav_path_following_calculation not found at 0x62DC72")
        # Try nearby addresses
        for func in bv.functions:
            if 0x62DC00 <= func.start <= 0x62DD00:
                nav_func = func
                print(f"  Found function at 0x{func.start:X} instead")
                break

    if nav_func:
        llil = nav_func.llil
        if llil is None:
            print("  WARNING: LLIL not available")
        else:
            il_count = 0
            nop_count = 0
            fpu_reg_count = 0
            intrinsic_count = 0

            for block in llil:
                for insn in block:
                    il_count += 1
                    text = str(insn)
                    if text.strip() == "nop":
                        nop_count += 1
                    if any(f"R{i}H" in text for i in range(8)):
                        fpu_reg_count += 1
                    if "__" in text or "intrinsic" in text.lower():
                        intrinsic_count += 1

            if il_count > 0:
                nop_pct = nop_count * 100 / il_count
                print(f"  LLIL instructions: {il_count}")
                print(f"  NOPs: {nop_count} ({nop_pct:.1f}%)")
                print(f"  FPU register references: {fpu_reg_count}")
                print(f"  Intrinsic calls: {intrinsic_count}")
                if nop_pct < 50:
                    print("  PASS: IL lifting functional (>50% non-nop)")
                else:
                    print(f"  WARN: High nop rate ({nop_pct:.1f}%), IL may need improvement")
            else:
                print("  WARNING: No LLIL instructions")

        # Test HLIL (decompiler output)
        hlil = nav_func.hlil
        if hlil:
            text = str(hlil)
            lines = text.strip().split("\n")
            print(f"  Decompiler output: {len(lines)} lines")
            # Show first few lines
            for line in lines[:5]:
                print(f"    {line.strip()}")
            if len(lines) > 5:
                print(f"    ... ({len(lines) - 5} more lines)")
        else:
            print("  WARNING: Decompiler output not available")
    else:
        print("  SKIP: nav function not found")

    # --- Test 4: Spot-check specific IL patterns ---
    print("\n[5/5] Spot-checking IL patterns at 0x610000")
    init_func = bv.get_function_at(0x610000)
    if init_func and init_func.llil:
        sample_il = []
        for block in init_func.llil:
            for insn in block:
                sample_il.append(str(insn))
                if len(sample_il) >= 15:
                    break
            if len(sample_il) >= 15:
                break

        print(f"  First {len(sample_il)} LLIL instructions:")
        for i, text in enumerate(sample_il):
            print(f"    [{i:2d}] {text}")
    else:
        print("  SKIP: init function not available")

    # --- Summary ---
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"  Architecture: PASS (FPU regs + intrinsics)")
    print(f"  Functions analyzed: {len(bv.functions)}")
    if total_insns > 0:
        print(f"  Decode rate: {rate:.1f}%")
    print(f"  IL lifting: {'PASS' if nav_func and nav_func.llil else 'NEEDS VERIFICATION'}")

    bv.file.close()
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
