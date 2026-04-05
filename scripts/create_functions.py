"""Create all discovered functions and disable guided analysis.

Run from Binary Ninja's Python console (Tools > Python Console):
    exec(open("/home/brian/projects/code/github.com/brianmcgillion/tms320c28x-re/scripts/create_functions.py").read())

Or paste the snippet below into the console:
    import runpy; runpy.run_path("/home/brian/projects/code/github.com/brianmcgillion/tms320c28x-re/scripts/create_functions.py", run_name="__main__")
"""

import sys
from pathlib import Path

# Ensure the c28x package is importable
_root = str(Path(__file__).resolve().parent.parent)
if _root not in sys.path:
    sys.path.insert(0, _root)

from c28x.decoder import Decoder
from c28x.types import BranchType
from c28x.util import bytes_to_opcode16

import binaryninja

bv = binaryninja.interaction.get_open_filenames_input  # dummy to check BN context
# Get the current binary view
bv = None
for view in binaryninja.BinaryViewType:
    pass  # just checking BN is available

# Try to get the active view from the UI context
try:
    ctx = binaryninja.UIContext.allContexts()
    if ctx:
        bv = ctx[0].getCurrentViewFrame().getCurrentBinaryView()
except Exception:
    pass

if bv is None:
    # Fallback: find the flash_memory binary
    print("Could not get active view from UI, searching open files...")
    # In headless or script mode, user must set bv manually
    print("Please run: bv = binaryninja.load('path/to/flash_memory_u1.bin')")
    print("Then re-run this script.")
else:
    print(f"Binary: {bv.file.filename}")
    print(f"Architecture: {bv.arch}")
    print(f"Existing functions: {len(bv.functions)}")

    CODE_START = 0x610000
    CODE_END = 0x64C000

    # Read the raw binary data from the view
    data = bv.read(CODE_START, CODE_END - CODE_START)
    if len(data) < 1000:
        print(f"ERROR: Could not read code region (got {len(data)} bytes). Check base address.")
    else:
        d = Decoder(objmode=1)

        # Pass 1: Find direct call targets
        call_targets = set()
        offset = 0
        while offset < len(data) - 3:
            chunk = data[offset:offset + 4]
            insn = d.decode(chunk, addr=CODE_START + offset)
            if insn:
                if insn.branch_type == BranchType.CALL and insn.branch_target is not None:
                    t = insn.branch_target
                    if CODE_START <= t < CODE_END:
                        call_targets.add(t)
                offset += insn.size
            else:
                offset += 2

        # Pass 2: Find ADDB SP, #N prologues
        prologue_addrs = set()
        offset = 0
        while offset < len(data) - 1:
            op16 = bytes_to_opcode16(data[offset:offset + 2])
            if (op16 & 0xFF80) == 0xFE00:
                prologue_addrs.add(CODE_START + offset)
            offset += 2

        all_entries = sorted(call_targets | prologue_addrs)
        existing = {f.start for f in bv.functions}
        new_entries = [a for a in all_entries if a not in existing]

        print(f"\nDiscovered {len(all_entries)} function entries:")
        print(f"  From call targets: {len(call_targets)}")
        print(f"  From prologues: {len(prologue_addrs)}")
        print(f"  Already exist: {len(all_entries) - len(new_entries)}")
        print(f"  New to create: {len(new_entries)}")

        # Create new functions
        print(f"\nCreating {len(new_entries)} new functions...")
        for i, addr in enumerate(new_entries):
            bv.create_user_function(addr)
            if (i + 1) % 100 == 0:
                print(f"  Created {i + 1}/{len(new_entries)}...")

        print(f"Created {len(new_entries)} functions.")

        # Disable guided analysis on ALL functions
        print("\nDisabling guided analysis on all functions...")
        skipped_count = 0
        for func in bv.functions:
            if func.analysis_skipped:
                func.analysis_skipped = False
                skipped_count += 1

        print(f"Re-enabled analysis on {skipped_count} functions.")

        # Trigger full reanalysis
        print("\nStarting full analysis (this may take a while)...")
        bv.update_analysis_and_wait()

        # Report results
        total_funcs = len(bv.functions)
        code_in_funcs = sum(
            sum(block.length for block in func.basic_blocks)
            for func in bv.functions
            if CODE_START <= func.start < CODE_END
        )
        total_code = CODE_END - CODE_START
        coverage = code_in_funcs * 100 / total_code if total_code > 0 else 0

        print(f"\n{'=' * 60}")
        print(f"ANALYSIS COMPLETE")
        print(f"{'=' * 60}")
        print(f"Total functions: {total_funcs}")
        print(f"Code coverage: {code_in_funcs:,} / {total_code:,} bytes ({coverage:.1f}%)")

        # Check for remaining guided analysis
        still_guided = sum(1 for f in bv.functions if f.analysis_skipped)
        if still_guided:
            print(f"WARNING: {still_guided} functions still in guided analysis")
        else:
            print("All functions fully analyzed (no guided analysis)")
