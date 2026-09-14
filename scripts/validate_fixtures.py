"""Validate compiled C28x ELF fixtures against the Rust BN plugin.

Run: nix develop -c python3 scripts/validate_fixtures.py
"""

import sys
import os
import glob

sys.path.insert(0, os.path.dirname(__file__))
from _bn_helpers import init_bn, load_c28x

binaryninja = init_bn()

FIXTURE_DIR = os.path.join(
    os.path.dirname(__file__), "..", "tests", "fixtures", "build"
)

EXPECTED_FUNCTIONS = {
    "led_blink.out": ["main", "delay", "gpio_toggle"],
    "pid_loop.out": ["main", "pid_init", "pid_compute", "run_pid_loop"],
    "switch_table.out": ["main", "process_command", "run_commands"],
    "isr_handler.out": [
        "main",
        "buf_init",
        "buf_put",
        "buf_get",
        "sci_rx_isr",
        "process_received",
    ],
}

total_pass = 0
total_fail = 0
total_warn = 0

fixture_files = sorted(glob.glob(os.path.join(FIXTURE_DIR, "*.out")))
if not fixture_files:
    print(f"[FAIL] No .out files found in {FIXTURE_DIR}")
    print("       Run: nix develop -c bash tests/fixtures/build.sh")
    sys.exit(1)

print(f"=== Validating {len(fixture_files)} fixtures ===\n")

for fixture_path in fixture_files:
    fixture_name = os.path.basename(fixture_path)
    print(f"--- {fixture_name} ---")

    # Load with word→byte address conversion
    bv = load_c28x(binaryninja, fixture_path)

    if bv is None:
        print(f"  [FAIL] Could not load {fixture_name}")
        total_fail += 1
        continue

    # Check architecture
    if bv.arch is None or "tms320" not in bv.arch.name:
        print(f"  [FAIL] Wrong architecture: {bv.arch}")
        total_fail += 1
        bv.file.close()
        continue

    print(f"  [OK] Architecture: {bv.arch.name}")
    total_pass += 1

    # Wait for analysis
    bv.update_analysis_and_wait()

    # Check function discovery
    func_names = {f.name for f in bv.functions}
    # TI C2000 prefixes C symbols with underscore
    expected = EXPECTED_FUNCTIONS.get(fixture_name, [])
    for fname in expected:
        # Try both _name (TI convention) and name (stripped)
        if fname in func_names or f"_{fname}" in func_names:
            print(f"  [OK] Found function: {fname}")
            total_pass += 1
        else:
            print(f"  [FAIL] Missing function: {fname}")
            print(
                f"         Available: {sorted(f.name for f in bv.functions if not f.name.startswith('sub_'))}"
            )
            total_fail += 1

    # Check IL quality
    llil_errors = 0
    mlil_errors = 0
    hlil_ok = 0
    hlil_fail = 0

    for func in bv.functions:
        # LLIL check
        try:
            llil = func.llil
            if llil:
                for block in llil:
                    for insn in block:
                        pass
        except Exception:
            llil_errors += 1

        # MLIL check
        try:
            mlil = func.mlil
            if mlil:
                for block in mlil:
                    for insn in block:
                        pass
        except Exception:
            mlil_errors += 1

        # HLIL / decompilation check
        try:
            hlil = func.hlil
            if hlil:
                hlil_ok += 1
        except Exception:
            hlil_fail += 1

    if llil_errors == 0:
        print("  [OK] LLIL: no errors")
        total_pass += 1
    else:
        print(f"  [FAIL] LLIL: {llil_errors} errors")
        total_fail += 1

    if mlil_errors == 0:
        print("  [OK] MLIL: no errors")
        total_pass += 1
    else:
        print(f"  [FAIL] MLIL: {mlil_errors} errors")
        total_fail += 1

    total_funcs = len(bv.functions)
    if hlil_fail == 0:
        print(f"  [OK] Decompilation: {hlil_ok}/{total_funcs} functions")
        total_pass += 1
    else:
        print(f"  [WARN] Decompilation: {hlil_ok}/{total_funcs} OK, {hlil_fail} failed")
        total_warn += 1

    print()
    bv.file.close()

print(f"{'=' * 50}")
print(f"TOTAL: {total_pass} passed, {total_fail} failed, {total_warn} warnings")
print(f"{'=' * 50}")
sys.exit(1 if total_fail > 0 else 0)
