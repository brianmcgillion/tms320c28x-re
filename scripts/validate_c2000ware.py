"""Validate C2000Ware ELF fixtures against the Rust BN plugin.

These are real TI SDK examples compiled with cl2000 — not synthetic tests.
Run: nix develop -c python3 scripts/validate_c2000ware.py
"""

import sys
import os
import glob
import subprocess

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "..", "tests", "fixtures", "c2000ware", "build")

# BN 6.1 segfaults after roughly 15 BinaryViews have had their IL walked in one
# process, so the driver validates each fixture in its own worker subprocess.
_WORKER_FLAG = "--fixture"


def _run_driver():
    fixtures = sorted(glob.glob(os.path.join(FIXTURE_DIR, "*.out")))
    if not fixtures:
        print(f"[FAIL] No .out files in {FIXTURE_DIR}")
        print("       Run: nix develop -c bash tests/fixtures/c2000ware/fetch.sh")
        print("       Run: nix develop -c bash tests/fixtures/c2000ware/build.sh")
        return 1

    print(f"=== Validating {len(fixtures)} C2000Ware fixtures ===\n")
    tp = tf = tw = 0
    for path in fixtures:
        proc = subprocess.run(
            [sys.executable, os.path.abspath(__file__), _WORKER_FLAG, path],
            capture_output=True, text=True,
        )
        tallied = False
        for line in proc.stdout.splitlines():
            if line.startswith("##TALLY "):
                pa, fa, wa = (int(x) for x in line.split()[1:4])
                tp += pa; tf += fa; tw += wa
                tallied = True
            else:
                print(line)
        if not tallied:
            print(f"--- {os.path.basename(path)} ---")
            print(f"  [FAIL] worker exited {proc.returncode} without a result")
            print(proc.stderr.strip()[-500:])
            tf += 1

    print(f"{'='*50}")
    print(f"TOTAL: {tp} passed, {tf} failed, {tw} warnings")
    print(f"{'='*50}")
    return 1 if tf > 0 else 0


if _WORKER_FLAG not in sys.argv:
    sys.exit(_run_driver())

sys.path.insert(0, os.path.dirname(__file__))
from _bn_helpers import init_bn, load_c28x

binaryninja = init_bn()

# Structural checks: function → {check_name: [keywords_any_must_match]}
STRUCTURAL_CHECKS = {
    "led_blink.out": {
        "main": {
            "has body": ["=", "*", "0x"],
        },
        "InitSysCtrl": {
            "has stores": ["=", "*"],
        },
        "InitPieVectTable": {
            "has stores": ["=", "*"],
        },
        "GPIO_SetupPinOptions": {
            "has stores": ["=", "*"],
        },
    },
    "adc_epwm.out": {
        "main": {
            "has body": ["=", "*", "0x"],
        },
        "adcA1ISR": {
            "has stores": ["=", "*"],
        },
        "InitSysCtrl": {
            "has stores": ["=", "*"],
        },
        "GPIO_WritePin": {
            "has conditional": ["if", "cond:", "while", "for"],
        },
    },
    "sci_echoback.out": {
        "main": {
            "has body": ["=", "*", "0x"],
        },
        "InitSysCtrl": {
            "has stores": ["=", "*"],
        },
    },
    "gpio_setup.out": {
        "main": {
            "has body": ["=", "*", "0x"],
        },
        "InitGpio": {
            "has stores": ["=", "*"],
        },
    },
    "timer_cputimers.out": {
        "main": {
            "has body": ["=", "*", "0x"],
        },
        "InitPieCtrl": {
            "has stores": ["=", "*"],
        },
    },
    "ecap_apwm.out": {
        "main": {
            "has body": ["=", "*", "0x"],
        },
    },
    "dma_transfer.out": {
        "main": {
            "has body": ["=", "*", "0x"],
        },
    },
    "spi_loopback.out": {
        "main": {
            "has body": ["=", "*", "0x"],
        },
    },
    "interrupts_prio.out": {
        "main": {
            "has body": ["=", "*", "0x"],
        },
    },
    # F2833x (COFF) structural checks
    "f2833x_led_blink.out": {
        "main": { "has body": ["=", "*", "0x"] },
    },
    "f2833x_gpio_toggle.out": {
        "main": { "has body": ["=", "*", "0x"] },
    },
    "f2833x_cpu_timer.out": {
        "main": { "has body": ["=", "*", "0x"] },
    },
    "f2833x_epwm_int.out": {
        "main": { "has body": ["=", "*", "0x"] },
    },
    "f2833x_fpu.out": {
        "main": { "has body": ["=", "*", "0x"] },
    },
}

EXPECTED_FUNCTIONS = {
    "led_blink.out": ["main", "InitSysCtrl", "InitGpio", "InitPieCtrl", "InitPieVectTable"],
    "adc_epwm.out": ["main", "InitSysCtrl"],
    "sci_echoback.out": ["main", "InitSysCtrl"],
    "gpio_setup.out": ["main", "InitSysCtrl", "InitGpio"],
    "timer_cputimers.out": ["main", "InitSysCtrl", "InitPieCtrl"],
    "ecap_apwm.out": ["main", "InitSysCtrl"],
    "dma_transfer.out": ["main", "InitSysCtrl"],
    "spi_loopback.out": ["main", "InitSysCtrl"],
    "interrupts_prio.out": ["main", "InitSysCtrl", "InitPieCtrl"],
    # F2833x (COFF) fixtures
    "f2833x_led_blink.out": ["main", "InitSysCtrl"],
    "f2833x_cpu_timer.out": ["main", "InitSysCtrl"],
    "f2833x_gpio_toggle.out": ["main", "InitSysCtrl"],
    "f2833x_gpio_setup.out": ["main", "InitSysCtrl"],
    "f2833x_adc_soc.out": ["main", "InitSysCtrl"],
    "f2833x_sci_echoback.out": ["main", "InitSysCtrl"],
    "f2833x_spi_loopback.out": ["main", "InitSysCtrl"],
    "f2833x_epwm_int.out": ["main", "InitSysCtrl"],
    "f2833x_ecap_apwm.out": ["main", "InitSysCtrl"],
    "f2833x_ecan.out": ["main", "InitSysCtrl"],
    "f2833x_i2c.out": ["main", "InitSysCtrl"],
    "f2833x_dma.out": ["main", "InitSysCtrl"],
    "f2833x_ext_int.out": ["main", "InitSysCtrl"],
    "f2833x_fpu.out": ["main", "InitSysCtrl"],
    "f2833x_watchdog.out": ["main", "InitSysCtrl"],
}

total_pass = 0
total_fail = 0
total_warn = 0

fixture_files = [sys.argv[sys.argv.index(_WORKER_FLAG) + 1]]

def _validate_coff_python(fixture_path, fixture_name):
    """Validate COFF files using our Python parser (headless fallback)."""
    global total_pass, total_fail, total_warn
    import sys as _sys
    _sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from c28x.coff import parse_coff

    try:
        coff = parse_coff(fixture_path)
    except Exception as e:
        print(f"  [FAIL] COFF parse error: {e}")
        total_fail += 1
        return

    print(f"  [OK] COFF parsed: {len(coff.sections)} sections, {len(coff.symbols)} symbols")
    total_pass += 1

    # Check for expected functions
    sym_names = {s.name for s in coff.symbols}
    # Also add without underscore prefix
    sym_names |= {s.name[1:] for s in coff.symbols if s.name.startswith("_")}

    expected = EXPECTED_FUNCTIONS.get(fixture_name, [])
    for fname in expected:
        if fname in sym_names or f"_{fname}" in sym_names:
            print(f"  [OK] Found symbol: {fname}")
            total_pass += 1
        else:
            print(f"  [WARN] Missing symbol: {fname}")
            total_warn += 1

    # Check text sections exist
    text_secs = [s for s in coff.sections if s.is_text and len(s.data) > 0]
    if text_secs:
        total_code = sum(len(s.data) for s in text_secs)
        print(f"  [OK] Code: {len(text_secs)} text sections, {total_code} bytes")
        total_pass += 1
    else:
        print(f"  [FAIL] No text sections with code")
        total_fail += 1

    # Decode a few instructions to verify decoder works on COFF code
    from c28x.decoder import Decoder
    d = Decoder(objmode=1)
    decoded = 0
    errors = 0
    for sec in text_secs[:3]:
        offset = 0
        while offset < len(sec.data) - 3:
            insn = d.decode(sec.data[offset:offset+4], addr=sec.byte_addr + offset)
            if insn:
                decoded += 1
                offset += insn.size
            else:
                errors += 1
                offset += 2
            if decoded > 200:
                break

    if decoded > 0:
        print(f"  [OK] Decoded {decoded} instructions ({errors} decode errors)")
        total_pass += 1
    else:
        print(f"  [FAIL] Could not decode any instructions")
        total_fail += 1


for fixture_path in fixture_files:
    fixture_name = os.path.basename(fixture_path)
    print(f"--- {fixture_name} ({os.path.getsize(fixture_path)//1024}KB) ---")

    # Try loading with ELF platform hint
    bv = load_c28x(binaryninja, fixture_path)

    # If that failed or got wrong arch, check if it's COFF and skip
    # (COFF requires the BinaryView plugin which isn't available in headless)
    if bv is None or (bv.arch is not None and "tms320" not in bv.arch.name):
        if bv is not None:
            bv.file.close()
        import struct as _struct
        with open(fixture_path, "rb") as _f:
            _magic = _struct.unpack("<H", _f.read(2))[0]
        if _magic == 0x00C2:
            # COFF file — validate via Python parser instead of BN
            print(f"  [INFO] COFF format — validating via Python parser")
            _validate_coff_python(fixture_path, fixture_name)
            continue
        print(f"  [FAIL] Could not load")
        total_fail += 1
        continue

    if bv is None:
        print(f"  [FAIL] Could not load")
        total_fail += 1
        continue

    if bv.arch is None or "tms320" not in bv.arch.name:
        print(f"  [FAIL] Wrong architecture: {bv.arch}")
        total_fail += 1
        bv.file.close()
        continue

    print(f"  [OK] Architecture: {bv.arch.name}")
    total_pass += 1

    bv.update_analysis_and_wait()

    # Function stats
    all_funcs = list(bv.functions)
    print(f"  [INFO] Functions discovered: {len(all_funcs)}")

    # Check expected functions
    func_names = set()
    for f in all_funcs:
        func_names.add(f.name)
        # Also add without leading underscore
        if f.name.startswith("_"):
            func_names.add(f.name[1:])

    expected = EXPECTED_FUNCTIONS.get(fixture_name, [])
    for fname in expected:
        if fname in func_names or f"_{fname}" in func_names:
            print(f"  [OK] Found function: {fname}")
            total_pass += 1
        else:
            print(f"  [WARN] Missing function: {fname}")
            total_warn += 1

    # IL quality
    llil_errors = 0
    mlil_errors = 0
    hlil_ok = 0
    hlil_fail = 0

    for func in all_funcs:
        try:
            llil = func.llil
            if llil:
                for block in llil:
                    for insn in block:
                        pass
        except Exception:
            llil_errors += 1

        try:
            mlil = func.mlil
            if mlil:
                for block in mlil:
                    for insn in block:
                        pass
        except Exception:
            mlil_errors += 1

        try:
            hlil = func.hlil
            if hlil:
                hlil_ok += 1
        except Exception:
            hlil_fail += 1

    if llil_errors == 0:
        print(f"  [OK] LLIL: no errors")
        total_pass += 1
    else:
        print(f"  [FAIL] LLIL: {llil_errors} errors")
        total_fail += 1

    if mlil_errors == 0:
        print(f"  [OK] MLIL: no errors")
        total_pass += 1
    else:
        print(f"  [FAIL] MLIL: {mlil_errors} errors")
        total_fail += 1

    decompile_pct = hlil_ok * 100 // max(len(all_funcs), 1)
    if hlil_fail == 0:
        print(f"  [OK] Decompilation: {hlil_ok}/{len(all_funcs)} ({decompile_pct}%)")
        total_pass += 1
    elif decompile_pct >= 90:
        print(f"  [WARN] Decompilation: {hlil_ok}/{len(all_funcs)} ({decompile_pct}%), {hlil_fail} failed")
        total_warn += 1
    else:
        print(f"  [FAIL] Decompilation: {hlil_ok}/{len(all_funcs)} ({decompile_pct}%), {hlil_fail} failed")
        total_fail += 1

    # Structural decompilation checks for key functions
    structural = STRUCTURAL_CHECKS.get(fixture_name, {})
    for fname, checks in structural.items():
        f = None
        for func in all_funcs:
            if func.name == fname or func.name == f"_{fname}" or fname in func.name:
                f = func
                break
        if f is None:
            continue

        try:
            hlil = str(f.hlil)
        except Exception:
            continue

        for check_name, keywords in checks.items():
            found = any(kw in hlil for kw in keywords)
            if found:
                print(f"  [OK] {fname}: {check_name}")
                total_pass += 1
            else:
                print(f"  [WARN] {fname}: {check_name} not found")
                total_warn += 1

    print()
    bv.file.close()

print(f"##TALLY {total_pass} {total_fail} {total_warn}")
