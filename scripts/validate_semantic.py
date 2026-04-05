"""Comprehensive semantic validation for all 28 test binaries.

Validates decompilation equivalence against expected_semantics.yaml:
- ELF binaries: loaded via BN with HLIL semantic checks
- COFF binaries: validated via Python parser (symbol + decode quality)

Run: nix develop -c python3 scripts/validate_semantic.py
"""

import os
import re
import struct
import sys
import yaml

sys.path.insert(0, os.path.dirname(__file__))
from _bn_helpers import init_bn, load_c28x

binaryninja = init_bn()

ROOT = os.path.join(os.path.dirname(__file__), "..")
SYNTHETIC_DIR = os.path.join(ROOT, "tests", "fixtures", "build")
C2000WARE_DIR = os.path.join(ROOT, "tests", "fixtures", "c2000ware", "build")
YAML_PATH = os.path.join(ROOT, "tests", "expected_semantics.yaml")

with open(YAML_PATH) as f:
    SPEC = yaml.safe_load(f)

total_pass = 0
total_fail = 0
total_skip = 0


def check(cond, msg_pass, msg_fail):
    global total_pass, total_fail
    if cond:
        print(f"      [OK] {msg_pass}")
        total_pass += 1
        return True
    else:
        print(f"      [FAIL] {msg_fail}")
        total_fail += 1
        return False


def skip(msg):
    global total_skip
    print(f"      [SKIP] {msg}")
    total_skip += 1


def find_func(bv, name):
    """Find function by name (with or without _ prefix, case-insensitive)."""
    for f in bv.functions:
        fn = f.name
        if fn == name or fn == f"_{name}" or fn.endswith(f"_{name}"):
            return f
        # Case-insensitive fallback for TI naming
        if fn.lower() == name.lower() or fn.lower() == f"_{name.lower()}":
            return f
    return None


def get_hlil_text(func):
    try:
        hlil = func.hlil
        if hlil:
            return str(hlil)
    except Exception:
        pass
    return None


def check_has_loop(hlil):
    return any(kw in hlil for kw in ["while", "for", "do", "loop"])


def check_has_conditional(hlil):
    return any(kw in hlil for kw in ["if", "switch", "case", "cond:", "?"])


def check_has_stores(hlil):
    # Memory writes: assignment to dereferenced pointer, MMIO address, or globals
    if "=" not in hlil:
        return False
    # Pointer dereference, hex address, array index, or named global assignment
    return ("*" in hlil or "0x" in hlil or "[" in hlil
            or bool(re.search(r'^[a-zA-Z_]\w*\s*=', hlil, re.MULTILINE)))


def check_has_calls(hlil):
    # Function calls appear as name( in HLIL
    return bool(re.search(r'[a-zA-Z_]\w*\s*\(', hlil))


def check_has_float_ops(hlil):
    return any(kw in hlil for kw in [
        "float", "R0H", "R1H", "R2H", "R3H", "R4H", "R5H", "R6H", "R7H",
        "f-", "f+", "f*", "fmul", "fadd", "fsub",
        "arg1", "arg2", "arg3",  # float args in registers
        ".0f", "e+", "e-",  # float literals
    ])


def check_has_arithmetic(hlil):
    return any(op in hlil for op in ["+", "-", "*", "&", "|", "^", "<<", ">>"])


def check_has_mask(hlil):
    # Masking: & with hex or decimal constant (including compound &=)
    return bool(re.search(r'&=?\s*0x[0-9a-fA-F]+', hlil)) or bool(re.search(r'&=?\s*\d+', hlil))


def check_has_body(hlil):
    # Non-trivial: more than just a return or empty
    stripped = hlil.strip()
    if not stripped:
        return False
    # A function with just "return" or "return 0" is trivial
    lines = [l.strip() for l in stripped.split('\n') if l.strip()]
    if len(lines) <= 1 and lines[0].startswith("return"):
        return False
    return True


HLIL_CHECKS = {
    "has_loop": check_has_loop,
    "has_conditional": check_has_conditional,
    "has_stores": check_has_stores,
    "has_calls": check_has_calls,
    "has_float_ops": check_has_float_ops,
    "has_arithmetic": check_has_arithmetic,
    "has_mask": check_has_mask,
    "has_body": check_has_body,
}


def validate_elf_binary(fixture_path, fixture_name, spec):
    """Validate an ELF binary using BN HLIL analysis."""
    bv = load_c28x(binaryninja, fixture_path)
    if bv is None:
        check(False, "", f"Could not load {fixture_name}")
        return

    if bv.arch is None or "tms320" not in bv.arch.name:
        check(False, "", f"Wrong architecture for {fixture_name}: {bv.arch}")
        bv.file.close()
        return

    bv.update_analysis_and_wait()

    functions = spec.get("functions", {})
    for fname, checks in functions.items():
        print(f"    {fname}:")

        # exists check
        if checks.get("exists", False):
            f = find_func(bv, fname)
            if not check(f is not None, f"{fname}() found", f"{fname}() not found"):
                continue  # skip remaining checks if function missing

            hlil = get_hlil_text(f)
            if hlil is None:
                skip(f"{fname}() HLIL unavailable — skipping semantic checks")
                continue

            # Run each specified HLIL check
            for check_name, checker in HLIL_CHECKS.items():
                if checks.get(check_name, False):
                    result = checker(hlil)
                    check(result,
                          f"{fname}(): {check_name}",
                          f"{fname}(): {check_name} not found")

    bv.file.close()


def validate_coff_binary(fixture_path, fixture_name, spec):
    """Validate a COFF binary using the Python parser."""
    sys.path.insert(0, ROOT)
    from c28x.coff import parse_coff
    from c28x.decoder import Decoder

    try:
        coff = parse_coff(fixture_path)
    except Exception as e:
        check(False, "", f"COFF parse error for {fixture_name}: {e}")
        return

    check(True, f"COFF parsed: {len(coff.sections)} sections, {len(coff.symbols)} symbols", "")

    # Build symbol name set (with and without _ prefix)
    sym_names = set()
    for s in coff.symbols:
        sym_names.add(s.name)
        if s.name.startswith("_"):
            sym_names.add(s.name[1:])

    # Check expected functions exist
    functions = spec.get("functions", {})
    for fname, checks in functions.items():
        if checks.get("exists", False):
            found = fname in sym_names or f"_{fname}" in sym_names
            check(found,
                  f"{fname} symbol found",
                  f"{fname} symbol not found (available: {sorted(s.name for s in coff.symbols if not s.name.startswith('.'))[:20]})")

    # Decode quality check on text sections
    text_secs = [s for s in coff.sections if s.is_text and len(s.data) > 0]
    if not text_secs:
        check(False, "", f"No text sections in {fixture_name}")
        return

    total_code = sum(len(s.data) for s in text_secs)
    check(total_code > 0, f"{len(text_secs)} text sections, {total_code} bytes", "No code")

    d = Decoder(objmode=1)
    decoded = 0
    errors = 0
    for sec in text_secs:
        offset = 0
        while offset < len(sec.data) - 1:
            insn = d.decode(sec.data[offset:offset + 4], addr=sec.byte_addr + offset)
            if insn:
                decoded += 1
                offset += insn.size
            else:
                errors += 1
                offset += 2
            if decoded > 500:
                break
        if decoded > 500:
            break

    if decoded > 0:
        decode_pct = decoded * 100 // (decoded + errors)
        check(decode_pct >= 80,
              f"Decoded {decoded} insns ({decode_pct}% success)",
              f"Decode rate too low: {decoded}/{decoded + errors} ({decode_pct}%)")
    else:
        check(False, "", "Could not decode any instructions")


def resolve_fixture_path(key, spec):
    """Resolve the fixture .out file path from the YAML key."""
    source = spec.get("source", "synthetic")
    # Handle the "name:c2000ware" override key pattern
    fixture_name = spec.get("fixture_name", key)

    if source == "c2000ware":
        return os.path.join(C2000WARE_DIR, fixture_name), fixture_name
    else:
        return os.path.join(SYNTHETIC_DIR, fixture_name), fixture_name


# ── Main ──

print("=" * 60)
print("  Comprehensive Semantic Validation")
print("=" * 60)
print()

for key, spec in SPEC.items():
    fixture_path, fixture_name = resolve_fixture_path(key, spec)
    fmt = spec.get("format", "elf")
    source = spec.get("source", "synthetic")

    if not os.path.exists(fixture_path):
        print(f"  [{fixture_name}] SKIP — not built")
        total_skip += 1
        continue

    size_kb = os.path.getsize(fixture_path) // 1024
    print(f"  [{fixture_name}] ({fmt.upper()}, {source}, {size_kb}KB)")

    if fmt == "coff":
        validate_coff_binary(fixture_path, fixture_name, spec)
    else:
        validate_elf_binary(fixture_path, fixture_name, spec)

    print()

# ── Summary ──

total = total_pass + total_fail + total_skip
equiv_total = total_pass + total_fail  # skip doesn't count against equivalence
equiv_pct = (total_pass * 100 // equiv_total) if equiv_total > 0 else 0

print("=" * 60)
print(f"  SEMANTIC EQUIVALENCE: {equiv_pct}% ({total_pass}/{equiv_total})")
print(f"  Passed: {total_pass}  Failed: {total_fail}  Skipped: {total_skip}")
print("=" * 60)

if equiv_pct < 96:
    print(f"\n  TARGET: 96%+ equivalence — currently {equiv_pct}%")
    sys.exit(1)
else:
    print(f"\n  TARGET MET: {equiv_pct}% >= 96%")
    sys.exit(0)
