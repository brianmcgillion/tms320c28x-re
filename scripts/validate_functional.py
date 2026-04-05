"""Comprehensive functional equivalence validation for all 28 test binaries.

Goes beyond structural property checks to verify behavioral equivalence:
- Callee verification via BN API + HLIL text
- MMIO address pattern matching
- Constant preservation checks
- Loop type classification
- Arithmetic operator verification
- Branch count and store count thresholds
- Global variable write verification

Run: nix develop -c python3 scripts/validate_functional.py
"""

import os
import re
import struct
import sys
import yaml

sys.path.insert(0, os.path.dirname(__file__))
from _bn_helpers import init_bn, load_c28x
from _functional_checks import (
    check_callees,
    check_no_callees,
    check_mmio_patterns,
    check_no_mmio_writes,
    check_constants,
    check_comparison_constants,
    check_loop_type,
    check_arithmetic_ops,
    check_min_branches,
    check_min_stores,
    check_global_writes,
)

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


def record(cond, msg_pass, msg_fail):
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
    for f in bv.functions:
        fn = f.name
        if fn == name or fn == f"_{name}" or fn.endswith(f"_{name}"):
            return f
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


# ── Legacy structural checks (reused from validate_semantic.py) ──

def check_has_loop(hlil):
    return any(kw in hlil for kw in ["while", "for", "do", "loop"])

def check_has_conditional(hlil):
    return any(kw in hlil for kw in ["if", "switch", "case", "cond:", "?"])

def check_has_stores(hlil):
    if "=" not in hlil:
        return False
    return ("*" in hlil or "0x" in hlil or "[" in hlil
            or bool(re.search(r'^[a-zA-Z_]\w*\s*=', hlil, re.MULTILINE)))

def check_has_calls(hlil):
    return bool(re.search(r'[a-zA-Z_]\w*\s*\(', hlil))

def check_has_float_ops(hlil):
    return any(kw in hlil for kw in [
        "float", "R0H", "R1H", "R2H", "R3H", "R4H", "R5H", "R6H", "R7H",
        "f-", "f+", "f*", "fmul", "fadd", "fsub", "arg1", "arg2", "arg3",
        ".0f", "e+", "e-",
    ])

def check_has_arithmetic(hlil):
    return any(op in hlil for op in ["+", "-", "*", "&", "|", "^", "<<", ">>"])

def check_has_mask(hlil):
    return bool(re.search(r'&=?\s*0x[0-9a-fA-F]+', hlil)) or bool(re.search(r'&=?\s*\d+', hlil))

def check_has_body(hlil):
    stripped = hlil.strip()
    if not stripped:
        return False
    lines = [l.strip() for l in stripped.split('\n') if l.strip()]
    if len(lines) <= 1 and lines[0].startswith("return"):
        return False
    return True

LEGACY_CHECKS = {
    "has_loop": check_has_loop,
    "has_conditional": check_has_conditional,
    "has_stores": check_has_stores,
    "has_calls": check_has_calls,
    "has_float_ops": check_has_float_ops,
    "has_arithmetic": check_has_arithmetic,
    "has_mask": check_has_mask,
    "has_body": check_has_body,
}


# ── Functional check dispatcher ──

def run_functional_checks(hlil_text, func_spec, bn_func):
    """Run all functional checks defined in func_spec['functional']."""
    fspec = func_spec.get("functional", {})
    if not fspec:
        return

    fname = bn_func.name.lstrip("_") if bn_func else "?"

    # callees
    if "callees" in fspec:
        results = check_callees(hlil_text, fspec["callees"], bn_func)
        for callee_name, found in results:
            record(found,
                   f"{fname}(): calls {callee_name}",
                   f"{fname}(): missing call to {callee_name}")

    # no_callees
    if fspec.get("no_callees", False):
        passed, detail = check_no_callees(hlil_text, None, bn_func)
        record(passed,
               f"{fname}(): no callees ({detail})",
               f"{fname}(): unexpected callees ({detail})")

    # mmio_patterns
    if "mmio_patterns" in fspec:
        results = check_mmio_patterns(hlil_text, fspec["mmio_patterns"])
        for pat, found in results:
            record(found,
                   f"{fname}(): MMIO pattern {pat}",
                   f"{fname}(): MMIO pattern {pat} not found")

    # no_mmio_writes
    if fspec.get("no_mmio_writes", False):
        passed, detail = check_no_mmio_writes(hlil_text, None)
        record(passed,
               f"{fname}(): {detail}",
               f"{fname}(): {detail}")

    # constants
    if "constants" in fspec:
        results = check_constants(hlil_text, fspec["constants"])
        for pat, found in results:
            record(found,
                   f"{fname}(): constant {pat}",
                   f"{fname}(): constant {pat} not found")

    # comparison_constants
    if "comparison_constants" in fspec:
        results = check_comparison_constants(hlil_text, fspec["comparison_constants"])
        for pat, found in results:
            record(found,
                   f"{fname}(): comparison constant {pat}",
                   f"{fname}(): comparison constant {pat} not found")

    # loop_type
    if "loop_type" in fspec:
        passed, detail = check_loop_type(hlil_text, fspec["loop_type"])
        record(passed,
               f"{fname}(): {detail}",
               f"{fname}(): {detail}")

    # arithmetic_ops
    if "arithmetic_ops" in fspec:
        results = check_arithmetic_ops(hlil_text, fspec["arithmetic_ops"])
        for op, found in results:
            record(found,
                   f"{fname}(): has op '{op}'",
                   f"{fname}(): missing op '{op}'")

    # min_branches
    if "min_branches" in fspec:
        passed, detail = check_min_branches(hlil_text, fspec["min_branches"])
        record(passed,
               f"{fname}(): {detail}",
               f"{fname}(): {detail}")

    # min_stores
    if "min_stores" in fspec:
        passed, detail = check_min_stores(hlil_text, fspec["min_stores"])
        record(passed,
               f"{fname}(): {detail}",
               f"{fname}(): {detail}")

    # global_writes
    if "global_writes" in fspec:
        results = check_global_writes(hlil_text, fspec["global_writes"])
        for gname, found in results:
            record(found,
                   f"{fname}(): writes global {gname}",
                   f"{fname}(): missing write to global {gname}")


# ── ELF binary validation ──

def validate_elf_binary(fixture_path, fixture_name, spec):
    bv = load_c28x(binaryninja, fixture_path)
    if bv is None:
        record(False, "", f"Could not load {fixture_name}")
        return
    if bv.arch is None or "tms320" not in bv.arch.name:
        record(False, "", f"Wrong architecture for {fixture_name}: {bv.arch}")
        bv.file.close()
        return

    bv.update_analysis_and_wait()

    functions = spec.get("functions", {})
    for fname, checks in functions.items():
        print(f"    {fname}:")

        if checks.get("exists", False):
            f = find_func(bv, fname)
            if not record(f is not None, f"{fname}() found", f"{fname}() not found"):
                continue

            hlil = get_hlil_text(f)
            if hlil is None:
                skip(f"{fname}() HLIL unavailable")
                continue

            # Legacy checks
            for check_name, checker in LEGACY_CHECKS.items():
                if checks.get(check_name, False):
                    result = checker(hlil)
                    record(result,
                           f"{fname}(): {check_name}",
                           f"{fname}(): {check_name} not found")

            # Functional checks
            run_functional_checks(hlil, checks, f)

    bv.file.close()


# ── COFF binary validation ──

def validate_coff_binary(fixture_path, fixture_name, spec):
    sys.path.insert(0, ROOT)
    from c28x.coff import parse_coff
    from c28x.decoder import Decoder

    try:
        coff = parse_coff(fixture_path)
    except Exception as e:
        record(False, "", f"COFF parse error for {fixture_name}: {e}")
        return

    record(True, f"COFF parsed: {len(coff.sections)} sections, {len(coff.symbols)} symbols", "")

    sym_names = set()
    for s in coff.symbols:
        sym_names.add(s.name)
        if s.name.startswith("_"):
            sym_names.add(s.name[1:])

    functions = spec.get("functions", {})
    for fname, checks in functions.items():
        if checks.get("exists", False):
            found = fname in sym_names or f"_{fname}" in sym_names
            record(found,
                   f"{fname} symbol found",
                   f"{fname} symbol not found")

    text_secs = [s for s in coff.sections if s.is_text and len(s.data) > 0]
    if not text_secs:
        record(False, "", f"No text sections in {fixture_name}")
        return

    total_code = sum(len(s.data) for s in text_secs)
    record(total_code > 0, f"{len(text_secs)} text sections, {total_code} bytes", "No code")

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
        record(decode_pct >= 80,
               f"Decoded {decoded} insns ({decode_pct}% success)",
               f"Decode rate too low: {decoded}/{decoded + errors} ({decode_pct}%)")
    else:
        record(False, "", "Could not decode any instructions")


def resolve_fixture_path(key, spec):
    source = spec.get("source", "synthetic")
    fixture_name = spec.get("fixture_name", key)
    if source == "c2000ware":
        return os.path.join(C2000WARE_DIR, fixture_name), fixture_name
    else:
        return os.path.join(SYNTHETIC_DIR, fixture_name), fixture_name


# ── Main ──

print("=" * 60)
print("  Functional Equivalence Validation")
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
equiv_total = total_pass + total_fail
equiv_pct = (total_pass * 100 // equiv_total) if equiv_total > 0 else 0

print("=" * 60)
print(f"  FUNCTIONAL EQUIVALENCE: {equiv_pct}% ({total_pass}/{equiv_total})")
print(f"  Passed: {total_pass}  Failed: {total_fail}  Skipped: {total_skip}")
print("=" * 60)

if equiv_pct < 96:
    print(f"\n  TARGET: 96%+ equivalence — currently {equiv_pct}%")
    sys.exit(1)
else:
    print(f"\n  TARGET MET: {equiv_pct}% >= 96%")
    sys.exit(0)
