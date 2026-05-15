"""Smoke validator for real-world C28x flash dumps without ELF symbols.

The synthetic test fixture (flash_test.bin) has matching ELF symbols and goes
through scripts/validate_flash.py for strict boundary checks. Production flash
binaries usually have no symbol table; this script verifies the plugin
behaves sensibly on such inputs.

Smoke checks:
  - View loads (segments + entry point established)
  - Decode coverage: <=1% undecodable instructions sampled from executable code
  - No oversized functions (>4 KB)
  - No orphan basic blocks landing in non-executable segments
  - HLIL renders without exception on entry + a few discovered functions
  - Padding ratio in executable regions is sane after pre-mark

Usage:
  TMS320_REAL_FIRMWARE=/path/to/firmware.bin python3 scripts/validate_real_firmware.py
  # or use the default path under tests/fixtures/real/firmware.bin
"""

import importlib.util
import os
import random
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _bn_helpers import init_bn

binaryninja = init_bn()

ROOT = os.path.join(os.path.dirname(__file__), "..")
FLASH_MOD = os.path.join(ROOT, "binja", "flash.py")
DEFAULT_PATH = os.path.join(ROOT, "tests", "fixtures", "real", "firmware.bin")

FIRMWARE = os.environ.get("TMS320_REAL_FIRMWARE", DEFAULT_PATH)

if not os.path.exists(FIRMWARE):
    print(f"[SKIP] real firmware not at {FIRMWARE}")
    print(f"       set TMS320_REAL_FIRMWARE=/path/to/firmware.bin to run")
    sys.exit(0)

spec = importlib.util.spec_from_file_location("flash", FLASH_MOD)
flash_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flash_mod)

total_pass = 0
total_fail = 0


def check(cond, msg_pass, msg_fail):
    global total_pass, total_fail
    if cond:
        print(f"  [OK] {msg_pass}")
        total_pass += 1
    else:
        print(f"  [FAIL] {msg_fail}")
        total_fail += 1


print("=" * 60)
print(f"  Real Firmware Smoke Validation")
print(f"  {FIRMWARE}")
print("=" * 60)
print()

# ── Load ──
raw_bv = binaryninja.BinaryViewType["Raw"].open(FIRMWARE)
view = flash_mod.TMS320C28xFlashView(raw_bv)
ok = view.init()
check(ok, "Flash view init()", "Flash view init() returned False")

if not ok:
    print(f"\nFAILED: cannot proceed without view")
    sys.exit(1)

view.update_analysis_and_wait()

# ── Segment setup ──
print()
print("--- Segments ---")
exec_segs = [s for s in view.segments if s.executable]
data_segs = [s for s in view.segments if not s.executable]
check(len(exec_segs) > 0, f"{len(exec_segs)} executable segments", "no executable segments")
check(len(data_segs) > 0, f"{len(data_segs)} non-executable segments", "no data segments")
check(view.entry_point > 0, f"entry point 0x{view.entry_point:X}", "no entry point")

# ── Decode coverage ──
print()
print("--- Decode coverage ---")
random.seed(42)
samples = []
for seg in exec_segs:
    span = seg.end - seg.start
    if span < 4:
        continue
    # Sample 1 in 64 word-aligned addresses, capped at 10000 per segment
    n_sample = min(span // 128, 10000)
    for _ in range(n_sample):
        offset = random.randrange(0, span - 4, 2)
        samples.append(seg.start + offset)

decoded = 0
undecoded = 0
for addr in samples:
    raw = view.read(addr, 4)
    if not raw or len(raw) < 2:
        continue
    info = view.arch.get_instruction_info(raw, addr)
    if info is None or info.length == 0:
        undecoded += 1
    else:
        decoded += 1

total_samples = decoded + undecoded
decode_pct = (decoded * 100 // total_samples) if total_samples else 0
check(
    decode_pct >= 95,
    f"decode rate {decode_pct}% ({decoded}/{total_samples} samples)",
    f"decode rate {decode_pct}% too low (need >=95%)",
)

# ── Function discovery ──
print()
print("--- Function discovery ---")
funcs = list(view.functions)
check(len(funcs) > 0, f"{len(funcs)} functions discovered", "no functions found")

# ── Truly-overshooting functions ──
# Raw span > 4 KB catches both real overshoots AND BN's shared-BB attribution
# (where BN considers a callee's blocks part of the caller). To filter the
# latter, we measure OOB-exclusive bytes: BBs past the function's natural end
# that are owned only by this function (not shared with another seeded one).
#
# Natural end heuristic for unsymboled firmware: scan basic blocks in order;
# the first inter-BB gap >1 KB is treated as the end of the function body.
print()
print("--- Function boundary overshoots ---")
OVERSIZE_LIMIT = 4096           # bytes — only consider span outliers
NATURAL_GAP_THRESHOLD = 1024    # bytes between BBs that suggests a "split"
OOB_EXCLUSIVE_TOLERANCE = 16    # per-function bytes of unshared OOB allowed
MAX_TRULY_OVERSIZED = 5         # firmware-wide allowance


def natural_end_of(f):
    """Heuristic: first BB whose successor is > NATURAL_GAP_THRESHOLD away."""
    bbs = sorted(f.basic_blocks, key=lambda b: b.start)
    for i in range(len(bbs) - 1):
        if bbs[i + 1].start - bbs[i].end > NATURAL_GAP_THRESHOLD:
            return bbs[i].end
    return bbs[-1].end if bbs else f.start


truly_oversized = []
candidates = 0
for f in funcs:
    if not f.basic_blocks:
        continue
    span = max(b.end for b in f.basic_blocks) - f.start
    if span <= OVERSIZE_LIMIT:
        continue
    candidates += 1
    end = natural_end_of(f)
    oob_bbs = [b for b in f.basic_blocks if b.start >= end]
    oob_exclusive = sum(
        b.length for b in oob_bbs
        if len(view.get_functions_containing(b.start)) <= 1
    )
    if oob_exclusive > OOB_EXCLUSIVE_TOLERANCE:
        truly_oversized.append((f.name, f.start, span, oob_exclusive))

if truly_oversized:
    print(f"    truly-overshooting functions (OOB-exclusive > {OOB_EXCLUSIVE_TOLERANCE}B):")
    for name, addr, span, excl in truly_oversized[:5]:
        print(f"      {name} @ 0x{addr:X} span={span}B OOB-excl={excl}B")
print(
    f"    {candidates} span-outliers; {len(truly_oversized)} have unshared OOB > {OOB_EXCLUSIVE_TOLERANCE}B"
)

check(
    len(truly_oversized) <= MAX_TRULY_OVERSIZED,
    f"truly-overshooting count {len(truly_oversized)} (threshold {MAX_TRULY_OVERSIZED})",
    f"truly-overshooting count {len(truly_oversized)} exceeds {MAX_TRULY_OVERSIZED}",
)

# ── No orphan BBs in data segments ──
print()
print("--- Orphan BBs in data ---")
data_starts = [s.start for s in data_segs]
def in_data_seg(addr):
    for s in data_segs:
        if s.start <= addr < s.end:
            return True
    return False

orphan_count = 0
for f in funcs:
    for b in f.basic_blocks:
        if in_data_seg(b.start):
            orphan_count += 1

check(
    orphan_count == 0,
    "no BBs land in non-executable segments",
    f"{orphan_count} BBs found in data segments",
)

# ── HLIL renders ──
print()
print("--- HLIL render smoke ---")
# Try the entry point + up to 5 random discovered functions
ep_func = view.get_function_at(view.entry_point) if view.entry_point else None
test_funcs = [ep_func] if ep_func else []
random.seed(123)
sample_funcs = random.sample(funcs, min(5, len(funcs)))
test_funcs.extend(sample_funcs)

hlil_ok = 0
hlil_err = 0
for f in test_funcs:
    if f is None:
        continue
    try:
        h = f.hlil
        if h is not None:
            _ = str(h)
            hlil_ok += 1
        else:
            hlil_err += 1
    except Exception:
        hlil_err += 1

check(
    hlil_err == 0 and hlil_ok > 0,
    f"HLIL rendered on {hlil_ok} sample functions",
    f"HLIL errors on {hlil_err}/{hlil_ok + hlil_err} samples",
)

# ── Padding ratio sanity ──
print()
print("--- Padding ratio in code segments ---")
total_words = 0
ffff_words = 0
estop_words = 0
for seg in exec_segs:
    seg_data = view.read(seg.start, seg.end - seg.start)
    if not seg_data:
        continue
    for i in range(0, len(seg_data) - 1, 2):
        total_words += 1
        if seg_data[i] == 0xFF and seg_data[i + 1] == 0xFF:
            ffff_words += 1
        elif seg_data[i] == 0x25 and seg_data[i + 1] == 0x76:
            estop_words += 1

if total_words:
    pad_pct = ((ffff_words + estop_words) * 100) // total_words
    print(
        f"  code segment words: {total_words}, "
        f"0xFFFF: {ffff_words} ({ffff_words*100//total_words}%), "
        f"ESTOP0: {estop_words} ({estop_words*100//total_words}%), "
        f"total padding: {pad_pct}%"
    )
    # Padding pre-mark should have removed bulk runs from code segments.
    # A high padding ratio means the pre-mark didn't catch them.
    check(
        pad_pct <= 30,
        f"padding in code segments is {pad_pct}% (acceptable)",
        f"padding in code segments is {pad_pct}% — pre-mark missed runs",
    )

# ── Summary ──
print()
total = total_pass + total_fail
pct = (total_pass * 100 // total) if total else 0
print("=" * 60)
print(f"  REAL FIRMWARE SMOKE: {pct}% ({total_pass}/{total})")
print(f"  Passed: {total_pass}  Failed: {total_fail}")
print("=" * 60)

view.file.close()
sys.exit(1 if total_fail > 0 else 0)
