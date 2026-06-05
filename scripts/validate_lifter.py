"""Lifter coverage oracle: which real-firmware instructions lift to no IL.

There is no external ground truth for IL *semantics* (no dis2000 equivalent), so
this measures the one thing that is mechanical and high-value: COVERAGE. For
every instruction in the manifest `code_ranges`, it lifts the bytes with the
plugin's Binary Ninja architecture and flags those that produce only a bare
LLIL_NOP (the lifter's fall-through for unhandled instructions, arch.rs:
`if !lifted { il.nop() }`, and family handlers that internally `il.nop(); true`).

A "nop-only" lift on a non-NOP instruction is a decompilation gap: the function's
HLIL loses that instruction's effect. Genuine no-IL instructions (NOP, ESTOP0/1,
IDLE, bit-reverse FLIP) are listed separately and not counted as gaps.

Run:  nix develop -c python scripts/validate_lifter.py [<dump-dir>] [--out PATH]
"""
import argparse
import json
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(__file__))
from _bn_helpers import init_bn
from validate_decode_vs_dis import (parse_dis, load_regions, fetch,
                                     norm_mnem, TI_PADDING_MNEMS, DEFAULT_DUMP)

# Instructions that have NO LLIL representation in this arch model, so a nop is
# the correct lift (not a coverage gap). Each writes privileged/FPU-status/mode
# state or is a pipeline control with no IL primitive:
#   NOP/NOP_ZERO/IDLE       - no-op / wait
#   ESTOP0/1, ITRAP0/1      - halt / trap (handled as bp/no_ret or filler)
#   FLIP/NORM/CSB           - DSP ops with no IL primitive (bit-reverse, normalize, count-sign)
#   EALLOW/EDIS             - write-protection privilege bit
#   SPM                     - PM product-shift mode bits
#   SETFLG                  - FPU rounding/mode flags (not modeled)
#   MOVST0/MOVST1           - copy FPU status -> ST0 (FPU flags not modeled)
#   RPT/RPTB, ||RPT         - pipeline repeat (no IL loop primitive; the repeated insn lifts)
#   ||NOP/||NORM            - parallel-slot no-ops
#   NASP                    - SP-alignment artifact (paired with ASP)
#   ABORTI/LPADDR/IACK      - interrupt / pipeline hardware handshakes
#   SAT                     - OVM-mode-dependent clamp
#   SETC/CLRC               - the BN-modeled flag forms (C/OVM/TC) DO lift to
#                             set_flag (counted real); only the mode-only bits
#                             (SXM/INTM/DBGM/PAGE0/VMAP/OBJMODE/...) nop, and
#                             those have no BN flag to model.
#   .WORD                   - data, not an instruction
INTENTIONAL_NOP = {
    "NOP", "NOP_ZERO", "IDLE", "ESTOP0", "ESTOP1", "ITRAP0", "ITRAP1",
    "FLIP", "NORM", "CSB", "EALLOW", "EDIS", "SPM", "SETFLG",
    "MOVST0", "MOVST1", "RPT", "RPTB", "||RPT", "||NOP", "||NORM",
    "NASP", "ABORTI", "LPADDR", "IACK", "SAT", "SETC", "CLRC", ".WORD",
}

# The dump captures two memory regions: the J33 firmware FLASH (word
# 0x300000-0x33FFFF) and the F28335 on-chip BOOT ROM (word 0x3FE000-0x3FFFFF).
# The boot ROM is TI's bootloader + IQmath lookup TABLES — not the firmware
# under analysis. Its low region is data; dis2000 linearly disassembles those
# tables into nonsensical "instructions" (`.word` fallbacks, SETC-of-all-bits,
# FPU64 ops the FPU32-only F28335 can't execute), and the classifier carves
# false-positive code ranges out of them. Lifter "gaps" there are not real
# instructions, so the headline data-flow metric is computed on FLASH only;
# the boot-ROM region is reported separately for transparency.
BOOTROM_WORD = 0x3FE000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dump_dir", nargs="?", default=DEFAULT_DUMP)
    ap.add_argument("--out", default="/tmp/lifter_coverage.json")
    ap.add_argument("--limit-examples", type=int, default=40)
    args = ap.parse_args()

    dis = os.path.join(args.dump_dir, "dis", "dumped.dis")
    manifest = os.path.join(args.dump_dir, "dis", "dumped.analysis.json")
    for p in (dis, manifest):
        if not os.path.isfile(p):
            print(f"FAIL: missing {p}")
            return 1

    print("parsing dumped.dis ...", flush=True)
    ti = parse_dis(dis)
    code = json.load(open(manifest))["code_ranges"]
    regions = load_regions(args.dump_dir)

    bn = init_bn()
    arch = bn.Architecture["tms320c28x"]
    from binaryninja.lowlevelil import LowLevelILFunction, LowLevelILOperation
    NOP = LowLevelILOperation.LLIL_NOP
    print(f"  BN {bn.core_version()}; arch {arch.name}", flush=True)

    starts = sorted(a for a in ti
                    if any(r["start_word"] <= a < r["end_word"] for r in code))
    print(f"  lifting {len(starts)} instructions in code ranges ...", flush=True)

    cats = Counter()                  # real / nop_only / intentional_nop / lift_fail
    gap_by_mnem = Counter()           # mnemonic -> nop-only count (the gaps)
    examples = defaultdict(list)
    total = 0
    boot = Counter()                  # boot-ROM region tallies (reported separately)

    for w in starts:
        t = ti[w]
        mn = norm_mnem(t["mnem"])
        if mn in TI_PADDING_MNEMS:
            continue
        data = fetch(regions, w, 4)
        if len(data) < 2:
            continue
        try:
            il = LowLevelILFunction(arch)
            il.current_address = w * 2
            n = arch.get_instruction_low_level_il(data, w * 2, il)
            il.finalize()
        except Exception:
            n = 0
            il = None
        real = bool(n) and il is not None and not (len(il) == 1 and il[0].operation == NOP)

        # Boot ROM (>= 0x3FE000): known TI bootloader + IQmath data tables, not
        # the firmware. Tally separately; never counts toward the headline.
        if w >= BOOTROM_WORD:
            boot["total"] += 1
            boot["real" if real else "nop"] += 1
            continue

        total += 1
        def add_example(cat):  # bucket per mnemonic so every gap family has examples
            if len(examples[mn]) < args.limit_examples:
                examples[mn].append({"cat": cat, "hex": "%06X" % w,
                                     "bytes": data.hex(), "mnem": t["mnem"], "ops": t["ops"]})
        if not n or il is None:
            cats["lift_fail"] += 1
            gap_by_mnem[mn] += 1
            add_example("lift_fail")
            continue
        nop_only = len(il) == 1 and il[0].operation == NOP
        if nop_only and mn in INTENTIONAL_NOP:
            cats["intentional_nop"] += 1
        elif nop_only:
            cats["nop_only"] += 1
            gap_by_mnem[mn] += 1
            add_example("nop_only")
        else:
            cats["real"] += 1

    covered = cats["real"]
    dataflow = total - cats["intentional_nop"]   # instructions that SHOULD lift
    print("\n" + "=" * 60)
    print(f"  FLASH FIRMWARE (word < 0x3FE000)")
    print(f"  LIFTER COVERAGE: {covered}/{total} produce real IL "
          f"({100.0 * covered / total:.2f}%)")
    print(f"  data-flow coverage (excl. {cats['intentional_nop']} intentional-nop): "
          f"{covered}/{dataflow} ({100.0 * covered / dataflow:.2f}%)")
    print("=" * 60)
    for k in ("real", "nop_only", "lift_fail", "intentional_nop"):
        print(f"  {k:16s} {cats[k]}")
    if boot["total"]:
        print(f"\n  boot-ROM region (word >= 0x3FE000): {boot['total']} insns "
              f"({boot['nop']} nop) — EXCLUDED: TI boot ROM / IQmath data tables,")
        print(f"    classifier false-positives, not firmware (see BOOTROM_WORD note).")
    print("\n  top GAP mnemonics (nop-only / lift-fail on non-NOP instructions):")
    for mn, c in gap_by_mnem.most_common(30):
        print(f"    {mn:16s} {c}")

    json.dump({"dump": args.dump_dir, "total": total, "real": covered,
               "coverage_pct": round(100.0 * covered / total, 3) if total else 0,
               "dataflow_pct": round(100.0 * covered / dataflow, 3) if dataflow else 0,
               "categories": dict(cats),
               "bootrom_excluded": dict(boot),
               "gap_by_mnemonic": dict(gap_by_mnem), "examples": dict(examples)},
              open(args.out, "w"), indent=2)
    print(f"\n  corpus -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
