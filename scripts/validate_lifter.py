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

# Instructions that legitimately have no IL effect -> a nop lift is correct.
INTENTIONAL_NOP = {"NOP", "ESTOP0", "ESTOP1", "IDLE", "ITRAP0", "ITRAP1",
                   "FLIP", "NOP_ZERO"}


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

    for w in starts:
        t = ti[w]
        mn = norm_mnem(t["mnem"])
        if mn in TI_PADDING_MNEMS:
            continue
        data = fetch(regions, w, 4)
        if len(data) < 2:
            continue
        total += 1
        try:
            il = LowLevelILFunction(arch)
            il.current_address = w * 2
            n = arch.get_instruction_low_level_il(data, w * 2, il)
            il.finalize()
        except Exception:
            n = 0
            il = None
        if not n or il is None:
            cats["lift_fail"] += 1
            gap_by_mnem[mn] += 1
            if len(examples["lift_fail"]) < args.limit_examples:
                examples["lift_fail"].append({"hex": "%06X" % w, "bytes": data.hex(),
                                              "mnem": t["mnem"], "ops": t["ops"]})
            continue
        nop_only = len(il) == 1 and il[0].operation == NOP
        if nop_only and mn in INTENTIONAL_NOP:
            cats["intentional_nop"] += 1
        elif nop_only:
            cats["nop_only"] += 1
            gap_by_mnem[mn] += 1
            if len(examples["nop_only"]) < args.limit_examples:
                examples["nop_only"].append({"hex": "%06X" % w, "bytes": data.hex(),
                                             "mnem": t["mnem"], "ops": t["ops"]})
        else:
            cats["real"] += 1

    covered = cats["real"]
    print("\n" + "=" * 60)
    print(f"  LIFTER COVERAGE: {covered}/{total} produce real IL "
          f"({100.0 * covered / total:.2f}%)")
    print("=" * 60)
    for k in ("real", "nop_only", "lift_fail", "intentional_nop"):
        print(f"  {k:16s} {cats[k]}")
    print("\n  top GAP mnemonics (nop-only / lift-fail on non-NOP instructions):")
    for mn, c in gap_by_mnem.most_common(30):
        print(f"    {mn:16s} {c}")

    json.dump({"dump": args.dump_dir, "total": total, "real": covered,
               "coverage_pct": round(100.0 * covered / total, 3) if total else 0,
               "categories": dict(cats),
               "gap_by_mnemonic": dict(gap_by_mnem), "examples": dict(examples)},
              open(args.out, "w"), indent=2)
    print(f"\n  corpus -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
