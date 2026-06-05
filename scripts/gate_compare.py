"""Verdict on a candidate isa/ change: structural defect delta + regressions vs
the baseline differential, using dis2000 as ground truth.

Structural defect = DECODE_FAIL + LEN + MNEM (wrong instruction identity or
length). OPVAL (operand value/rendering) and MNEM_DISP (display-only) are
secondary and not counted here -- a fix that converts MNEM -> OPVAL (correct
instruction, non-idiomatic operand) is still a structural win.

Usage:
    python scripts/gate_compare.py <after.json> [<baseline.json>]

Prints FIXED / REGRESSIONS per mnemonic and a VERDICT. A change is acceptable
iff VERDICT is CLEAN_IMPROVEMENT (structural defects down, zero regressions).
"""
import json
import sys

BASE = "/tmp/decode_vs_dis_py.json"


def struct(cats):
    return cats.get("DECODE_FAIL", 0) + cats.get("LEN", 0) + cats.get("MNEM", 0)


def main(argv):
    after = json.load(open(argv[1]))
    base = json.load(open(argv[2] if len(argv) > 2 else BASE))
    sb, sa = struct(base["categories"]), struct(after["categories"])
    print(f"structural defects: {sb} -> {sa}  (delta {sa - sb:+d})")
    print(f"decode_correct:     {base['decode_correct']} -> {after['decode_correct']}"
          f"  (delta {after['decode_correct'] - base['decode_correct']:+d})")
    mb, ma = base["by_mnemonic"], after["by_mnemonic"]
    regs, fixes = [], []
    for mn in sorted(set(list(mb) + list(ma))):
        db, da = struct(mb.get(mn, {})), struct(ma.get(mn, {}))
        if da > db:
            regs.append(f"{mn}:{db}->{da}")
        elif da < db:
            fixes.append(f"{mn}:{db}->{da}")
    print("FIXED:      ", ", ".join(fixes) if fixes else "none")
    print("REGRESSIONS:", ", ".join(regs) if regs else "NONE")
    verdict = ("CLEAN_IMPROVEMENT" if sa < sb and not regs
               else "REGRESSION" if regs else "NO_CHANGE")
    print("VERDICT:", verdict)
    return 0 if verdict == "CLEAN_IMPROVEMENT" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
