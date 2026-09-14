"""Verdict on a candidate decompilation change: HLIL metric deltas vs a baseline.

Usage:
    python scripts/hlil_gate.py <after.json> [<baseline.json>]

Prints per-metric deltas and a VERDICT. Exits non-zero on REGRESSION, so it can
gate a commit. Metrics that are informational (function counts, IL size) are
reported but never fail the gate -- they move for legitimate reasons.
"""

import json
import os
import sys

DEFAULT_BASE = os.path.join(
    os.path.dirname(__file__), "..", "tests", "baselines", "hlil.json"
)

# Artifacts of poor lifting: calls whose return set BN could not determine,
# instructions with no IL at all.
LOWER_IS_BETTER = ["calls_multi_ret", "llil_unimpl", "hlil_fail"]
# "How register-y is the output" is a density, not a count. Recovering more code
# legitimately raises the absolute number: fixing conditional branches took
# f2833x_fpu if_count 34->46 and hlil_lines 1052->1099, and raw_acc rose 108->119
# with it. Judged per 100 HLIL lines these stay honest in both directions.
LOWER_IS_BETTER_DENSITY = ["raw_acc", "raw_xar"]
# Recovered structure.
HIGHER_IS_BETTER = ["var_count", "if_count"]
# cond_n is NOT a defect count. Inspection of every occurrence in adc_epwm shows
# BN synthesising the condition correctly and merely naming the boolean temp
# "cond:0" because the flag's definition and use are separated by intervening
# code. It rises when more real conditionals are recovered -- fixing conditional
# branches took f2833x_fpu if_count 34->46 and cond_n 5->8 together -- so gating
# on it downward would penalise the improvement.
INFORMATIONAL = [
    "funcs",
    "hlil_lines",
    "calls_total",
    "llil_total",
    "cond_n",
    "raw_acc",
    "raw_xar",
]


def material(metric, baseline, delta):
    """Is this delta worth failing a commit over?

    Emitting more IL legitimately shifts variable naming downstream, so a real
    improvement routinely moves an unrelated counter by a token or two. Observed:
    fixing MOVL XARn,#const22 dropped raw_xar by 21 and moved raw_acc by +1 on the
    same binary. Without a floor the gate fails on every genuine win.

    The floor is relative, not absolute: 1 token in 337 raw_acc is noise, but 2 in
    12 multi-return calls is a quarter of the problem.
    """
    return abs(delta) > max(1, baseline * 0.02)


def main(argv):
    if len(argv) < 2:
        print(__doc__.strip())
        return 2
    after = json.load(open(argv[1]))
    base = json.load(open(argv[2] if len(argv) > 2 else DEFAULT_BASE))

    regressions, improvements = [], []
    for fixture in sorted(set(base) | set(after)):
        b, a = base.get(fixture), after.get(fixture)
        if b is None or a is None:
            regressions.append(f"{fixture}: present in only one run")
            continue
        print(f"\n{fixture}")
        for metric in LOWER_IS_BETTER_DENSITY:
            bd = 100.0 * b.get(metric, 0) / max(b.get("hlil_lines", 1), 1)
            ad = 100.0 * a.get(metric, 0) / max(a.get("hlil_lines", 1), 1)
            delta = ad - bd
            if abs(delta) <= max(0.1, bd * 0.02):
                continue
            better = delta < 0
            print(
                f"  {metric + '/100ln':<18} {bd:>7.1f} -> {ad:<7.1f} ({delta:+.1f})"
                + ("  better" if better else "  WORSE")
            )
            (improvements if better else regressions).append(
                f"{fixture}/{metric} {bd:.1f}->{ad:.1f} per 100ln"
            )

        for metric in LOWER_IS_BETTER + HIGHER_IS_BETTER + INFORMATIONAL:
            bv, av = b.get(metric, 0), a.get(metric, 0)
            if bv == av:
                continue
            delta = av - bv
            better = delta < 0 if metric in LOWER_IS_BETTER else delta > 0
            tag = (
                ""
                if metric in INFORMATIONAL
                else "  better"
                if better and material(metric, bv, delta)
                else "  WORSE"
                if material(metric, bv, delta)
                else "  (within noise)"
            )
            print(f"  {metric:<18} {bv:>7} -> {av:<7} ({delta:+d}){tag}")
            if metric in INFORMATIONAL or not material(metric, bv, delta):
                continue
            (improvements if better else regressions).append(
                f"{fixture}/{metric} {bv}->{av}"
            )

    print("\nIMPROVED:   ", ", ".join(improvements) if improvements else "none")
    print("REGRESSED:  ", ", ".join(regressions) if regressions else "NONE")
    verdict = (
        "REGRESSION" if regressions else "IMPROVEMENT" if improvements else "NO_CHANGE"
    )
    print("VERDICT:", verdict)
    return 1 if verdict == "REGRESSION" else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
