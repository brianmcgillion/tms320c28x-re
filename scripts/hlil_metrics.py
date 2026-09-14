"""HLIL quality metrics — the ruler every decompilation change is judged by.

Walks every function of a fixed fixture set and counts the artifacts that make
decompiled output hard to read: registers that never became variables, calls
that appear to return a tuple, conditions BN could not synthesise from flags.

Loads via _bn_helpers.load_c28x, NOT binaryninja.load: the latter skips the
C28x word->byte conversion and decompiles plausible-looking nonsense from the
wrong addresses.

Each fixture runs in its own subprocess — BN 6.1 segfaults after roughly 15
BinaryViews have had their IL walked in one process.

Run: nix develop -c python3 scripts/hlil_metrics.py [--out tests/baselines/hlil.json]
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys

FIXTURE_DIR = os.path.join(
    os.path.dirname(__file__), "..", "tests", "fixtures", "c2000ware", "build"
)
FIXTURES = ["adc_epwm.out", "led_blink.out", "sci_echoback.out", "f2833x_fpu.out"]

_WORKER_FLAG = "--fixture"

# A call whose HLIL destination is a tuple: "a, b, c = f(...)". BN renders a
# multi-return call this way when it cannot tell which registers the callee
# actually defines.
RE_CALL = re.compile(r"^\s*([A-Za-z_][\w, ]*?) = \w+\(", re.M)
RE_COND_N = re.compile(r"cond:\d+")
RE_ACC = re.compile(r"\bACC(_\d+)?\b")
RE_XAR = re.compile(r"\bXAR[0-7](_\d+)?\b")
RE_VAR = re.compile(r"\bvar_[0-9a-f]+\b")
RE_IF = re.compile(r"\bif\s*\(")


def measure(path):
    sys.path.insert(0, os.path.dirname(__file__))
    from _bn_helpers import init_bn, load_c28x

    bn = init_bn()
    bv = load_c28x(bn, path)
    bv.update_analysis_and_wait()

    m = dict.fromkeys(
        [
            "funcs",
            "hlil_lines",
            "calls_total",
            "calls_multi_ret",
            "cond_n",
            "raw_acc",
            "raw_xar",
            "if_count",
            "unimplemented",
            "llil_total",
            "llil_unimpl",
            "hlil_fail",
        ],
        0,
    )
    variables = set()

    funcs = list(bv.functions)
    m["funcs"] = len(funcs)
    for f in funcs:
        try:
            text = str(f.hlil)
        except Exception:
            m["hlil_fail"] += 1
            continue

        m["hlil_lines"] += text.count("\n") + 1
        m["cond_n"] += len(RE_COND_N.findall(text))
        m["raw_acc"] += len(RE_ACC.findall(text))
        m["raw_xar"] += len(RE_XAR.findall(text))
        m["if_count"] += len(RE_IF.findall(text))
        m["unimplemented"] += text.count("unimplemented")
        variables.update(RE_VAR.findall(text))

        for dest in RE_CALL.findall(text):
            m["calls_total"] += 1
            if "," in dest:
                m["calls_multi_ret"] += 1

        try:
            for block in f.llil or []:
                for insn in block:
                    m["llil_total"] += 1
                    # str() on this IntEnum yields the integer, not the name.
                    if insn.operation.name in ("LLIL_UNIMPL", "LLIL_UNIMPL_MEM"):
                        m["llil_unimpl"] += 1
        except Exception:
            pass

    m["var_count"] = len(variables)
    return m


def main():
    if _WORKER_FLAG in sys.argv:
        path = sys.argv[sys.argv.index(_WORKER_FLAG) + 1]
        print("##JSON " + json.dumps(measure(path)))
        return 0

    out_path = None
    if "--out" in sys.argv:
        out_path = sys.argv[sys.argv.index("--out") + 1]

    results = {}
    for name in FIXTURES:
        path = os.path.join(FIXTURE_DIR, name)
        if not os.path.exists(path):
            print(f"  [SKIP] {name} — not built")
            continue
        proc = subprocess.run(
            [sys.executable, os.path.abspath(__file__), _WORKER_FLAG, path],
            capture_output=True,
            text=True,
        )
        line = next(
            (ln for ln in proc.stdout.splitlines() if ln.startswith("##JSON ")), None
        )
        if line is None:
            print(f"  [FAIL] {name} — worker exited {proc.returncode}")
            print(proc.stderr.strip()[-400:])
            return 1
        results[name] = json.loads(line[len("##JSON ") :])

    cols = [
        "funcs",
        "hlil_lines",
        "calls_multi_ret",
        "calls_total",
        "cond_n",
        "raw_acc",
        "raw_xar",
        "var_count",
        "if_count",
        "llil_total",
        "llil_unimpl",
    ]
    print(f"{'fixture':<20}" + "".join(f"{c:>17}" for c in cols))
    for name, m in results.items():
        print(f"{name:<20}" + "".join(f"{m.get(c, 0):>17}" for c in cols))

    if out_path:
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w") as fh:
            json.dump(results, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"\nwrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
