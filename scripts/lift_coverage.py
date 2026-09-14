"""Which instructions reach LLIL_UNIMPL, by occurrence count.

After B3's honesty switch an unlifted instruction says so instead of claiming to
have no effect, which makes the gap measurable for the first time. This list is
the backlog: B4 works down it in frequency order rather than authoring a table
row for all 413 encodings when a couple of dozen account for the damage.

Run: nix develop -c python3 scripts/lift_coverage.py [fixture ...]
"""

from __future__ import annotations

import collections
import json
import os
import subprocess
import sys

FIXTURE_DIR = os.path.join(
    os.path.dirname(__file__), "..", "tests", "fixtures", "c2000ware", "build"
)
DEFAULT = ["adc_epwm.out", "led_blink.out", "sci_echoback.out", "f2833x_fpu.out"]
_WORKER = "--fixture"


def measure(path):
    sys.path.insert(0, os.path.dirname(__file__))
    from _bn_helpers import init_bn, load_c28x

    bn = init_bn()
    bv = load_c28x(bn, path)
    bv.update_analysis_and_wait()

    # LLIL_UNIMPL carries no mnemonic, so recover it from the disassembly at the
    # same address.
    mnemonic_at = {}
    for f in bv.functions:
        for bb in f.basic_blocks:
            for line in bb.get_disassembly_text():
                text = str(line).strip()
                if text:
                    mnemonic_at[line.address] = text.split()[0]

    counts = collections.Counter()
    for f in bv.functions:
        try:
            blocks = f.llil or []
        except Exception:
            continue
        for bb in blocks:
            for insn in bb:
                if insn.operation.name in ("LLIL_UNIMPL", "LLIL_UNIMPL_MEM"):
                    counts[mnemonic_at.get(insn.address, "<unknown>")] += 1
    return counts


def main():
    if _WORKER in sys.argv:
        path = sys.argv[sys.argv.index(_WORKER) + 1]
        print("##JSON " + json.dumps(measure(path)))
        return 0

    fixtures = [a for a in sys.argv[1:] if not a.startswith("-")] or DEFAULT
    total = collections.Counter()
    per_fixture = {}
    for name in fixtures:
        path = name if os.path.exists(name) else os.path.join(FIXTURE_DIR, name)
        if not os.path.exists(path):
            print(f"  [SKIP] {name}")
            continue
        proc = subprocess.run(
            [sys.executable, os.path.abspath(__file__), _WORKER, path],
            capture_output=True,
            text=True,
        )
        line = next(
            (ln for ln in proc.stdout.splitlines() if ln.startswith("##JSON ")), None
        )
        if line is None:
            print(f"  [FAIL] {name}: worker exited {proc.returncode}")
            print(proc.stderr.strip()[-300:])
            continue
        counts = collections.Counter(json.loads(line[len("##JSON ") :]))
        per_fixture[os.path.basename(path)] = sum(counts.values())
        total.update(counts)

    grand = sum(total.values())
    print(f"{'mnemonic':<28}{'count':>8}{'cumulative %':>15}")
    running = 0
    for mnem, n in total.most_common():
        running += n
        print(f"{mnem:<28}{n:>8}{100.0 * running / max(grand, 1):>14.1f}%")
    print(
        f"\n{len(total)} distinct instructions, {grand} occurrences across "
        f"{len(per_fixture)} fixtures"
    )
    for name, n in per_fixture.items():
        print(f"    {name:<24}{n:>6}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
