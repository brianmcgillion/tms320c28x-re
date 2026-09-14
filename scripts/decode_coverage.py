"""Decode coverage against dis2000, TI's own disassembler.

The only external ground truth in the repo. For every instruction dis2000
identifies in the fixtures, feed the same words to our decoder and compare.

Needs no Binary Ninja and no licence -- it talks to c28xdec, so it can gate CI.
That is the point: scripts/validate_decode_vs_dis.py does the same job through a
BN-linked plugin and consequently has never run in CI.

Padding is excluded: TI renders erased flash as ITRAP1 and zero words as ITRAP0,
and .word means TI itself could not decode it, so none of those are our failure.

Run: nix develop -c python3 scripts/decode_coverage.py
     ... --baseline tests/baselines/decode.json        compare, fail on regression
     ... --write-baseline tests/baselines/decode.json  bank the current numbers
"""

from __future__ import annotations

import collections
import glob
import json
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.join(os.path.dirname(__file__), "..")
FIXTURES = os.path.join(ROOT, "tests", "fixtures", "c2000ware", "build", "*.out")
SKIP_MNEMONICS = {".word", "ITRAP0", "ITRAP1"}


def find(name, *candidates):
    # Newest wins: a stale debug build must not silently shadow a fresh release
    # one, or this gate reports "unchanged" while measuring the old table.
    present = [c for c in candidates if c and os.path.exists(c)]
    if present:
        return max(present, key=os.path.getmtime)
    found = shutil.which(name)
    if found:
        return found
    sys.exit(
        f"{name} not found — build it with: cargo build --manifest-path core/Cargo.toml"
    )


def ti_instructions(dis2000, path):
    """(addr, [words], mnemonic) for each instruction dis2000 recognises.

    A line with an address, a word and a mnemonic starts an instruction; a line
    with an address and a word but no mnemonic is a continuation word; a line
    beginning || is a parallel op of the current instruction.

    `--data_as_text` disassembles DATA sections too, which is useful -- it
    exercises the decoder over arbitrary bit patterns -- but those words are
    not code, so each row records which kind of section it came from. The 153
    `XMAC`s that were the last undecoded mnemonic all live in `.const`.
    """
    out = subprocess.run(
        [dis2000, "--data_as_text", path], capture_output=True, text=True
    ).stdout
    rows, pending, kind = [], None, "?"
    for line in out.splitlines():
        if line.lstrip().startswith("||"):
            continue
        tok = line.split()
        if len(tok) >= 3 and tok[1] == "Section":
            kind = tok[0]
            continue
        if len(tok) < 2 or len(tok[0]) != 8 or len(tok[1]) != 4:
            continue
        try:
            addr = int(tok[0], 16)
        except ValueError:
            continue
        if len(tok) >= 3:
            if pending:
                rows.append(pending)
            pending = (
                addr,
                [tok[1]],
                tok[2],
                kind,
                re.sub(r"\s+", " ", line.split(None, 2)[2]).strip(),
            )
        elif pending:
            pending[1].append(tok[1])
    if pending:
        rows.append(pending)
    return [r for r in rows if r[2] not in SKIP_MNEMONICS]


def _defects(r):
    """Words we cannot decode at all, plus words we decode under the wrong name."""
    return (r["instructions"] - r["decoded"]) + (r["decoded"] - r["mnemonic_ok"])


def compare(result, path):
    """Verdict against a recorded baseline: FIXED/REGRESSIONS per mnemonic.

    Folded in from gate_compare.py, which read a hardcoded /tmp path and a JSON
    shape only the BN-linked differential produced -- so it could never run.

    One deliberate change of meaning: gate_compare was an acceptance test for a
    candidate ISA change and exited non-zero on NO_CHANGE, demanding every commit
    improve something. This is a ratchet, so NO_CHANGE passes and only a real
    regression fails.
    """
    with open(path) as fh:
        base = json.load(fh)
    missing = [
        k
        for k in ("instructions", "decoded", "mnemonic_ok", "undecoded")
        if k not in base
    ]
    if missing:
        sys.exit(
            f"{path}: baseline is missing {missing}; it predates the current "
            "shape -- regenerate it with --write-baseline"
        )

    db, da = _defects(base), _defects(result)
    print(f"\nstructural defects: {db} -> {da}  (delta {da - db:+d})")
    print(f"decoded:            {base['decoded']} -> {result['decoded']}")
    ub, uo = base["undecoded"], result["undecoded"]
    fixes, regs = [], []
    for mn in sorted(set(ub) | set(uo)):
        b, a = ub.get(mn, 0), uo.get(mn, 0)
        (regs if a > b else fixes if a < b else []).append(f"{mn}:{b}->{a}")
    print("FIXED:      ", ", ".join(fixes) if fixes else "none")
    print("REGRESSIONS:", ", ".join(regs) if regs else "NONE")
    verdict = (
        "REGRESSION"
        if regs or da > db
        else "CLEAN_IMPROVEMENT"
        if da < db
        else "NO_CHANGE"
    )
    print("VERDICT:", verdict)
    return 1 if verdict == "REGRESSION" else 0


def main():
    ti_bin = shutil.which("dis2000")
    if not ti_bin:
        sys.exit("dis2000 not on PATH — run inside `nix develop`")
    c28xdec = find(
        "c28xdec",
        os.path.join(ROOT, "core/target/debug/c28xdec"),
        os.path.join(ROOT, "core/target/release/c28xdec"),
    )

    fixtures = sorted(glob.glob(FIXTURES))
    if not fixtures:
        sys.exit("no fixtures — run: bash tests/fixtures/c2000ware/build.sh")

    total = decoded = mnemonic_ok = text_ok = text_deliberate = 0
    text_diff = collections.Counter()
    text_total = text_decoded = 0
    undecoded = collections.Counter()
    mismatched = collections.Counter()

    for path in fixtures:
        rows = ti_instructions(ti_bin, path)
        stdin = "\n".join(" ".join(r[1]) for r in rows)
        out = subprocess.run(
            [c28xdec, "decode"], input=stdin, capture_output=True, text=True
        ).stdout
        lines = [line for line in out.splitlines() if line.startswith("{")]
        # zip() would silently compare only the shorter prefix, which is how a
        # stale binary once made this report 27,195 of 43,238 instructions.
        if len(lines) != len(rows):
            sys.exit(
                f"{path}: c28xdec returned {len(lines)} lines for "
                f"{len(rows)} instructions"
            )
        for (_, _, ti_mnem, kind, ti_text), line in zip(rows, lines):
            total += 1
            if kind == "TEXT":
                text_total += 1
            d = json.loads(line)
            if d.get("yaml_name") is None:
                undecoded[ti_mnem] += 1
                continue
            decoded += 1
            if kind == "TEXT":
                text_decoded += 1
            # A leading `||` marks the second half of a parallel pair, which
            # is a property of the pairing, not of the instruction's name.
            if d["name"].upper() == ti_mnem.lstrip("|").upper():
                mnemonic_ok += 1
            else:
                mismatched[f"{ti_mnem}->{d['name']}"] += 1
            ours = d.get("text", "")
            want = ti_text.lstrip("|").strip()
            if ours == want:
                text_ok += 1
            elif (
                d["branch_type"] != "None"
                and d["operands"]
                and d["operands"][0]["type"] == "Immediate"
            ):
                # Deliberate: TI prints a branch's raw offset, we print the
                # resolved target so the reader can click it.
                text_deliberate += 1
            elif len(text_diff) < 12000:
                text_diff[f"{want}  ||  {ours}"] += 1

    result = {
        "fixtures": len(fixtures),
        "instructions": total,
        "text_instructions": text_total,
        "text_decoded": text_decoded,
        "decoded": decoded,
        "mnemonic_ok": mnemonic_ok,
        "undecoded": dict(undecoded.most_common()),
    }

    def pct(n):
        return 100.0 * n / max(total, 1)

    print(
        f"fixtures {len(fixtures)}   words disassembled {total} "
        f"(TEXT {text_total}, DATA {total - text_total})"
    )
    print(f"  decoded              {decoded:6d}  {pct(decoded):6.2f}%")
    print(f"  base mnemonic agrees {mnemonic_ok:6d}  {pct(mnemonic_ok):6.2f}%")
    agree = text_ok + text_deliberate
    print(
        f"  full text agrees     {text_ok:6d}  {pct(text_ok):6.2f}%"
        f"   (+{text_deliberate} deliberate = {pct(agree):.2f}%)"
    )
    print(
        f"  decoded in TEXT      {text_decoded:6d}  "
        f"{100.0 * text_decoded / max(text_total, 1):6.2f}%"
    )
    if text_diff:
        print("  text differs (TI || ours):")
        for k, v in text_diff.most_common(6):
            print(f"    x{v:<5d} {k}")
    if undecoded:
        print(
            "  undecoded:", ", ".join(f"{k} x{v}" for k, v in undecoded.most_common(8))
        )
    if mismatched:
        print(
            "  mnemonic differs:",
            ", ".join(f"{k} x{v}" for k, v in mismatched.most_common(6)),
        )

    if "--write-baseline" in sys.argv:
        path = sys.argv[sys.argv.index("--write-baseline") + 1]
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            json.dump(result, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"\nwrote {path}")
    if "--baseline" in sys.argv:
        return compare(result, sys.argv[sys.argv.index("--baseline") + 1])
    return 0


if __name__ == "__main__":
    sys.exit(main())
