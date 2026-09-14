"""Diff the lifter's flag writes against TI's Flags and Modes tables.

The lifter asserts `FlagWrite::All` by convention in most arms and nothing at
all in the rest, and nothing has ever checked either against the manual. Both
directions are defects:

  writes LESS   BN cannot recover a conditional whose flag the instruction
                really sets, so the branch reads as opaque
  writes MORE   BN believes C or V is clobbered when it is not, and kills the
                dataflow of whatever set it -- the failure mode section 5 of
                plan-lift-semantics.md calls "the lifter destroying dataflow"

Reads `tests/baselines/lift.json` rather than Binary Ninja, so it is a
licence-free gate; `lift_ratchet.py` is what keeps that baseline honest.

CAVEAT: TI's "Flags and Modes" table lists every flag an instruction *affects or
is affected by*, not only the ones it writes, so a disagreement is a lead to
read the page about rather than a proven bug. Two that were read and confirmed:

  CMP/CMPB/CMPL claim V, and SPRU430F says in prose "The instructions CMP, CMPB
  and CMPL do not affect the state of the V flag" -- the lifter is wrong.
  MOV AX,loc16 sets N and Z on every load and the lifter declares neither; but
  MOV loc16,AX sets them only when loc16 is @AX, so declaring nothing there is
  a defensible reading of an addressing-mode-dependent write.

Ratcheted against tests/baselines/flags.json so the known disagreements are
recorded and a NEW one fails, rather than 93 lines of output nobody reads.

Run:
    nix develop -c python3 scripts/flag_diff.py                   compare
    nix develop -c python3 scripts/flag_diff.py --write-baseline  re-record
"""

from __future__ import annotations

import glob
import json
import os
import re
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIFT = os.path.join(ROOT, "tests", "baselines", "lift.json")
BASELINE = os.path.join(ROOT, "tests", "baselines", "flags.json")
REF_GLOB = os.path.join(ROOT, "isa", "reference", "*.yaml")
ISA_GLOB = os.path.join(ROOT, "isa", "instructions", "*.yaml")

# arch.rs FlagWrite::flags_written, which is what BN is actually told. Keep in
# step with it: an annotation missing here used to read as "writes no flags",
# which turned every row using a new write type into a false "writes LESS".
WRITES = {
    "*": {"N", "Z", "C", "V"},
    "nzcv": {"N", "Z", "C", "V"},
    "nz": {"N", "Z"},
    "nzc": {"N", "Z", "C"},
    "nzv": {"N", "Z", "V"},
    "tc": {"TC"},
}
# The union of WRITES: the only flags any FlagWrite can assign. Everything else
# TI lists -- OVC, SXM, PM, the STF bits, and OVM, which arch.rs registers as a
# flag but no write type ever sets -- BN has no way to write, so a difference
# there says nothing about the lifter.
MODELLED = set().union(*WRITES.values())

ANNOTATION = re.compile(r"\{([^}]*)\}")
# An explicit `flag:TC = ...` assignment, which SETC/CLRC, ABSTC and NEGTC emit
# through set_flag. It carries no `{...}` annotation, so counting annotations
# alone reported those rows as writing nothing.
ASSIGNED = re.compile(r"\bflag:([A-Za-z0-9]+)\s*=")


def _lifter_flags(il_lines):
    out = set()
    for line in il_lines:
        out |= {m.upper() for m in ASSIGNED.findall(line)}
        for tag in ANNOTATION.findall(line):
            if tag not in WRITES:
                raise SystemExit(
                    f"unknown flag-write annotation {{{tag}}} in {line!r}: add it "
                    "to WRITES, or this row silently reads as writing nothing"
                )
            out |= WRITES[tag]
    return out


def _ti_flags():
    """opcode -> flags TI's page lists, for the entries that list any."""
    out = {}
    for path in sorted(glob.glob(REF_GLOB)):
        for entry in yaml.safe_load(open(path))["instructions"]:
            flags = set(entry.get("flags") or [])
            if flags and entry["opcode"] not in out:
                out[entry["opcode"]] = flags
    return out


def compare():
    """name -> {more, less}, for every lifted row TI also describes."""
    lift = json.load(open(LIFT))
    ti = _ti_flags()

    rows = []
    for path in sorted(glob.glob(ISA_GLOB)):
        rows += yaml.safe_load(open(path))["instructions"]

    compared, out = 0, {}
    for row in rows:
        spec = ti.get(row["opcode"])
        entry = lift.get(row["name"])
        if spec is None or entry is None or entry["class"] != "lifted":
            continue
        compared += 1
        ours = _lifter_flags(entry["il"])
        theirs = spec & MODELLED
        if ours != theirs:
            out[row["name"]] = {
                "more": sorted(ours - theirs),
                "less": sorted(theirs - ours),
            }
    return compared, out


def main() -> int:
    compared, current = compare()
    more = sum(1 for d in current.values() if d["more"])
    less = sum(1 for d in current.values() if d["less"])
    print(f"rows compared          {compared}")
    print(f"  agree                {compared - len(current)}")
    print(f"  lifter writes MORE   {more}")
    print(f"  lifter writes LESS   {less}")

    if "--write-baseline" in sys.argv:
        with open(BASELINE, "w") as fh:
            json.dump(current, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"\nwrote {BASELINE}")
        return 0

    if not os.path.exists(BASELINE):
        print(f"\nERROR: {BASELINE} missing; create it with --write-baseline")
        return 1
    base = json.load(open(BASELINE))

    new = {n: d for n, d in current.items() if base.get(n) != d}
    fixed = sorted(set(base) - set(current))

    if fixed:
        print(f"\nRESOLVED ({len(fixed)}): {fixed[:12]}")
        print("  Re-record with --write-baseline.")
    if new:
        print(f"\nNEW DISAGREEMENT ({len(new)}):")
        for name, d in sorted(new.items()):
            was = base.get(name)
            extra = f"+{','.join(d['more'])}" if d["more"] else ""
            missing = f"-{','.join(d['less'])}" if d["less"] else ""
            print(f"  {name:34} {extra:10} {missing:12} was {was}")
        print(
            "\nA lifter arm's flag write no longer matches TI's page. Read the "
            "page before re-recording with --write-baseline."
        )
        return 1

    print("\nVERDICT: no new disagreement")
    return 0


if __name__ == "__main__":
    sys.exit(main())
