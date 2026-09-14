"""Per-row lifter coverage, ratcheted: a row may improve, never regress.

`llil_unimpl` counts what the *corpus* exercises, and it is 0 — but the corpus
touches a fraction of the table, so a row can lift to nothing and no fixture
will say so. This lifts every row in `isa/instructions/` through the real
architecture plugin and classifies the result:

    lifted         real IL
    nop_only       only LLIL_NOP — correct for EALLOW, ASP, CLRC_*, and the
                   other flag/mode instructions BN has no way to model
    unimplemented  LLIL_UNIMPL, which is B3's honest "no IL for this yet"
    no_il          nothing emitted at all
    unreachable    no encoding selects this row (A3's gate should make this 0)

Needs Binary Ninja, because LLIL comes from the plugin — so this is a local
gate, not a CI one. `tests/test_isa_reachable.py` covers the licence-free half
of the same ground.

Run:
    nix develop -c python3 scripts/lift_ratchet.py                   compare
    nix develop -c python3 scripts/lift_ratchet.py --write-baseline  re-record
"""

from __future__ import annotations

import glob
import json
import os
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

BASELINE = os.path.join(ROOT, "tests", "baselines", "lift.json")
ISA_GLOB = os.path.join(ROOT, "isa", "instructions", "*.yaml")

# Worse than `lifted`, in the order a regression would take.
CLASSES = ["lifted", "nop_only", "unimplemented", "no_il", "unreachable"]


def _rows():
    for path in sorted(glob.glob(ISA_GLOB)):
        yield from yaml.safe_load(open(path))["instructions"]


def _probe_words(row):
    """The row's own encoding, plus each operand field at 1 and at its maximum.

    A row can be shadowed at its all-zero encoding and still reachable once an
    operand distinguishes it, so one probe is not enough. Same reasoning as
    tests/test_isa_reachable.py.
    """
    yield row["opcode"]
    for op in row.get("operands") or []:
        hi, lo = op["bits"]
        yield row["opcode"] | (1 << lo)
        yield row["opcode"] | (((1 << (hi - lo + 1)) - 1) << lo)


def _encode(word: int, fmt: int) -> bytes:
    if fmt == 16:
        return bytes([word & 0xFF, (word >> 8) & 0xFF, 0, 0])
    return bytes(
        [
            (word >> 16) & 0xFF,
            (word >> 24) & 0xFF,
            word & 0xFF,
            (word >> 8) & 0xFF,
        ]
    )


def classify() -> dict[str, list[str]]:
    from _bn_helpers import init_bn

    from c28x_rs import Decoder

    bn = init_bn()
    arch = bn.Architecture["tms320c28x"]
    dec = Decoder(objmode=1)

    out: dict[str, list[str]] = {c: [] for c in CLASSES}
    for row in _rows():
        data = None
        for word in _probe_words(row):
            candidate = _encode(word, row["format"])
            insn = dec.decode(candidate, 0)
            if insn is not None and insn.yaml_name == row["name"]:
                data = candidate
                break
        if data is None:
            out["unreachable"].append(row["name"])
            continue

        il = bn.lowlevelil.LowLevelILFunction(arch)
        arch.get_instruction_low_level_il(data, 0, il)
        kinds = {type(il[i]).__name__ for i in range(len(il))}
        if not kinds:
            out["no_il"].append(row["name"])
        elif any("Unimpl" in k for k in kinds):
            out["unimplemented"].append(row["name"])
        elif kinds == {"LowLevelILNop"}:
            out["nop_only"].append(row["name"])
        else:
            out["lifted"].append(row["name"])
    return {c: sorted(v) for c, v in out.items()}


def main() -> int:
    current = classify()
    total = sum(len(v) for v in current.values())
    for c in CLASSES:
        n = len(current[c])
        print(f"  {c:14} {n:4}  {100 * n / max(total, 1):5.1f}%")
    print(f"  {'TOTAL':14} {total:4}")

    if "--write-baseline" in sys.argv:
        with open(BASELINE, "w") as fh:
            json.dump(current, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"\nwrote {BASELINE}")
        return 0

    if not os.path.exists(BASELINE):
        print(f"\nERROR: {BASELINE} missing; create it with --write-baseline")
        return 1
    with open(BASELINE) as fh:
        base = json.load(fh)

    rank = {name: i for i, c in enumerate(CLASSES) for name in base.get(c, [])}
    now = {name: i for i, c in enumerate(CLASSES) for name in current[c]}

    regressed = [
        (n, CLASSES[rank[n]], CLASSES[i])
        for n, i in now.items()
        if n in rank and i > rank[n]
    ]
    improved = [
        (n, CLASSES[rank[n]], CLASSES[i])
        for n, i in now.items()
        if n in rank and i < rank[n]
    ]
    added = sorted(set(now) - set(rank))

    if improved:
        print(f"\nIMPROVED ({len(improved)}):")
        for n, was, is_ in improved[:12]:
            print(f"  {n}: {was} -> {is_}")
    if added:
        print(f"\nNEW ROWS ({len(added)}): {added[:12]}")
    if regressed:
        print(f"\nREGRESSED ({len(regressed)}):")
        for n, was, is_ in regressed:
            print(f"  {n}: {was} -> {is_}")
        print(
            "\nA row that used to produce IL no longer does. If deliberate, "
            "rerun with --write-baseline and say why in the commit."
        )
        return 1

    print("\nVERDICT: no regression")
    return 0


if __name__ == "__main__":
    sys.exit(main())
