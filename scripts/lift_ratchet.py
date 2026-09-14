"""Per-row lifter coverage and IL text, ratcheted: a row may improve, never regress.

`llil_unimpl` counts what the *corpus* exercises, and it is 0 — but the corpus
touches a fraction of the table, so a row can lift to nothing and no fixture
will say so. This lifts every row in `isa/instructions/` through the real
architecture plugin and records two things per row:

    class   lifted         real IL
            nop_only       only LLIL_NOP — correct for EALLOW, ASP, CLRC_*, and
                           the other flag/mode instructions BN has no way to
                           model
            unimplemented  LLIL_UNIMPL, which is B3's honest "no IL for this yet"
            no_il          nothing emitted at all
            unreachable    no encoding selects this row (A3's gate makes this 0)

    il      the lifted IL as text, one entry per LLIL instruction

The class alone cannot see a wrong lift, only an absent one: reversing a store's
direction or naming the wrong register keeps the row `lifted`. The IL text is
what makes semantics changes visible, so migrating a family to a declarative
`lift:` block is a mechanical diff rather than 161 careful re-readings.

Operands are probed at *distinct non-zero values* for the same reason
`isa/reference/operand_text.tsv` is: with every field zero, operand 0 and
operand 1 render identically and a shift of 0 is indistinguishable from no
shift at all, so the snapshot could not see a lifter read the wrong one.

Probing happens at `PROBE_ADDR`, not 0, because the decoder drops any branch
target landing strictly inside the instruction's own bytes -- at address 0 the
absolute-target rows (LB, LC, LCR, FFC, XB/XCALL pma) aim at byte 2 of their own
4 bytes, lose their target, and record `nop` instead of the jump they lift to.

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

# Clear of the low bytes an absolute branch target can occupy; the decoder's own
# branch tests use this address for the same reason.
PROBE_ADDR = 0x10000


def _rows():
    for path in sorted(glob.glob(ISA_GLOB)):
        yield from yaml.safe_load(open(path))["instructions"]


def _probe_words(row):
    """Candidate encodings for this row, best first.

    The first is every operand at a *distinct* small non-zero value, so the
    recorded IL distinguishes operand 0 from operand 1 and shows a shift as a
    shift. The rest are the row's bare encoding and each field alone at 1 and
    at its maximum: a row can be shadowed at one encoding and still reachable
    once an operand distinguishes it, so one probe is not enough. Same
    reasoning as tests/test_isa_reachable.py.
    """
    operands = row.get("operands") or []

    distinct = row["opcode"]
    for i, op in enumerate(operands):
        hi, lo = op["bits"]
        field = (1 << (hi - lo + 1)) - 1
        distinct |= min(i + 1, field) << lo
    yield distinct

    yield row["opcode"]
    for op in operands:
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


def snapshot() -> dict[str, dict]:
    from _bn_helpers import init_bn

    from c28x_rs import Decoder

    bn = init_bn()
    arch = bn.Architecture["tms320c28x"]
    dec = Decoder(objmode=1)

    out: dict[str, dict] = {}
    for row in _rows():
        data = None
        for word in _probe_words(row):
            candidate = _encode(word, row["format"])
            insn = dec.decode(candidate, PROBE_ADDR)
            if insn is not None and insn.yaml_name == row["name"]:
                data = candidate
                break
        if data is None:
            out[row["name"]] = {"class": "unreachable", "probe": None, "il": []}
            continue

        il = bn.lowlevelil.LowLevelILFunction(arch)
        arch.get_instruction_low_level_il(data, PROBE_ADDR, il)
        text = [str(il[i]) for i in range(len(il))]
        kinds = {type(il[i]).__name__ for i in range(len(il))}
        if not kinds:
            cls = "no_il"
        elif any("Unimpl" in k for k in kinds):
            cls = "unimplemented"
        elif kinds == {"LowLevelILNop"}:
            cls = "nop_only"
        else:
            cls = "lifted"
        out[row["name"]] = {"class": cls, "probe": data.hex(), "il": text}
    return out


def _print_counts(current: dict[str, dict]) -> None:
    total = len(current)
    for c in CLASSES:
        n = sum(1 for r in current.values() if r["class"] == c)
        print(f"  {c:14} {n:4}  {100 * n / max(total, 1):5.1f}%")
    print(f"  {'TOTAL':14} {total:4}")


def main() -> int:
    current = snapshot()
    _print_counts(current)

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

    rank = {c: i for i, c in enumerate(CLASSES)}
    shared = sorted(set(base) & set(current))

    regressed, improved, il_changed = [], [], []
    for name in shared:
        was, now = base[name], current[name]
        if rank[now["class"]] > rank[was["class"]]:
            regressed.append((name, was["class"], now["class"]))
        elif rank[now["class"]] < rank[was["class"]]:
            improved.append((name, was["class"], now["class"]))
        elif was.get("il") != now["il"] or was.get("probe") != now["probe"]:
            il_changed.append((name, was, now))

    added = sorted(set(current) - set(base))
    removed = sorted(set(base) - set(current))

    if improved:
        print(f"\nIMPROVED ({len(improved)}):")
        for n, was, is_ in improved[:12]:
            print(f"  {n}: {was} -> {is_}")
    if added:
        print(f"\nNEW ROWS ({len(added)}): {added[:12]}")
    if removed:
        print(f"\nREMOVED ROWS ({len(removed)}): {removed[:12]}")

    if regressed:
        print(f"\nREGRESSED ({len(regressed)}):")
        for n, was, is_ in regressed:
            print(f"  {n}: {was} -> {is_}")
    if il_changed:
        print(f"\nIL CHANGED ({len(il_changed)}):")
        for n, was, now in il_changed:
            print(f"  {n}  [{now['class']}]")
            if was.get("probe") != now["probe"]:
                print(f"      probe {was.get('probe')} -> {now['probe']}")
            for line in was.get("il", []):
                print(f"      - {line}")
            for line in now["il"]:
                print(f"      + {line}")

    if regressed or il_changed:
        print(
            "\nA row's lifted IL is not what it was. Read the diff: an unchanged "
            "migration should produce identical IL. If the change is deliberate, "
            "rerun with --write-baseline and say why in the commit."
        )
        return 1

    print("\nVERDICT: no regression")
    return 0


if __name__ == "__main__":
    sys.exit(main())
