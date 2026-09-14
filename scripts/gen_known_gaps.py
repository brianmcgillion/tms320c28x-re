"""Regenerate isa/known_gaps.yaml — the unmodeled-encoding-bit ratchet.

An "unmodeled bit" is a bit that is neither fixed by an instruction's `mask` nor
covered by one of its operand fields. The decoder silently discards it, so the
instruction decodes but loses information -- which is why 808 of them went
unnoticed until the TI manuals were transcribed.

The file is a ratchet: tests/test_isa_gaps.py fails if the total grows. Run this
only after reducing the count, never to paper over an increase.

Run: nix develop -c python3 scripts/gen_known_gaps.py
"""

from __future__ import annotations

import glob
import os
import sys

import yaml

ROOT = os.path.join(os.path.dirname(__file__), "..")
OUT = os.path.join(ROOT, "isa", "known_gaps.yaml")

HEADER = """# Encoding bits that are neither fixed by `mask` nor bound to an operand.
#
# Each one is information the decoder silently discards. This file is a RATCHET:
# tests/test_isa_gaps.py fails if the total grows or a new name appears, so the
# number can only come down. Entries are removed as the fields are recovered
# from isa/reference/, never added without a reason.
#
# The two rows left are deferred on purpose, not unexplained:
#
#   NOP  bits[7:0] are the `{*ind}{ARPn}` field -- dis2000 reads 0x7712 as
#        `NOP @0x12`. Binding it would print `NOP @0x0` on all 75 corpus NOPs
#        (every one has the field zero) and recover nothing until the display
#        layer can suppress it. Phase B6.
#   SBF  bits[9:8] are the condition: 00 EQ, 01 NEQ, 10 TC, 11 NTC (asm2000).
#        This is not the 4-bit cond4 encoding, so it needs its own operand
#        type rather than a bit range. Phase B5.
#
# Regenerate deliberately (only after reducing the count):
#   nix develop -c python3 scripts/gen_known_gaps.py
"""


def unmodeled(insn):
    """Bits neither fixed by the mask nor claimed by an operand."""
    width = 16 if insn.get("format", 16) == 16 else 32
    full = (1 << width) - 1
    covered = insn["mask"] & full
    for op in insn.get("operands") or []:
        bits = op.get("bits")
        if bits:
            hi, lo = bits
            covered |= ((1 << (hi - lo + 1)) - 1) << lo
    return full & ~covered


def collect():
    gaps = []
    for path in sorted(glob.glob(os.path.join(ROOT, "isa", "instructions", "*.yaml"))):
        doc = yaml.safe_load(open(path)) or {}
        for insn in doc.get("instructions") or []:
            free = unmodeled(insn)
            if free:
                gaps.append(
                    {
                        "name": insn["name"],
                        "file": os.path.basename(path),
                        "bits": bin(free).count("1"),
                        "free_mask": free,
                    }
                )
    gaps.sort(key=lambda g: (-g["bits"], g["name"]))
    return gaps


def main():
    gaps = collect()
    total = sum(g["bits"] for g in gaps)
    with open(OUT, "w") as fh:
        fh.write(HEADER)
        fh.write(f"\ntotal_bits: {total}\ntotal_rows: {len(gaps)}\n\nunmodeled_bits:\n")
        for g in gaps:
            fh.write(
                f"  - {{ name: {g['name']}, file: {g['file']}, "
                f"bits: {g['bits']}, free_mask: 0x{g['free_mask']:08X} }}\n"
            )
    print(f"{OUT}: {len(gaps)} rows, {total} bits")
    return 0


if __name__ == "__main__":
    sys.exit(main())
