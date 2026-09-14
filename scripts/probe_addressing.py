"""Regenerate isa/reference/addressing_text.tsv from dis2000.

How TI renders every value of the 8-bit loc16 and loc32 addressing fields, by
disassembling one instruction of each shape for all 256 values. The decoder has
to agree with this exactly, which tests/test_addressing_text.py checks without
needing the TI toolchain.

Run: nix develop -c python3 scripts/probe_addressing.py
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "isa", "reference", "addressing_text.tsv")

# (opcode base, mnemonic dis2000 prints, text that precedes the operand)
SHAPES = {"loc16": (0x8100, "ADD", "ACC,"), "loc32": (0x0600, "MOVL", "ACC,")}


def probe(work, base, mnemonic, prefix):
    asm = os.path.join(work, "probe.asm")
    with open(asm, "w") as fh:
        fh.write("        .text\n")
        for field in range(256):
            fh.write(f"        .word 0x{base | field:04x},0x7700,0x7700\n")
    subprocess.run(["asm2000", "-v28", asm], cwd=work, capture_output=True, text=True)
    out = subprocess.run(
        ["dis2000", "--data_as_text", os.path.join(work, "probe.obj")],
        capture_output=True,
        text=True,
    ).stdout

    want = re.compile(
        rf"^[0-9a-f]{{8}}\s+([0-9a-f]{{4}})\s+{mnemonic}\s+{re.escape(prefix)} ?(.*)$"
    )
    seen = {}
    for line in out.splitlines():
        m = want.match(line)
        if m:
            seen[int(m.group(1), 16) & 0xFF] = m.group(2).strip()
    if len(seen) != 256:
        sys.exit(f"{mnemonic}: read back {len(seen)} of 256 fields")
    return [seen[i] for i in range(256)]


def main():
    if not all(
        subprocess.run(["which", t], capture_output=True).returncode == 0
        for t in ("asm2000", "dis2000")
    ):
        sys.exit("asm2000/dis2000 not on PATH — run inside `nix develop`")

    with tempfile.TemporaryDirectory() as work:
        cols = {k: probe(work, *v) for k, v in SHAPES.items()}

    with open(OUT, "w") as fh:
        fh.write(
            __doc__.splitlines()[0].replace("Regenerate ", "# How TI renders ") + "\n"
        )
        fh.write("# field\tloc16\tloc32\n")
        for i in range(256):
            fh.write(f"0x{i:02X}\t{cols['loc16'][i]}\t{cols['loc32'][i]}\n")
    print(f"{OUT}: 256 rows")


if __name__ == "__main__":
    main()
