"""What TI calls each row, probed through dis2000 at a *reachable* encoding.

Run: nix develop -c python3 scripts/probe_mnemonics.py [out_dir]

Probing the bare opcode with every operand bit zero is not enough: that word
may belong to a more specific row, which is how the earlier survey concluded
MOV32_RAH_CPUREG was "VMOV32". This reuses the reachability prober, so each
row is probed at a word that actually decodes to it.
"""

import glob
import os
import re
import subprocess
import sys
import tempfile
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from c28x_rs import Decoder  # noqa: E402 (needs the sys.path line above)

rows = [
    i
    for f in sorted(glob.glob(f"{ROOT}/isa/instructions/*.yaml"))
    for i in yaml.safe_load(open(f))["instructions"]
]
dec = Decoder(objmode=1)


def probes(row):
    yield row["opcode"]
    for op in row.get("operands") or []:
        hi, lo = op["bits"]
        yield row["opcode"] | (1 << lo)
        yield row["opcode"] | (((1 << (hi - lo + 1)) - 1) << lo)


def encode(word, fmt):
    if fmt == 16:
        return bytes([word & 0xFF, (word >> 8) & 0xFF]) + b"\0\0"
    return (
        bytes(
            [(word >> 16) & 0xFF, (word >> 24) & 0xFF, word & 0xFF, (word >> 8) & 0xFF]
        )
        + b"\0\0"
    )


# pick a reachable probe word per row
chosen = {}
for r in rows:
    for w in probes(r):
        insn = dec.decode(encode(w, r["format"]), addr=0)
        if insn is not None and insn.yaml_name == r["name"]:
            chosen[r["name"]] = (w, r["format"])
            break

SEP = 4  # NOPs between probes, so a rejected word cannot swallow the next
lines, addr, at = ["        .text"], 0, {}
for name, (w, fmt) in chosen.items():
    words = [w & 0xFFFF] if fmt == 16 else [(w >> 16) & 0xFFFF, w & 0xFFFF]
    lines.append(
        "        .word " + ",".join(f"0x{x:04x}" for x in words + [0x7700] * SEP)
    )
    at[addr] = name
    addr += len(words) + SEP

out_dir = sys.argv[1] if len(sys.argv) > 1 else tempfile.mkdtemp()
asm = os.path.join(out_dir, "mnem.asm")
open(asm, "w").write("\n".join(lines) + "\n")
subprocess.run(
    ["asm2000", "-v28", "--float_support=fpu32", asm],
    cwd=out_dir,
    capture_output=True,
    text=True,
)
out = subprocess.run(
    ["dis2000", "--data_as_text", os.path.join(out_dir, "mnem.obj")],
    capture_output=True,
    text=True,
).stdout

ti, full = {}, {}
for line in out.splitlines():
    tok = line.split()
    if len(tok) >= 3 and re.fullmatch(r"[0-9a-f]{8}", tok[0]) and len(tok[1]) == 4:
        a = int(tok[0], 16)
        if a in at:
            ti[at[a]] = tok[2]
            full[at[a]] = line.split(None, 2)[2].rstrip() if len(tok) > 2 else ""

import json  # noqa: E402 (needs the sys.path line above)

json.dump(
    ti, open(os.path.join(out_dir, "ti_mnemonics.json"), "w"), indent=1, sort_keys=True
)
json.dump(
    full, open(os.path.join(out_dir, "ti_full.json"), "w"), indent=1, sort_keys=True
)
json.dump(
    {k: f"0x{v[0]:0{v[1] // 4}X}" for k, v in chosen.items()},
    open(os.path.join(out_dir, "probe_words.json"), "w"),
    indent=1,
    sort_keys=True,
)
same = diff = 0
for r in rows:
    n = r["name"]
    if n not in ti:
        print(f"  NO-READBACK  {n}")
        continue
    lead = n.split("_")[0]
    if lead.upper() == ti[n].lstrip("|").upper():
        same += 1
    else:
        diff += 1
        w, fmt = chosen[n]
        print(f"  DIFF  {n:34s} probe=0x{w:0{fmt // 4}X} leading={lead:12s} TI={ti[n]}")
print(f"rows {len(rows)}  leading token == TI {same}  differs {diff}")
