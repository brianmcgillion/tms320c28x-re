"""Transcribe the TI manuals into isa/reference/*.yaml — the third oracle.

asm2000 answers what a mnemonic encodes to; dis2000 answers what a word decodes
to. Neither can say which bits are an operand field and which are fixed opcode --
you would have to probe 2**n encodings and infer. That blind spot is why 808
encoding bits across 96 of 413 rows are neither fixed by a mask nor bound to an
operand, and it is why the manuals have to become machine-readable.

Both manuals print a regular opcode block:

    Opcode                          Opcode
    0101 0110 0000 1101             LSW: 1110 1000 10II IIII
    0000 BBBB LLLL LLLL             MSW: IIII IIII IIbb baaa

Digits are fixed bits, letters are operand fields. So opcode and mask are
computed, and each distinct letter yields a [high, low] bit range -- which is the
part no other oracle can supply.

Run: nix develop -c python3 scripts/spec_transcribe.py [--check]

  (default)  regenerate isa/reference/*.yaml
  --check    only report differences against isa/instructions/, exit 1 if any
"""

from __future__ import annotations

import collections
import os
import re
import sys

REF_DIR = os.path.join(os.path.dirname(__file__), "..", "isa", "reference")
DOC_DIR = os.path.join(os.path.dirname(__file__), "..", "docs", "reference")
ISA_DIR = os.path.join(os.path.dirname(__file__), "..", "isa", "instructions")

DOCS = [
    ("spru430f", "TMS320C28x CPU and Instruction Set (Rev. F)"),
    ("sprueo2b", "TMS320C28x Floating Point Unit and Instruction Set (Rev. B)"),
]

GROUP = "[01A-Za-z]{4}"
# TI prints an 8-bit addressing-mode operand as its name, not as bit slots:
#   MSW: eedd daaa mem32
NAMED = ("mem32", "mem16", "loc16")
BITS = re.compile(
    rf"^(?:(LSW|MSW):\s*)?({GROUP} {GROUP} (?:{GROUP} {GROUP}|{'|'.join(NAMED)}))\s*$"
)
FREE = "~"

FLAG_NAMES = {
    "N",
    "Z",
    "C",
    "V",
    "TC",
    "OVC",
    "SXM",
    "OVM",
    "PM",
    "INTM",
    "DBGM",
    "PAGE0",
    "VMAP",
    "SPA",
    "LOOP",
    "IDLESTAT",
    "EALLOW",
    "M0M1MAP",
    "ARP",
    "XF",
    "RND32",
    "RNDF32",
    "RNDF64",
    "TF",
    "ZI",
    "NI",
    "ZF",
    "NF",
    "LUF",
    "LVF",
}
BOILERPLATE = (
    "www.",
    "SPRU",
    "Copyright",
    "Submit",
    "Instruction Set",
    "Central Processing",
)


def _expand(pattern):
    """A named 8-bit operand tail becomes 8 free slots; _named recovers the name."""
    p = pattern.replace(" ", "")
    for name in NAMED:
        if p.endswith(name):
            return p[: -len(name)] + FREE * 8
    return p


def _named(raw):
    """`{name: bits}` for the named operand tails, in whole-instruction bit numbers."""
    out, n = {}, len(raw)
    for k, text in enumerate(raw):
        for name in NAMED:
            if text.endswith(name):
                out[name] = {
                    "bits": [(n - 1 - k) * 16 + 7, (n - 1 - k) * 16],
                    "contiguous": True,
                }
    return out


def _fields(patterns):
    """Letter -> [high_bit, low_bit]. Width is 16 per pattern line.

    KNOWN LIMITATION: a field whose printed name is a word, not a repeated
    letter, is split into one entry per letter. `0000 COND LLLL LLLL` yields
    C/O/N/D at [11,11]..[8,8] rather than one COND field at [11,8]. The bit
    SPAN is still right, and merging adjacent single-occurrence letters would
    silently mis-merge genuinely distinct 1-bit fields, so this is left faithful
    to the page for a human to interpret.
    """
    joined = "".join(patterns)
    width = len(joined)
    spans = collections.defaultdict(list)
    for idx, ch in enumerate(joined):
        if ch.isalpha():
            spans[ch].append(width - 1 - idx)  # MSB-first text, LSB-numbered bits
    out = {}
    for letter, bits in spans.items():
        hi, lo = max(bits), min(bits)
        # Non-contiguous fields exist (a value split across the word); record the
        # span and flag it rather than silently pretending it is contiguous.
        out[letter] = {"bits": [hi, lo], "contiguous": len(bits) == hi - lo + 1}
    return out


def _opcode_mask(patterns):
    op = mask = 0
    for ch in "".join(patterns):
        op <<= 1
        mask <<= 1
        if ch == "1":
            op |= 1
            mask |= 1
        elif ch == "0":
            mask |= 1
    return op, mask


def _labelled(lines, start, label, limit=14):
    """Value printed under a `label` heading, e.g. Objmode / RPT / CYC."""
    for k in range(start, min(start + limit, len(lines))):
        if lines[k].strip() == label:
            for j in range(k + 1, min(k + 4, len(lines))):
                v = lines[j].strip()
                if v:
                    return v
    return None


def _flags(lines, start):
    """Flag letters listed under the Flags and Modes table."""
    for k in range(start, min(start + 120, len(lines))):
        if lines[k].strip() == "Flags and Modes":
            found = []
            for j in range(k + 1, min(k + 90, len(lines))):
                t = lines[j].strip()
                if t in FLAG_NAMES and t not in found:
                    found.append(t)
                elif t.startswith(("Example", "Repeat")) and found:
                    break
            return found
    return []


def _syntax(lines, opcode_idx):
    """The instruction heading above an Opcode block.

    The two manuals lay the page out differently: SPRU430F prints the syntax
    under a "Syntax Options" heading, SPRUEO2B prints it immediately above
    "Operands". Take whichever anchor is nearer, walking back from the opcode.
    """
    for k in range(opcode_idx - 1, max(0, opcode_idx - 60), -1):
        t = lines[k].strip()
        if t == "Syntax Options":
            for j in range(k + 1, min(k + 5, len(lines))):
                if lines[j].strip():
                    return lines[j].strip()
        if t == "Operands":
            for j in range(k - 1, max(0, k - 5), -1):
                v = lines[j].strip()
                if v and not v.startswith(BOILERPLATE):
                    return v
    return ""


def parse(doc):
    path = os.path.join(DOC_DIR, f"{doc}.txt")
    if not os.path.exists(path):
        sys.exit(f"{path} missing — run: bash docs/reference/fetch.sh")
    lines = open(path, errors="replace").read().splitlines()

    entries = []
    for i, line in enumerate(lines):
        if line.strip() != "Opcode":
            continue
        patterns, raw, j = [], [], i + 1
        while j < len(lines) and len(patterns) < 2:
            t = lines[j].strip()
            if not t:
                j += 1
                continue
            m = BITS.match(t)
            if not m:
                break
            raw.append(m.group(2).replace(" ", ""))
            patterns.append(_expand(m.group(2)))
            j += 1
        if not patterns:
            continue

        syntax = _syntax(lines, i)

        op, mask = _opcode_mask(patterns)
        entries.append(
            {
                "syntax": syntax,
                "format": 16 * len(patterns),
                "opcode": op,
                "mask": mask,
                "fields": {**_fields(patterns), **_named(raw)},
                "objmode": _labelled(lines, j, "Objmode"),
                "rpt": _labelled(lines, j, "RPT"),
                "cyc": _labelled(lines, j, "CYC"),
                "flags": _flags(lines, j),
                "bit_pattern": raw,
            }
        )

    # A page reprints its opcode block once per syntax variant; keep the first.
    seen, unique = set(), []
    for e in entries:
        key = (e["opcode"], e["mask"], tuple(e["bit_pattern"]))
        if key in seen:
            continue
        seen.add(key)
        unique.append(e)
    return unique


def _hex(n, width):
    return f"0x{n:0{width}X}"


def emit(doc, title, entries):
    os.makedirs(REF_DIR, exist_ok=True)
    path = os.path.join(REF_DIR, f"{doc}.yaml")
    with open(path, "w") as fh:
        fh.write(f"# {title}\n")
        fh.write("#\n# Transcribed from the TI manual by scripts/spec_transcribe.py.\n")
        fh.write(
            "# Digits in the printed opcode are fixed bits; letters are operand fields,\n"
        )
        fh.write("# which is the part asm2000 and dis2000 cannot tell us.\n")
        fh.write(
            "# NOTE: a field printed as a word (COND) appears as one entry per letter;\n"
        )
        fh.write("# the bit span is still correct. See _fields() in the script.\n")
        fh.write(
            "# Regenerate with: nix develop -c python3 scripts/spec_transcribe.py\n\n"
        )
        fh.write("instructions:\n")
        for e in entries:
            w = 8 if e["format"] == 32 else 4
            fh.write(f"  - syntax: {e['syntax']!r}\n")
            fh.write(f"    format: {e['format']}\n")
            fh.write(f"    opcode: {_hex(e['opcode'], w)}\n")
            fh.write(f"    mask: {_hex(e['mask'], w)}\n")
            fh.write(f"    bit_pattern: {e['bit_pattern']}\n")
            if e["fields"]:
                fh.write("    fields:\n")
                for letter, f in sorted(e["fields"].items()):
                    flag = "" if f["contiguous"] else ", contiguous: false"
                    fh.write(f"      {letter}: {{ bits: {f['bits']}{flag} }}\n")
            for k in ("objmode", "rpt", "cyc"):
                if e[k]:
                    fh.write(f"    {k}: {e[k]!r}\n")
            if e["flags"]:
                fh.write(f"    flags: {e['flags']}\n")
    return path


# The manual prints `xxxxxxxx` for the high byte of these second words, but
# asm2000 always emits zero there and dis2000 rejects anything else (`5640 ff04`
# does not disassemble, `5640 0004` is `ADDCL ACC, @0x4`). Following the tools
# over the page is deliberate: it can only refuse encodings TI never produces.
RESERVED_AS_ZERO = {
    0x56400000,  # ADDCL  ACC,loc32
    0x56530000,  # ADDUL  ACC,loc32
    0x56590000,  # MINCUL P,loc32
    0x56210000,  # MOVX   TL,loc16
    0x56110000,  # SQRS   loc16
}


def check(entries_by_doc):
    import yaml
    import glob

    ours = {}
    for f in sorted(glob.glob(os.path.join(ISA_DIR, "*.yaml"))):
        d = yaml.safe_load(open(f)) or {}
        for i in d.get("instructions") or []:
            ours.setdefault(i["opcode"], []).append((os.path.basename(f), i))

    exact = looser = tighter = absent = 0
    problems = []
    for doc, entries in entries_by_doc.items():
        for e in entries:
            cands = ours.get(e["opcode"])
            if not cands:
                absent += 1
                problems.append(
                    ("ABSENT", e["syntax"], e["opcode"], None, e["mask"], doc)
                )
                continue
            fname, row = cands[0]
            if row["mask"] == e["mask"]:
                exact += 1
            elif (row["mask"] & e["mask"]) == row["mask"]:
                looser += 1
                problems.append(
                    (
                        "OURS_LOOSER",
                        row["name"],
                        e["opcode"],
                        row["mask"],
                        e["mask"],
                        fname,
                    )
                )
            elif e["opcode"] in RESERVED_AS_ZERO:
                exact += 1
            else:
                tighter += 1
                problems.append(
                    (
                        "DISAGREE",
                        row["name"],
                        e["opcode"],
                        row["mask"],
                        e["mask"],
                        fname,
                    )
                )

    print(
        f"exact {exact}   ours-looser {looser}   disagree {tighter}   absent {absent}"
    )
    for kind, name, op, ourmask, specmask in (
        (p[0], p[1], p[2], p[3], p[4]) for p in problems
    ):
        om = _hex(ourmask, 8) if ourmask is not None else "-"
        print(
            f"  {kind:12s} {str(name)[:40]:42s} op={_hex(op, 8)} ours={om} spec={_hex(specmask, 8)}"
        )
    return 1 if problems else 0


def main():
    entries_by_doc = {}
    for doc, title in DOCS:
        entries = parse(doc)
        entries_by_doc[doc] = entries
        if "--check" not in sys.argv:
            path = emit(doc, title, entries)
            print(f"{doc}: {len(entries)} instructions -> {path}")
    if "--check" in sys.argv:
        return check(entries_by_doc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
