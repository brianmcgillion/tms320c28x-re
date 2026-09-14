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

Each page also closes its Description with TI's own operation notation --
`ACC = ACC + [loc32];`, `[loc32] = ACC - [loc32];`, `Modify flags on (ACC - P)` --
which is the only statement anywhere of what an instruction *computes*. dis2000
never says, and the encoding says nothing about direction: `MOVL loc32, P` and
`MOVL P, loc32` differ only in which side is the operand. That is captured here
as `operation`, with the coverage and the caveats in `--check`. It is a reading
aid for a human writing a `lift:` block, NOT a checkable gate: the notation is
irregular, occasionally a table rather than an operation, and sometimes simply
wrong (the `AND AX, loc16` page prints `AX = AX AND 16bit`, meaning `[loc16]`).

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

# Headings that end the Description prose. "Flags" alone is SPRUEO2B's spelling
# of SPRU430F's "Flags and Modes", and both manuals reuse "Description" as the
# column header *inside* that table, so it has to stop the block too.
SECTION = (
    "Flags and Modes",
    "Flags",
    "Example",
    "Repeat",
    "Restrictions",
    "Syntax Options",
    "Opcode",
    "Operands",
    "Objmode",
    "RPT",
    "CYC",
    "Description",
)
# A formal left-hand side is a register, a memory reference or a flag: short,
# and with none of the connective words that make a line prose.
LHS = re.compile(r"^[A-Za-z_\[][A-Za-z0-9_ ()\[\].:*]{0,26}$")
PROSE = re.compile(
    r"\b(the|is|are|of|to|then|if|and|or|this|that|which|be|by|for|with"
    r"|value|bit|register|instruction)\b",
    re.I,
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
    """Flag letters listed under the Flags and Modes table.

    Matched case-insensitively: the LSL64 and LSR64 pages print their N row as
    a lowercase `n`, and reading the column as typed dropped the flag and made
    the lifter look like it wrote one TI never mentions.
    """
    for k in range(start, min(start + 120, len(lines))):
        if lines[k].strip() == "Flags and Modes":
            found = []
            for j in range(k + 1, min(k + 90, len(lines))):
                t = lines[j].strip()
                # "Flags and Modes: None" -- FFC and AND IFR say exactly this.
                # Without it the scan ran past the end of the page and read the
                # NEXT instruction's table, so a call came out setting N and Z.
                if t == "None" and not found:
                    return []
                # Nor may it run into the following page even when that page
                # has no None marker.
                if t in ("Syntax Options", "Opcode") and found:
                    break
                # Only the flag cell is case-folded. The section break must not
                # be: the CMP pages open a sentence with "example, consider the
                # subtraction ...", which upper-cases into the Example heading
                # and ended the table after its first flag.
                name = t.upper()
                if name in FLAG_NAMES and name not in found:
                    found.append(name)
                elif t.startswith(("Example", "Repeat")) and found:
                    break
            return found
    return []


def _description(lines, start):
    """Prose under the page's own Description heading, or None."""
    for k in range(start, min(start + 90, len(lines))):
        t = lines[k].strip()
        if t in ("Flags and Modes", "Flags"):
            return None  # the flags table came first; this page has no prose
        if t == "Description":
            body = []
            for j in range(k + 1, min(k + 80, len(lines))):
                s = lines[j].strip()
                if s in SECTION:
                    break
                if s.startswith(BOILERPLATE):
                    continue
                body.append(s)
            return body
    return None


def _is_assignment(text):
    """`RaH = RbH + #16FHi:0` yes; `If(OVM = 0, enabled) then ...` no."""
    lhs, sep, rhs = text.partition("=")
    if not sep or not rhs.strip():
        return False
    lhs = lhs.strip()
    return bool(lhs) and bool(LHS.match(lhs)) and not PROSE.search(lhs)


def _operation(lines, start):
    """TI's operation notation from the Description block.

    Two shapes, because the manuals punctuate differently: SPRU430F closes the
    statement with `;`, SPRUEO2B drops the assignment into the prose with no
    punctuation at all -- which is why matching on `;` alone found the operation
    on 14% of the FPU pages and 82% of the arithmetic ones.
    """
    body = _description(lines, start)
    if not body:
        return []
    out = []
    for s in body:
        core = s.rstrip(";").strip()
        if not core:
            continue
        if not s.endswith(";") and (s.endswith(".") or not _is_assignment(core)):
            continue
        # A wholly parenthesised line is a figure caption -- the C28MAP page's
        # `(M0M1MAP = 0)` labels a memory-map table, it is not an operation.
        if core.startswith("(") and core.endswith(")"):
            continue
        out.append(core)
    return out


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
                "operation": _operation(lines, j),
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
            "# `operation` is TI's own notation for what the instruction computes, quoted\n"
        )
        fh.write(
            "# verbatim. It is a reading aid, not a gate: see _operation() for why.\n"
        )
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
            if e["operation"]:
                fh.write("    operation:\n")
                for line in e["operation"]:
                    fh.write(f"      - {line!r}\n")
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


# The four lifter families a declarative `lift:` block could replace, by the
# `semantics.type` their rows carry. Reported separately because that is the
# population the migration would touch, and its coverage is nothing like the
# whole table's.
LIFTER_FAMILIES = {
    "arith": {
        "add",
        "addc",
        "sub",
        "subb",
        "subcu",
        "cmp",
        "neg",
        "abs",
        "sat",
        "test",
    },
    "bitwise": {"and", "or", "xor", "not"},
    "shift": {"lsl", "lsr", "asr", "rol", "ror"},
    "fpu": {"fpu", "fpu_parallel"},
}


def _family(sem_type):
    for name, types in LIFTER_FAMILIES.items():
        if sem_type in types:
            return name
    return "other"


def _report_operation(entries_by_doc, ours):
    """Operation-line coverage, per manual and per row of our own table."""
    have = {}
    entries = 0
    for entries_ in entries_by_doc.values():
        for e in entries_:
            entries += 1
            if e["operation"] and not have.get(e["opcode"]):
                have[e["opcode"]] = True
    with_op = sum(1 for es in entries_by_doc.values() for e in es if e["operation"])

    counts = {k: [0, 0] for k in (*LIFTER_FAMILIES, "other")}
    for rows in ours.values():
        for _fname, row in rows:
            fam = _family((row.get("semantics") or {}).get("type", ""))
            counts[fam][0] += 1
            counts[fam][1] += bool(have.get(row["opcode"]))

    rows_n = sum(c[0] for c in counts.values())
    rows_w = sum(c[1] for c in counts.values())
    print(
        f"operation: {with_op}/{entries} manual entries "
        f"({100 * with_op / max(entries, 1):.1f}%),  "
        f"{rows_w}/{rows_n} of our rows ({100 * rows_w / max(rows_n, 1):.1f}%)"
    )
    mig_n = sum(counts[k][0] for k in LIFTER_FAMILIES)
    mig_w = sum(counts[k][1] for k in LIFTER_FAMILIES)
    per = "  ".join(f"{k} {counts[k][1]}/{counts[k][0]}" for k in LIFTER_FAMILIES)
    print(
        f"  lifter families {mig_w}/{mig_n} "
        f"({100 * mig_w / max(mig_n, 1):.1f}%):  {per}"
    )


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
    _report_operation(entries_by_doc, ours)
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
