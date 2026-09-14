"""Derive each row's TI operand template from dis2000.

An instruction encodes only some of its operands; the rest are named in the
mnemonic. `ADDL ACC, loc32` encodes the loc32 and nothing else, so rendering
the decoded operands alone gives `ADDL @0x0` and a reader cannot tell it from
`ADDL @0x0, ACC`. TI prints both sides, and this works out how.

Rather than substitute rendered text into TI's string -- ambiguous the moment
two operands render alike, as `R0H, R0H, R0H` does -- each operand is probed
*independently*: disassemble the row once as a baseline, then once more with
only that operand's field changed, and whatever moved in TI's output is that
operand. The result is a template such as `ACC, {0}` or, where TI orders the
operands differently from the table, `{0}, {2}, {1}`.

A loc16 or loc32 slot also records which register-direct codes TI marks with
`@`, as `{1:@AH|AL}` -- that choice is per instruction and per register, so the
single-value probe above cannot see it and the codes have to be swept.

Writes isa/reference/operand_text.tsv.

Run: nix develop -c python3 scripts/probe_operands.py
"""

from __future__ import annotations

import difflib
import glob
import os
import re
import subprocess
import sys
import tempfile

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from c28x_rs import Decoder  # noqa: E402

OUT = os.path.join(ROOT, "isa", "reference", "operand_text.tsv")
SEP = 4  # NOP words between probes, so a rejected word cannot swallow the next


def encode(word, fmt):
    if fmt == 16:
        return bytes([word & 0xFF, (word >> 8) & 0xFF]) + b"\0\0"
    return (
        bytes(
            [(word >> 16) & 0xFF, (word >> 24) & 0xFF, word & 0xFF, (word >> 8) & 0xFF]
        )
        + b"\0\0"
    )


def decodes_to(dec, word, row):
    insn = dec.decode(encode(word, row["format"]), addr=0)
    return insn if insn is not None and insn.yaml_name == row["name"] else None


def variants(row):
    """Baseline word, then one word per operand with only that field changed."""
    ops = row.get("operands") or []
    base = row["opcode"]
    for op in ops:  # a baseline that is reachable and non-zero
        hi, lo = op["bits"]
        base |= (1 << lo) if hi > lo else 0
    yield None, base
    for i, op in enumerate(ops):
        hi, lo = op["bits"]
        width = hi - lo + 1
        field = 0b10 if width >= 2 else 1
        yield (
            i,
            (row["opcode"] & ~(((1 << width) - 1) << lo))
            | (field << lo)
            | (base & ~(((1 << width) - 1) << lo) & ~row["opcode"]),
        )


def reg_direct(row, base):
    """(operand index, loc field, word) over the register-direct codes 0xA0-0xAD.

    TI marks some of these with `@` and leaves others bare, per instruction and
    per register, so the choice cannot come from the one-value probe above and
    has to be swept.
    """
    for i, op in enumerate(row.get("operands") or []):
        if op["type"] not in ("loc16", "loc32"):
            continue
        _hi, lo = op["bits"]
        for field in range(0xA0, 0xAE):
            yield i, field, (base & ~(0xFF << lo)) | (field << lo)


def disassemble(work, words):
    """words: [(key, word, fmt)] -> {key: 'MNEMONIC operands'}"""
    lines, addr, at = ["        .text"], 0, {}
    for key, word, fmt in words:
        ws = [word & 0xFFFF] if fmt == 16 else [(word >> 16) & 0xFFFF, word & 0xFFFF]
        lines.append(
            "        .word " + ",".join(f"0x{x:04x}" for x in ws + [0x7700] * SEP)
        )
        at[addr] = key
        addr += len(ws) + SEP
    asm = os.path.join(work, "ops.asm")
    open(asm, "w").write("\n".join(lines) + "\n")
    subprocess.run(
        ["asm2000", "-v28", "--float_support=fpu32", asm],
        cwd=work,
        capture_output=True,
        text=True,
    )
    out = subprocess.run(
        ["dis2000", "--data_as_text", os.path.join(work, "ops.obj")],
        capture_output=True,
        text=True,
    ).stdout
    got = {}
    for line in out.splitlines():
        tok = line.split()
        if len(tok) >= 3 and re.fullmatch(r"[0-9a-f]{8}", tok[0]) and len(tok[1]) == 4:
            a = int(tok[0], 16)
            if a in at:
                got[at[a]] = re.sub(r"\s+", " ", line.split(None, 2)[2]).strip()
    return got


def operand_text(op):
    """How the plugin renders one decoded operand."""
    from c28x_rs import OperandType

    if op.type in (OperandType.REGISTER, OperandType.CONDITION):
        return op.name
    if op.type in (OperandType.LOC16, OperandType.LOC32):
        return op.resolved.text if op.resolved else op.name
    v = op.value
    return f"-0x{-v:x}" if op.signed and v < 0 else f"#0x{v:x}"


def changed_span(base, other):
    """The [start, end) of base that differs from other, or None."""
    sm = difflib.SequenceMatcher(None, base, other, autojunk=False)
    spans = [(i1, i2) for tag, i1, i2, _, _ in sm.get_opcodes() if tag != "equal"]
    if not spans:
        return None
    return spans[0][0], spans[-1][1]


def main():
    dec = Decoder(objmode=1)
    rows = [
        i
        for f in sorted(glob.glob(os.path.join(ROOT, "isa/instructions/*.yaml")))
        for i in yaml.safe_load(open(f))["instructions"]
    ]

    probes, keep = [], {}
    for row in rows:
        usable = []
        for idx, word in variants(row):
            if decodes_to(dec, word, row) is None:
                if idx is None:
                    usable = None
                    break
                continue
            usable.append((idx, word))
        if not usable:
            continue
        keep[row["name"]] = row
        for idx, word in usable:
            probes.append(((row["name"], idx), word, row["format"]))
        base = next(w for i, w in variants(row) if i is None)
        for i, field, word in reg_direct(row, base):
            if decodes_to(dec, word, row) is not None:
                probes.append(((row["name"], "@", i, field), word, row["format"]))

    with tempfile.TemporaryDirectory() as work:
        text = disassemble(work, probes)

    out = {}
    for name, row in keep.items():
        base = text.get((name, None))
        if base is None:
            continue
        mnemonic, _, ops = base.partition(" ")
        ops = ops.strip()
        template = ops
        marks = []
        for i in range(len(row.get("operands") or [])):
            other = text.get((name, i))
            if other is None or other.split(" ", 1)[0] != mnemonic:
                continue
            other_ops = other.partition(" ")[2].strip()
            span = changed_span(ops, other_ops)
            if span:
                marks.append((span, i))
        # Widen each change to the comma-separated field it lands in: changing
        # R1H to R2H moves one character, but the operand is the whole `R1H`.
        fields, pos = [], 0
        for part in ops.split(", "):
            fields.append((pos, pos + len(part)))
            pos += len(part) + 2

        owner = {}
        for (start, _end), i in marks:
            for f, (fs, fe) in enumerate(fields):
                if fs <= start < fe:
                    owner.setdefault(f, []).append(i)
                    break

        # A placeholder replaces one whole space-separated token: widening only
        # to the comma-separated field would swallow the fixed `<< 16` of
        # `ACC, @0x1 << 16`, and not widening at all would replace the single
        # character that changed between `R1H` and `R2H`.
        pieces, slot_field = [], {}
        for f, (fs, fe) in enumerate(fields):
            piece = ops[fs:fe]
            toks, tpos = [], 0
            for t in piece.split(" "):
                toks.append((tpos, tpos + len(t)))
                tpos += len(t) + 1
            tok_owner = {}
            for (st, _en), i in marks:
                if not (fs <= st < fe):
                    continue
                for ti, (ts, te) in enumerate(toks):
                    if ts <= st - fs < te:
                        tok_owner.setdefault(ti, i)
                        break
            for i in tok_owner.values():
                slot_field.setdefault(i, f)
            rendered = []
            for ti, (ts, te) in enumerate(toks):
                if ti not in tok_owner:
                    rendered.append(piece[ts:te])
                    continue
                # TI formats an immediate per instruction, not per width:
                # `ADDB ACC, #1` but `ANDB AL, #0x1`, and a shift amount bare.
                # Record which, so the renderer need not guess.
                tok = piece[ts:te]
                i = tok_owner[ti]
                if tok.startswith("#0x") or tok.startswith("-0x"):
                    rendered.append("{%d}" % i)
                elif tok.startswith("#") and tok[1:].lstrip("-").isdigit():
                    rendered.append("{%d:d}" % i)
                elif tok.lstrip("-").isdigit():
                    rendered.append("{%d:b}" % i)
                else:
                    rendered.append("{%d}" % i)
            pieces.append(" ".join(rendered))
        template = ", ".join(pieces)
        # Which register-direct codes TI marks with `@` in this row. Matched by
        # position, not by name: `MOV loc16, T` with loc16 = T prints
        # `MOV T, @T`, where the `@` is on the fixed second operand and the
        # loc16 -- the first -- carries none.
        at, base = {}, next(w for i, w in variants(row) if i is None)
        for i, field, word in reg_direct(row, base):
            insn = decodes_to(dec, word, row)
            got = text.get((name, "@", i, field))
            if insn is None or got is None or got.split(" ", 1)[0] != mnemonic:
                continue
            reg = insn.operands[i].resolved
            got_fields = got.partition(" ")[2].strip().split(", ")
            f = slot_field.get(i)
            if reg is None or f is None or f >= len(got_fields):
                continue
            if got_fields[f].startswith(f"@{reg.text}"):
                at.setdefault(i, []).append(reg.text)
        for i, regs in at.items():
            template = template.replace(
                "{%d}" % i, "{%d:@%s}" % (i, "|".join(dict.fromkeys(regs)))
            )
        out[name] = (mnemonic, template, ops)

    with open(OUT, "w") as fh:
        fh.write(
            "# TI's operand text per instruction, and the template derived from it by\n"
            "# probing each operand independently. `{N}` is our operand N, and\n"
            "# `{N:@AH|AL}` the registers TI marks with `@` when N is register-direct.\n"
            "#\n"
            "# Regenerate: nix develop -c python3 scripts/probe_operands.py\n"
            "#\n"
            "# name\tmnemonic\ttemplate\tprobed_text\n"
        )
        for name in sorted(out):
            m, t, o = out[name]
            fh.write(f"{name}\t{m}\t{t}\t{o}\n")
    bad = 0
    for name, (m, t, probed) in sorted(out.items()):
        row = keep[name]
        base = next(w for i, w in variants(row) if i is None)
        insn = decodes_to(dec, base, row)
        # The `@` spec cannot fire at this probe's operand value, so drop it.
        rendered = re.sub(r"\{(\d+):@[^}]*\}", r"{\1}", t)
        for i, op in enumerate(insn.operands):
            rendered = rendered.replace("{%d:d}" % i, f"#{op.value}")
            rendered = rendered.replace("{%d:b}" % i, f"{op.value}")
            rendered = rendered.replace("{%d}" % i, operand_text(op))
        if rendered != probed:
            bad += 1
            if bad <= 12:
                print(
                    f"  MISMATCH {name:30s} template={t!r} -> {rendered!r} want {probed!r}"
                )
    print(
        f"{OUT}: {len(out)} rows, {len(out) - bad} reproduce TI exactly, {bad} do not"
    )


if __name__ == "__main__":
    main()
