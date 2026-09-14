"""Every addressing-mode field must render exactly as dis2000 renders it.

`isa/reference/addressing_text.tsv` is TI's own output for all 256 values of
both fields, captured by scripts/probe_addressing.py. Checking against the file
rather than against the toolchain keeps this runnable without a TI install.

The renderings were wrong for 90 of the 256 loc16 values before this existed:
direct offsets printed in decimal, and the register-direct codes 0xA0-0xAD --
which name a CPU register, not a memory location -- fell through to a
`*ind(0xA0)` fallback that also lost their addressing mode.
"""

from __future__ import annotations

import os

import pytest

from c28x_rs import Decoder

TSV = os.path.join(
    os.path.dirname(__file__), "..", "isa", "reference", "addressing_text.tsv"
)
BASE = {"loc16": 0x8100, "loc32": 0x0600}


def _expected():
    rows = []
    with open(TSV) as fh:
        for line in fh:
            if line.startswith("#") or not line.strip():
                continue
            field, loc16, loc32 = (line.rstrip("\n").split("\t") + ["", ""])[:3]
            rows.append((int(field, 16), loc16, loc32))
    assert len(rows) == 256, f"{TSV} has {len(rows)} rows"
    return rows


EXPECTED = _expected()


@pytest.fixture(scope="module")
def decoder():
    return Decoder(objmode=1)


def _render(decoder, base, field):
    word = base | field
    insn = decoder.decode(bytes([word & 0xFF, (word >> 8) & 0xFF, 0, 0]), addr=0)
    assert insn is not None, f"0x{word:04X} did not decode"
    return insn.operands[0].resolved.text


@pytest.mark.parametrize(
    "field,loc16,loc32",
    EXPECTED,
    ids=lambda v: v if isinstance(v, str) else f"0x{v:02X}",
)
def test_addressing_text_matches_ti(decoder, field, loc16, loc32):
    assert _render(decoder, BASE["loc16"], field) == loc16
    if loc32:
        # 0xAD is not a valid loc32 code and dis2000 prints nothing for it; we
        # render `*ind(0xAD)`, which at least names the field.
        assert _render(decoder, BASE["loc32"], field) == loc32
