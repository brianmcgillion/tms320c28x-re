"""Properties the decoder must hold for *any* input, not just chosen ones.

The rest of the suite feeds the decoder encodings someone wrote down. These
feed it arbitrary bytes and arbitrary operand values, which is how you find the
cases nobody thought to write down.
"""

from __future__ import annotations

import glob
import os

import pytest
import yaml
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from c28x_rs import Decoder

ISA_DIR = os.path.join(os.path.dirname(__file__), "..", "isa", "instructions")

# One decoder, one subprocess, for every example. Building one per example would
# spend all its time on process startup.
_DECODER = Decoder(objmode=1)

# The pipe is shared mutable state, which is exactly what function_scoped_fixture
# warns about; here it is deliberate and safe, since decode is request/response.
_SETTINGS = settings(
    max_examples=300,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)


@given(st.binary(min_size=4, max_size=4))
@_SETTINGS
def test_decode_returns_none_or_a_legal_size(data: bytes):
    insn = _DECODER.decode(data, 0)
    if insn is not None:
        assert insn.size in (2, 4), f"{data.hex()} decoded with size {insn.size}"


@given(st.binary(min_size=4, max_size=4))
@_SETTINGS
def test_decode_does_not_read_past_the_instruction(data: bytes):
    """A 2-byte instruction must not depend on the two bytes after it.

    The decoder is handed a 4-byte window whatever the instruction's length, so
    a 16-bit row that accidentally matched on the following word would decode
    differently once that word changed -- and would then disagree with itself
    at the end of a section.
    """
    insn = _DECODER.decode(data, 0)
    if insn is None or insn.size != 2:
        return
    # Same first word, different second word, padded back to the 4 bytes the
    # decoder expects.
    other = _DECODER.decode(data[:2] + bytes([data[2] ^ 0xFF, data[3] ^ 0xFF]), 0)
    assert other is not None, (
        f"{data.hex()} decoded but {data[:2].hex()} + noise did not"
    )
    assert other.yaml_name == insn.yaml_name, (
        f"{data[:2].hex()} decodes as {insn.yaml_name} or {other.yaml_name} "
        "depending on the word after it"
    )
    assert other.size == insn.size


def _rows():
    for path in sorted(glob.glob(os.path.join(ISA_DIR, "*.yaml"))):
        yield from yaml.safe_load(open(path))["instructions"]


def _encode(word: int, fmt: int) -> bytes:
    """Little-endian per 16-bit word; the first word is the opcode's high half."""
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


ROWS = [r for r in _rows() if r.get("operands")]


@pytest.mark.parametrize("row", ROWS, ids=lambda r: r["name"])
def test_operand_values_do_not_change_which_row_matches(row):
    """Filling a row's operand fields must never select a different row.

    An operand field is by definition outside the mask, so no value in it can
    change the match -- unless a field overlaps the mask or another row, which
    is the defect class A3's build-time gate exists to catch. This walks the
    real matcher rather than the table's own claim about itself.
    """
    dec = _DECODER
    base, fmt = row["opcode"], row["format"]
    width = 16 if fmt == 16 else 32

    # Deterministic corners rather than random draws: 0, 1, and all-ones in each
    # field, which is where an overlap shows up if it is going to.
    for op in row["operands"]:
        hi, lo = op["bits"]
        if hi >= width:
            continue
        for value in (0, 1, (1 << (hi - lo + 1)) - 1):
            word = base | ((value << lo) & ((1 << width) - 1))
            insn = dec.decode(_encode(word, fmt), 0)
            if insn is None:
                continue
            assert insn.yaml_name == row["name"], (
                f"{row['name']}: setting {op['name']}={value:#x} at bits "
                f"[{hi}:{lo}] made {word:#0{width // 4 + 2}x} decode as "
                f"{insn.yaml_name}"
            )
