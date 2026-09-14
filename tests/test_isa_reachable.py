"""Every row in the ISA table must be reachable by some word.

A row that no input can ever select is dead weight that still looks like
coverage. Three kinds have been found in this table: an opcode with bits
outside its own mask, a byte-identical duplicate of another row, and a row
whose space was swallowed whole by a looser one (`XPREAD` at 0xAC00, hidden
behind a fabricated `ADD ACC,loc16<<shift` claiming all of 0xA000/0xF000).
"""

from __future__ import annotations

import glob
import os

import pytest
import yaml

from c28x_rs import Decoder

ISA_DIR = os.path.join(os.path.dirname(__file__), "..", "isa", "instructions")


def _rows():
    for path in sorted(glob.glob(os.path.join(ISA_DIR, "*.yaml"))):
        yield from yaml.safe_load(open(path))["instructions"]


def _words(row):
    """The canonical encoding, plus each operand field set to 1 and to its max.

    A row can be shadowed at its all-zero encoding and still reachable once an
    operand distinguishes it, so one probe per row is not enough.
    """
    yield row["opcode"]
    for op in row.get("operands") or []:
        hi, lo = op["bits"]
        yield row["opcode"] | (1 << lo)
        yield row["opcode"] | (((1 << (hi - lo + 1)) - 1) << lo)


def _encode(word, fmt):
    n = 4 if fmt == 32 else 2
    return (
        word.to_bytes(n, "big")[::-1]
        if fmt == 16
        else bytes(
            [(word >> 16) & 0xFF, (word >> 24) & 0xFF, word & 0xFF, (word >> 8) & 0xFF]
        )
    ) + b"\0\0"


@pytest.fixture(scope="module")
def decoder():
    return Decoder(objmode=1)


@pytest.mark.parametrize("row", list(_rows()), ids=lambda r: r["name"])
def test_row_is_reachable(row, decoder):
    for word in _words(row):
        insn = decoder.decode(_encode(word, row["format"]), addr=0)
        if insn is not None and insn.yaml_name == row["name"]:
            return
    pytest.fail(
        f"{row['name']} (opcode 0x{row['opcode']:08X}, mask 0x{row['mask']:08X}) "
        f"is unreachable: no probe decodes to it"
    )
