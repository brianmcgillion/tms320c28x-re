"""Ratchet on unmodeled encoding bits — the count may fall, never rise.

An unmodeled bit is neither fixed by an instruction's `mask` nor covered by an
operand field, so the decoder discards it: the instruction decodes, but loses
information. 808 of them went unnoticed until the TI manuals were transcribed,
precisely because nothing counted them.
"""

from __future__ import annotations

import os
import sys

import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from gen_known_gaps import collect  # noqa: E402

BASELINE = os.path.join(os.path.dirname(__file__), "..", "isa", "known_gaps.yaml")


@pytest.fixture(scope="module")
def baseline():
    with open(BASELINE) as fh:
        return yaml.safe_load(fh)


def test_unmodeled_bits_do_not_increase(baseline):
    total = sum(g["bits"] for g in collect())
    assert total <= baseline["total_bits"], (
        f"unmodeled encoding bits rose {baseline['total_bits']} -> {total}. "
        "Bind the new bits to an operand or widen the mask; if the increase is "
        "genuinely correct, rerun scripts/gen_known_gaps.py deliberately."
    )


def test_no_new_rows_carry_unmodeled_bits(baseline):
    known = {g["name"] for g in baseline["unmodeled_bits"]}
    current = {g["name"] for g in collect()}
    assert not (current - known), (
        f"instructions newly carrying unmodeled bits: {sorted(current - known)}"
    )


def test_baseline_is_current_or_stale_in_the_safe_direction(baseline):
    """A stale baseline is fine only if the real count has fallen below it."""
    total = sum(g["bits"] for g in collect())
    if total < baseline["total_bits"]:
        pytest.skip(
            f"baseline stale in the safe direction: {baseline['total_bits']} -> {total}; "
            "rerun scripts/gen_known_gaps.py to bank the improvement"
        )
    assert total == baseline["total_bits"]
