"""The golden transcript must match what the decoder produces today.

197 of the decoder's assertions were `assert insn is not None`, which asks the
table about itself and so can catch a missing opcode but never a wrong one.
This diffs a committed transcript of real cl2000 output instead, so a change
that moves one byte fails and names the instruction.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from gen_golden import TRANSCRIPT, render, transcribe  # noqa: E402


def test_transcript_matches_decoder():
    with open(TRANSCRIPT) as fh:
        committed = fh.read()
    assert render(transcribe()) == committed, (
        "the golden transcript no longer matches the decoder. If the change is "
        "deliberate, regenerate it with `python3 scripts/gen_golden.py` and "
        "review the diff as part of the commit."
    )


def test_transcript_is_not_trivially_small():
    """A truncated or empty transcript would pass the diff and prove nothing."""
    with open(TRANSCRIPT) as fh:
        lines = [ln for ln in fh if ln.strip()]
    assert len(lines) > 500, f"transcript has only {len(lines)} instructions"


def test_every_instruction_decoded():
    """A decode failure over real compiler output is a defect, not a datum."""
    failed = [r for r in transcribe() if not r.get("decoded", True)]
    assert not failed, f"{len(failed)} words failed to decode: {failed[:5]}"
