"""Golden decode transcripts over real cl2000 output.

Every other decoder test asks the table about itself: `assert insn is not None`
round-trips a row through the matcher that the same row configured, so it can
catch a *missing* opcode and never a *wrong* one. This walks the committed
objects in tests/golden/ linearly and records what the decoder says about each
instruction, so any change that moves a single byte of real compiler output
shows up as a diff naming the instruction.

Needs no Binary Ninja, no licence, and no TI toolchain: the objects are
committed and c28xdec reads them. Rebuilding the objects needs cl2000 and is a
separate, deliberate step (tests/golden/build.sh).

Run:  nix develop -c python3 scripts/gen_golden.py [--check]

  --check  regenerate and diff against the committed transcript, exit 1 on any
           difference. This is what tests/test_golden.py runs.
"""

from __future__ import annotations

import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import c28x_rs as c28x  # noqa: E402

GOLDEN_DIR = os.path.join(ROOT, "tests", "golden")
TRANSCRIPT = os.path.join(GOLDEN_DIR, "transcript.ndjson")


def transcribe() -> list[dict]:
    """One record per decoded instruction, in address order, every fixture."""
    dec = c28x.Decoder(objmode=1)
    out = []
    for path in sorted(glob.glob(os.path.join(GOLDEN_DIR, "*.obj"))):
        fixture = os.path.basename(path)
        coff = c28x.parse_coff(path)
        for sec in coff.sections:
            if not (sec.is_text and sec.data):
                continue
            off = 0
            while off + 4 <= len(sec.data):
                word_addr = sec.phys_addr + off // 2
                insn = dec.decode(sec.data[off : off + 4], word_addr)
                if insn is None:
                    out.append(
                        {
                            "fixture": fixture,
                            "section": sec.name,
                            "word_addr": word_addr,
                            "bytes": sec.data[off : off + 2].hex(),
                            "decoded": False,
                        }
                    )
                    off += 2
                    continue
                out.append(
                    {
                        "fixture": fixture,
                        "section": sec.name,
                        "word_addr": word_addr,
                        "bytes": sec.data[off : off + insn.size].hex(),
                        "yaml_name": insn.yaml_name,
                        "name": insn.name,
                        "size": insn.size,
                        "branch_type": insn.branch_type.name,
                        "branch_target": insn.branch_target,
                        "text": insn.text,
                        "operands": [
                            {
                                "type": op.type.name,
                                "value": op.value,
                                "name": op.name,
                                "mode": op.resolved.mode.name if op.resolved else None,
                            }
                            for op in insn.operands
                        ],
                    }
                )
                off += insn.size
    return out


def render(records: list[dict]) -> str:
    return "".join(json.dumps(r, sort_keys=True) + "\n" for r in records)


def main() -> int:
    text = render(transcribe())
    n = text.count("\n")
    if "--check" not in sys.argv:
        os.makedirs(GOLDEN_DIR, exist_ok=True)
        with open(TRANSCRIPT, "w") as fh:
            fh.write(text)
        print(f"wrote {TRANSCRIPT}: {n} instructions")
        return 0

    if not os.path.exists(TRANSCRIPT):
        print(f"ERROR: {TRANSCRIPT} is missing; run without --check to create it")
        return 1
    with open(TRANSCRIPT) as fh:
        want = fh.read()
    if want == text:
        print(f"golden transcript matches: {n} instructions")
        return 0

    import difflib

    diff = list(
        difflib.unified_diff(
            want.splitlines(),
            text.splitlines(),
            fromfile="committed",
            tofile="regenerated",
            lineterm="",
            n=0,
        )
    )
    print(f"golden transcript DIFFERS ({len(diff) - 2} changed lines):")
    for line in diff[:40]:
        print("  " + line)
    if len(diff) > 40:
        print(f"  ... {len(diff) - 40} more")
    return 1


if __name__ == "__main__":
    sys.exit(main())
