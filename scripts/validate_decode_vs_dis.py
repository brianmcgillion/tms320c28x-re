"""Differential decoder oracle: plugin (Rust) decode vs TI dis2000 `dumped.dis`.

TI's `dis2000` is the authoritative C28x disassembler; `dumped.dis` is its
disassembly of real firmware. This walks the dump's manifest `code_ranges` and,
at every TI instruction boundary, decodes the same bytes with the plugin's
Binary Ninja architecture (the Rust decoder) and compares. It iterates by *TI's*
boundaries so a single length bug cannot cascade into a wall of false positives.

Scoped to `code_ranges` from `dumped.analysis.json` so the const pools that
`--data_as_text` force-disassembles do not generate noise.

Mismatch categories (most actionable first):
  DECODE_FAIL  plugin returns nothing where TI has an instruction
  LEN          plugin instruction length (words) != TI's  -> desync bug
  MNEM         normalized mnemonic differs                 -> wrong instruction
  BRANCH_TGT   plugin branch target != TI's computed target
  OPVAL        non-branch operand numeric values differ    -> wrong operand

Output: a JSON corpus (every mismatch) + a human summary with per-category
counts and clustered examples (by mnemonic / opcode top-byte) to drive fixes.

Run:  nix develop -c python scripts/validate_decode_vs_dis.py <dump-dir> [--out PATH]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
# repo root so the pure-Python c28x decoder is importable for 3-way triage
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from _bn_helpers import init_bn

# TI markers for non-code: 0x0000 -> ITRAP0, 0xFFFF -> ITRAP1 (erased filler).
# These are not real instructions; skip them so padding the classifier's descent
# may have over-covered does not masquerade as decoder mismatches.
TI_PADDING_MNEMS = {"ITRAP0", "ITRAP1"}

# Code-bearing regions: (section, origin_word, bin-filename). This is the
# F28335 layout -- on-chip flash at word 0x300000, boot ROM at 0x3FE000 -- and
# the filenames a dump directory is expected to use. A device convention, not
# one firmware: any F28335 dump laid out this way works. Edit for another part.
REGIONS = [("flash", 0x300000, "flash.bin"), ("bootrom", 0x3FE000, "bootrom.bin")]

_HEX = re.compile(r"-?0x[0-9a-fA-F]+|-?\b\d+\b")


# ── dumped.dis parser ────────────────────────────────────────────────────────
def parse_dis(path):
    """word_addr -> {addr, words[list], len(words), mnem, ops, parallel}.

    Primary line: '<8hex addr> <4hex word> MNEM operands'. A bare '<addr> <word>'
    line is a continuation word of the preceding (32-bit) instruction. A line
    that is '||MNEM ...' (no address) is a parallel op of the current insn.
    """
    insns = {}
    cur = None
    with open(path, "r", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            stripped = line.strip()
            if not stripped:
                cur = None
                continue
            if stripped.startswith("||"):
                if cur is not None:
                    cur["parallel"] = (
                        stripped[2:].split()[0] if len(stripped) > 2 else "||"
                    )
                continue
            toks = line.split()
            if len(toks) < 2 or len(toks[0]) != 8 or len(toks[1]) != 4:
                cur = None
                continue
            try:
                addr = int(toks[0], 16)
                word = int(toks[1], 16)
            except ValueError:
                cur = None
                continue
            if len(toks) >= 3:  # primary line
                cur = {
                    "addr": addr,
                    "words": [word],
                    "len": 1,
                    "mnem": toks[2],
                    "ops": " ".join(toks[3:]),
                    "parallel": None,
                }
                insns[addr] = cur
            else:  # continuation word
                if cur is not None and addr == cur["addr"] + cur["len"]:
                    cur["words"].append(word)
                    cur["len"] += 1
                else:
                    cur = None
    return insns


# ── normalization ────────────────────────────────────────────────────────────
def norm_mnem(m):
    return (m or "").upper().strip()


def numbers(s):
    """Signed integer values of every numeric literal in a string (hex or dec)."""
    out = []
    for tok in _HEX.findall(s or ""):
        try:
            out.append(
                int(tok, 16)
                if tok.lower().lstrip("-").startswith("0x")
                else int(tok, 10)
            )
        except ValueError:
            pass
    return out


def ti_branch_candidates(ti, word_addr):
    """Candidate target WORD addresses for a TI branch operand string: each
    number taken both as an absolute word and as a PC-relative offset (TI shows
    long branches absolute, short branches as a signed offset)."""
    cands = set()
    for n in numbers(ti["ops"]):
        cands.add(n & 0x3FFFFF)  # absolute word
        cands.add((word_addr + ti["len"] + n) & 0x3FFFFF)  # PC-relative
    return cands


# ── region bytes ─────────────────────────────────────────────────────────────
def load_regions(dump):
    regions = []
    for section, origin, fname in REGIONS:
        p = os.path.join(dump, fname)
        if section == "flash" and not os.path.isfile(p):
            cand = [
                f
                for f in os.listdir(dump)
                if "flash" in f and f.endswith(".bin") and not f.startswith("flash_")
            ]
            p = os.path.join(dump, cand[0]) if cand else p
        if os.path.isfile(p):
            regions.append((origin, open(p, "rb").read()))
    return regions


def fetch(regions, word, n=4):
    for origin, data in regions:
        off = (word - origin) * 2
        if 0 <= off < len(data):
            return data[off : off + n]
    return b""


# ── plugin decode via BN arch ────────────────────────────────────────────────
def plugin_decode(arch, data, byte_addr):
    """Return (length_words, mnemonic, operands_str, branch_target_word|None) or
    None if the plugin cannot decode."""
    info = arch.get_instruction_info(data, byte_addr)
    if info is None or info.length == 0:
        return None
    length_words = info.length // 2
    btgt = None
    try:
        for br in info.branches:
            t = getattr(br, "target", None)
            if t:
                btgt = (t // 2) & 0x3FFFFF
                break
    except Exception:
        pass
    mnem, ops = "", ""
    try:
        res = arch.get_instruction_text(data, byte_addr)
        tokens = res[0] if isinstance(res, tuple) else res
        texts = [t.text for t in tokens]
        if texts:
            mnem = texts[0].strip()
            ops = "".join(texts[1:]).strip()
    except Exception:
        pass
    return length_words, mnem, ops, btgt


def py_decode(pydec, data, byte_addr):
    """(length_words, mnemonic) from the pure-Python c28x decoder, or None.
    Used to triangulate: TI=Python!=Rust -> Rust-impl bug; TI!=both -> YAML/table."""
    if pydec is None:
        return None
    try:
        insn = pydec.decode(data, addr=byte_addr)
    except Exception:
        return None
    if insn is None:
        return None
    return insn.size // 2, insn.name


def python_decode_full(pydec, data, byte_addr):
    """Full (length_words, mnemonic, operands_str, branch_target_word|None) from
    the pure-Python decoder -- the backend used for the fast, BN-free, no-rebuild
    differential gate (the Python decoder reads the same isa/*.yaml the Rust
    tables are generated from, so its verdict matches a rebuilt Rust decoder)."""
    try:
        insn = pydec.decode(data, addr=byte_addr)
    except Exception:
        return None
    if insn is None:
        return None
    ops = ", ".join(o.name for o in insn.operands)
    tgt = (
        (insn.branch_target // 2) & 0x3FFFFF if insn.branch_target is not None else None
    )
    return insn.size // 2, insn.name, ops, tgt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "dump_dir",
        help="directory holding dis/dumped.dis, dis/dumped.analysis.json and "
        "the region binaries named in REGIONS",
    )
    ap.add_argument("--out", default="/tmp/decode_vs_dis.json")
    ap.add_argument("--limit-examples", type=int, default=60)
    ap.add_argument(
        "--backend",
        choices=("rust", "python"),
        default="rust",
        help="rust = the built plugin through BN; python = c28xdec. Since C1 "
        "both reach the same c28x_core table, so they should agree exactly; "
        "python needs no licence and is the one to use unless you are testing "
        "the plugin's own decode path.",
    )
    ap.add_argument(
        "--isa",
        default=None,
        help="isa/ dir for the python backend (default: repo isa/)",
    )
    args = ap.parse_args()

    dump = args.dump_dir
    dis_path = os.path.join(dump, "dis", "dumped.dis")
    manifest_path = os.path.join(dump, "dis", "dumped.analysis.json")
    for p in (dis_path, manifest_path):
        if not os.path.isfile(p):
            print(f"FAIL: missing {p}")
            return 1

    print("parsing dumped.dis ...", flush=True)
    ti = parse_dis(dis_path)
    manifest = json.load(open(manifest_path))
    code_ranges = manifest["code_ranges"]
    regions = load_regions(dump)
    print(
        f"  TI instructions: {len(ti)};  code_ranges: {len(code_ranges)};  "
        f"regions: {[hex(o) for o, _ in regions]}",
        flush=True,
    )

    from c28x_rs import Decoder as PyDecoder

    if args.backend == "rust":
        bn = init_bn()
        arch = bn.Architecture["tms320c28x"]
        print(f"  backend=rust  BN {bn.core_version()}; arch {arch.name}", flush=True)
        try:
            pydec = PyDecoder(objmode=1)  # for 3-way triage
        except Exception as e:
            print(f"  (python triage unavailable: {e})", flush=True)
            pydec = None

        def decode_fn(data, byte_addr):
            return plugin_decode(arch, data, byte_addr)
    else:
        if args.isa:
            # The Rust table is generated by core/c28x-core/build.rs and compiled
            # in, so there is no runtime table to point elsewhere. Rebuild
            # against the scratch tree instead:
            #   cargo build --release --manifest-path core/Cargo.toml
            sys.exit(
                "--isa is gone with the Python decoder; rebuild c28xdec "
                "against the isa/ tree you want to test"
            )
        pydec = PyDecoder(objmode=1)
        print("  backend=decoder  (c28xdec, repo isa/)", flush=True)

        def decode_fn(data, byte_addr):
            return python_decode_full(pydec, data, byte_addr)

    # TI instruction starts that fall inside a code_range, in address order.
    starts = sorted(
        a for a in ti if any(r["start_word"] <= a < r["end_word"] for r in code_ranges)
    )
    print(f"  comparing {len(starts)} instructions in code ranges ...", flush=True)

    cats = Counter()
    by_mnem = defaultdict(Counter)  # mnemonic -> category counts
    examples = defaultdict(list)  # category -> example rows
    total = ok = skipped_pad = 0

    for w in starts:
        t = ti[w]
        tmn = norm_mnem(t["mnem"])
        if tmn in TI_PADDING_MNEMS:  # 0x0000/0xFFFF filler, not real code
            skipped_pad += 1
            continue
        data = fetch(regions, w, 4)
        if len(data) < 2:
            continue
        total += 1
        pd = decode_fn(data, w * 2)
        row = {
            "word": w,
            "hex": "%06X" % w,
            "bytes": data.hex(),
            "ti": {"len": t["len"], "mnem": t["mnem"], "ops": t["ops"]},
        }

        def attach_py():
            if args.backend != "rust":
                return
            py = py_decode(pydec, data, w * 2)
            row["py"] = {"len": py[0], "mnem": py[1]} if py else None

        if pd is None:
            attach_py()
            cats["DECODE_FAIL"] += 1
            by_mnem[tmn]["DECODE_FAIL"] += 1
            if len(examples["DECODE_FAIL"]) < args.limit_examples:
                examples["DECODE_FAIL"].append(row)
            continue

        rlen, rmnem, rops, rtgt = pd
        row["rust"] = {"len": rlen, "mnem": rmnem, "ops": rops, "tgt": rtgt}
        rmn = norm_mnem(rmnem)
        issue = None

        if rlen != t["len"]:
            issue = "LEN"
        elif rmn != tmn:
            # display divergence: same base instruction, register/operand class
            # baked into the YAML name (e.g. MOVL_XAR6 vs MOVL). Correct decode,
            # non-idiomatic text. Real wrong-instruction bugs fall to MNEM.
            issue = "MNEM_DISP" if rmn.startswith(tmn + "_") else "MNEM"
        elif rtgt is not None:
            if rtgt not in ti_branch_candidates(t, w):
                issue = "BRANCH_TGT"
        elif sorted(numbers(t["ops"])) != sorted(numbers(rops)):
            issue = "OPVAL"  # non-branch: numeric operand values differ

        if issue is None:
            ok += 1
            continue
        attach_py()
        cats[issue] += 1
        by_mnem[tmn][issue] += 1
        if len(examples[issue]) < args.limit_examples:
            examples[issue].append(row)

    # ── report ──
    mism = sum(cats.values())
    disp = cats["MNEM_DISP"]
    real = mism - disp  # genuine decode defects
    decode_correct = ok + disp  # right instruction (maybe non-idiomatic text)
    print("\n" + "=" * 64)
    print(f"  DIFFERENTIAL DECODE  (skipped {skipped_pad} ITRAP padding words)")
    print(f"  exact match      : {ok}/{total} ({100.0 * ok / total:.2f}%)")
    print(
        f"  decode-correct   : {decode_correct}/{total} "
        f"({100.0 * decode_correct / total:.2f}%)  [+{disp} display-only]"
    )
    print(f"  REAL defects     : {real}")
    print("=" * 64)
    for cat in ("DECODE_FAIL", "LEN", "MNEM", "BRANCH_TGT", "OPVAL", "MNEM_DISP"):
        if cats[cat]:
            tag = " (display-only)" if cat == "MNEM_DISP" else ""
            print(f"  {cat:12s} {cats[cat]}{tag}")
    # Top offending mnemonics among REAL defects (the clusters to fix)
    print("\n  top mnemonics by REAL defect count:")

    def real_count(c):
        return sum(v for k, v in c.items() if k != "MNEM_DISP")

    worst = sorted(by_mnem.items(), key=lambda kv: -real_count(kv[1]))[:24]
    for mnem, c in worst:
        if real_count(c):
            print(f"    {mnem:14s} {dict(c)}")

    out = {
        "dump": dump,
        "total": total,
        "match": ok,
        "match_pct": round(100.0 * ok / total, 3) if total else 0,
        "decode_correct": decode_correct,
        "real_defects": real,
        "skipped_padding": skipped_pad,
        "categories": dict(cats),
        "by_mnemonic": {m: dict(c) for m, c in by_mnem.items() if sum(c.values())},
        "examples": dict(examples),
    }
    json.dump(out, open(args.out, "w"), indent=2)
    print(f"\n  corpus -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
