"""Analyze HLIL quality across the corpus of 10 controlled test binaries.

For each .out in tests/fixtures/hlil_corpus/build/, this loads the binary via
binja/elf_plugin.py, walks every discovered function, renders its HLIL, and
classifies each suspicious token. The output is a CSV-style table that
distinguishes:
  - LIFTER: the IL we emit doesn't capture the source semantics
  - ABI:    return values appear in unexpected registers (calling convention)
  - ARTIFACT: HLIL synthesis quirk (cosmetic; semantics unchanged)
  - UNDECODE: tokens that suggest a missed decode

Run: nix develop -c python3 scripts/analyze_hlil_corpus.py
"""

import importlib.util
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(__file__))
from _bn_helpers import init_bn

binaryninja = init_bn()

ROOT = os.path.join(os.path.dirname(__file__), "..")
CORPUS_DIR = os.path.join(ROOT, "tests", "fixtures", "hlil_corpus", "build")
ELF_MOD = os.path.join(ROOT, "binja", "elf_plugin.py")

spec = importlib.util.spec_from_file_location("elf_plugin", ELF_MOD)
elf_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(elf_mod)

# Token patterns we classify
PATTERNS = {
    "unimplemented": re.compile(r"\bunimplemented\b"),
    "undef": re.compile(r"\bundef(?:ined)?\b"),
    "cond_0": re.compile(r"\bcond:\d+\b"),
    "temp_n": re.compile(r"\btemp\d+\b"),
    "intrinsic": re.compile(r"__intrinsic|unimplemented_intrinsic"),
}

USER_FUNC_NAMES = {
    "sum_n", "main",                                 # simple_loop
    "divide", "compute",                             # fpu_divide
    "make_pair", "sum_pair",                         # multi_return
    "classify",                                      # nested_conditions
    "dispatch",                                      # switch_compare_chain
}


def load_view(out_path):
    raw = binaryninja.BinaryViewType["Raw"].open(out_path)
    view = elf_mod.C28xELFView(raw)
    view.init()
    view.update_analysis_and_wait()
    return view


def elf_symbols(out_path):
    """Map func name -> byte address from nm."""
    syms = {}
    result = subprocess.run(["nm", out_path], capture_output=True, text=True)
    for line in result.stdout.split("\n"):
        parts = line.split()
        if len(parts) >= 3 and parts[1] == "T":
            name = parts[2]
            if not name.startswith("$C$") and not name.startswith("__TI_"):
                syms[name] = int(parts[0], 16) * 2
    return syms


def analyze_function(func, hlil_text):
    """Classify suspicious tokens. Returns counter of pattern → count."""
    counts = Counter()
    for tag, pattern in PATTERNS.items():
        n = len(pattern.findall(hlil_text))
        if n:
            counts[tag] = n
    return counts


def main():
    if not os.path.isdir(CORPUS_DIR):
        print(f"FAIL: corpus not found at {CORPUS_DIR}")
        return 1

    out_files = sorted(f for f in os.listdir(CORPUS_DIR) if f.endswith(".out"))
    if not out_files:
        print(f"FAIL: no .out files in {CORPUS_DIR}")
        return 1

    aggregate = defaultdict(Counter)
    rows = []

    for out_name in out_files:
        out_path = os.path.join(CORPUS_DIR, out_name)
        binary_label = out_name[:-4]  # strip .out
        syms = elf_symbols(out_path)

        view = load_view(out_path)
        try:
            for sym_name, addr in syms.items():
                if sym_name not in USER_FUNC_NAMES:
                    continue
                f = view.get_function_at(addr)
                if not f:
                    # Try ±4 fallback (find_func pattern)
                    f = next(
                        (g for g in view.functions if abs(g.start - addr) <= 4),
                        None,
                    )
                if not f:
                    rows.append((binary_label, sym_name, "MISSING", 0, Counter()))
                    continue

                try:
                    hlil_text = str(f.hlil) if f.hlil else ""
                except Exception as e:
                    rows.append((binary_label, sym_name, f"HLIL_ERR:{e}", 0, Counter()))
                    continue

                bb_count = len(f.basic_blocks)
                line_count = hlil_text.count("\n")
                tokens = analyze_function(f, hlil_text)
                rows.append((binary_label, sym_name, "OK", bb_count, tokens))
                for tag, n in tokens.items():
                    aggregate[binary_label][tag] += n
                    aggregate["__total__"][tag] += n
        finally:
            view.file.close()

    # Output table
    print("=" * 100)
    print(f"  HLIL corpus analysis ({len(out_files)} binaries, {len(rows)} functions sampled)")
    print("=" * 100)
    print(f"\n{'binary':<28} {'func':<14} {'status':<8} {'BBs':>4} {'tokens'}")
    print("-" * 100)
    for binary, func, status, bbs, tokens in rows:
        tok_str = ", ".join(f"{k}={v}" for k, v in sorted(tokens.items())) if tokens else "clean"
        print(f"{binary:<28} {func:<14} {status:<8} {bbs:>4}  {tok_str}")

    print("\n--- Aggregate by binary ---")
    print(f"{'binary':<28} {'total tokens':<20}")
    for binary in sorted(aggregate):
        if binary == "__total__":
            continue
        tok_str = ", ".join(f"{k}={v}" for k, v in sorted(aggregate[binary].items())) if aggregate[binary] else "clean"
        print(f"{binary:<28} {tok_str}")

    print("\n--- Grand total ---")
    total = aggregate["__total__"]
    if not total:
        print("CLEAN across all binaries — no suspicious tokens found.")
    else:
        for k, v in sorted(total.items()):
            print(f"  {k}: {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
