"""TMS320C28x: Import dumped.dis / manifest — seed functions + mark data.

Projects the authoritative code/data + function-entry intelligence produced by
the dump toolchain (``classify_f28335.py`` -> ``dumped.analysis.json``) onto the
*live* flash BinaryView, without a COFF re-load. This recovers the ~150 KB of
long-branch-dispatched code Binary Ninja never reaches on its own and stops it
disassembling const tables (e.g. the dead WGS84 block) as code -- while leaving
every analyst rename/comment/function intact (idempotent, never clobbers user
symbols).

Source preference (resolved from the loaded view's path):
  1. ``<dump-reset>/dis/dumped.analysis.json``   -- the manifest (preferred)
  2. ``<dump-reset>/dis/dumped.dis``             -- TI disassembly (fallback)
The reconstructed COFF (``link/dumped.out``) carries no function symbols -- it is
all ``STYP_DATA`` because ``.word`` content never yields ``STYP_TEXT`` -- so it is
not used as a source here.

Addressing: the manifest stores chip-WORD addresses. This view's word->byte
mapping is auto-detected (``flash.bin`` at BN base 0x600000 and the stitched
8 MiB image at base 0 both use ``byte = word*2``; a raw ``flash.bin`` at base 0
uses ``byte = (word-0x300000)*2``).

Menu: Plugins > TMS320C28x > Import dumped.dis (seed functions + mark data)
"""

import json
import os

from binaryninja import (
    BackgroundTaskThread,
    PluginCommand,
    Symbol,
    SymbolType,
    Type,
    log_info,
    log_warn,
)

FLASH_ORIGIN_WORD = 0x300000


# ── artifact resolution ──────────────────────────────────────────────────────
def _candidate_dirs(bv):
    """Directories that may hold the sibling dis/ and link/ artifacts, derived
    from the view's file name(s) (handles .bndb and the original raw path)."""
    names = []
    fm = bv.file
    for attr in ("original_filename", "filename"):
        v = getattr(fm, attr, None)
        if v:
            names.append(v)
    dirs = []
    for n in names:
        base = n[:-5] if n.endswith(".bndb") else n
        dirs.append(os.path.dirname(os.path.abspath(base)))
    # de-dupe, preserve order
    return list(dict.fromkeys(dirs))


def _find_sources(bv):
    """Return (manifest_path | None, dis_path | None) for the loaded view."""
    manifest = dis = None
    for d in _candidate_dirs(bv):
        m = os.path.join(d, "dis", "dumped.analysis.json")
        s = os.path.join(d, "dis", "dumped.dis")
        if manifest is None and os.path.isfile(m):
            manifest = m
        if dis is None and os.path.isfile(s):
            dis = s
    return manifest, dis


# ── word -> byte mapping detection ───────────────────────────────────────────
def _detect_word_to_byte(bv, sample_words):
    """Pick the offset such that ``byte = word*2 + offset`` maps the manifest's
    chip-word addresses into this view, by trying the known load conventions and
    keeping whichever maps the most sample words.

      offset 0          -> byte = word*2   (flash.bin @0x600000; stitch @0)
      offset -0x600000  -> byte = (word-0x300000)*2  (raw flash.bin @ base 0)
    """
    candidates = [0, -FLASH_ORIGIN_WORD * 2, bv.start - FLASH_ORIGIN_WORD * 2]
    best_off, best_hits = 0, -1
    for off in dict.fromkeys(candidates):
        hits = sum(
            1 for w in sample_words if bv.get_segment_at(w * 2 + off) is not None
        )
        if hits > best_hits:
            best_hits, best_off = hits, off
    return best_off, best_hits


def _is_user_named(bv, addr):
    """True if the analyst (not auto-analysis) put a symbol at ``addr``."""
    sym = bv.get_symbol_at(addr)
    return sym is not None and not sym.auto


# ── the importer ─────────────────────────────────────────────────────────────
class DisImportTask(BackgroundTaskThread):
    def __init__(self, bv):
        super().__init__("C28x: importing dumped.dis manifest...", can_cancel=True)
        self.bv = bv
        # Action counters (the sidecar's OWN effect — distinct from BN's
        # reanalysis, which may drift the total function count by a few). A
        # second import on an unchanged view must yield funcs_added == 0.
        self.stats = {
            "funcs_added": 0,
            "funcs_skipped_existing": 0,
            "funcs_skipped_named": 0,
            "funcs_unmapped": 0,
            "data_words": 0,
            "funcs_removed": 0,
        }

    def run(self):
        bv = self.bv
        if bv.arch is None or bv.arch.name != "tms320c28x":
            log_warn("dis_sidecar: not a TMS320C28x binary")
            return

        manifest_path, dis_path = _find_sources(bv)
        if manifest_path:
            log_info(f"dis_sidecar: using manifest {manifest_path}")
            try:
                manifest = json.load(open(manifest_path))
            except Exception as e:
                log_warn(f"dis_sidecar: cannot read manifest: {e}")
                return
            functions = manifest.get("functions", [])
            data_ranges = manifest.get("data_ranges", [])
        elif dis_path:
            log_info(f"dis_sidecar: no manifest; parsing {dis_path}")
            functions, data_ranges = _parse_dis(dis_path)
        else:
            log_warn(
                "dis_sidecar: no dumped.analysis.json or dumped.dis found "
                f"near {bv.file.filename}"
            )
            return

        if not functions and not data_ranges:
            log_warn("dis_sidecar: nothing to import")
            return

        # Detect the word->byte mapping from a sample of manifest addresses.
        sample = [f["entry_word"] for f in functions[:64]] or [
            r["start_word"] for r in data_ranges[:64]
        ]
        offset, hits = _detect_word_to_byte(bv, sample)
        log_info(
            f"dis_sidecar: word->byte offset 0x{offset & 0xFFFFFFFF:X} "
            f"({hits}/{len(sample)} sample addrs mapped)"
        )
        if hits == 0:
            log_warn(
                "dis_sidecar: manifest addresses do not map into this view "
                "(wrong dump?) — aborting"
            )
            return

        def w2b(word):
            return word * 2 + offset

        self._apply_functions(functions, w2b)
        if self.cancelled:
            return
        self._apply_data(data_ranges, w2b)
        if self.cancelled:
            return

        self.progress = "C28x: re-analyzing..."
        bv.update_analysis_and_wait()
        log_info(f"dis_sidecar: done — {len(bv.functions)} functions total")

    # ── functions ────────────────────────────────────────────────────────────
    def _apply_functions(self, functions, w2b):
        bv = self.bv
        added = skipped_exist = skipped_named = skipped_unmapped = 0
        self.progress = "C28x: seeding functions..."
        for f in functions:
            if self.cancelled:
                return
            byte = w2b(f["entry_word"])
            seg = bv.get_segment_at(byte)
            if seg is None:
                skipped_unmapped += 1
                continue
            if bv.get_function_at(byte) is not None:
                skipped_exist += 1  # already a function -> idempotent
                continue
            if _is_user_named(bv, byte):
                skipped_named += 1  # analyst put a symbol here -> respect
                continue
            bv.add_function(byte)
            bv.define_auto_symbol(
                Symbol(
                    SymbolType.FunctionSymbol,
                    byte,
                    f.get("name", f"fn_{f['entry_word']:06X}"),
                )
            )
            added += 1
        self.stats.update(
            funcs_added=added,
            funcs_skipped_existing=skipped_exist,
            funcs_skipped_named=skipped_named,
            funcs_unmapped=skipped_unmapped,
        )
        log_info(
            f"dis_sidecar: functions +{added} "
            f"(skipped {skipped_exist} existing, {skipped_named} analyst-named, "
            f"{skipped_unmapped} unmapped)"
        )

    # ── data ─────────────────────────────────────────────────────────────────
    def _apply_data(self, data_ranges, w2b):
        bv = self.bv
        int2 = Type.int(2)
        # Snapshot function starts once (mapping start_byte -> function).
        func_at = {fn.start: fn for fn in bv.functions}
        marked_words = removed_funcs = 0
        self.progress = "C28x: marking data ranges..."
        for r in data_ranges:
            if self.cancelled:
                return
            lo = w2b(r["start_word"])
            hi = w2b(r["end_word"])
            if hi <= lo or bv.get_segment_at(lo) is None:
                continue

            # Drop auto-analysis functions that start inside the data span
            # (false "code"), but never an analyst-named one.
            for start in [a for a in func_at if lo <= a < hi]:
                if _is_user_named(bv, start):
                    continue
                try:
                    bv.remove_user_function(func_at[start])
                    removed_funcs += 1
                except Exception:
                    pass  # auto fn not user-removable; the data var below drops it

            # Define data over maximal sub-runs that carry no analyst symbol, so
            # renames/labels survive. One array per sub-run (fast + idempotent).
            addr = lo
            while addr < hi:
                if self.cancelled:
                    return
                if _is_user_named(bv, addr):
                    addr += 2
                    continue
                run_start = addr
                while addr < hi and not _is_user_named(bv, addr):
                    addr += 2
                n = (addr - run_start) // 2
                if n > 0:
                    try:
                        bv.define_user_data_var(run_start, Type.array(int2, n))
                        marked_words += n
                    except Exception:
                        pass
        self.stats.update(data_words=marked_words, funcs_removed=removed_funcs)
        log_info(
            f"dis_sidecar: data marked {marked_words} words across "
            f"{len(data_ranges)} ranges; removed {removed_funcs} false functions"
        )


# ── dumped.dis fallback parser ───────────────────────────────────────────────
def _parse_dis(dis_path):
    """Heuristically recover (functions, data_ranges) from a TI ``dumped.dis``.

    The .dis is produced with ``--data_as_text`` (everything shown as
    instructions), so it carries no native code/data split. We therefore:
      - seed functions from direct call targets (``LCR``/``LC``/``LCR``) and
        from ``ADDB SP`` prologue lines;
      - mark as data the long runs of obvious filler/garbage (``ITRAP0`` /
        repeated identical words), which is how const pools disassemble.
    This is a weaker source than the manifest and is used only when the manifest
    is absent. Addresses are chip WORD addresses (as in the .dis).
    """
    call_targets = set()
    prologues = set()
    garbage_run = []
    data_ranges = []
    GARBAGE = ("ITRAP0", "NOP_ZERO")
    GARBAGE_MIN = 8  # words

    def flush_garbage():
        if len(garbage_run) >= GARBAGE_MIN:
            data_ranges.append(
                {
                    "start_word": garbage_run[0],
                    "end_word": garbage_run[-1] + 1,
                    "section": ".dis_data",
                    "type": "data",
                }
            )
        garbage_run.clear()

    try:
        with open(dis_path, "r", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 2:
                    continue
                # instruction line: <8-hex word-addr> <4-hex word> [MNEMONIC ...]
                try:
                    addr = int(parts[0], 16)
                except ValueError:
                    continue
                if len(parts[1]) != 4:
                    continue
                try:
                    int(parts[1], 16)
                except ValueError:
                    continue
                mnem = parts[2] if len(parts) > 2 else ""

                if mnem in ("LCR", "LC", "FFC") and len(parts) > 3:
                    tgt = _parse_hex_operand(parts[3])
                    if tgt is not None:
                        call_targets.add(tgt)
                elif mnem == "ADDB" and len(parts) > 3 and parts[3].rstrip(",") == "SP":
                    prologues.add(addr)

                if mnem in GARBAGE:
                    garbage_run.append(addr)
                else:
                    flush_garbage()
        flush_garbage()
    except Exception as e:
        log_warn(f"dis_sidecar: .dis parse error: {e}")

    entries = sorted(call_targets | prologues)
    functions = [
        {
            "name": f"fn_{w:06X}",
            "entry_word": w,
            "source": "call" if w in call_targets else "prologue",
        }
        for w in entries
    ]
    return functions, data_ranges


def _parse_hex_operand(tok):
    tok = tok.strip().rstrip(",")
    if tok.startswith("0x") or tok.startswith("0X"):
        try:
            return int(tok, 16)
        except ValueError:
            return None
    if all(c in "0123456789abcdefABCDEF" for c in tok) and tok:
        try:
            return int(tok, 16)
        except ValueError:
            return None
    return None


# ── registration ─────────────────────────────────────────────────────────────
def import_dumped_dis(bv):
    DisImportTask(bv).start()


PluginCommand.register(
    r"TMS320C28x\Import dumped.dis (seed functions + mark data)",
    "Seed functions and mark data on the live flash view from the dump "
    "toolchain's dumped.analysis.json manifest (or dumped.dis fallback)",
    import_dumped_dis,
)
