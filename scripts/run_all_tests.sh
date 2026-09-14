#!/usr/bin/env bash
# Full test suite for the TMS320C28x Binary Ninja plugin.
# Usage: nix run .#tests   (or:  nix develop -c bash scripts/run_all_tests.sh)
set -euo pipefail
# BASH_SOURCE is a /nix/store path under `nix run`, where dirname/.. silently
# yields /nix rather than failing, so ask git first and check what we got.
ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"
[ -n "$ROOT" ] || ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd)"
[ -f "$ROOT/pyproject.toml" ] || { echo "ERROR: cannot find repo root"; exit 1; }
cd "$ROOT"

# ── NixOS workaround: ensure Cargo build scripts can link against glibc ──
if [ -z "${CARGO_BUILD_RUSTFLAGS:-}" ] && command -v cc &>/dev/null; then
    _glibc_dir="$(dirname "$(cc -print-file-name=libc.so.6)" 2>/dev/null)"
    if [ -n "$_glibc_dir" ] && [ -d "$_glibc_dir" ]; then
        export CARGO_BUILD_RUSTFLAGS="-C link-arg=-L${_glibc_dir}"
    fi
fi

# ── Find Binary Ninja from PATH ──
find_bn_dir() {
    if ! command -v binaryninja &>/dev/null; then
        echo ""
        return
    fi
    local bn_bin
    bn_bin="$(readlink -f "$(which binaryninja)")"
    local bn_prefix
    bn_prefix="$(dirname "$(dirname "$bn_bin")")"
    local bn_dir="$bn_prefix/opt/binaryninja"
    if [ -f "$bn_dir/libbinaryninjacore.so.1" ]; then
        echo "$bn_dir"
    else
        echo ""
    fi
}

BN_DIR="${BINARYNINJADIR:-$(find_bn_dir)}"
if [ -z "$BN_DIR" ]; then
    echo "WARNING: Binary Ninja not found in PATH. BN validation tests will be skipped."
    echo "         Install BN or set BINARYNINJADIR."
else
    export BINARYNINJADIR="$BN_DIR"
    export LD_LIBRARY_PATH="$BN_DIR:${LD_LIBRARY_PATH:-}"
fi

passed=0
failed=0
skipped=0
# A REQUIRED stage needs no Binary Ninja and no cl2000, so it must run
# everywhere. One that cannot run is an ERROR, not a skip: a run where nothing
# ran used to print "ALL PASSED: 2 passed, 12 skipped" and exit 0.
req_total=0; req_ok=0
opt_total=0; opt_ok=0
incomplete=0

run_req() { _run REQ "$@"; }
run_opt() { _run OPT "$@"; }

# An OPTIONAL stage that cannot run prints the exact command that would enable it.
skip_opt() {
    echo "  [$1] SKIPPED ($2)"
    echo "      enable with: $3"
    skipped=$((skipped + 1))
    opt_total=$((opt_total + 1))
}

# A REQUIRED stage that cannot run. Never "ALL PASSED" after this.
miss_req() {
    echo "  [$1] UNAVAILABLE ($2)"
    echo "      this stage needs no licence and no TI toolchain, so it should run here"
    req_total=$((req_total + 1))
    incomplete=1
}

_run() {
    local kind="$1" name="$2"
    local logfile=""
    shift 2
    # A REQUIRED stage whose tool is absent has not failed -- it did not run.
    # Reporting that as a failure would be as misleading as reporting it as a
    # pass: the distinction is the whole point of the exit codes below.
    if ! command -v "$1" &>/dev/null; then
        if [ "$kind" = REQ ]; then
            miss_req "$name" "$1 not in PATH"
        else
            skip_opt "$name" "$1 not in PATH" "install $1"
        fi
        return
    fi
    echo -n "  [$name] "
    logfile=$(mktemp)
    # Without the trap every failure path leaks the temp file.
    trap 'rm -f "${logfile:-}"' RETURN
    if [ "$kind" = REQ ]; then req_total=$((req_total + 1)); else opt_total=$((opt_total + 1)); fi
    if "$@" > "$logfile" 2>&1; then
        echo "PASSED"
        passed=$((passed + 1))
        if [ "$kind" = REQ ]; then req_ok=$((req_ok + 1)); else opt_ok=$((opt_ok + 1)); fi
    else
        echo "FAILED"
        tail -10 "$logfile" | sed 's/^/    /'
        failed=$((failed + 1))
    fi
}

echo "=============================================="
echo "  TMS320C28x BN Plugin — Full Test Suite"
echo "=============================================="
echo "  Root: $ROOT"
[ -n "$BN_DIR" ] && echo "  BN:   $BN_DIR" || echo "  BN:   not found"
echo

# ── Stage 1: Build Rust plugin ──
echo "Stage 1: Build plugin"
# --no-default-features links the binaryninjacore stub, so this needs no
# licence and is the only link smoke over arch.rs and the lifter that CI can
# run. REQUIRED.
#
# DESTDIR is not optional. The stub's own CMakeLists ends with
# `install(TARGETS ... DESTINATION ${PROJECT_BINARY_DIR})` -- it installs the
# library onto itself, and the copy removes the destination before reading the
# source, so the build destroys its own output and then fails to find it.
# Pointing DESTDIR elsewhere makes source and destination differ. This is an
# upstream bug, not a cmake-version one: 3.30.5 fails exactly the same way.
DESTDIR="$(mktemp -d)" run_req "cargo build (stub link)" \
    cargo build --release --manifest-path rust/Cargo.toml --no-default-features
if [ -n "$BN_DIR" ]; then
    run_opt "cargo build --release" cargo build --release --manifest-path rust/Cargo.toml
else
    skip_opt "cargo build --release" "BN not found" "install Binary Ninja or set BINARYNINJADIR"
fi

# ── Stage 2: Rust unit tests ──
echo
echo "Stage 2: Rust unit tests"
# The decoder tests live in core/, which has no Binary Ninja dependency, so this
# needs no licence and no system toolchain. It replaces a stage that swallowed
# every failure mentioning "DSO missing from command line" -- which on NixOS was
# all of them, because the tests were in a crate whose lib.rs imports
# binaryninja. They had therefore never run. This is a hard gate: if it cannot
# run, that is a failure, not a skip.
run_req "cargo test (core)" cargo test --manifest-path core/Cargo.toml

if [ -n "$BN_DIR" ] && [ -f rust/target/release/libtms320c28x_binja.so ]; then
    patchelf --set-rpath "$BN_DIR" rust/target/release/libtms320c28x_binja.so 2>/dev/null || true
    # Deploy the same layout scripts/package.sh ships: one `tms320c28x/`
    # package directory. It used to copy each module in as its own top-level
    # plugin file under a renamed filename, which meant __init__.py never ran,
    # the modules had no parent package, and so they could not share one --
    # which is why the F28335 memory map existed twice and had drifted.
    PLUGIN_DIR="$HOME/.binaryninja/plugins/tms320c28x"
    mkdir -p "$PLUGIN_DIR"
    # Remove the old flat deploy, or every module registers twice.
    rm -f "$HOME"/.binaryninja/plugins/tms320c28x_{flash,coff,elf,cleanup}.py \
          "$HOME/.binaryninja/plugins/libtms320c28x_binja.so" 2>/dev/null || true
    cp binja/*.py binja/plugin.json "$PLUGIN_DIR/" 2>/dev/null || true
    cp rust/target/release/libtms320c28x_binja.so "$PLUGIN_DIR/" 2>/dev/null || true
    echo "  → Plugins deployed (Rust + Python) to $PLUGIN_DIR"
fi

# ── Stage 3: Compile synthetic fixtures ──
echo
echo "Stage 3: Synthetic fixtures"
if command -v cl2000 &>/dev/null; then
    run_opt "build" bash tests/fixtures/build.sh
else
    skip_opt "build" "cl2000 not in PATH" "nix develop (x86_64-linux ships the TI compiler)"
fi
# Build synthetic flash fixture (no cl2000 needed)
run_req "flash fixture" python3 tests/build_flash_fixture.py

# ── Stage 4: Compile C2000Ware fixtures ──
echo
echo "Stage 4: C2000Ware fixtures"
if command -v cl2000 &>/dev/null; then
    if [ ! -d tests/fixtures/c2000ware/sdk/device_support ]; then
        run_opt "fetch SDK" bash tests/fixtures/c2000ware/fetch.sh
    fi
    run_opt "build" bash tests/fixtures/c2000ware/build.sh
else
    skip_opt "build" "cl2000 not in PATH" "nix develop (x86_64-linux ships the TI compiler)"
fi

# ── Stage 5: BN headless validation ──
echo
echo "Stage 5: BN headless validation"
if [ -z "$BN_DIR" ]; then
    skip_opt "synthetic fixtures" "BN not found" "install Binary Ninja or set BINARYNINJADIR"
    skip_opt "C2000Ware fixtures" "BN not found" "install Binary Ninja or set BINARYNINJADIR"
else
    if ls tests/fixtures/build/*.out &>/dev/null 2>&1; then
        run_opt "synthetic fixtures" python3 scripts/validate_fixtures.py
    else
        skip_opt "synthetic fixtures" "no .out files" "bash tests/fixtures/build.sh"
    fi
    if ls tests/fixtures/c2000ware/build/*.out &>/dev/null 2>&1; then
        run_opt "C2000Ware fixtures" python3 scripts/validate_c2000ware.py
    else
        skip_opt "C2000Ware fixtures" "no .out files" "bash tests/fixtures/c2000ware/build.sh"
    fi
fi

# ── Stage 5b: Flash binary validation ──
echo
echo "Stage 5b: Flash binary validation"
if [ -n "$BN_DIR" ] && [ -f tests/fixtures/build/flash_test.bin ]; then
    run_opt "flash parsing" python3 scripts/validate_flash.py
else
    skip_opt "flash parsing" "BN or flash fixture not available" "python3 tests/build_flash_fixture.py, with BN installed"
fi

# ── Stage 5a: binja/tools.py — missing-import smoke ──
echo
echo "Stage 5a: tools.py smoke (missing-import detector)"
# Needs no licence: every Task is exercised against a MagicMock BinaryView
# either way, so without BN we swap in tests/conftest_bn_stub.py rather than
# skip. This stage is the only thing that catches a missing top-level import
# in tools.py, which otherwise surfaces when a user clicks a menu item.
if [ -n "$BN_DIR" ]; then
    run_req "tools.py smoke" python3 scripts/smoke_tools.py
else
    run_req "tools.py smoke (stub)" python3 scripts/smoke_tools.py --stub
fi

# ── Stage 5d: Per-row lifter coverage ──
echo
echo "Stage 5d: Lifter coverage (per row)"
# llil_unimpl is 0, but it only counts what the corpus exercises -- a row the
# fixtures never reach can lift to nothing and no test would say so. This walks
# all 407 rows through the real plugin. Needs BN for LLIL, so it is OPTIONAL and
# has no CI equivalent; tests/test_isa_reachable.py covers the licence-free half.
if [ -n "$BN_DIR" ]; then
    run_opt "lifter ratchet" python3 scripts/lift_ratchet.py
else
    skip_opt "lifter ratchet" "BN not found" "install Binary Ninja or set BINARYNINJADIR"
fi

# ── Stage 5c: Real firmware smoke validation ──
echo
echo "Stage 5c: Real firmware smoke"
_real_fw="${TMS320_REAL_FIRMWARE:-tests/fixtures/real/firmware.bin}"
if [ -n "$BN_DIR" ] && [ -f "$_real_fw" ]; then
    TMS320_REAL_FIRMWARE="$_real_fw" run_opt "real firmware smoke" python3 scripts/validate_real_firmware.py
else
    skip_opt "real firmware smoke" "no real firmware" "TMS320_REAL_FIRMWARE=/path/to/firmware.bin nix run .#tests"
fi

# ── Stage 6: Structural decompilation comparison ──
echo
echo "Stage 6: Decompilation quality"
if [ -n "$BN_DIR" ] && ls tests/fixtures/build/*.out &>/dev/null 2>&1; then
    # Was PARTIAL-and-count-as-skipped, on the grounds that decompilation
    # quality is a work in progress. "Work in progress" is not a reason to be
    # exempt from regression detection: validate_decompilation.py already exits
    # non-zero only when a check it used to pass now fails, so a failure here is
    # a regression and is treated as one.
    run_opt "decompilation check" python3 scripts/validate_decompilation.py
else
    skip_opt "decompilation check" "BN or fixtures not available" "bash tests/fixtures/build.sh, with BN installed"
fi

# ── Stage 7: Functional equivalence validation ──
echo
echo "Stage 7: Functional equivalence"
if [ -n "$BN_DIR" ]; then
    has_fixtures=false
    ls tests/fixtures/build/*.out &>/dev/null 2>&1 && has_fixtures=true
    ls tests/fixtures/c2000ware/build/*.out &>/dev/null 2>&1 && has_fixtures=true
    if $has_fixtures; then
        run_opt "functional equivalence" python3 scripts/validate_functional.py
    else
        skip_opt "functional equivalence" "no .out files" "bash tests/fixtures/build.sh"
    fi
else
    skip_opt "functional equivalence" "BN not found" "install Binary Ninja or set BINARYNINJADIR"
fi

# ── Stage 8: Python decoder tests ──
echo
echo "Stage 8: Python decoder tests"
if command -v uv &>/dev/null; then
    # No --ignore: both files self-skip via pytestmark when BN is absent, so
    # the flags hid zero failures and hid the skip count from the ratchet. No
    # -x either, or the first failure stops the run before the ratchet sees it.
    run_req "pytest" uv run pytest tests/ -q
else
    miss_req "pytest" "uv not in PATH"
fi

# ── Summary ──
#
# 0 = every REQUIRED stage passed, and every OPTIONAL one passed or was
#     legitimately unavailable
# 1 = something failed
# 2 = a REQUIRED stage could not run; the run proves nothing, so INCOMPLETE
echo
echo "=============================================="
total=$((passed + failed + skipped))
if [ $failed -gt 0 ]; then
    rc=1
    echo "  FAILED: $passed passed, $failed failed, $skipped skipped (of $total)"
elif [ $incomplete -ne 0 ]; then
    rc=2
    echo "  INCOMPLETE: a required stage could not run ($req_ok/$req_total required)"
else
    rc=0
    echo "  ALL PASSED: $passed passed, $skipped skipped (of $total)"
fi
echo "=============================================="
echo "RESULT required=$req_ok/$req_total optional=$opt_ok/$opt_total exit=$rc"

exit $rc
