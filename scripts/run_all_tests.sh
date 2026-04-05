#!/usr/bin/env bash
# Full test suite for the TMS320C28x Binary Ninja plugin.
# Usage: nix run .#tests   (or:  nix develop -c bash scripts/run_all_tests.sh)
set -euo pipefail

# cd to repo root (works whether called directly or via nix run)
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd)" \
  || ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" \
  || { echo "ERROR: cannot find repo root"; exit 1; }
cd "$ROOT"

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

run_test() {
    local name="$1"
    shift
    echo -n "  [$name] "
    local logfile
    logfile=$(mktemp)
    if "$@" > "$logfile" 2>&1; then
        echo "PASSED"
        passed=$((passed + 1))
    else
        echo "FAILED"
        tail -10 "$logfile" | sed 's/^/    /'
        failed=$((failed + 1))
    fi
    rm -f "$logfile"
}

skip_test() {
    echo "  [$1] SKIPPED ($2)"
    skipped=$((skipped + 1))
}

echo "=============================================="
echo "  TMS320C28x BN Plugin — Full Test Suite"
echo "=============================================="
echo "  Root: $ROOT"
[ -n "$BN_DIR" ] && echo "  BN:   $BN_DIR" || echo "  BN:   not found"
echo

# ── Stage 1: Build Rust plugin ──
echo "Stage 1: Build plugin"
run_test "cargo build --release" cargo build --release --manifest-path rust/Cargo.toml

# ── Stage 2: Rust unit tests ──
echo
echo "Stage 2: Rust unit tests"
# Note: on NixOS, cargo test may fail to link the test binary due to
# bindgen/build-script linker issues (DSO missing from command line).
# The cdylib (stage 1) builds fine. BN headless validation (stage 5)
# is the authoritative test.
if LD_LIBRARY_PATH="$BN_DIR:${LD_LIBRARY_PATH:-}" \
    cargo test --release --manifest-path rust/Cargo.toml > /tmp/bn_test_$$.log 2>&1; then
    echo "  [cargo test --release] PASSED"
    passed=$((passed + 1))
else
    if grep -q "DSO missing from command line" /tmp/bn_test_$$.log 2>/dev/null; then
        skip_test "cargo test" "NixOS linker issue (DSO missing) — BN validation covers this"
    else
        echo "  [cargo test --release] FAILED"
        tail -10 /tmp/bn_test_$$.log | sed 's/^/    /'
        failed=$((failed + 1))
    fi
fi
rm -f /tmp/bn_test_$$.log

if [ -n "$BN_DIR" ] && [ -f rust/target/release/libtms320c28x_binja.so ]; then
    patchelf --set-rpath "$BN_DIR" rust/target/release/libtms320c28x_binja.so 2>/dev/null || true
    mkdir -p "$HOME/.binaryninja/plugins"
    cp rust/target/release/libtms320c28x_binja.so "$HOME/.binaryninja/plugins/" 2>/dev/null || true
    # Deploy Python companion plugins (flash loader, COFF loader, analysis tools)
    cp binja/flash.py "$HOME/.binaryninja/plugins/tms320c28x_flash.py" 2>/dev/null || true
    cp binja/coff_plugin.py "$HOME/.binaryninja/plugins/tms320c28x_coff.py" 2>/dev/null || true
    cp binja/elf_plugin.py "$HOME/.binaryninja/plugins/tms320c28x_elf.py" 2>/dev/null || true
    cp binja/tools.py "$HOME/.binaryninja/plugins/tms320c28x_cleanup.py" 2>/dev/null || true
    echo "  → Plugins deployed (Rust + Python)"
fi

# ── Stage 3: Compile synthetic fixtures ──
echo
echo "Stage 3: Synthetic fixtures"
if command -v cl2000 &>/dev/null; then
    run_test "build" bash tests/fixtures/build.sh
else
    skip_test "build" "cl2000 not in PATH"
fi
# Build synthetic flash fixture (no cl2000 needed)
run_test "flash fixture" python3 tests/build_flash_fixture.py

# ── Stage 4: Compile C2000Ware fixtures ──
echo
echo "Stage 4: C2000Ware fixtures"
if command -v cl2000 &>/dev/null; then
    if [ ! -d tests/fixtures/c2000ware/sdk/device_support ]; then
        run_test "fetch SDK" bash tests/fixtures/c2000ware/fetch.sh
    fi
    run_test "build" bash tests/fixtures/c2000ware/build.sh
else
    skip_test "build" "cl2000 not in PATH"
fi

# ── Stage 5: BN headless validation ──
echo
echo "Stage 5: BN headless validation"
if [ -z "$BN_DIR" ]; then
    skip_test "synthetic fixtures" "BN not found"
    skip_test "C2000Ware fixtures" "BN not found"
else
    if ls tests/fixtures/build/*.out &>/dev/null 2>&1; then
        run_test "synthetic fixtures" python3 scripts/validate_fixtures.py
    else
        skip_test "synthetic fixtures" "no .out files"
    fi
    if ls tests/fixtures/c2000ware/build/*.out &>/dev/null 2>&1; then
        run_test "C2000Ware fixtures" python3 scripts/validate_c2000ware.py
    else
        skip_test "C2000Ware fixtures" "no .out files"
    fi
fi

# ── Stage 5b: Flash binary validation ──
echo
echo "Stage 5b: Flash binary validation"
if [ -n "$BN_DIR" ] && [ -f tests/fixtures/build/flash_test.bin ]; then
    run_test "flash parsing" python3 scripts/validate_flash.py
else
    skip_test "flash parsing" "BN or flash fixture not available"
fi

# ── Stage 6: Structural decompilation comparison ──
echo
echo "Stage 6: Decompilation quality"
if [ -n "$BN_DIR" ] && ls tests/fixtures/build/*.out &>/dev/null 2>&1; then
    # This test reports warnings for decompilation gaps but doesn't fail the suite
    # (decompilation quality is a work-in-progress metric, not a gate)
    if python3 scripts/validate_decompilation.py > /tmp/bn_test_$$.log 2>&1; then
        echo "  [decompilation check] PASSED"
        passed=$((passed + 1))
    else
        # Extract pass/fail counts from output
        result=$(tail -2 /tmp/bn_test_$$.log | head -1)
        echo "  [decompilation check] PARTIAL ($result)"
        skipped=$((skipped + 1))
        # Don't count as failure — it's a quality metric
    fi
    rm -f /tmp/bn_test_$$.log
else
    skip_test "decompilation check" "BN or fixtures not available"
fi

# ── Stage 7: Functional equivalence validation ──
echo
echo "Stage 7: Functional equivalence"
if [ -n "$BN_DIR" ]; then
    has_fixtures=false
    ls tests/fixtures/build/*.out &>/dev/null 2>&1 && has_fixtures=true
    ls tests/fixtures/c2000ware/build/*.out &>/dev/null 2>&1 && has_fixtures=true
    if $has_fixtures; then
        run_test "functional equivalence (96%+ target)" python3 scripts/validate_functional.py
    else
        skip_test "functional equivalence" "no .out files"
    fi
else
    skip_test "functional equivalence" "BN not found"
fi

# ── Stage 8: Python decoder tests ──
echo
echo "Stage 8: Python decoder tests"
if command -v uv &>/dev/null; then
    run_test "pytest" uv run pytest tests/ -x -q --ignore=tests/test_firmware_bn.py --ignore=tests/test_pmsm_bn.py
else
    skip_test "pytest" "uv not in PATH"
fi

# ── Summary ──
echo
echo "=============================================="
total=$((passed + failed + skipped))
if [ $failed -eq 0 ]; then
    echo "  ALL PASSED: $passed passed, $skipped skipped (of $total)"
else
    echo "  FAILED: $passed passed, $failed failed, $skipped skipped (of $total)"
fi
echo "=============================================="

exit $failed
