#!/usr/bin/env bash
# Build all test fixture C programs into ELF .out files using cl2000.
# Run: nix develop -c bash tests/fixtures/build.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"
LINK_DIR="$SCRIPT_DIR/link"
BUILD_DIR="$SCRIPT_DIR/build"
CGT_DIR="$(dirname "$(which cl2000)")/.."

echo "=== Building C28x test fixtures ==="
echo "Compiler: cl2000 $(cl2000 --compiler_revision)"
echo "CGT dir:  $CGT_DIR"
echo "Output:   $BUILD_DIR"
echo

mkdir -p "$BUILD_DIR"

COMMON_FLAGS=(
    -v28                          # C28x core
    --abi=eabi                    # ELF output (modern)
    --float_support=fpu32         # FPU32 hardware
    -O2                           # Match real firmware optimization level
    -g                            # Debug symbols
    --obj_directory="$BUILD_DIR"
    -I"$CGT_DIR/include"
)

LINK_FLAGS=(
    -z                            # Invoke linker
    --rom_model                   # ROM-based initialization
    -i"$CGT_DIR/lib"
    -l"rts2800_fpu32_eabi.lib"    # Runtime support library
    "$LINK_DIR/test.cmd"
)

success=0
fail=0

for src in "$SRC_DIR"/*.c; do
    name="$(basename "$src" .c)"
    out="$BUILD_DIR/${name}.out"
    map="$BUILD_DIR/${name}.map"

    echo -n "Building $name... "

    if cl2000 "${COMMON_FLAGS[@]}" "$src" \
        "${LINK_FLAGS[@]}" \
        -m"$map" \
        -o"$out" 2>"$BUILD_DIR/${name}.log"; then
        echo "OK ($(wc -c < "$out") bytes)"
        success=$((success + 1))
    else
        echo "FAILED (see $BUILD_DIR/${name}.log)"
        cat "$BUILD_DIR/${name}.log"
        fail=$((fail + 1))
    fi
done

echo
echo "=== Results: $success OK, $fail failed ==="

# Verify ELF format
echo
echo "=== Output files ==="
for out in "$BUILD_DIR"/*.out; do
    [ -f "$out" ] || continue
    fmt=$(file -b "$out" | head -c 40)
    syms=$(nm "$out" 2>/dev/null | wc -l)
    echo "  $(basename "$out"): $fmt ($syms symbols)"
done

exit $fail
