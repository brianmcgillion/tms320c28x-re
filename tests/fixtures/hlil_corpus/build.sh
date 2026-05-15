#!/usr/bin/env bash
# Build HLIL corpus: each src/*.c is compiled at -O0 and -O2 with cl2000.
# Produces 10 .out files in build/ for the HLIL quality investigation.
# Run: nix develop -c bash tests/fixtures/hlil_corpus/build.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"
LINK_DIR="$(cd "$SCRIPT_DIR/../link" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
CGT_DIR="$(dirname "$(which cl2000)")/.."

echo "=== Building HLIL corpus (-O0 + -O2 each) ==="
echo "Compiler: cl2000 $(cl2000 --compiler_revision)"
echo "Output:   $BUILD_DIR"
echo

mkdir -p "$BUILD_DIR"

BASE_FLAGS=(
    -v28
    --abi=eabi
    --float_support=fpu32
    -g
    --obj_directory="$BUILD_DIR"
    -I"$CGT_DIR/include"
)

LINK_FLAGS=(
    -z
    --rom_model
    -i"$CGT_DIR/lib"
    -l"rts2800_fpu32_eabi.lib"
    "$LINK_DIR/test.cmd"
)

success=0
fail=0

for src in "$SRC_DIR"/*.c; do
    name="$(basename "$src" .c)"
    for opt in O0 O2; do
        out="$BUILD_DIR/${name}_${opt}.out"
        map="$BUILD_DIR/${name}_${opt}.map"
        log="$BUILD_DIR/${name}_${opt}.log"

        echo -n "  Building ${name}_${opt}... "
        if cl2000 "${BASE_FLAGS[@]}" "-${opt}" "$src" \
            "${LINK_FLAGS[@]}" \
            -m"$map" -o"$out" 2>"$log"; then
            echo "OK ($(wc -c < "$out") bytes)"
            success=$((success + 1))
        else
            echo "FAILED (see $log)"
            tail -5 "$log" | sed 's/^/    /'
            fail=$((fail + 1))
        fi
    done
done

echo
echo "=== Results: $success OK, $fail failed ==="
exit $fail
