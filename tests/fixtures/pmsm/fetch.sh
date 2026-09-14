#!/usr/bin/env bash
# Fetch the PMSM-28335 firmware fixture — the only real-world COFF in the suite.
#
# 18 tests in tests/test_pmsm_firmware.py skip without it, including
# test_100_percent_decode: 47 C files' worth of F28335 motor-control firmware
# built by someone else's toolchain, which is a very different thing from our
# own five fixtures.
#
# The upstream repo ships a prebuilt pmsm.out, so this needs no cl2000 — the
# phase plan assumed a build step that turns out to be unnecessary.
#
# Not committed and not vendored: the .out is 233 KB of third-party object code
# and the upstream repo carries no LICENSE file. `.gitignore`'s `*.out` already
# keeps it out of the tree.
#
# Run: bash tests/fixtures/pmsm/fetch.sh
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$DIR/pmsm.out"
REPO="https://github.com/lestums/PMSM-28335"
SRC="PMSMCONTROL/sys/build/pmsm.out"

if [ -f "$OUT" ]; then
    echo "already present: $OUT ($(wc -c < "$OUT") bytes)"
    exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "=== Fetching $SRC from $REPO ==="
# Sparse checkout of the single file: the full tree is 47 .c files plus
# prebuilt IQmath/SFO libraries, none of which the tests read.
git init -q "$tmp"
git -C "$tmp" remote add origin "$REPO"
git -C "$tmp" config core.sparseCheckout true
echo "/$SRC" > "$tmp/.git/info/sparse-checkout"
git -C "$tmp" fetch -q --depth=1 origin master
git -C "$tmp" checkout -q master

cp "$tmp/$SRC" "$OUT"
echo "=== $OUT ($(wc -c < "$OUT") bytes) ==="
echo "18 previously-skipped tests in tests/test_pmsm_firmware.py will now run."
