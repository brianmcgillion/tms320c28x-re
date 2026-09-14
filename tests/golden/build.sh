#!/usr/bin/env bash
# Rebuild the golden COFF objects from this repo's own MIT sources.
#
# Objects, not linked .out files, for three reasons: a link needs TI's runtime
# library (which cannot be committed), `.gitignore` already excludes `*.out`,
# and an object carries the compiler's real encodings without dragging in any
# TI code. Addresses are unrelocated, so a call to an external symbol decodes
# with a placeholder target -- deterministic, which is all the transcript needs.
#
# Run: nix develop -c bash tests/golden/build.sh
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$DIR/../fixtures/src"
CGT="$(dirname "$(which cl2000)")/.."

for src in "$SRC"/*.c; do
    name="$(basename "$src" .c)"
    cl2000 -v28 --float_support=fpu32 -O2 -c \
        --obj_directory="$DIR" -I"$CGT/include" "$src" >/dev/null
    echo "  $name.obj: $(wc -c < "$DIR/$name.obj") bytes"
done
