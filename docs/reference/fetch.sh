#!/usr/bin/env bash
# Fetch the TI reference manuals that isa/reference/*.yaml is transcribed from.
# Run: nix develop -c bash docs/reference/fetch.sh
#
# The PDFs are copyrighted TI documents and are NOT committed. The derived
# encoding tables in isa/reference/ are facts about the hardware and are.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# name|url|sha256
DOCS=(
  "spru430f|https://www.ti.com/lit/ug/spru430f/spru430f.pdf|f705551b1c4630a0476b58d0ba7509e254c5bf1378956c41ade1e2ac16115a72"
  "sprueo2b|https://www.ti.com/lit/ug/sprueo2/sprueo2.pdf|da5c631340ae19d4f1db872f343a0fac181618912c660a10242ed45c9ae253a7"
)

for entry in "${DOCS[@]}"; do
    IFS='|' read -r name url want <<< "$entry"
    pdf="$SCRIPT_DIR/$name.pdf"
    txt="$SCRIPT_DIR/$name.txt"
    lay="$SCRIPT_DIR/$name-layout.txt"

    if [ -f "$pdf" ] && [ "$(sha256sum "$pdf" | cut -d' ' -f1)" = "$want" ]; then
        echo "$name: already present"
    else
        echo "$name: fetching $url"
        curl -sSL -o "$pdf" "$url"
        got="$(sha256sum "$pdf" | cut -d' ' -f1)"
        if [ "$got" != "$want" ]; then
            echo "  ERROR: sha256 mismatch" >&2
            echo "    want $want" >&2
            echo "    got  $got" >&2
            echo "  TI may have published a new revision. Verify the document, then update" >&2
            echo "  the checksum here AND re-check isa/reference/$name.yaml against it." >&2
            exit 1
        fi
    fi

    # Text extraction is what the transcription actually reads.
    [ -f "$txt" ] || pdftotext "$pdf" "$txt"
    # TI draws the shift and rotate operations as figures, and the default
    # rendering scatters their labels -- which is why spec_transcribe.py finds
    # an operation line on 3 of 21 shift rows. `-layout` keeps the figure
    # readable, so the semantics are recoverable by eye even where the parser
    # gives up. Not what the parser reads: it puts the label and the value on
    # one line, and the opcode block scan expects a bare `Opcode` line.
    #   pdftoppm -f <page> -l <page> -r 150 -png <pdf> out   renders the page.
    [ -f "$lay" ] || pdftotext -layout "$pdf" "$lay"
    printf '  %-10s %s pages, %s lines of text (+%s laid out)\n' \
        "$name" "$(pdfinfo "$pdf" | awk '/^Pages:/{print $2}')" \
        "$(wc -l < "$txt")" "$(wc -l < "$lay")"
done
