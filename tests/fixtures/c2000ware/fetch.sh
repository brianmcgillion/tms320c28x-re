#!/usr/bin/env bash
# Sparse-clone the minimum C2000Ware files needed to build f28004x examples.
# Run: nix develop -c bash tests/fixtures/c2000ware/fetch.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_DIR="$SCRIPT_DIR/sdk"

if [ -d "$SDK_DIR/device_support" ]; then
    echo "SDK already fetched at $SDK_DIR"
    exit 0
fi

echo "=== Fetching C2000Ware SDK (sparse) ==="

mkdir -p "$SDK_DIR"
cd "$SDK_DIR"

git init
git remote add origin https://github.com/TexasInstruments/c2000ware-core-sdk.git
git config core.sparseCheckout true

# Fetch f28004x and f2833x (F28335) device support + all examples
cat > .git/info/sparse-checkout << 'EOF'
/device_support/f28004x/common/
/device_support/f28004x/headers/
/device_support/f28004x/examples/
/device_support/f2833x/common/
/device_support/f2833x/headers/
/device_support/f2833x/examples/
EOF

echo "Fetching (this may take a moment)..."
git fetch --depth=1 origin main
git checkout main

echo "=== SDK fetched ==="
du -sh "$SDK_DIR"
echo "Examples available:"
ls "$SDK_DIR/device_support/f28004x/examples/"
