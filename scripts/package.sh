#!/usr/bin/env bash
# Package the TMS320C28x Binary Ninja plugin for distribution.
# Creates a zip archive containing the Python + native plugin ready to install.
#
# Usage: bash scripts/package.sh [target]
#   target: rust target triple (default: auto-detect current platform)
#
# Output: dist/tms320c28x-<target>.zip
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Detect platform
case "$(uname -s)-$(uname -m)" in
    Linux-x86_64)  TARGET="${1:-x86_64-unknown-linux-gnu}";    NATIVE="libtms320c28x_binja.so" ;;
    Darwin-x86_64) TARGET="${1:-x86_64-apple-darwin}";         NATIVE="libtms320c28x_binja.dylib" ;;
    Darwin-arm64)  TARGET="${1:-aarch64-apple-darwin}";         NATIVE="libtms320c28x_binja.dylib" ;;
    MINGW*|MSYS*)  TARGET="${1:-x86_64-pc-windows-msvc}";      NATIVE="tms320c28x_binja.dll" ;;
    *)             echo "Unknown platform: $(uname -s)-$(uname -m)"; exit 1 ;;
esac

echo "=== Packaging TMS320C28x plugin ==="
echo "Target: $TARGET"
echo "Native: $NATIVE"

# Build native library
echo
echo "Building Rust plugin..."
cargo build --release --manifest-path rust/Cargo.toml ${TARGET:+--target "$TARGET"} 2>&1 | tail -3

# Find the built library
if [ -n "$TARGET" ] && [ -d "rust/target/$TARGET/release" ]; then
    NATIVE_PATH="rust/target/$TARGET/release/$NATIVE"
else
    NATIVE_PATH="rust/target/release/$NATIVE"
fi

if [ ! -f "$NATIVE_PATH" ]; then
    echo "ERROR: Native library not found at $NATIVE_PATH"
    exit 1
fi

# Create distribution
DIST="$ROOT/dist"
PKG="$DIST/tms320c28x"
rm -rf "$PKG"
mkdir -p "$PKG"

# Copy Python plugin files
cp binja/__init__.py "$PKG/"
cp binja/coff_plugin.py "$PKG/"
cp binja/elf_plugin.py "$PKG/"
cp binja/flash.py "$PKG/"
cp binja/tools.py "$PKG/"
cp binja/plugin.json "$PKG/"

# Copy native library
cp "$NATIVE_PATH" "$PKG/"

echo
echo "=== Package contents ==="
ls -la "$PKG/"

# Create zip
ZIPNAME="tms320c28x-${TARGET}.zip"
(cd "$DIST" && zip -r "$ZIPNAME" tms320c28x/)
echo
echo "=== Created: dist/$ZIPNAME ==="
ls -la "$DIST/$ZIPNAME"
