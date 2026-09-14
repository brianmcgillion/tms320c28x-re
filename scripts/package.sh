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
# Only cross-compile when actually cross-compiling. Passing --target for the
# host triple makes cargo build build scripts in a separate host pass that does
# not inherit CARGO_BUILD_RUSTFLAGS, so the devShell's glibc link flag is lost
# and every build script fails to link.
HOST=$(rustc -vV | sed -n 's/^host: //p')
if [ "$TARGET" = "$HOST" ]; then
    cargo build --release --manifest-path rust/Cargo.toml 2>&1 | tail -3
else
    cargo build --release --manifest-path rust/Cargo.toml --target "$TARGET" 2>&1 | tail -3
fi

# Find the built library
if [ "$TARGET" != "$HOST" ] && [ -d "rust/target/$TARGET/release" ]; then
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
# Every module, so a new shared one (memmap.py, patterns.py) cannot be left
# out of the release and break the plugin on a user's machine only.
cp binja/*.py binja/plugin.json "$PKG/"

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
