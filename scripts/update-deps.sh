#!/usr/bin/env bash
# Update package dependencies for tms320c28x-re
#
# This repo pins four independent dependency sources:
#   - Nix flake inputs        flake.lock
#   - Cargo dependencies      rust/Cargo.lock (workspace root is rust/)
#   - Binary Ninja API        git rev pinned in rust/Cargo.toml
#   - TI C2000 CGT            version + hash in the ti-cgt-c2000 derivation
#
# The first three of those are lock-file bumps and are safe by default.
# --binja and --ti change *pins* that must match an externally installed
# toolchain, so they are opt-in only and never run as part of --all.
#
# Usage: ./scripts/update-deps.sh [OPTIONS]
#
# Options:
#   --all            Update nix + cargo + python lock files (default)
#   --nix            Update only Nix flake inputs
#   --cargo          Update only Cargo dependencies
#   --python         Refresh only the uv-managed Python environment
#   --binja [REF]    Re-pin the binaryninja-api git rev to REF (default: the
#                    stable_<major.minor> branch matching the current pin)
#   --ti VERSION     Bump ti-cgt-c2000 to VERSION and recompute its hash
#   --upgrade        Also raise version constraints in source files
#   --no-verify      Skip the post-update verification stage
#   --help           Show this help message
#
# Examples:
#   ./scripts/update-deps.sh                   # Update all lock files
#   ./scripts/update-deps.sh --cargo --upgrade # Raise Cargo.toml bounds too
#   ./scripts/update-deps.sh --binja dev       # Track the BN API dev branch
#   ./scripts/update-deps.sh --ti 22.6.3.LTS   # Re-pin the TI compiler

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
info() {
  echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
  echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warn() {
  echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
  echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in the project root
if [[ ! -f "flake.nix" ]] || [[ ! -f "rust/Cargo.toml" ]]; then
  error "Must be run from the project root directory"
  error "  (expected ./flake.nix and ./rust/Cargo.toml)"
  exit 1
fi

CARGO_MANIFEST="rust/Cargo.toml"
BINJA_API_URL="https://github.com/Vector35/binaryninja-api"

# Run a command, capturing output, and report pass/fail from its real exit
# status rather than by grepping the output for "error:".
#
# Usage: run_step "<label>" cmd args...
run_step() {
  local label="$1"
  shift
  local logfile
  logfile=$(mktemp)
  if "$@" > "$logfile" 2>&1; then
    success "$label"
    rm -f "$logfile"
    return 0
  else
    warn "$label failed:"
    tail -20 "$logfile" | sed 's/^/    /'
    rm -f "$logfile"
    return 1
  fi
}

# Resolve the cargo invocation once: prefer cargo on PATH, fall back to the
# devShell.
resolve_cargo() {
  if [[ -n ${CARGO_CMD:-} ]]; then
    return 0
  fi
  if command -v cargo &> /dev/null; then
    CARGO_CMD="cargo"
    return 0
  fi
  warn "Cargo not found in PATH, trying via nix develop..."
  if nix develop -c cargo --version &> /dev/null; then
    CARGO_CMD="nix develop -c cargo"
    return 0
  fi
  error "Cargo is not available"
  return 1
}

update_nix() {
  info "Updating Nix flake inputs..."

  if ! command -v nix &> /dev/null; then
    error "Nix is not installed"
    return 1
  fi

  nix flake update

  success "Nix flake inputs updated"

  info "Flake input changes:"
  git --no-pager diff flake.lock | grep -E "^\+.*\"(narHash|rev)\"" | head -20 || true
}

update_cargo() {
  local upgrade_mode=${1:-false}

  if [[ $upgrade_mode == true ]]; then
    info "Upgrading Cargo dependencies (will update $CARGO_MANIFEST)..."
  else
    info "Updating Cargo dependencies (lock file only)..."
  fi

  resolve_cargo || return 1

  if [[ $upgrade_mode == true ]]; then
    if $CARGO_CMD upgrade --help &> /dev/null; then
      warn "⚠️  UPGRADE MODE: This will modify $CARGO_MANIFEST!"

      info "Running cargo upgrade..."
      # binaryninja is pinned to a git rev that must match the installed BN
      # ABI — it is bumped by --binja, never by cargo-upgrade.
      $CARGO_CMD upgrade --manifest-path "$CARGO_MANIFEST" --exclude binaryninja \
        || warn "cargo upgrade failed"

      success "$CARGO_MANIFEST upgraded"
    else
      warn "cargo-upgrade not available"
      warn "To enable version upgrades, install cargo-edit:"
      warn "  cargo install cargo-edit"
      warn "Falling back to lock file updates only"
    fi
  fi

  info "Updating rust/Cargo.lock..."
  $CARGO_CMD update --manifest-path "$CARGO_MANIFEST"

  success "Cargo dependencies updated"

  info "Checking for version changes..."
  git --no-pager diff rust/Cargo.lock 2> /dev/null | grep -E "^[\+\-]version = " | head -20 || true
}

update_python() {
  local upgrade_mode=${1:-false}

  info "Refreshing the uv-managed Python environment..."

  if ! command -v uv &> /dev/null; then
    error "uv is not available (enter 'nix develop' first)"
    return 1
  fi

  # uv.lock is gitignored in this repo, so this mode intentionally produces no
  # tracked diff — it only refreshes the local .venv.
  uv lock --upgrade || warn "uv lock failed"
  uv sync --all-extras || warn "uv sync failed"

  success "Python environment refreshed (uv.lock is gitignored — no repo diff expected)"

  info "Resolved dependency tree (newer versions flagged):"
  uv tree --outdated || warn "could not list the dependency tree"

  if [[ $upgrade_mode == true ]]; then
    warn "Version bounds in pyproject.toml are NOT rewritten automatically."
    warn "Raise them by hand based on the table above."
  fi
}

update_binja() {
  local ref="${1:-}"

  info "Re-pinning the binaryninja-api git rev..."

  if ! git diff --quiet -- "$CARGO_MANIFEST"; then
    error "$CARGO_MANIFEST already has uncommitted changes — refusing to rewrite it"
    return 1
  fi

  local current_rev
  current_rev=$(grep -oP 'rev = "\K[0-9a-f]{40}' "$CARGO_MANIFEST" | head -1 || true)
  if [[ -z $current_rev ]]; then
    error "Could not find the binaryninja rev pin in $CARGO_MANIFEST"
    return 1
  fi

  # Derive the default ref from the ABI comment, e.g.
  #   "# Pinned to ABI 164 to match BN 5.3.9434"  ->  stable_5.3
  if [[ -z $ref ]]; then
    local bn_version
    bn_version=$(grep -oP 'match BN \K[0-9]+\.[0-9]+' "$CARGO_MANIFEST" | head -1 || true)
    if [[ -n $bn_version ]]; then
      ref="stable_${bn_version}"
    else
      ref="dev"
      warn "No BN version comment found in $CARGO_MANIFEST, defaulting to '$ref'"
    fi
  fi

  info "Resolving $BINJA_API_URL @ $ref ..."
  local new_rev
  new_rev=$(git ls-remote "$BINJA_API_URL" "$ref" 2> /dev/null | awk 'NR==1 {print $1}')
  if [[ -z $new_rev ]]; then
    error "Could not resolve ref '$ref' in $BINJA_API_URL"
    return 1
  fi

  info "  current: $current_rev"
  info "  latest:  $new_rev ($ref)"

  if [[ $current_rev == "$new_rev" ]]; then
    success "Already at the latest rev for $ref"
    return 0
  fi

  sed -i "s/${current_rev}/${new_rev}/" "$CARGO_MANIFEST"
  success "$CARGO_MANIFEST re-pinned to $new_rev"

  resolve_cargo || return 1
  $CARGO_CMD update -p binaryninja --manifest-path "$CARGO_MANIFEST" \
    || warn "cargo update -p binaryninja failed"

  echo ""
  warn "⚠️  The BN API rev must match your INSTALLED Binary Ninja ABI."
  local bn_dir=""
  if command -v binaryninja &> /dev/null; then
    local bn_real bn_prefix
    bn_real="$(readlink -f "$(which binaryninja)")"
    bn_prefix="$(dirname "$(dirname "$bn_real")")"
    bn_dir="$bn_prefix/opt/binaryninja"
  fi
  if [[ -n $bn_dir ]]; then
    warn "Installed BN detected at: $bn_dir"
  else
    warn "No Binary Ninja found in PATH — cannot check the installed version."
  fi
  warn "Verify and update by hand if needed:"
  warn "  - the 'Pinned to ABI ... to match BN ...' comment in $CARGO_MANIFEST"
  warn "  - 'minimumBinaryNinjaVersion' in binja/plugin.json"
}

update_ti() {
  local version="${1:-}"

  if [[ -z $version ]]; then
    error "--ti requires a version, e.g. --ti 22.6.3.LTS"
    error "TI publishes no version index; check https://www.ti.com/tool/C2000-CGT"
    return 1
  fi

  info "Re-pinning ti-cgt-c2000 to $version ..."

  if [[ "$(uname -s)-$(uname -m)" != "Linux-x86_64" ]]; then
    warn "ti-cgt-c2000 is x86_64-linux only — skipping on $(uname -s)-$(uname -m)"
    return 0
  fi

  for tool in nix jq; do
    if ! command -v "$tool" &> /dev/null; then
      error "$tool is required for --ti but was not found"
      return 1
    fi
  done

  local old_version old_hash
  old_version=$(grep -oP 'version = "\K[^"]+' flake.nix | head -1 || true)
  old_hash=$(grep -oP 'hash = "\Ksha256-[^"]+' flake.nix | head -1 || true)
  if [[ -z $old_version ]] || [[ -z $old_hash ]]; then
    error "Could not find the ti-cgt-c2000 version/hash pin in flake.nix"
    return 1
  fi

  local url="https://dr-download.ti.com/software-development/ide-configuration-compiler-or-debugger/MD-xqxJ05PLfM/${version}/ti_cgt_c2000_${version}_linux-x64_installer.bin"

  info "Prefetching $url ..."
  local new_hash
  new_hash=$(nix store prefetch-file --json --hash-type sha256 "$url" 2> /dev/null | jq -r '.hash') || true
  if [[ -z $new_hash ]] || [[ $new_hash == "null" ]]; then
    error "Prefetch failed — is $version a valid TI CGT release?"
    return 1
  fi

  info "  version: $old_version -> $version"
  info "  hash:    $old_hash -> $new_hash"

  if [[ $old_version == "$version" ]] && [[ $old_hash == "$new_hash" ]]; then
    success "flake.nix already pins $version with the correct hash"
    return 0
  fi

  sed -i "s|version = \"${old_version}\"|version = \"${version}\"|" flake.nix
  sed -i "s|hash = \"${old_hash}\"|hash = \"${new_hash}\"|" flake.nix

  success "ti-cgt-c2000 re-pinned to $version"
  warn "Rebuild the devShell to pick it up: nix develop --refresh"
}

verify_updates() {
  info "Verifying updates..."

  # This repo exposes no packages/checks outputs, so 'nix build' and
  # 'nix flake check' prove nothing. Evaluate the lock instead.
  if command -v nix &> /dev/null; then
    run_step "Flake evaluation" nix flake metadata || true
  fi

  if resolve_cargo 2> /dev/null; then
    # Always cheap and environment-independent: proves every entry in the
    # refreshed lock file is still resolvable and downloadable.
    # shellcheck disable=SC2086  # CARGO_CMD may be "nix develop -c cargo"
    run_step "cargo fetch (lock integrity)" \
      $CARGO_CMD fetch --manifest-path "$CARGO_MANIFEST" || true

    # A real compile check needs Binary Ninja: the --no-default-features stub
    # path builds a C stub via cmake, which does not link on NixOS (the same
    # "DSO missing"/libc issue run_all_tests.sh tolerates in stage 2). CI
    # covers that path on ubuntu/macos/windows instead.
    if [[ -n ${BINARYNINJADIR:-} ]] || command -v binaryninja &> /dev/null; then
      # shellcheck disable=SC2086  # CARGO_CMD may be "nix develop -c cargo"
      run_step "cargo check" \
        $CARGO_CMD check --release --manifest-path "$CARGO_MANIFEST" || true
    else
      warn "cargo check skipped: Binary Ninja not found (CI covers the stub build)"
    fi
  fi

  if command -v uv &> /dev/null; then
    run_step "pytest" \
      uv run pytest tests/ -q \
      --ignore=tests/test_firmware_bn.py \
      --ignore=tests/test_pmsm_bn.py || true
  fi
}

show_summary() {
  echo ""
  info "Update Summary:"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  if git diff --quiet; then
    info "No changes detected"
  else
    info "Changed files:"
    git status --short | grep -E "^\s*M\s+" | awk '{print "  - " $2}'
  fi

  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  info "Next steps:"
  echo "  1. Review changes: git diff"
  echo "  2. Run the full suite: nix run .#tests"
  echo "  3. Commit: git add -A && git commit -sm 'chore: update dependencies'"
}

usage() {
  echo "Usage: $0 [OPTIONS]"
  echo ""
  echo "Update tms320c28x-re dependencies"
  echo ""
  echo "Options:"
  echo "  --all            Update nix + cargo + python (default)"
  echo "  --nix            Update only Nix flake inputs (flake.lock)"
  echo "  --cargo          Update only Cargo dependencies (rust/Cargo.lock)"
  echo "  --python         Refresh only the uv-managed Python environment"
  echo "  --binja [REF]    Re-pin the binaryninja-api git rev to REF"
  echo "                   (default: the stable_<major.minor> branch matching"
  echo "                   the BN version in rust/Cargo.toml; 'dev' also works)"
  echo "  --ti VERSION     Bump ti-cgt-c2000 to VERSION and recompute its hash"
  echo "  --upgrade        Raise version constraints in source files"
  echo "                   (rust/Cargo.toml — potentially breaking)"
  echo "  --no-verify      Skip the post-update verification stage"
  echo "  --help           Show this help message"
  echo ""
  echo "Examples:"
  echo "  $0                       # Update all lock files"
  echo "  $0 --upgrade             # Raise source bounds + update locks"
  echo "  $0 --cargo               # Update only rust/Cargo.lock"
  echo "  $0 --binja dev           # Track the BN API dev branch"
  echo "  $0 --ti 22.6.3.LTS       # Re-pin the TI C2000 compiler"
  echo ""
  echo "Notes:"
  echo "  - Without --upgrade: only lock files change (safe)"
  echo "  - --binja and --ti change pins that must match externally installed"
  echo "    tooling, so they never run as part of --all"
  echo "  - uv.lock is gitignored, so --python leaves no tracked diff"
}

main() {
  local update_all=true
  local do_nix=false
  local do_cargo=false
  local do_python=false
  local do_binja=false
  local do_ti=false
  local binja_ref=""
  local ti_version=""
  local upgrade_mode=false
  local verify=true

  while [[ $# -gt 0 ]]; do
    case $1 in
    --all)
      update_all=true
      ;;
    --nix)
      update_all=false
      do_nix=true
      ;;
    --cargo)
      update_all=false
      do_cargo=true
      ;;
    --python)
      update_all=false
      do_python=true
      ;;
    --binja)
      update_all=false
      do_binja=true
      # Optional ref argument
      if [[ $# -gt 1 ]] && [[ $2 != --* ]]; then
        binja_ref="$2"
        shift
      fi
      ;;
    --ti)
      update_all=false
      do_ti=true
      if [[ $# -gt 1 ]] && [[ $2 != --* ]]; then
        ti_version="$2"
        shift
      fi
      ;;
    --upgrade)
      upgrade_mode=true
      ;;
    --no-verify)
      verify=false
      ;;
    --help | -h)
      usage
      exit 0
      ;;
    *)
      error "Unknown option: $1"
      echo "Use --help for usage information"
      exit 1
      ;;
    esac
    shift
  done

  echo ""
  echo "╔════════════════════════════════════════════════════╗"
  echo "║    tms320c28x-re Dependency Update Script         ║"
  echo "╚════════════════════════════════════════════════════╝"
  echo ""

  if [[ $upgrade_mode == true ]]; then
    warn "⚠️  UPGRADE MODE ENABLED"
    warn "This will modify source files (rust/Cargo.toml)"
    warn "and may introduce breaking changes!"
    warn "Please review all changes and test thoroughly before committing."
    echo ""
  fi

  if [[ $update_all == true ]]; then
    update_nix || warn "Nix update failed"
    echo ""
    update_cargo "$upgrade_mode" || warn "Cargo update failed"
    echo ""
    update_python "$upgrade_mode" || warn "Python update failed"
  else
    if [[ $do_nix == true ]]; then
      update_nix || warn "Nix update failed"
    fi
    if [[ $do_cargo == true ]]; then
      update_cargo "$upgrade_mode" || warn "Cargo update failed"
    fi
    if [[ $do_python == true ]]; then
      update_python "$upgrade_mode" || warn "Python update failed"
    fi
    if [[ $do_binja == true ]]; then
      update_binja "$binja_ref" || warn "Binary Ninja re-pin failed"
    fi
    if [[ $do_ti == true ]]; then
      update_ti "$ti_version" || warn "TI CGT re-pin failed"
    fi
  fi

  if [[ $verify == true ]]; then
    echo ""
    verify_updates
  fi

  echo ""
  show_summary

  if [[ $upgrade_mode == true ]]; then
    echo ""
    warn "⚠️  REMINDER: UPGRADE MODE was used"
    warn "Please carefully review ALL changes and run the full test suite!"
  fi
}

main "$@"
