# SPDX-License-Identifier: MIT
#
# Built against the public binaryninja-api headers and stub core, never the
# consumer's install: a version bump must only stop the plugin loading, not fail
# their whole `nix build`. Section 13 of plan-lift-semantics.md has the detail.
{
  lib,
  stdenv,
  rustPlatform,
  fetchFromGitHub,
  cmake,
  ninja,
  python3,
  llvmPackages,
  glibc,
  src,
  version,
}:

let
  nativeName =
    if stdenv.hostPlatform.isDarwin then "libtms320c28x_binja.dylib" else "libtms320c28x_binja.so";

  apiSrc = fetchFromGitHub {
    owner = "Vector35";
    repo = "binaryninja-api";
    rev = "b6cdbaf9e8d2c0e3f4d688b24982377e9da1e02e"; # keep equal to rust/Cargo.lock
    hash = "sha256-hEm1EaSgvD75EIsr5UjkVFTMoVJWkUVv4QfDaDVVefA=";
  };
in
rustPlatform.buildRustPackage {
  pname = "tms320c28x-binja";
  inherit src version;

  # src is the whole tree: core/c28x-core/build.rs reads ../../isa.
  cargoRoot = "rust";
  buildAndTestSubdir = "rust";
  cargoLock = {
    lockFile = ../rust/Cargo.lock;
    outputHashes."binaryninja-0.1.0" = "sha256-Bm8SsV7+/eX4eadZbxgUB3X4FOgWvS3Cec/EY8vzIWc=";
  };

  # The default `bn-link` feature links the real core; this builds the stub.
  buildNoDefaultFeatures = true;

  nativeBuildInputs = [
    cmake
    ninja
    python3
  ];
  # Otherwise ninja's hook takes buildPhase away from buildRustPackage.
  dontUseCmakeConfigure = true;
  dontUseNinjaBuild = true;

  # build.rs reads these from the API repo root; cargo vendor flattens it away.
  postPatch = ''
    mkdir -p "$NIX_BUILD_TOP/ui"
    cp ${apiSrc}/binaryninjacore.h "$NIX_BUILD_TOP/binaryninjacore.h"
    cp ${apiSrc}/ui/uitypes.h "$NIX_BUILD_TOP/ui/uitypes.h"
    cp -r ${apiSrc}/stubs "$NIX_BUILD_TOP/stubs"
    chmod -R u+w "$NIX_BUILD_TOP/stubs"
  '';

  LIBCLANG_PATH = "${llvmPackages.libclang.lib}/lib";
  BINDGEN_EXTRA_CLANG_ARGS =
    "-isystem ${llvmPackages.libcxx.dev}/include/c++/v1 -isystem ${glibc.dev}/include";

  # The stub's CMakeLists installs the library over itself; DESTDIR redirects it.
  preBuild = ''
    export DESTDIR="$NIX_BUILD_TOP/destdir"
    mkdir -p "$DESTDIR"
  '';

  # The Rust tests need a licence and the built fixtures; `nix run .#tests` does.
  doCheck = false;

  # $out IS the plugin directory Binary Ninja loads.
  installPhase = ''
    runHook preInstall
    mkdir -p $out
    cp "target/${stdenv.hostPlatform.rust.cargoShortTarget}/release/${nativeName}" $out/ 2>/dev/null \
      || cp "target/release/${nativeName}" $out/
    cp ${src}/binja/*.py ${src}/binja/plugin.json $out/
    runHook postInstall
  '';

  # Binary Ninja already holds libbinaryninjacore.so.1 open when it dlopens a
  # plugin; an rpath here would pin the plugin to one installation.
  postFixup = lib.optionalString stdenv.hostPlatform.isLinux ''
    patchelf --remove-rpath "$out/${nativeName}"
  '';

  meta = {
    description = "TMS320C28x architecture plugin for Binary Ninja";
    homepage = "https://github.com/brianmcgillion/tms320c28x-re";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux ++ lib.platforms.darwin;
  };
}
