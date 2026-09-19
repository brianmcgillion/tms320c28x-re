{
  description = "TMS320C28x reverse engineering tools";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      version = "0.2.0";

      # TI C2000 Code Generation Tools (cl2000 compiler) — x86_64-linux only
      ti-cgt-c2000 = { pkgs }: pkgs.stdenv.mkDerivation rec {
        pname = "ti-cgt-c2000";
        version = "22.6.3.LTS";
        src = pkgs.fetchurl {
          url = "https://dr-download.ti.com/software-development/ide-configuration-compiler-or-debugger/MD-xqxJ05PLfM/${version}/ti_cgt_c2000_${version}_linux-x64_installer.bin";
          hash = "sha256-9mUf4hVzxWSVccrDTMBxnwELQ+a9ZARc3xV9zmMWZ+U=";
        };
        nativeBuildInputs = [ pkgs.autoPatchelfHook ];
        buildInputs = [ pkgs.stdenv.cc.cc.lib pkgs.ncurses ];
        dontUnpack = true;
        installPhase = ''
          # Patch the installer's ELF interpreter so it can run in the nix sandbox
          install -m755 $src $TMPDIR/installer.bin
          patchelf --set-interpreter "$(cat $NIX_CC/nix-support/dynamic-linker)" $TMPDIR/installer.bin
          $TMPDIR/installer.bin --mode unattended --prefix $TMPDIR/cgt
          # Flatten: move from cgt/ti-cgt-c2000_VERSION/* to $out/*
          mkdir -p $out
          mv $TMPDIR/cgt/ti-cgt-c2000_${version}/* $out/
        '';
        meta = {
          description = "TI C2000 Code Generation Tools (cl2000 cross-compiler)";
          homepage = "https://www.ti.com/tool/C2000-CGT";
          platforms = [ "x86_64-linux" ];
        };
      };
    in
    {
      # Attribute `c28x`, distribution `tms320c28x-re`, module `c28x_rs`.
      overlays.default = final: prev: {
        c28xdec = final.callPackage ./nix/c28xdec.nix { src = self; inherit version; };

        tms320c28x-binja = final.callPackage ./nix/plugin.nix {
          src = self;
          inherit version;
        };

        pythonPackagesExtensions = (prev.pythonPackagesExtensions or [ ]) ++ [
          (pyfinal: _pyprev: {
            c28x = pyfinal.callPackage ./nix/python.nix {
              src = self;
              inherit version;
              inherit (final) c28xdec;
            };
          })
        ];
      };

      homeModules.default = import ./nix/home-module.nix { inherit self version; };

      packages = forAllSystems (pkgs: rec {
        default = c28xdec;
        c28xdec = pkgs.callPackage ./nix/c28xdec.nix { src = self; inherit version; };
        tms320c28x-binja = pkgs.callPackage ./nix/plugin.nix { src = self; inherit version; };
      });

      # nix run .#tests — full test suite (run from repo root)
      apps = forAllSystems (pkgs: {
        tests = {
          type = "app";
          program = let
            testScript = pkgs.writeShellScript "run-tests" ''
              export PATH="${pkgs.lib.makeBinPath (with pkgs; [
                # scripts/validate_functional.py and friends import yaml; the
                # devShell gets it from .venv, this app has no .venv.
                rustc cargo patchelf (python3.withPackages (ps: [ ps.pyyaml ])) uv git coreutils
                # cmake + ninja for the REQUIRED stub-link stage: binaryninjacore-sys
                # builds its stub library with them, and that is the only link smoke
                # over arch.rs and the lifter that needs no licence.
                cmake ninja
              ] ++ pkgs.lib.optionals
                (pkgs.stdenv.hostPlatform.isLinux && pkgs.stdenv.hostPlatform.isx86_64) [
                (ti-cgt-c2000 { inherit pkgs; })
              ])}:$PATH"
              export LIBCLANG_PATH="${pkgs.llvmPackages.libclang.lib}/lib"
              export BINDGEN_EXTRA_CLANG_ARGS="-isystem ${pkgs.llvmPackages.libcxx.dev}/include/c++/v1 -isystem ${pkgs.glibc.dev}/include"
              export CARGO_BUILD_RUSTFLAGS="-C link-arg=-L${pkgs.glibc}/lib"

              exec ${./scripts/run_all_tests.sh}
            '';
          in "${testScript}";
        };

        # nix run .#update-deps -- [OPTIONS] — bump dependency pins
        update-deps = {
          type = "app";
          program = let
            updateScript = pkgs.writeShellScript "update-deps" ''
              # Appended (not prepended) so the caller's `nix` stays reachable —
              # `nix flake update` cannot run without it.
              export PATH="$PATH:${pkgs.lib.makeBinPath (with pkgs; [
                cargo cargo-edit uv git jq gnused coreutils
              ])}"
              exec ${./scripts/update-deps.sh} "$@"
            '';
          in "${updateScript}";
        };
      });

      devShells = forAllSystems (pkgs: let
        # PATH only, never `packages`. As a package, nix appends its include/ to
        # NIX_CFLAGS_COMPILE and lib/ to NIX_LDFLAGS -- and those hold C28x
        # *target* headers and a C28x libc.a, which shadow glibc's. Every host C
        # compile in the shell then fails: `gcc` on a bare `int main(void){}`
        # dies on `undefined reference to __libc_start_main`. That also broke the
        # binaryninjacore stub build, and with it the only licence-free link
        # smoke over arch.rs and the lifter.
        tiCgt = pkgs.lib.optionals
          (pkgs.stdenv.hostPlatform.isLinux && pkgs.stdenv.hostPlatform.isx86_64)
          [ (ti-cgt-c2000 { inherit pkgs; }) ];
      in {
        default = pkgs.mkShell {
          packages = with pkgs; [
            # Python
            python3
            uv

            zip   # scripts/package.sh

            # Rust
            rustc
            cargo
            cargo-edit # provides `cargo upgrade` for scripts/update-deps.sh
            rust-analyzer
            clippy
            rustfmt
            pkg-config
            llvmPackages.libclang

            # Build tools (needed by binaryninjacore-sys stubs)
            cmake
            ninja

            # Dependency tooling (scripts/update-deps.sh)
            jq

            # LSP servers
            basedpyright # type checking + completions
            ruff # linting + formatting (includes ruff server)
            semgrep # security/SAST analysis (includes semgrep lsp)
          ];

          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          BINDGEN_EXTRA_CLANG_ARGS = "-isystem ${pkgs.llvmPackages.libcxx.dev}/include/c++/v1 -isystem ${pkgs.glibc.dev}/include";

          # Ensure Cargo build scripts can link against glibc on NixOS.
          # Without this, `cargo clean && cargo build` fails with
          # "DSO missing from command line" because rustc's linker
          # invocation for build-script binaries doesn't go through
          # the NixOS cc-wrapper.
          #
          # POSSIBLY REDUNDANT since ti-cgt-c2000 left `packages` above: with it
          # unset, a clean `cargo build --release --manifest-path core/Cargo.toml`
          # -- build script and all -- now succeeds. The same shadowing that broke
          # every C compile is the likeliest original cause. Kept because that was
          # checked only for core/, and removing it is its own change.
          CARGO_BUILD_RUSTFLAGS = "-C link-arg=-L${pkgs.glibc}/lib";

          shellHook = pkgs.lib.optionalString (tiCgt != [ ]) ''
            # cl2000/asm2000/dis2000, on PATH and nothing more -- see tiCgt above.
            export PATH="${pkgs.lib.makeBinPath tiCgt}:$PATH"
          '' + ''
            # Auto-detect BINARYNINJADIR from PATH (needed by binaryninjacore-sys)
            if command -v binaryninja &>/dev/null && [ -z "''${BINARYNINJADIR:-}" ]; then
              _bn_real="$(readlink -f "$(which binaryninja)")"
              _bn_prefix="$(dirname "$(dirname "$_bn_real")")"
              export BINARYNINJADIR="$_bn_prefix/opt/binaryninja"
            fi

            # Activate venv if it exists, otherwise create it
            if [ ! -d .venv ]; then
              uv venv
            fi
            source .venv/bin/activate

            # Bump dependency pins from anywhere in the tree
            update-deps() {
              "$(git rev-parse --show-toplevel)/scripts/update-deps.sh" "$@"
            }
            # export so it survives into `nix develop -c bash ...` subshells
            export -f update-deps

            echo "Commands: update-deps [--help]  |  nix run .#tests"
          '';
        };
      });
    };
}
