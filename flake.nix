{
  description = "TMS320C28x reverse engineering tools";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

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
      # Consumers get `python3Packages.c28x` built against *their* interpreter.
      #
      # A pythonPackagesExtensions entry rather than a plain `packages` output
      # on purpose: this flake pins its own nixpkgs, so a package built here
      # would land in some other python3.X/site-packages and simply not be on
      # the consumer's PYTHONPATH — an import that vanishes rather than fails.
      overlays.default = _final: prev: {
        pythonPackagesExtensions = (prev.pythonPackagesExtensions or [ ]) ++ [
          (pyfinal: _pyprev: {
            c28x = pyfinal.buildPythonPackage {
              # pname must match the distribution in pyproject.toml or the
              # metadata check fails; the attribute and importable module are
              # both `c28x`.
              pname = "tms320c28x-re";
              version = "0.1.0";
              pyproject = true;

              src = self;

              build-system = [ pyfinal.setuptools ];
              dependencies = [ pyfinal.pyyaml ];

              # pyproject.toml packages only `c28x*`, and isa/ has to stay at
              # the repo root for rust/build.rs. Install a copy beside the
              # module so the fallback in c28x/isa.py finds it.
              postInstall = ''
                cp -r isa "$out/${pyfinal.python.sitePackages}/c28x/isa"
              '';

              pythonImportsCheck = [
                "c28x"
                "c28x.decoder"
              ];

              meta = {
                description = "TMS320C28x ISA decoder and COFF reader";
                homepage = "https://github.com/brianmcgillion/tms320c28x-re";
                license = nixpkgs.lib.licenses.mit;
              };
            };
          })
        ];
      };

      # nix run .#tests — full test suite (run from repo root)
      apps = forAllSystems (pkgs: {
        tests = {
          type = "app";
          program = let
            testScript = pkgs.writeShellScript "run-tests" ''
              export PATH="${pkgs.lib.makeBinPath (with pkgs; [
                rustc cargo patchelf python313 uv git coreutils
              ] ++ pkgs.lib.optionals (pkgs.stdenv.isLinux && pkgs.stdenv.isx86_64) [
                (ti-cgt-c2000 { inherit pkgs; })
              ])}:$PATH"
              export LIBCLANG_PATH="${pkgs.llvmPackages.libclang.lib}/lib"
              export BINDGEN_EXTRA_CLANG_ARGS="-isystem ${pkgs.llvmPackages.libcxx.dev}/include/c++/v1 -isystem ${pkgs.glibc.dev}/include"
              export CARGO_BUILD_RUSTFLAGS="-C link-arg=-L${pkgs.glibc}/lib"

              # Auto-detect BN from system PATH (not from nix — BN is impure)
              for p in $(echo "$ORIGINAL_PATH" | tr ':' ' ') /usr/bin /usr/local/bin; do
                if [ -x "$p/binaryninja" ]; then
                  _bn_real="$(readlink -f "$p/binaryninja")"
                  _bn_prefix="$(dirname "$(dirname "$_bn_real")")"
                  export BINARYNINJADIR="$_bn_prefix/opt/binaryninja"
                  export PATH="$p:$PATH"
                  break
                fi
              done

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

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            # Python
            python313
            uv

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
          ] ++ pkgs.lib.optionals (pkgs.stdenv.isLinux && pkgs.stdenv.isx86_64) [
            # TI C2000 cross-compiler (x86_64-linux only)
            (ti-cgt-c2000 { inherit pkgs; })
          ];

          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          BINDGEN_EXTRA_CLANG_ARGS = "-isystem ${pkgs.llvmPackages.libcxx.dev}/include/c++/v1 -isystem ${pkgs.glibc.dev}/include";

          # Ensure Cargo build scripts can link against glibc on NixOS.
          # Without this, `cargo clean && cargo build` fails with
          # "DSO missing from command line" because rustc's linker
          # invocation for build-script binaries doesn't go through
          # the NixOS cc-wrapper.
          CARGO_BUILD_RUSTFLAGS = "-C link-arg=-L${pkgs.glibc}/lib";

          shellHook = ''
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
