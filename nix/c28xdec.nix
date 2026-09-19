# SPDX-License-Identifier: MIT
#
# The decoder CLI -- the one real instruction table. `c28x_rs.py` drives it.
{
  lib,
  rustPlatform,
  src,
  version,
}:

rustPlatform.buildRustPackage {
  pname = "c28xdec";
  inherit src version;

  # cargoRoot as well as buildAndTestSubdir: the vendor hook looks for
  # Cargo.lock relative to the source root, and ours is in core/.
  cargoRoot = "core";
  buildAndTestSubdir = "core";
  cargoLock.lockFile = ../core/Cargo.lock;

  # src is the whole tree: build.rs reads ../../isa/instructions.
  meta = {
    description = "TMS320C28x decoder CLI: NDJSON disassembly, COFF parsing, addressing tables";
    homepage = "https://github.com/brianmcgillion/tms320c28x-re";
    license = lib.licenses.mit;
    mainProgram = "c28xdec";
  };
}
