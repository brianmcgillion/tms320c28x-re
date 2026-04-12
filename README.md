# TMS320C28x Binary Ninja Plugin

Architecture plugin for reverse engineering TI TMS320C28x (C2000) DSP firmware in Binary Ninja.

## Features

- **401 instructions** — full ISA decode based on TI SPRU430F
- **97% LLIL lifting** — arithmetic, moves, branches, FPU, multiply-accumulate, bit manipulation, I/O
- **HLIL decompilation** — proper flag-based condition synthesis, no `cond:0` artifacts
- **BinaryView plugins** — TI ELF (word→byte), TI COFF, raw flash images (F28335)
- **F28335 memory map** — peripheral register labels, PIE vector table, erased sector detection
- **Analysis tools** — false function cleanup, pointer table scanning, inline data detection

## Installation

### From GitHub Release (recommended)

1. Download the latest release for your platform from [Releases](../../releases)
2. Extract the `tms320c28x/` folder to your Binary Ninja plugins directory:
   - **Linux**: `~/.binaryninja/plugins/`
   - **macOS**: `~/Library/Application Support/Binary Ninja/plugins/`
   - **Windows**: `%APPDATA%\Binary Ninja\plugins\`
3. Restart Binary Ninja

### From Source

```bash
git clone https://github.com/brianmcgillion/tms320c28x-re.git
cd tms320c28x-re

# Build the Rust native plugin
cargo build --release --manifest-path rust/Cargo.toml

# Install to Binary Ninja
ln -s $(pwd)/binja ~/.binaryninja/plugins/tms320c28x
cp rust/target/release/libtms320c28x_binja.so ~/.binaryninja/plugins/tms320c28x/
```

## Usage

### Loading Binaries

Open any C28x binary in BN — the plugin auto-detects:
- **ELF** (`.out` from cl2000 with `--abi=eabi`) — word→byte address conversion handled automatically
- **COFF** (`.out` from cl2000 legacy) — TI COFF2 format parsed natively
- **Raw flash** (`.bin`) — F28335 flash dump with full memory map

### Analysis Workflow (Flash)

After loading a raw flash binary, run from the **Plugins** menu:
1. `TMS320C28x > Remove False Functions` — removes false positives from 0xFF padding
2. `TMS320C28x > Find Functions from PIE Table` — discovers ISR handlers
3. `TMS320C28x > Mark Inline Data` — identifies data tables between functions

## Architecture

```
rust/           Rust native plugin (decoder, lifter, architecture registration)
binja/          Python BinaryView plugins (ELF, COFF, flash, analysis tools)
isa/            YAML ISA definitions (instruction opcodes, operands, semantics)
c28x/           Pure-Python decoder library (no BN dependency)
tests/          Test suite with 28 test binaries + flash fixture
scripts/        Validation scripts (434 functional equivalence checks)
```

The core architecture (instruction decoding, IL lifting, calling convention) is implemented in **Rust** for performance. Python provides BinaryView plugins for format-specific loading and analysis tools.

## Supported Devices

- TMS320F28335 / F28334 / F28333 / F28332
- TMS320F28004x family
- Any C28x-core device (decoder is ISA-generic)

## Development

```bash
# NixOS (recommended): provides all dependencies
nix develop
bash scripts/run_all_tests.sh

# Manual: requires Rust, Python 3.10+, cl2000, Binary Ninja
pip install -e ".[dev]"
cargo build --release --manifest-path rust/Cargo.toml
pytest tests/ -x -q --ignore=tests/test_firmware_bn.py --ignore=tests/test_pmsm_bn.py
```

## References

- [TMS320C28x CPU and Instruction Set Reference (SPRU430F)](https://www.ti.com/lit/ug/spru430f/spru430f.pdf)
- [Idaho National Lab bn-tic28x-arch](https://github.com/idaholab/bn-tic28x-arch) — C++ BN plugin (MIT, opcode tables referenced)
- [Binary Ninja Architecture Plugin Guide](https://binary.ninja/2020/01/08/guide-to-architecture-plugins-part1.html)

## License

MIT — see [LICENSE](LICENSE).

Opcode encoding values reference [idaholab/bn-tic28x-arch](https://github.com/idaholab/bn-tic28x-arch) (MIT License, Copyright Battelle Energy Alliance, LLC).
