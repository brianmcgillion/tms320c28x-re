# TMS320C28x Reverse Engineering Tools

Shared ISA description and tooling for reverse engineering TI TMS320C28x (C2000) firmware, with plugin support for Binary Ninja and Ghidra.

## Architecture

```
isa/            Shared YAML ISA descriptions (registers, flags, instructions)
c28x/           Pure-Python decoder library (no tool dependencies)
binja/          Binary Ninja architecture plugin
ghidra/         Future: SLEIGH processor module generator
```

The core ISA description in `isa/` is tool-neutral YAML. The `c28x/` Python library consumes these definitions to provide instruction decoding. Tool-specific plugins (`binja/`, `ghidra/`) wrap the shared library with their respective APIs.

## Binary Ninja Plugin

### Installation

Symlink the `binja/` directory into your Binary Ninja plugins folder:

```bash
ln -s $(pwd)/binja ~/.binaryninja/plugins/tms320c28x
```

### Status

- [x] Instruction disassembly (365 instructions, 100% decode on real firmware)
- [x] IL lifting (arithmetic, moves, branches, stack ops; DSP multiply/FPU use nop placeholders)
- [x] TI COFF parser and BinaryView (open `.out` files directly in BN)
- [ ] Ghidra SLEIGH generation

## Development

```bash
pip install -e ".[dev]"
pytest
```

## References

- [TMS320C28x CPU and Instruction Set Reference (SPRU430F)](https://www.ti.com/lit/ug/spru430f/spru430f.pdf)
- [Idaho National Lab bn-tic28x-arch](https://github.com/idaholab/bn-tic28x-arch) — C++ BN plugin with complete disassembly (MIT, opcode tables referenced)
- [Binary Ninja Architecture Plugin Guide](https://binary.ninja/2020/01/08/guide-to-architecture-plugins-part1.html)

## License

MIT — see [LICENSE](LICENSE).

Opcode encoding values reference [idaholab/bn-tic28x-arch](https://github.com/idaholab/bn-tic28x-arch) (MIT License, Copyright Battelle Energy Alliance, LLC).
