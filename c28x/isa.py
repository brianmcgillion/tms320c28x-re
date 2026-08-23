# SPDX-License-Identifier: MIT
"""YAML ISA loader — builds instruction lookup tables from isa/ definitions."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass
class InstructionDef:
    """A single instruction definition loaded from YAML."""
    name: str
    full_name: str
    format: int            # 16 or 32 (instruction size in bits)
    opcode: int
    mask: int
    objmode: int | None    # None = any, 0 = C27x, 1 = C28x
    operands: list[dict]
    semantics: dict

    @property
    def size_bytes(self) -> int:
        return self.format // 8


@dataclass
class ConditionDef:
    """Branch condition code definition."""
    code: int
    name: str
    flag_test: dict | None


class ISA:
    """Loaded ISA definitions with indexed lookup tables."""

    def __init__(self, isa_dir: Path | None = None):
        if isa_dir is None:
            # In a repo checkout the YAML lives at <repo>/isa, alongside c28x/.
            # It has to stay there: rust/build.rs reads ../isa/instructions at
            # build time. When installed as a package that path does not exist
            # (it would resolve to site-packages/isa), so the Nix derivation
            # drops a copy inside the package and we fall back to it.
            isa_dir = Path(__file__).parent.parent / "isa"
            if not isa_dir.is_dir():
                isa_dir = Path(__file__).parent / "isa"
        self.isa_dir = isa_dir

        self.instructions_16: list[InstructionDef] = []
        self.instructions_32: list[InstructionDef] = []
        self.conditions: dict[int, ConditionDef] = {}
        self.registers: dict = {}
        self.flags: dict = {}

        self._load()

    def _load(self) -> None:
        self._load_registers()
        self._load_flags()
        self._load_conditions()
        self._load_instructions()

    def _load_registers(self) -> None:
        path = self.isa_dir / "registers.yaml"
        if path.exists():
            with open(path) as f:
                self.registers = yaml.safe_load(f).get("registers", {})

    def _load_flags(self) -> None:
        path = self.isa_dir / "flags.yaml"
        if path.exists():
            with open(path) as f:
                data = yaml.safe_load(f)
                self.flags = {
                    "st0": data.get("st0_flags", {}),
                    "st1": data.get("st1_flags", {}),
                }

    def _load_conditions(self) -> None:
        path = self.isa_dir / "conditions.yaml"
        if path.exists():
            with open(path) as f:
                data = yaml.safe_load(f)
                for cond in data.get("conditions", []):
                    self.conditions[cond["code"]] = ConditionDef(
                        code=cond["code"],
                        name=cond["name"],
                        flag_test=cond.get("flag_test"),
                    )

    def _load_instructions(self) -> None:
        instr_dir = self.isa_dir / "instructions"
        if not instr_dir.exists():
            return

        for yaml_file in sorted(instr_dir.glob("*.yaml")):
            with open(yaml_file) as f:
                data = yaml.safe_load(f)
                for entry in data.get("instructions", []):
                    idef = InstructionDef(
                        name=entry["name"],
                        full_name=entry.get("full_name", ""),
                        format=entry.get("format", 16),
                        opcode=entry["opcode"],
                        mask=entry["mask"],
                        objmode=entry.get("objmode"),
                        operands=entry.get("operands", []),
                        semantics=entry.get("semantics", {}),
                    )
                    if idef.format == 16:
                        self.instructions_16.append(idef)
                    else:
                        self.instructions_32.append(idef)

        # Sort by mask specificity (more bits set = more specific = try first)
        self.instructions_16.sort(key=lambda i: bin(i.mask).count("1"), reverse=True)
        self.instructions_32.sort(key=lambda i: bin(i.mask).count("1"), reverse=True)
