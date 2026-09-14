# SPDX-License-Identifier: MIT
"""The Rust decoder, with the API the deleted Python `c28x` package had.

There were two decoders generated from the same YAML and nothing compared them,
so the Python one could drift without anything noticing. This keeps one
implementation -- `c28x_core` -- and reaches it through the `c28xdec` CLI.

Transport is a persistent `c28xdec decode` subprocess speaking NDJSON, one line
in and one line out. Not PyO3 (a wheel matrix and an ABI to keep in step), not
ctypes (a hand-written C ABI over `repr(Rust)` structs is a segfault waiting to
happen). The CLI has to exist anyway for the dis2000 differential and the
addressing-table probes, so this adds no build step that was not already there.

Lives at the repo root rather than under `tests/` because `scripts/` needs it
too: validate_functional.py, validate_c2000ware.py, probe_mnemonics.py,
probe_operands.py and validate_decode_vs_dis.py all imported `c28x`.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum, auto

ROOT = os.path.dirname(os.path.abspath(__file__))


# ── Types, mirroring the package this replaces ──────────────────────────────


class OperandType(Enum):
    REGISTER = auto()
    IMMEDIATE = auto()
    LOC16 = auto()
    LOC32 = auto()
    CONDITION = auto()
    MEMORY = auto()


class BranchType(Enum):
    NONE = auto()
    UNCONDITIONAL = auto()
    CONDITIONAL_TRUE = auto()
    CONDITIONAL_FALSE = auto()
    CALL = auto()
    RETURN = auto()
    TRAP = auto()
    # Not in the Python package: ESTOP0/ESTOP1, which terminate a block.
    HALT = auto()


class AddressingMode(Enum):
    DP_DIRECT = auto()
    SP_RELATIVE = auto()
    INDIRECT = auto()
    INDIRECT_POST_INC = auto()
    INDIRECT_PRE_DEC = auto()
    INDIRECT_AR0 = auto()
    INDIRECT_AR1 = auto()
    REGISTER_DIRECT = auto()
    ARP_INDIRECT = auto()


def _snake(camel: str) -> str:
    """`IndirectPostInc` -> `INDIRECT_POST_INC`, and `Ar0` -> `AR0` not `AR_0`."""
    out = []
    for i, ch in enumerate(camel):
        if ch.isupper() and i and not camel[i - 1].isdigit():
            out.append("_")
        out.append(ch.upper())
    return "".join(out)


_BRANCH = {m.name: m for m in BranchType}
_OPTYPE = {m.name: m for m in OperandType}
_MODE = {m.name: m for m in AddressingMode}


@dataclass
class ResolvedOperand:
    mode: AddressingMode
    text: str
    register: str | None = None
    xar_index: int | None = None
    offset: int = 0


@dataclass
class Operand:
    type: OperandType
    value: int = 0
    name: str = ""
    size: int = 2
    signed: bool = False
    resolved: ResolvedOperand | None = None


@dataclass
class DecodedInstruction:
    name: str
    yaml_name: str = ""
    full_name: str = ""
    size: int = 2
    operands: list[Operand] = field(default_factory=list)
    opcode: int = 0
    branch_type: BranchType = BranchType.NONE
    branch_target: int | None = None
    flags_written: list[str] = field(default_factory=list)
    semantics: dict = field(default_factory=dict)
    text: str = ""

    @property
    def is_branch(self) -> bool:
        return self.branch_type is not BranchType.NONE

    @property
    def is_call(self) -> bool:
        return self.branch_type is BranchType.CALL

    @property
    def is_return(self) -> bool:
        return self.branch_type is BranchType.RETURN


# ── Locating c28xdec ────────────────────────────────────────────────────────


def _refuse_if_stale(binary: str) -> None:
    """Fail loudly if the ISA table is newer than the binary that encodes it.

    build.rs compiles isa/ in, so a binary built before an edit still answers
    for the old table. It also survives a *failed* rebuild, which is the nastier
    case: `cargo build` panics on a malformed table, the previous binary is
    still on disk, and every caller carries on decoding against it. A golden
    transcript then agrees with itself and proves nothing.
    """
    isa = os.path.join(ROOT, "isa")
    if not os.path.isdir(isa):
        return
    # isa/reference/ is transcribed FROM the TI manuals, not compiled INTO the
    # binary -- build.rs reads only isa/instructions/, registers.yaml and
    # flags.yaml. Counting it made regenerating the transcription look like a
    # stale table, and cargo had nothing to rebuild, so the two never converged.
    skip = os.path.join(isa, "reference")
    newest = max(
        (
            os.path.getmtime(os.path.join(d, f))
            for d, _, fs in os.walk(isa)
            if not d.startswith(skip)
            for f in fs
            if f.endswith((".yaml", ".tsv"))
        ),
        default=0.0,
    )
    if newest > os.path.getmtime(binary):
        raise RuntimeError(
            f"{binary} is older than isa/. It encodes a stale table -- and if "
            "your last `cargo build` failed, this is the binary that silently "
            "answered anyway. Rebuild: "
            "cargo build --release --manifest-path core/Cargo.toml"
        )


def c28xdec_path() -> str:
    """$C28XDEC, else the newest local build, else $PATH, else build it.

    Newest wins rather than first: a stale debug binary silently shadowing a
    fresh release one is how a differential once reported 27,195 of 43,238
    instructions and called it success.
    """
    env = os.environ.get("C28XDEC")
    if env and os.path.exists(env):
        return env
    candidates = [
        os.path.join(ROOT, "core", "target", p, "c28xdec") for p in ("release", "debug")
    ]
    present = [c for c in candidates if os.path.exists(c)]
    if present:
        newest = max(present, key=os.path.getmtime)
        _refuse_if_stale(newest)
        return newest
    found = shutil.which("c28xdec")
    if found:
        return found
    if shutil.which("cargo"):
        subprocess.run(
            [
                "cargo",
                "build",
                "--release",
                "--manifest-path",
                os.path.join(ROOT, "core", "Cargo.toml"),
            ],
            check=True,
        )
        built = os.path.join(ROOT, "core", "target", "release", "c28xdec")
        if os.path.exists(built):
            return built
    raise RuntimeError(
        "c28xdec not found and could not be built. This is the decoder under "
        "test, so there is nothing to fall back to: build it with "
        "`cargo build --release --manifest-path core/Cargo.toml`."
    )


# ── Decoder ────────────────────────────────────────────────────────────────


class Decoder:
    """One persistent `c28xdec decode` subprocess.

    `isa_dir` is accepted and ignored: the Rust table is generated at build
    time by core/c28x-core/build.rs, so there is no runtime table to point
    elsewhere. It was only ever used to decode against a scratch copy of isa/.
    """

    def __init__(self, objmode: int = 1, isa_dir=None):
        self.objmode = objmode
        self._proc = None

    def _pipe(self):
        if self._proc is None or self._proc.poll() is not None:
            self._proc = subprocess.Popen(
                [c28xdec_path(), "decode", "--objmode", str(self.objmode)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        return self._proc

    def decode(self, data: bytes, addr: int = 0) -> DecodedInstruction | None:
        if len(data) < 2:
            return None
        words = len(data) // 2
        hexwords = "".join(
            f"{data[2 * i + 1]:02x}{data[2 * i]:02x}" for i in range(words)
        )
        p = self._pipe()
        p.stdin.write(f"{addr:x}:{hexwords}\n")
        p.stdin.flush()
        line = p.stdout.readline()
        if not line:
            raise RuntimeError("c28xdec closed its pipe mid-session")
        return _instruction(json.loads(line))

    def close(self):
        if self._proc is not None and self._proc.poll() is None:
            self._proc.stdin.close()
            self._proc.wait(timeout=5)
        self._proc = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


def _instruction(d: dict) -> DecodedInstruction | None:
    if d.get("yaml_name") is None:
        return None
    return DecodedInstruction(
        name=d["name"],
        yaml_name=d["yaml_name"],
        size=d["size"],
        opcode=d["opcode"],
        branch_type=_BRANCH[_snake(d["branch_type"])],
        branch_target=d["branch_target"],
        text=d.get("text", ""),
        operands=[_operand(o) for o in d["operands"]],
    )


def _operand(o: dict) -> Operand:
    resolved = None
    if "mode" in o:
        resolved = ResolvedOperand(
            mode=_MODE[_snake(o["mode"])],
            text=o["text"],
            register=o["name"] if o["mode"] == "RegisterDirect" else None,
            xar_index=o.get("xar"),
            offset=o.get("offset", 0),
        )
    return Operand(
        type=_OPTYPE[_snake(o["type"])],
        value=o["value"],
        name=o["name"],
        size=o["size"],
        signed=o["signed"],
        resolved=resolved,
    )


# ── loc16 / loc32 addressing ───────────────────────────────────────────────

_LOC_TABLES: dict[int, list[ResolvedOperand]] = {}


def _loc_table(width: int) -> list[ResolvedOperand]:
    """All 256 fields in one call — the CLI emits the whole table anyway."""
    if width not in _LOC_TABLES:
        out = subprocess.run(
            [c28xdec_path(), f"loc{width}"], capture_output=True, text=True, check=True
        ).stdout
        rows = [json.loads(line) for line in out.splitlines() if line.strip()]
        _LOC_TABLES[width] = [
            ResolvedOperand(
                mode=_MODE[_snake(r["mode"])],
                text=r["text"],
                register=r["register"],
                xar_index=r["xar_index"],
                offset=r["offset"],
            )
            for r in rows
        ]
    return _LOC_TABLES[width]


def decode_loc16(field: int) -> ResolvedOperand:
    return _loc_table(16)[field & 0xFF]


def decode_loc32(field: int) -> ResolvedOperand:
    return _loc_table(32)[field & 0xFF]


# ── COFF ───────────────────────────────────────────────────────────────────


@dataclass
class Section:
    name: str
    phys_addr: int
    virt_addr: int
    size: int
    data_offset: int
    flags: int
    data: bytes
    is_text: bool
    is_data: bool
    is_bss: bool
    byte_addr: int


@dataclass
class Symbol:
    name: str
    value: int
    section_num: int
    storage_class: int
    byte_addr: int
    is_function: bool


@dataclass
class CoffFile:
    sections: list[Section] = field(default_factory=list)
    symbols: list[Symbol] = field(default_factory=list)

    @property
    def text_sections(self) -> list[Section]:
        return [s for s in self.sections if s.is_text]

    def get_symbol(self, name: str) -> Symbol | None:
        return next((s for s in self.symbols if s.name == name), None)

    def get_functions(self) -> list[Symbol]:
        """Symbols that are likely functions: external, in .text, non-zero."""
        text_nums = {i + 1 for i, s in enumerate(self.sections) if s.is_text}
        return [
            s
            for s in self.symbols
            if s.is_function and s.section_num in text_nums and s.value != 0
        ]

    def read_at(self, word_addr: int, num_bytes: int) -> bytes | None:
        """Bytes from the loaded image at a word address, or None if unmapped."""
        for section in self.sections:
            sec_end = section.phys_addr + len(section.data) // 2
            if section.phys_addr <= word_addr < sec_end:
                byte_offset = (word_addr - section.phys_addr) * 2
                return section.data[byte_offset : byte_offset + num_bytes]
        return None

    def extract_flat_binary(self) -> tuple[bytes, int]:
        """Every .text section in one blob, plus its base word address.

        Byte offset for a word address is (word_addr - base) * 2.
        """
        text = self.text_sections
        if not text:
            return b"", 0
        base = min(s.phys_addr for s in text)
        end = max(s.phys_addr + len(s.data) // 2 for s in text)
        buf = bytearray((end - base) * 2)
        for s in text:
            off = (s.phys_addr - base) * 2
            buf[off : off + len(s.data)] = s.data
        return bytes(buf), base


def parse_coff(path) -> CoffFile:
    r = subprocess.run(
        [c28xdec_path(), "coff", str(path)], capture_output=True, text=True
    )
    d = json.loads(r.stdout or '{"error":"c28xdec produced no output"}')
    if "error" in d:
        raise ValueError(d["error"])
    return CoffFile(
        sections=[
            Section(
                name=s["name"],
                phys_addr=s["phys_addr"],
                virt_addr=s["virt_addr"],
                size=s["size"],
                data_offset=s["data_offset"],
                flags=s["flags"],
                data=bytes.fromhex(s["data"]),
                is_text=s["is_text"],
                is_data=s["is_data"],
                is_bss=s["is_bss"],
                byte_addr=s["byte_addr"],
            )
            for s in d["sections"]
        ],
        symbols=[
            Symbol(
                name=s["name"],
                value=s["value"],
                section_num=s["section_num"],
                storage_class=s["storage_class"],
                byte_addr=s["byte_addr"],
                is_function=s["is_function"],
            )
            for s in d["symbols"]
        ],
    )


# ── Byte/word helpers ──────────────────────────────────────────────────────
#
# Pure Python on purpose: four lines of shifting, and routing them through a
# subprocess would buy nothing.


def bytes_to_opcode16(data: bytes) -> int:
    """2 bytes to a 16-bit opcode (little-endian word)."""
    return data[1] << 8 | data[0]


def bytes_to_opcode32(data: bytes) -> int:
    """4 bytes to a 32-bit opcode; the first word in memory is the HIGH half."""
    return (data[1] << 24) | (data[0] << 16) | (data[3] << 8) | data[2]


def sign_extend(value: int, bits: int) -> int:
    sign_bit = 1 << (bits - 1)
    return (value ^ sign_bit) - sign_bit


def extract_bits(value: int, high: int, low: int) -> int:
    return (value >> low) & ((1 << (high - low + 1)) - 1)
