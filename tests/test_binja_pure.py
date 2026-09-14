"""Tests for binja/ that need no Binary Ninja licence.

Regression coverage for the two crashers in the pointer-table scanners, both of
which abort init() and present to a user as "Binary Ninja won't open my
firmware".
"""

from __future__ import annotations

import ast
import os
import pathlib
import struct
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from tests.conftest_bn_stub import install as install_bn_stub

install_bn_stub()

from binja import tools  # noqa: E402


class _Segment:
    def __init__(self, start, end, readable=True, executable=False):
        self.start, self.end = start, end
        self.readable, self.executable = readable, executable


class _FakeBinaryView:
    """Two readable segments holding one pointer table each.

    get_segment_at returns None for every pointer target, which is the case that
    used to rebind the loop variable in _scan_pointer_tables.
    """

    CODE = 0x10000

    def __init__(self):
        self.segments = [_Segment(0x1000, 0x1040), _Segment(0x2000, 0x2040)]
        self.added = []

    def read(self, addr, length):
        if not any(s.start <= addr and addr + length <= s.end for s in self.segments):
            return b""
        # Every slot is a valid code pointer, so a run of >= 4 is always found.
        return struct.pack("<I", self.CODE // 2)

    def get_segment_at(self, addr):
        return None

    def add_function(self, addr):
        self.added.append(addr)


def test_scan_pointer_tables_does_not_rebind_the_segment_loop():
    """Regression: `seg = bv.get_segment_at(...)` clobbered the iterated segment.

    After the first table, the enclosing `while offset + 15 < seg.end` read the
    target segment's bound -- or raised AttributeError when it was None. Fails
    with AttributeError against the pre-fix tools.py.
    """
    task = tools.PIEFunctionTask.__new__(tools.PIEFunctionTask)
    bv = _FakeBinaryView()
    task._scan_pointer_tables(bv, bv.CODE, bv.CODE + 0x1000)


def test_scan_pointer_tables_survives_a_short_read():
    """Regression: the second read was unpacked without the guard the first has."""

    class _Truncating(_FakeBinaryView):
        def __init__(self):
            super().__init__()
            self._n = 0

        def read(self, addr, length):
            self._n += 1
            # Satisfy the scan loop, then truncate once the run is re-read.
            return b"" if self._n > 16 else super().read(addr, length)

    task = tools.PIEFunctionTask.__new__(tools.PIEFunctionTask)
    bv = _Truncating()
    task._scan_pointer_tables(bv, bv.CODE, bv.CODE + 0x1000)


def test_word_to_byte_conversion():
    assert tools._w2b(0) == 0
    assert tools._w2b(1) == 2
    assert tools._w2b(0x3FFFFF) == 0x7FFFFE


def _table(module_path, name):
    """Read a module-level list literal without importing the module.

    binja/flash.py subclasses BinaryView and registers itself at import time,
    which would need far more stubbing than these tables are worth.
    """
    tree = ast.parse(pathlib.Path(module_path).read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == name for t in node.targets
        ):
            return ast.literal_eval(node.value)
    raise AssertionError(f"{name} not found in {module_path}")


def _has_table(module_path, name):
    tree = ast.parse(pathlib.Path(module_path).read_text())
    return any(
        isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == name for t in node.targets)
        for node in tree.body
    )


@pytest.mark.parametrize("table", ["PERIPHERALS", "RAM_REGIONS"])
def test_memory_map_has_exactly_one_definition(table):
    """The F28335 map was carried twice, and had drifted.

    flash.py had XINTF and tools.py did not, so the plugin described different
    memory depending on which entry point the user reached it through. The two
    copies could not be extracted while the dev deploy flattened the package;
    now that it ships the `tms320c28x/` directory it does, they share
    binja/memmap.py, and this asserts nothing has grown a second copy.
    """
    defined_in = [
        p
        for p in ("binja/memmap.py", "binja/tools.py", "binja/flash.py")
        if _has_table(p, table)
    ]
    assert defined_in == ["binja/memmap.py"], f"{table} defined in {defined_in}"


def test_memory_map_is_sane():
    peripherals = _table("binja/memmap.py", "PERIPHERALS")
    ram = _table("binja/memmap.py", "RAM_REGIONS")

    names = [p[0] for p in peripherals]
    assert len(names) == len(set(names)), "duplicate peripheral names"

    spans = sorted((base, base + size, name) for name, base, size in peripherals)
    for (_, a_end, a_name), (b_start, _, b_name) in zip(spans, spans[1:]):
        assert a_end <= b_start, f"{a_name} overlaps {b_name}"

    for name, base, size in peripherals + ram:
        assert 0 <= base < 0x400000, f"{name} word base out of range"
        assert 0 < size <= 0x10000, f"{name} implausible size"


def test_prologue_pattern_matches_the_isa_table():
    """binja/patterns.py must not be a second opinion about the encoding.

    The constants were hardcoded in three places in binja/ and two more in
    scripts/, while isa/instructions/arithmetic.yaml already defined the row.
    They are literals in patterns.py so the shipped plugin need not parse YAML
    at import time; this is what keeps them honest.
    """
    import glob

    import yaml

    from binja import patterns

    repo = os.path.join(os.path.dirname(__file__), "..")
    rows = [
        i
        for f in sorted(glob.glob(os.path.join(repo, "isa/instructions/*.yaml")))
        for i in yaml.safe_load(open(f))["instructions"]
    ]
    addb_sp = next(r for r in rows if r["name"] == "ADDB_SP_CONST7")

    assert patterns.ADDB_SP_OPCODE == addb_sp["opcode"]
    assert patterns.ADDB_SP_MASK == addb_sp["mask"]
    assert patterns.is_function_prologue(addb_sp["opcode"])
    assert patterns.is_function_prologue(addb_sp["opcode"] | 0x7F)  # any #7bit
    assert not patterns.is_function_prologue(0x7700)  # NOP


@pytest.mark.parametrize(
    "addr,want",
    [
        (9, False),
        (10, True),
        (19, True),  # first range, boundaries
        (29, True),
        (30, False),  # merged with the overlapping one
        (50, False),  # the gap
        (100, True),
        (102, True),
        (104, False),  # second range
    ],
)
def test_covered_predicate(addr, want):
    """Replaces a set holding every 2-byte address of every basic block.

    ~256K integers for a 512KB image, to answer a question sorted intervals
    answer in log time. Overlapping ranges must merge, and `end` is exclusive.
    """
    covered = tools.covered_predicate([(10, 20), (18, 30), (100, 104)])
    assert covered(addr) is want


def test_covered_predicate_empty():
    assert tools.covered_predicate([])(0) is False


class _RawData:
    """Just enough BinaryView surface for is_valid_for_data."""

    def __init__(self, blob):
        self.blob = blob
        self.length = len(blob)

    def read(self, offset, count):
        return self.blob[offset : offset + count]


FLASH_BIN = os.path.join(
    os.path.dirname(__file__), "fixtures", "build", "flash_test.bin"
)


@pytest.mark.skipif(not os.path.exists(FLASH_BIN), reason="flash fixture not built")
def test_flash_view_claims_only_plausible_images():
    """It used to claim any file of 64KB+ with code-shaped bytes at 0x10000.

    The segment layout the view builds assumes the file covers flash from word
    0x300000, so a whole-device size is part of being a flash image --
    KNOWN_FLASH_SIZES was written down for this and never used. Code may also
    start in any sector, not only Flash G at the hardcoded offset.
    """
    from binja import flash

    blob = open(FLASH_BIN, "rb").read()
    claim = flash.TMS320C28xFlashView.is_valid_for_data

    assert claim(_RawData(blob))  # the real fixture
    assert not claim(_RawData(blob[:-2]))  # not a whole-device size
    assert not claim(_RawData(b"\xff" * len(blob)))  # fully erased: no code
    assert not claim(_RawData(b"\x00" * len(blob)))


def test_flash_sector_offsets_cover_the_image():
    """Every sector must land inside a 512KB image, or the scan misses code."""
    from binja import flash

    for name, word_base, size in flash.FLASH_SECTORS:
        offset = (word_base - flash.FLASH_H_WORD) * 2
        assert 0 <= offset < 512 * 1024, f"{name} at {offset:#x}"


# ── Release packaging ──────────────────────────────────────────────────────

PACKAGERS = [
    "scripts/package.sh",
    ".github/workflows/release.yml",
]


@pytest.mark.parametrize("packager", PACKAGERS)
def test_packaging_ships_every_binja_module(packager):
    """Every packaging path must copy binja/*.py by glob, not by a hand list.

    release.yml named six files and omitted memmap.py, patterns.py and
    dis_sidecar.py. flash.py and tools.py both `from .memmap import ...`, so
    every published archive raised ImportError the moment BN loaded it. The
    test that was meant to guard this checked the source tree, where all the
    modules of course exist, so it could never have caught it.
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    text = open(os.path.join(root, packager)).read()
    assert "binja/*.py" in text, (
        f"{packager} does not copy binja/*.py. A hand-written file list goes "
        "stale the first time a shared module is added, and the failure only "
        "shows up on a user's machine."
    )
