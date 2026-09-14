"""Smoke test for binja/tools.py — catches missing imports.

The plugin's task classes (CleanupTask, ApplyMemoryMapTask, ...) use Binary
Ninja names (`Symbol`, `SegmentFlag`, ...) inside their `run()` methods. A
missing top-level import only surfaces when a user clicks the relevant menu
item — easy to ship undetected (we hit this with `Symbol` not imported in
ApplyMemoryMapTask).

This script imports `binja.tools` and exercises each Task's `run()` against a
permissive `MagicMock` BinaryView. Mock-induced AttributeError / TypeError is
tolerated; only `NameError` (missing import) fails the smoke test.

It used to load the file standalone via `spec_from_file_location`, with a
comment claiming that matched how BN loads it. It does not: package.sh ships a
`tms320c28x/` directory and `__init__.py` imports the modules as
`tms320c28x.tools`, so importing the package is the faithful thing -- and it
is what lets the modules share code at all.

Run: nix develop -c python3 scripts/smoke_tools.py [--stub]

`--stub` swaps the real Binary Ninja for tests/conftest_bn_stub.py, so the
check runs with no install and no licence. Nothing here needs real BN -- every
Task is already exercised against a MagicMock BinaryView -- the import of
binja.tools was the only thing that did. That makes this a CI gate.
"""

import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(__file__))
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

if "--stub" in sys.argv:
    from tests.conftest_bn_stub import install as install_bn_stub

    install_bn_stub()
    import binaryninja
else:
    from _bn_helpers import init_bn

    binaryninja = init_bn()

from binja import tools  # noqa: E402 (needs the sys.path line above)


def make_mock_bv():
    """Permissive BinaryView mock.

    Each Task.run() reads several attributes and iterates bv.functions and
    bv.segments. Default MagicMock returns aren't iterable, so we explicitly
    set those to empty lists. Other accesses fall through to MagicMock's
    auto-attribute machinery.
    """
    bv = MagicMock()
    bv.arch.name = "tms320c28x"
    bv.functions = []
    bv.segments = []
    bv.entry_point = 0
    bv.read = MagicMock(return_value=b"\x00" * 4)
    bv.get_symbols = MagicMock(return_value=[])
    return bv


TASK_CLASSES = [
    "CleanupTask",
    "ApplyMemoryMapTask",
    "PIEFunctionTask",
    "MarkInlineDataTask",
]

passed = 0
failed = 0


def report(ok, msg_ok, msg_fail):
    global passed, failed
    if ok:
        print(f"  [OK] {msg_ok}")
        passed += 1
    else:
        print(f"  [FAIL] {msg_fail}")
        failed += 1


print("=" * 60)
print("  binja/tools.py — Smoke test (missing-import detector)")
print("=" * 60)
print()

# Sanity: tools module must expose each Task and command function.
print("--- Module surface ---")
EXPECTED = TASK_CLASSES + [
    "remove_false_functions",
    "apply_memory_map",
    "find_pie_functions",
    "mark_inline_data",
]
for name in EXPECTED:
    report(
        hasattr(tools, name),
        f"tools.{name} present",
        f"tools.{name} missing — refactor regression?",
    )

# Each Task.run() must execute without NameError on a mock BV.
print()
print("--- Task.run() — NameError detection ---")
for task_name in TASK_CLASSES:
    task_class = getattr(tools, task_name)
    bv = make_mock_bv()
    task = task_class(bv)
    try:
        task.run()
        report(
            True,
            f"{task_name}.run() clean",
            "",
        )
    except NameError as exc:
        report(
            False,
            "",
            f"{task_name}.run() raised NameError: {exc} — missing top-level import in tools.py",
        )
    except Exception as exc:
        # Mock-related AttributeError / TypeError is tolerated — we only fail
        # on unresolved names. Report quietly so a real regression isn't hidden.
        report(
            True,
            f"{task_name}.run() executed (mock-tolerated {type(exc).__name__})",
            "",
        )

print()
total = passed + failed
print("=" * 60)
if failed == 0:
    print(f"  SMOKE TEST PASSED ({passed}/{total})")
else:
    print(f"  SMOKE TEST FAILED ({passed}/{total} passed, {failed} failed)")
print("=" * 60)
sys.exit(1 if failed else 0)
