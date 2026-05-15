"""Smoke test for binja/tools.py — catches missing imports.

The plugin's task classes (CleanupTask, ApplyMemoryMapTask, ...) use Binary
Ninja names (`Symbol`, `SegmentFlag`, ...) inside their `run()` methods. A
missing top-level import only surfaces when a user clicks the relevant menu
item — easy to ship undetected (we hit this with `Symbol` not imported in
ApplyMemoryMapTask).

This script imports `binja.tools` and exercises each Task's `run()` against a
permissive `MagicMock` BinaryView. Mock-induced AttributeError / TypeError is
tolerated; only `NameError` (missing import) fails the smoke test.

Run: nix develop -c python3 scripts/smoke_tools.py
"""

import importlib.util
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(__file__))
from _bn_helpers import init_bn

binaryninja = init_bn()

ROOT = os.path.join(os.path.dirname(__file__), "..")
TOOLS_PY = os.path.join(ROOT, "binja", "tools.py")

# Load binja/tools.py as a standalone module (matches how BN itself loads it).
spec = importlib.util.spec_from_file_location("tools", TOOLS_PY)
tools = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tools)


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
