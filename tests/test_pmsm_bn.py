# SPDX-License-Identifier: MIT
"""Binary Ninja integration tests for PMSM motor control firmware.

Tests the TI COFF BinaryView: open pmsm.out → auto-detect arch →
load sections → create functions from symbols → verify decompilation.

Skipped when Binary Ninja is not available.
"""

from pathlib import Path

import pytest

try:
    import binaryninja

    # tests/conftest_bn_stub.py installs a MagicMock under this name; it is
    # enough to import binja/, not to analyse a binary.
    BN_AVAILABLE = not getattr(binaryninja, "_c28x_stub", False)
except ImportError:
    BN_AVAILABLE = False


PMSM_PATH = Path(__file__).parent / "fixtures" / "pmsm" / "pmsm.out"

pytestmark = [
    pytest.mark.skipif(not BN_AVAILABLE, reason="Binary Ninja not installed"),
    pytest.mark.skipif(
        not PMSM_PATH.exists(),
        reason="PMSM firmware absent; run tests/fixtures/pmsm/fetch.sh",
    ),
]


@pytest.fixture(scope="module")
def bv():
    """Load PMSM firmware via TI COFF BinaryView."""
    bv = binaryninja.open_view(str(PMSM_PATH))
    yield bv
    bv.file.close()


class TestCOFFAutoLoad:
    """TI COFF BinaryView auto-loads the firmware correctly."""

    def test_architecture_detected(self, bv):
        assert bv.arch.name == "tms320c28x"

    def test_text_section_loaded(self, bv):
        secs = [s for s in bv.sections.values() if s.name == ".text"]
        assert len(secs) == 1
        assert secs[0].length > 0

    def test_functions_created_from_symbols(self, bv):
        """Key functions should be auto-created from COFF symbol table."""
        func_names = {f.name for f in bv.functions}
        for expected in ["main", "PWM_ISR", "pid_reg3_calc", "InitFlash"]:
            assert any(expected in name for name in func_names), (
                f"Function {expected} not found in {len(bv.functions)} functions"
            )

    def test_function_count(self, bv):
        assert len(bv.functions) >= 20


class TestPSMSDecompilation:
    """Verify decompiler output against known source patterns."""

    def _get_func(self, bv, name):
        for f in bv.functions:
            if name in f.name:
                return f
        return None

    def test_main_decompiles(self, bv):
        func = self._get_func(bv, "main")
        assert func is not None
        hlil = func.hlil
        assert hlil is not None

    def test_usdelay_decompiles_to_loop(self, bv):
        """DSP28x_usDelay should decompile to a countdown loop."""
        func = self._get_func(bv, "usDelay") or self._get_func(bv, "DSP28x_usDelay")
        if func is None:
            pytest.skip("usDelay function not found")
        # Should have at least 2 basic blocks (loop structure)
        assert len(func.basic_blocks) >= 2

    def test_pwm_isr_decompiles(self, bv):
        func = self._get_func(bv, "PWM_ISR")
        assert func is not None
        hlil = func.hlil
        assert hlil is not None
        # ISR should be substantial
        assert len(list(hlil)) > 5
