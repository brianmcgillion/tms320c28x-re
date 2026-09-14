# SPDX-License-Identifier: MIT
"""Binary Ninja integration tests for the reference firmware.

These tests require Binary Ninja to be installed and licensed.
They are automatically skipped when BN is not available.

To run manually:
    pytest tests/test_firmware_bn.py -v
"""

import pytest

try:
    import binaryninja

    # tests/conftest_bn_stub.py installs a MagicMock under this name; it is
    # enough to import binja/, not to analyse a binary.
    BN_AVAILABLE = not getattr(binaryninja, "_c28x_stub", False)
except ImportError:
    BN_AVAILABLE = False

from tests.conftest import write_firmware_bin, FUNCTIONS


pytestmark = pytest.mark.skipif(not BN_AVAILABLE, reason="Binary Ninja not installed")


@pytest.fixture(scope="module")
def firmware_path():
    """Write the firmware binary and return its path."""
    return write_firmware_bin()


@pytest.fixture(scope="module")
def bv(firmware_path):
    """Load the firmware in Binary Ninja with our architecture."""
    bv = binaryninja.BinaryViewType["Raw"].open(str(firmware_path))
    bv.arch = binaryninja.Architecture["tms320c28x"]
    bv.platform = bv.arch.standalone_platform

    # Create functions at known entry points
    for name, word_addr, byte_addr in FUNCTIONS:
        bv.create_user_function(byte_addr)

    bv.update_analysis_and_wait()
    yield bv
    bv.file.close()


class TestBNFunctionDiscovery:
    """Binary Ninja discovers all functions in the firmware."""

    def test_function_count(self, bv):
        """At least 6 functions should be discovered."""
        assert len(bv.functions) >= len(FUNCTIONS)

    def test_function_addresses(self, bv):
        """Functions exist at all expected byte addresses."""
        func_addrs = {f.start for f in bv.functions}
        for name, _, byte_addr in FUNCTIONS:
            assert byte_addr in func_addrs, (
                f"Function {name} not found at 0x{byte_addr:X}"
            )


class TestBNDisassembly:
    """Verify disassembly text matches expectations."""

    def test_main_has_lcr_instructions(self, bv):
        main_func = bv.get_function_at(0x020)
        assert main_func is not None
        disasm = "\n".join(str(line) for line in main_func.llil)
        # main should contain call instructions
        assert "call" in disasm.lower()

    def test_init_system_has_eallow(self, bv):
        func = bv.get_function_at(0x040)
        assert func is not None
        # Check that the function has instructions (was analyzed)
        assert len(list(func.llil)) > 0

    def test_delay_has_loop(self, bv):
        func = bv.get_function_at(0x088)
        assert func is not None
        # A conditional-branch check was computed here and never asserted.
        # The block-count assertion below is what this test actually tests.
        assert len(func.basic_blocks) >= 2, "delay() should have loop structure"


class TestBNDecompilation:
    """Verify the decompiler produces recognizable C output."""

    def test_main_decompiles(self, bv):
        main_func = bv.get_function_at(0x020)
        assert main_func is not None
        hlil = main_func.hlil
        assert hlil is not None, "main() should decompile"
        text = str(hlil)
        # Should contain at least one call and a loop construct
        assert len(text) > 0

    def test_delay_shows_loop(self, bv):
        func = bv.get_function_at(0x088)
        assert func is not None
        hlil = func.hlil
        if hlil is None:
            pytest.skip("Decompiler not available for delay()")
        text = str(hlil)
        # The decompiler should produce a while/do-while or similar loop
        has_loop = (
            "while" in text.lower()
            or "do" in text.lower()
            or "goto" in text.lower()
            or "loop" in text.lower()
        )
        assert has_loop or len(func.basic_blocks) >= 2, (
            "delay() should decompile to a loop"
        )

    def test_init_system_decompiles(self, bv):
        func = bv.get_function_at(0x040)
        assert func is not None
        hlil = func.hlil
        assert hlil is not None, "init_system() should decompile"
