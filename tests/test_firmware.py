# SPDX-License-Identifier: MIT
"""Integration tests: decode a reference LED-blink firmware end-to-end.

The firmware is hand-assembled from known opcodes (see conftest.py) to model
a TI C2000Ware blinky example. Tests verify that every instruction decodes
correctly and that control flow (calls, returns, loops) is properly resolved.

Expected C equivalent:
    void _c_int00()    { main(); }
    void main()        { init_system(); init_gpio(); while(1) { gpio_toggle(); delay(0xFF); } }
    void init_system() { EALLOW; *(0x7029)=0x68; EDIS; }
    void init_gpio()   { EALLOW; *(0x7C80)=1; EDIS; }
    void gpio_toggle() { *(0x7F06)=1; }
    void delay(n)      { while(n!=0) n--; }
"""

import pytest

from c28x.decoder import Decoder
from c28x.types import BranchType


@pytest.fixture
def decoder():
    return Decoder(objmode=1)


class TestFirmwareDecode:
    """Every instruction in the reference firmware decodes to the expected mnemonic."""

    def test_all_instructions_decode(self, decoder, firmware_bytes, firmware_def):
        for word_addr, opcode, size, expected_name, comment in firmware_def:
            byte_addr = word_addr * 2
            data = firmware_bytes[byte_addr:byte_addr + 4]
            insn = decoder.decode(data, addr=byte_addr)
            assert insn is not None, (
                f"Failed to decode at word 0x{word_addr:03X} "
                f"(byte 0x{byte_addr:03X}): {comment}"
            )
            assert insn.yaml_name == expected_name, (
                f"At word 0x{word_addr:03X}: expected {expected_name}, "
                f"got {insn.yaml_name} ({comment})"
            )
            assert insn.size == size, (
                f"At word 0x{word_addr:03X}: expected size {size}, "
                f"got {insn.size} ({comment})"
            )

    def test_no_gaps(self, decoder, firmware_bytes, firmware_def):
        """The firmware has no undecoded gaps between instructions within each function."""
        from tests.conftest import FUNCTIONS

        for func_name, func_word, func_byte in FUNCTIONS:
            # Find all instructions in this function
            func_insns = [
                (w, o, s, n, c)
                for w, o, s, n, c in firmware_def
                if w >= func_word
            ]
            if not func_insns:
                continue

            # Check contiguous within function (until LRETR/ESTOP0)
            expected_word = func_word
            for w, o, s, n, c in func_insns:
                if w < expected_word:
                    continue
                assert w == expected_word, (
                    f"Gap in {func_name} at word 0x{expected_word:03X}, "
                    f"next insn at 0x{w:03X}"
                )
                expected_word = w + s // 2
                if n in ("LRETR", "ESTOP0"):
                    break


class TestControlFlow:
    """Branch targets and function call/return structure."""

    def test_c_int00_calls_main(self, decoder, firmware_bytes):
        """_c_int00 first instruction is LCR to main."""
        insn = decoder.decode(firmware_bytes[0:4], addr=0)
        assert insn.yaml_name == "LCR"
        assert insn.branch_type == BranchType.CALL
        # main is at word 0x010 = byte 0x020
        assert insn.branch_target == 0x020

    def test_main_calls_init_system(self, decoder, firmware_bytes):
        """main's second instruction calls init_system."""
        # main at byte 0x020, first insn is ADDB SP (2 bytes), second is LCR
        insn = decoder.decode(firmware_bytes[0x022:0x026], addr=0x022)
        assert insn.yaml_name == "LCR"
        assert insn.branch_target == 0x040  # init_system at word 0x020 = byte 0x040

    def test_main_calls_init_gpio(self, decoder, firmware_bytes):
        insn = decoder.decode(firmware_bytes[0x026:0x02A], addr=0x026)
        assert insn.yaml_name == "LCR"
        assert insn.branch_target == 0x058  # init_gpio at word 0x02C = byte 0x058

    def test_main_loop_calls_gpio_toggle(self, decoder, firmware_bytes):
        insn = decoder.decode(firmware_bytes[0x02A:0x02E], addr=0x02A)
        assert insn.yaml_name == "LCR"
        assert insn.branch_target == 0x070  # gpio_toggle at word 0x038 = byte 0x070

    def test_main_loop_calls_delay(self, decoder, firmware_bytes):
        # After MOVB AL (2 bytes at 0x02E), LCR delay at 0x030
        insn = decoder.decode(firmware_bytes[0x030:0x034], addr=0x030)
        assert insn.yaml_name == "LCR"
        assert insn.branch_target == 0x088  # delay at word 0x044 = byte 0x088

    def test_main_loop_branches_back(self, decoder, firmware_bytes):
        """Main loop ends with SB UNC back to the loop start."""
        insn = decoder.decode(firmware_bytes[0x034:0x038], addr=0x034)
        assert insn.yaml_name == "SB"
        assert insn.branch_type == BranchType.UNCONDITIONAL
        # Should branch back to word 0x015 = byte 0x02A
        assert insn.branch_target == 0x02A, f"got 0x{insn.branch_target:X}"

    def test_all_functions_end_with_return(self, decoder, firmware_bytes, firmware_def):
        """Every function (except _c_int00) ends with LRETR."""
        from tests.conftest import FUNCTIONS
        for func_name, func_word, func_byte in FUNCTIONS:
            if func_name == "_c_int00":
                continue  # ends with ESTOP0
            # Find the last instruction of this function
            func_insns = [
                (w, o, s, n, c) for w, o, s, n, c in firmware_def
                if w >= func_word
            ]
            for w, o, s, n, c in func_insns:
                if n == "LRETR":
                    byte_addr = w * 2
                    insn = decoder.decode(firmware_bytes[byte_addr:byte_addr+4], addr=byte_addr)
                    assert insn.branch_type == BranchType.RETURN
                    break
            else:
                pytest.fail(f"{func_name} has no LRETR")


class TestDelayLoop:
    """The delay() function implements a countdown loop."""

    def test_delay_has_conditional_branch(self, decoder, firmware_bytes):
        """delay() has SB EQ (branch to done when count==0)."""
        # SB EQ at word 0x048 = byte 0x090
        insn = decoder.decode(firmware_bytes[0x090:0x094], addr=0x090)
        assert insn.yaml_name == "SB"
        assert insn.branch_type == BranchType.CONDITIONAL_TRUE

    def test_delay_decrements(self, decoder, firmware_bytes):
        """delay() has DEC *-SP[1]."""
        insn = decoder.decode(firmware_bytes[0x092:0x096], addr=0x092)
        assert insn.yaml_name == "DEC_LOC16"

    def test_delay_loop_back(self, decoder, firmware_bytes):
        """delay() has SB UNC back to loop start."""
        # SB at word 0x04A = byte 0x094
        insn = decoder.decode(firmware_bytes[0x094:0x098], addr=0x094)
        assert insn.yaml_name == "SB"
        assert insn.branch_type == BranchType.UNCONDITIONAL
        # Should go back to word 0x046 = byte 0x08C
        assert insn.branch_target == 0x08C, f"got 0x{insn.branch_target:X}"


class TestInstructionPatterns:
    """Verify specific instruction patterns in the firmware."""

    def test_eallow_edis_pairs(self, firmware_def):
        """EALLOW and EDIS appear in pairs."""
        names = [n for _, _, _, n, _ in firmware_def]
        eallow_count = names.count("EALLOW")
        edis_count = names.count("EDIS")
        assert eallow_count == edis_count == 2

    def test_stack_frame_balanced(self, firmware_def):
        """Functions with ADDB SP also have matching SUBB SP."""
        addb = sum(1 for _, _, _, n, _ in firmware_def if n == "ADDB_SP_CONST7")
        subb = sum(1 for _, _, _, n, _ in firmware_def if n == "SUBB_SP_CONST7")
        assert addb == subb

    def test_dp_setup_before_memory_access(self, decoder, firmware_bytes):
        """init_system sets DP before writing to a DP-relative address."""
        # MOVW DP at word 0x021 = byte 0x042
        insn = decoder.decode(firmware_bytes[0x042:0x046], addr=0x042)
        assert insn.yaml_name == "MOVW_DP_CONST16"
        # Followed by MOVB AL, then MOV @offset, AL
        insn2 = decoder.decode(firmware_bytes[0x048:0x04C], addr=0x048)
        assert insn2.yaml_name == "MOV_LOC16_AX"


class TestFullWalk:
    """Walk the entire firmware sequentially, verifying no decode failures."""

    def test_sequential_decode(self, decoder, firmware_bytes, firmware_def):
        """Decode from start, following sequential flow, covers all instructions."""
        decoded_addrs = set()
        for word_addr, _, size, _, _ in firmware_def:
            byte_addr = word_addr * 2
            data = firmware_bytes[byte_addr:byte_addr + 4]
            if len(data) < 2:
                continue
            insn = decoder.decode(data, addr=byte_addr)
            assert insn is not None
            decoded_addrs.add(byte_addr)

        # Verify we decoded every defined instruction
        expected_addrs = {w * 2 for w, _, _, _, _ in firmware_def}
        assert decoded_addrs == expected_addrs
