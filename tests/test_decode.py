# SPDX-License-Identifier: MIT
"""Tests for the C28x instruction decoder."""

import pytest

from c28x_rs import Decoder
from c28x_rs import BranchType


@pytest.fixture
def decoder():
    return Decoder(objmode=1)


def _encode16(opcode: int) -> bytes:
    """Encode a 16-bit opcode to little-endian bytes."""
    return bytes([opcode & 0xFF, (opcode >> 8) & 0xFF, 0, 0])


def _encode32(opcode: int) -> bytes:
    """Encode a 32-bit opcode to little-endian bytes.

    First word (HIGH 16 bits) goes to bytes [0:1],
    second word (LOW 16 bits) goes to bytes [2:3].
    """
    word0 = (opcode >> 16) & 0xFFFF  # HIGH half -> first in memory
    word1 = opcode & 0xFFFF  # LOW half -> second in memory
    return bytes(
        [
            word0 & 0xFF,
            (word0 >> 8) & 0xFF,
            word1 & 0xFF,
            (word1 >> 8) & 0xFF,
        ]
    )


class TestUtil:
    """Verify encoding helpers match INL's DataToOpcode."""

    def test_encode16_roundtrip(self):
        from c28x_rs import bytes_to_opcode16

        assert bytes_to_opcode16(_encode16(0x9200)) == 0x9200

    def test_encode32_roundtrip(self):
        from c28x_rs import bytes_to_opcode32

        assert bytes_to_opcode32(_encode32(0x8D000000)) == 0x8D000000

    def test_encode32_mixed(self):
        from c28x_rs import bytes_to_opcode32

        # opcode 0x76401234: word0=0x7640, word1=0x1234
        data = _encode32(0x76401234)
        assert bytes_to_opcode32(data) == 0x76401234


class TestSystemInstructions:
    def test_nop(self, decoder):
        insn = decoder.decode(_encode16(0x7700))
        assert insn is not None
        assert insn.name == "NOP"
        assert insn.size == 2

    def test_eallow(self, decoder):
        insn = decoder.decode(_encode16(0x7622))
        assert insn is not None
        assert insn.name == "EALLOW"
        assert insn.size == 2

    def test_edis(self, decoder):
        insn = decoder.decode(_encode16(0x761A))
        assert insn is not None
        assert insn.name == "EDIS"

    def test_estop0(self, decoder):
        insn = decoder.decode(_encode16(0x7625))
        assert insn is not None
        assert insn.name == "ESTOP0"


class TestBranch:
    def test_lret(self, decoder):
        insn = decoder.decode(_encode16(0x7614))
        assert insn is not None
        assert insn.name == "LRET"
        assert insn.branch_type == BranchType.RETURN

    def test_lretr(self, decoder):
        insn = decoder.decode(_encode16(0x0006))
        assert insn is not None
        assert insn.name == "LRETR"
        assert insn.branch_type == BranchType.RETURN

    def test_iret(self, decoder):
        insn = decoder.decode(_encode16(0x7602))
        assert insn is not None
        assert insn.name == "IRET"
        assert insn.branch_type == BranchType.RETURN

    def test_lb_xar7(self, decoder):
        insn = decoder.decode(_encode16(0x7620))
        assert insn is not None
        assert insn.name == "LB"
        assert insn.branch_type == BranchType.UNCONDITIONAL

    def test_lc_xar7(self, decoder):
        insn = decoder.decode(_encode16(0x7604))
        assert insn is not None
        assert insn.name == "LC"
        assert insn.branch_type == BranchType.CALL

    def test_lb_absolute(self, decoder):
        # LB 0x1000 -> opcode 0x00401000
        insn = decoder.decode(_encode32(0x00401000), addr=0)
        assert insn is not None
        assert "LB" in insn.name
        assert insn.branch_type == BranchType.UNCONDITIONAL
        assert insn.branch_target == 0x1000 * 2  # word to byte addr

    def test_lc_absolute(self, decoder):
        # LC 0x2000 -> opcode 0x00802000
        insn = decoder.decode(_encode32(0x00802000), addr=0)
        assert insn is not None
        assert "LC" in insn.name
        assert insn.branch_type == BranchType.CALL
        assert insn.branch_target == 0x2000 * 2

    def test_lcr_absolute(self, decoder):
        # LCR 0x3000 -> opcode 0x76403000
        insn = decoder.decode(_encode32(0x76403000), addr=0)
        assert insn is not None
        assert "LCR" in insn.name
        assert insn.branch_type == BranchType.CALL

    def test_sb_conditional(self, decoder):
        # SB +5, EQ -> opcode 0x6105 (cond=1=EQ, offset=5)
        insn = decoder.decode(_encode16(0x6105))
        assert insn is not None
        assert insn.name == "SB"
        assert insn.branch_type == BranchType.CONDITIONAL_TRUE


class TestMov:
    def test_mov_ax_loc16(self, decoder):
        # MOV AL, *XAR0 -> opcode 0x9280 (ax=0=AL, loc=0x80=*XAR0)
        insn = decoder.decode(_encode16(0x9280))
        assert insn is not None
        assert "MOV_AX" in insn.yaml_name
        assert insn.size == 2

    def test_movb_acc_const8(self, decoder):
        # MOVB ACC, #0x42
        insn = decoder.decode(_encode16(0x0242))
        assert insn is not None
        assert "MOVB_ACC" in insn.yaml_name

    def test_movl_xar0_const22(self, decoder):
        # MOVL XAR0, #0x1234 -> opcode 0x8D001234
        insn = decoder.decode(_encode32(0x8D001234), addr=0)
        assert insn is not None
        assert "MOVL_XAR0" in insn.yaml_name
        assert insn.size == 4

    def test_push_loc16(self, decoder):
        insn = decoder.decode(_encode16(0x22A9))  # PUSH @AL (loc=0xA9)
        assert insn is not None
        assert "PUSH" in insn.name

    def test_pop_loc16(self, decoder):
        insn = decoder.decode(_encode16(0x2AA8))  # POP @AH (loc=0xA8)
        assert insn is not None
        assert "POP" in insn.name


class TestArithmetic:
    def test_addb_acc_const8(self, decoder):
        # ADDB ACC, #5
        insn = decoder.decode(_encode16(0x0905))
        assert insn is not None
        assert "ADDB_ACC" in insn.yaml_name
        # No flags_written: the decoder does not carry a per-row flag list, and
        # the lifter does not read one -- it declares FlagWrite::All at the
        # point of emission. Assert the operand the encoding actually carries.
        assert [op.value for op in insn.operands] == [5]

    def test_subb_acc_const8(self, decoder):
        insn = decoder.decode(_encode16(0x1903))
        assert insn is not None
        assert "SUBB_ACC" in insn.yaml_name

    def test_cmpb_ax_const8(self, decoder):
        # CMPB AL, #0x10
        insn = decoder.decode(_encode16(0x5210))
        assert insn is not None
        assert "CMPB_AX" in insn.yaml_name

    def test_inc_loc16(self, decoder):
        insn = decoder.decode(_encode16(0x0AA9))  # INC @AL
        assert insn is not None
        assert "INC" in insn.name

    def test_dec_loc16(self, decoder):
        insn = decoder.decode(_encode16(0x0BA8))  # DEC @AH
        assert insn is not None
        assert "DEC" in insn.name

    def test_abs_acc(self, decoder):
        insn = decoder.decode(_encode16(0xFF56))
        assert insn is not None
        assert insn.yaml_name == "ABS_ACC"

    def test_neg_acc(self, decoder):
        insn = decoder.decode(_encode16(0xFF54))
        assert insn is not None
        assert insn.yaml_name == "NEG_ACC"


class TestLogical:
    def test_and_acc_loc16(self, decoder):
        insn = decoder.decode(_encode16(0x89A9))  # AND ACC, @AL
        assert insn is not None
        assert "AND_ACC" in insn.yaml_name

    def test_or_acc_loc16(self, decoder):
        insn = decoder.decode(_encode16(0xAFA9))  # OR ACC, @AL
        assert insn is not None
        assert "OR_ACC" in insn.yaml_name

    def test_xor_acc_loc16(self, decoder):
        insn = decoder.decode(_encode16(0xB7A9))  # XOR ACC, @AL
        assert insn is not None
        assert "XOR_ACC" in insn.yaml_name

    def test_not_acc(self, decoder):
        insn = decoder.decode(_encode16(0xFF55))
        assert insn is not None
        assert insn.yaml_name == "NOT_ACC"

    def test_andb_ax_const8(self, decoder):
        insn = decoder.decode(_encode16(0x90FF))  # ANDB AL, #0xFF
        assert insn is not None
        assert "ANDB_AX" in insn.yaml_name


class TestShift:
    def test_lsl_acc_shift(self, decoder):
        insn = decoder.decode(_encode16(0xFF34))  # LSL ACC, #4
        assert insn is not None
        assert "LSL_ACC" in insn.yaml_name

    def test_lsr_ax_shift(self, decoder):
        insn = decoder.decode(_encode16(0xFFC2))  # LSR AL, #2
        assert insn is not None
        assert "LSR_AX" in insn.yaml_name

    def test_asr_ax_shift(self, decoder):
        insn = decoder.decode(_encode16(0xFFA3))  # ASR AL, #3
        assert insn is not None
        assert "ASR_AX" in insn.yaml_name

    def test_rol_acc(self, decoder):
        insn = decoder.decode(_encode16(0xFF53))
        assert insn is not None
        assert insn.yaml_name == "ROL_ACC"

    def test_ror_acc(self, decoder):
        insn = decoder.decode(_encode16(0xFF52))
        assert insn is not None
        assert insn.yaml_name == "ROR_ACC"


class TestResolvedOperand:
    """Test that DecodedInstruction operands carry resolved metadata."""

    def test_loc16_resolved_present(self, decoder):
        # MOV AL, @5 -> loc16 operand should have resolved field
        insn = decoder.decode(_encode16(0x9205))  # MOV_AX_LOC16, loc=0x05
        assert insn is not None
        loc_op = insn.operands[1]  # second operand is loc16
        assert loc_op.resolved is not None
        from c28x_rs import AddressingMode

        assert loc_op.resolved.mode == AddressingMode.DP_DIRECT
        assert loc_op.resolved.offset == 5

    def test_loc16_register_direct(self, decoder):
        insn = decoder.decode(_encode16(0x92A9))  # MOV AL, @AL
        assert insn is not None
        loc_op = insn.operands[1]
        assert loc_op.resolved is not None
        from c28x_rs import AddressingMode

        assert loc_op.resolved.mode == AddressingMode.REGISTER_DIRECT
        assert loc_op.resolved.register == "AL"

    def test_loc16_indirect_postinc(self, decoder):
        insn = decoder.decode(_encode16(0x9283))  # MOV AL, *XAR3++
        loc_op = insn.operands[1]
        assert loc_op.resolved is not None
        from c28x_rs import AddressingMode

        assert loc_op.resolved.mode == AddressingMode.INDIRECT_POST_INC
        assert loc_op.resolved.xar_index == 3

    def test_yaml_name_preserved(self, decoder):
        insn = decoder.decode(_encode16(0x9280))  # MOV_AX_LOC16
        assert insn.yaml_name == "MOV_AX_LOC16"
        insn2 = decoder.decode(_encode16(0x9680))  # MOV_LOC16_AX
        assert insn2.yaml_name == "MOV_LOC16_AX"


class TestOperands:
    """Test loc16/loc32 operand decoding."""

    def test_dp_direct(self):
        from c28x_rs import decode_loc16

        result = decode_loc16(0x05)  # DP-direct, offset=5
        assert result.text == "@0x5"

    def test_sp_relative(self):
        from c28x_rs import decode_loc16

        result = decode_loc16(0x43)  # SP-relative, offset=3
        assert result.text == "*-SP[3]"

    def test_indirect_xar0(self):
        from c28x_rs import decode_loc16

        result = decode_loc16(0xC0)  # *XAR0, which TI renders as *+XAR0[0]
        assert result.text == "*+XAR0[0]"

    def test_indirect_xar3_postinc(self):
        from c28x_rs import decode_loc16

        result = decode_loc16(0x83)  # *XAR3++
        assert result.text == "*XAR3++"

    def test_indirect_predec_xar2(self):
        from c28x_rs import decode_loc16

        result = decode_loc16(0x8A)  # *--XAR2
        assert result.text == "*--XAR2"

    def test_register_direct_ah(self):
        from c28x_rs import decode_loc16

        result = decode_loc16(0xA8)
        assert result.text == "AH"
        assert result.register == "AH"

    def test_register_direct_al(self):
        from c28x_rs import decode_loc16

        result = decode_loc16(0xA9)
        assert result.text == "AL"

    def test_loc32_acc(self):
        from c28x_rs import decode_loc32

        result = decode_loc32(0xA8)
        assert result.text == "ACC"
        assert result.register == "ACC"

    def test_loc32_p(self):
        from c28x_rs import decode_loc32

        result = decode_loc32(0xAA)
        assert result.text == "P"

    def test_loc16_br0_dec(self):
        """0xAF is *BR0-- per TI; unimplemented, so it takes the labelled fallback."""
        from c28x_rs import decode_loc16

        result = decode_loc16(0xAF)
        assert result.text == "*BR0--"

    def test_loc32_br0_dec(self):
        from c28x_rs import decode_loc32

        result = decode_loc32(0xAF)
        assert result.text == "*BR0--"


class TestFpuMov32:
    """Test FPU MOV32 load/store instruction decoding."""

    def test_mov32_rah_mem32_uncf(self, decoder):
        """MOV32 R0H, @54, UNCF — from firmware at 0x62DC76: af e2 36 00."""
        insn = decoder.decode(_encode32(0xE2AF0036), addr=0)
        assert insn is not None
        assert insn.size == 4
        assert insn.yaml_name == "MOV32_RAH_MEM32"
        assert insn.name == "MOV32"
        # Check operands: RaH=R0H (bits [10:8]=0), mem32=@54 (bits [7:0]=0x36)
        assert len(insn.operands) == 3
        assert insn.operands[0].name == "R0H"  # rah
        assert insn.operands[2].name == "UNCF"  # cndf=0xF

    def test_mov32_rah_mem32_sp_relative(self, decoder):
        """MOV32 R0H, *-SP[36], UNCF — from firmware: af e2 64 00."""
        insn = decoder.decode(_encode32(0xE2AF0064), addr=0)
        assert insn is not None
        assert insn.operands[0].name == "R0H"
        assert insn.operands[1].resolved is not None
        from c28x_rs import AddressingMode

        assert insn.operands[1].resolved.mode == AddressingMode.SP_RELATIVE
        assert insn.operands[1].resolved.offset == 36

    def test_mov32_rah_mem32_eq(self, decoder):
        """MOV32 with condition EQ (CNDF=1)."""
        insn = decoder.decode(_encode32(0xE2A10036), addr=0)
        assert insn is not None
        assert insn.operands[2].name == "EQ"

    def test_mov32_mem32_rah(self, decoder):
        """MOV32 *-SP[36], R0H — from firmware at 0x62DC80: 03 e2 64 00."""
        insn = decoder.decode(_encode32(0xE2030064), addr=0)
        assert insn is not None
        assert insn.size == 4
        assert insn.yaml_name == "MOV32_MEM32_RAH"
        assert insn.name == "MOV32"
        # mem32 = bits [7:0] = 0x64 → SP-relative @36
        assert insn.operands[0].resolved is not None
        from c28x_rs import AddressingMode

        assert insn.operands[0].resolved.mode == AddressingMode.SP_RELATIVE
        assert insn.operands[0].resolved.offset == 36
        # rah = bits [10:8] = 0 → R0H
        assert insn.operands[1].name == "R0H"

    def test_mov32_mem32_rah_r2h(self, decoder):
        """MOV32 with R2H source — second word has register bits set."""
        insn = decoder.decode(_encode32(0xE2030236), addr=0)
        assert insn is not None
        assert insn.operands[1].name == "R2H"

    def test_mov32_mem32_stf(self, decoder):
        """MOV32 *-SP[16], STF — TI encodes this 32-bit as E200 0050."""
        insn = decoder.decode(_encode32(0xE2000050), addr=0)
        assert insn is not None
        assert insn.size == 4
        assert insn.yaml_name == "MOV32_MEM32_STF"
        assert insn.name == "MOV32"
        from c28x_rs import AddressingMode

        assert insn.operands[0].resolved.mode == AddressingMode.SP_RELATIVE
        assert insn.operands[0].resolved.offset == 16

    def test_mov32_stf_mem32(self, decoder):
        """MOV32 STF, *-SP[16] — TI encodes this 32-bit as E280 0050."""
        insn = decoder.decode(_encode32(0xE2800050), addr=0)
        assert insn is not None
        assert insn.size == 4
        assert insn.yaml_name == "MOV32_STF_MEM32"
        from c28x_rs import AddressingMode

        assert insn.operands[0].resolved.mode == AddressingMode.SP_RELATIVE
        assert insn.operands[0].resolved.offset == 16

    def test_mov32_no_conflict_with_absf32(self, decoder):
        """ABSF32 R0H, R0H at 0xE695 should still decode correctly."""
        insn = decoder.decode(_encode32(0xE6950000), addr=0)
        assert insn is not None
        assert insn.yaml_name == "ABSF32_RAH_RBH"

    def test_mov32_no_conflict_with_cmpf32(self, decoder):
        """CMPF32 R0H, #0.0 at 0xE5A0 should still decode as 16-bit."""
        insn = decoder.decode(_encode16(0xE5A0))
        assert insn is not None
        assert insn.yaml_name == "CMPF32_RAH_0"
        assert insn.size == 2

    def test_mov32_no_conflict_with_i16tof32(self, decoder):
        """I16TOF32 should still decode at E2C8."""
        insn = decoder.decode(_encode32(0xE2C80000), addr=0)
        assert insn is not None
        assert insn.yaml_name == "I16TOF32_RAH_MEM16"


class TestAddrModeCoverage:
    """Verify 0xADxx decodes as a 16-bit instruction, not an undecoded 32-bit one."""

    def test_ad14_is_movst0(self, decoder):
        """0xAD14 is MOVST0 NF,ZF per TI (ADD ACC, @20 << 13 is 5604 0D14)."""
        insn = decoder.decode(_encode16(0xAD14))
        assert insn is not None
        assert insn.size == 2
        assert insn.yaml_name == "MOVST0"


class TestMovAbsoluteAddr:
    """Test MOV with *(0:16bit) absolute addressing."""

    def test_mov_loc16_abs16_al(self, decoder):
        """MOV AL, *(0:0x0F12) — TI encodes this as F5A9 0F12."""
        insn = decoder.decode(_encode32(0xF5A90F12), addr=0)
        assert insn is not None
        assert insn.size == 4
        assert insn.yaml_name == "MOV_LOC16_MEM16"
        # loc16 = 0xA9 = @AL
        assert insn.operands[0].name == "AL"
        # addr16 = 0x0F12
        assert insn.operands[1].value == 0x0F12

    def test_mov_abs16_loc16_al(self, decoder):
        """MOV *(0:0x0F12), AL — TI encodes this as F4A9 0F12."""
        insn = decoder.decode(_encode32(0xF4A90F12), addr=0)
        assert insn is not None
        assert insn.size == 4
        assert insn.yaml_name == "MOV_MEM16_LOC16"
        assert insn.operands[0].name == "AL"
        assert insn.operands[1].value == 0x0F12

    def test_mov_loc16_abs16_indirect(self, decoder):
        """MOV *+XAR2[AR1], *(0:0x0F12) — loc16=0x9A."""
        insn = decoder.decode(_encode32(0xF59A0F12), addr=0)
        assert insn is not None
        from c28x_rs import AddressingMode

        assert insn.operands[0].resolved.mode == AddressingMode.INDIRECT_AR1

    def test_mov_abs16_loc16_pl(self, decoder):
        """MOV *(0:0x0F12), @PL — loc16=0xAB."""
        insn = decoder.decode(_encode32(0xF4AB0F12), addr=0)
        assert insn is not None
        assert insn.operands[0].name == "PL"


class TestFpuConversions:
    """Test FPU conversion instructions (Phase 2)."""

    def test_ui16tof32_rah_mem16(self, decoder):
        """dis2000: e2c4 003f = `UI16TOF32 R0H, @0x3f`, e2c4 043f = R4H.

        RaH is in the second word at bits [10:8], not in the first word.
        """
        insn = decoder.decode(_encode32(0xE2C4003F), addr=0)
        assert insn is not None
        assert insn.size == 4
        assert insn.yaml_name == "UI16TOF32_RAH_MEM16"
        assert insn.operands[0].name == "R0H"

        insn = decoder.decode(_encode32(0xE2C4043F), addr=0)
        assert insn is not None
        assert insn.operands[0].name == "R4H"

    def test_ui16tof32_no_conflict_i16tof32(self, decoder):
        """I16TOF32 at E2C8 should still work."""
        insn = decoder.decode(_encode32(0xE2C80000), addr=0)
        assert insn is not None
        assert insn.yaml_name == "I16TOF32_RAH_MEM16"

    def test_f32toi32_rah_rbh(self, decoder):
        """F32TOI32 R0H, R1H — opcode E688."""
        insn = decoder.decode(_encode32(0xE6880008), addr=0)
        assert insn is not None
        assert insn.yaml_name == "F32TOI32_RAH_RBH"

    def test_f32toui32_rah_rbh(self, decoder):
        """F32TOUI32 R0H, R1H — opcode E68A."""
        insn = decoder.decode(_encode32(0xE68A0008), addr=0)
        assert insn is not None
        assert insn.yaml_name == "F32TOUI32_RAH_RBH"

    def test_ui32tof32_rah_rbh(self, decoder):
        """UI32TOF32 R0H, R1H — opcode E68B."""
        insn = decoder.decode(_encode32(0xE68B0008), addr=0)
        assert insn is not None
        assert insn.yaml_name == "UI32TOF32_RAH_RBH"

    def test_ui16tof32_rah_rbh(self, decoder):
        """UI16TOF32 R0H, R1H — opcode E68F."""
        insn = decoder.decode(_encode32(0xE68F0008), addr=0)
        assert insn is not None
        assert insn.yaml_name == "UI16TOF32_RAH_RBH"


class TestE7xxArithmetic:
    """Test additional E7xx FPU arithmetic (Phase 3)."""

    def test_mpyf32_addf32_parallel(self, decoder):
        """MPYF32 || ADDF32 parallel at E740."""
        insn = decoder.decode(_encode32(0xE74293BB), addr=0)
        assert insn is not None
        assert insn.size == 4
        assert "E7400000" not in insn.yaml_name or insn.yaml_name == "MPYF32_ADDF32_PAR"

    def test_macf32(self, decoder):
        """MACF32 at E750."""
        insn = decoder.decode(_encode32(0xE75010D1), addr=0)
        assert insn is not None
        assert insn.size == 4

    def test_no_conflict_mpyf32(self, decoder):
        """Existing MPYF32 at E700 still works."""
        insn = decoder.decode(_encode32(0xE7000008), addr=0)
        assert insn is not None
        assert insn.yaml_name == "MPYF32_RAH_RBH_RCH"

    def test_no_conflict_addf32(self, decoder):
        """Existing ADDF32 at E710 still works."""
        insn = decoder.decode(_encode32(0xE7100000), addr=0)
        assert insn is not None
        assert insn.yaml_name == "ADDF32_RAH_RBH_RCH"
