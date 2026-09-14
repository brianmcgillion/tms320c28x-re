// SPDX-License-Identifier: MIT
//! Arithmetic lifter: ADD, SUB, CMP, NEG, ABS, INC, DEC, SAT.

use crate::arch::{Flag, FlagWrite, Register};
use crate::types::*;

use binaryninja::low_level_il::{
    LowLevelILMutableFunction, LowLevelILRegisterKind, LowLevelILTempRegister,
};

use binaryninja::low_level_il::lifting::LowLevelILLabel;

use super::{op_at, read_op, reg_by_name, write_loc};

type ILFunc = LowLevelILMutableFunction;

pub fn lift_add(insn: &DecodedInstruction, _addr: u64, il: &ILFunc) -> bool {
    arith_common(insn, il, true)
}

pub fn lift_sub(insn: &DecodedInstruction, _addr: u64, il: &ILFunc) -> bool {
    arith_common(insn, il, false)
}

fn arith_common(insn: &DecodedInstruction, il: &ILFunc, is_add: bool) -> bool {
    let n = insn.id;

    // ── SUBCU / SUBCUL — conditional subtract, the modulus-division step ──
    // Not subtractions. SPRU430F prints a three-way conditional for each, and
    // lifting them as `ACC = ACC - [loc]` was a wrong value on both branches.
    // `read_op` is called exactly once per row: on an indirect operand it
    // post-increments XARn, and reading twice would step the pointer twice.
    if matches!(n, InsnId::SUBCU_ACC_LOC16 | InsnId::SUBCUL_ACC_LOC32) {
        let Some(op) = op_at(insn, 0) else {
            il.unimplemented().append();
            return true;
        };
        let tmp = LowLevelILRegisterKind::<Register>::Temp(LowLevelILTempRegister::new(0));
        let mut yes = LowLevelILLabel::new();
        let mut no = LowLevelILLabel::new();
        let mut done = LowLevelILLabel::new();

        if matches!(n, InsnId::SUBCU_ACC_LOC16) {
            // temp(32:0) = ACC << 1 - [loc16] << 16, at 64 bits so bit 32 lives
            let lhs = il.lsl(8, il.zx(8, il.reg(4, Register::ACC)), il.const_int(8, 1));
            let rhs = il.lsl(8, il.zx(8, read_op(op, il, 2)), il.const_int(8, 16));
            il.set_reg(8, tmp, il.sub(8, lhs, rhs)).append();
            let cond = il.cmp_sgt(8, il.reg(8, tmp), il.const_int(8, 0)).build();
            il.if_expr(cond, &mut yes, &mut no).append();
            il.mark_label(&mut yes);
            // ACC = temp(31:0) + 1
            let taken = il.add(4, il.low_part(4, il.reg(8, tmp)), il.const_int(4, 1));
            let flagged = taken.with_flag_write(FlagWrite::NZC).build();
            il.set_reg(4, Register::ACC, flagged).append();
            il.goto(&mut done).append();
            il.mark_label(&mut no);
            // ACC = ACC << 1
            let shifted = il.lsl(4, il.reg(4, Register::ACC), il.const_int(4, 1));
            let flagged = shifted.with_flag_write(FlagWrite::NZC).build();
            il.set_reg(4, Register::ACC, flagged).append();
            il.mark_label(&mut done);
        } else {
            // temp(32:0) = ACC << 1 + P(31) - [loc32]
            let p_msb = il.lsr(8, il.zx(8, il.reg(4, Register::P)), il.const_int(8, 31));
            let acc2 = il.lsl(8, il.zx(8, il.reg(4, Register::ACC)), il.const_int(8, 1));
            let rhs = il.zx(8, read_op(op, il, 4));
            il.set_reg(8, tmp, il.sub(8, il.add(8, acc2, p_msb), rhs))
                .append();
            let cond = il.cmp_sge(8, il.reg(8, tmp), il.const_int(8, 0)).build();
            il.if_expr(cond, &mut yes, &mut no).append();
            il.mark_label(&mut yes);
            // ACC = temp(31:0);  P = (P << 1) + 1
            let flagged = il
                .low_part(4, il.reg(8, tmp))
                .with_flag_write(FlagWrite::NZC)
                .build();
            il.set_reg(4, Register::ACC, flagged).append();
            let p_next = il.lsl(4, il.reg(4, Register::P), il.const_int(4, 1));
            il.set_reg(4, Register::P, il.add(4, p_next, il.const_int(4, 1)))
                .append();
            il.goto(&mut done).append();
            il.mark_label(&mut no);
            // ACC:P = ACC:P << 1 -- ACC first, while P still holds its old bit 31
            let carry = il.lsr(4, il.reg(4, Register::P), il.const_int(4, 31));
            let acc_next = il.lsl(4, il.reg(4, Register::ACC), il.const_int(4, 1));
            let flagged = il
                .or(4, acc_next, carry)
                .with_flag_write(FlagWrite::NZC)
                .build();
            il.set_reg(4, Register::ACC, flagged).append();
            let p_shifted = il.lsl(4, il.reg(4, Register::P), il.const_int(4, 1));
            il.set_reg(4, Register::P, p_shifted).append();
            il.mark_label(&mut done);
        }
        return true;
    }

    // INC/DEC loc16
    if matches!(n, InsnId::INC_LOC16) {
        if let Some(op) = op_at(insn, 0) {
            let val = read_op(op, il, 2);
            let result = il
                .add(2, val, il.const_int(2, 1))
                .with_flag_write(FlagWrite::All)
                .build();
            write_loc(op, il, 2, result);
        }
        return true;
    }
    if matches!(n, InsnId::DEC_LOC16) {
        if let Some(op) = op_at(insn, 0) {
            let val = read_op(op, il, 2);
            let result = il
                .sub(2, val, il.const_int(2, 1))
                .with_flag_write(FlagWrite::All)
                .build();
            write_loc(op, il, 2, result);
        }
        return true;
    }

    // ACC ± loc16 (sign-extended to 32-bit)
    if matches!(n, InsnId::ADD_ACC_LOC16 | InsnId::SUB_ACC_LOC16) {
        if let Some(op) = op_at(insn, 0) {
            let src = il.sx(4, read_op(op, il, 2));
            let acc = il.reg(4, Register::ACC);
            let expr = if is_add {
                il.add(4, acc, src)
            } else {
                il.sub(4, acc, src)
            };
            let flagged = expr.with_flag_write(FlagWrite::All).build();
            il.set_reg(4, Register::ACC, flagged).append();
        }
        return true;
    }

    // ACC ± #const8
    if matches!(n, InsnId::ADDB_ACC_CONST8 | InsnId::SUBB_ACC_CONST8) {
        if let Some(op) = op_at(insn, 0) {
            let src = il.zx(4, il.const_int(1, op.value as u64));
            let acc = il.reg(4, Register::ACC);
            let expr = if is_add {
                il.add(4, acc, src)
            } else {
                il.sub(4, acc, src)
            };
            let flagged = expr.with_flag_write(FlagWrite::All).build();
            il.set_reg(4, Register::ACC, flagged).append();
        }
        return true;
    }

    // ACC ± loc32 (32-bit)
    if matches!(
        n,
        InsnId::ADDL_ACC_LOC32
            | InsnId::SUBL_ACC_LOC32
            | InsnId::ADDUL_ACC_LOC32
            | InsnId::SUBUL_ACC_LOC32
    ) {
        if let Some(op) = op_at(insn, 0) {
            let src = read_op(op, il, 4);
            let acc = il.reg(4, Register::ACC);
            let expr = if is_add {
                il.add(4, acc, src)
            } else {
                il.sub(4, acc, src)
            };
            let flagged = expr.with_flag_write(FlagWrite::All).build();
            il.set_reg(4, Register::ACC, flagged).append();
        }
        return true;
    }

    // loc32 ± ACC
    if matches!(n, InsnId::ADDL_LOC32_ACC | InsnId::SUBL_LOC32_ACC) {
        if let Some(op) = op_at(insn, 0) {
            let src = read_op(op, il, 4);
            let acc = il.reg(4, Register::ACC);
            let expr = if is_add {
                il.add(4, src, acc)
            } else {
                il.sub(4, src, acc)
            };
            let result = expr.with_flag_write(FlagWrite::All).build();
            write_loc(op, il, 4, result);
        }
        return true;
    }

    // P ± loc32 (unsigned)
    if matches!(n, InsnId::ADDUL_P_LOC32 | InsnId::SUBUL_P_LOC32) {
        if let Some(op) = op_at(insn, 0) {
            let src = read_op(op, il, 4);
            let p = il.reg(4, Register::P);
            // The flag write goes on the ARITHMETIC, not on the set_reg. BN
            // derives C and V from the operands of the flagged expression, and
            // a flag write attached to a set_reg arrives as LowLevelILFlagWriteOp
            // ::SetReg, which carries none -- so C came out `unimplemented` and
            // the SUBUL/SUBBL borrow chain that cl2000 emits for every 64-bit
            // subtraction decompiled to nothing.
            let expr = if is_add {
                il.add(4, p, src)
            } else {
                il.sub(4, p, src)
            };
            let result = expr.with_flag_write(FlagWrite::All).build();
            il.set_reg(4, Register::P, result).append();
        }
        return true;
    }

    // SP ± #const7 — no flag write
    if matches!(n, InsnId::ADDB_SP_CONST7 | InsnId::SUBB_SP_CONST7) {
        if let Some(op) = op_at(insn, 0) {
            let expr = if is_add {
                il.add(
                    4,
                    il.reg(4, Register::SP),
                    il.const_int(4, op.value as u64 * 2),
                )
            } else {
                il.sub(
                    4,
                    il.reg(4, Register::SP),
                    il.const_int(4, op.value as u64 * 2),
                )
            };
            il.set_reg(4, Register::SP, expr).append();
        }
        return true;
    }

    // XARn ± #const7 — no flag write
    if matches!(n, InsnId::ADDB_XARN_CONST7 | InsnId::SUBB_XARN_CONST7) {
        if insn.operands.len() >= 2 {
            let reg = reg_by_name(insn.operands[0].display_name());
            let val = insn.operands[1].value as u64;
            let expr = if is_add {
                il.add(4, il.reg(4, reg), il.const_int(4, val))
            } else {
                il.sub(4, il.reg(4, reg), il.const_int(4, val))
            };
            il.set_reg(4, reg, expr).append();
        }
        return true;
    }

    // loc16 ± AX
    if matches!(n, InsnId::ADD_LOC16_AX | InsnId::SUB_LOC16_AX) {
        if insn.operands.len() >= 2 {
            let dst = &insn.operands[0];
            let src = &insn.operands[1];
            let lhs = read_op(dst, il, 2);
            let rhs = read_op(src, il, 2);
            let expr = if is_add {
                il.add(2, lhs, rhs)
            } else {
                il.sub(2, lhs, rhs)
            };
            let result = expr.with_flag_write(FlagWrite::All).build();
            write_loc(dst, il, 2, result);
        }
        return true;
    }

    // loc16 + #const16
    if matches!(n, InsnId::ADD_LOC16_CONST16) {
        if insn.operands.len() >= 2 {
            let dst = &insn.operands[0];
            let src = &insn.operands[1];
            let lhs = read_op(dst, il, 2);
            let rhs = il.const_int(2, src.value as u64);
            let result = il.add(2, lhs, rhs).with_flag_write(FlagWrite::All).build();
            write_loc(dst, il, 2, result);
        }
        return true;
    }

    // ACC ± loc16 << shift (shifted variants)
    if matches!(
        n,
        InsnId::ADD_ACC_LOC16_SHIFT16
            | InsnId::ADD_ACC_LOC16_SHIFT1_15
            | InsnId::ADD_ACC_LOC16_SHIFT_T
            | InsnId::SUB_ACC_LOC16_SHIFT16
            | InsnId::SUB_ACC_LOC16_SHIFT1_15_OBJMODE1
            | InsnId::SUB_ACC_LOC16_SHIFT_T
            | InsnId::SUB_ACC_CONST16_SHIFT
            | InsnId::ADD_ACC_CONST16_SHIFT
    ) {
        // The shift was discarded, so `ADD ACC, @x << 16` lifted identically to
        // `ADD ACC, @x` -- off by a factor of 65536, and fixed-point C28x code
        // is built out of these. The `_SHIFT_T` forms shift by the T register.
        if let Some(op) = op_at(insn, 0) {
            let value = il.sx(4, read_op(op, il, 2)).build();
            let src = match n {
                InsnId::ADD_ACC_LOC16_SHIFT16 | InsnId::SUB_ACC_LOC16_SHIFT16 => {
                    il.lsl(4, value, il.const_int(4, 16)).build()
                }
                InsnId::ADD_ACC_LOC16_SHIFT_T | InsnId::SUB_ACC_LOC16_SHIFT_T => {
                    il.lsl(4, value, il.zx(4, il.reg(2, Register::T))).build()
                }
                _ => match op_at(insn, 1) {
                    Some(sh) => il.lsl(4, value, il.const_int(4, sh.value as u64)).build(),
                    None => value,
                },
            };
            let acc = il.reg(4, Register::ACC);
            let expr = if is_add {
                il.add(4, acc, src)
            } else {
                il.sub(4, acc, src)
            };
            let flagged = expr.with_flag_write(FlagWrite::All).build();
            il.set_reg(4, Register::ACC, flagged).append();
        }
        return true;
    }

    // Unsigned ACC ± loc16
    if matches!(n, InsnId::ADDU_ACC_LOC16 | InsnId::SUBU_ACC_LOC16) {
        if let Some(op) = op_at(insn, 0) {
            let src = il.zx(4, read_op(op, il, 2));
            let acc = il.reg(4, Register::ACC);
            let expr = if is_add {
                il.add(4, acc, src)
            } else {
                il.sub(4, acc, src)
            };
            let flagged = expr.with_flag_write(FlagWrite::All).build();
            il.set_reg(4, Register::ACC, flagged).append();
        }
        return true;
    }

    // AX ± #const8
    if matches!(n, InsnId::ADDB_AX_CONST8) {
        if insn.operands.len() >= 2 {
            let reg = reg_by_name(insn.operands[0].display_name());
            // TI spells this one `ADDB AX, #8bitSigned` -- `AX = AX + S:8bit`,
            // unlike the ACC form's `0:8bit`. Zero-extending made `ADDB AL, #-1`
            // add 255. The operand is `signed: true` in the table for the same
            // reason, so the two now agree.
            let val = il.sx(2, il.const_int(1, insn.operands[1].value as u64));
            let flagged = il
                .add(2, il.reg(2, reg), val)
                .with_flag_write(FlagWrite::All)
                .build();
            il.set_reg(2, reg, flagged).append();
        }
        return true;
    }

    // AX ± loc16
    if matches!(n, InsnId::ADD_AX_LOC16 | InsnId::SUB_AX_LOC16) {
        if insn.operands.len() >= 2 {
            let reg = reg_by_name(insn.operands[0].display_name());
            let src = read_op(&insn.operands[1], il, 2);
            let expr = if is_add {
                il.add(2, il.reg(2, reg), src)
            } else {
                il.sub(2, il.reg(2, reg), src)
            };
            let flagged = expr.with_flag_write(FlagWrite::All).build();
            il.set_reg(2, reg, flagged).append();
        }
        return true;
    }

    // ── Subtract with borrow ──
    // SPRU430F: `ACC = ACC − 0:[loc16] − ~C` (SBBU) and `ACC = ACC − [loc32] −
    // ~C` (SUBBL). Two separate defects: the borrow was dropped entirely, and
    // SBBU sign-extended an operand its page writes as `0:[loc16]`.
    //
    // Polarity, which is easy to get backwards. TI writes the term `~C` because
    // on the C28x the hardware bit is the INVERSE of a borrow ("If the
    // subtraction generates a borrow, C is cleared"). BN's `flag:C` is NOT that
    // bit: `flag_write_llil` is left at BN's default, which computes `a u< b`
    // for a subtract -- C SET on borrow, the common convention. Since
    // sbb(a, b, carry) subtracts the borrow, the operand is `flag:C` as BN
    // defines it, and writing `flag:C ^ 1` would invert it twice.
    // Confirmed against cl2000, which pairs SUBUL with SUBBL for every 64-bit
    // subtraction; see the note on ADDC below for why addition needs no such
    // care (both conventions set C on carry-out).
    if matches!(n, InsnId::SBBU_ACC_LOC16 | InsnId::SUBBL_ACC_LOC32) {
        if let Some(op) = op_at(insn, 0) {
            let src = if matches!(n, InsnId::SBBU_ACC_LOC16) {
                il.zx(4, read_op(op, il, 2)).build()
            } else {
                read_op(op, il, 4)
            };
            let diff = il.sbb(4, il.reg(4, Register::ACC), src, il.flag(Flag::C));
            let flagged = diff.with_flag_write(FlagWrite::All).build();
            il.set_reg(4, Register::ACC, flagged).append();
        }
        return true;
    }

    // Add with carry
    if matches!(n, InsnId::ADDCU_ACC_LOC16 | InsnId::ADDCL_ACC_LOC32) {
        if let Some(op) = op_at(insn, 0) {
            let size = if matches!(n, InsnId::ADDCL_ACC_LOC32) {
                4
            } else {
                2
            };
            let src = if size == 2 {
                il.zx(4, read_op(op, il, 2)).build()
            } else {
                read_op(op, il, 4)
            };
            // SPRU430F: `ACC = ACC + [loc32] + C`. The carry-in was dropped, so
            // ADDCL lifted identically to ADDL and the upper word of every
            // multi-word addition built out of them came out one short.
            let sum = il.adc(4, il.reg(4, Register::ACC), src, il.flag(Flag::C));
            let flagged = sum.with_flag_write(FlagWrite::All).build();
            il.set_reg(4, Register::ACC, flagged).append();
        }
        return true;
    }

    // Generic 2-operand: reg ± operand
    if insn.operands.len() >= 2 {
        let op0 = &insn.operands[0];
        let op1 = &insn.operands[1];

        if op0.op_type == OperandType::Register {
            let reg = reg_by_name(op0.display_name());
            let size = if matches!(
                reg,
                Register::ACC
                    | Register::P
                    | Register::XT
                    | Register::XAR0
                    | Register::XAR1
                    | Register::XAR2
                    | Register::XAR3
                    | Register::XAR4
                    | Register::XAR5
                    | Register::XAR6
                    | Register::XAR7
            ) {
                4
            } else {
                2
            };
            let src = read_op(op1, il, size);
            let expr = if is_add {
                il.add(size, il.reg(size, reg), src)
            } else {
                il.sub(size, il.reg(size, reg), src)
            };
            let flagged = expr.with_flag_write(FlagWrite::All).build();
            il.set_reg(size, reg, flagged).append();
            return true;
        }
    }

    // Reverse subtract: the destination is the right-hand side.
    //   SPRU430F:  SUBR  loc16, AX   ->  [loc16] = AX  - [loc16]
    //              SUBRL loc32, ACC  ->  [loc32] = ACC - [loc32]
    // SUBRL reached the single-operand arm below and became `ACC -= [loc32]`:
    // wrong destination, wrong direction, and reading two bytes of a loc32.
    if matches!(n, InsnId::SUBR_LOC16_AX | InsnId::SUBRL_LOC32_ACC) {
        if let Some(dst) = op_at(insn, 0) {
            let (size, lhs) = match n {
                InsnId::SUBRL_LOC32_ACC => (4, il.reg(4, Register::ACC)),
                _ => match op_at(insn, 1) {
                    Some(ax) => (2, il.reg(2, reg_by_name(ax.display_name()))),
                    None => {
                        il.unimplemented().append();
                        return true;
                    }
                },
            };
            let result = il
                .sub(size, lhs, read_op(dst, il, size))
                .with_flag_write(FlagWrite::All)
                .build();
            write_loc(dst, il, size, result);
        }
        return true;
    }

    // SBRK / ADRK modify XAR(ARP), not ACC. ARP is not in the register model --
    // it selects which XARn an instruction means -- so there is nothing correct
    // to emit. They reached the arm below and became `ACC -= imm8`, which
    // destroys a live accumulator to model an instruction that never touches it.
    if matches!(n, InsnId::SBRK_CONST8 | InsnId::ADRK_IMM8) {
        il.unimplemented().append();
        return true;
    }

    // Single-operand add/sub: ACC ± operand (implicit ACC destination)
    if insn.operands.len() == 1 {
        let op = &insn.operands[0];
        let src = il.sx(4, read_op(op, il, 2));
        let acc = il.reg(4, Register::ACC);
        let expr = if is_add {
            il.add(4, acc, src)
        } else {
            il.sub(4, acc, src)
        };
        let flagged = expr.with_flag_write(FlagWrite::All).build();
        il.set_reg(4, Register::ACC, flagged).append();
        return true;
    }

    il.unimplemented().append(); // guard: should not be reached for valid decoded instructions
    true
}

pub fn lift_cmp(insn: &DecodedInstruction, _addr: u64, il: &ILFunc) -> bool {
    let n = insn.id;

    // CMP64 ACC:P — compare the signed 64-bit register pair (ACC high, P low)
    // to zero, setting N/Z/C. Both operands are implicit (decoded as ops=[]).
    if matches!(n, InsnId::CMP64_ACC_P) {
        let lhs = il.reg_split(8, Register::ACC, Register::P);
        il.sub(8, lhs, il.const_int(8, 0))
            .with_flag_write(FlagWrite::NZV)
            .append();
        return true;
    }

    // CMPL ACC, loc32 (32-bit compare)
    if matches!(n, InsnId::CMPL_ACC_LOC32) {
        if let Some(op) = op_at(insn, 0) {
            let lhs = il.reg(4, Register::ACC);
            let rhs = read_op(op, il, 4);
            il.sub(4, lhs, rhs).with_flag_write(FlagWrite::NZC).append();
        }
        return true;
    }

    // CMPB AX, #const8
    if matches!(n, InsnId::CMPB_AX_CONST8) {
        if insn.operands.len() >= 2 {
            let lhs = il.reg(2, reg_by_name(insn.operands[0].display_name()));
            let rhs = il.zx(2, il.const_int(1, insn.operands[1].value as u64));
            il.sub(2, lhs, rhs).with_flag_write(FlagWrite::NZC).append();
        }
        return true;
    }

    // CMP AX, loc16
    if matches!(n, InsnId::CMP_AX_LOC16) {
        if insn.operands.len() >= 2 {
            let lhs = il.reg(2, reg_by_name(insn.operands[0].display_name()));
            let rhs = read_op(&insn.operands[1], il, 2);
            il.sub(2, lhs, rhs).with_flag_write(FlagWrite::NZC).append();
        }
        return true;
    }

    // CMP loc16, #const16
    if matches!(n, InsnId::CMP_LOC16_CONST16) {
        if insn.operands.len() >= 2 {
            let lhs = read_op(&insn.operands[0], il, 2);
            let rhs = il.const_int(2, insn.operands[1].value as u64);
            il.sub(2, lhs, rhs).with_flag_write(FlagWrite::NZC).append();
        }
        return true;
    }

    // Generic 2-operand compare
    if insn.operands.len() >= 2 {
        let op0 = &insn.operands[0];
        let op1 = &insn.operands[1];
        let size = if op0.op_type == OperandType::Loc32 {
            4
        } else {
            2
        };
        let lhs = read_op(op0, il, size);
        let rhs = read_op(op1, il, size);
        il.sub(size, lhs, rhs)
            .with_flag_write(FlagWrite::NZC)
            .append();
    } else if insn.operands.len() == 1 {
        // Single-operand compare: CMP ACC, operand (implicit ACC)
        let op = &insn.operands[0];
        let size = if op.op_type == OperandType::Loc32 {
            4
        } else {
            2
        };
        let lhs = il.reg(4, Register::ACC);
        let rhs = if size == 2 {
            il.sx(4, read_op(op, il, 2)).build()
        } else {
            read_op(op, il, 4)
        };
        il.sub(4, lhs, rhs).with_flag_write(FlagWrite::NZC).append();
    } else {
        il.unimplemented().append(); // guard: CMP with no operands
    }
    true
}

pub fn lift_misc(insn: &DecodedInstruction, _addr: u64, il: &ILFunc) -> bool {
    match insn.id {
        InsnId::NEG_ACC => {
            let flagged = il
                .neg(4, il.reg(4, Register::ACC))
                .with_flag_write(FlagWrite::All)
                .build();
            il.set_reg(4, Register::ACC, flagged).append();
        }
        InsnId::NEG_AX => {
            if let Some(op) = op_at(insn, 0) {
                let reg = reg_by_name(op.display_name());
                let flagged = il
                    .neg(2, il.reg(2, reg))
                    .with_flag_write(FlagWrite::All)
                    .build();
                il.set_reg(2, reg, flagged).append();
            }
        }
        InsnId::TEST_ACC => {
            // TEST ACC: sets N, Z flags based on ACC value (like CMP ACC, 0)
            il.sub(4, il.reg(4, Register::ACC), il.const_int(4, 0))
                .with_flag_write(FlagWrite::NZ)
                .append();
        }
        // ABS negates only a negative ACC. Both of these were an unconditional
        // negate, which is a wrong *value* for every ACC that was already
        // positive -- and it feeds whatever reads ACC next.
        InsnId::ABS_ACC | InsnId::ABSTC_ACC => {
            let cond = il
                .cmp_slt(4, il.reg(4, Register::ACC), il.const_int(4, 0))
                .build();
            let mut negate = LowLevelILLabel::new();
            let mut done = LowLevelILLabel::new();
            il.if_expr(cond, &mut negate, &mut done).append();
            il.mark_label(&mut negate);
            let flagged = il
                .neg(4, il.reg(4, Register::ACC))
                .with_flag_write(FlagWrite::All)
                .build();
            il.set_reg(4, Register::ACC, flagged).append();
            // ABSTC additionally toggles TC on the branch that negates:
            // "load the TC bit with the sign bit XORed with the previous value".
            if matches!(insn.id, InsnId::ABSTC_ACC) {
                il.set_flag(Flag::TC, il.xor(0, il.flag(Flag::TC), il.const_int(0, 1)))
                    .append();
            }
            il.mark_label(&mut done);
        }
        InsnId::NEG64_ACC_P => {
            // Negate 64-bit ACC:P — negate both halves
            let flagged = il
                .neg(4, il.reg(4, Register::ACC))
                .with_flag_write(FlagWrite::All)
                .build();
            il.set_reg(4, Register::ACC, flagged).append();
            il.set_reg(4, Register::P, il.neg(4, il.reg(4, Register::P)))
                .append();
        }
        InsnId::NEGTC_ACC => {
            // SPRU430F p.337: `if( TC = 1 ) ... ACC = -ACC`. The negate was
            // unconditional, which is a wrong value for every ACC reached with
            // TC clear -- the same defect ABS_ACC above already carries a note
            // about, in the one instruction whose condition is a flag.
            let cond = il.cmp_e(0, il.flag(Flag::TC), il.const_int(0, 1)).build();
            let mut negate = LowLevelILLabel::new();
            let mut done = LowLevelILLabel::new();
            il.if_expr(cond, &mut negate, &mut done).append();
            il.mark_label(&mut negate);
            let flagged = il
                .neg(4, il.reg(4, Register::ACC))
                .with_flag_write(FlagWrite::All)
                .build();
            il.set_reg(4, Register::ACC, flagged).append();
            il.mark_label(&mut done);
        }
        InsnId::SAT_ACC | InsnId::SAT64_ACC_P => {
            // Saturate: clamp based on overflow — model as nop
            // (depends on OVM mode bit, not representable in IL)
            il.nop().append();
        }
        // ── Test bit instructions ──
        InsnId::TBIT_LOC16_BIT => {
            // Test bit N of loc16 → sets TC flag
            if insn.operands.len() >= 2 {
                let val = read_op(&insn.operands[0], il, 2);
                let bit = il.const_int(2, insn.operands[1].value as u64);
                il.and(2, il.lsr(2, val, bit), il.const_int(2, 1))
                    .with_flag_write(FlagWrite::TC)
                    .append();
            }
        }
        InsnId::TBIT_LOC16_T => {
            // Test bit at position T of loc16
            if let Some(op) = op_at(insn, 0) {
                let val = read_op(op, il, 2);
                let t = il.zx(2, il.reg(2, Register::T));
                il.and(2, il.lsr(2, val, t), il.const_int(2, 1))
                    .with_flag_write(FlagWrite::TC)
                    .append();
            }
        }
        InsnId::TCLR_LOC16_BIT => {
            // Test bit N then clear it
            if insn.operands.len() >= 2 {
                let bit = insn.operands[1].value as u64;
                let val = read_op(&insn.operands[0], il, 2);
                il.and(2, il.lsr(2, val, il.const_int(2, bit)), il.const_int(2, 1))
                    .with_flag_write(FlagWrite::TC)
                    .append();
                let mask = il.const_int(2, !(1u16 as u64) << bit & 0xFFFF);
                let cleared = il
                    .and(2, read_op(&insn.operands[0], il, 2), mask)
                    .with_flag_write(FlagWrite::NZ)
                    .build();
                write_loc(&insn.operands[0], il, 2, cleared);
            }
        }
        InsnId::TSET_LOC16_BIT => {
            // Test bit N then set it
            if insn.operands.len() >= 2 {
                let bit = insn.operands[1].value as u64;
                let val = read_op(&insn.operands[0], il, 2);
                il.and(2, il.lsr(2, val, il.const_int(2, bit)), il.const_int(2, 1))
                    .with_flag_write(FlagWrite::TC)
                    .append();
                let mask = il.const_int(2, 1u64 << bit);
                let set_val = il
                    .or(2, read_op(&insn.operands[0], il, 2), mask)
                    .with_flag_write(FlagWrite::NZ)
                    .build();
                write_loc(&insn.operands[0], il, 2, set_val);
            }
        }
        _ => {
            il.unimplemented().append(); // guard: unmatched misc arithmetic
        }
    }
    true
}
