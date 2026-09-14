// SPDX-License-Identifier: MIT
//! Arithmetic lifter: ADD, SUB, CMP, NEG, ABS, INC, DEC, SAT.

use crate::arch::{FlagWrite, Register};
use crate::types::*;

use binaryninja::low_level_il::LowLevelILMutableFunction;

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
            il.set_reg(4, Register::ACC, expr)
                .with_flag_write(FlagWrite::All)
                .append();
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
            il.set_reg(4, Register::ACC, expr)
                .with_flag_write(FlagWrite::All)
                .append();
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
            il.set_reg(4, Register::ACC, expr)
                .with_flag_write(FlagWrite::All)
                .append();
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
            let expr = if is_add {
                il.add(4, p, src)
            } else {
                il.sub(4, p, src)
            };
            il.set_reg(4, Register::P, expr)
                .with_flag_write(FlagWrite::All)
                .append();
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
            il.set_reg(4, Register::ACC, expr)
                .with_flag_write(FlagWrite::All)
                .append();
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
            il.set_reg(4, Register::ACC, expr)
                .with_flag_write(FlagWrite::All)
                .append();
        }
        return true;
    }

    // AX ± #const8
    if matches!(n, InsnId::ADDB_AX_CONST8) {
        if insn.operands.len() >= 2 {
            let reg = reg_by_name(insn.operands[0].display_name());
            let val = il.zx(2, il.const_int(1, insn.operands[1].value as u64));
            il.set_reg(2, reg, il.add(2, il.reg(2, reg), val))
                .with_flag_write(FlagWrite::All)
                .append();
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
            il.set_reg(2, reg, expr)
                .with_flag_write(FlagWrite::All)
                .append();
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
            il.set_reg(4, Register::ACC, il.add(4, il.reg(4, Register::ACC), src))
                .with_flag_write(FlagWrite::All)
                .append();
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
            il.set_reg(size, reg, expr)
                .with_flag_write(FlagWrite::All)
                .append();
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
        il.set_reg(4, Register::ACC, expr)
            .with_flag_write(FlagWrite::All)
            .append();
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
            .with_flag_write(FlagWrite::All)
            .append();
        return true;
    }

    // CMPL ACC, loc32 (32-bit compare)
    if matches!(n, InsnId::CMPL_ACC_LOC32) {
        if let Some(op) = op_at(insn, 0) {
            let lhs = il.reg(4, Register::ACC);
            let rhs = read_op(op, il, 4);
            il.sub(4, lhs, rhs).with_flag_write(FlagWrite::All).append();
        }
        return true;
    }

    // CMPB AX, #const8
    if matches!(n, InsnId::CMPB_AX_CONST8) {
        if insn.operands.len() >= 2 {
            let lhs = il.reg(2, reg_by_name(insn.operands[0].display_name()));
            let rhs = il.zx(2, il.const_int(1, insn.operands[1].value as u64));
            il.sub(2, lhs, rhs).with_flag_write(FlagWrite::All).append();
        }
        return true;
    }

    // CMP AX, loc16
    if matches!(n, InsnId::CMP_AX_LOC16) {
        if insn.operands.len() >= 2 {
            let lhs = il.reg(2, reg_by_name(insn.operands[0].display_name()));
            let rhs = read_op(&insn.operands[1], il, 2);
            il.sub(2, lhs, rhs).with_flag_write(FlagWrite::All).append();
        }
        return true;
    }

    // CMP loc16, #const16
    if matches!(n, InsnId::CMP_LOC16_CONST16) {
        if insn.operands.len() >= 2 {
            let lhs = read_op(&insn.operands[0], il, 2);
            let rhs = il.const_int(2, insn.operands[1].value as u64);
            il.sub(2, lhs, rhs).with_flag_write(FlagWrite::All).append();
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
            .with_flag_write(FlagWrite::All)
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
        il.sub(4, lhs, rhs).with_flag_write(FlagWrite::All).append();
    } else {
        il.unimplemented().append(); // guard: CMP with no operands
    }
    true
}

pub fn lift_misc(insn: &DecodedInstruction, _addr: u64, il: &ILFunc) -> bool {
    match insn.id {
        InsnId::NEG_ACC => {
            il.set_reg(4, Register::ACC, il.neg(4, il.reg(4, Register::ACC)))
                .with_flag_write(FlagWrite::All)
                .append();
        }
        InsnId::NEG_AX => {
            if let Some(op) = op_at(insn, 0) {
                let reg = reg_by_name(op.display_name());
                il.set_reg(2, reg, il.neg(2, il.reg(2, reg)))
                    .with_flag_write(FlagWrite::All)
                    .append();
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
            il.set_reg(4, Register::ACC, il.neg(4, il.reg(4, Register::ACC)))
                .with_flag_write(FlagWrite::All)
                .append();
            il.mark_label(&mut done);
        }
        InsnId::NEG64_ACC_P => {
            // Negate 64-bit ACC:P — negate both halves
            il.set_reg(4, Register::ACC, il.neg(4, il.reg(4, Register::ACC)))
                .with_flag_write(FlagWrite::All)
                .append();
            il.set_reg(4, Register::P, il.neg(4, il.reg(4, Register::P)))
                .append();
        }
        InsnId::NEGTC_ACC => {
            // Negate ACC conditional on TC — simplified to unconditional negate
            let acc = il.reg(4, Register::ACC);
            il.set_reg(4, Register::ACC, il.neg(4, acc))
                .with_flag_write(FlagWrite::All)
                .append();
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
