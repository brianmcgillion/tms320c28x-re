// SPDX-License-Identifier: MIT
//! Arithmetic lifter: ADD, SUB, CMP, NEG, ABS, INC, DEC, SAT.

use crate::arch::{FlagWrite, Register};
use crate::types::*;

use binaryninja::low_level_il::LowLevelILMutableFunction;

use super::{op_at, read_op, write_loc, reg_by_name};

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
            let result = il.add(2, val, il.const_int(2, 1))
                .with_flag_write(FlagWrite::All).build();
            write_loc(op, il, 2, result);
        }
        return true;
    }
    if matches!(n, InsnId::DEC_LOC16) {
        if let Some(op) = op_at(insn, 0) {
            let val = read_op(op, il, 2);
            let result = il.sub(2, val, il.const_int(2, 1))
                .with_flag_write(FlagWrite::All).build();
            write_loc(op, il, 2, result);
        }
        return true;
    }

    // ACC ± loc16 (sign-extended to 32-bit)
    if matches!(n, InsnId::ADD_ACC_LOC16 | InsnId::SUB_ACC_LOC16) {
        if let Some(op) = op_at(insn, 0) {
            let src = il.sx(4, read_op(op, il, 2));
            let acc = il.reg(4, Register::ACC);
            let expr = if is_add { il.add(4, acc, src) } else { il.sub(4, acc, src) };
            il.set_reg(4, Register::ACC, expr)
                .with_flag_write(FlagWrite::All).append();
        }
        return true;
    }

    // ACC ± #const8
    if matches!(n, InsnId::ADDB_ACC_CONST8 | InsnId::SUBB_ACC_CONST8) {
        if let Some(op) = op_at(insn, 0) {
            let src = il.zx(4, il.const_int(1, op.value as u64));
            let acc = il.reg(4, Register::ACC);
            let expr = if is_add { il.add(4, acc, src) } else { il.sub(4, acc, src) };
            il.set_reg(4, Register::ACC, expr)
                .with_flag_write(FlagWrite::All).append();
        }
        return true;
    }

    // ACC ± loc32 (32-bit)
    if matches!(n, InsnId::ADDL_ACC_LOC32 | InsnId::SUBL_ACC_LOC32 |
                    InsnId::ADDUL_ACC_LOC32 | InsnId::SUBUL_ACC_LOC32) {
        if let Some(op) = op_at(insn, 0) {
            let src = read_op(op, il, 4);
            let acc = il.reg(4, Register::ACC);
            let expr = if is_add { il.add(4, acc, src) } else { il.sub(4, acc, src) };
            il.set_reg(4, Register::ACC, expr)
                .with_flag_write(FlagWrite::All).append();
        }
        return true;
    }

    // loc32 ± ACC
    if matches!(n, InsnId::ADDL_LOC32_ACC | InsnId::SUBL_LOC32_ACC) {
        if let Some(op) = op_at(insn, 0) {
            let src = read_op(op, il, 4);
            let acc = il.reg(4, Register::ACC);
            let expr = if is_add { il.add(4, src, acc) } else { il.sub(4, src, acc) };
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
            let expr = if is_add { il.add(4, p, src) } else { il.sub(4, p, src) };
            il.set_reg(4, Register::P, expr)
                .with_flag_write(FlagWrite::All).append();
        }
        return true;
    }

    // SP ± #const7 — no flag write
    if matches!(n, InsnId::ADDB_SP_CONST7 | InsnId::SUBB_SP_CONST7) {
        if let Some(op) = op_at(insn, 0) {
            let expr = if is_add {
                il.add(2, il.reg(2, Register::SP), il.const_int(2, op.value as u64))
            } else {
                il.sub(2, il.reg(2, Register::SP), il.const_int(2, op.value as u64))
            };
            il.set_reg(2, Register::SP, expr).append();
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
            let expr = if is_add { il.add(2, lhs, rhs) } else { il.sub(2, lhs, rhs) };
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
    if matches!(n, InsnId::ADD_ACC_LOC16_SHIFT0_15 | InsnId::ADD_ACC_LOC16_SHIFT16 |
                    InsnId::ADD_ACC_LOC16_SHIFT1_15 | InsnId::ADD_ACC_LOC16_SHIFT_T |
                    InsnId::SUB_ACC_LOC16_SHIFT16 | InsnId::SUB_ACC_LOC16_SHIFT1_15_OBJMODE1 |
                    InsnId::SUB_ACC_LOC16_SHIFT_T | InsnId::SUB_ACC_CONST16_SHIFT |
                    InsnId::ADD_ACC_CONST16_SHIFT) {
        // Simplified: ignore shift amount, just add/sub the value sign-extended
        if let Some(op) = op_at(insn, 0) {
            let src = il.sx(4, read_op(op, il, 2));
            let acc = il.reg(4, Register::ACC);
            let expr = if is_add { il.add(4, acc, src) } else { il.sub(4, acc, src) };
            il.set_reg(4, Register::ACC, expr)
                .with_flag_write(FlagWrite::All).append();
        }
        return true;
    }

    // Unsigned ACC ± loc16
    if matches!(n, InsnId::ADDU_ACC_LOC16 | InsnId::SUBU_ACC_LOC16) {
        if let Some(op) = op_at(insn, 0) {
            let src = il.zx(4, read_op(op, il, 2));
            let acc = il.reg(4, Register::ACC);
            let expr = if is_add { il.add(4, acc, src) } else { il.sub(4, acc, src) };
            il.set_reg(4, Register::ACC, expr)
                .with_flag_write(FlagWrite::All).append();
        }
        return true;
    }

    // AX ± #const8
    if matches!(n, InsnId::ADDB_AX_CONST8) {
        if insn.operands.len() >= 2 {
            let reg = reg_by_name(insn.operands[0].display_name());
            let val = il.zx(2, il.const_int(1, insn.operands[1].value as u64));
            il.set_reg(2, reg, il.add(2, il.reg(2, reg), val))
                .with_flag_write(FlagWrite::All).append();
        }
        return true;
    }

    // AX ± loc16
    if matches!(n, InsnId::ADD_AX_LOC16 | InsnId::SUB_AX_LOC16) {
        if insn.operands.len() >= 2 {
            let reg = reg_by_name(insn.operands[0].display_name());
            let src = read_op(&insn.operands[1], il, 2);
            let expr = if is_add { il.add(2, il.reg(2, reg), src) } else { il.sub(2, il.reg(2, reg), src) };
            il.set_reg(2, reg, expr)
                .with_flag_write(FlagWrite::All).append();
        }
        return true;
    }

    // Add with carry
    if matches!(n, InsnId::ADDCU_ACC_LOC16 | InsnId::ADDCL_ACC_LOC32) {
        if let Some(op) = op_at(insn, 0) {
            let size = if matches!(n, InsnId::ADDCL_ACC_LOC32) { 4 } else { 2 };
            let src = if size == 2 { il.zx(4, read_op(op, il, 2)).build() } else { read_op(op, il, 4) };
            il.set_reg(4, Register::ACC, il.add(4, il.reg(4, Register::ACC), src))
                .with_flag_write(FlagWrite::All).append();
        }
        return true;
    }

    // Generic 2-operand: reg ± operand
    if insn.operands.len() >= 2 {
        let op0 = &insn.operands[0];
        let op1 = &insn.operands[1];

        if op0.op_type == OperandType::Register {
            let reg = reg_by_name(op0.display_name());
            let size = if matches!(reg, Register::ACC | Register::P | Register::XT |
                Register::XAR0 | Register::XAR1 | Register::XAR2 | Register::XAR3 |
                Register::XAR4 | Register::XAR5 | Register::XAR6 | Register::XAR7) { 4 } else { 2 };
            let src = read_op(op1, il, size);
            let expr = if is_add {
                il.add(size, il.reg(size, reg), src)
            } else {
                il.sub(size, il.reg(size, reg), src)
            };
            il.set_reg(size, reg, expr)
                .with_flag_write(FlagWrite::All).append();
            return true;
        }
    }

    // Single-operand add/sub: ACC ± operand (implicit ACC destination)
    if insn.operands.len() == 1 {
        let op = &insn.operands[0];
        let src = il.sx(4, read_op(op, il, 2));
        let acc = il.reg(4, Register::ACC);
        let expr = if is_add { il.add(4, acc, src) } else { il.sub(4, acc, src) };
        il.set_reg(4, Register::ACC, expr)
            .with_flag_write(FlagWrite::All).append();
        return true;
    }

    il.nop().append(); // guard: should not be reached for valid decoded instructions
    true
}

pub fn lift_cmp(insn: &DecodedInstruction, _addr: u64, il: &ILFunc) -> bool {
    let n = insn.id;

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
        let size = if op0.op_type == OperandType::Loc32 { 4 } else { 2 };
        let lhs = read_op(op0, il, size);
        let rhs = read_op(op1, il, size);
        il.sub(size, lhs, rhs).with_flag_write(FlagWrite::All).append();
    } else if insn.operands.len() == 1 {
        // Single-operand compare: CMP ACC, operand (implicit ACC)
        let op = &insn.operands[0];
        let size = if op.op_type == OperandType::Loc32 { 4 } else { 2 };
        let lhs = il.reg(4, Register::ACC);
        let rhs = if size == 2 { il.sx(4, read_op(op, il, 2)).build() } else { read_op(op, il, 4) };
        il.sub(4, lhs, rhs).with_flag_write(FlagWrite::All).append();
    } else {
        il.nop().append(); // guard: CMP with no operands
    }
    true
}

pub fn lift_misc(insn: &DecodedInstruction, _addr: u64, il: &ILFunc) -> bool {
    match insn.id {
        InsnId::NEG_ACC => {
            il.set_reg(4, Register::ACC, il.neg(4, il.reg(4, Register::ACC)))
                .with_flag_write(FlagWrite::All).append();
        }
        InsnId::NEG_AX => {
            if let Some(op) = op_at(insn, 0) {
                let reg = reg_by_name(op.display_name());
                il.set_reg(2, reg, il.neg(2, il.reg(2, reg)))
                    .with_flag_write(FlagWrite::All).append();
            }
        }
        InsnId::TEST_ACC => {
            // TEST ACC: sets N, Z flags based on ACC value (like CMP ACC, 0)
            il.sub(4, il.reg(4, Register::ACC), il.const_int(4, 0))
                .with_flag_write(FlagWrite::NZ).append();
        }
        InsnId::ABS_ACC => {
            let acc = il.reg(4, Register::ACC);
            il.set_reg(4, Register::ACC, il.neg(4, acc))
                .with_flag_write(FlagWrite::All).append();
        }
        // ABS16 is a MOV variant (MOV_ABS16_LOC16), not an Abs semantic — handled in mov.rs
        InsnId::ABSTC_ACC => {
            // ABS with TC flag — negate ACC if TC set
            let acc = il.reg(4, Register::ACC);
            il.set_reg(4, Register::ACC, il.neg(4, acc))
                .with_flag_write(FlagWrite::All).append();
        }
        InsnId::NEG64_ACC_P => {
            // Negate 64-bit ACC:P — negate both halves
            il.set_reg(4, Register::ACC, il.neg(4, il.reg(4, Register::ACC)))
                .with_flag_write(FlagWrite::All).append();
            il.set_reg(4, Register::P, il.neg(4, il.reg(4, Register::P))).append();
        }
        InsnId::NEGTC_ACC => {
            // Negate ACC conditional on TC — simplified to unconditional negate
            let acc = il.reg(4, Register::ACC);
            il.set_reg(4, Register::ACC, il.neg(4, acc))
                .with_flag_write(FlagWrite::All).append();
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
                    .with_flag_write(FlagWrite::All).append();
            }
        }
        InsnId::TBIT_LOC16_T => {
            // Test bit at position T of loc16
            if let Some(op) = op_at(insn, 0) {
                let val = read_op(op, il, 2);
                let t = il.zx(2, il.reg(2, Register::T));
                il.and(2, il.lsr(2, val, t), il.const_int(2, 1))
                    .with_flag_write(FlagWrite::All).append();
            }
        }
        InsnId::TCLR_LOC16_BIT => {
            // Test bit N then clear it
            if insn.operands.len() >= 2 {
                let bit = insn.operands[1].value as u64;
                let val = read_op(&insn.operands[0], il, 2);
                il.and(2, il.lsr(2, val, il.const_int(2, bit)), il.const_int(2, 1))
                    .with_flag_write(FlagWrite::All).append();
                let mask = il.const_int(2, !(1u16 as u64) << bit & 0xFFFF);
                let cleared = il.and(2, read_op(&insn.operands[0], il, 2), mask)
                    .with_flag_write(FlagWrite::NZ).build();
                write_loc(&insn.operands[0], il, 2, cleared);
            }
        }
        InsnId::TSET_LOC16_BIT => {
            // Test bit N then set it
            if insn.operands.len() >= 2 {
                let bit = insn.operands[1].value as u64;
                let val = read_op(&insn.operands[0], il, 2);
                il.and(2, il.lsr(2, val, il.const_int(2, bit)), il.const_int(2, 1))
                    .with_flag_write(FlagWrite::All).append();
                let mask = il.const_int(2, 1u64 << bit);
                let set_val = il.or(2, read_op(&insn.operands[0], il, 2), mask)
                    .with_flag_write(FlagWrite::NZ).build();
                write_loc(&insn.operands[0], il, 2, set_val);
            }
        }
        _ => {
            il.nop().append(); // guard: unmatched misc arithmetic
        }
    }
    true
}
