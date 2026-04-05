// SPDX-License-Identifier: MIT
//! Shift/rotate lifter: LSL, LSR, ASR, ROL, ROR, LSL64, LSR64, ASR64.

use crate::arch::{FlagWrite, Register};
use crate::types::*;

use binaryninja::low_level_il::LowLevelILMutableFunction;

use super::{op_at, read_op, reg_by_name};

type ILFunc = LowLevelILMutableFunction;

pub fn lift_lsl(insn: &DecodedInstruction, _addr: u64, il: &ILFunc) -> bool {
    shift_common(insn, il, "lsl")
}

pub fn lift_lsr(insn: &DecodedInstruction, _addr: u64, il: &ILFunc) -> bool {
    shift_common(insn, il, "lsr")
}

pub fn lift_asr(insn: &DecodedInstruction, _addr: u64, il: &ILFunc) -> bool {
    shift_common(insn, il, "asr")
}

pub fn lift_rotate(insn: &DecodedInstruction, _addr: u64, il: &ILFunc) -> bool {
    let acc = il.reg(4, Register::ACC);
    let one = il.const_int(4, 1);
    let n = insn.id;
    let expr = if matches!(n, InsnId::ROL_ACC) {
        il.rol(4, acc, one)
    } else {
        il.ror(4, acc, one)
    };
    il.set_reg(4, Register::ACC, expr)
        .with_flag_write(FlagWrite::All)
        .append();
    true
}

fn shift_common(insn: &DecodedInstruction, il: &ILFunc, op_name: &str) -> bool {
    let n = insn.id;

    // ── 64-bit shifts: ACC:P as a 64-bit value ──
    // LSL64/LSR64/ASR64 ACC:P, #shift or T
    if matches!(n, InsnId::LSL64_ACC_P_SHIFT | InsnId::LSL64_ACC_P_T |
                    InsnId::LSR64_ACC_P_SHIFT | InsnId::LSR64_ACC_P_T |
                    InsnId::ASR64_ACC_P_SHIFT | InsnId::ASR64_ACC_P_T) {
        // Model as: combine ACC:P into 64-bit, shift, split back
        // Simplified: just shift ACC by the amount (approximation for decompilation)
        let shift_amt = if insn.operands.len() >= 1 {
            read_op(&insn.operands[0], il, 4)
        } else {
            il.const_int(4, 1)
        };
        let acc = il.reg(4, Register::ACC);
        let is_lsl = matches!(n, InsnId::LSL64_ACC_P_SHIFT | InsnId::LSL64_ACC_P_T);
        let is_asr = matches!(n, InsnId::ASR64_ACC_P_SHIFT | InsnId::ASR64_ACC_P_T);
        let expr = if is_lsl {
            il.lsl(4, acc, shift_amt)
        } else if is_asr {
            il.asr(4, acc, shift_amt)
        } else {
            il.lsr(4, acc, shift_amt)
        };
        il.set_reg(4, Register::ACC, expr)
            .with_flag_write(FlagWrite::All).append();
        return true;
    }

    // ── LSLL/LSRL/ASRL ACC, T — long shift by T register ──
    if matches!(n, InsnId::LSLL_ACC_T | InsnId::LSRL_ACC_T | InsnId::ASRL_ACC_T) {
        let t = il.zx(4, il.reg(2, Register::T));
        let acc = il.reg(4, Register::ACC);
        let expr = if matches!(n, InsnId::LSLL_ACC_T) {
            il.lsl(4, acc, t)
        } else if matches!(n, InsnId::ASRL_ACC_T) {
            il.asr(4, acc, t)
        } else {
            il.lsr(4, acc, t)
        };
        il.set_reg(4, Register::ACC, expr)
            .with_flag_write(FlagWrite::All).append();
        return true;
    }

    // ── Standard 2-operand shifts ──
    if insn.operands.len() >= 2 {
        let op0 = &insn.operands[0];
        let op1 = &insn.operands[1];

        if op0.op_type == OperandType::Register {
            let reg = reg_by_name(op0.display_name());
            let size = if matches!(reg, Register::ACC) { 4 } else { 2 };
            let lhs = il.reg(size, reg);
            let rhs = read_op(op1, il, size);
            let expr = match op_name {
                "lsl" => il.lsl(size, lhs, rhs),
                "lsr" => il.lsr(size, lhs, rhs),
                "asr" => il.asr(size, lhs, rhs),
                _ => { il.nop().append(); return true; }
            };
            il.set_reg(size, reg, expr)
                .with_flag_write(FlagWrite::All)
                .append();
            return true;
        }
    }

    // ── Single-operand: ACC shift by immediate or T ──
    if insn.operands.len() == 1 {
        let op0 = &insn.operands[0];
        let acc = il.reg(4, Register::ACC);
        let rhs = read_op(op0, il, 4);
        let expr = match op_name {
            "lsl" => il.lsl(4, acc, rhs),
            "lsr" => il.lsr(4, acc, rhs),
            "asr" => il.asr(4, acc, rhs),
            _ => { il.nop().append(); return true; }
        };
        il.set_reg(4, Register::ACC, expr)
            .with_flag_write(FlagWrite::All)
            .append();
        return true;
    }

    il.nop().append();
    true
}
