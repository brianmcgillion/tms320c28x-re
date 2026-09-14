// SPDX-License-Identifier: MIT
//! Shift/rotate lifter: LSL, LSR, ASR, ROL, ROR, LSL64, LSR64, ASR64.

use crate::arch::{FlagWrite, Register};
use crate::types::*;

use binaryninja::low_level_il::LowLevelILMutableFunction;

use super::{read_op, reg_by_name};

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
    let flagged = expr.with_flag_write(FlagWrite::NZC).build();
    il.set_reg(4, Register::ACC, flagged).append();
    true
}

fn shift_common(insn: &DecodedInstruction, il: &ILFunc, op_name: &str) -> bool {
    let n = insn.id;

    // ── 64-bit shifts: ACC:P as a 64-bit value ──
    // LSL64/LSR64/ASR64 ACC:P, #shift or T
    // Model as: combine ACC:P into 64-bit, shift, split back into ACC and P.
    if matches!(
        n,
        InsnId::LSL64_ACC_P_SHIFT
            | InsnId::LSL64_ACC_P_T
            | InsnId::LSR64_ACC_P_SHIFT
            | InsnId::LSR64_ACC_P_T
            | InsnId::ASR64_ACC_P_SHIFT
            | InsnId::ASR64_ACC_P_T
    ) {
        let shift_amt = if !insn.operands.is_empty() {
            read_op(&insn.operands[0], il, 8)
        } else {
            il.const_int(8, 1)
        };
        // Combine ACC:P into 64-bit: (ACC << 32) | zx(P)
        let acc = il.zx(8, il.reg(4, Register::ACC));
        let p = il.zx(8, il.reg(4, Register::P));
        let combined = il.or(8, il.lsl(8, acc, il.const_int(8, 32)), p);
        // Shift the 64-bit value
        let is_lsl = matches!(n, InsnId::LSL64_ACC_P_SHIFT | InsnId::LSL64_ACC_P_T);
        let is_asr = matches!(n, InsnId::ASR64_ACC_P_SHIFT | InsnId::ASR64_ACC_P_T);
        let shifted = if is_lsl {
            il.lsl(8, combined, shift_amt)
        } else if is_asr {
            il.asr(8, combined, shift_amt)
        } else {
            il.lsr(8, combined, shift_amt)
        };
        // The flag write belongs on the 64-bit shift, not on the `lsr` that
        // extracts the high word afterwards. TI defines all three flags over the
        // combined value -- N is bit 31 of ACC (bit 63 of the pair), Z is the
        // whole 64 bits, C is the last bit shifted out of it -- and that is
        // exactly what BN derives from a flagged 64-bit shift. Flagging the
        // extraction instead would have produced a confident, wrong C.
        let shifted_built = shifted.with_flag_write(FlagWrite::NZC).build();
        // Split back: ACC = high 32 bits, P = low 32 bits
        il.set_reg(
            4,
            Register::ACC,
            il.lsr(8, shifted_built, il.const_int(8, 32)),
        )
        .append();
        il.set_reg(4, Register::P, il.low_part(4, shifted_built))
            .append();
        return true;
    }

    // ── LSLL/LSRL/ASRL ACC, T — long shift by T register ──
    if matches!(
        n,
        InsnId::LSLL_ACC_T | InsnId::LSRL_ACC_T | InsnId::ASRL_ACC_T
    ) {
        let t = il.zx(4, il.reg(2, Register::T));
        let acc = il.reg(4, Register::ACC);
        let expr = if matches!(n, InsnId::LSLL_ACC_T) {
            il.lsl(4, acc, t)
        } else if matches!(n, InsnId::ASRL_ACC_T) {
            il.asr(4, acc, t)
        } else {
            il.lsr(4, acc, t)
        };
        // LSRL and ASRL load C with the last bit shifted out; the LSLL page
        // lists only N and Z, so it is the one shift that leaves C alone.
        let written = if matches!(n, InsnId::LSLL_ACC_T) {
            FlagWrite::NZ
        } else {
            FlagWrite::NZC
        };
        let flagged = expr.with_flag_write(written).build();
        il.set_reg(4, Register::ACC, flagged).append();
        return true;
    }

    // ── LSL/LSR/ASR AX, T — 16-bit shift of AX by T(3:0) ──
    // Only the AX selector is encoded, so these have ONE operand and used to
    // fall into the ACC arm below, which read that selector as the shift
    // amount: `ASR AL, T` lifted as `ACC = ACC s>> AH`. Wrong destination,
    // wrong source, wrong amount and wrong width, all at once.
    // SPRU430F: "...on the content of the specified AX register as specified by
    // the four least significant bits of the T register ... The contents of
    // higher order bits are ignored."
    if matches!(n, InsnId::LSL_AX_T | InsnId::LSR_AX_T | InsnId::ASR_AX_T) {
        if let Some(op) = insn.operands.first() {
            let reg = reg_by_name(op.display_name());
            let amt = il.and(2, il.reg(2, Register::T), il.const_int(2, 0xF));
            let lhs = il.reg(2, reg);
            let expr = match op_name {
                "lsl" => il.lsl(2, lhs, amt),
                "lsr" => il.lsr(2, lhs, amt),
                _ => il.asr(2, lhs, amt),
            };
            let flagged = expr.with_flag_write(FlagWrite::NZC).build();
            il.set_reg(2, reg, flagged).append();
        } else {
            il.unimplemented().append();
        }
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
                _ => unreachable!("shift_common called with invalid op_name"),
            };
            let flagged = expr.with_flag_write(FlagWrite::NZC).build();
            il.set_reg(size, reg, flagged).append();
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
            _ => {
                il.unimplemented().append();
                return true;
            }
        };
        let flagged = expr.with_flag_write(FlagWrite::NZC).build();
        il.set_reg(4, Register::ACC, flagged).append();
        return true;
    }

    il.unimplemented().append(); // guard: shift with no operands
    true
}
