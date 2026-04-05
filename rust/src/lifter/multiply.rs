// SPDX-License-Identifier: MIT
//! Multiply lifter: MPY, MPYA, MPYS, MPYB, MPYU, IMPYL, QMPYL, SQRA, MAC.

use crate::arch::{FlagWrite, Register};
use crate::types::*;

use binaryninja::low_level_il::LowLevelILMutableFunction;

use super::{op_at, read_op};

type ILFunc = LowLevelILMutableFunction;

pub fn lift(insn: &DecodedInstruction, _addr: u64, il: &ILFunc) -> bool {
    let n = insn.id;

    // ── 16-bit multiplies: result = T * loc16 ──

    // MPY ACC, T, loc16 — signed multiply into ACC
    if matches!(n, InsnId::MPY_ACC_T_LOC16 | InsnId::MPYU_ACC_T_LOC16 | InsnId::MPYXU_ACC_T_LOC16) {
        if let Some(op) = op_at(insn, 0) {
            let src = read_op(op, il, 2);
            let t = il.reg(2, Register::T);
            let (l, r) = if matches!(n, InsnId::MPYU_ACC_T_LOC16) {
                (il.zx(4, t), il.zx(4, src))
            } else {
                (il.sx(4, t), il.sx(4, src))
            };
            il.set_reg(4, Register::ACC, il.mul(4, l, r))
                .with_flag_write(FlagWrite::NZ).append();
        }
        return true;
    }

    // MPY P, T, loc16 — multiply into P register
    if matches!(n, InsnId::MPY_P_T_LOC16 | InsnId::MPYU_P_T_LOC16 | InsnId::MPYXU_P_T_LOC16) {
        if let Some(op) = op_at(insn, 0) {
            let src = read_op(op, il, 2);
            let t = il.reg(2, Register::T);
            let (l, r) = if matches!(n, InsnId::MPYU_P_T_LOC16) {
                (il.zx(4, t), il.zx(4, src))
            } else {
                (il.sx(4, t), il.sx(4, src))
            };
            il.set_reg(4, Register::P, il.mul(4, l, r)).append();
        }
        return true;
    }

    // MPYB ACC/P, T, #const8
    if matches!(n, InsnId::MPYB_ACC_T_CONST8) {
        if let Some(op) = op_at(insn, 0) {
            let t = il.sx(4, il.reg(2, Register::T));
            let c = il.zx(4, il.const_int(1, op.value as u64));
            il.set_reg(4, Register::ACC, il.mul(4, t, c)).append();
        }
        return true;
    }
    if matches!(n, InsnId::MPYB_P_T_CONST8) {
        if let Some(op) = op_at(insn, 0) {
            let t = il.sx(4, il.reg(2, Register::T));
            let c = il.zx(4, il.const_int(1, op.value as u64));
            il.set_reg(4, Register::P, il.mul(4, t, c)).append();
        }
        return true;
    }

    // MPY ACC/P, loc16, #const16
    if matches!(n, InsnId::MPY_ACC_LOC16_CONST16) {
        if insn.operands.len() >= 2 {
            let src = il.sx(4, read_op(&insn.operands[0], il, 2));
            let c = il.sx(4, il.const_int(2, insn.operands[1].value as u64));
            il.set_reg(4, Register::ACC, il.mul(4, src, c))
                .with_flag_write(FlagWrite::NZ).append();
        }
        return true;
    }
    if matches!(n, InsnId::MPY_P_LOC16_CONST16) {
        if insn.operands.len() >= 2 {
            let src = il.sx(4, read_op(&insn.operands[0], il, 2));
            let c = il.sx(4, il.const_int(2, insn.operands[1].value as u64));
            il.set_reg(4, Register::P, il.mul(4, src, c)).append();
        }
        return true;
    }

    // ── Multiply-accumulate: ACC += P; P = T * loc16 ──
    if matches!(n, InsnId::MPYA_P_T_LOC16) {
        if let Some(op) = op_at(insn, 0) {
            // ACC += P
            il.set_reg(4, Register::ACC,
                il.add(4, il.reg(4, Register::ACC), il.reg(4, Register::P))).append();
            // P = T * loc16
            let src = read_op(op, il, 2);
            il.set_reg(4, Register::P,
                il.mul(4, il.sx(4, il.reg(2, Register::T)), il.sx(4, src))).append();
        }
        return true;
    }

    // ── Multiply-subtract: ACC -= P; P = T * loc16 ──
    if matches!(n, InsnId::MPYS_P_T_LOC16) {
        if let Some(op) = op_at(insn, 0) {
            // ACC -= P
            il.set_reg(4, Register::ACC,
                il.sub(4, il.reg(4, Register::ACC), il.reg(4, Register::P))).append();
            // P = T * loc16
            let src = read_op(op, il, 2);
            il.set_reg(4, Register::P,
                il.mul(4, il.sx(4, il.reg(2, Register::T)), il.sx(4, src))).append();
        }
        return true;
    }

    // ── 32-bit multiplies: result = XT * loc32 ──
    if matches!(n, InsnId::IMPYL_ACC_XT_LOC32 | InsnId::QMPYL_ACC_XT_LOC32) {
        if let Some(op) = op_at(insn, 0) {
            let src = read_op(op, il, 4);
            il.set_reg(4, Register::ACC,
                il.mul(4, il.reg(4, Register::XT), src)).append();
        }
        return true;
    }
    if matches!(n, InsnId::IMPYL_P_XT_LOC32 | InsnId::QMPYL_P_XT_LOC32) {
        if let Some(op) = op_at(insn, 0) {
            let src = read_op(op, il, 4);
            il.set_reg(4, Register::P,
                il.mul(4, il.reg(4, Register::XT), src)).append();
        }
        return true;
    }

    // ── 32-bit multiply-accumulate/subtract ──
    if matches!(n, InsnId::IMPYAL_P_XT_LOC32 | InsnId::QMPYAL_P_XT_LOC32) {
        if let Some(op) = op_at(insn, 0) {
            // ACC += P:ACC shift; P = XT * loc32 (simplified: ACC += P, P = XT*loc32)
            il.set_reg(4, Register::ACC,
                il.add(4, il.reg(4, Register::ACC), il.reg(4, Register::P))).append();
            il.set_reg(4, Register::P,
                il.mul(4, il.reg(4, Register::XT), read_op(op, il, 4))).append();
        }
        return true;
    }
    if matches!(n, InsnId::IMPYSL_P_XT_LOC32 | InsnId::QMPYSL_P_XT_LOC32) {
        if let Some(op) = op_at(insn, 0) {
            il.set_reg(4, Register::ACC,
                il.sub(4, il.reg(4, Register::ACC), il.reg(4, Register::P))).append();
            il.set_reg(4, Register::P,
                il.mul(4, il.reg(4, Register::XT), read_op(op, il, 4))).append();
        }
        return true;
    }

    // ── Square: ACC += P; P = loc16 * loc16; T = loc16 ──
    if matches!(n, InsnId::SQRA_LOC16) {
        if let Some(op) = op_at(insn, 0) {
            il.set_reg(4, Register::ACC,
                il.add(4, il.reg(4, Register::ACC), il.reg(4, Register::P))).append();
            let src = read_op(op, il, 2);
            il.set_reg(4, Register::P,
                il.mul(4, il.sx(4, src), il.sx(4, read_op(op, il, 2)))).append();
        }
        return true;
    }
    if matches!(n, InsnId::SQRS_LOC16) {
        if let Some(op) = op_at(insn, 0) {
            il.set_reg(4, Register::ACC,
                il.sub(4, il.reg(4, Register::ACC), il.reg(4, Register::P))).append();
            let src = read_op(op, il, 2);
            il.set_reg(4, Register::P,
                il.mul(4, il.sx(4, src), il.sx(4, read_op(op, il, 2)))).append();
        }
        return true;
    }

    // ── Fallback: generic T * operand → P ──
    if insn.operands.len() >= 1 {
        let src = read_op(&insn.operands[0], il, 2);
        let t = il.reg(2, Register::T);
        il.set_reg(4, Register::P,
            il.mul(4, il.sx(4, t), il.sx(4, src))).append();
        return true;
    }

    il.nop().append();
    true
}
