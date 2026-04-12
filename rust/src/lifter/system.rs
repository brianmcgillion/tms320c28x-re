// SPDX-License-Identifier: MIT
//! System instruction lifter: NOP, EALLOW, EDIS, ESTOP, SETC, CLRC, etc.

use crate::arch::{FlagWrite, Register};
use crate::types::*;

use binaryninja::low_level_il::LowLevelILMutableFunction;
use binaryninja::low_level_il::lifting::LowLevelILLabel;

use super::{op_at, read_op, write_loc, reg_by_name};

type ILFunc = LowLevelILMutableFunction;

pub fn lift(insn: &DecodedInstruction, _addr: u64, il: &ILFunc) -> bool {
    match insn.id {
        // Breakpoints
        InsnId::ESTOP0 | InsnId::ESTOP1 => {
            il.bp().append();
        }

        // EALLOW/EDIS: privilege state — nop is correct
        InsnId::EALLOW | InsnId::EDIS => {
            il.nop().append();
        }

        // Flag manipulation — SETC/CLRC — privilege/mode state
        InsnId::SETC_MODE | InsnId::CLRC_MODE |
        InsnId::SETC_OBJMODE | InsnId::CLRC_OBJMODE |
        InsnId::SETC_M0M1MAP | InsnId::CLRC_M0M1MAP |
        InsnId::SETC_XF | InsnId::CLRC_XF |
        InsnId::CLRC_AMODE | InsnId::CLRC_OVC => {
            il.nop().append();
        }

        // ── Integer MAX/MIN ──
        // MAX AX, loc16: AX = max(AX, loc16)
        InsnId::MAX_AX_LOC16 => {
            if insn.operands.len() >= 2 {
                let reg = reg_by_name(insn.operands[0].display_name());
                let src = read_op(&insn.operands[1], il, 2);
                let dst_val = il.reg(2, reg);
                // if (dst >= src) keep, else dst = src
                let cond = il.cmp_sge(2, dst_val, src);
                let mut keep = LowLevelILLabel::new();
                let mut replace = LowLevelILLabel::new();
                il.if_expr(cond, &mut keep, &mut replace).append();
                il.mark_label(&mut replace);
                il.set_reg(2, reg, read_op(&insn.operands[1], il, 2)).append();
                il.mark_label(&mut keep);
            }
        }
        InsnId::MIN_AX_LOC16 => {
            if insn.operands.len() >= 2 {
                let reg = reg_by_name(insn.operands[0].display_name());
                let src = read_op(&insn.operands[1], il, 2);
                let dst_val = il.reg(2, reg);
                let cond = il.cmp_sle(2, dst_val, src);
                let mut keep = LowLevelILLabel::new();
                let mut replace = LowLevelILLabel::new();
                il.if_expr(cond, &mut keep, &mut replace).append();
                il.mark_label(&mut replace);
                il.set_reg(2, reg, read_op(&insn.operands[1], il, 2)).append();
                il.mark_label(&mut keep);
            }
        }
        // MAXL ACC, loc32
        InsnId::MAXL_ACC_LOC32 => {
            if let Some(op) = op_at(insn, 0) {
                let src = read_op(op, il, 4);
                let acc = il.reg(4, Register::ACC);
                let cond = il.cmp_sge(4, acc, src);
                let mut keep = LowLevelILLabel::new();
                let mut replace = LowLevelILLabel::new();
                il.if_expr(cond, &mut keep, &mut replace).append();
                il.mark_label(&mut replace);
                il.set_reg(4, Register::ACC, read_op(op, il, 4)).append();
                il.mark_label(&mut keep);
            }
        }
        // MAXCUL/MINCUL P, loc32 (unsigned)
        InsnId::MAXCUL_P_LOC32 => {
            if let Some(op) = op_at(insn, 0) {
                let src = read_op(op, il, 4);
                let p = il.reg(4, Register::P);
                let cond = il.cmp_uge(4, p, src);
                let mut keep = LowLevelILLabel::new();
                let mut replace = LowLevelILLabel::new();
                il.if_expr(cond, &mut keep, &mut replace).append();
                il.mark_label(&mut replace);
                il.set_reg(4, Register::P, read_op(op, il, 4)).append();
                il.mark_label(&mut keep);
            }
        }
        InsnId::MINCUL_P_LOC32 => {
            if let Some(op) = op_at(insn, 0) {
                let src = read_op(op, il, 4);
                let p = il.reg(4, Register::P);
                let cond = il.cmp_ule(4, p, src);
                let mut keep = LowLevelILLabel::new();
                let mut replace = LowLevelILLabel::new();
                il.if_expr(cond, &mut keep, &mut replace).append();
                il.mark_label(&mut replace);
                il.set_reg(4, Register::P, read_op(op, il, 4)).append();
                il.mark_label(&mut keep);
            }
        }
        // MINL ACC, loc32
        InsnId::MINL_ACC_LOC32 => {
            if let Some(op) = op_at(insn, 0) {
                let src = read_op(op, il, 4);
                let acc = il.reg(4, Register::ACC);
                let cond = il.cmp_sle(4, acc, src);
                let mut keep = LowLevelILLabel::new();
                let mut replace = LowLevelILLabel::new();
                il.if_expr(cond, &mut keep, &mut replace).append();
                il.mark_label(&mut replace);
                il.set_reg(4, Register::ACC, read_op(op, il, 4)).append();
                il.mark_label(&mut keep);
            }
        }

        // ── I/O port access ──
        InsnId::IN_LOC16_PA => {
            // IN loc16, PA: read from I/O port
            if insn.operands.len() >= 2 {
                let pa_addr = il.const_int(4, insn.operands[1].value as u64 * 2);
                let val = il.load(2, pa_addr).build();
                write_loc(&insn.operands[0], il, 2, val);
            } else { il.nop().append(); }
        }
        InsnId::OUT_PA_LOC16 | InsnId::UOUT_PA_LOC16 => {
            // OUT PA, loc16: write to I/O port
            if insn.operands.len() >= 2 {
                let pa_addr = il.const_int(4, insn.operands[0].value as u64 * 2);
                let val = read_op(&insn.operands[1], il, 2);
                il.store(2, pa_addr, val).append();
            } else { il.nop().append(); }
        }

        // ── Zero operations ──
        InsnId::ZAPA => {
            // Zero ACC, P, and OVC
            il.set_reg(4, Register::ACC, il.const_int(4, 0)).append();
            il.set_reg(4, Register::P, il.const_int(4, 0)).append();
        }

        // ── Interrupt mask manipulation ──
        InsnId::AND_IER_CONST16 => {
            if let Some(op) = op_at(insn, 0) {
                il.set_reg(2, Register::IER,
                    il.and(2, il.reg(2, Register::IER), il.const_int(2, op.value as u64))).append();
            }
        }
        InsnId::OR_IER_CONST16 => {
            if let Some(op) = op_at(insn, 0) {
                il.set_reg(2, Register::IER,
                    il.or(2, il.reg(2, Register::IER), il.const_int(2, op.value as u64))).append();
            }
        }
        InsnId::AND_IFR_CONST16 => {
            if let Some(op) = op_at(insn, 0) {
                il.set_reg(2, Register::IFR,
                    il.and(2, il.reg(2, Register::IFR), il.const_int(2, op.value as u64))).append();
            }
        }
        InsnId::OR_IFR_CONST16 => {
            if let Some(op) = op_at(insn, 0) {
                il.set_reg(2, Register::IFR,
                    il.or(2, il.reg(2, Register::IFR), il.const_int(2, op.value as u64))).append();
            }
        }

        // ── Stack alignment ──
        InsnId::ASP => {
            // Align SP to even boundary
            il.set_reg(2, Register::SP,
                il.and(2, il.reg(2, Register::SP), il.const_int(2, 0xFFFE))).append();
        }

        // ── Instructions that are correctly nop for decompilation ──
        // CSB: count sign bits (result in T, no general IL equivalent)
        // NORM: normalize ACC (specialized DSP op)
        // RPT: repeat next instruction (pipeline control)
        // SPM: set product shift mode (mode bit)
        // IDLE: wait for interrupt
        // ABORTI: abort interrupt
        // NASP: undo stack alignment
        // LPADDR: load PC address (pipeline)
        // IACK: interrupt acknowledge (hardware handshake)
        InsnId::CSB_ACC |
        InsnId::NORM_ACC_IND | InsnId::NORM_ACC_XARN_POSTDEC | InsnId::NORM_ACC_XARN_POSTINC |
        InsnId::RPT_CONST8 | InsnId::RPT_LOC16 |
        InsnId::SPM_SHIFT |
        InsnId::IDLE | InsnId::ABORTI | InsnId::NASP | InsnId::LPADDR |
        InsnId::IACK_CONST16 => {
            il.nop().append();
        }

        _ => {
            il.nop().append(); // remaining system/privilege ops
        }
    }
    true
}
