// SPDX-License-Identifier: MIT
//! System instruction lifter: NOP, EALLOW, EDIS, ESTOP, SETC, CLRC, etc.

use crate::arch::{Flag, Register};
use crate::types::*;

use binaryninja::low_level_il::lifting::LowLevelILLabel;
use binaryninja::low_level_il::LowLevelILMutableFunction;

use super::{op_at, read_op, reg_by_name, write_loc};

type ILFunc = LowLevelILMutableFunction;

/// Which comparison decides that the destination is already the answer.
#[derive(Clone, Copy)]
pub(crate) enum Keep {
    Sge,
    Sle,
    Uge,
    Ule,
}

/// `if !keep(reg, src) { reg = src }` — the MAX/MIN shape, written out six
/// times between this file and fpu.rs before this existed.
pub(crate) fn emit_select(il: &ILFunc, size: usize, reg: Register, op: &Operand, keep: Keep) {
    let dst = il.reg(size, reg);
    let src = read_op(op, il, size);
    let cond = match keep {
        Keep::Sge => il.cmp_sge(size, dst, src).build(),
        Keep::Sle => il.cmp_sle(size, dst, src).build(),
        Keep::Uge => il.cmp_uge(size, dst, src).build(),
        Keep::Ule => il.cmp_ule(size, dst, src).build(),
    };
    let mut keep_label = LowLevelILLabel::new();
    let mut replace = LowLevelILLabel::new();
    il.if_expr(cond, &mut keep_label, &mut replace).append();
    il.mark_label(&mut replace);
    il.set_reg(size, reg, read_op(op, il, size)).append();
    il.mark_label(&mut keep_label);
}

pub fn lift(insn: &DecodedInstruction, _addr: u64, il: &ILFunc) -> bool {
    match insn.id {
        // CPU halt: emit bp() for debugger semantic, then no_ret() so the
        // CFG terminates here and BN does not fall through to padding.
        InsnId::ESTOP0 | InsnId::ESTOP1 => {
            il.bp().append();
            il.no_ret().append();
        }

        // EALLOW/EDIS: privilege state — nop is correct
        InsnId::EALLOW | InsnId::EDIS => {
            il.nop().append();
        }

        // SETC/CLRC #mode8: set/clear the status flags named by the imm8 mask.
        // ST0 bit map (TI SPRU430 / dis2000 rendering): bit0=SXM 1=OVM 2=TC 3=C
        // 4=INTM 5=DBGM 6=PAGE0 7=VMAP. Only OVM/TC/C are BN-modeled flags; emit
        // a single-flag write for each of those present. The mode-only bits
        // (SXM/INTM/DBGM/PAGE0/VMAP) have no IL representation and are skipped.
        InsnId::SETC_MODE | InsnId::CLRC_MODE => {
            let set = matches!(insn.id, InsnId::SETC_MODE);
            let mask = insn.operands.first().map(|o| o.value as u32).unwrap_or(0);
            let mut any = false;
            for (bit, flag) in [(1u32, Flag::OVM), (2, Flag::TC), (3, Flag::C)] {
                if mask & (1 << bit) != 0 {
                    il.set_flag(flag, il.const_int(0, if set { 1 } else { 0 }))
                        .append();
                    any = true;
                }
            }
            if !any {
                il.nop().append(); // pure mode-bit form — no IL effect
            }
        }
        // Single named mode/privilege bits — no IL representation.
        InsnId::SETC_OBJMODE
        | InsnId::CLRC_OBJMODE
        | InsnId::SETC_M0M1MAP
        | InsnId::CLRC_M0M1MAP
        | InsnId::SETC_XF
        | InsnId::CLRC_XF
        | InsnId::CLRC_AMODE
        | InsnId::CLRC_OVC => {
            il.nop().append();
        }

        // ── Integer MAX/MIN ──
        // MAX AX, loc16: AX = max(AX, loc16)
        InsnId::MAX_AX_LOC16 => {
            if insn.operands.len() >= 2 {
                let reg = reg_by_name(insn.operands[0].display_name());
                emit_select(il, 2, reg, &insn.operands[1], Keep::Sge);
            }
        }
        InsnId::MIN_AX_LOC16 => {
            if insn.operands.len() >= 2 {
                let reg = reg_by_name(insn.operands[0].display_name());
                emit_select(il, 2, reg, &insn.operands[1], Keep::Sle);
            }
        }
        // MAXL ACC, loc32
        InsnId::MAXL_ACC_LOC32 => {
            if let Some(op) = op_at(insn, 0) {
                emit_select(il, 4, Register::ACC, op, Keep::Sge);
            }
        }
        // MAXCUL/MINCUL P, loc32 (unsigned)
        InsnId::MAXCUL_P_LOC32 => {
            if let Some(op) = op_at(insn, 0) {
                emit_select(il, 4, Register::P, op, Keep::Uge);
            }
        }
        InsnId::MINCUL_P_LOC32 => {
            if let Some(op) = op_at(insn, 0) {
                emit_select(il, 4, Register::P, op, Keep::Ule);
            }
        }
        // MINL ACC, loc32
        InsnId::MINL_ACC_LOC32 => {
            if let Some(op) = op_at(insn, 0) {
                emit_select(il, 4, Register::ACC, op, Keep::Sle);
            }
        }

        // ── I/O port access ──
        InsnId::IN_LOC16_PA => {
            // IN loc16, PA: read from I/O port
            if insn.operands.len() >= 2 {
                let pa_addr = il.const_int(4, insn.operands[1].value as u64 * 2);
                let val = il.load(2, pa_addr).build();
                write_loc(&insn.operands[0], il, 2, val);
            } else {
                il.nop().append();
            }
        }
        InsnId::OUT_PA_LOC16 | InsnId::UOUT_PA_LOC16 => {
            // OUT PA, loc16: write to I/O port
            if insn.operands.len() >= 2 {
                let pa_addr = il.const_int(4, insn.operands[0].value as u64 * 2);
                let val = read_op(&insn.operands[1], il, 2);
                il.store(2, pa_addr, val).append();
            } else {
                il.nop().append();
            }
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
                il.set_reg(
                    2,
                    Register::IER,
                    il.and(
                        2,
                        il.reg(2, Register::IER),
                        il.const_int(2, op.value as u64),
                    ),
                )
                .append();
            }
        }
        InsnId::OR_IER_CONST16 => {
            if let Some(op) = op_at(insn, 0) {
                il.set_reg(
                    2,
                    Register::IER,
                    il.or(
                        2,
                        il.reg(2, Register::IER),
                        il.const_int(2, op.value as u64),
                    ),
                )
                .append();
            }
        }
        InsnId::AND_IFR_CONST16 => {
            if let Some(op) = op_at(insn, 0) {
                il.set_reg(
                    2,
                    Register::IFR,
                    il.and(
                        2,
                        il.reg(2, Register::IFR),
                        il.const_int(2, op.value as u64),
                    ),
                )
                .append();
            }
        }
        InsnId::OR_IFR_CONST16 => {
            if let Some(op) = op_at(insn, 0) {
                il.set_reg(
                    2,
                    Register::IFR,
                    il.or(
                        2,
                        il.reg(2, Register::IFR),
                        il.const_int(2, op.value as u64),
                    ),
                )
                .append();
            }
        }

        // ── Instructions that are correctly nop for decompilation ──
        // CSB: count sign bits (result in T, no general IL equivalent)
        // NORM: normalize ACC (specialized DSP op)
        // RPT: repeat next instruction (pipeline control)
        // SPM: set product shift mode (mode bit)
        // IDLE: wait for interrupt
        // ABORTI: abort interrupt
        // ASP/NASP: ASP aligns SP to an even boundary and records whether it moved
        // in SPA; NASP undoes it. ASP previously did SP &= 0xFFFE, which rounds
        // DOWN -- TI rounds UP -- while NASP was already a nop, so the pair never
        // balanced. Both are nops here: correct whenever SP is already even, and
        // strictly better than a wrong-direction adjustment. Modelling SPA
        // properly belongs with the rest of the SP model in B2.
        // NASP: undo stack alignment
        // LPADDR: load PC address (pipeline)
        // IACK: interrupt acknowledge (hardware handshake)
        InsnId::CSB_ACC
        | InsnId::NORM_ACC_IND
        | InsnId::NORM_ACC_XARN_POSTDEC
        | InsnId::NORM_ACC_XARN_POSTINC
        | InsnId::RPT_CONST8
        | InsnId::RPT_LOC16
        | InsnId::SPM_SHIFT
        | InsnId::ASP
        | InsnId::IDLE
        | InsnId::ABORTI
        | InsnId::NASP
        | InsnId::LPADDR
        | InsnId::IACK_CONST16 => {
            il.nop().append();
        }

        _ => {
            il.unimplemented().append(); // remaining system/privilege ops
        }
    }
    true
}
