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
    if matches!(
        n,
        InsnId::MPY_ACC_T_LOC16 | InsnId::MPYU_ACC_T_LOC16 | InsnId::MPYXU_ACC_T_LOC16
    ) {
        if let Some(op) = op_at(insn, 0) {
            let src = read_op(op, il, 2);
            let t = il.reg(2, Register::T);
            let (l, r) = if matches!(n, InsnId::MPYU_ACC_T_LOC16) {
                (il.zx(4, t), il.zx(4, src))
            } else {
                (il.sx(4, t), il.sx(4, src))
            };
            il.set_reg(4, Register::ACC, il.mul(4, l, r))
                .with_flag_write(FlagWrite::NZ)
                .append();
        }
        return true;
    }

    // MPY P, T, loc16 — multiply into P register
    if matches!(
        n,
        InsnId::MPY_P_T_LOC16 | InsnId::MPYU_P_T_LOC16 | InsnId::MPYXU_P_T_LOC16
    ) {
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
            il.set_reg(4, Register::ACC, il.mul(4, t, c))
                .with_flag_write(FlagWrite::NZ)
                .append();
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
                .with_flag_write(FlagWrite::NZ)
                .append();
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

    // ── MPYA P, loc16, #16bit ──
    // SPRU430F p.324 prints three steps: `ACC = ACC + P << PM; T = [loc16];
    // P = signed T * signed 16bit`. There was no arm for this row at all, so a
    // generic path emitted the product alone -- the accumulate was missing and
    // T was never loaded, leaving the multiply reading a stale T.
    if matches!(n, InsnId::MPYA_P_LOC16_CONST16) {
        if let (Some(loc), Some(imm)) = (op_at(insn, 0), op_at(insn, 1)) {
            il.set_reg(
                4,
                Register::ACC,
                il.add(4, il.reg(4, Register::ACC), il.reg(4, Register::P)),
            )
            .with_flag_write(FlagWrite::All)
            .append();
            il.set_reg(2, Register::T, read_op(loc, il, 2)).append();
            let t = il.sx(4, il.reg(2, Register::T));
            let c = il.sx(4, il.const_int(2, imm.value as u64));
            il.set_reg(4, Register::P, il.mul(4, t, c)).append();
        }
        return true;
    }

    // ── Multiply-accumulate: ACC += P; P = T * loc16 ──
    if matches!(n, InsnId::MPYA_P_T_LOC16) {
        if let Some(op) = op_at(insn, 0) {
            // ACC += P
            il.set_reg(
                4,
                Register::ACC,
                il.add(4, il.reg(4, Register::ACC), il.reg(4, Register::P)),
            )
            .with_flag_write(FlagWrite::All)
            .append();
            // P = T * loc16
            let src = read_op(op, il, 2);
            il.set_reg(
                4,
                Register::P,
                il.mul(4, il.sx(4, il.reg(2, Register::T)), il.sx(4, src)),
            )
            .append();
        }
        return true;
    }

    // ── Multiply-subtract: ACC -= P; P = T * loc16 ──
    if matches!(n, InsnId::MPYS_P_T_LOC16) {
        if let Some(op) = op_at(insn, 0) {
            // ACC -= P
            il.set_reg(
                4,
                Register::ACC,
                il.sub(4, il.reg(4, Register::ACC), il.reg(4, Register::P)),
            )
            .with_flag_write(FlagWrite::All)
            .append();
            // P = T * loc16
            let src = read_op(op, il, 2);
            il.set_reg(
                4,
                Register::P,
                il.mul(4, il.sx(4, il.reg(2, Register::T)), il.sx(4, src)),
            )
            .append();
        }
        return true;
    }

    // ── 32-bit multiplies: result = XT * loc32 ──
    if matches!(n, InsnId::IMPYL_ACC_XT_LOC32 | InsnId::QMPYL_ACC_XT_LOC32) {
        if let Some(op) = op_at(insn, 0) {
            let src = read_op(op, il, 4);
            il.set_reg(4, Register::ACC, il.mul(4, il.reg(4, Register::XT), src))
                .with_flag_write(FlagWrite::NZ)
                .append();
        }
        return true;
    }
    // IMPYXUL joins these: TI prints `signed XT * unsigned [loc32]`, and the low
    // 32 bits of a product do not depend on either sign, but it was falling into
    // a generic arm that multiplied **T** -- a different, 16-bit register.
    if matches!(
        n,
        InsnId::IMPYL_P_XT_LOC32 | InsnId::QMPYL_P_XT_LOC32 | InsnId::IMPYXUL_P_XT_LOC32
    ) {
        if let Some(op) = op_at(insn, 0) {
            let src = read_op(op, il, 4);
            il.set_reg(4, Register::P, il.mul(4, il.reg(4, Register::XT), src))
                .append();
        }
        return true;
    }

    // ── 32-bit multiply-accumulate/subtract ──
    if matches!(n, InsnId::IMPYAL_P_XT_LOC32 | InsnId::QMPYAL_P_XT_LOC32) {
        if let Some(op) = op_at(insn, 0) {
            // ACC += P:ACC shift; P = XT * loc32 (simplified: ACC += P, P = XT*loc32)
            il.set_reg(
                4,
                Register::ACC,
                il.add(4, il.reg(4, Register::ACC), il.reg(4, Register::P)),
            )
            .with_flag_write(FlagWrite::All)
            .append();
            il.set_reg(
                4,
                Register::P,
                il.mul(4, il.reg(4, Register::XT), read_op(op, il, 4)),
            )
            .append();
        }
        return true;
    }
    if matches!(n, InsnId::IMPYSL_P_XT_LOC32 | InsnId::QMPYSL_P_XT_LOC32) {
        if let Some(op) = op_at(insn, 0) {
            il.set_reg(
                4,
                Register::ACC,
                il.sub(4, il.reg(4, Register::ACC), il.reg(4, Register::P)),
            )
            .with_flag_write(FlagWrite::All)
            .append();
            il.set_reg(
                4,
                Register::P,
                il.mul(4, il.reg(4, Register::XT), read_op(op, il, 4)),
            )
            .append();
        }
        return true;
    }

    // ── Square: ACC += P; P = loc16 * loc16; T = loc16 ──
    if matches!(n, InsnId::SQRA_LOC16) {
        if let Some(op) = op_at(insn, 0) {
            il.set_reg(
                4,
                Register::ACC,
                il.add(4, il.reg(4, Register::ACC), il.reg(4, Register::P)),
            )
            .with_flag_write(FlagWrite::All)
            .append();
            let src = read_op(op, il, 2);
            il.set_reg(
                4,
                Register::P,
                il.mul(4, il.sx(4, src), il.sx(4, read_op(op, il, 2))),
            )
            .append();
        }
        return true;
    }
    if matches!(n, InsnId::SQRS_LOC16) {
        if let Some(op) = op_at(insn, 0) {
            il.set_reg(
                4,
                Register::ACC,
                il.sub(4, il.reg(4, Register::ACC), il.reg(4, Register::P)),
            )
            .with_flag_write(FlagWrite::All)
            .append();
            let src = read_op(op, il, 2);
            il.set_reg(
                4,
                Register::P,
                il.mul(4, il.sx(4, src), il.sx(4, read_op(op, il, 2))),
            )
            .append();
        }
        return true;
    }

    // ── MAC/XMAC P, loc16, <program memory> ──
    //    SPRU430F states three effects in this order, and the accumulate uses
    //    the *old* P while the multiply uses the *new* T:
    //        ACC = ACC + P << PM;  T = [loc16];  P = sx(T) * sx(Prog[addr]);
    //    `P << PM` is modelled as P throughout this file. XMAC addresses
    //    0x3F:pma; the *XAR7 forms take the word address from XAR7.
    //    XMACD adds `[loc16 + 1] = T`, which needs addressing this lifter
    //    cannot express, so it says so rather than emit three of four effects.
    if matches!(insn.id, InsnId::XMACD_P_LOC16_PMA) {
        il.unimplemented().append();
        return true;
    }
    if matches!(
        insn.id,
        InsnId::XMAC_P_LOC16_PMA | InsnId::MAC_P_LOC16_XAR7 | InsnId::MAC_P_LOC16_XAR7_POSTINC
    ) {
        if let Some(loc) = op_at(insn, 0) {
            il.set_reg(
                4,
                Register::ACC,
                il.add(4, il.reg(4, Register::ACC), il.reg(4, Register::P)),
            )
            .with_flag_write(FlagWrite::All)
            .append();
            let value = read_op(loc, il, 2);
            il.set_reg(2, Register::T, value).append();

            let word = match insn.id {
                InsnId::XMAC_P_LOC16_PMA => il.const_int(
                    4,
                    0x3F_0000 | (op_at(insn, 1).map(|o| o.value as u64).unwrap_or(0) & 0xFFFF),
                ),
                _ => il.reg(4, Register::XAR7),
            };
            let prog = il.load(2, il.lsl(4, word, il.const_int(4, 1))).build();
            il.set_reg(
                4,
                Register::P,
                il.mul(4, il.sx(4, il.reg(2, Register::T)), il.sx(4, prog)),
            )
            .append();

            if matches!(insn.id, InsnId::MAC_P_LOC16_XAR7_POSTINC) {
                il.set_reg(
                    4,
                    Register::XAR7,
                    il.add(4, il.reg(4, Register::XAR7), il.const_int(4, 1)),
                )
                .append();
            }
        }
        return true;
    }

    // ── Fallback: generic T * operand → P ──
    if !insn.operands.is_empty() {
        let src = read_op(&insn.operands[0], il, 2);
        let t = il.reg(2, Register::T);
        il.set_reg(4, Register::P, il.mul(4, il.sx(4, t), il.sx(4, src)))
            .append();
        return true;
    }

    il.unimplemented().append(); // guard: multiply with no operands
    true
}
