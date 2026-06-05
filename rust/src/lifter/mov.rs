// SPDX-License-Identifier: MIT
//! MOV/MOVB/MOVL/MOVZ/MOVU/PUSH/POP lifter handlers.

use crate::arch::Register;
use crate::types::*;

use binaryninja::low_level_il::LowLevelILMutableFunction;

use super::{op_at, read_op, write_loc, reg_by_name, ar_reg};
use binaryninja::low_level_il::lifting::LowLevelILLabel;

type ILFunc = LowLevelILMutableFunction;

/// Emit C28x PUSH: [SP] = val; SP += words (stack grows upward)
fn emit_push_reg(il: &ILFunc, reg: Register, size: usize) {
    let sp_byte = il.lsl(4, il.zx(4, il.reg(2, Register::SP)), il.const_int(4, 1));
    il.store(size, sp_byte, il.reg(size, reg)).append();
    il.set_reg(2, Register::SP,
        il.add(2, il.reg(2, Register::SP), il.const_int(2, (size / 2) as u64))).append();
}

/// Emit C28x POP: SP -= words; val = [SP]
fn emit_pop_reg(il: &ILFunc, reg: Register, size: usize) {
    il.set_reg(2, Register::SP,
        il.sub(2, il.reg(2, Register::SP), il.const_int(2, (size / 2) as u64))).append();
    let sp_byte = il.lsl(4, il.zx(4, il.reg(2, Register::SP)), il.const_int(4, 1));
    il.set_reg(size, reg, il.load(size, sp_byte)).append();
}

pub fn lift(insn: &DecodedInstruction, _addr: u64, il: &ILFunc) -> bool {
    let n = insn.id;

    // ── PUSH/POP ──
    if matches!(n, InsnId::PUSH_LOC16) {
        if let Some(op) = op_at(insn, 0) {
            let val = read_op(op, il, 2);
            let sp_byte = il.lsl(4, il.zx(4, il.reg(2, Register::SP)), il.const_int(4, 1));
            il.store(2, sp_byte, val).append();
            il.set_reg(2, Register::SP, il.add(2, il.reg(2, Register::SP), il.const_int(2, 1))).append();
        }
        return true;
    }
    if matches!(n, InsnId::POP_LOC16) {
        if let Some(op) = op_at(insn, 0) {
            il.set_reg(2, Register::SP, il.sub(2, il.reg(2, Register::SP), il.const_int(2, 1))).append();
            let sp_byte = il.lsl(4, il.zx(4, il.reg(2, Register::SP)), il.const_int(4, 1));
            write_loc(op, il, 2, il.load(2, sp_byte).build());
        }
        return true;
    }
    match n {
        InsnId::PUSH_ST0 => { emit_push_reg(il, Register::ST0, 2); return true; }
        InsnId::PUSH_ST1 => { emit_push_reg(il, Register::ST1, 2); return true; }
        InsnId::PUSH_DP => { emit_push_reg(il, Register::DP, 2); return true; }
        InsnId::PUSH_RPC => { emit_push_reg(il, Register::RPC, 4); return true; }
        InsnId::PUSH_IFR => { emit_push_reg(il, Register::IFR, 2); return true; }
        InsnId::PUSH_DBGIER => { emit_push_reg(il, Register::DBGIER, 2); return true; }
        InsnId::PUSH_P => { emit_push_reg(il, Register::P, 4); return true; }
        InsnId::PUSH_XT => { emit_push_reg(il, Register::XT, 4); return true; }
        InsnId::PUSH_AR1_AR0 => { emit_push_reg(il, Register::AR0, 2); emit_push_reg(il, Register::AR1, 2); return true; }
        InsnId::PUSH_AR3_AR2 => { emit_push_reg(il, Register::AR2, 2); emit_push_reg(il, Register::AR3, 2); return true; }
        InsnId::PUSH_AR5_AR4 => { emit_push_reg(il, Register::AR4, 2); emit_push_reg(il, Register::AR5, 2); return true; }
        InsnId::PUSH_DP_ST1 => { emit_push_reg(il, Register::ST1, 2); emit_push_reg(il, Register::DP, 2); return true; }
        InsnId::PUSH_T_ST0 => { emit_push_reg(il, Register::ST0, 2); emit_push_reg(il, Register::T, 2); return true; }
        InsnId::POP_ST0 => { emit_pop_reg(il, Register::ST0, 2); return true; }
        InsnId::POP_ST1 => { emit_pop_reg(il, Register::ST1, 2); return true; }
        InsnId::POP_DP => { emit_pop_reg(il, Register::DP, 2); return true; }
        InsnId::POP_RPC => { emit_pop_reg(il, Register::RPC, 4); return true; }
        InsnId::POP_IFR => { emit_pop_reg(il, Register::IFR, 2); return true; }
        InsnId::POP_DBGIER => { emit_pop_reg(il, Register::DBGIER, 2); return true; }
        InsnId::POP_P => { emit_pop_reg(il, Register::P, 4); return true; }
        InsnId::POP_XT => { emit_pop_reg(il, Register::XT, 4); return true; }
        InsnId::POP_AR1_AR0 => { emit_pop_reg(il, Register::AR1, 2); emit_pop_reg(il, Register::AR0, 2); return true; }
        InsnId::POP_AR3_AR2 => { emit_pop_reg(il, Register::AR3, 2); emit_pop_reg(il, Register::AR2, 2); return true; }
        InsnId::POP_AR5_AR4 => { emit_pop_reg(il, Register::AR5, 2); emit_pop_reg(il, Register::AR4, 2); return true; }
        InsnId::POP_DP_ST1 => { emit_pop_reg(il, Register::DP, 2); emit_pop_reg(il, Register::ST1, 2); return true; }
        InsnId::POP_T_ST0 => { emit_pop_reg(il, Register::T, 2); emit_pop_reg(il, Register::ST0, 2); return true; }
        InsnId::PUSH_RB => { emit_push_reg(il, Register::RB, 2); return true; }
        InsnId::POP_RB => { emit_pop_reg(il, Register::RB, 2); return true; }
        // PUSH/POP AR1H:AR0H — the high 16 bits of XAR0/XAR1 (no standalone
        // ARnH register in the model). Push AR0H (low addr) then AR1H, 16-bit
        // each; pop reverses and reconstructs the high half, preserving the low.
        InsnId::PUSH_AR1H_AR0H => {
            for reg in [Register::XAR0, Register::XAR1] {
                let sp_byte = il.lsl(4, il.zx(4, il.reg(2, Register::SP)), il.const_int(4, 1));
                il.store(2, sp_byte, il.lsr(4, il.reg(4, reg), il.const_int(4, 16))).append();
                il.set_reg(2, Register::SP, il.add(2, il.reg(2, Register::SP), il.const_int(2, 1))).append();
            }
            return true;
        }
        InsnId::POP_AR1H_AR0H => {
            for reg in [Register::XAR1, Register::XAR0] {
                il.set_reg(2, Register::SP, il.sub(2, il.reg(2, Register::SP), il.const_int(2, 1))).append();
                let sp_byte = il.lsl(4, il.zx(4, il.reg(2, Register::SP)), il.const_int(4, 1));
                let hi = il.lsl(4, il.zx(4, il.load(2, sp_byte)), il.const_int(4, 16));
                let lo = il.and(4, il.reg(4, reg), il.const_int(4, 0xFFFF));
                il.set_reg(4, reg, il.or(4, lo, hi)).append();
            }
            return true;
        }
        _ => {}
    }

    // ── SP adjustment ──
    if matches!(n, InsnId::ADDB_SP_CONST7) {
        if let Some(op) = op_at(insn, 0) {
            il.set_reg(2, Register::SP, il.add(2, il.reg(2, Register::SP), il.const_int(2, op.value as u64))).append();
        }
        return true;
    }
    if matches!(n, InsnId::SUBB_SP_CONST7) {
        if let Some(op) = op_at(insn, 0) {
            il.set_reg(2, Register::SP, il.sub(2, il.reg(2, Register::SP), il.const_int(2, op.value as u64))).append();
        }
        return true;
    }

    // ── MOV_LOC16_0: store zero ──
    if matches!(n, InsnId::MOV_LOC16_0) {
        if let Some(op) = op_at(insn, 0) {
            write_loc(op, il, 2, il.const_int(2, 0));
        }
        return true;
    }

    // ── MOVB ACC, #const8: zero-extend 8-bit to 32-bit ACC ──
    if matches!(n, InsnId::MOVB_ACC_CONST8) {
        if let Some(op) = op_at(insn, 0) {
            il.set_reg(4, Register::ACC, il.zx(4, il.const_int(1, op.value as u64))).append();
        }
        return true;
    }

    // ── MOVU ACC, loc16: unsigned (zero-extend) load to ACC ──
    if matches!(n, InsnId::MOVU_ACC_LOC16) {
        if let Some(op) = op_at(insn, 0) {
            il.set_reg(4, Register::ACC, il.zx(4, read_op(op, il, 2))).append();
        }
        return true;
    }

    // ── MOV/MOVZ DP, #10bit: load 10-bit const to DP. MOVZ additionally zeros
    //    DP[15:10]; since both write the full 10-bit value and the model treats
    //    DP as a flat 16-bit reg, `DP = const10` covers both. ──
    if matches!(n, InsnId::MOV_DP_CONST10 | InsnId::MOVZ_DP_CONST10) {
        if let Some(op) = op_at(insn, 0) {
            il.set_reg(2, Register::DP, il.const_int(2, op.value as u64)).append();
        }
        return true;
    }

    // ── MOV_LOC16_ARN: store ARn to loc16 (n encoded in opcode) ──
    if matches!(n, InsnId::MOV_LOC16_ARN) {
        if insn.operands.len() >= 2 {
            let dst = &insn.operands[0];
            let src = &insn.operands[1];
            write_loc(dst, il, 2, read_op(src, il, 2));
        } else if let Some(op) = op_at(insn, 0) {
            // ARn may be encoded in opcode bits
            write_loc(op, il, 2, il.reg(2, Register::AR0)); // fallback
        }
        return true;
    }

    // ── MOV ACC, #const16 << shift ──
    if matches!(n, InsnId::MOV_ACC_CONST16_SHIFT) {
        if insn.operands.len() >= 2 {
            let val = insn.operands[0].value as u64;
            let shift = insn.operands[1].value as u64;
            let shifted = il.lsl(4, il.sx(4, il.const_int(2, val)), il.const_int(4, shift));
            il.set_reg(4, Register::ACC, shifted).append();
        } else if let Some(op) = op_at(insn, 0) {
            il.set_reg(4, Register::ACC, il.sx(4, il.const_int(2, op.value as u64))).append();
        }
        return true;
    }

    // ── MOVB XARn, #const8 ──
    match n {
        InsnId::MOVB_XAR0_CONST8 | InsnId::MOVB_XAR1_CONST8 | InsnId::MOVB_XAR2_CONST8 |
        InsnId::MOVB_XAR3_CONST8 | InsnId::MOVB_XAR4_CONST8 | InsnId::MOVB_XAR5_CONST8 |
        InsnId::MOVB_XAR6_CONST8 | InsnId::MOVB_XAR7_CONST8 => {
            if let Some(op) = op_at(insn, 0) {
                // Extract XARn index from instruction name via the generated enum
                let reg = match n {
                    InsnId::MOVB_XAR0_CONST8 => Register::XAR0, InsnId::MOVB_XAR1_CONST8 => Register::XAR1,
                    InsnId::MOVB_XAR2_CONST8 => Register::XAR2, InsnId::MOVB_XAR3_CONST8 => Register::XAR3,
                    InsnId::MOVB_XAR4_CONST8 => Register::XAR4, InsnId::MOVB_XAR5_CONST8 => Register::XAR5,
                    InsnId::MOVB_XAR6_CONST8 => Register::XAR6, _ => Register::XAR7,
                };
                il.set_reg(4, reg, il.zx(4, il.const_int(1, op.value as u64))).append();
            }
            return true;
        }
        _ => {}
    }

    // ── MOVL XARn, loc32 ──
    match n {
        InsnId::MOVL_XAR0_LOC32 | InsnId::MOVL_XAR1_LOC32 | InsnId::MOVL_XAR2_LOC32 |
        InsnId::MOVL_XAR3_LOC32 | InsnId::MOVL_XAR4_LOC32 | InsnId::MOVL_XAR5_LOC32 |
        InsnId::MOVL_XAR6_LOC32 | InsnId::MOVL_XAR7_LOC32 => {
            if let Some(op) = op_at(insn, 0) {
                let reg = match n {
                    InsnId::MOVL_XAR0_LOC32 => Register::XAR0, InsnId::MOVL_XAR1_LOC32 => Register::XAR1,
                    InsnId::MOVL_XAR2_LOC32 => Register::XAR2, InsnId::MOVL_XAR3_LOC32 => Register::XAR3,
                    InsnId::MOVL_XAR4_LOC32 => Register::XAR4, InsnId::MOVL_XAR5_LOC32 => Register::XAR5,
                    InsnId::MOVL_XAR6_LOC32 => Register::XAR6, _ => Register::XAR7,
                };
                il.set_reg(4, reg, read_op(op, il, 4)).append();
            }
            return true;
        }
        _ => {}
    }

    // ── MOVL loc32, XARn ──
    match n {
        InsnId::MOVL_LOC32_XAR0 | InsnId::MOVL_LOC32_XAR1 | InsnId::MOVL_LOC32_XAR2 |
        InsnId::MOVL_LOC32_XAR3 | InsnId::MOVL_LOC32_XAR4 | InsnId::MOVL_LOC32_XAR5 |
        InsnId::MOVL_LOC32_XAR6 | InsnId::MOVL_LOC32_XAR7 => {
            if let Some(op) = op_at(insn, 0) {
                let reg = match n {
                    InsnId::MOVL_LOC32_XAR0 => Register::XAR0, InsnId::MOVL_LOC32_XAR1 => Register::XAR1,
                    InsnId::MOVL_LOC32_XAR2 => Register::XAR2, InsnId::MOVL_LOC32_XAR3 => Register::XAR3,
                    InsnId::MOVL_LOC32_XAR4 => Register::XAR4, InsnId::MOVL_LOC32_XAR5 => Register::XAR5,
                    InsnId::MOVL_LOC32_XAR6 => Register::XAR6, _ => Register::XAR7,
                };
                write_loc(op, il, 4, il.reg(4, reg));
            }
            return true;
        }
        _ => {}
    }

    // ── MOVL XARn, #const22 ──
    if matches!(n, InsnId::MOVL_XAR0_CONST22 | InsnId::MOVL_XAR1_CONST22 | InsnId::MOVL_XAR2_CONST22 |
                    InsnId::MOVL_XAR3_CONST22 | InsnId::MOVL_XAR4_CONST22 | InsnId::MOVL_XAR5_CONST22 |
                    InsnId::MOVL_XAR6_CONST22 | InsnId::MOVL_XAR7_CONST22) {
        if let (Some(dst), Some(src)) = (op_at(insn, 0), op_at(insn, 1)) {
            il.set_reg(4, reg_by_name(dst.display_name()), il.const_int(4, src.value as u64)).append();
        }
        return true;
    }

    // ── MOVZ ARn, loc16: zero-extend 16-bit to ARn ──
    match n {
        InsnId::MOVZ_AR0_LOC16 | InsnId::MOVZ_AR1_LOC16 | InsnId::MOVZ_AR2_LOC16 |
        InsnId::MOVZ_AR3_LOC16 | InsnId::MOVZ_AR4_LOC16 | InsnId::MOVZ_AR5_LOC16 |
        InsnId::MOVZ_AR6_LOC16 | InsnId::MOVZ_AR7_LOC16 => {
            if let Some(op) = op_at(insn, 0) {
                let idx = match n {
                    InsnId::MOVZ_AR0_LOC16 => 0, InsnId::MOVZ_AR1_LOC16 => 1,
                    InsnId::MOVZ_AR2_LOC16 => 2, InsnId::MOVZ_AR3_LOC16 => 3,
                    InsnId::MOVZ_AR4_LOC16 => 4, InsnId::MOVZ_AR5_LOC16 => 5,
                    InsnId::MOVZ_AR6_LOC16 => 6, _ => 7,
                };
                il.set_reg(2, ar_reg(idx), read_op(op, il, 2)).append();
            }
            return true;
        }
        _ => {}
    }

    // ── Explicit 2-operand MOVs ──
    if matches!(n, InsnId::MOV_ACC_LOC16 | InsnId::MOV_ACC_LOC16_SHIFT16) {
        if let Some(op) = op_at(insn, 0) {
            il.set_reg(4, Register::ACC, il.sx(4, read_op(op, il, 2))).append();
        }
        return true;
    }
    if matches!(n, InsnId::MOV_LOC16_AX) {
        if let (Some(dst), Some(src)) = (op_at(insn, 0), op_at(insn, 1)) {
            write_loc(dst, il, 2, read_op(src, il, 2));
        }
        return true;
    }
    if matches!(n, InsnId::MOV_AX_LOC16) {
        if let (Some(dst), Some(src)) = (op_at(insn, 0), op_at(insn, 1)) {
            il.set_reg(2, reg_by_name(dst.display_name()), read_op(src, il, 2)).append();
        }
        return true;
    }
    if matches!(n, InsnId::MOVB_AX_CONST8) {
        if let (Some(dst), Some(src)) = (op_at(insn, 0), op_at(insn, 1)) {
            il.set_reg(2, reg_by_name(dst.display_name()), il.const_int(2, src.value as u64)).append();
        }
        return true;
    }
    if matches!(n, InsnId::MOVW_DP_CONST16) {
        if let Some(op) = op_at(insn, 0) {
            il.set_reg(2, Register::DP, il.const_int(2, op.value as u64)).append();
        }
        return true;
    }
    if matches!(n, InsnId::MOV_LOC16_CONST16) {
        if let (Some(dst), Some(src)) = (op_at(insn, 0), op_at(insn, 1)) {
            write_loc(dst, il, 2, il.const_int(2, src.value as u64));
        }
        return true;
    }
    if matches!(n, InsnId::MOVL_LOC32_ACC) {
        if let Some(dst) = op_at(insn, 0) { write_loc(dst, il, 4, il.reg(4, Register::ACC)); }
        return true;
    }
    if matches!(n, InsnId::MOVL_ACC_LOC32) {
        if let Some(src) = op_at(insn, 0) { il.set_reg(4, Register::ACC, read_op(src, il, 4)).append(); }
        return true;
    }
    // ── MOVL P, ACC : 32-bit register-to-register (both operands implicit) ──
    if matches!(n, InsnId::MOVL_P_ACC) {
        il.set_reg(4, Register::P, il.reg(4, Register::ACC)).append();
        return true;
    }

    // ── MOVH loc16, ACC >> 16: store high half of ACC ──
    if matches!(n, InsnId::MOVH_LOC16_ACC_SHIFT1 | InsnId::MOVH_LOC16_ACC_SHIFT2_8_OBJMODE_1) {
        if let Some(op) = op_at(insn, 0) {
            let ah = il.reg(2, Register::AH);
            write_loc(op, il, 2, ah);
        }
        return true;
    }
    if matches!(n, InsnId::MOVH_LOC16_P) {
        if let Some(op) = op_at(insn, 0) {
            write_loc(op, il, 2, il.reg(2, Register::PH));
        }
        return true;
    }

    // ── MOVB byte move variants ──
    if matches!(n, InsnId::MOVB_AXLSB_LOC16) {
        if let (Some(dst), Some(src)) = (op_at(insn, 0), op_at(insn, 1)) {
            let reg = reg_by_name(dst.display_name());
            il.set_reg(2, reg, il.and(2, read_op(src, il, 2), il.const_int(2, 0xFF))).append();
        }
        return true;
    }
    if matches!(n, InsnId::MOVB_AXMSB_LOC16) {
        if let (Some(dst), Some(src)) = (op_at(insn, 0), op_at(insn, 1)) {
            let reg = reg_by_name(dst.display_name());
            il.set_reg(2, reg, il.lsr(2, read_op(src, il, 2), il.const_int(2, 8))).append();
        }
        return true;
    }

    // ── MOV_MEM16_LOC16: store loc16 to absolute address (operand order: src, dest) ──
    if matches!(n, InsnId::MOV_MEM16_LOC16) {
        if insn.operands.len() >= 2 {
            let src_val = read_op(&insn.operands[0], il, 2);  // loc16 = source
            let dest_addr = insn.operands[1].value as u64 * 2; // mem16 word addr → byte addr
            il.store(2, il.const_ptr(dest_addr), src_val).append();
        }
        return true;
    }
    // ── MOV_LOC16_MEM16: load from absolute address to loc16 ──
    if matches!(n, InsnId::MOV_LOC16_MEM16) {
        if insn.operands.len() >= 2 {
            let dest = &insn.operands[0];                      // loc16 = destination
            let src_addr = insn.operands[1].value as u64 * 2;  // mem16 word addr → byte addr
            let val = il.load(2, il.const_ptr(src_addr)).build();
            write_loc(dest, il, 2, val);
        }
        return true;
    }

    // ── Generic 2-operand MOV fallback ──
    if insn.operands.len() >= 2 {
        let dst = &insn.operands[0];
        let src = &insn.operands[1];
        if dst.op_type == OperandType::Register {
            let reg = reg_by_name(dst.display_name());
            let size = if matches!(reg, Register::ACC | Register::P | Register::XT |
                Register::XAR0 | Register::XAR1 | Register::XAR2 | Register::XAR3 |
                Register::XAR4 | Register::XAR5 | Register::XAR6 | Register::XAR7) { 4 } else { 2 };
            il.set_reg(size, reg, read_op(src, il, size)).append();
            return true;
        }
        if matches!(dst.op_type, OperandType::Loc16 | OperandType::Loc32) {
            let size = if dst.op_type == OperandType::Loc32 { 4 } else { 2 };
            write_loc(dst, il, size, read_op(src, il, size));
            return true;
        }
    }

    // Single-operand MOV (destination implicit)
    if insn.operands.len() == 1 {
        let op = &insn.operands[0];
        if matches!(op.op_type, OperandType::Loc16 | OperandType::Loc32) {
            // Many single-operand MOVs store to/from ACC
            let size = if op.op_type == OperandType::Loc32 { 4 } else { 2 };
            let reg = if size == 4 { Register::ACC } else { Register::AL };
            il.set_reg(size, reg, read_op(op, il, size)).append();
            return true;
        }
    }

    il.nop().append(); // guard: MOV with unrecognized operand types
    true
}

/// Lift `MOVB loc16, #const8, cond` — conditional byte move.
///
/// Encoded as a 32-bit instruction (`0x56Bx_xxxx`) with `loc16` destination,
/// 8-bit immediate `const8`, and 4-bit `cond`. Decode lives in mov.yaml; this
/// function is wired through the Tier-1 InsnId match in `lifter/mod.rs` because
/// the generic `mov::lift` would otherwise ignore the condition and emit an
/// unconditional move.
///
/// Pattern mirrors `branch::lift_xretc` for conditional return.
pub fn lift_movb_cond(insn: &DecodedInstruction, _addr: u64, il: &ILFunc) -> bool {
    let dest = match op_at(insn, 0) {
        Some(op) => op,
        None => { il.nop().append(); return true; }
    };
    let const_op = match op_at(insn, 1) {
        Some(op) => op,
        None => { il.nop().append(); return true; }
    };
    let cond_op = insn.operands.iter().find(|op| op.op_type == OperandType::Condition);

    // Unconditional path (cond == 0xF UNC, or operand absent): emit a plain move.
    let emit_move = |il: &ILFunc| {
        let val = il.const_int(2, const_op.value as u64);
        write_loc(dest, il, 2, val);
    };

    match cond_op {
        Some(cop) if cop.value == 0xF => {
            emit_move(il);
        }
        Some(cop) => {
            if let Some(cond) = super::branch::flag_condition_il(cop.value as u8, il) {
                let mut t_label = LowLevelILLabel::new();
                let mut f_label = LowLevelILLabel::new();
                il.if_expr(cond, &mut t_label, &mut f_label).append();
                il.mark_label(&mut t_label);
                emit_move(il);
                il.mark_label(&mut f_label);
            } else {
                // Unknown condition code — fall back to unconditional rather
                // than emitting a nop (preserves data flow on edge cases).
                emit_move(il);
            }
        }
        None => emit_move(il),
    }
    true
}
