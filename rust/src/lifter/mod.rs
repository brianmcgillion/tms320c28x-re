// SPDX-License-Identifier: MIT
//! LLIL lifter for TMS320C28x — dispatch + helpers.

pub mod arith;
pub mod bitwise;
pub mod branch;
pub mod fpu;
pub mod mov;
pub mod multiply;
pub mod shift;
pub mod system;

use crate::arch::Register;
use crate::operands::{AddressingMode, ResolvedOperand};
use crate::types::*;

use binaryninja::low_level_il::expression::ValueExpr;
use binaryninja::low_level_il::{LowLevelILMutableExpression, LowLevelILMutableFunction};

type ILFunc = LowLevelILMutableFunction;
type Expr<'a> = LowLevelILMutableExpression<'a, ValueExpr>;

/// Main lifter entry point — 3-tier dispatch.
pub fn lift(insn: &DecodedInstruction, addr: u64, il: &ILFunc) -> bool {
    // Tier 1: explicit per-instruction handlers
    match insn.id {
        InsnId::SBF => return branch::lift_sbf(insn, addr, il),
        InsnId::BAR_OFF16_ARN_ARM_EQ => return branch::lift_bar(insn, addr, il, true),
        InsnId::BAR_OFF16_ARN_ARM_NEQ => return branch::lift_bar(insn, addr, il, false),
        InsnId::BANZ => return branch::lift_banz(insn, addr, il),
        InsnId::XRETC_COND => return branch::lift_xretc(insn, addr, il),
        // MOVB loc16, #const8, cond — must wrap the move in if_expr; the
        // generic SemType::Mov dispatch in mov::lift would discard the cond.
        InsnId::MOVB_LOC16_CONST8_COND => return mov::lift_movb_cond(insn, addr, il),
        _ => {}
    }

    // Tier 2: semantic-type dispatch
    let lifted = match insn.sem_type {
        SemType::Mov | SemType::Push | SemType::Pop => mov::lift(insn, addr, il),
        SemType::Add | SemType::Addc => arith::lift_add(insn, addr, il),
        SemType::Sub | SemType::Subb | SemType::Subcu => arith::lift_sub(insn, addr, il),
        SemType::Cmp => arith::lift_cmp(insn, addr, il),
        SemType::Neg | SemType::Abs | SemType::Sat => arith::lift_misc(insn, addr, il),
        SemType::And => bitwise::lift_and(insn, addr, il),
        SemType::Or => bitwise::lift_or(insn, addr, il),
        SemType::Xor => bitwise::lift_xor(insn, addr, il),
        SemType::Not => bitwise::lift_not(insn, addr, il),
        SemType::Flip => { il.nop().append(); true } // bit reversal — no IL equivalent
        SemType::Test => arith::lift_misc(insn, addr, il), // TEST ACC sets flags
        SemType::Lsl => shift::lift_lsl(insn, addr, il),
        SemType::Lsr => shift::lift_lsr(insn, addr, il),
        SemType::Asr => shift::lift_asr(insn, addr, il),
        SemType::Rol | SemType::Ror => shift::lift_rotate(insn, addr, il),
        SemType::CondBranch => branch::lift_cond_branch(insn, addr, il),
        SemType::Branch => branch::lift_branch(insn, addr, il),
        SemType::Call => branch::lift_call(insn, addr, il),
        SemType::Return => branch::lift_return(insn, addr, il),
        SemType::Mpy | SemType::Mac => multiply::lift(insn, addr, il),
        SemType::Fpu | SemType::FpuParallel => fpu::lift(insn, addr, il),
        SemType::Nop => { il.nop().append(); true }
        SemType::System | SemType::Csb | SemType::Max | SemType::Min => system::lift(insn, addr, il),
        SemType::Trap => { il.nop().append(); true }
        SemType::Halt => system::lift(insn, addr, il),
        _ => false,
    };

    if lifted {
        return true;
    }

    // Tier 3: branch-type fallback
    match insn.branch_type {
        BranchType::Return => {
            il.ret(il.reg(4, Register::RPC)).append();
            true
        }
        BranchType::Unconditional if insn.branch_target.is_some() => {
            il.jump(il.const_ptr(insn.branch_target.unwrap())).append();
            true
        }
        BranchType::Call if insn.branch_target.is_some() => {
            il.call(il.const_ptr(insn.branch_target.unwrap())).append();
            true
        }
        BranchType::Halt => {
            il.no_ret().append();
            true
        }
        _ => false,
    }
}

// ------------------------------------------------------------------ //
// Operand helpers                                                      //
// ------------------------------------------------------------------ //

/// Read an operand as an IL expression.
pub fn read_op<'a>(op: &Operand, il: &'a ILFunc, size: usize) -> Expr<'a> {
    match op.op_type {
        OperandType::Register => {
            let reg = reg_by_name(op.display_name());
            il.reg(size, reg)
        }
        OperandType::Immediate => il.const_int(size, op.value as u64),
        OperandType::Loc16 | OperandType::Loc32 => {
            let loc_size = if op.op_type == OperandType::Loc32 { 4 } else { 2 };
            read_loc(op, il, loc_size)
        }
        _ => il.const_int(size, 0),
    }
}

/// Read a loc16/loc32 operand — handles all addressing modes.
pub fn read_loc<'a>(op: &Operand, il: &'a ILFunc, size: usize) -> Expr<'a> {
    let r = match &op.resolved {
        Some(r) => r,
        None => return il.const_int(size, 0),
    };

    if r.mode == AddressingMode::RegisterDirect {
        if let Some(reg_name) = r.register {
            return il.reg(size, reg_by_name(reg_name));
        }
    }

    // Pre-decrement side effect
    if r.mode == AddressingMode::IndirectPreDec {
        if let Some(n) = r.xar_index {
            let xar = xar_reg(n);
            il.set_reg(4, xar, il.sub(4, il.reg(4, xar), il.const_int(4, size as u64))).append();
        }
    }

    let addr_expr = loc_address(r, il);
    let result = il.load(size, addr_expr).build();

    // Post-increment side effect
    if r.mode == AddressingMode::IndirectPostInc {
        if let Some(n) = r.xar_index {
            let xar = xar_reg(n);
            il.set_reg(4, xar, il.add(4, il.reg(4, xar), il.const_int(4, size as u64))).append();
        }
    }

    result
}

/// Write to a loc16/loc32 operand.
pub fn write_loc(op: &Operand, il: &ILFunc, size: usize, value: Expr<'_>) {
    let r = match &op.resolved {
        Some(r) => r,
        None => { il.nop().append(); return; }
    };

    if r.mode == AddressingMode::RegisterDirect {
        if let Some(reg_name) = r.register {
            il.set_reg(size, reg_by_name(reg_name), value).append();
            return;
        }
    }

    // Pre-decrement side effect
    if r.mode == AddressingMode::IndirectPreDec {
        if let Some(n) = r.xar_index {
            let xar = xar_reg(n);
            il.set_reg(4, xar, il.sub(4, il.reg(4, xar), il.const_int(4, size as u64))).append();
        }
    }

    let addr_expr = loc_address(r, il);
    il.store(size, addr_expr, value).append();

    // Post-increment side effect
    if r.mode == AddressingMode::IndirectPostInc {
        if let Some(n) = r.xar_index {
            let xar = xar_reg(n);
            il.set_reg(4, xar, il.add(4, il.reg(4, xar), il.const_int(4, size as u64))).append();
        }
    }
}

/// Compute the byte address for a loc operand.
fn loc_address<'a>(r: &ResolvedOperand, il: &'a ILFunc) -> Expr<'a> {
    match r.mode {
        AddressingMode::DpDirect => {
            let dp_base = il.lsl(4, il.zx(4, il.reg(2, Register::DP)), il.const_int(4, 6));
            let word_addr = il.add(4, dp_base, il.const_int(4, r.offset as u64));
            il.lsl(4, word_addr, il.const_int(4, 1)).build()
        }
        AddressingMode::SpRelative => {
            let word_addr = il.sub(4, il.zx(4, il.reg(2, Register::SP)), il.const_int(4, r.offset as u64));
            il.lsl(4, word_addr, il.const_int(4, 1)).build()
        }
        AddressingMode::Indirect | AddressingMode::IndirectPostInc | AddressingMode::IndirectPreDec => {
            if let Some(n) = r.xar_index {
                if r.offset == 0 {
                    il.reg(4, xar_reg(n))
                } else {
                    // *+XARn[offset]: byte addr = XARn + (word offset << 1),
                    // same word->byte convention as the AR0/AR1-indexed modes.
                    il.add(4, il.reg(4, xar_reg(n)),
                        il.const_int(4, (r.offset as u64) << 1)).build()
                }
            } else {
                il.const_int(4, 0)
            }
        }
        AddressingMode::IndirectAr0 => {
            if let Some(n) = r.xar_index {
                il.add(4, il.reg(4, xar_reg(n)),
                    il.lsl(4, il.zx(4, il.reg(2, Register::AR0)), il.const_int(4, 1))).build()
            } else {
                il.const_int(4, 0)
            }
        }
        AddressingMode::IndirectAr1 => {
            if let Some(n) = r.xar_index {
                il.add(4, il.reg(4, xar_reg(n)),
                    il.lsl(4, il.zx(4, il.reg(2, Register::AR1)), il.const_int(4, 1))).build()
            } else {
                il.const_int(4, 0)
            }
        }
        _ => il.const_int(4, 0),
    }
}

/// Map register name string to Register enum.
pub fn reg_by_name(name: &str) -> Register {
    match name {
        "ACC" => Register::ACC, "AH" => Register::AH, "AL" => Register::AL,
        "XAR0" => Register::XAR0, "AR0" => Register::AR0,
        "XAR1" => Register::XAR1, "AR1" => Register::AR1,
        "XAR2" => Register::XAR2, "AR2" => Register::AR2,
        "XAR3" => Register::XAR3, "AR3" => Register::AR3,
        "XAR4" => Register::XAR4, "AR4" => Register::AR4,
        "XAR5" => Register::XAR5, "AR5" => Register::AR5,
        "XAR6" => Register::XAR6, "AR6" => Register::AR6,
        "XAR7" => Register::XAR7, "AR7" => Register::AR7,
        "P" => Register::P, "PH" => Register::PH, "PL" => Register::PL,
        "XT" => Register::XT, "T" => Register::T, "TL" => Register::TL,
        "SP" => Register::SP, "DP" => Register::DP,
        "PC" => Register::PC, "RPC" => Register::RPC,
        "ST0" => Register::ST0, "ST1" => Register::ST1,
        "IER" => Register::IER, "IFR" => Register::IFR,
        "DBGIER" => Register::DBGIER,
        "R0H" => Register::R0H, "R1H" => Register::R1H,
        "R2H" => Register::R2H, "R3H" => Register::R3H,
        "R4H" => Register::R4H, "R5H" => Register::R5H,
        "R6H" => Register::R6H, "R7H" => Register::R7H,
        "STF" => Register::STF,
        _ => Register::AL, // fallback
    }
}

fn xar_reg(n: u8) -> Register {
    match n {
        0 => Register::XAR0, 1 => Register::XAR1, 2 => Register::XAR2, 3 => Register::XAR3,
        4 => Register::XAR4, 5 => Register::XAR5, 6 => Register::XAR6, 7 => Register::XAR7,
        _ => Register::XAR0,
    }
}

fn ar_reg(n: u8) -> Register {
    match n {
        0 => Register::AR0, 1 => Register::AR1, 2 => Register::AR2, 3 => Register::AR3,
        4 => Register::AR4, 5 => Register::AR5, 6 => Register::AR6, 7 => Register::AR7,
        _ => Register::AR0,
    }
}

/// Get operand safely (returns None if out of bounds).
pub fn op_at(insn: &DecodedInstruction, idx: usize) -> Option<&Operand> {
    insn.operands.get(idx)
}
