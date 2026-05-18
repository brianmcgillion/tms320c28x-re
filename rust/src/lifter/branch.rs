// SPDX-License-Identifier: MIT
//! Branch/call/return lifter handlers.

use crate::arch::Register;
use crate::types::*;

use binaryninja::architecture::FlagCondition;
use binaryninja::low_level_il::lifting::LowLevelILLabel;
use binaryninja::low_level_il::LowLevelILMutableFunction;

use super::{ar_reg, reg_by_name};

type ILFunc = LowLevelILMutableFunction;

/// Emit a conditional branch. Both labels must resolve (be inside the
/// current function) for if_expr to work. If either target is outside
/// the function, fall back to unimplemented — BN still builds the CFG
/// correctly from instruction_info.
fn emit_cond_branch(
    il: &ILFunc,
    cond: binaryninja::low_level_il::LowLevelILMutableExpression<'_, binaryninja::low_level_il::expression::ValueExpr>,
    target: u64,
    fallthrough: u64,
) {
    let t_label = il.label_for_address(target);
    let f_label = il.label_for_address(fallthrough);

    match (t_label, f_label) {
        (Some(mut t), Some(mut f)) => {
            il.if_expr(cond, &mut t, &mut f).append();
        }
        (Some(_), None) => {
            // True target resolved, fallthrough outside function.
            // Emit jump to the true target (BN follows it).
            let _ = cond;
            il.jump(il.const_ptr(target)).append();
        }
        (None, Some(_)) => {
            // True target outside function, fallthrough resolved.
            // Fall through naturally (nop) — BN handles from instruction_info.
            let _ = cond;
            il.nop().append();
        }
        (None, None) => {
            // Both outside function — emit jump to target.
            let _ = cond;
            il.jump(il.const_ptr(target)).append();
        }
    }
}

/// Lift unconditional branch (LB, B UNC).
pub fn lift_branch(insn: &DecodedInstruction, _addr: u64, il: &ILFunc) -> bool {
    if let Some(target) = insn.branch_target {
        il.jump(il.const_ptr(target)).append();
    } else {
        match insn.id {
            InsnId::LB_XAR7 => il.jump(il.reg(4, Register::XAR7)).append(),
            InsnId::XB_AL => il.jump(il.zx(4, il.reg(2, Register::AL))).append(),
            _ => il.nop().append(), // BN builds CFG from instruction_info
        }
    }
    true
}

/// Lift conditional branch (B cond, SB cond, BF cond).
pub fn lift_cond_branch(insn: &DecodedInstruction, addr: u64, il: &ILFunc) -> bool {
    // Find condition operand
    let cond_op = insn
        .operands
        .iter()
        .find(|op| op.op_type == OperandType::Condition);

    // Unconditional (cond code 0xF = UNC)
    if let Some(cop) = cond_op {
        if cop.value == 0xF {
            if let Some(target) = insn.branch_target {
                il.jump(il.const_ptr(target)).append();
            } else {
                il.nop().append();
            }
            return true;
        }
    }

    let target = match insn.branch_target {
        Some(t) => t,
        None => {
            il.nop().append(); // BN builds CFG from instruction_info
            return true;
        }
    };

    // No condition operand → implicit condition (SBF handled in tier 1)
    let cond_op = match cond_op {
        Some(c) => c,
        None => {
            il.nop().append(); // BN builds CFG from instruction_info
            return true;
        }
    };

    match flag_condition_il(cond_op.value as u8, il) {
        Some(cond) => emit_cond_branch(il, cond, target, addr + insn.size as u64),
        None => il.nop().append(),
    }
    true
}

/// Lift function call (LCR, LC, FFC, XCALL).
pub fn lift_call(insn: &DecodedInstruction, _addr: u64, il: &ILFunc) -> bool {
    if let Some(target) = insn.branch_target {
        il.call(il.const_ptr(target)).append();
    } else {
        match insn.id {
            InsnId::LC_XAR7 => il.call(il.reg(4, Register::XAR7)).append(),
            InsnId::LCR_XARN => {
                if let Some(op) = insn.operands.first() {
                    if (0..=7).contains(&op.value) {
                        let xar = reg_by_name(&format!("XAR{}", op.value));
                        il.call(il.reg(4, xar)).append();
                    } else {
                        il.nop().append();
                    }
                } else {
                    il.nop().append();
                }
            }
            InsnId::XCALL_AL => il.call(il.zx(4, il.reg(2, Register::AL))).append(),
            _ => il.nop().append(), // BN builds CFG from instruction_info
        }
    }
    true
}

/// Lift function return (LRETR, LRET, LRETE, IRET).
pub fn lift_return(insn: &DecodedInstruction, _addr: u64, il: &ILFunc) -> bool {
    match insn.id {
        InsnId::LRETR => {
            il.set_reg(4, Register::RPC, il.pop(4).build()).append();
            il.ret(il.reg(4, Register::RPC)).append();
        }
        InsnId::IRET => {
            il.ret(il.pop(4).build()).append();
        }
        _ => {
            il.ret(il.reg(4, Register::RPC)).append();
        }
    }
    true
}

/// Lift XRETC (conditional return).
pub fn lift_xretc(insn: &DecodedInstruction, _addr: u64, il: &ILFunc) -> bool {
    let cond_op = insn.operands.iter().find(|op| op.op_type == OperandType::Condition);

    match cond_op {
        Some(cop) if cop.value == 0xF => {
            // UNC — unconditional return
            il.ret(il.reg(4, Register::RPC)).append();
        }
        Some(cop) => {
            // Conditional return: if(cond) ret(RPC)
            // BN doesn't have conditional return IL, so use if_expr + ret
            if let Some(cond) = flag_condition_il(cop.value as u8, il) {
                let mut t_label = LowLevelILLabel::new();
                let mut f_label = LowLevelILLabel::new();
                il.if_expr(cond, &mut t_label, &mut f_label).append();
                il.mark_label(&mut t_label);
                il.ret(il.reg(4, Register::RPC)).append();
                il.mark_label(&mut f_label);
            } else {
                il.nop().append();
            }
        }
        None => {
            il.ret(il.reg(4, Register::RPC)).append();
        }
    }
    true
}

/// Lift SBF (short branch fast) — condition encoded in opcode bits [9:8].
pub fn lift_sbf(insn: &DecodedInstruction, addr: u64, il: &ILFunc) -> bool {
    let target = match insn.branch_target {
        Some(t) => t,
        None => {
            il.nop().append();
            return true;
        }
    };

    // SBF condition: bits [9:8] → 0=EQ, 1=NEQ, 2=TC, 3=NTC
    let sbf_cond = ((insn.opcode >> 8) & 0x3) as u8;
    let cond = match sbf_cond {
        0 => il.flag_cond(FlagCondition::LLFC_E),
        1 => il.flag_cond(FlagCondition::LLFC_NE),
        2 => il.flag(crate::arch::Flag::TC),
        3 => il.not(0, il.flag(crate::arch::Flag::TC)).build(),
        _ => {
            il.nop().append();
            return true;
        }
    };

    emit_cond_branch(il, cond, target, addr + insn.size as u64);
    true
}

/// Lift BAR (branch if ARn == / != ARm).
pub fn lift_bar(insn: &DecodedInstruction, addr: u64, il: &ILFunc, equal: bool) -> bool {
    let target = match insn.branch_target {
        Some(t) => t,
        None => {
            il.nop().append();
            return true;
        }
    };

    let reg_ops: Vec<&Operand> = insn
        .operands
        .iter()
        .filter(|op| op.op_type == OperandType::Register)
        .collect();

    if reg_ops.len() < 2 {
        il.nop().append();
        return true;
    }

    let ar_n = ar_reg(reg_ops[0].value as u8);
    let ar_m = ar_reg(reg_ops[1].value as u8);

    let cond = if equal {
        il.cmp_e(2, il.reg(2, ar_n), il.reg(2, ar_m)).build()
    } else {
        il.cmp_ne(2, il.reg(2, ar_n), il.reg(2, ar_m)).build()
    };

    emit_cond_branch(il, cond, target, addr + insn.size as u64);
    true
}

/// Lift BANZ (branch if ARn not zero, decrement).
pub fn lift_banz(insn: &DecodedInstruction, addr: u64, il: &ILFunc) -> bool {
    let target = match insn.branch_target {
        Some(t) => t,
        None => {
            il.nop().append();
            return true;
        }
    };

    let n_op = insn
        .operands
        .iter()
        .find(|op| op.op_type == OperandType::Register);
    let n = match n_op {
        Some(op) if (0..=7).contains(&op.value) => op.value as u8,
        _ => {
            il.nop().append();
            return true;
        }
    };

    let ar = ar_reg(n);
    // Decrement ARn
    il.set_reg(2, ar, il.sub(2, il.reg(2, ar), il.const_int(2, 1)))
        .append();

    // Branch if ARn != 0
    let cond = il.cmp_ne(2, il.reg(2, ar), il.const_int(2, 0)).build();
    emit_cond_branch(il, cond, target, addr + insn.size as u64);
    true
}

/// Map 4-bit C28x condition code to a BN flag-condition IL expression.
/// Made `pub(crate)` so other lifter modules (e.g. `mov::lift_movb_cond`)
/// can wrap their bodies in `if_expr(flag_condition_il(cond), ...)`.
pub(crate) fn flag_condition_il<'a>(
    code: u8,
    il: &'a ILFunc,
) -> Option<
    binaryninja::low_level_il::LowLevelILMutableExpression<
        'a,
        binaryninja::low_level_il::expression::ValueExpr,
    >,
> {
    let fc = match code {
        0x0 => FlagCondition::LLFC_NE,
        0x1 => FlagCondition::LLFC_E,
        0x2 => FlagCondition::LLFC_SGT,
        0x3 => FlagCondition::LLFC_SGE,
        0x4 => FlagCondition::LLFC_SLT,
        0x5 => FlagCondition::LLFC_SLE,
        0x6 => FlagCondition::LLFC_UGT,
        0x7 => FlagCondition::LLFC_UGE,
        0x8 => FlagCondition::LLFC_ULT,
        0x9 => FlagCondition::LLFC_ULE,
        0xA => FlagCondition::LLFC_NO,
        0xB => FlagCondition::LLFC_O,
        0xC => return Some(il.not(0, il.flag(crate::arch::Flag::TC)).build()),
        0xD => return Some(il.flag(crate::arch::Flag::TC)),
        0xE => return Some(il.const_int(0, 1)), // NBIO: always true on F28335
        _ => return None,
    };
    Some(il.flag_cond(fc))
}
