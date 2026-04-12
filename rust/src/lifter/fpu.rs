// SPDX-License-Identifier: MIT
//! FPU lifter: ADDF32, SUBF32, MPYF32, CMPF32, MOV32, conversions.

use crate::types::*;

use binaryninja::low_level_il::LowLevelILMutableFunction;

use binaryninja::low_level_il::lifting::LowLevelILLabel;

use super::{op_at, read_op, write_loc, reg_by_name};

type ILFunc = LowLevelILMutableFunction;

pub fn lift(insn: &DecodedInstruction, _addr: u64, il: &ILFunc) -> bool {
    let ops = &insn.operands;
    let n = insn.id;

    // ── CMPF32: compare only, no destination write ──
    if matches!(n, InsnId::CMPF32_RAH_RBH) {
        if ops.len() >= 2 {
            let a = il.reg(4, reg_by_name(ops[0].display_name()));
            let b = il.reg(4, reg_by_name(ops[1].display_name()));
            il.fsub(4, a, b).append(); // sets FPU flags only
        }
        return true;
    }
    if matches!(n, InsnId::CMPF32_RAH_0) {
        if ops.len() >= 1 {
            let a = il.reg(4, reg_by_name(ops[0].display_name()));
            il.fsub(4, a, il.const_int(4, 0)).append();
        }
        return true;
    }

    // ── Integer ↔ Float conversions ──
    if matches!(n, InsnId::I16TOF32_RAH_RBH | InsnId::I32TOF32_RAH_RBH |
                    InsnId::UI16TOF32_RAH_RBH | InsnId::UI32TOF32_RAH_RBH) {
        if ops.len() >= 2 {
            let dst = reg_by_name(ops[0].display_name());
            let src = il.reg(4, reg_by_name(ops[1].display_name()));
            il.set_reg(4, dst, il.int_to_float(4, src)).append();
        }
        return true;
    }
    if matches!(n, InsnId::F32TOI16_RAH_RBH | InsnId::F32TOI16R_RAH_RBH |
                    InsnId::F32TOI32_RAH_RBH | InsnId::F32TOUI16_RAH_RBH |
                    InsnId::F32TOUI16R_RAH_RBH | InsnId::F32TOUI32_RAH_RBH) {
        if ops.len() >= 2 {
            let dst = reg_by_name(ops[0].display_name());
            let src = il.reg(4, reg_by_name(ops[1].display_name()));
            il.set_reg(4, dst, il.float_to_int(4, src)).append();
        }
        return true;
    }
    // Memory-operand conversions
    if matches!(n, InsnId::I16TOF32_RAH_MEM16 | InsnId::UI16TOF32_RAH_MEM16) {
        if ops.len() >= 2 {
            let dst = reg_by_name(ops[0].display_name());
            let src = read_op(&ops[1], il, 2);
            il.set_reg(4, dst, il.int_to_float(4, il.sx(4, src))).append();
        }
        return true;
    }
    if matches!(n, InsnId::I32TOF32_RAH_MEM32) {
        if ops.len() >= 2 {
            let dst = reg_by_name(ops[0].display_name());
            let src = read_op(&ops[1], il, 4);
            il.set_reg(4, dst, il.int_to_float(4, src)).append();
        }
        return true;
    }
    if matches!(n, InsnId::F32TOI32_RAH_MEM32 | InsnId::F32TOUI32_RAH_MEM32) {
        if ops.len() >= 2 {
            let dst = reg_by_name(ops[0].display_name());
            let src = read_op(&ops[1], il, 4);
            il.set_reg(4, dst, il.float_to_int(4, src)).append();
        }
        return true;
    }

    // ── 3-operand FPU: RaH = RbH op RcH ──
    if ops.len() >= 3
        && ops[0].op_type == OperandType::Register
        && ops[1].op_type == OperandType::Register
        && ops[2].op_type == OperandType::Register
    {
        let dst = reg_by_name(ops[0].display_name());
        let src1 = il.reg(4, reg_by_name(ops[1].display_name()));
        let src2 = il.reg(4, reg_by_name(ops[2].display_name()));

        let result = if matches!(n, InsnId::ADDF32_RAH_RBH_RCH) {
            il.fadd(4, src1, src2).build()
        } else if matches!(n, InsnId::SUBF32_RAH_RBH_RCH) {
            il.fsub(4, src1, src2).build()
        } else if matches!(n, InsnId::MPYF32_RAH_RBH_RCH) {
            il.fmul(4, src1, src2).build()
        } else if matches!(n, InsnId::MACF32_RAH_RBH_RCH) {
            // MAC: dst += src1 * src2 (multiply-accumulate)
            il.fadd(4, il.reg(4, dst), il.fmul(4, src1, src2)).build()
        } else {
            // All known 3-reg FPU variants handled above
            il.nop().append();
            return true;
        };
        il.set_reg(4, dst, result).append();

        // Handle parallel MOV (ops[3..4]) if present — FPU parallel instructions
        // e.g., MPYF32 R0H,R1H,R2H || MOV32 R3H,mem
        if ops.len() >= 5 {
            let mov_dst = &ops[3];
            let mov_src = &ops[4];
            if mov_dst.op_type == OperandType::Register {
                il.set_reg(4, reg_by_name(mov_dst.display_name()), read_op(mov_src, il, 4)).append();
            } else if matches!(mov_dst.op_type, OperandType::Loc16 | OperandType::Loc32) {
                write_loc(mov_dst, il, 4, read_op(mov_src, il, 4));
            }
        }
        return true;
    }

    // ── 2-operand FPU: RaH = op(RbH) ──
    if ops.len() >= 2
        && ops[0].op_type == OperandType::Register
        && ops[1].op_type == OperandType::Register
    {
        let dst = reg_by_name(ops[0].display_name());
        let src = il.reg(4, reg_by_name(ops[1].display_name()));

        if matches!(n, InsnId::MAXF32_RAH_RBH | InsnId::MINF32_RAH_RBH) {
            // MAXF32: dst = (dst >= src) ? dst : src
            // MINF32: dst = (dst <= src) ? dst : src
            let dst_val = il.reg(4, dst);
            let cond = if matches!(n, InsnId::MAXF32_RAH_RBH) {
                il.fcmp_ge(4, dst_val, src)
            } else {
                il.fcmp_le(4, dst_val, src)
            };
            let mut keep_label = LowLevelILLabel::new();
            let mut replace_label = LowLevelILLabel::new();
            il.if_expr(cond, &mut keep_label, &mut replace_label).append();
            il.mark_label(&mut replace_label);
            let src_reload = il.reg(4, reg_by_name(ops[1].display_name()));
            il.set_reg(4, dst, src_reload).append();
            il.mark_label(&mut keep_label);
            return true;
        }

        let result = if matches!(n, InsnId::ABSF32_RAH_RBH) {
            il.fabs(4, src).build()
        } else if matches!(n, InsnId::NEGF32_RAH_RBH) {
            il.fneg(4, src).build()
        } else {
            // Generic reg-to-reg move (MOV32 RaH, RbH etc.)
            src
        };
        il.set_reg(4, dst, result).append();
        return true;
    }

    // ── MOV32 with memory operand ──
    if ops.len() >= 2 {
        let op0 = &ops[0];
        let op1 = &ops[1];

        if matches!(op0.op_type, OperandType::Loc16 | OperandType::Loc32) {
            write_loc(op0, il, 4, read_op(op1, il, 4));
            return true;
        }
        if op0.op_type == OperandType::Register {
            il.set_reg(4, reg_by_name(op0.display_name()), read_op(op1, il, 4)).append();
            return true;
        }
    }

    il.nop().append(); // guard: FPU with unrecognized operand types
    true
}
