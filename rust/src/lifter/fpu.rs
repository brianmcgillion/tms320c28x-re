// SPDX-License-Identifier: MIT
//! FPU lifter: ADDF32, SUBF32, MPYF32, CMPF32, MOV32, conversions.

use crate::types::*;

use binaryninja::low_level_il::LowLevelILMutableFunction;

use binaryninja::low_level_il::lifting::LowLevelILLabel;

use super::{read_op, reg_by_name, write_loc};
use crate::arch::{Intrinsic, Register};

type ILFunc = LowLevelILMutableFunction;

pub fn lift(insn: &DecodedInstruction, _addr: u64, il: &ILFunc) -> bool {
    let ops = &insn.operands;
    let n = insn.id;

    // ── SETFLG FLAG, VALUE ──
    // Sets/clears STF mode bits, which BN has no representation for. It was
    // reaching the catch-all at the bottom of this function -- 444 occurrences
    // across the four fixtures, every single unlifted instruction in the corpus.
    // An intrinsic keeps it readable and tells dataflow that STF is clobbered.
    if matches!(n, InsnId::SETFLG) {
        let flags = il.const_int(
            4,
            insn.operands.first().map(|o| o.value as u64).unwrap_or(0),
        );
        il.intrinsic([Register::STF], Intrinsic::SetFlg, [flags])
            .append();
        return true;
    }

    // ── MOV32 loc32 <-> *(0:16bitAddr). The assembler spells the FPU half of
    //    this as a register (`MOV32 ACC, R2H`), but RaH is encoded as the
    //    address: R0H..R7H are 0x0F12 + 4n. Only the register-direct loc32
    //    codes 0xA0-0xAB (XAR0-7 / ACC / P) are modelled; anything else is a
    //    real memory move and falls through. ──
    if matches!(n, InsnId::MOV32_ADDR16_LOC32 | InsnId::MOV32_LOC32_ADDR16) {
        let cpu = match ((insn.opcode >> 16) & 0xFF) as u8 {
            v @ 0xA0..=0xA7 => Some(reg_by_name(&format!("XAR{}", v - 0xA0))),
            0xA9 => Some(Register::ACC),
            0xAB => Some(Register::P),
            _ => None,
        };
        let rah = match (insn.opcode & 0xFFFF) as u16 {
            a if (0x0F12..=0x0F2E).contains(&a) && (a - 0x0F12) % 4 == 0 => {
                Some(reg_by_name(&format!("R{}H", (a - 0x0F12) / 4)))
            }
            _ => None,
        };
        if let (Some(cpu), Some(rah)) = (cpu, rah) {
            if matches!(n, InsnId::MOV32_ADDR16_LOC32) {
                il.set_reg(4, rah, il.reg(4, cpu)).append(); // RaH = CPUreg
            } else {
                il.set_reg(4, cpu, il.reg(4, rah)).append(); // CPUreg = RaH
            }
            return true;
        }
    }

    // ── MOV32 *SP++, STF / MOV32 STF, *--SP : FPU status-register save and
    //    restore. STF is implicit (only the memory operand is decoded), and the
    //    SP post-inc/pre-dec specials don't carry an xar_index for the generic
    //    loc path — so model them directly as a 32-bit STF push/pop. ──
    if matches!(n, InsnId::MOV32_MEM32_STF) {
        let sp_byte = il.reg(4, Register::SP);
        il.store(4, sp_byte, il.reg(4, Register::STF)).append(); // [SP] = STF
        il.set_reg(
            4,
            Register::SP,
            il.add(4, il.reg(4, Register::SP), il.const_int(4, 4)),
        )
        .append(); // SP += 2 words
        return true;
    }
    if matches!(n, InsnId::MOV32_STF_MEM32) {
        il.set_reg(
            4,
            Register::SP,
            il.sub(4, il.reg(4, Register::SP), il.const_int(4, 4)),
        )
        .append(); // SP -= 2 words
        let sp_byte = il.reg(4, Register::SP);
        il.set_reg(4, Register::STF, il.load(4, sp_byte)).append(); // STF = [SP]
        return true;
    }

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
        if !ops.is_empty() {
            let a = il.reg(4, reg_by_name(ops[0].display_name()));
            il.fsub(4, a, il.const_int(4, 0)).append();
        }
        return true;
    }

    // ── Integer ↔ Float conversions ──
    if matches!(
        n,
        InsnId::I16TOF32_RAH_RBH
            | InsnId::I32TOF32_RAH_RBH
            | InsnId::UI16TOF32_RAH_RBH
            | InsnId::UI32TOF32_RAH_RBH
    ) {
        if ops.len() >= 2 {
            let dst = reg_by_name(ops[0].display_name());
            let src = il.reg(4, reg_by_name(ops[1].display_name()));
            il.set_reg(4, dst, il.int_to_float(4, src)).append();
        }
        return true;
    }
    if matches!(
        n,
        InsnId::F32TOI16_RAH_RBH
            | InsnId::F32TOI16R_RAH_RBH
            | InsnId::F32TOI32_RAH_RBH
            | InsnId::F32TOUI16_RAH_RBH
            | InsnId::F32TOUI16R_RAH_RBH
            | InsnId::F32TOUI32_RAH_RBH
    ) {
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
            il.set_reg(4, dst, il.int_to_float(4, il.sx(4, src)))
                .append();
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
    // ── ZERO RaH: RaH = 0.0 (single FPU-register operand) ──
    if matches!(n, InsnId::ZERO) && !ops.is_empty() && ops[0].op_type == OperandType::Register {
        let dst = reg_by_name(ops[0].display_name());
        il.set_reg(4, dst, il.const_int(4, 0)).append();
        return true;
    }

    // ── 3-operand FPU: RaH = RbH op RcH (incl. the `op || MOV32` parallel
    //    forms, whose extra MOV operands, if decoded, are handled below). Match
    //    by mnemonic FAMILY, not exact InsnId, so every encoding variant lifts. ──
    if ops.len() >= 3
        && ops[0].op_type == OperandType::Register
        && ops[1].op_type == OperandType::Register
        && ops[2].op_type == OperandType::Register
    {
        let dst = reg_by_name(ops[0].display_name());
        let src1 = il.reg(4, reg_by_name(ops[1].display_name()));
        let src2 = il.reg(4, reg_by_name(ops[2].display_name()));

        // Dispatch on InsnId, not on the display name. This used to be
        // `display_mnemonic(n, None).starts_with("ADDF32")`, so renaming a row
        // for B6 would have turned a float add into `unimplemented()` with no
        // compile error -- and a new row whose name happened to start with a
        // family prefix would have been lifted as that family.
        let result = match n {
            InsnId::ADDF32_RAH_RBH_RCH | InsnId::ADDF32_MOV32_LOAD | InsnId::ADDF32_MOV32_STORE => {
                il.fadd(4, src1, src2).build()
            }
            InsnId::SUBF32_RAH_RBH_RCH | InsnId::SUBF32_MOV32_LOAD | InsnId::SUBF32_MOV32_STORE => {
                il.fsub(4, src1, src2).build()
            }
            InsnId::MPYF32_RAH_RBH_RCH
            | InsnId::MPYF32_ADDF32_PAR
            | InsnId::MPYF32_MOV32_LOAD
            | InsnId::MPYF32_MOV32_STORE => il.fmul(4, src1, src2).build(),
            // MAC: dst += src1 * src2
            InsnId::MACF32_RAH_RBH_RCH => {
                il.fadd(4, il.reg(4, dst), il.fmul(4, src1, src2)).build()
            }
            _ => {
                il.unimplemented().append();
                return true;
            }
        };
        il.set_reg(4, dst, result).append();

        // Handle parallel MOV (ops[3..4]) if present — FPU parallel instructions
        // e.g., MPYF32 R0H,R1H,R2H || MOV32 R3H,mem
        if ops.len() >= 5 {
            let mov_dst = &ops[3];
            let mov_src = &ops[4];
            if mov_dst.op_type == OperandType::Register {
                il.set_reg(
                    4,
                    reg_by_name(mov_dst.display_name()),
                    read_op(mov_src, il, 4),
                )
                .append();
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
            il.if_expr(cond, &mut keep_label, &mut replace_label)
                .append();
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

    // ── MOVIZ / MOVXI RaH, #16bit : load one half of RaH ──
    //    SPRUEO2B's own example is the specification:
    //        MOVIZF32 R0H,#0x4049   ; R0H = 0x40490000
    //        MOVXI    R0H,#0x0FDB   ; R0H = 0x40490FDB
    //    The two-operand arm below gave `RaH = imm` for both, which drops
    //    MOVIZ's shift and clobbers the half MOVXI must preserve.
    if matches!(n, InsnId::MOVIZ | InsnId::MOVXI) && ops.len() >= 2 {
        let dst = reg_by_name(ops[0].display_name());
        let imm = ops[1].value as u64 & 0xFFFF;
        let value = if matches!(n, InsnId::MOVIZ) {
            il.const_int(4, imm << 16)
        } else {
            il.or(
                4,
                il.and(4, il.reg(4, dst), il.const_int(4, 0xFFFF_0000)),
                il.const_int(4, imm),
            )
            .build()
        };
        il.set_reg(4, dst, value).append();
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
            il.set_reg(4, reg_by_name(op0.display_name()), read_op(op1, il, 4))
                .append();
            return true;
        }
    }

    il.unimplemented().append(); // guard: FPU with unrecognized operand types
    true
}
