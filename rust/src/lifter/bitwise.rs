// SPDX-License-Identifier: MIT
//! Bitwise operation lifter: AND, OR, XOR, NOT.

use crate::arch::{FlagWrite, Register};
use crate::types::*;

use binaryninja::low_level_il::LowLevelILMutableFunction;

use super::{op_at, read_op, reg_by_name, write_loc};

type ILFunc = LowLevelILMutableFunction;

pub fn lift_and(insn: &DecodedInstruction, _addr: u64, il: &ILFunc) -> bool {
    bitwise_common(insn, il, "and")
}

pub fn lift_or(insn: &DecodedInstruction, _addr: u64, il: &ILFunc) -> bool {
    bitwise_common(insn, il, "or")
}

pub fn lift_xor(insn: &DecodedInstruction, _addr: u64, il: &ILFunc) -> bool {
    bitwise_common(insn, il, "xor")
}

pub fn lift_not(insn: &DecodedInstruction, _addr: u64, il: &ILFunc) -> bool {
    // NOT ACC / NOT AX — complement all bits
    if matches!(insn.id, InsnId::NOT_ACC) {
        il.set_reg(4, Register::ACC, il.not(4, il.reg(4, Register::ACC)))
            .with_flag_write(FlagWrite::NZ)
            .append();
        return true;
    }
    if matches!(insn.id, InsnId::NOT_AX) {
        if let Some(op) = op_at(insn, 0) {
            let reg = reg_by_name(op.display_name());
            il.set_reg(2, reg, il.not(2, il.reg(2, reg)))
                .with_flag_write(FlagWrite::NZ)
                .append();
        }
        return true;
    }
    // Generic NOT loc16/loc32
    if let Some(op) = op_at(insn, 0) {
        let size = if op.op_type == OperandType::Loc32 {
            4
        } else {
            2
        };
        let val = read_op(op, il, size);
        let result = il.not(size, val).with_flag_write(FlagWrite::NZ).build();
        write_loc(op, il, size, result);
    } else {
        il.unimplemented().append(); // guard: NOT with no operands
    }
    true
}

fn bitwise_common(insn: &DecodedInstruction, il: &ILFunc, op_name: &str) -> bool {
    // ACC OP loc16 (single-operand: destination is implicit ACC)
    let n = insn.id;
    if matches!(
        (op_name, n),
        ("and", InsnId::AND_ACC_LOC16)
            | ("or", InsnId::OR_ACC_LOC16)
            | ("xor", InsnId::XOR_ACC_LOC16)
            | ("and", InsnId::AND_ACC_CONST16_SHIFT0_15)
            | ("or", InsnId::OR_ACC_CONST16_SHIFT0_15)
            | ("xor", InsnId::XOR_ACC_CONST16_SHIFT0_15)
    ) {
        if let Some(op) = op_at(insn, 0) {
            let acc = il.reg(4, Register::ACC);
            let src = il.sx(4, read_op(op, il, 2));
            let expr = match op_name {
                "and" => il.and(4, acc, src),
                "or" => il.or(4, acc, src),
                _ => il.xor(4, acc, src),
            };
            il.set_reg(4, Register::ACC, expr)
                .with_flag_write(FlagWrite::NZ)
                .append();
        }
        return true;
    }

    // xB AX, #const8 (byte immediate)
    if matches!(
        (op_name, n),
        ("and", InsnId::ANDB_AX_CONST8)
            | ("or", InsnId::ORB_AX_CONST8)
            | ("xor", InsnId::XORB_AX_CONST8)
    ) {
        if insn.operands.len() >= 2 {
            let reg = reg_by_name(insn.operands[0].display_name());
            let val = il.const_int(2, insn.operands[1].value as u64 & 0xFF);
            let lhs = il.reg(2, reg);
            let expr = match op_name {
                "and" => il.and(2, lhs, val),
                "or" => il.or(2, lhs, val),
                _ => il.xor(2, lhs, val),
            };
            il.set_reg(2, reg, expr)
                .with_flag_write(FlagWrite::NZ)
                .append();
        }
        return true;
    }

    // ── AND AX, loc16, #16bit ──
    //    SPRU430F: `AX = [loc16] AND 16bit`. The two-operand arm below reads
    //    only operands 0 and 1, so this became `AX = AX AND [loc16]` -- the
    //    mask silently dropped and the wrong source read. 799 corpus sites.
    if matches!(n, InsnId::AND_AX_LOC16_CONST16) {
        if insn.operands.len() >= 3 {
            let reg = reg_by_name(insn.operands[0].display_name());
            let src = read_op(&insn.operands[1], il, 2);
            let mask = il.const_int(2, insn.operands[2].value as u64);
            il.set_reg(2, reg, il.and(2, src, mask))
                .with_flag_write(FlagWrite::NZ)
                .append();
        }
        return true;
    }

    // ── AND ACC, #16bit << #16 ──
    if matches!(n, InsnId::AND_ACC_IMM16_SHIFT16) {
        if let Some(op) = op_at(insn, 0) {
            let mask = il.const_int(4, (op.value as u64 & 0xFFFF) << 16);
            il.set_reg(4, Register::ACC, il.and(4, il.reg(4, Register::ACC), mask))
                .with_flag_write(FlagWrite::NZ)
                .append();
        }
        return true;
    }

    // The arms below assume operand 0 is the destination and operand 1 the
    // only source. A row with a third operand does not fit that shape, and
    // guessing from the first two is how the mask above went missing.
    if insn.operands.len() > 2 {
        il.unimplemented().append();
        return true;
    }

    if insn.operands.len() >= 2 {
        let op0 = &insn.operands[0];
        let op1 = &insn.operands[1];

        if op0.op_type == OperandType::Register {
            let reg = reg_by_name(op0.display_name());
            let size = if matches!(reg, Register::ACC) { 4 } else { 2 };
            let lhs = il.reg(size, reg);
            let rhs = read_op(op1, il, size);
            let expr = match op_name {
                "and" => il.and(size, lhs, rhs),
                "or" => il.or(size, lhs, rhs),
                "xor" => il.xor(size, lhs, rhs),
                _ => unreachable!("bitwise_common called with invalid op_name"),
            };
            il.set_reg(size, reg, expr)
                .with_flag_write(FlagWrite::NZ)
                .append();
            return true;
        }

        if matches!(op0.op_type, OperandType::Loc16 | OperandType::Loc32) {
            let size = if op0.op_type == OperandType::Loc32 {
                4
            } else {
                2
            };
            let lhs = read_op(op0, il, size);
            let rhs = read_op(op1, il, size);
            let result = match op_name {
                "and" => il
                    .and(size, lhs, rhs)
                    .with_flag_write(FlagWrite::NZ)
                    .build(),
                "or" => il.or(size, lhs, rhs).with_flag_write(FlagWrite::NZ).build(),
                "xor" => il
                    .xor(size, lhs, rhs)
                    .with_flag_write(FlagWrite::NZ)
                    .build(),
                _ => unreachable!("bitwise_common called with invalid op_name"),
            };
            write_loc(op0, il, size, result);
            return true;
        }
    }

    // Single-operand bitwise: ACC op operand (implicit ACC destination)
    if insn.operands.len() == 1 {
        let op = &insn.operands[0];
        let acc = il.reg(4, Register::ACC);
        let src = il.sx(4, read_op(op, il, 2));
        let expr = match op_name {
            "and" => il.and(4, acc, src),
            "or" => il.or(4, acc, src),
            _ => il.xor(4, acc, src),
        };
        il.set_reg(4, Register::ACC, expr)
            .with_flag_write(FlagWrite::NZ)
            .append();
        return true;
    }

    il.unimplemented().append(); // guard: bitwise with no operands
    true
}
