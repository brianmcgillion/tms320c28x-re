// SPDX-License-Identifier: MIT
//! Lifts the moves whose semantics the ISA table declares in its `lift:` block.
//!
//! The mnemonic names both sides of these instructions but only one is encoded,
//! so a lifter that reads operands alone cannot tell `MOV T, loc16` from
//! `MOV loc16, T`. The generic fallback guessed `ACC`/`AL` and always loaded,
//! which reversed the direction of every store and named the wrong register in
//! all of them.

use crate::types::{DecodedInstruction, LiftRef, LiftSpec};

use binaryninja::low_level_il::LowLevelILMutableFunction;

use super::{read_op, reg_by_name, write_loc};

type ILFunc = LowLevelILMutableFunction;

pub fn lift(spec: LiftSpec, insn: &DecodedInstruction, il: &ILFunc) -> bool {
    let width = spec.width;
    match (spec.dst, spec.src) {
        (LiftRef::Reg(dst), LiftRef::Opnd(i)) => {
            let Some(op) = insn.operands.get(i) else {
                return false;
            };
            let value = read_op(op, il, width);
            il.set_reg(width, reg_by_name(dst), value).append();
        }
        (LiftRef::Opnd(i), LiftRef::Reg(src)) => {
            let Some(op) = insn.operands.get(i) else {
                return false;
            };
            let value = il.reg(width, reg_by_name(src));
            write_loc(op, il, width, value);
        }
        // build.rs rejects every other shape.
        _ => return false,
    }
    true
}
