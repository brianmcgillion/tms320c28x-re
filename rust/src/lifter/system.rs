// SPDX-License-Identifier: MIT
//! System instruction lifter: NOP, EALLOW, EDIS, ESTOP, SETC, CLRC, etc.

use crate::arch::{Flag, Register};
use crate::types::*;

use binaryninja::low_level_il::LowLevelILMutableFunction;

type ILFunc = LowLevelILMutableFunction;

pub fn lift(insn: &DecodedInstruction, _addr: u64, il: &ILFunc) -> bool {
    match insn.id {
        // Breakpoints
        InsnId::ESTOP0 | InsnId::ESTOP1 => {
            il.bp().append();
        }

        // EALLOW/EDIS: enable/disable protected register access
        // Model as ST1 modification (bit 9 = EALLOW)
        InsnId::EALLOW => {
            // ST1.EALLOW = 1 — just emit nop, this is a privilege change
            il.nop().append();
        }
        InsnId::EDIS => {
            il.nop().append();
        }

        // Flag manipulation — SETC/CLRC
        // These set/clear specific status bits. We model with set_flag where possible.
        InsnId::SETC_MODE | InsnId::CLRC_MODE => {
            // SETC/CLRC with mode bits (OVM, SXM, C, TC, etc.)
            // The mode operand encodes which bits to set/clear
            // For decompilation, modeling as nop is acceptable
            il.nop().append();
        }
        InsnId::SETC_OBJMODE | InsnId::CLRC_OBJMODE |
        InsnId::SETC_M0M1MAP | InsnId::CLRC_M0M1MAP |
        InsnId::SETC_XF | InsnId::CLRC_XF |
        InsnId::CLRC_AMODE | InsnId::CLRC_OVC => {
            il.nop().append();
        }

        _ => {
            il.nop().append();
        }
    }
    true
}
