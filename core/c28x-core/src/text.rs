// SPDX-License-Identifier: MIT
//! Instruction text, in TI syntax.
//!
//! This lives in core rather than in the Binary Ninja plugin so the plugin and
//! `c28xdec` render identically. They did not before: the differential in
//! `scripts/decode_coverage.py` reimplemented the plugin's rules in Python and
//! could report a parity the plugin did not have.
//!
//! The plugin needs a token *kind* per operand, so this yields pieces rather
//! than a finished string; `text()` joins them for anyone who only wants the
//! line.

use crate::types::{
    display_mnemonic, operand_text, DecodedInstruction, InsnId, OpType, Operand, OperandType,
    MODE_BITS, SETFLG_BITS,
};

/// What a piece of rendered text is, so a caller can colour it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Mnemonic,
    Literal,
    Register,
    Condition,
    Memory,
    Immediate(i64),
    /// A resolved branch destination, in bytes.
    Target(u64),
    /// An immediate that is also an address, in bytes.
    Address(u64),
}

#[derive(Debug, Clone)]
pub struct Piece {
    pub text: String,
    pub kind: Kind,
}

fn piece(text: String, kind: Kind) -> Piece {
    Piece { text, kind }
}

/// CLRC/SETC name their mode bits; SETFLG pairs an 11-bit select with 11 values.
fn flag_names(id: InsnId, value: i32) -> Option<String> {
    match id {
        InsnId::CLRC_MODE | InsnId::SETC_MODE => {
            let names: Vec<&str> = MODE_BITS
                .iter()
                .enumerate()
                .filter(|(b, _)| value & (1 << b) != 0)
                .map(|(_, n)| *n)
                .collect();
            Some(if names.is_empty() {
                format!("#0x{value:x}")
            } else {
                names.join("|")
            })
        }
        InsnId::SETFLG => {
            let v = value as u32;
            Some(
                SETFLG_BITS
                    .iter()
                    .enumerate()
                    .filter(|(b, _)| v & (1 << (b + 11)) != 0)
                    .map(|(b, n)| format!("{n}={}", (v >> b) & 1))
                    .collect::<Vec<_>>()
                    .join(","),
            )
        }
        _ => None,
    }
}

fn operand(insn: &DecodedInstruction, index: usize, op: &Operand, style: &str) -> Piece {
    if let Some(text) = flag_names(insn.id, op.value) {
        return piece(text, Kind::Literal);
    }
    // SPM's 3-bit field encodes the shift as `1 - field`: 0 is `#1` and 7 is
    // `#-6`, so the raw value is neither what TI prints nor what the hardware
    // shifts by. Checked before the style, which would otherwise print the raw
    // field in decimal and look right.
    if insn.id == InsnId::SPM_SHIFT {
        let shift = 1 - (op.value & 0x7);
        return piece(format!("#{shift}"), Kind::Immediate(shift as i64));
    }
    // The style comes from the table, which took it from TI: `ADDB ACC, #1` but
    // `ANDB AL, #0x1`, and a shift amount bare.
    match style {
        "d" => return piece(format!("#{}", op.value), Kind::Immediate(op.value as i64)),
        "b" => return piece(format!("{}", op.value), Kind::Immediate(op.value as i64)),
        // MOVIZ and SWAPF name the FPU register `R1`, where MOVXI names the
        // same register at the same width `R1H`. Display only -- the operand
        // keeps the name the lifter resolves.
        "R" => return piece(format!("R{}", op.value & 0x7), Kind::Register),
        // `MOV32 loc32, addr16` reaches the FPU register file through its
        // memory mapping, and dis2000 names the register whenever the address
        // is one: sweeping 0x0F00-0x0F3F, 0x0F10 + 4n is RnL and the three
        // words above it are RnH. Everything else is a plain absolute address.
        "m32" => {
            let addr = op.value as u32 & 0xFFFF;
            return match addr.checked_sub(0x0F10).filter(|d| *d < 32) {
                Some(d) => piece(
                    format!("R{}{}", d / 4, if d % 4 == 0 { "L" } else { "H" }),
                    Kind::Register,
                ),
                None => piece(format!("*(0:0x{addr:04x})"), Kind::Memory),
            };
        }
        _ => {}
    }
    // `{N:0Wx}` -- a zero-padded hex width, because TI's width is per
    // instruction, not per operand size: `OR loc16, #0x0001` pads a 16-bit
    // immediate to four digits while `MOVW DP, #0x1` does not pad the same
    // width at all. The widths come from isa/reference/operand_text.tsv, which
    // probed each row against dis2000 with the value 1, so the padding is
    // visible directly in the sample text. `{N:b0Wx}` is the same without the
    // `#`, which the address inside `*(0:0x0001)` needs.
    let (hash, width_spec) = match style.strip_prefix('b') {
        Some(rest) if !rest.is_empty() => ("", rest),
        _ => ("#", style),
    };
    let hex_width = width_spec
        .strip_prefix('0')
        .and_then(|s| s.strip_suffix('x'))
        .and_then(|s| s.parse::<usize>().ok());
    match op.op_type {
        OperandType::Register => piece(op.display_name().to_string(), Kind::Register),
        OperandType::Condition => piece(op.display_name().to_string(), Kind::Condition),
        OperandType::Loc16 | OperandType::Loc32 => {
            // TI marks a register-direct loc16/loc32 with `@` in some rows and
            // leaves it bare in others, and the choice is per register too:
            // `OR AL, @AH` but `OR AL, AR0`, `MOVZ AR4, @AR0` but
            // `MOVZ AR4, AR6`. asm2000 assembles both spellings to the same
            // word, so nothing derives the choice -- `{N:@AH|AL}` lists the
            // registers dis2000 was probed to mark, per row.
            let name = op.display_name();
            if style
                .strip_prefix('@')
                .is_some_and(|regs| regs.split('|').any(|r| r == name))
            {
                return piece(format!("@{name}"), Kind::Memory);
            }
            piece(name.to_string(), Kind::Memory)
        }
        OperandType::Immediate => {
            // `MOVL XARn, #const22` is TI's global-access idiom and its
            // immediate is a word address; as a plain integer it left every
            // global out of the Cross-References pane.
            if op.op_kind == OpType::Imm22 && insn.branch_type == crate::types::BranchType::None {
                let target = (op.value as u64 & 0x3F_FFFF) * 2;
                return piece(
                    format!("#0x{:0width$x}", op.value, width = hex_width.unwrap_or(1)),
                    Kind::Address(target),
                );
            }
            if index == 0 && insn.branch_type != crate::types::BranchType::None {
                let target = insn.branch_target.unwrap_or(op.value as u64);
                return piece(format!("0x{target:x}"), Kind::Target(target));
            }
            if op.signed && op.value < 0 {
                return piece(
                    format!("-0x{:0width$x}", -op.value, width = hex_width.unwrap_or(1)),
                    Kind::Immediate(op.value as i64),
                );
            }
            piece(
                format!(
                    "{hash}0x{:0width$x}",
                    op.value,
                    width = hex_width.unwrap_or(1)
                ),
                Kind::Immediate(op.value as i64),
            )
        }
    }
}

/// Mnemonic, then the operands laid out as the table's `operand_text:` says.
pub fn pieces(insn: &DecodedInstruction) -> Vec<Piece> {
    let mut out = vec![piece(
        display_mnemonic(insn.id, None).to_string(),
        Kind::Mnemonic,
    )];

    // TI never prints `<< 0`: a zero shift collapses to the instruction's
    // shift-free syntax, which can also format the immediate differently
    // (`MOV ACC, #1498` against `MOV ACC, #0x5da << 1`). A row that has both
    // carries them as `long | short`, and the short one wins when every
    // operand it drops is zero.
    let layout = match operand_text(insn.id).split_once(" | ") {
        Some((long, short)) => {
            let mentions = |t: &str, i: usize| {
                t.contains(&format!("{{{i}}}")) || t.contains(&format!("{{{i}:"))
            };
            let folds = insn
                .operands
                .iter()
                .enumerate()
                .all(|(i, op)| op.value == 0 || !mentions(long, i) || mentions(short, i));
            if folds {
                short
            } else {
                long
            }
        }
        None => operand_text(insn.id),
    };
    let mut slots: Vec<(Option<(usize, &str)>, String)> = Vec::new();
    if layout.is_empty() {
        for i in 0..insn.operands.len() {
            if i > 0 {
                slots.push((None, ", ".to_string()));
            }
            slots.push((Some((i, "")), String::new()));
        }
    } else {
        let mut rest = layout;
        while let Some(open) = rest.find('{') {
            let Some(close) = rest[open..].find('}') else {
                break;
            };
            let body = &rest[open + 1..open + close];
            let (num, style) = match body.split_once(':') {
                Some((n, st)) => (n, st),
                None => (body, ""),
            };
            if !rest[..open].is_empty() {
                slots.push((None, rest[..open].to_string()));
            }
            slots.push((num.parse::<usize>().ok().map(|i| (i, style)), String::new()));
            rest = &rest[open + close + 1..];
        }
        if !rest.is_empty() {
            slots.push((None, rest.to_string()));
        }
    }

    let mut first = true;
    for (slot, literal) in slots {
        match slot {
            None => {
                out.push(piece(
                    if first {
                        format!(" {literal}")
                    } else {
                        literal
                    },
                    Kind::Literal,
                ));
                first = false;
            }
            Some((i, style)) => {
                let Some(op) = insn.operands.get(i) else {
                    continue;
                };
                if first {
                    out.push(piece(" ".to_string(), Kind::Literal));
                    first = false;
                }
                out.push(operand(insn, i, op, style));
            }
        }
    }
    out
}

/// The whole line, for callers that do not need tokens.
pub fn text(insn: &DecodedInstruction) -> String {
    pieces(insn).into_iter().map(|p| p.text).collect()
}
