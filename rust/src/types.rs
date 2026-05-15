// SPDX-License-Identifier: MIT
//! Core types for the TMS320C28x decoder.

// Include generated code from build.rs
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// Control flow classification for CFG construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchType {
    None,
    Unconditional,
    ConditionalTrue,
    Call,
    Return,
    Trap,
    /// CPU halt instructions (ESTOP0/ESTOP1) — execution never returns.
    /// Maps to BN's BranchKind::Exception so BN terminates the basic block
    /// and does not fall through to the next instruction.
    Halt,
}

/// Types of instruction operands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperandType {
    Register,
    Immediate,
    Loc16,
    Loc32,
    Condition,
}

/// A decoded instruction operand.
#[derive(Debug, Clone)]
pub struct Operand {
    pub op_type: OperandType,
    pub value: i32,
    pub name: &'static str,
    /// Dynamic name for addressing modes (heap-allocated only when needed)
    pub name_owned: Option<String>,
    pub size: u8,
    pub signed: bool,
    pub resolved: Option<crate::operands::ResolvedOperand>,
}

impl Operand {
    pub fn display_name(&self) -> &str {
        if let Some(ref owned) = self.name_owned {
            owned
        } else {
            self.name
        }
    }
}

/// Result of decoding a single instruction.
#[derive(Debug, Clone)]
pub struct DecodedInstruction {
    pub id: InsnId,
    pub name: &'static str,
    pub full_name: &'static str,
    pub size: u8,
    pub operands: Vec<Operand>,
    pub opcode: u32,
    pub branch_type: BranchType,
    pub branch_target: Option<u64>,
    pub sem_type: SemType,
}

impl DecodedInstruction {
    pub fn is_branch(&self) -> bool {
        self.branch_type != BranchType::None
    }
}

/// Extract bits [high:low] from value (inclusive).
#[inline]
pub fn extract_bits(value: u32, high: u8, low: u8) -> u32 {
    let mask = (1u32 << (high - low + 1)) - 1;
    (value >> low) & mask
}

/// Sign-extend a value from the given bit width.
#[inline]
pub fn sign_extend(value: u32, bits: u8) -> i32 {
    let sign_bit = 1u32 << (bits - 1);
    ((value ^ sign_bit).wrapping_sub(sign_bit)) as i32
}
