// SPDX-License-Identifier: MIT
//! TMS320C28x Architecture trait implementation for Binary Ninja.

use std::borrow::Cow;
use std::collections::HashMap;

use binaryninja::architecture::{
    self, BranchKind, CoreArchitecture, CustomArchitectureHandle, FlagCondition,
    FlagRole, ImplicitRegisterExtend, InstructionInfo, UnusedIntrinsic,
    UnusedRegisterStack, FlagId, FlagWriteId, FlagClassId, FlagGroupId, RegisterId,
};
use binaryninja::disassembly::{
    InstructionTextToken, InstructionTextTokenContext, InstructionTextTokenKind,
};
use binaryninja::low_level_il::LowLevelILMutableFunction;
use binaryninja::Endianness;

use crate::decoder::Decoder;
use crate::types::*;

// ------------------------------------------------------------------ //
// Register definitions                                                 //
// ------------------------------------------------------------------ //

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Register {
    ACC, AH, AL,
    XAR0, AR0, XAR1, AR1, XAR2, AR2, XAR3, AR3,
    XAR4, AR4, XAR5, AR5, XAR6, AR6, XAR7, AR7,
    P, PH, PL,
    XT, T, TL,
    SP, DP, PC, RPC,
    ST0, ST1, IER, IFR, DBGIER,
    R0H, R1H, R2H, R3H, R4H, R5H, R6H, R7H,
    STF,
}

impl Register {
    const ALL: &'static [Register] = &[
        Register::ACC, Register::AH, Register::AL,
        Register::XAR0, Register::AR0, Register::XAR1, Register::AR1,
        Register::XAR2, Register::AR2, Register::XAR3, Register::AR3,
        Register::XAR4, Register::AR4, Register::XAR5, Register::AR5,
        Register::XAR6, Register::AR6, Register::XAR7, Register::AR7,
        Register::P, Register::PH, Register::PL,
        Register::XT, Register::T, Register::TL,
        Register::SP, Register::DP, Register::PC, Register::RPC,
        Register::ST0, Register::ST1, Register::IER, Register::IFR, Register::DBGIER,
        Register::R0H, Register::R1H, Register::R2H, Register::R3H,
        Register::R4H, Register::R5H, Register::R6H, Register::R7H,
        Register::STF,
    ];

    const FULL_WIDTH: &'static [Register] = &[
        Register::ACC,
        Register::XAR0, Register::XAR1, Register::XAR2, Register::XAR3,
        Register::XAR4, Register::XAR5, Register::XAR6, Register::XAR7,
        Register::P, Register::XT,
        Register::SP, Register::DP, Register::PC, Register::RPC,
        Register::ST0, Register::ST1, Register::IER, Register::IFR, Register::DBGIER,
        Register::R0H, Register::R1H, Register::R2H, Register::R3H,
        Register::R4H, Register::R5H, Register::R6H, Register::R7H,
        Register::STF,
    ];
}

impl TryFrom<u32> for Register {
    type Error = ();
    fn try_from(id: u32) -> Result<Self, Self::Error> {
        Register::ALL.get(id as usize).copied().ok_or(())
    }
}

impl architecture::Register for Register {
    type InfoType = Self;

    fn name(&self) -> Cow<'_, str> {
        match self {
            Register::ACC => "ACC".into(), Register::AH => "AH".into(), Register::AL => "AL".into(),
            Register::XAR0 => "XAR0".into(), Register::AR0 => "AR0".into(),
            Register::XAR1 => "XAR1".into(), Register::AR1 => "AR1".into(),
            Register::XAR2 => "XAR2".into(), Register::AR2 => "AR2".into(),
            Register::XAR3 => "XAR3".into(), Register::AR3 => "AR3".into(),
            Register::XAR4 => "XAR4".into(), Register::AR4 => "AR4".into(),
            Register::XAR5 => "XAR5".into(), Register::AR5 => "AR5".into(),
            Register::XAR6 => "XAR6".into(), Register::AR6 => "AR6".into(),
            Register::XAR7 => "XAR7".into(), Register::AR7 => "AR7".into(),
            Register::P => "P".into(), Register::PH => "PH".into(), Register::PL => "PL".into(),
            Register::XT => "XT".into(), Register::T => "T".into(), Register::TL => "TL".into(),
            Register::SP => "SP".into(), Register::DP => "DP".into(),
            Register::PC => "PC".into(), Register::RPC => "RPC".into(),
            Register::ST0 => "ST0".into(), Register::ST1 => "ST1".into(),
            Register::IER => "IER".into(), Register::IFR => "IFR".into(),
            Register::DBGIER => "DBGIER".into(),
            Register::R0H => "R0H".into(), Register::R1H => "R1H".into(),
            Register::R2H => "R2H".into(), Register::R3H => "R3H".into(),
            Register::R4H => "R4H".into(), Register::R5H => "R5H".into(),
            Register::R6H => "R6H".into(), Register::R7H => "R7H".into(),
            Register::STF => "STF".into(),
        }
    }

    fn info(&self) -> Self::InfoType { *self }

    fn id(&self) -> RegisterId {
        RegisterId(Register::ALL.iter().position(|r| r == self).unwrap() as u32)
    }
}

impl architecture::RegisterInfo for Register {
    type RegType = Self;

    fn parent(&self) -> Option<Self::RegType> {
        match self {
            Register::AH | Register::AL => Some(Register::ACC),
            Register::AR0 => Some(Register::XAR0), Register::AR1 => Some(Register::XAR1),
            Register::AR2 => Some(Register::XAR2), Register::AR3 => Some(Register::XAR3),
            Register::AR4 => Some(Register::XAR4), Register::AR5 => Some(Register::XAR5),
            Register::AR6 => Some(Register::XAR6), Register::AR7 => Some(Register::XAR7),
            Register::PH | Register::PL => Some(Register::P),
            Register::T | Register::TL => Some(Register::XT),
            _ => None,
        }
    }

    fn size(&self) -> usize {
        match self {
            Register::ACC | Register::P | Register::XT | Register::PC | Register::RPC => 4,
            Register::XAR0 | Register::XAR1 | Register::XAR2 | Register::XAR3 => 4,
            Register::XAR4 | Register::XAR5 | Register::XAR6 | Register::XAR7 => 4,
            Register::R0H | Register::R1H | Register::R2H | Register::R3H => 4,
            Register::R4H | Register::R5H | Register::R6H | Register::R7H => 4,
            Register::STF => 4,
            _ => 2,
        }
    }

    fn offset(&self) -> usize {
        match self {
            Register::AH | Register::PH | Register::T => 2,
            _ => 0,
        }
    }

    fn implicit_extend(&self) -> ImplicitRegisterExtend {
        ImplicitRegisterExtend::NoExtend
    }
}

impl From<Register> for binaryninja::low_level_il::LowLevelILRegisterKind<Register> {
    fn from(reg: Register) -> Self {
        binaryninja::low_level_il::LowLevelILRegisterKind::Arch(reg)
    }
}

// ------------------------------------------------------------------ //
// Flag definitions                                                     //
// ------------------------------------------------------------------ //

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Flag {
    N, Z, C, V, TC, OVM,
}

impl TryFrom<u32> for Flag {
    type Error = ();
    fn try_from(id: u32) -> Result<Self, Self::Error> {
        match id {
            0 => Ok(Flag::N), 1 => Ok(Flag::Z), 2 => Ok(Flag::C),
            3 => Ok(Flag::V), 4 => Ok(Flag::TC), 5 => Ok(Flag::OVM),
            _ => Err(()),
        }
    }
}

impl architecture::Flag for Flag {
    type FlagClass = FlagClass;

    fn name(&self) -> Cow<'_, str> {
        match self {
            Flag::N => "N".into(), Flag::Z => "Z".into(), Flag::C => "C".into(),
            Flag::V => "V".into(), Flag::TC => "TC".into(), Flag::OVM => "OVM".into(),
        }
    }

    fn role(&self, _class: Option<Self::FlagClass>) -> FlagRole {
        match self {
            Flag::N => FlagRole::NegativeSignFlagRole,
            Flag::Z => FlagRole::ZeroFlagRole,
            Flag::C => FlagRole::CarryFlagRole,
            Flag::V => FlagRole::OverflowFlagRole,
            Flag::TC | Flag::OVM => FlagRole::SpecialFlagRole,
        }
    }

    fn id(&self) -> FlagId {
        FlagId(match self {
            Flag::N => 0, Flag::Z => 1, Flag::C => 2,
            Flag::V => 3, Flag::TC => 4, Flag::OVM => 5,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlagWrite {
    All, NZ, NZCV,
}

impl TryFrom<u32> for FlagWrite {
    type Error = ();
    fn try_from(id: u32) -> Result<Self, Self::Error> {
        match id {
            1 => Ok(FlagWrite::All), 2 => Ok(FlagWrite::NZ), 3 => Ok(FlagWrite::NZCV),
            _ => Err(()),
        }
    }
}

impl architecture::FlagWrite for FlagWrite {
    type FlagType = Flag;
    type FlagClass = FlagClass;

    fn name(&self) -> Cow<'_, str> {
        match self {
            FlagWrite::All => "*".into(), FlagWrite::NZ => "nz".into(), FlagWrite::NZCV => "nzcv".into(),
        }
    }

    fn class(&self) -> Option<Self::FlagClass> { None }

    fn id(&self) -> FlagWriteId {
        FlagWriteId(match self {
            FlagWrite::All => 1, FlagWrite::NZ => 2, FlagWrite::NZCV => 3,
        })
    }

    fn flags_written(&self) -> Vec<Self::FlagType> {
        match self {
            FlagWrite::All | FlagWrite::NZCV => vec![Flag::N, Flag::Z, Flag::C, Flag::V],
            FlagWrite::NZ => vec![Flag::N, Flag::Z],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlagClass;

impl architecture::FlagClass for FlagClass {
    fn name(&self) -> Cow<'_, str> { unimplemented!() }
    fn id(&self) -> FlagClassId { unimplemented!() }
}

impl TryFrom<u32> for FlagClass {
    type Error = ();
    fn try_from(_: u32) -> Result<Self, Self::Error> { Err(()) }
}

/// Flag groups tell BN how to synthesize readable conditions from CPU flags.
/// Without these, HLIL shows `cond:0` instead of `x == 0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlagGroup {
    E,    // Z==1  (equal)
    NE,   // Z==0  (not equal)
    SLT,  // N==1  (signed less than)
    SGE,  // N==0  (signed greater or equal)
    SGT,  // Z==0 && N==0 (signed greater than)
    SLE,  // Z==1 || N==1 (signed less or equal)
    UGE,  // C==1  (unsigned greater or equal / carry set)
    ULT,  // C==0  (unsigned less than / carry clear)
    UGT,  // C==1 && Z==0 (unsigned greater than)
    ULE,  // C==0 || Z==1 (unsigned less or equal)
    O,    // V==1  (overflow)
    NO,   // V==0  (no overflow)
}

impl architecture::FlagGroup for FlagGroup {
    type FlagType = Flag;
    type FlagClass = FlagClass;

    fn name(&self) -> Cow<'_, str> {
        match self {
            FlagGroup::E => "e".into(),     FlagGroup::NE => "ne".into(),
            FlagGroup::SLT => "slt".into(), FlagGroup::SGE => "sge".into(),
            FlagGroup::SGT => "sgt".into(), FlagGroup::SLE => "sle".into(),
            FlagGroup::UGE => "uge".into(), FlagGroup::ULT => "ult".into(),
            FlagGroup::UGT => "ugt".into(), FlagGroup::ULE => "ule".into(),
            FlagGroup::O => "o".into(),     FlagGroup::NO => "no".into(),
        }
    }

    fn id(&self) -> FlagGroupId {
        FlagGroupId(match self {
            FlagGroup::E => 1,   FlagGroup::NE => 2,
            FlagGroup::SLT => 3, FlagGroup::SGE => 4,
            FlagGroup::SGT => 5, FlagGroup::SLE => 6,
            FlagGroup::UGE => 7, FlagGroup::ULT => 8,
            FlagGroup::UGT => 9, FlagGroup::ULE => 10,
            FlagGroup::O => 11,  FlagGroup::NO => 12,
        })
    }

    fn flags_required(&self) -> Vec<Self::FlagType> {
        match self {
            FlagGroup::E | FlagGroup::NE => vec![Flag::Z],
            FlagGroup::SLT | FlagGroup::SGE => vec![Flag::N],
            FlagGroup::SGT | FlagGroup::SLE => vec![Flag::Z, Flag::N],
            FlagGroup::UGE | FlagGroup::ULT => vec![Flag::C],
            FlagGroup::UGT | FlagGroup::ULE => vec![Flag::C, Flag::Z],
            FlagGroup::O | FlagGroup::NO => vec![Flag::V],
        }
    }

    fn flag_conditions(&self) -> HashMap<Self::FlagClass, FlagCondition> {
        HashMap::new()
    }
}

impl TryFrom<u32> for FlagGroup {
    type Error = ();
    fn try_from(id: u32) -> Result<Self, Self::Error> {
        match id {
            1 => Ok(FlagGroup::E),   2 => Ok(FlagGroup::NE),
            3 => Ok(FlagGroup::SLT), 4 => Ok(FlagGroup::SGE),
            5 => Ok(FlagGroup::SGT), 6 => Ok(FlagGroup::SLE),
            7 => Ok(FlagGroup::UGE), 8 => Ok(FlagGroup::ULT),
            9 => Ok(FlagGroup::UGT), 10 => Ok(FlagGroup::ULE),
            11 => Ok(FlagGroup::O),  12 => Ok(FlagGroup::NO),
            _ => Err(()),
        }
    }
}

// ------------------------------------------------------------------ //
// Architecture struct                                                  //
// ------------------------------------------------------------------ //

pub struct TMS320C28x {
    handle: CoreArchitecture,
    custom_handle: CustomArchitectureHandle<TMS320C28x>,
    decoder: Decoder,
}

impl TMS320C28x {
    pub fn new(
        handle: CoreArchitecture,
        custom_handle: CustomArchitectureHandle<TMS320C28x>,
    ) -> Self {
        Self {
            handle,
            custom_handle,
            decoder: Decoder::new(1),
        }
    }
}

impl AsRef<CoreArchitecture> for TMS320C28x {
    fn as_ref(&self) -> &CoreArchitecture {
        &self.handle
    }
}

impl architecture::Architecture for TMS320C28x {
    type Handle = CustomArchitectureHandle<Self>;
    type Register = Register;
    type RegisterInfo = Register;
    type RegisterStackInfo = UnusedRegisterStack<Self::Register>;
    type RegisterStack = UnusedRegisterStack<Self::Register>;
    type Flag = Flag;
    type FlagWrite = FlagWrite;
    type FlagClass = FlagClass;
    type FlagGroup = FlagGroup;
    type Intrinsic = UnusedIntrinsic;

    fn endianness(&self) -> Endianness { Endianness::LittleEndian }
    fn address_size(&self) -> usize { 4 }
    fn default_integer_size(&self) -> usize { 2 }
    fn instruction_alignment(&self) -> usize { 2 }
    fn max_instr_len(&self) -> usize { 4 }
    fn opcode_display_len(&self) -> usize { 4 }

    fn associated_arch_by_addr(&self, _addr: u64) -> CoreArchitecture {
        self.handle
    }

    fn handle(&self) -> Self::Handle {
        self.custom_handle
    }

    fn registers_all(&self) -> Vec<Self::Register> { Register::ALL.to_vec() }
    fn registers_full_width(&self) -> Vec<Self::Register> { Register::FULL_WIDTH.to_vec() }

    fn register_from_id(&self, id: RegisterId) -> Option<Self::Register> {
        Register::try_from(id.0).ok()
    }

    fn stack_pointer_reg(&self) -> Option<Self::Register> { Some(Register::SP) }
    fn link_reg(&self) -> Option<Self::Register> { Some(Register::RPC) }

    fn flags(&self) -> Vec<Self::Flag> {
        vec![Flag::N, Flag::Z, Flag::C, Flag::V, Flag::TC, Flag::OVM]
    }

    fn flag_write_types(&self) -> Vec<Self::FlagWrite> {
        vec![FlagWrite::All, FlagWrite::NZ, FlagWrite::NZCV]
    }

    fn flag_from_id(&self, id: FlagId) -> Option<Self::Flag> { Flag::try_from(id.0).ok() }
    fn flag_write_from_id(&self, id: FlagWriteId) -> Option<Self::FlagWrite> { FlagWrite::try_from(id.0).ok() }
    fn flag_class_from_id(&self, _id: FlagClassId) -> Option<Self::FlagClass> { None }
    fn flag_group_from_id(&self, id: FlagGroupId) -> Option<Self::FlagGroup> { FlagGroup::try_from(id.0).ok() }

    fn flags_required_for_flag_condition(
        &self,
        condition: FlagCondition,
        _class: Option<Self::FlagClass>,
    ) -> Vec<Self::Flag> {
        match condition {
            FlagCondition::LLFC_NE | FlagCondition::LLFC_E => vec![Flag::Z],
            FlagCondition::LLFC_SGT | FlagCondition::LLFC_SLE => vec![Flag::Z, Flag::N],
            FlagCondition::LLFC_SGE | FlagCondition::LLFC_SLT => vec![Flag::N],
            FlagCondition::LLFC_UGT => vec![Flag::C, Flag::Z],
            FlagCondition::LLFC_UGE | FlagCondition::LLFC_ULT => vec![Flag::C],
            FlagCondition::LLFC_O | FlagCondition::LLFC_NO => vec![Flag::V],
            _ => vec![],
        }
    }

    fn flag_group_llil<'a>(
        &self,
        group: Self::FlagGroup,
        il: &'a LowLevelILMutableFunction,
    ) -> Option<binaryninja::low_level_il::LowLevelILMutableExpression<'a, binaryninja::low_level_il::expression::ValueExpr>> {
        let z = || il.flag(Flag::Z);
        let n = || il.flag(Flag::N);
        let c = || il.flag(Flag::C);
        let v = || il.flag(Flag::V);
        let one = || il.const_int(0, 1);
        let zero = || il.const_int(0, 0);

        let expr = match group {
            FlagGroup::E   => il.cmp_e(0, z(), one()),     // Z == 1
            FlagGroup::NE  => il.cmp_e(0, z(), zero()),    // Z == 0
            FlagGroup::SLT => il.cmp_e(0, n(), one()),     // N == 1
            FlagGroup::SGE => il.cmp_e(0, n(), zero()),    // N == 0
            FlagGroup::SGT => il.and(0, il.cmp_e(0, z(), zero()), il.cmp_e(0, n(), zero())), // Z==0 && N==0
            FlagGroup::SLE => il.or(0, il.cmp_e(0, z(), one()), il.cmp_e(0, n(), one())),    // Z==1 || N==1
            FlagGroup::UGE => il.cmp_e(0, c(), one()),     // C == 1
            FlagGroup::ULT => il.cmp_e(0, c(), zero()),    // C == 0
            FlagGroup::UGT => il.and(0, il.cmp_e(0, c(), one()), il.cmp_e(0, z(), zero())),  // C==1 && Z==0
            FlagGroup::ULE => il.or(0, il.cmp_e(0, c(), zero()), il.cmp_e(0, z(), one())),   // C==0 || Z==1
            FlagGroup::O   => il.cmp_e(0, v(), one()),     // V == 1
            FlagGroup::NO  => il.cmp_e(0, v(), zero()),    // V == 0
        };
        Some(expr.build())
    }

    fn instruction_info(&self, data: &[u8], addr: u64) -> Option<InstructionInfo> {
        let insn = self.decoder.decode(data, addr)?;
        let mut info = InstructionInfo::new(insn.size as usize, 0);

        match insn.branch_type {
            BranchType::Unconditional => {
                if let Some(target) = insn.branch_target {
                    info.add_branch(BranchKind::Unconditional(target));
                } else {
                    info.add_branch(BranchKind::Indirect);
                }
            }
            BranchType::ConditionalTrue => {
                if let Some(target) = insn.branch_target {
                    info.add_branch(BranchKind::True(target));
                    info.add_branch(BranchKind::False(addr + insn.size as u64));
                }
            }
            BranchType::Call => {
                if let Some(target) = insn.branch_target {
                    info.add_branch(BranchKind::Call(target));
                } else {
                    info.add_branch(BranchKind::Indirect);
                }
            }
            BranchType::Return => {
                info.add_branch(BranchKind::FunctionReturn);
            }
            BranchType::Trap => {
                info.add_branch(BranchKind::SystemCall);
            }
            BranchType::Halt => {
                // ESTOP0/ESTOP1: CPU halt, never returns. Exception kind tells
                // BN to terminate the basic block with no fall-through.
                info.add_branch(BranchKind::Exception);
            }
            BranchType::None => {}
        }

        Some(info)
    }

    fn instruction_text(
        &self,
        data: &[u8],
        addr: u64,
    ) -> Option<(usize, Vec<InstructionTextToken>)> {
        let insn = self.decoder.decode(data, addr)?;
        let mut tokens = Vec::new();

        let mnemonic = display_mnemonic(insn.id, None);
        tokens.push(InstructionTextToken {
            address: 0,
            text: mnemonic.to_string(),
            confidence: 255,
            context: InstructionTextTokenContext::Normal,
            expr_index: None,
            kind: InstructionTextTokenKind::Instruction,
        });

        for (i, op) in insn.operands.iter().enumerate() {
            tokens.push(InstructionTextToken {
                address: 0,
                text: if i == 0 { " ".to_string() } else { ", ".to_string() },
                confidence: 255,
                context: InstructionTextTokenContext::Normal,
                expr_index: None,
                kind: if i == 0 { InstructionTextTokenKind::Text } else { InstructionTextTokenKind::OperandSeparator },
            });

            let (text, kind) = match op.op_type {
                OperandType::Register => (
                    op.display_name().to_string(),
                    InstructionTextTokenKind::Register,
                ),
                OperandType::Condition => (
                    op.display_name().to_string(),
                    InstructionTextTokenKind::Text,
                ),
                OperandType::Loc16 | OperandType::Loc32 => (
                    op.display_name().to_string(),
                    InstructionTextTokenKind::Text,
                ),
                OperandType::Immediate => {
                    if insn.is_branch() && i == 0 {
                        let target = insn.branch_target.unwrap_or(op.value as u64);
                        (
                            format!("0x{:X}", target),
                            InstructionTextTokenKind::PossibleAddress { value: target, size: Some(4) },
                        )
                    } else if op.signed && op.value < 0 {
                        (
                            format!("-0x{:X}", -op.value),
                            InstructionTextTokenKind::Integer { value: op.value as u64, size: Some(2) },
                        )
                    } else {
                        (
                            format!("#0x{:X}", op.value),
                            InstructionTextTokenKind::Integer { value: op.value as u64, size: Some(2) },
                        )
                    }
                }
            };

            tokens.push(InstructionTextToken {
                address: 0,
                text,
                confidence: 255,
                context: InstructionTextTokenContext::Normal,
                expr_index: None,
                kind,
            });
        }

        Some((insn.size as usize, tokens))
    }

    fn instruction_llil(
        &self,
        data: &[u8],
        addr: u64,
        il: &LowLevelILMutableFunction,
    ) -> Option<(usize, bool)> {
        let insn = self.decoder.decode(data, addr)?;
        let lifted = crate::lifter::lift(&insn, addr, il);
        if !lifted {
            il.nop().append();
        }
        Some((insn.size as usize, lifted))
    }
}
