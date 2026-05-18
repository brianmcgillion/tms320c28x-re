// SPDX-License-Identifier: MIT
//! TMS320C28x Binary Ninja architecture plugin (Rust).

pub mod arch;
pub mod coff;
pub mod decoder;
pub mod lifter;
pub mod operands;
pub mod types;

use binaryninja::architecture::{register_architecture, ArchitectureExt, RegisterId};
use binaryninja::calling_convention::{CallingConvention, register_calling_convention};

use arch::Register;

/// ELF e_machine values used by TI C2000 toolchains.
/// Referenced by the Python ELF BinaryView; documented here for cross-reference.
#[allow(dead_code)]
const EM_TI_C6000: u32 = 141;
#[allow(dead_code)]
const EM_TI_C2000: u32 = 157;

/// TI C28x C/C++ compiler calling convention.
///
/// Reference: TI SPRU514 "TMS320C28x Optimizing C/C++ Compiler User's Guide"
/// - Arguments passed in AL, AH, XAR4, XAR5 (then stack)
/// - Return value in AL (16-bit) or ACC = AH:AL (32-bit)
/// - XAR1, XAR2, XAR3 are callee-saved
struct C28xCallingConvention;

unsafe impl Sync for C28xCallingConvention {}

impl CallingConvention for C28xCallingConvention {
    fn caller_saved_registers(&self) -> Vec<RegisterId> {
        use Register::*;
        // TI SPRU514 Table 7-2: "Save on Call" (caller-saved / volatile)
        [ACC, AH, AL, P, PH, PL, XT, T, TL,
         XAR0, XAR4, XAR5, XAR6, XAR7,
         ST0, ST1, DP,
         R0H, R1H, R2H, R3H,  // FPU scratch registers
         STF]
            .iter()
            .map(|r| <Register as binaryninja::architecture::Register>::id(r))
            .collect()
    }

    fn callee_saved_registers(&self) -> Vec<RegisterId> {
        use Register::*;
        // TI SPRU514: "Save on Entry" (callee-saved / non-volatile)
        // XAR1-XAR3 always; R4H-R7H when FPU enabled
        [XAR1, XAR2, XAR3, R4H, R5H, R6H, R7H]
            .iter()
            .map(|r| <Register as binaryninja::architecture::Register>::id(r))
            .collect()
    }

    fn int_arg_registers(&self) -> Vec<RegisterId> {
        use Register::*;
        [AL, AH, XAR4, XAR5]
            .iter()
            .map(|r| <Register as binaryninja::architecture::Register>::id(r))
            .collect()
    }

    fn float_arg_registers(&self) -> Vec<RegisterId> {
        Vec::new()
    }

    fn arg_registers_shared_index(&self) -> bool { false }
    fn reserved_stack_space_for_arg_registers(&self) -> bool { false }
    fn stack_adjusted_on_return(&self) -> bool { false }
    fn is_eligible_for_heuristics(&self) -> bool { true }

    fn return_int_reg(&self) -> Option<RegisterId> {
        Some(<Register as binaryninja::architecture::Register>::id(&Register::AL))
    }

    fn return_hi_int_reg(&self) -> Option<RegisterId> {
        Some(<Register as binaryninja::architecture::Register>::id(&Register::AH))
    }

    fn return_float_reg(&self) -> Option<RegisterId> {
        Some(<Register as binaryninja::architecture::Register>::id(&Register::R0H))
    }

    fn global_pointer_reg(&self) -> Option<RegisterId> { None }

    fn implicitly_defined_registers(&self) -> Vec<RegisterId> {
        Vec::new()
    }

    fn are_argument_registers_used_for_var_args(&self) -> bool { true }
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginInit() -> bool {
    let arch = register_architecture("tms320c28x", |custom_handle, handle| {
        arch::TMS320C28x::new(handle, custom_handle)
    });

    // ELF loading is handled by binja/elf_plugin.py (Python BinaryView)
    // which converts C28x word addresses to byte addresses.
    // BN's built-in ELF loader doesn't support word→byte conversion.

    // Register calling convention
    let cc = register_calling_convention(arch, "c28x-default", C28xCallingConvention);
    if let Some(platform) = arch.standalone_platform() {
        platform.set_default_calling_convention(&cc);
    }

    // TODO: register custom TI COFF BinaryView

    true
}
