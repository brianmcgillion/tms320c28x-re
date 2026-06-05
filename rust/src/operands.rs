// SPDX-License-Identifier: MIT
//! loc16/loc32 addressing mode decoder.
//!
//! Reference: TI SPRU430F Chapter 5.

/// Addressing modes for loc16/loc32 operands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressingMode {
    DpDirect,
    SpRelative,
    Indirect,
    IndirectPostInc,
    IndirectPreDec,
    IndirectAr0,
    IndirectAr1,
    RegisterDirect,
    ArpIndirect,
}

/// Decoded loc16/loc32 addressing mode result.
#[derive(Debug, Clone)]
pub struct ResolvedOperand {
    pub mode: AddressingMode,
    pub text: String,
    pub register: Option<&'static str>,
    pub xar_index: Option<u8>,
    pub offset: u16,
}

/// Decode an 8-bit loc16 addressing mode field.
pub fn decode_loc16(field: u8) -> ResolvedOperand {
    // Check register-direct special codes first
    match field {
        0xA8 => return reg_direct("@AH", "AH"),
        0xA9 => return reg_direct("@AL", "AL"),
        0xAA => return reg_direct("@PH", "PH"),
        0xAB => return reg_direct("@PL", "PL"),
        0xAC => return reg_direct("@T", "T"),
        0xAD => return reg_direct("@SP", "SP"),
        _ => {}
    }
    decode_loc_common(field)
}

/// Decode an 8-bit loc32 addressing mode field.
pub fn decode_loc32(field: u8) -> ResolvedOperand {
    match field {
        0xA8 => return reg_direct("@ACC", "ACC"),
        0xAA => return reg_direct("@P", "P"),
        0xAC => return reg_direct("@XT", "XT"),
        _ => {}
    }
    decode_loc_common(field)
}

fn reg_direct(text: &str, reg: &'static str) -> ResolvedOperand {
    ResolvedOperand {
        mode: AddressingMode::RegisterDirect,
        text: text.to_string(),
        register: Some(reg),
        xar_index: None,
        offset: 0,
    }
}

fn decode_loc_common(field: u8) -> ResolvedOperand {
    let category = (field >> 6) & 0x3;

    match category {
        0b00 => {
            // DP-direct: offset = bits [5:0]
            let offset = (field & 0x3F) as u16;
            ResolvedOperand {
                mode: AddressingMode::DpDirect,
                text: format!("@{}", offset),
                register: None,
                xar_index: None,
                offset,
            }
        }
        0b01 => {
            // SP-relative: offset = bits [5:0]
            let offset = (field & 0x3F) as u16;
            ResolvedOperand {
                mode: AddressingMode::SpRelative,
                text: format!("*-SP[{}]", offset),
                register: None,
                xar_index: None,
                offset,
            }
        }
        0b10 => {
            // Indirect (complex sub-decode). bits[5:3] = sub-mode, bits[2:0] = n.
            // Mapping derived from dis2000 (TI ground truth); the previous table
            // was shifted by one and category 0b11 rendered a *arp() fallback.
            // (Mirror of c28x/operands.py::_decode_loc_common.)
            let sub_mode = (field >> 3) & 0x1F;
            let n = field & 0x7;

            match sub_mode {
                0b10000 => ResolvedOperand {
                    mode: AddressingMode::IndirectPostInc,
                    text: format!("*XAR{}++", n),
                    register: None,
                    xar_index: Some(n),
                    offset: 0,
                },
                0b10001 => ResolvedOperand {
                    mode: AddressingMode::IndirectPreDec,
                    text: format!("*--XAR{}", n),
                    register: None,
                    xar_index: Some(n),
                    offset: 0,
                },
                0b10010 => ResolvedOperand {
                    mode: AddressingMode::IndirectAr0,
                    text: format!("*+XAR{}[AR0]", n),
                    register: None,
                    xar_index: Some(n),
                    offset: 0,
                },
                0b10011 => ResolvedOperand {
                    mode: AddressingMode::IndirectAr1,
                    text: format!("*+XAR{}[AR1]", n),
                    register: None,
                    xar_index: Some(n),
                    offset: 0,
                },
                0b10111 => {
                    // SP / circular / post-inc-dec specials selected by n.
                    let text = match n {
                        0b001 => "*++",
                        0b010 => "*--",
                        0b011 => "*0++",
                        0b100 => "*0--",
                        0b101 => "*SP++",
                        0b110 => "*--SP",
                        _ => "",
                    };
                    if text.is_empty() {
                        ResolvedOperand {
                            mode: AddressingMode::Indirect,
                            text: format!("*ind(0x{:02X})", field),
                            register: None,
                            xar_index: Some(n),
                            offset: 0,
                        }
                    } else {
                        ResolvedOperand {
                            mode: AddressingMode::Indirect,
                            text: text.to_string(),
                            register: None,
                            xar_index: None,
                            offset: 0,
                        }
                    }
                }
                _ => ResolvedOperand {
                    mode: AddressingMode::Indirect,
                    text: format!("*ind(0x{:02X})", field),
                    register: None,
                    xar_index: Some(n),
                    offset: 0,
                },
            }
        }
        _ => {
            // category == 0b11: *+XARn[offset], offset = bits[5:3], n = bits[2:0].
            let n = field & 0x7;
            let offset = ((field >> 3) & 0x7) as u16;
            ResolvedOperand {
                mode: AddressingMode::Indirect,
                text: format!("*+XAR{}[{}]", n, offset),
                register: None,
                xar_index: Some(n),
                offset,
            }
        }
    }
}
