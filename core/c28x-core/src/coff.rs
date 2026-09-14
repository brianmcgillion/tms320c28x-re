// SPDX-License-Identifier: MIT
//! TI COFF2 parser for TMS320C28x.
//!
//! Parses .out files from cl2000 to extract sections, symbols, and code.

const COFF_MAGIC_C2000: u16 = 0x00C2;
const STYP_TEXT: u32 = 0x0020;
const STYP_DATA: u32 = 0x0040;
const STYP_BSS: u32 = 0x0080;
const C_EXT: u8 = 2;
const C_LABEL: u8 = 6;

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub phys_addr: u32,
    pub virt_addr: u32,
    pub size: u32,
    pub data_offset: u32,
    pub flags: u32,
    pub data: Vec<u8>,
}

impl Section {
    pub fn is_text(&self) -> bool {
        self.flags & STYP_TEXT != 0
    }
    pub fn is_data(&self) -> bool {
        self.flags & STYP_DATA != 0
    }
    pub fn is_bss(&self) -> bool {
        self.flags & STYP_BSS != 0
    }
    pub fn byte_addr(&self) -> u64 {
        self.phys_addr as u64 * 2
    }
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub value: u32,
    pub section_num: i16,
    pub storage_class: u8,
}

impl Symbol {
    pub fn byte_addr(&self) -> u64 {
        self.value as u64 * 2
    }
    pub fn is_function(&self) -> bool {
        self.storage_class == C_EXT || self.storage_class == C_LABEL
    }
}

#[derive(Debug, Clone, Default)]
pub struct CoffFile {
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
}

impl CoffFile {
    pub fn get_symbol(&self, name: &str) -> Option<&Symbol> {
        self.symbols.iter().find(|s| s.name == name)
    }
}

/// Parse a TI COFF2 file from raw bytes.
pub fn parse_coff(data: &[u8]) -> Result<CoffFile, String> {
    if data.len() < 22 {
        return Err("File too small for COFF header".into());
    }

    let magic = u16::from_le_bytes([data[0], data[1]]);
    if magic != COFF_MAGIC_C2000 {
        return Err(format!("Not a TI C2000 COFF file (magic=0x{:04X})", magic));
    }

    let num_sections = u16::from_le_bytes([data[2], data[3]]) as usize;
    let symtab_offset = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
    let num_symbols = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;
    let opt_hdr_size = u16::from_le_bytes([data[16], data[17]]) as usize;

    let hdr_size = 22 + opt_hdr_size;
    let mut coff = CoffFile::default();

    // Parse section headers (48 bytes each)
    for i in 0..num_sections {
        let sh = hdr_size + i * 48;
        if sh + 48 > data.len() {
            break;
        }

        let raw_name = &data[sh..sh + 8];
        let name = if raw_name[..4] == [0, 0, 0, 0] {
            let str_off =
                u32::from_le_bytes([raw_name[4], raw_name[5], raw_name[6], raw_name[7]]) as usize;
            read_string(data, symtab_offset + num_symbols * 18 + str_off)
        } else {
            String::from_utf8_lossy(raw_name.split(|&b| b == 0).next().unwrap_or(raw_name))
                .to_string()
        };

        let phys_addr = read_u32(data, sh + 8);
        let virt_addr = read_u32(data, sh + 12);
        let sec_size = read_u32(data, sh + 16);
        let data_ptr = read_u32(data, sh + 20) as usize;
        let sec_flags = read_u32(data, sh + 40);

        let byte_size = sec_size as usize * 2;
        let sec_data = if data_ptr > 0 && sec_size > 0 && (sec_flags & STYP_BSS) == 0 {
            let end = (data_ptr + byte_size).min(data.len());
            data[data_ptr..end].to_vec()
        } else {
            Vec::new()
        };

        coff.sections.push(Section {
            name,
            phys_addr,
            virt_addr,
            size: sec_size,
            data_offset: data_ptr as u32,
            flags: sec_flags,
            data: sec_data,
        });
    }

    // Parse symbol table (18 bytes each)
    if symtab_offset > 0 && num_symbols > 0 {
        let strtab_offset = symtab_offset + num_symbols * 18;
        let mut i = 0;
        while i < num_symbols {
            let so = symtab_offset + i * 18;
            if so + 18 > data.len() {
                break;
            }

            let raw_name = &data[so..so + 8];
            let name = if raw_name[..4] == [0, 0, 0, 0] {
                let str_off =
                    u32::from_le_bytes([raw_name[4], raw_name[5], raw_name[6], raw_name[7]])
                        as usize;
                read_string(data, strtab_offset + str_off)
            } else {
                String::from_utf8_lossy(raw_name.split(|&b| b == 0).next().unwrap_or(raw_name))
                    .to_string()
            };

            let value = read_u32(data, so + 8);
            let sec_num = i16::from_le_bytes([data[so + 12], data[so + 13]]);
            let sclass = data[so + 16];
            let num_aux = data[so + 17] as usize;

            if !name.is_empty() && !name.starts_with('.') {
                coff.symbols.push(Symbol {
                    name,
                    value,
                    section_num: sec_num,
                    storage_class: sclass,
                });
            }

            i += 1 + num_aux;
        }
    }

    Ok(coff)
}

/// Check if data starts with TI COFF magic.
pub fn is_coff(data: &[u8]) -> bool {
    data.len() >= 2 && u16::from_le_bytes([data[0], data[1]]) == COFF_MAGIC_C2000
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn read_string(data: &[u8], offset: usize) -> String {
    if offset >= data.len() {
        return String::new();
    }
    let end = data[offset..]
        .iter()
        .position(|&b| b == 0)
        .map_or(data.len(), |p| offset + p);
    String::from_utf8_lossy(&data[offset..end]).to_string()
}
