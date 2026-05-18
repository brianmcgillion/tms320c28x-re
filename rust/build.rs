// SPDX-License-Identifier: MIT
//! Build script: reads isa/instructions/*.yaml and generates Rust source code.
//!
//! Generates:
//! - InsnId enum (one variant per instruction)
//! - SemType enum (semantic type for lifter dispatch)
//! - Static instruction tables (INSTRUCTIONS_16, INSTRUCTIONS_32)
//! - Top-byte lookup tables (TABLE_16, TABLE_32)

use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct YamlFile {
    instructions: Option<Vec<YamlInstruction>>,
}

#[derive(Debug, Deserialize)]
struct YamlInstruction {
    name: String,
    #[serde(default)]
    full_name: String,
    #[serde(default = "default_format")]
    format: u32,
    opcode: u64,
    mask: u64,
    #[serde(default)]
    objmode: Option<u32>,
    #[serde(default)]
    operands: Vec<YamlOperand>,
    #[serde(default)]
    semantics: HashMap<String, serde_yaml::Value>,
}

fn default_format() -> u32 {
    16
}

#[derive(Debug, Deserialize)]
struct YamlOperand {
    /// Operand name from YAML schema; kept for cross-reference but not used by the generator.
    #[serde(default)]
    #[allow(dead_code)]
    name: String,
    #[serde(default, rename = "type")]
    op_type: String,
    #[serde(default)]
    bits: Vec<u32>,
    #[serde(default)]
    signed: bool,
}

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let isa_dir = PathBuf::from(&manifest_dir).join("../isa/instructions");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Rerun if YAML changes
    println!("cargo:rerun-if-changed=../isa/instructions");

    let mut all_insns: Vec<(YamlInstruction, String)> = Vec::new(); // (insn, source_file)

    let mut yaml_files: Vec<_> = fs::read_dir(&isa_dir)
        .expect("Cannot read isa/instructions directory")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "yaml"))
        .collect();
    yaml_files.sort_by_key(|e| e.path());

    for entry in &yaml_files {
        let path = entry.path();
        let contents = fs::read_to_string(&path).unwrap();
        let parsed: YamlFile = serde_yaml::from_str(&contents)
            .unwrap_or_else(|e| panic!("Failed to parse {}: {}", path.display(), e));

        if let Some(instructions) = parsed.instructions {
            let fname = path.file_stem().unwrap().to_str().unwrap().to_string();
            for insn in instructions {
                all_insns.push((insn, fname.clone()));
            }
        }
    }

    // Separate 16-bit and 32-bit, sort by mask specificity (popcount desc)
    let mut insns_16: Vec<&(YamlInstruction, String)> = all_insns
        .iter()
        .filter(|(i, _)| i.format == 16)
        .collect();
    let mut insns_32: Vec<&(YamlInstruction, String)> = all_insns
        .iter()
        .filter(|(i, _)| i.format == 32)
        .collect();

    insns_16.sort_by(|a, b| {
        (b.0.mask as u32)
            .count_ones()
            .cmp(&(a.0.mask as u32).count_ones())
    });
    insns_32.sort_by(|a, b| {
        (b.0.mask as u32)
            .count_ones()
            .cmp(&(a.0.mask as u32).count_ones())
    });

    // Collect all unique instruction names for InsnId enum
    let mut all_names: Vec<String> = all_insns.iter().map(|(i, _)| i.name.clone()).collect();
    all_names.sort();
    all_names.dedup();

    // Collect all unique semantic types for SemType enum
    let mut sem_types: Vec<String> = all_insns
        .iter()
        .filter_map(|(i, _)| {
            i.semantics
                .get("type")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .collect();
    sem_types.sort();
    sem_types.dedup();

    // Generate the output file
    let out_path = out_dir.join("generated.rs");
    let mut out = fs::File::create(&out_path).unwrap();

    // --- InsnId enum ---
    writeln!(out, "/// Instruction identifier — one variant per YAML instruction name.").unwrap();
    writeln!(
        out,
        "#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]"
    )
    .unwrap();
    writeln!(out, "#[allow(non_camel_case_types)]").unwrap();
    writeln!(out, "pub enum InsnId {{").unwrap();
    for name in &all_names {
        writeln!(out, "    {},", name).unwrap();
    }
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // --- SemType enum ---
    writeln!(
        out,
        "/// Semantic type for lifter dispatch — maps YAML semantics.type."
    )
    .unwrap();
    writeln!(
        out,
        "#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]"
    )
    .unwrap();
    writeln!(out, "pub enum SemType {{").unwrap();
    writeln!(out, "    None,").unwrap();
    for st in &sem_types {
        writeln!(out, "    {},", to_pascal(st)).unwrap();
    }
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // --- OpType enum ---
    writeln!(
        out,
        "/// Operand type from YAML — used by the decoder to interpret bit fields."
    )
    .unwrap();
    writeln!(
        out,
        "#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]"
    )
    .unwrap();
    writeln!(out, "pub enum OpType {{").unwrap();
    let op_types = [
        "loc16", "loc32", "ax", "cond4", "reg3", "fpu_reg", "imm2", "imm4", "imm5", "imm7",
        "imm8", "imm10", "imm16", "imm22", "shift4",
    ];
    for ot in &op_types {
        writeln!(out, "    {},", to_pascal(ot)).unwrap();
    }
    writeln!(out, "    Unknown,").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // --- OperandDef struct ---
    writeln!(out, "#[derive(Debug, Clone, Copy)]").unwrap();
    writeln!(out, "pub struct OperandDef {{").unwrap();
    writeln!(out, "    pub op_type: OpType,").unwrap();
    writeln!(out, "    pub high_bit: u8,").unwrap();
    writeln!(out, "    pub low_bit: u8,").unwrap();
    writeln!(out, "    pub signed: bool,").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // --- InstructionDef struct ---
    writeln!(out, "#[derive(Debug, Clone)]").unwrap();
    writeln!(out, "pub struct InstructionDef {{").unwrap();
    writeln!(out, "    pub name: &'static str,").unwrap();
    writeln!(out, "    pub full_name: &'static str,").unwrap();
    writeln!(out, "    pub id: InsnId,").unwrap();
    writeln!(out, "    pub opcode: u32,").unwrap();
    writeln!(out, "    pub mask: u32,").unwrap();
    writeln!(out, "    pub objmode: Option<u32>,").unwrap();
    writeln!(
        out,
        "    pub operands: &'static [OperandDef],"
    )
    .unwrap();
    writeln!(out, "    pub sem_type: SemType,").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // --- Operand definitions as statics ---
    // First, generate all unique operand arrays
    let mut operand_statics: Vec<String> = Vec::new();
    let mut operand_map: HashMap<String, String> = HashMap::new();

    for (idx, (insn, _)) in all_insns.iter().enumerate() {
        if insn.operands.is_empty() {
            continue;
        }
        let key = format!("OPDEF_{}", idx);
        let mut ops = String::new();
        ops.push_str(&format!(
            "#[allow(dead_code)]\nstatic {}: [OperandDef; {}] = [\n",
            key,
            insn.operands.len()
        ));
        for op in &insn.operands {
            let (high, low) = if op.bits.len() == 2 {
                (op.bits[0], op.bits[1])
            } else {
                (0, 0)
            };
            ops.push_str(&format!(
                "    OperandDef {{ op_type: OpType::{}, high_bit: {}, low_bit: {}, signed: {} }},\n",
                op_type_variant(&op.op_type),
                high,
                low,
                op.signed
            ));
        }
        ops.push_str("];\n");
        operand_statics.push(ops);
        operand_map.insert(insn.name.clone(), key);
    }

    for s in &operand_statics {
        write!(out, "{}", s).unwrap();
    }
    writeln!(out).unwrap();

    // --- Static instruction tables ---
    write_table(&mut out, "INSTRUCTIONS_16", &insns_16, &operand_map);
    write_table(&mut out, "INSTRUCTIONS_32", &insns_32, &operand_map);

    // --- Lookup tables ---
    write_lookup_table(&mut out, "TABLE_16", &insns_16, 8); // top byte of 16-bit opcode
    write_lookup_table(&mut out, "TABLE_32", &insns_32, 24); // top byte of 32-bit opcode

    // --- Display name helper ---
    // Generate a function that strips internal YAML suffixes for display
    writeln!(out, "/// Strip internal YAML suffixes from instruction name for display.").unwrap();
    writeln!(out, "pub fn display_mnemonic(id: InsnId, _cond_code: Option<u8>) -> &'static str {{").unwrap();
    writeln!(out, "    match id {{").unwrap();
    for name in &all_names {
        let display = strip_yaml_suffixes(name);
        writeln!(out, "        InsnId::{} => \"{}\",", name, display).unwrap();
    }
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
}

fn write_table(
    out: &mut fs::File,
    name: &str,
    insns: &[&(YamlInstruction, String)],
    operand_map: &HashMap<String, String>,
) {
    writeln!(
        out,
        "pub static {}: [InstructionDef; {}] = [",
        name,
        insns.len()
    )
    .unwrap();
    for (insn, _) in insns {
        let sem_type = insn
            .semantics
            .get("type")
            .and_then(|v| v.as_str())
            .map(|s| format!("SemType::{}", to_pascal(s)))
            .unwrap_or_else(|| "SemType::None".to_string());

        let ops_ref = if insn.operands.is_empty() {
            "&[]".to_string()
        } else if let Some(key) = operand_map.get(&insn.name) {
            format!("&{}", key)
        } else {
            "&[]".to_string()
        };

        // Truncate full_name to avoid very long strings
        let full_name = if insn.full_name.len() > 60 {
            &insn.full_name[..60]
        } else {
            &insn.full_name
        };

        writeln!(
            out,
            "    InstructionDef {{ name: \"{}\", full_name: \"{}\", id: InsnId::{}, opcode: 0x{:08X}, mask: 0x{:08X}, objmode: {}, operands: {}, sem_type: {} }},",
            strip_yaml_suffixes(&insn.name),
            full_name.replace('"', "\\\""),
            insn.name,
            insn.opcode as u32,
            insn.mask as u32,
            match insn.objmode {
                Some(v) => format!("Some({})", v),
                None => "None".to_string(),
            },
            ops_ref,
            sem_type
        )
        .unwrap();
    }
    writeln!(out, "];").unwrap();
    writeln!(out).unwrap();
}

fn write_lookup_table(
    out: &mut fs::File,
    name: &str,
    insns: &[&(YamlInstruction, String)],
    shift: u32,
) {
    // Group instructions by top byte
    let mut groups: HashMap<u8, Vec<usize>> = HashMap::new();
    for (idx, (insn, _)) in insns.iter().enumerate() {
        // For each instruction, determine which top-byte values it can match
        let opcode = insn.opcode as u32;
        let mask = insn.mask as u32;
        let top_mask = (mask >> shift) & 0xFF;
        let top_opcode = (opcode >> shift) & 0xFF;

        // If top byte is fully constrained, only one bucket
        if top_mask == 0xFF {
            groups.entry(top_opcode as u8).or_default().push(idx);
        } else {
            // Otherwise, this instruction can match multiple top bytes
            for byte_val in 0u16..256 {
                if (byte_val as u32 & top_mask) == top_opcode {
                    groups.entry(byte_val as u8).or_default().push(idx);
                }
            }
        }
    }

    // Write the table as (start_index, count) pairs into a flat array
    // First, build a flat list of indices per bucket
    let mut flat_indices: Vec<usize> = Vec::new();
    let mut table: [(u16, u16); 256] = [(0, 0); 256];

    for byte_val in 0u16..256 {
        if let Some(indices) = groups.get(&(byte_val as u8)) {
            let start = flat_indices.len() as u16;
            let count = indices.len() as u16;
            flat_indices.extend(indices);
            table[byte_val as usize] = (start, count);
        }
    }

    // Write the flat index array
    writeln!(
        out,
        "pub static {}_INDICES: [u16; {}] = [",
        name,
        flat_indices.len()
    )
    .unwrap();
    for chunk in flat_indices.chunks(16) {
        write!(out, "    ").unwrap();
        for (i, idx) in chunk.iter().enumerate() {
            if i > 0 {
                write!(out, ", ").unwrap();
            }
            write!(out, "{}", idx).unwrap();
        }
        writeln!(out, ",").unwrap();
    }
    writeln!(out, "];").unwrap();
    writeln!(out).unwrap();

    // Write the lookup table
    writeln!(
        out,
        "/// Lookup table: top byte -> (start, count) into {}_INDICES.",
        name
    )
    .unwrap();
    writeln!(
        out,
        "pub static {}: [(u16, u16); 256] = [",
        name
    )
    .unwrap();
    for (i, (start, count)) in table.iter().enumerate() {
        if *count > 0 {
            writeln!(out, "    ({}, {}), // 0x{:02X}", start, count, i).unwrap();
        } else {
            writeln!(out, "    (0, 0),").unwrap();
        }
    }
    writeln!(out, "];").unwrap();
    writeln!(out).unwrap();
}

/// Convert snake_case to PascalCase
fn to_pascal(s: &str) -> String {
    s.split('_')
        .map(|part| {
            let mut c = part.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
            }
        })
        .collect()
}

/// Map YAML operand type string to OpType variant name
fn op_type_variant(s: &str) -> String {
    match s {
        "loc16" => "Loc16".to_string(),
        "loc32" => "Loc32".to_string(),
        "ax" => "Ax".to_string(),
        "cond4" => "Cond4".to_string(),
        "reg3" => "Reg3".to_string(),
        "fpu_reg" => "FpuReg".to_string(),
        "imm2" => "Imm2".to_string(),
        "imm4" => "Imm4".to_string(),
        "imm5" => "Imm5".to_string(),
        "imm7" => "Imm7".to_string(),
        "imm8" => "Imm8".to_string(),
        "imm10" => "Imm10".to_string(),
        "imm16" => "Imm16".to_string(),
        "imm22" => "Imm22".to_string(),
        "shift4" => "Shift4".to_string(),
        _ => "Unknown".to_string(),
    }
}

/// Strip internal YAML suffixes for display mnemonic
fn strip_yaml_suffixes(name: &str) -> String {
    let suffixes = [
        "_LOC16", "_LOC32", "_CONST22", "_CONST16", "_CONST8", "_CONST7", "_CONST10", "_SHIFT",
        "_XARN", "_XAR7", "_MEM32", "_RAH", "_RBH", "_STF", "_COND", "_PMA", "_ABS16", "_16FHI",
        "_PAR", "_LOAD", "_STORE",
    ];
    let mut result = name.to_string();
    for suffix in &suffixes {
        result = result.replace(suffix, "");
    }
    // Clean up double underscores
    while result.contains("__") {
        result = result.replace("__", "_");
    }
    result.trim_end_matches('_').to_string()
}
