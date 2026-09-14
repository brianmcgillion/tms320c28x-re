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
    /// Display mnemonic in TI syntax. Falls back to stripping the name's
    /// operand suffixes, which is what every row used before this existed.
    #[serde(default)]
    mnemonic: Option<String>,
    /// TI's operand layout, with `{N}` standing for decoded operand N. The
    /// encoding names only some operands; the rest live in the mnemonic, so
    /// rendering the decoded ones alone loses the other half of the line.
    #[serde(default)]
    operand_text: Option<String>,
    /// Machine-readable move semantics. `semantics:` is prose -- 48 spellings
    /// of ~20 concepts, and only 12% of rows carry both a dest and a src -- so
    /// it cannot drive lifting. This can.
    #[serde(default)]
    lift: Option<YamlLift>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct YamlLift {
    dst: LiftRef,
    src: LiftRef,
    width: u32,
}

#[derive(Debug, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum LiftRef {
    Reg { reg: String },
    Opnd { opnd: usize },
}

impl LiftRef {
    fn rust(&self) -> String {
        match self {
            LiftRef::Reg { reg } => format!("LiftRef::Reg(\"{reg}\")"),
            LiftRef::Opnd { opnd } => format!("LiftRef::Opnd({opnd})"),
        }
    }
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
    /// Added to the extracted field. The shift-by-immediate instructions store
    /// `shift - 1`, so `LSL AL, #1` is field 0 -- without this the decoder,
    /// the disassembly and the lifter are all off by one.
    #[serde(default)]
    bias: i32,
}

/// Reject a malformed instruction table at build time.
///
/// Every defect this catches was found in the shipped table, and each one was
/// invisible: an entry whose opcode has bits outside its mask can never match,
/// a duplicate name silently collapses two encodings into one InsnId *and* one
/// operand array, and an operand field overlapping the mask can never vary.
/// Register name -> size in bytes, from isa/registers.yaml (including sub-registers).
fn register_sizes(isa_dir: &str) -> HashMap<String, u32> {
    #[derive(Deserialize)]
    struct Reg {
        size: u32,
        #[serde(default)]
        sub: HashMap<String, Reg>,
    }
    #[derive(Deserialize)]
    struct File {
        registers: HashMap<String, Reg>,
    }
    let path = format!("{isa_dir}/registers.yaml");
    println!("cargo:rerun-if-changed={path}");
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let file: File = serde_yaml::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"));
    let mut out = HashMap::new();
    for (name, reg) in file.registers {
        for (sub_name, sub) in &reg.sub {
            out.insert(sub_name.clone(), sub.size);
        }
        out.insert(name, reg.size);
    }
    out
}

/// The bit-name lists TI's disassembler uses for CLRC/SETC and SETFLG.
fn flag_bit_names(isa_dir: &str) -> (Vec<String>, Vec<String>) {
    #[derive(Deserialize)]
    struct File {
        #[serde(default)]
        mode_bits: Vec<String>,
        #[serde(default)]
        setflg_bits: Vec<String>,
    }
    let path = format!("{isa_dir}/flags.yaml");
    println!("cargo:rerun-if-changed={path}");
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let f: File = serde_yaml::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"));
    assert_eq!(
        f.mode_bits.len(),
        8,
        "{path}: mode_bits must have 8 entries"
    );
    assert_eq!(
        f.setflg_bits.len(),
        11,
        "{path}: setflg_bits must have 11 entries"
    );
    (f.mode_bits, f.setflg_bits)
}

fn validate(all_insns: &[(YamlInstruction, String)], reg_sizes: &HashMap<String, u32>) {
    let mut errors: Vec<String> = Vec::new();
    let mut seen: HashMap<&str, &str> = HashMap::new();
    let mut encodings: HashMap<(u64, u64, u32), &str> = HashMap::new();

    for (insn, file) in all_insns {
        let width = if insn.format == 32 { 32 } else { 16 };
        let full: u64 = if width == 32 { 0xFFFF_FFFF } else { 0xFFFF };
        let here = format!(
            "{}: {} (opcode {:#010X}, mask {:#010X})",
            file, insn.name, insn.opcode, insn.mask
        );

        // I1 -- opcode bits outside the mask make the entry unmatchable.
        let stray = insn.opcode & !insn.mask & full;
        if stray != 0 {
            errors.push(format!(
                "{here}: opcode has bits outside mask ({stray:#010X})"
            ));
        }

        // I2 -- duplicate names collapse InsnId variants and operand arrays.
        if let Some(prev) = seen.insert(insn.name.as_str(), file.as_str()) {
            errors.push(format!("{here}: duplicate name, also in {prev}"));
        }

        // I8 -- an identical (opcode, mask, format) under a different name is a
        // shadow: whichever sorts second can never be reached. NOP_IND_ARPN was
        // exactly this against NOP, and a duplicate-name check alone misses it.
        let enc = (insn.opcode, insn.mask, insn.format);
        if let Some(prev) = encodings.insert(enc, insn.name.as_str()) {
            errors.push(format!(
                "{here}: same opcode/mask/format as {prev}, so one of them is unreachable"
            ));
        }

        // I5 -- the declared format must contain the mask.
        if insn.mask & !full != 0 {
            errors.push(format!("{here}: mask exceeds its {width}-bit format"));
        }

        // I3/I4 -- operand fields must be outside the fixed mask and disjoint.
        let mut claimed: u64 = 0;
        for op in &insn.operands {
            if op.bits.len() != 2 {
                continue;
            }
            let (hi, lo) = (op.bits[0], op.bits[1]);
            if hi < lo {
                errors.push(format!(
                    "{here}: operand {} has bits [{hi}, {lo}] reversed",
                    op.name
                ));
                continue;
            }
            if hi >= width {
                errors.push(format!(
                    "{here}: operand {} bit {hi} outside {width}-bit format",
                    op.name
                ));
                continue;
            }
            let field = if hi - lo + 1 >= 64 {
                u64::MAX
            } else {
                ((1u64 << (hi - lo + 1)) - 1) << lo
            };
            if field & insn.mask == field {
                errors.push(format!("{here}: operand {} at [{hi}, {lo}] lies inside the fixed mask, so it can never vary", op.name));
            }
            if field & claimed != 0 {
                errors.push(format!(
                    "{here}: operand {} at [{hi}, {lo}] overlaps another operand",
                    op.name
                ));
            }
            claimed |= field;
        }

        // I9 -- `lift:` must name a register the architecture has, at that
        // register's own width, and an operand that exists. A move has exactly
        // one memory side, so exactly one of dst/src is an operand: `{reg, reg}`
        // is a register move that needs no table, and `{opnd, opnd}` is not a
        // shape this schema can express.
        if let Some(lift) = &insn.lift {
            if !matches!(lift.width, 2 | 4) {
                errors.push(format!("{here}: lift width {} is not 2 or 4", lift.width));
            }
            let mut opnds = 0;
            for (role, r) in [("dst", &lift.dst), ("src", &lift.src)] {
                match r {
                    LiftRef::Reg { reg } => match reg_sizes.get(reg.as_str()) {
                        None => {
                            errors.push(format!("{here}: lift {role} names unknown register {reg}"))
                        }
                        Some(&size) if size != lift.width => errors.push(format!(
                            "{here}: lift {role} {reg} is {size} bytes but width is {}",
                            lift.width
                        )),
                        Some(_) => {}
                    },
                    LiftRef::Opnd { opnd } => {
                        opnds += 1;
                        match insn.operands.get(*opnd) {
                            None => errors.push(format!(
                                "{here}: lift {role} is operand {opnd} but there are {}",
                                insn.operands.len())),
                            Some(op) if !matches!(op.op_type.as_str(), "loc16" | "loc32") =>
                                errors.push(format!(
                                    "{here}: lift {role} is operand {opnd} of type {}, not loc16/loc32",
                                    op.op_type)),
                            Some(_) => {}
                        }
                    }
                }
            }
            if opnds != 1 {
                errors.push(format!(
                    "{here}: lift has {opnds} operand sides, expected exactly 1"
                ));
            }
        }
    }

    if !errors.is_empty() {
        for e in &errors {
            println!("cargo:warning={e}");
        }
        panic!(
            "isa/instructions is malformed -- {} problem(s); see the warnings above",
            errors.len()
        );
    }
}

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let isa_dir = PathBuf::from(&manifest_dir).join("../../isa/instructions");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Rerun if YAML changes
    // Per FILE, not just the directory: cargo tracks a watched directory by its
    // mtime, which does not change when a file inside it is edited in place. With
    // only the directory watched, editing an opcode could silently fail to
    // regenerate the tables -- and the validation below would not re-run either.
    println!("cargo:rerun-if-changed=../../isa/instructions");

    let mut all_insns: Vec<(YamlInstruction, String)> = Vec::new(); // (insn, source_file)

    let mut yaml_files: Vec<_> = fs::read_dir(&isa_dir)
        .expect("Cannot read isa/instructions directory")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "yaml"))
        .collect();
    yaml_files.sort_by_key(|e| e.path());

    for entry in &yaml_files {
        println!("cargo:rerun-if-changed={}", entry.path().display());
    }

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
    let reg_sizes = register_sizes(
        &PathBuf::from(&manifest_dir)
            .join("../../isa")
            .to_string_lossy(),
    );
    validate(&all_insns, &reg_sizes);

    let mut insns_16: Vec<&(YamlInstruction, String)> =
        all_insns.iter().filter(|(i, _)| i.format == 16).collect();
    let mut insns_32: Vec<&(YamlInstruction, String)> =
        all_insns.iter().filter(|(i, _)| i.format == 32).collect();

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
    let mnemonics: HashMap<String, String> = all_insns
        .iter()
        .filter_map(|(i, _)| i.mnemonic.clone().map(|m| (i.name.clone(), m)))
        .collect();
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
    writeln!(
        out,
        "/// Instruction identifier — one variant per YAML instruction name."
    )
    .unwrap();
    writeln!(out, "#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]").unwrap();
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
    writeln!(out, "#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]").unwrap();
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
    writeln!(out, "#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]").unwrap();
    writeln!(out, "pub enum OpType {{").unwrap();
    let op_types = [
        "loc16", "loc32", "ax", "cond4", "cndf", "reg3", "arn", "fpu_reg", "imm2", "imm4", "imm5",
        "imm7", "imm8", "imm10", "imm16", "imm22", "shift4",
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
    writeln!(out, "    pub bias: i32,").unwrap();
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
    writeln!(out, "    pub operands: &'static [OperandDef],").unwrap();
    writeln!(out, "    pub sem_type: SemType,").unwrap();
    writeln!(out, "    pub operand_text: &'static str,").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // --- lift: table ---
    writeln!(out, "#[derive(Debug, Clone, Copy, PartialEq, Eq)]").unwrap();
    writeln!(out, "pub enum LiftRef {{").unwrap();
    writeln!(out, "    Reg(&'static str),").unwrap();
    writeln!(out, "    Opnd(usize),").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "#[derive(Debug, Clone, Copy, PartialEq, Eq)]").unwrap();
    writeln!(out, "pub struct LiftSpec {{").unwrap();
    writeln!(out, "    pub dst: LiftRef,").unwrap();
    writeln!(out, "    pub src: LiftRef,").unwrap();
    writeln!(out, "    pub width: usize,").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "/// Declared move semantics, where the table carries them."
    )
    .unwrap();
    writeln!(out, "pub fn lift_spec(id: InsnId) -> Option<LiftSpec> {{").unwrap();
    writeln!(out, "    match id {{").unwrap();
    for (insn, _) in all_insns.iter() {
        if let Some(lift) = &insn.lift {
            writeln!(
                out,
                "        InsnId::{} => Some(LiftSpec {{ dst: {}, src: {}, width: {} }}),",
                insn.name,
                lift.dst.rust(),
                lift.src.rust(),
                lift.width
            )
            .unwrap();
        }
    }
    writeln!(out, "        _ => None,").unwrap();
    writeln!(out, "    }}").unwrap();
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
                "    OperandDef {{ op_type: OpType::{}, high_bit: {}, low_bit: {}, signed: {}, bias: {} }},\n",
                op_type_variant(&op.op_type),
                high,
                low,
                op.signed,
                op.bias
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
    let (mode_bits, setflg_bits) = flag_bit_names(
        &PathBuf::from(&manifest_dir)
            .join("../../isa")
            .to_string_lossy(),
    );
    writeln!(
        out,
        "/// Bit names of the CLRC/SETC operand, from isa/flags.yaml."
    )
    .unwrap();
    writeln!(
        out,
        "pub static MODE_BITS: [&str; 8] = [{}];",
        mode_bits
            .iter()
            .map(|n| format!("\"{n}\""))
            .collect::<Vec<_>>()
            .join(", ")
    )
    .unwrap();
    writeln!(
        out,
        "/// Bit names of SETFLG's select field, from isa/flags.yaml."
    )
    .unwrap();
    writeln!(
        out,
        "pub static SETFLG_BITS: [&str; 11] = [{}];",
        setflg_bits
            .iter()
            .map(|n| format!("\"{n}\""))
            .collect::<Vec<_>>()
            .join(", ")
    )
    .unwrap();
    writeln!(out).unwrap();

    writeln!(
        out,
        "/// TI's operand layout for an instruction; `{{N}}` is decoded operand N."
    )
    .unwrap();
    writeln!(out, "pub fn operand_text(id: InsnId) -> &'static str {{").unwrap();
    writeln!(out, "    match id {{").unwrap();
    for (insn, _) in all_insns.iter() {
        if let Some(t) = &insn.operand_text {
            writeln!(
                out,
                "        InsnId::{} => \"{}\",",
                insn.name,
                t.replace('"', "\\\"")
            )
            .unwrap();
        }
    }
    // Only when some row has none; with every row covered the arm is dead and
    // rustc says so.
    if all_insns.iter().any(|(i, _)| i.operand_text.is_none()) {
        writeln!(out, "        _ => \"\",").unwrap();
    }
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "/// TI-syntax mnemonic for an instruction.").unwrap();
    writeln!(
        out,
        "pub fn display_mnemonic(id: InsnId, _cond_code: Option<u8>) -> &'static str {{"
    )
    .unwrap();
    writeln!(out, "    match id {{").unwrap();
    for name in &all_names {
        writeln!(
            out,
            "        InsnId::{} => \"{}\",",
            name,
            mnemonic_of(&mnemonics, name)
        )
        .unwrap();
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
            "    InstructionDef {{ name: \"{}\", full_name: \"{}\", id: InsnId::{}, opcode: 0x{:08X}, mask: 0x{:08X}, objmode: {}, operands: {}, sem_type: {}, operand_text: \"{}\" }},",
            insn.mnemonic.clone().unwrap_or_else(|| strip_yaml_suffixes(&insn.name)),
            full_name.replace('"', "\\\""),
            insn.name,
            insn.opcode as u32,
            insn.mask as u32,
            match insn.objmode {
                Some(v) => format!("Some({})", v),
                None => "None".to_string(),
            },
            ops_ref,
            sem_type,
            insn.operand_text.as_deref().unwrap_or("").replace('"', "\\\"")
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
    writeln!(out, "pub static {}: [(u16, u16); 256] = [", name).unwrap();
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
        "cndf" => "Cndf".to_string(),
        "reg3" => "Reg3".to_string(),
        "arn" => "Arn".to_string(),
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

/// The row's `mnemonic:` if it has one, else the stripped name.
fn mnemonic_of(mnemonics: &HashMap<String, String>, name: &str) -> String {
    mnemonics
        .get(name)
        .cloned()
        .unwrap_or_else(|| strip_yaml_suffixes(name))
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
