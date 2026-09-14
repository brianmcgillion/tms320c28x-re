// SPDX-License-Identifier: MIT
//! c28xdec — command-line access to the C28x decoder.
//!
//! The seam that lets pytest, CI and the dis2000 differential all talk to the
//! *real* decoder without Binary Ninja. Before this existed the only way to
//! check the Rust decoder was through a BN-linked plugin, so CI checked nothing
//! and a second decoder was maintained in Python to stand in for it.
//!
//! JSON is emitted by hand rather than via serde: this crate has no
//! dependencies beyond c28x-core, which is what keeps `cargo test` free of
//! cmake, ninja and libclang.

use std::io::{self, BufRead, Write};

use c28x_core::coff;
use c28x_core::decoder::Decoder;
use c28x_core::operands::{decode_loc16, decode_loc32, ResolvedOperand};
use c28x_core::types::{DecodedInstruction, Operand};

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn operand_json(op: &Operand) -> String {
    let resolved = match &op.resolved {
        Some(r) => format!(
            r#","mode":"{:?}","text":"{}","offset":{},"xar":{}"#,
            r.mode,
            esc(&r.text),
            r.offset,
            match r.xar_index {
                Some(n) => n.to_string(),
                None => "null".into(),
            }
        ),
        None => String::new(),
    };
    format!(
        r#"{{"type":"{:?}","kind":"{:?}","value":{},"name":"{}","size":{},"signed":{}{}}}"#,
        op.op_type,
        op.op_kind,
        op.value,
        esc(op.display_name()),
        op.size,
        op.signed,
        resolved
    )
}

fn insn_json(addr: u64, insn: &DecodedInstruction) -> String {
    let ops: Vec<String> = insn.operands.iter().map(operand_json).collect();
    format!(
        r#"{{"addr":{},"yaml_name":"{}","name":"{}","size":{},"opcode":{},"branch_type":"{:?}","branch_target":{},"sem_type":"{:?}","text":"{}","operands":[{}]}}"#,
        addr,
        // The table identity (InsnId), which tests assert on -- distinct from
        // `name`, which is the display mnemonic with its suffixes stripped.
        esc(&format!("{:?}", insn.id)),
        esc(insn.name),
        insn.size,
        insn.opcode,
        insn.branch_type,
        match insn.branch_target {
            Some(t) => t.to_string(),
            None => "null".into(),
        },
        insn.sem_type,
        esc(&c28x_core::text::text(insn)),
        ops.join(",")
    )
}

/// Read `addr:hexwords` or bare `hexwords` per line; emit one JSON object each.
///
/// Little-endian bytes, as they appear in memory: "9283" is the single word
/// 0x9283. An unrecognised line yields {"error":...} rather than silence.
fn cmd_decode(objmode: u32) -> io::Result<()> {
    let decoder = Decoder::new(objmode);
    let stdin = io::stdin();
    let mut out = io::BufWriter::new(io::stdout());

    for line in stdin.lock().lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (addr, hex) = match line.split_once(':') {
            Some((a, h)) => (
                u64::from_str_radix(a.trim().trim_start_matches("0x"), 16).unwrap_or(0),
                h.trim(),
            ),
            None => (0, line),
        };
        let hex: String = hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if !hex.len().is_multiple_of(4) {
            writeln!(
                out,
                r#"{{"error":"need whole 16-bit words","input":"{}"}}"#,
                esc(line)
            )?;
            continue;
        }
        let mut bytes = Vec::with_capacity(hex.len() / 2);
        for word in hex.as_bytes().chunks(4) {
            let w = u16::from_str_radix(std::str::from_utf8(word).unwrap(), 16).unwrap_or(0);
            bytes.push((w & 0xFF) as u8);
            bytes.push((w >> 8) as u8);
        }
        // The decoder reads up to 4 bytes; pad so a 16-bit input is decodable.
        while bytes.len() < 4 {
            bytes.push(0);
        }
        match decoder.decode(&bytes, addr) {
            Some(insn) => writeln!(out, "{}", insn_json(addr, &insn))?,
            None => writeln!(
                out,
                r#"{{"addr":{},"yaml_name":null,"input":"{}"}}"#,
                addr,
                esc(line)
            )?,
        }
        out.flush()?;
    }
    Ok(())
}

/// The fields of a ResolvedOperand, without enclosing braces, so callers can
/// prepend their own keys.
fn resolved_fields(r: &ResolvedOperand) -> String {
    format!(
        r#""mode":"{:?}","text":"{}","register":{},"xar_index":{},"offset":{}"#,
        r.mode,
        esc(&r.text),
        match r.register {
            Some(s) => format!("\"{}\"", esc(s)),
            None => "null".into(),
        },
        match r.xar_index {
            Some(n) => n.to_string(),
            None => "null".into(),
        },
        r.offset
    )
}

/// Decode every loc16/loc32 addressing field, 0x00-0xFF, as one NDJSON line each.
///
/// The whole table rather than selected fields: it is 256 rows, the callers all
/// want a lookup table anyway, and a fixed output is diffable.
fn cmd_loc(width: u32) -> io::Result<()> {
    let mut out = io::BufWriter::new(io::stdout());
    for field in 0u16..=0xFF {
        let r = if width == 32 {
            decode_loc32(field as u8)
        } else {
            decode_loc16(field as u8)
        };
        writeln!(out, r#"{{"field":{},{}}}"#, field, resolved_fields(&r))?;
    }
    out.flush()
}

/// Parse a TI COFF2 file and emit one JSON object: sections (with hex data) and symbols.
fn cmd_coff(path: &str) -> io::Result<()> {
    let data = std::fs::read(path)?;
    let f = match coff::parse_coff(&data) {
        Ok(f) => f,
        Err(e) => {
            println!(r#"{{"error":"{}"}}"#, esc(&e));
            std::process::exit(1);
        }
    };
    let secs: Vec<String> = f
        .sections
        .iter()
        .map(|s| {
            let hex: String = s.data.iter().map(|b| format!("{:02x}", b)).collect();
            format!(
                r#"{{"name":"{}","phys_addr":{},"virt_addr":{},"size":{},"data_offset":{},"flags":{},"is_text":{},"is_data":{},"is_bss":{},"byte_addr":{},"data":"{}"}}"#,
                esc(&s.name), s.phys_addr, s.virt_addr, s.size, s.data_offset, s.flags,
                s.is_text(), s.is_data(), s.is_bss(), s.byte_addr(), hex
            )
        })
        .collect();
    let syms: Vec<String> = f
        .symbols
        .iter()
        .map(|s| {
            format!(
                r#"{{"name":"{}","value":{},"section_num":{},"storage_class":{},"byte_addr":{},"is_function":{}}}"#,
                esc(&s.name), s.value, s.section_num, s.storage_class, s.byte_addr(), s.is_function()
            )
        })
        .collect();
    let mut out = io::BufWriter::new(io::stdout());
    writeln!(
        out,
        r#"{{"sections":[{}],"symbols":[{}]}}"#,
        secs.join(","),
        syms.join(",")
    )?;
    out.flush()
}

fn usage() -> ! {
    eprintln!(
        "c28xdec — C28x decoder CLI\n\
         \n\
         usage:\n\
         \x20 c28xdec decode [--objmode N]   decode `addr:hex` or `hex` lines from stdin as NDJSON\n\
         \x20 c28xdec loc16 | loc32         all 256 addressing fields as NDJSON\n\
         \x20 c28xdec coff <path>           parse a TI COFF2 file as one JSON object\n"
    );
    std::process::exit(2)
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let objmode = args
        .iter()
        .position(|a| a == "--objmode")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);

    match args.first().map(String::as_str) {
        Some("decode") => cmd_decode(objmode),
        Some("loc16") => cmd_loc(16),
        Some("loc32") => cmd_loc(32),
        Some("coff") => match args.get(1) {
            Some(p) => cmd_coff(p),
            None => usage(),
        },
        _ => usage(),
    }
}
