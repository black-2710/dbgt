//! Static, no-process analysis of the executable's own bytes: sections,
//! segments (program headers), the full symbol table, imported functions
//! with their GOT/PLT addresses, and a string scan. Everything here is a
//! pure function over `&[u8]` at link-time (unbiased) addresses, the same
//! addresses `readelf`/`objdump` show — not the runtime, ASLR-shifted ones
//! `Symbols` (in `symbols.rs`) tracks once a process is running.

use iced_x86::{Decoder, DecoderOptions, Mnemonic};
use object::{Object, ObjectSection, ObjectSymbol, RelocationTarget, SectionKind};
use std::collections::HashMap;

pub struct SectionRow {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub kind: String,
    /// Rough r/w/x guess from the section kind (ELF doesn't store this on
    /// the section itself; the authoritative version lives on the segment
    /// that maps it, which is what `segments` reports).
    pub perm: String,
}

pub struct SegmentRow {
    pub kind: String,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub perm: String,
}

pub struct SymRow {
    pub addr: u64,
    pub size: u64,
    pub kind: String,
    pub bind: String,
    pub name: String,
}

pub struct ImportRow {
    pub name: String,
    pub got: u64,
    pub plt: Option<u64>,
}

pub struct StringRow {
    pub addr: u64,
    pub text: String,
}

#[derive(Default)]
pub struct StaticInfo {
    pub sections: Vec<SectionRow>,
    pub segments: Vec<SegmentRow>,
    pub symbols: Vec<SymRow>,
    pub imports: Vec<ImportRow>,
    pub strings: Vec<StringRow>,
    pub strings_truncated: bool,
}

const SYM_LIMIT: usize = 20_000;
const STRING_LIMIT: usize = 8_000;
const MIN_STRING: usize = 4;

pub fn analyze(data: &[u8]) -> Result<StaticInfo, String> {
    let file = object::File::parse(data).map_err(|e| format!("not a readable object file: {e}"))?;

    let mut sections = Vec::new();
    for sec in file.sections() {
        let name = sec.name().unwrap_or("?").to_string();
        let perm = match sec.kind() {
            SectionKind::Text => "r-x",
            SectionKind::ReadOnlyData | SectionKind::ReadOnlyString => "r--",
            SectionKind::Data | SectionKind::UninitializedData | SectionKind::Tls | SectionKind::UninitializedTls => "rw-",
            _ => "---",
        };
        sections.push(SectionRow { name, addr: sec.address(), size: sec.size(), kind: format!("{:?}", sec.kind()), perm: perm.to_string() });
    }
    sections.sort_by_key(|s| s.addr);

    let segments = segments_of(data);

    let mut symbols = Vec::new();
    for sym in file.symbols().chain(file.dynamic_symbols()) {
        let Ok(name) = sym.name() else { continue };
        if name.is_empty() {
            continue;
        }
        let bind = if sym.is_undefined() {
            "UND"
        } else if sym.is_weak() {
            "WEAK"
        } else if sym.is_global() {
            "GLOBAL"
        } else {
            "LOCAL"
        };
        symbols.push(SymRow {
            addr: sym.address(),
            size: sym.size(),
            kind: format!("{:?}", sym.kind()),
            bind: bind.to_string(),
            name: name.to_string(),
        });
        if symbols.len() >= SYM_LIMIT {
            break;
        }
    }
    symbols.sort_by_key(|s| s.addr);

    let imports = imports_of(&file);

    let (strings, strings_truncated) = strings_of(&file);

    Ok(StaticInfo { sections, segments, symbols, imports, strings, strings_truncated })
}

// --- segments (hand-parsed program headers, same layout checksec.rs uses) ---

fn u16at(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(o..o + 2)?.try_into().ok()?))
}
fn u32at(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(o..o + 4)?.try_into().ok()?))
}
fn u64at(d: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(d.get(o..o + 8)?.try_into().ok()?))
}

fn pt_name(t: u32) -> String {
    match t {
        0 => "NULL".into(),
        1 => "LOAD".into(),
        2 => "DYNAMIC".into(),
        3 => "INTERP".into(),
        4 => "NOTE".into(),
        6 => "PHDR".into(),
        7 => "TLS".into(),
        0x6474e550 => "GNU_EH_FRAME".into(),
        0x6474e551 => "GNU_STACK".into(),
        0x6474e552 => "GNU_RELRO".into(),
        0x6474e553 => "GNU_PROPERTY".into(),
        other => format!("{other:#x}"),
    }
}

fn perm_str(p_flags: u32) -> String {
    format!(
        "{}{}{}",
        if p_flags & 4 != 0 { "r" } else { "-" },
        if p_flags & 2 != 0 { "w" } else { "-" },
        if p_flags & 1 != 0 { "x" } else { "-" },
    )
}

fn segments_of(data: &[u8]) -> Vec<SegmentRow> {
    let mut out = Vec::new();
    if data.get(..4) != Some(b"\x7fELF".as_slice()) || data.get(4) != Some(&2) || data.get(5) != Some(&1) {
        return out; // not a 64-bit LE ELF: no program headers to show
    }
    let (Some(phoff), Some(phentsize), Some(phnum)) = (u64at(data, 32), u16at(data, 54), u16at(data, 56)) else {
        return out;
    };
    for i in 0..phnum as usize {
        let o = phoff as usize + i * phentsize as usize;
        let Some(p_type) = u32at(data, o) else { break };
        let p_flags = u32at(data, o + 4).unwrap_or(0);
        let p_offset = u64at(data, o + 8).unwrap_or(0);
        let p_vaddr = u64at(data, o + 16).unwrap_or(0);
        let p_filesz = u64at(data, o + 32).unwrap_or(0);
        let p_memsz = u64at(data, o + 40).unwrap_or(0);
        out.push(SegmentRow { kind: pt_name(p_type), offset: p_offset, vaddr: p_vaddr, filesz: p_filesz, memsz: p_memsz, perm: perm_str(p_flags) });
    }
    out
}

// --- imports: undefined dynamic symbols, their GOT slot, and (if resolvable) PLT stub ---

fn imports_of(file: &object::File) -> Vec<ImportRow> {
    let mut dynsyms: HashMap<usize, String> = HashMap::new();
    let mut undefined: Vec<String> = Vec::new();
    for s in file.dynamic_symbols() {
        let Ok(n) = s.name() else { continue };
        if n.is_empty() {
            continue;
        }
        dynsyms.insert(s.index().0, n.to_string());
        if s.is_undefined() {
            undefined.push(n.to_string());
        }
    }

    let mut got: HashMap<u64, String> = HashMap::new();
    if let Some(relocs) = file.dynamic_relocations() {
        for (off, r) in relocs {
            if let RelocationTarget::Symbol(i) = r.target() {
                if let Some(n) = dynsyms.get(&i.0) {
                    got.insert(off, n.clone());
                }
            }
        }
    }

    // PLT stubs: a jmp [rip+GOT] whose target matches a GOT slot we found above.
    let mut plt: HashMap<String, u64> = HashMap::new();
    for (sec_name, stride) in [(".plt", 16usize), (".plt.sec", 16), (".plt.got", 8)] {
        let Some(sec) = file.section_by_name(sec_name) else { continue };
        let Ok(bytes) = sec.data() else { continue };
        let base = sec.address();
        for (i, chunk) in bytes.chunks(stride).enumerate() {
            let addr = base + (i * stride) as u64;
            let mut dec = Decoder::with_ip(64, chunk, addr, DecoderOptions::NONE);
            while dec.can_decode() {
                let ins = dec.decode();
                if ins.is_invalid() {
                    break;
                }
                if ins.mnemonic() == Mnemonic::Jmp && ins.is_ip_rel_memory_operand() {
                    if let Some(n) = got.get(&ins.ip_rel_memory_address()) {
                        plt.entry(n.clone()).or_insert(addr);
                    }
                    break;
                }
            }
        }
    }
    let mut out: Vec<ImportRow> = got
        .iter()
        .filter(|(_, name)| undefined.iter().any(|u| u == *name))
        .map(|(&addr, name)| ImportRow { name: name.clone(), got: addr, plt: plt.get(name).copied() })
        .collect();
    out.sort_by_key(|i| i.got);
    out.dedup_by_key(|i| i.got);
    out
}

// --- strings: printable ASCII runs across every section with file bytes ---

fn strings_of(file: &object::File) -> (Vec<StringRow>, bool) {
    let mut out = Vec::new();
    let mut truncated = false;
    'secs: for sec in file.sections() {
        if sec.kind() == SectionKind::UninitializedData {
            continue; // .bss: no file bytes
        }
        let Ok(bytes) = sec.data() else { continue };
        let base = sec.address();
        let mut i = 0usize;
        while i < bytes.len() {
            if (0x20..0x7f).contains(&bytes[i]) {
                let start = i;
                while i < bytes.len() && (0x20..0x7f).contains(&bytes[i]) {
                    i += 1;
                }
                if i - start >= MIN_STRING {
                    if let Ok(s) = std::str::from_utf8(&bytes[start..i]) {
                        out.push(StringRow { addr: base + start as u64, text: s.to_string() });
                        if out.len() >= STRING_LIMIT {
                            truncated = true;
                            break 'secs;
                        }
                    }
                }
            } else {
                i += 1;
            }
        }
    }
    out.sort_by_key(|s| s.addr);
    (out, truncated)
}
