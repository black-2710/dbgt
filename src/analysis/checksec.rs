//! `checksec`: static exploit-mitigation report for a 64-bit little-endian ELF.
//! The ELF header, program headers and dynamic section are parsed by hand
//! (a few dozen bytes of structure); symbols come from the `object` crate.

use object::{Object, ObjectSymbol};
use std::collections::HashSet;

fn u16at(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(o..o + 2)?.try_into().ok()?))
}
fn u32at(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(o..o + 4)?.try_into().ok()?))
}
fn u64at(d: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(d.get(o..o + 8)?.try_into().ok()?))
}

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_GNU_STACK: u32 = 0x6474e551;
const PT_GNU_RELRO: u32 = 0x6474e552;
const DT_DEBUG: u64 = 21;
const DT_BIND_NOW: u64 = 24;
const DT_RPATH: u64 = 15;
const DT_RUNPATH: u64 = 29;
const DT_FLAGS: u64 = 30;
const DT_FLAGS_1: u64 = 0x6fff_fffb;

/// One line per check: `[+]` good, `[-]` weak/missing, `[ ]` informational.
pub fn checksec(data: &[u8]) -> Result<Vec<String>, String> {
    if data.get(..4) != Some(b"\x7fELF".as_slice()) {
        return Err("not an ELF file".into());
    }
    if data.get(4) != Some(&2) || data.get(5) != Some(&1) {
        return Err("only 64-bit little-endian ELF is supported".into());
    }
    let bad = || "truncated ELF header".to_string();
    let e_type = u16at(data, 16).ok_or_else(bad)?;
    let phoff = u64at(data, 32).ok_or_else(bad)? as usize;
    let phentsize = u16at(data, 54).ok_or_else(bad)? as usize;
    let phnum = u16at(data, 56).ok_or_else(bad)? as usize;

    let mut has_relro = false;
    let mut stack_flags: Option<u32> = None;
    let mut first_load: Option<u64> = None;
    let mut dynamic: Option<(usize, usize)> = None;
    for i in 0..phnum {
        let o = phoff + i * phentsize;
        let Some(p_type) = u32at(data, o) else { break };
        let p_flags = u32at(data, o + 4).unwrap_or(0);
        let p_offset = u64at(data, o + 8).unwrap_or(0) as usize;
        let p_vaddr = u64at(data, o + 16).unwrap_or(0);
        let p_filesz = u64at(data, o + 32).unwrap_or(0) as usize;
        match p_type {
            PT_LOAD => {
                first_load = Some(first_load.map_or(p_vaddr, |f| f.min(p_vaddr)));
            }
            PT_DYNAMIC => dynamic = Some((p_offset, p_filesz)),
            PT_GNU_STACK => stack_flags = Some(p_flags),
            PT_GNU_RELRO => has_relro = true,
            _ => {}
        }
    }

    let (mut bind_now, mut has_debug, mut rpath, mut runpath) = (false, false, false, false);
    if let Some((off, size)) = dynamic {
        for i in 0..size / 16 {
            let (Some(tag), Some(val)) = (u64at(data, off + i * 16), u64at(data, off + i * 16 + 8)) else {
                break;
            };
            match tag {
                0 => break,
                DT_BIND_NOW => bind_now = true,
                DT_FLAGS if val & 0x8 != 0 => bind_now = true, // DF_BIND_NOW
                DT_FLAGS_1 if val & 0x1 != 0 => bind_now = true, // DF_1_NOW
                DT_DEBUG => has_debug = true,
                DT_RPATH => rpath = true,
                DT_RUNPATH => runpath = true,
                _ => {}
            }
        }
    }

    // symbols: canary, fortify, stripped
    let mut canary = false;
    let mut fortified: HashSet<String> = HashSet::new();
    let mut stripped = true;
    if let Ok(f) = object::File::parse(data) {
        stripped = f.symbols().next().is_none();
        for s in f.symbols().chain(f.dynamic_symbols()) {
            if let Ok(n) = s.name() {
                if n == "__stack_chk_fail" || n == "__stack_chk_guard" {
                    canary = true;
                }
                if n.starts_with("__") && n.ends_with("_chk") {
                    fortified.insert(n.to_string());
                }
            }
        }
    }

    let mut out = Vec::new();
    out.push(match (has_relro, bind_now) {
        (true, true) => "[+] RELRO    : Full RELRO (GOT is read-only after startup)".to_string(),
        (true, false) => "[-] RELRO    : Partial RELRO (GOT stays writable: GOT overwrite possible)".to_string(),
        _ => "[-] RELRO    : No RELRO".to_string(),
    });
    out.push(if canary {
        "[+] Canary   : found (__stack_chk_fail referenced)".to_string()
    } else {
        "[-] Canary   : not found".to_string()
    });
    out.push(match stack_flags {
        Some(f) if f & 1 == 0 => "[+] NX       : enabled".to_string(),
        Some(_) => "[-] NX       : DISABLED (stack is executable)".to_string(),
        None => "[-] NX       : no PT_GNU_STACK header: assume executable stack".to_string(),
    });
    out.push(match (e_type, has_debug) {
        (3, true) => "[+] PIE      : enabled (randomised base)".to_string(),
        (3, false) => "[ ] PIE      : shared object (not an executable)".to_string(),
        (2, _) => format!("[-] PIE      : No PIE (fixed base {:#x})", first_load.unwrap_or(0)),
        _ => format!("[ ] PIE      : unusual ELF type {e_type}"),
    });
    out.push(if fortified.is_empty() {
        "[-] Fortify  : no *_chk functions".to_string()
    } else {
        format!("[+] Fortify  : {} fortified function(s) (e.g. {})", fortified.len(), {
            let mut v: Vec<_> = fortified.iter().cloned().collect();
            v.sort();
            v[0].clone()
        })
    });
    out.push(if rpath || runpath {
        format!("[ ] RPATH    : {} present (check it isn't writable)", if rpath { "RPATH" } else { "RUNPATH" })
    } else {
        "[+] RPATH    : none".to_string()
    });
    out.push(format!("[ ] Stripped : {}", if stripped { "yes (no .symtab)" } else { "no" }));
    Ok(out)
}
