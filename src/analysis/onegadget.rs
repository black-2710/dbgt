//! A scoped, honest substitute for `one_gadget`.
//!
//! Real `one_gadget` finds every call site into `execve`/`system`, follows
//! *every* path that can reach it through the function's control-flow graph,
//! and for each path proves exactly which registers must hold which values
//! (often `NULL`) by symbolically executing that whole path. That's a
//! constraint solver over one specific libc build.
//!
//! This is much smaller: for each call site into `execve`/`system` (plus
//! the raw `execve` syscall inside libc's own wrapper), it finds the
//! enclosing function and does a single **straight-line, fallthrough-only**
//! forward scan from the function's start to the call, tracking only
//! `rdi`/`rsi`/`rdx` as known constants via simple constant propagation
//! (`mov reg, imm`, `xor reg, reg`; anything else marks the register
//! "unknown" from that point on). It does not follow jumps, so if the real
//! path to the call goes through a taken branch, this scans the wrong bytes
//! and the constraints it reports can be wrong — every candidate here is a
//! starting point to verify by hand (read the actual disassembly at that
//! address), never a guarantee the way real `one_gadget`'s output is.

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};
use object::{Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind};

pub struct Gadget {
    pub addr: u64,
    pub via: &'static str,
    pub constraints: Vec<String>,
}

/// Cap on how far back we'll scan from a call site to its function's start.
const SCAN_LIMIT: usize = 4096;

pub fn find(data: &[u8]) -> Result<Vec<Gadget>, String> {
    let file = object::File::parse(data).map_err(|e| format!("not a readable object file: {e}"))?;

    let mut sinks: Vec<(u64, &'static str)> = Vec::new();
    for sym in file.symbols().chain(file.dynamic_symbols()) {
        let Ok(name) = sym.name() else { continue };
        match name {
            "execve" | "__execve" => sinks.push((sym.address(), "call execve")),
            "system" | "__libc_system" => sinks.push((sym.address(), "call system")),
            _ => {}
        }
    }

    // (start, end) of every sized function symbol, used to find the
    // "nearest enclosing function" for a hit address.
    let mut funcs: Vec<(u64, u64)> = file
        .symbols()
        .filter(|s| s.kind() == SymbolKind::Text && s.size() > 0)
        .map(|s| (s.address(), s.address() + s.size()))
        .collect();
    funcs.sort();

    let mut out = Vec::new();
    for sec in file.sections() {
        if sec.kind() != SectionKind::Text {
            continue;
        }
        let Ok(bytes) = sec.data() else { continue };
        let base = sec.address();

        // Direct calls into execve/system.
        let mut dec = Decoder::with_ip(64, bytes, base, DecoderOptions::NONE);
        while dec.can_decode() {
            let ins = dec.decode();
            if ins.is_invalid() || ins.mnemonic() != Mnemonic::Call {
                continue;
            }
            if !matches!(ins.op0_kind(), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64) {
                continue;
            }
            let target = ins.near_branch_target();
            if let Some(&(_, via)) = sinks.iter().find(|&&(a, _)| a == target) {
                if let Some(g) = analyze_site(bytes, base, &funcs, ins.ip(), via) {
                    out.push(g);
                }
            }
        }

        // The raw execve syscall inside libc's own `execve()`/`__execve()`:
        // `mov eax, 0x3b` shortly before `syscall`, same basic block.
        let mut dec2 = Decoder::with_ip(64, bytes, base, DecoderOptions::NONE);
        let mut window: Vec<Instruction> = Vec::new();
        while dec2.can_decode() {
            let ins = dec2.decode();
            if ins.is_invalid() {
                window.clear();
                continue;
            }
            if ins.mnemonic() == Mnemonic::Syscall {
                let eax_execve = window.iter().rev().take(12).any(|w| {
                    w.mnemonic() == Mnemonic::Mov
                        && w.op0_kind() == OpKind::Register
                        && w.op0_register().full_register() == Register::RAX
                        && matches!(w.op1_kind(), OpKind::Immediate8 | OpKind::Immediate16 | OpKind::Immediate32 | OpKind::Immediate64)
                        && w.immediate(1) == 0x3b
                });
                if eax_execve {
                    if let Some(g) = analyze_site(bytes, base, &funcs, ins.ip(), "execve syscall") {
                        out.push(g);
                    }
                }
            }
            if matches!(ins.flow_control(), FlowControl::UnconditionalBranch | FlowControl::IndirectBranch | FlowControl::Return) {
                window.clear();
            } else {
                window.push(ins);
                if window.len() > 16 {
                    window.remove(0);
                }
            }
        }
    }
    out.sort_by_key(|g| g.addr);
    out.dedup_by_key(|g| g.addr);
    Ok(out)
}

/// Straight-line (no branches followed) forward scan from the enclosing
/// function's start up to `call_addr`, tracking rdi/rsi/rdx.
fn analyze_site(bytes: &[u8], sec_base: u64, funcs: &[(u64, u64)], call_addr: u64, via: &'static str) -> Option<Gadget> {
    let start = funcs
        .iter()
        .rev()
        .find(|&&(s, e)| s <= call_addr && call_addr < e)
        .map(|&(s, _)| s)
        .unwrap_or_else(|| call_addr.saturating_sub(64).max(sec_base));
    if start < sec_base || call_addr <= start {
        return None;
    }
    let off = (start - sec_base) as usize;
    let end_off = ((call_addr - sec_base) as usize).min(bytes.len());
    if off >= end_off || end_off - off > SCAN_LIMIT {
        return None;
    }

    let mut rdi = None::<u64>;
    let mut rsi = None::<u64>;
    let mut rdx = None::<u64>;
    let mut dec = Decoder::with_ip(64, &bytes[off..end_off], start, DecoderOptions::NONE);
    while dec.can_decode() {
        let ins = dec.decode();
        if ins.is_invalid() {
            continue;
        }
        update_const(&ins, Register::RDI, &mut rdi);
        update_const(&ins, Register::RSI, &mut rsi);
        update_const(&ins, Register::RDX, &mut rdx);
    }

    let describe = |name: &str, v: Option<u64>| match v {
        Some(0) => format!("{name}=NULL (fixed by this path)"),
        Some(x) => format!("{name}={x:#x} (fixed by this path)"),
        None => format!("{name}=? — must be valid/NULL when you land here"),
    };
    Some(Gadget {
        addr: call_addr,
        via,
        constraints: vec![describe("rdi", rdi), describe("rsi", rsi), describe("rdx", rdx)],
    })
}

/// If `ins` sets `reg` to a value we can pin down (constant or zero), record
/// it; if it writes `reg` some other way, mark it unknown from here on.
fn update_const(ins: &Instruction, reg: Register, slot: &mut Option<u64>) {
    if ins.op_count() == 0 || ins.op0_kind() != OpKind::Register || ins.op0_register().full_register() != reg {
        return;
    }
    match ins.mnemonic() {
        Mnemonic::Xor if ins.op1_kind() == OpKind::Register && ins.op1_register() == ins.op0_register() => {
            *slot = Some(0);
        }
        Mnemonic::Mov if matches!(ins.op1_kind(), OpKind::Immediate8 | OpKind::Immediate16 | OpKind::Immediate32 | OpKind::Immediate32to64 | OpKind::Immediate64) => {
            *slot = Some(ins.immediate(1));
        }
        _ => *slot = None,
    }
}
