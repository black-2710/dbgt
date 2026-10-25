//! Backend thread. It owns the tracee: every ptrace call happens on this one
//! thread, because ptrace requests must come from the thread that attached.
//! The UI talks to it with `Cmd` and hears back with `Event`.

mod ptrace;

use crate::analysis::{
    cfg::{self, Cfg},
    checksec,
    symbols::{short, Symbols},
};
use anyhow::Result;
use nix::sys::signal::Signal;
use std::{
    collections::{HashMap, HashSet},
    fmt,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::{
        mpsc::{self, Receiver, Sender},
        Arc,
    },
    thread,
};

pub use ptrace::{Tracee, WatchKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    Start,
    /// Registers or memory were modified by the user.
    Edited,
    Step,
    Breakpoint(u64),
    Trap,
    /// Hardware watchpoint (slot 0-3) fired.
    Watch(u8),
    Signal(Signal),
    Exited(i32),
    Killed(Signal),
}

impl fmt::Display for Stop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Stop::Start => write!(f, "stopped at entry"),
            Stop::Step => write!(f, "step"),
            Stop::Edited => write!(f, "edited"),
            Stop::Breakpoint(a) => write!(f, "breakpoint {a:#x}"),
            Stop::Trap => write!(f, "SIGTRAP"),
            Stop::Watch(n) => write!(f, "watchpoint {}", n + 1),
            Stop::Signal(s) => write!(f, "signal {s}"),
            Stop::Exited(c) => write!(f, "exited with code {c}"),
            Stop::Killed(s) => write!(f, "killed by {s}"),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Regs {
    pub rax: u64, pub rbx: u64, pub rcx: u64, pub rdx: u64,
    pub rsi: u64, pub rdi: u64, pub rbp: u64, pub rsp: u64,
    pub r8: u64, pub r9: u64, pub r10: u64, pub r11: u64,
    pub r12: u64, pub r13: u64, pub r14: u64, pub r15: u64,
    pub rip: u64, pub eflags: u64,
    pub cs: u64, pub ss: u64, pub ds: u64, pub es: u64, pub fs: u64, pub gs: u64,
    pub fs_base: u64, pub gs_base: u64,
}

impl From<nix::libc::user_regs_struct> for Regs {
    fn from(r: nix::libc::user_regs_struct) -> Self {
        Regs {
            rax: r.rax, rbx: r.rbx, rcx: r.rcx, rdx: r.rdx,
            rsi: r.rsi, rdi: r.rdi, rbp: r.rbp, rsp: r.rsp,
            r8: r.r8, r9: r.r9, r10: r.r10, r11: r.r11,
            r12: r.r12, r13: r.r13, r14: r.r14, r15: r.r15,
            rip: r.rip, eflags: r.eflags,
            cs: r.cs, ss: r.ss, ds: r.ds, es: r.es, fs: r.fs, gs: r.gs,
            fs_base: r.fs_base, gs_base: r.gs_base,
        }
    }
}

impl Regs {
    pub fn get(&self, name: &str) -> Option<u64> {
        Some(match name {
            "rax" => self.rax, "rbx" => self.rbx, "rcx" => self.rcx, "rdx" => self.rdx,
            "rsi" => self.rsi, "rdi" => self.rdi, "rbp" => self.rbp, "rsp" | "sp" => self.rsp,
            "r8" => self.r8, "r9" => self.r9, "r10" => self.r10, "r11" => self.r11,
            "r12" => self.r12, "r13" => self.r13, "r14" => self.r14, "r15" => self.r15,
            "rip" | "pc" => self.rip, "eflags" => self.eflags,
            "cs" => self.cs, "ss" => self.ss, "ds" => self.ds, "es" => self.es,
            "fs" => self.fs, "gs" => self.gs,
            "fs_base" => self.fs_base, "gs_base" => self.gs_base,
            _ => return None,
        })
    }
}

/// Everything the UI needs to redraw after the tracee stops.
pub struct Snapshot {
    pub stop: Stop,
    pub regs: Regs,
    /// Raw bytes starting at RIP (for linear disassembly).
    pub code: Vec<u8>,
}

pub struct StackRow {
    pub addr: u64,
    pub val: u64,
    pub desc: String,
}

/// Stack telescope + hexdump contents.
pub struct Views {
    pub stack: Vec<StackRow>,
    pub hex_addr: u64,
    pub hex: Vec<u8>,
}

/// `None` = follow RSP.
#[derive(Default)]
struct ViewCfg {
    stack: Option<u64>,
    hex: Option<u64>,
}

/// One line of /proc/<pid>/maps.
#[derive(Clone)]
pub struct MapEntry {
    pub start: u64,
    pub end: u64,
    pub perms: String,
    pub offset: u64,
    pub path: String,
}

pub fn parse_maps(text: &str) -> Vec<MapEntry> {
    text.lines()
        .filter_map(|line| {
            let mut it = line.splitn(6, ' ');
            let range = it.next()?;
            let perms = it.next()?;
            let off = it.next()?;
            let (_dev, _ino) = (it.next()?, it.next()?);
            let path = it.next().unwrap_or("").trim().to_string();
            let (s, e) = range.split_once('-')?;
            Some(MapEntry {
                start: u64::from_str_radix(s, 16).ok()?,
                end: u64::from_str_radix(e, 16).ok()?,
                perms: perms.to_string(),
                offset: u64::from_str_radix(off, 16).ok()?,
                path,
            })
        })
        .collect()
}

/// Result of a memory search.
pub struct Found {
    pub desc: String,
    pub hits: Vec<(u64, String)>,
    pub truncated: bool,
}

pub enum Cmd {
    Step,
    Next,
    Continue,
    Break(u64),
    Delete(u64),
    Stack(Option<u64>),
    Hex(Option<u64>),
    /// Search every readable mapping (optionally only those whose path contains `filter`).
    Find { pat: Vec<u8>, filter: Option<String>, desc: String },
    Checksec,
    SetReg { name: String, value: u64 },
    WriteMem { addr: u64, bytes: Vec<u8> },
    /// Build a CFG for the function containing this address (call-following).
    Cfg(u64),
    Watch { addr: u64, len: usize, kind: WatchKind },
    /// 1-based, as shown to the user.
    Unwatch(usize),
    Watches,
}

pub enum Event {
    Started(i32),
    Stopped(Snapshot),
    Views(Views),
    Cfg(Arc<Cfg>),
    BrowseCfg(Arc<Cfg>),
    Maps(Arc<Vec<MapEntry>>),
    Found(Found),
    Symbols(Arc<Symbols>),
    Ended(Stop),
    Breakpoints(Vec<u64>),
    /// Pty master: the UI writes keystrokes to it directly.
    Pty(File),
    /// Bytes the target wrote to its terminal.
    PtyOut(Vec<u8>),
    Log(String),
    /// Backend thread is finished (spawn failure, or the UI went away).
    Gone,
}

pub fn start(program: PathBuf, args: Vec<String>, ev: Sender<Event>) -> Sender<Cmd> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        if let Err(e) = run(&program, &args, &rx, &ev) {
            let _ = ev.send(Event::Log(format!("backend error: {e:#}")));
        }
        let _ = ev.send(Event::Gone);
    });
    tx
}

fn snapshot(t: &Tracee, stop: Stop) -> Result<Snapshot> {
    let regs = t.regs()?;
    let code = t.read_mem(regs.rip, 256);
    Ok(Snapshot { stop, regs, code })
}

fn views(t: &Tracee, syms: &Symbols, regs: &Regs, cfg: &ViewCfg) -> Views {
    let base = cfg.stack.unwrap_or(regs.rsp);
    let raw = t.read_mem(base, 48 * 8);
    let stack = raw
        .chunks_exact(8)
        .enumerate()
        .map(|(i, c)| {
            let val = u64::from_le_bytes(<[u8; 8]>::try_from(c).unwrap());
            StackRow { addr: base + 8 * i as u64, val, desc: describe(t, syms, val) }
        })
        .collect();
    let hex_addr = cfg.hex.unwrap_or(regs.rsp);
    Views { stack, hex_addr, hex: t.read_mem(hex_addr, 384) }
}

/// GEF-style pointer chain: `→ 0x… → "text"` or `<symbol+off>`.
fn describe(t: &Tracee, syms: &Symbols, mut v: u64) -> String {
    let mut out = String::new();
    for _ in 0..4 {
        if let Some((n, off)) = syms.lookup(v) {
            if off == 0 {
                out.push_str(&format!(" <{n}>"));
            } else {
                out.push_str(&format!(" <{n}+{off:#x}>"));
            }
            return out;
        }
        let buf = t.read_mem(v, 32);
        if buf.len() < 8 {
            return out; // not a readable pointer
        }
        let s: String = buf
            .iter()
            .take_while(|&&b| (0x20..0x7f).contains(&b))
            .map(|&b| b as char)
            .collect();
        if s.len() >= 4 {
            out.push_str(&format!(" → \"{s}\""));
            return out;
        }
        v = u64::from_le_bytes(<[u8; 8]>::try_from(&buf[..8]).unwrap());
        out.push_str(&format!(" → {v:#x}"));
    }
    out
}

/// CFG of the function containing `addr` (root = function start, plus `addr` itself).
fn build_cfg(t: &Tracee, syms: &Symbols, addr: u64) -> Arc<Cfg> {
    let (start, size) = syms.func_range(addr).unwrap_or((addr, 0x800));
    let code = t.read_mem(start, size.clamp(16, 0x10000) as usize);
    Arc::new(cfg::build(&code, start, &[start, addr]))
}

fn find_in_memory(t: &Tracee, syms: &Symbols, pat: &[u8], filter: Option<&str>, desc: String) -> Found {
    const MAX_HITS: usize = 500;
    const CHUNK: usize = 1 << 20;
    let maps = parse_maps(&t.maps());
    let mut hits: Vec<(u64, String)> = Vec::new();
    let mut truncated = false;

    'maps: for m in &maps {
        if !m.perms.starts_with('r') || m.path == "[vvar]" || m.path == "[vsyscall]" {
            continue;
        }
        if let Some(f) = filter {
            if !m.path.contains(f) {
                continue;
            }
        }
        let name = if m.path.is_empty() { "[anon]".to_string() } else { short(&m.path).to_string() };
        let mut off = m.start;
        while off < m.end {
            // CHUNK start positions per read; the extra bytes catch matches across the boundary
            let len = ((m.end - off) as usize).min(CHUNK + pat.len() - 1);
            let buf = t.read_mem(off, len);
            if buf.len() < pat.len() {
                break;
            }
            for (i, w) in buf.windows(pat.len()).enumerate() {
                if w[0] != pat[0] || w != pat {
                    continue;
                }
                let addr = off + i as u64;
                let ctx = t.read_mem(addr, 24usize.min((m.end - addr) as usize));
                let ascii: String = ctx
                    .iter()
                    .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
                    .collect();
                let sym = match syms.lookup(addr) {
                    Some((n, 0)) => format!(" <{n}>"),
                    Some((n, o)) => format!(" <{n}+{o:#x}>"),
                    None => String::new(),
                };
                hits.push((
                    addr,
                    format!("[{}] {}+{:#x}{}  \"{}\"", m.perms, name, addr - m.start, sym, ascii),
                ));
                if hits.len() >= MAX_HITS {
                    truncated = true;
                    break 'maps;
                }
            }
            off += CHUNK as u64;
        }
    }
    Found { desc, hits, truncated }
}

/// Report a stop. Rebuilds the CFG only when RIP left the one the UI already has.
fn send_stop(
    t: &Tracee,
    syms: &Symbols,
    ev: &Sender<Event>,
    stop: Stop,
    cfg: &ViewCfg,
    cur: &mut Option<Arc<Cfg>>,
) -> Result<()> {
    let snap = snapshot(t, stop)?;
    let rip = snap.regs.rip;
    if !cur.as_ref().map(|c| c.has_insn(rip)).unwrap_or(false) {
        let c = build_cfg(t, syms, rip);
        let _ = ev.send(Event::Cfg(c.clone()));
        *cur = Some(c);
    }
    let v = views(t, syms, &snap.regs, cfg);
    let _ = ev.send(Event::Stopped(snap));
    let _ = ev.send(Event::Views(v));
    Ok(())
}

/// Watches /proc/<pid>/maps and loads symbols from every ELF that appears
/// (the executable and ld.so at start; libc etc. once ld.so has mapped them).
struct ModLoader {
    exe: Option<String>,
    tried: HashSet<String>,
    last_maps: String,
}

fn is_elf(path: &str) -> bool {
    let mut magic = [0u8; 4];
    File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .map(|_| &magic == b"\x7fELF")
        .unwrap_or(false)
}

fn refresh_modules(t: &Tracee, loader: &mut ModLoader, syms: &mut Arc<Symbols>, ev: &Sender<Event>) {
    let maps = t.maps();
    if maps == loader.last_maps {
        return;
    }
    loader.last_maps = maps.clone();
    let _ = ev.send(Event::Maps(Arc::new(parse_maps(&maps))));

    // path -> lowest offset-0 mapping = load base of that file
    let mut bases: HashMap<String, u64> = HashMap::new();
    for line in maps.lines() {
        let mut it = line.split_whitespace();
        let (Some(range), Some(_perms), Some(off)) = (it.next(), it.next(), it.next()) else { continue };
        let (_dev, _ino) = (it.next(), it.next());
        let Some(path) = it.next() else { continue };
        if !path.starts_with('/') || u64::from_str_radix(off, 16).ok() != Some(0) {
            continue;
        }
        let Some(start) = range.split('-').next().and_then(|s| u64::from_str_radix(s, 16).ok()) else {
            continue;
        };
        bases.entry(path.to_string()).and_modify(|b| *b = (*b).min(start)).or_insert(start);
    }

    let mut todo: Vec<(u64, String)> = bases
        .into_iter()
        .filter(|(p, _)| !loader.tried.contains(p))
        .map(|(p, b)| (b, p))
        .collect();
    if todo.is_empty() {
        return;
    }
    todo.sort();

    let mut s: Symbols = (**syms).clone();
    for (base, path) in todo {
        loader.tried.insert(path.clone());
        if !is_elf(&path) {
            continue;
        }
        let Ok(data) = std::fs::read(&path) else { continue };
        let name = Path::new(&path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.clone());
        let is_main = loader.exe.as_deref() == Some(path.as_str());
        match s.add_module(&name, &data, base, is_main) {
            Ok(n) => {
                let _ = ev.send(Event::Log(format!("symbols: {name} @ {base:#x} ({n})")));
            }
            Err(e) => {
                let _ = ev.send(Event::Log(format!("symbols: {name}: {e:#}")));
            }
        }
    }
    *syms = Arc::new(s);
    let _ = ev.send(Event::Symbols(syms.clone()));
}

fn run(program: &Path, args: &[String], rx: &Receiver<Cmd>, ev: &Sender<Event>) -> Result<()> {
    let (mut t, _child, master) = Tracee::launch(program, args)?;
    pump_pty(master.try_clone()?, ev.clone());
    let _ = ev.send(Event::Pty(master));

    let mut syms: Arc<Symbols> = Arc::new(Symbols::default());
    let mut loader = ModLoader { exe: t.exe_path(), tried: HashSet::new(), last_maps: String::new() };
    refresh_modules(&t, &mut loader, &mut syms, ev);

    let mut cfg = ViewCfg::default();
    let mut cur_cfg: Option<Arc<Cfg>> = None;

    let _ = ev.send(Event::Started(t.pid().as_raw()));
    send_stop(&t, &syms, ev, Stop::Start, &cfg, &mut cur_cfg)?;

    let mut alive = true;
    while let Ok(cmd) = rx.recv() {
        let stop = match cmd {
            Cmd::Break(a) => {
                t.add_bp(a);
                let _ = ev.send(Event::Breakpoints(t.bps()));
                let _ = ev.send(Event::Log(format!("breakpoint set at {a:#x}")));
                continue;
            }
            Cmd::Delete(a) => {
                let msg = if t.del_bp(a) {
                    format!("breakpoint at {a:#x} deleted")
                } else {
                    format!("no breakpoint at {a:#x}")
                };
                let _ = ev.send(Event::Breakpoints(t.bps()));
                let _ = ev.send(Event::Log(msg));
                continue;
            }
            Cmd::Watch { addr, len, kind } => {
                let msg = match t.add_watch(addr, len, kind) {
                    Ok((slot, l)) => {
                        let what = if kind == WatchKind::Write { "watch" } else { "rwatch" };
                        let note = if l != len { format!(" (shrunk from {len}: address not aligned)") } else { String::new() };
                        format!("hardware {what} {}: *{addr:#x}, {l} byte(s){note}", slot + 1)
                    }
                    Err(e) => format!("watch failed: {e:#}"),
                };
                let _ = ev.send(Event::Log(msg));
                continue;
            }
            Cmd::Unwatch(n) => {
                let msg = match n.checked_sub(1).map(|s| t.del_watch(s)) {
                    Some(Ok(true)) => format!("watchpoint {n} deleted"),
                    Some(Ok(false)) | None => format!("no watchpoint {n}"),
                    Some(Err(e)) => format!("unwatch failed: {e:#}"),
                };
                let _ = ev.send(Event::Log(msg));
                continue;
            }
            Cmd::Watches => {
                let list = t.watch_list();
                if list.is_empty() {
                    let _ = ev.send(Event::Log("no watchpoints (watch <addr> [1|2|4|8])".into()));
                }
                for (i, addr, len, kind, hits) in list {
                    let k = if kind == WatchKind::Write { "write" } else { "read/write" };
                    let _ = ev.send(Event::Log(format!("{}: *{addr:#x}  {len}B  {k}  hits={hits}", i + 1)));
                }
                continue;
            }
            Cmd::Cfg(a) => {
                let _ = ev.send(Event::BrowseCfg(build_cfg(&t, &syms, a)));
                continue;
            }
            Cmd::Find { pat, filter, desc } => {
                let found = find_in_memory(&t, &syms, &pat, filter.as_deref(), desc);
                let _ = ev.send(Event::Found(found));
                continue;
            }
            Cmd::SetReg { name, value } => {
                let res = if alive {
                    t.set_reg(&name, value)
                } else {
                    Err(anyhow::anyhow!("process has exited"))
                };
                match res {
                    Ok(()) => {
                        let _ = ev.send(Event::Log(format!("{} = {value:#x}", name.trim_start_matches('$'))));
                        send_stop(&t, &syms, ev, Stop::Edited, &cfg, &mut cur_cfg)?;
                    }
                    Err(e) => {
                        let _ = ev.send(Event::Log(format!("set failed: {e:#}")));
                    }
                }
                continue;
            }
            Cmd::WriteMem { addr, bytes } => {
                let res = if alive {
                    t.write_mem(addr, &bytes)
                } else {
                    Err(anyhow::anyhow!("process has exited"))
                };
                match res {
                    Ok(()) => {
                        let _ = ev.send(Event::Log(format!("wrote {} byte(s) at {addr:#x}", bytes.len())));
                        cur_cfg = None; // code may have changed: rebuild the graph
                        send_stop(&t, &syms, ev, Stop::Edited, &cfg, &mut cur_cfg)?;
                    }
                    Err(e) => {
                        let _ = ev.send(Event::Log(format!("write failed: {e:#}")));
                    }
                }
                continue;
            }
            Cmd::Checksec => {
                let report = t
                    .exe_path()
                    .and_then(|p| std::fs::read(&p).ok().map(|d| (p, d)));
                match report {
                    Some((p, d)) => match checksec::checksec(&d) {
                        Ok(lines) => {
                            let _ = ev.send(Event::Log(format!("checksec {p}")));
                            for l in lines {
                                let _ = ev.send(Event::Log(l));
                            }
                        }
                        Err(e) => {
                            let _ = ev.send(Event::Log(format!("checksec: {e}")));
                        }
                    },
                    None => {
                        let _ = ev.send(Event::Log("checksec: cannot read the executable".into()));
                    }
                }
                continue;
            }
            Cmd::Stack(a) => {
                cfg.stack = a;
                if alive {
                    if let Ok(r) = t.regs() {
                        let _ = ev.send(Event::Views(views(&t, &syms, &r, &cfg)));
                    }
                }
                continue;
            }
            Cmd::Hex(a) => {
                cfg.hex = a;
                if alive {
                    if let Ok(r) = t.regs() {
                        let _ = ev.send(Event::Views(views(&t, &syms, &r, &cfg)));
                    }
                }
                continue;
            }
            _ if !alive => {
                let _ = ev.send(Event::Log("process has exited".into()));
                continue;
            }
            Cmd::Step => t.step()?,
            Cmd::Next => t.next()?,
            Cmd::Continue => t.cont(None)?,
        };

        if let Stop::Watch(slot) = stop {
            if let Some(msg) = t.watch_report(slot) {
                let _ = ev.send(Event::Log(msg));
            }
        }

        match stop {
            Stop::Exited(_) | Stop::Killed(_) => {
                alive = false;
                let _ = ev.send(Event::Ended(stop));
            }
            _ => {
                refresh_modules(&t, &mut loader, &mut syms, ev);
                send_stop(&t, &syms, ev, stop, &cfg, &mut cur_cfg)?
            }
        }
    }

    if alive {
        t.kill();
    }
    Ok(())
}

/// Forward everything the target writes to its terminal. Ends (EIO) when the target exits.
fn pump_pty(mut r: File, ev: Sender<Event>) {
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match r.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if ev.send(Event::PtyOut(buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
            }
        }
    });
}
