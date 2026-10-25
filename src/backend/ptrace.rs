use super::{Regs, Stop};
use crate::analysis::disasm;
use anyhow::{bail, Context, Result};
use nix::sys::{
    personality::{self, Persona},
    ptrace,
    signal::{self, Signal},
    wait::{waitpid, WaitStatus},
};
use nix::unistd::Pid;
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    os::unix::{
        fs::FileExt,
        io::{AsRawFd, RawFd},
        process::CommandExt,
    },
    path::Path,
    process::{Child, Command, Stdio},
};

/// offsetof(struct user, u_debugreg) on x86_64 Linux (PTRACE_PEEKUSER/POKEUSER offset of DR0).
const DEBUGREG_OFFSET: usize = 848;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WatchKind {
    /// Trap after a write (only reported when the value actually changed).
    Write,
    /// Trap after any read or write (x86 cannot watch reads alone).
    ReadWrite,
}

pub struct Watch {
    pub addr: u64,
    pub len: usize,
    pub kind: WatchKind,
    pub hits: u32,
    last: Vec<u8>,
    old: Vec<u8>,
}

enum WatchHit {
    No,
    Report(u8),
    /// Hardware trap, but a write that didn't change the value: keep running.
    Silent,
}

fn fmt_val(b: &[u8]) -> String {
    if b.is_empty() || b.len() > 8 {
        return "?".into();
    }
    let mut a = [0u8; 8];
    a[..b.len()].copy_from_slice(b);
    format!("{:#x}", u64::from_le_bytes(a))
}

pub struct Tracee {
    pid: Pid,
    /// /proc/<pid>/mem: reads and writes work on any mapping (incl. read-only
    /// text) while we're ptrace-attached, and partial reads are handled for us.
    mem: File,
    breakpoints: BTreeSet<u64>,
    /// Signal to deliver on the next resume (set when the tracee stopped on one).
    pending_sig: Option<Signal>,
    watches: [Option<Watch>; 4],
}

/// Signals that are delivered to the target without stopping the debugger
/// (window resizes when the pane changes size, timers, child exits...).
fn is_silent(sig: Signal) -> bool {
    matches!(
        sig,
        Signal::SIGWINCH
            | Signal::SIGURG
            | Signal::SIGCHLD
            | Signal::SIGALRM
            | Signal::SIGVTALRM
            | Signal::SIGPROF
            | Signal::SIGIO
    )
}

impl Tracee {
    /// Spawns the target on a fresh pty (its stdin/stdout/stderr and controlling
    /// terminal). Returns the pty master so the UI can read output and send input.
    pub fn launch(program: &Path, args: &[String]) -> Result<(Tracee, Child, File)> {
        let ws = nix::pty::Winsize { ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0 };
        let pty = nix::pty::openpty(Some(&ws), None).context("openpty failed")?;
        let master = File::from(pty.master);
        let slave = pty.slave;
        let set_cloexec = |fd: RawFd| unsafe {
            nix::libc::fcntl(fd, nix::libc::F_SETFD, nix::libc::FD_CLOEXEC);
        };
        set_cloexec(master.as_raw_fd());
        set_cloexec(slave.as_raw_fd()); // try_clone() copies are close-on-exec too

        let mut cmd = Command::new(program);
        cmd.args(args)
            .stdin(Stdio::from(slave.try_clone()?))
            .stdout(Stdio::from(slave.try_clone()?))
            .stderr(Stdio::from(slave));

        // Runs in the forked child, after std has dup2'd the slave onto fds 0-2.
        unsafe {
            cmd.pre_exec(|| {
                // New session, with the pty slave (fd 0) as controlling terminal.
                nix::libc::setsid();
                nix::libc::ioctl(0, nix::libc::TIOCSCTTY as _, 0);
                // Like gdb: no ASLR, so addresses are stable between runs.
                if let Ok(cur) = personality::get() {
                    let _ = personality::set(cur | Persona::ADDR_NO_RANDOMIZE);
                }
                ptrace::traceme().map_err(std::io::Error::from)
            });
        }

        let child = cmd
            .spawn()
            .with_context(|| format!("failed to spawn {}", program.display()))?;
        drop(cmd); // closes our copies of the slave, so the master sees EOF when the target exits
        let pid = Pid::from_raw(child.id() as i32);

        // The tracee stops with SIGTRAP right after exec.
        match waitpid(pid, None)? {
            WaitStatus::Stopped(_, Signal::SIGTRAP) => {}
            other => bail!("unexpected initial wait status: {other:?}"),
        }
        // If dbgt dies, the tracee dies with it.
        ptrace::setoptions(pid, ptrace::Options::PTRACE_O_EXITKILL)?;

        let mem = OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/proc/{}/mem", pid.as_raw()))
            .context("cannot open /proc/<pid>/mem")?;

        Ok((
            Tracee {
                pid,
                mem,
                breakpoints: BTreeSet::new(),
                pending_sig: None,
                watches: Default::default(),
            },
            child,
            master,
        ))
    }

    pub fn pid(&self) -> Pid {
        self.pid
    }

    pub fn regs(&self) -> Result<Regs> {
        Ok(ptrace::getregs(self.pid)?.into())
    }

    /// Best-effort read; returns fewer bytes (or none) if the range isn't mapped.
    pub fn read_mem(&self, addr: u64, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        match self.mem.read_at(&mut buf, addr) {
            Ok(n) => {
                buf.truncate(n);
                buf
            }
            Err(_) => Vec::new(),
        }
    }

    /// Overwrite one register (only meaningful while the target is stopped).
    pub fn set_reg(&mut self, name: &str, v: u64) -> Result<()> {
        let mut r = ptrace::getregs(self.pid)?;
        match name.trim_start_matches('$') {
            "rax" => r.rax = v,
            "rbx" => r.rbx = v,
            "rcx" => r.rcx = v,
            "rdx" => r.rdx = v,
            "rsi" => r.rsi = v,
            "rdi" => r.rdi = v,
            "rbp" => r.rbp = v,
            "rsp" | "sp" => r.rsp = v,
            "r8" => r.r8 = v,
            "r9" => r.r9 = v,
            "r10" => r.r10 = v,
            "r11" => r.r11 = v,
            "r12" => r.r12 = v,
            "r13" => r.r13 = v,
            "r14" => r.r14 = v,
            "r15" => r.r15 = v,
            "rip" | "pc" => r.rip = v,
            "eflags" => r.eflags = v,
            "fs_base" => r.fs_base = v,
            "gs_base" => r.gs_base = v,
            other => bail!("cannot set register '{other}'"),
        }
        ptrace::setregs(self.pid, r)?;
        Ok(())
    }

    /// Write bytes into the target (works on read-only code too).
    pub fn write_mem(&self, addr: u64, bytes: &[u8]) -> Result<()> {
        let n = self.mem.write_at(bytes, addr)?;
        if n != bytes.len() {
            bail!("short write ({n} of {} bytes): is {addr:#x} mapped?", bytes.len());
        }
        Ok(())
    }

    pub fn add_bp(&mut self, addr: u64) {
        self.breakpoints.insert(addr);
    }

    pub fn del_bp(&mut self, addr: u64) -> bool {
        self.breakpoints.remove(&addr)
    }

    pub fn bps(&self) -> Vec<u64> {
        self.breakpoints.iter().copied().collect()
    }

    pub fn kill(&mut self) {
        let _ = signal::kill(self.pid, Signal::SIGKILL);
        let _ = waitpid(self.pid, None);
    }

    fn wait(&mut self) -> Result<Stop> {
        Ok(match waitpid(self.pid, None)? {
            WaitStatus::Exited(_, code) => Stop::Exited(code),
            WaitStatus::Signaled(_, sig, _) => Stop::Killed(sig),
            WaitStatus::Stopped(_, Signal::SIGTRAP) => Stop::Trap,
            WaitStatus::Stopped(_, sig) => {
                // SIGSTOP is how the UI interrupts us (Ctrl-C); don't forward it.
                if sig != Signal::SIGSTOP {
                    self.pending_sig = Some(sig);
                }
                Stop::Signal(sig)
            }
            other => bail!("unexpected wait status: {other:?}"),
        })
    }

    fn read_dr(&self, i: usize) -> Result<u64> {
        let off = (DEBUGREG_OFFSET + i * 8) as ptrace::AddressType;
        Ok(ptrace::read_user(self.pid, off)? as u64)
    }

    fn write_dr(&self, i: usize, v: u64) -> Result<()> {
        let off = (DEBUGREG_OFFSET + i * 8) as ptrace::AddressType;
        ptrace::write_user(self.pid, off, v as nix::libc::c_long)?;
        Ok(())
    }

    /// Program DR0-3 and DR7 from `self.watches`.
    fn apply_watches(&self) -> Result<()> {
        self.write_dr(7, 0)?; // disable everything while the address registers change
        let mut dr7: u64 = 0;
        for (i, w) in self.watches.iter().enumerate() {
            let Some(w) = w else {
                self.write_dr(i, 0)?;
                continue;
            };
            self.write_dr(i, w.addr)?;
            let rw: u64 = match w.kind {
                WatchKind::Write => 0b01,
                WatchKind::ReadWrite => 0b11,
            };
            let ln: u64 = match w.len {
                1 => 0b00,
                2 => 0b01,
                4 => 0b11,
                _ => 0b10, // 8 bytes
            };
            dr7 |= (1u64 << (2 * i)) | (rw << (16 + 4 * i)) | (ln << (18 + 4 * i));
        }
        if dr7 != 0 {
            self.write_dr(7, dr7)?;
        }
        Ok(())
    }

    /// Returns (slot, effective length). The address must be aligned to the length,
    /// so the length shrinks until it is.
    pub fn add_watch(&mut self, addr: u64, len: usize, kind: WatchKind) -> Result<(usize, usize)> {
        let mut len = len;
        while len > 1 && addr % (len as u64) != 0 {
            len /= 2;
        }
        let Some(slot) = self.watches.iter().position(|w| w.is_none()) else {
            bail!("all 4 hardware debug registers are in use (unwatch one first)");
        };
        let last = self.read_mem(addr, len);
        if last.len() != len {
            bail!("{addr:#x} is not readable memory");
        }
        self.watches[slot] = Some(Watch { addr, len, kind, hits: 0, last, old: Vec::new() });
        if let Err(e) = self.apply_watches() {
            self.watches[slot] = None;
            let _ = self.apply_watches();
            return Err(e);
        }
        Ok((slot, len))
    }

    pub fn del_watch(&mut self, slot: usize) -> Result<bool> {
        if slot >= 4 || self.watches[slot].is_none() {
            return Ok(false);
        }
        self.watches[slot] = None;
        self.apply_watches()?;
        Ok(true)
    }

    pub fn watch_list(&self) -> Vec<(usize, u64, usize, WatchKind, u32)> {
        self.watches
            .iter()
            .enumerate()
            .filter_map(|(i, w)| w.as_ref().map(|w| (i, w.addr, w.len, w.kind, w.hits)))
            .collect()
    }

    pub fn watch_report(&self, slot: u8) -> Option<String> {
        let w = self.watches.get(slot as usize)?.as_ref()?;
        Some(format!(
            "watchpoint {}: *{:#x}  old={}  new={}  (hit {})",
            slot + 1,
            w.addr,
            fmt_val(&w.old),
            fmt_val(&w.last),
            w.hits
        ))
    }

    /// After a SIGTRAP: did a debug register fire? (DR6 low bits)
    fn check_watch(&mut self) -> Result<WatchHit> {
        if self.watches.iter().all(|w| w.is_none()) {
            return Ok(WatchHit::No);
        }
        let dr6 = self.read_dr(6)?;
        if dr6 & 0xF == 0 {
            return Ok(WatchHit::No);
        }
        self.write_dr(6, 0)?;
        for i in 0..4 {
            if dr6 & (1u64 << i) == 0 {
                continue;
            }
            let Some(w) = self.watches[i].as_ref() else { continue };
            let (addr, len, kind) = (w.addr, w.len, w.kind);
            let new = self.read_mem(addr, len);
            let w = self.watches[i].as_mut().unwrap();
            let changed = new != w.last;
            w.old = std::mem::replace(&mut w.last, new);
            w.hits += 1;
            if changed || kind == WatchKind::ReadWrite {
                return Ok(WatchHit::Report(i as u8));
            }
        }
        Ok(WatchHit::Silent)
    }

    /// Execute exactly one instruction.
    pub fn step(&mut self) -> Result<Stop> {
        ptrace::step(self.pid, self.pending_sig.take())?;
        let stop = self.wait()?;
        if stop == Stop::Trap {
            if let WatchHit::Report(slot) = self.check_watch()? {
                return Ok(Stop::Watch(slot));
            }
            return Ok(Stop::Step);
        }
        Ok(stop)
    }

    /// Step over calls (`ni`): run until the instruction after the call is reached
    /// with the stack back where it was, or until a breakpoint/watchpoint hits.
    pub fn next(&mut self) -> Result<Stop> {
        let r = self.regs()?;
        let code = self.read_mem(r.rip, 16);
        match disasm::call_return_addr(&code, r.rip) {
            Some(ret) => self.cont(Some((ret, r.rsp))),
            None => self.step(),
        }
    }

    /// Continue. Breakpoints are only written into memory while the tracee runs,
    /// so every read we do while stopped sees the original bytes.
    ///
    /// `temp` = (address, min_rsp): a one-shot stop used by `ni`. The rsp check
    /// ignores the same address being reached by a deeper (recursive) frame.
    pub fn cont(&mut self, temp: Option<(u64, u64)>) -> Result<Stop> {
        // true: first move off the current instruction, so a breakpoint at RIP isn't re-hit.
        // false: we're already sitting where we want to resume (after a silent trap).
        let mut step_off = true;
        loop {
            if step_off {
                match self.step()? {
                    Stop::Step => {}
                    other => return Ok(other),
                }
                let r = self.regs()?;
                if self.breakpoints.contains(&r.rip) {
                    return Ok(Stop::Breakpoint(r.rip));
                }
                if let Some((a, sp)) = temp {
                    if r.rip == a && r.rsp >= sp {
                        return Ok(Stop::Step);
                    }
                }
            }

            let mut addrs: Vec<u64> = self.breakpoints.iter().copied().collect();
            if let Some((a, _)) = temp {
                if !addrs.contains(&a) {
                    addrs.push(a);
                }
            }
            let saved = self.insert(&addrs)?;
            ptrace::cont(self.pid, self.pending_sig.take())?;
            let stop = self.wait()?;

            if matches!(stop, Stop::Exited(_) | Stop::Killed(_)) {
                return Ok(stop); // process is gone, nothing to restore
            }
            self.remove(&saved)?;

            if let Stop::Signal(sig) = stop {
                if is_silent(sig) {
                    step_off = false; // pass it on and keep running, like gdb's "nostop"
                    continue;
                }
                return Ok(stop);
            }
            if stop != Stop::Trap {
                return Ok(stop);
            }

            match self.check_watch()? {
                WatchHit::Report(slot) => return Ok(Stop::Watch(slot)),
                WatchHit::Silent => {
                    step_off = false;
                    continue;
                }
                WatchHit::No => {}
            }

            // SIGTRAP: was it one of our int3s? RIP is one past the 0xCC.
            let mut raw = ptrace::getregs(self.pid)?;
            let pc = raw.rip.wrapping_sub(1);
            if !saved.iter().any(|&(a, _)| a == pc) {
                return Ok(Stop::Trap); // program's own int3 / stray trap
            }
            raw.rip = pc;
            ptrace::setregs(self.pid, raw)?;

            if self.breakpoints.contains(&pc) {
                return Ok(Stop::Breakpoint(pc));
            }
            if let Some((a, sp)) = temp {
                if pc == a && raw.rsp >= sp {
                    return Ok(Stop::Step);
                }
            }
            step_off = true; // temp hit by a deeper frame: step off it and keep going
        }
    }

    pub fn maps(&self) -> String {
        std::fs::read_to_string(format!("/proc/{}/maps", self.pid.as_raw())).unwrap_or_default()
    }

    pub fn exe_path(&self) -> Option<String> {
        std::fs::read_link(format!("/proc/{}/exe", self.pid.as_raw()))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }

    fn insert(&self, addrs: &[u64]) -> Result<Vec<(u64, u8)>> {
        let mut saved = Vec::new();
        for &a in addrs {
            let mut b = [0u8; 1];
            match self.mem.read_at(&mut b, a) {
                Ok(1) => {}
                _ => continue, // unmapped (yet); skip
            }
            self.mem.write_at(&[0xCC], a)?;
            saved.push((a, b[0]));
        }
        Ok(saved)
    }

    fn remove(&self, saved: &[(u64, u8)]) -> Result<()> {
        for &(a, orig) in saved {
            self.mem.write_at(&[orig], a)?;
        }
        Ok(())
    }
}
