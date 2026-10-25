use crate::analysis::{
    disasm::{disasm, Insn},
    symbols::Symbols,
};
use crate::analysis::symbols::short;
use crate::graph::GraphView;
use crate::backend::{Cmd, Event, Found, MapEntry, Regs, Snapshot, Views};
use crate::cmd::{self, Command};
use nix::{
    sys::signal::{kill, Signal},
    unistd::Pid,
};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::{
    cell::{Cell, RefCell},
    collections::{HashMap, VecDeque},
    fs::File,
    io::Write,
    os::unix::io::AsRawFd,
    sync::{mpsc::Sender, Arc},
};

/// The six panes you move between with Tab / Shift-Tab.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    Regs,
    Main,
    Stack,
    Hex,
    Log,
    Target,
}

impl Pane {
    pub const ALL: [Pane; 6] = [Pane::Regs, Pane::Main, Pane::Stack, Pane::Hex, Pane::Log, Pane::Target];

    pub fn name(self) -> &'static str {
        match self {
            Pane::Regs => "regs",
            Pane::Main => "main",
            Pane::Stack => "stack",
            Pane::Hex => "hex",
            Pane::Log => "log",
            Pane::Target => "target",
        }
    }
}

/// Display order of the cursor in the Regs pane (two per row, rip last).
pub const REG_ORDER: [&str; 17] = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip",
];

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ViewMode {
    Graph,
    Disasm,
    Source,
    Maps,
    /// Output of the last `find` (reached by running it, not by `g`).
    Results,
}

pub struct App {
    cmd_tx: Sender<Cmd>,
    pub pid: Option<i32>,
    pub snap: Option<Snapshot>,
    /// Registers at the previous stop, for changed-register highlighting.
    pub prev: Option<Regs>,
    pub lines: Vec<Insn>,
    pub bps: Vec<u64>,
    pub views: Option<Views>,
    pub graph: Option<GraphView>,
    /// Functions entered with `o` / `graph`; the last one is shown instead of `graph`.
    pub browse: Vec<GraphView>,
    pub mode: ViewMode,
    pub maps: Arc<Vec<MapEntry>>,
    pub found: Option<Found>,
    /// Scroll position of the Maps / Results lists.
    pub list_scroll: Cell<usize>,
    /// Source files read for the source view (None = unreadable).
    pub src_cache: RefCell<HashMap<String, Option<Vec<String>>>>,
    /// Last (path, line) we stopped at inside code that has line info.
    pub last_src: Option<(String, u32)>,
    pub zoom: bool,
    /// Pty master of the target, and the terminal emulator that renders its output.
    pub pty: Option<File>,
    pub term: vt100::Parser,
    pub term_size: Cell<(u16, u16)>,
    /// Keystrokes go to the target instead of dbgt (Ctrl-] leaves).
    pub input_mode: bool,
    /// Which pane receives pane-specific keys and commands.
    pub focus: Pane,
    pub reg_sel: usize,
    pub stack_sel: usize,
    /// Lines scrolled up from the newest log line.
    pub log_scroll: usize,
    /// Source view offset from the current line.
    pub src_off: isize,
    pub hits: HashMap<u64, u32>,
    pub scroll: Cell<(usize, usize)>,
    pub view_size: Cell<(usize, usize)>,
    pub center_pending: Cell<bool>,
    pub syms: Arc<Symbols>,
    pub log: VecDeque<String>,
    pub input: String,
    pub editing: bool,
    pub busy: bool,
    pub alive: bool,
    pub quit: bool,
    pub status: String,
    last_cmd: String,
}

impl App {
    pub fn new(cmd_tx: Sender<Cmd>) -> Self {
        App {
            cmd_tx,
            pid: None,
            snap: None,
            prev: None,
            lines: Vec::new(),
            bps: Vec::new(),
            views: None,
            graph: None,
            browse: Vec::new(),
            mode: ViewMode::Graph,
            maps: Arc::new(Vec::new()),
            found: None,
            list_scroll: Cell::new(0),
            src_cache: RefCell::new(HashMap::new()),
            last_src: None,
            zoom: false,
            pty: None,
            term: vt100::Parser::new(24, 80, 0),
            term_size: Cell::new((0, 0)),
            input_mode: false,
            focus: Pane::Main,
            reg_sel: 0,
            stack_sel: 0,
            log_scroll: 0,
            src_off: 0,
            hits: HashMap::new(),
            scroll: Cell::new((0, 0)),
            view_size: Cell::new((80, 20)),
            center_pending: Cell::new(false),
            syms: Arc::new(Symbols::default()),
            log: VecDeque::new(),
            input: String::new(),
            editing: false,
            busy: false,
            alive: true,
            quit: false,
            status: "starting…".into(),
            last_cmd: String::new(),
        }
    }

    pub fn push_log(&mut self, s: impl Into<String>) {
        self.log.push_back(s.into());
        if self.log_scroll > 0 {
            self.log_scroll += 1; // keep the view where the user scrolled to
        }
        while self.log.len() > 500 {
            self.log.pop_front();
        }
        self.log_scroll = self.log_scroll.min(self.log.len().saturating_sub(1));
    }

    pub fn on_backend(&mut self, ev: Event) {
        match ev {
            Event::Started(pid) => self.pid = Some(pid),
            Event::Stopped(snap) => {
                self.prev = self.snap.as_ref().map(|s| s.regs);
                let rip = snap.regs.rip;
                self.lines = disasm(&snap.code, rip, 64);
                let mut st = format!("{} @ {:#x}", snap.stop, rip);
                if let Some((n, off)) = self.syms.lookup(rip) {
                    st.push_str(&if off == 0 { format!(" <{n}>") } else { format!(" <{n}+{off:#x}>") });
                }
                if let Some((p, l)) = self.syms.line(rip) {
                    st.push_str(&format!(" {}:{}", short(p), l));
                    self.last_src = Some((p.to_string(), l));
                }
                self.status = st;
                self.snap = Some(snap);
                self.busy = false;
                self.browse.clear(); // a real stop snaps the view back to the live function
                self.src_off = 0;
                if let Some(g) = self.graph.as_mut() {
                    if g.cfg.is_block_start(rip) {
                        *self.hits.entry(rip).or_insert(0) += 1;
                    }
                    g.sel = None;
                    g.refresh(Some(rip), &self.hits, &self.syms);
                }
                self.center_pending.set(true);
            }
            Event::Ended(stop) => {
                self.alive = false;
                self.busy = false;
                self.status = format!("{stop}");
                self.push_log(format!("process {stop}"));
            }
            Event::Views(v) => self.views = Some(v),
            Event::Cfg(c) => {
                let rip = self.snap.as_ref().map(|s| s.regs.rip);
                let mut g = GraphView::new(c, &self.syms);
                g.refresh(rip, &self.hits, &self.syms);
                self.graph = Some(g);
                self.center_pending.set(true);
            }
            Event::BrowseCfg(c) => {
                if c.blocks.is_empty() {
                    self.push_log(format!("cannot read code at {:#x} (not mapped yet?)", c.entry));
                } else if self.browse.last().map(|b| b.cfg.entry) != Some(c.entry) {
                    let rip = self.snap.as_ref().map(|s| s.regs.rip);
                    let mut g = GraphView::new(c, &self.syms);
                    g.refresh(rip, &self.hits, &self.syms);
                    self.browse.push(g);
                    self.center_pending.set(true);
                }
            }
            Event::Symbols(new_syms) => {
                self.syms = new_syms;
                // labels may have changed (and block widths with them): rebuild every view
                let rip = self.snap.as_ref().map(|s| s.regs.rip);
                let rebuild = |g: &GraphView, syms: &Symbols, hits: &HashMap<u64, u32>| {
                    let mut n = GraphView::new(g.cfg.clone(), syms);
                    n.sel = g.sel;
                    n.refresh(rip, hits, syms);
                    n
                };
                self.graph = self.graph.as_ref().map(|g| rebuild(g, &*self.syms, &self.hits));
                self.browse = self.browse.iter().map(|g| rebuild(g, &*self.syms, &self.hits)).collect();
            }
            Event::Breakpoints(v) => self.bps = v,
            Event::Log(s) => self.push_log(s),
            Event::Maps(m) => self.maps = m,
            Event::Found(f) => {
                let n = f.hits.len();
                self.push_log(format!(
                    "find {}: {} hit(s){}",
                    f.desc,
                    n,
                    if f.truncated { " (stopped at the limit)" } else { "" }
                ));
                self.found = Some(f);
                self.list_scroll.set(0);
                self.mode = ViewMode::Results;
            }
            Event::Pty(f) => self.pty = Some(f),
            Event::PtyOut(b) => self.term.process(&b),
            Event::Gone => {
                self.alive = false;
                self.busy = false;
            }
        }
    }

    pub fn send_bytes(&mut self, b: &[u8]) {
        match &self.pty {
            Some(f) => {
                let mut w: &File = f;
                let _ = w.write_all(b);
            }
            None => self.push_log("no target terminal yet"),
        }
    }

    /// Keep the emulator and the pty window size equal to the target pane.
    pub fn sync_term_size(&mut self) {
        let (r, c) = self.term_size.get();
        if r == 0 || c == 0 || self.term.screen().size() == (r, c) {
            return;
        }
        self.term.set_size(r, c);
        if let Some(f) = &self.pty {
            let ws = nix::libc::winsize { ws_row: r, ws_col: c, ws_xpixel: 0, ws_ypixel: 0 };
            unsafe {
                nix::libc::ioctl(f.as_raw_fd(), nix::libc::TIOCSWINSZ as _, &ws);
            }
        }
    }

    pub fn on_key(&mut self, k: KeyEvent) {
        if self.input_mode {
            if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char(']') {
                self.input_mode = false;
            } else if let Some(bytes) = key_bytes(&k) {
                self.send_bytes(&bytes);
            }
            return;
        }
        if k.modifiers.contains(KeyModifiers::CONTROL) {
            if k.code == KeyCode::Char('c') {
                if self.busy {
                    self.interrupt();
                } else {
                    self.quit = true;
                }
            }
            return;
        }

        if self.editing {
            match k.code {
                KeyCode::Esc => {
                    self.editing = false;
                    self.input.clear();
                }
                KeyCode::Enter => {
                    let line = std::mem::take(&mut self.input);
                    self.editing = false;
                    self.run_command(&line);
                }
                KeyCode::Backspace => {
                    self.input.pop();
                }
                KeyCode::Char(c) => self.input.push(c),
                _ => {}
            }
            return;
        }

        // ---- keys that work in every pane ----
        match k.code {
            KeyCode::Tab => return self.focus_next(1),
            KeyCode::BackTab => return self.focus_next(-1),
            KeyCode::Char(':') => {
                self.editing = true;
                return;
            }
            KeyCode::Char('q') => {
                self.quit = true;
                return;
            }
            KeyCode::Char('f') => {
                self.zoom = !self.zoom;
                self.center_pending.set(true);
                return;
            }
            KeyCode::Char('?') => {
                for l in cmd::HELP {
                    self.push_log(*l);
                }
                return;
            }
            KeyCode::Char('s') | KeyCode::F(7) => return self.resume(Cmd::Step),
            KeyCode::Char('n') | KeyCode::F(8) => return self.resume(Cmd::Next),
            KeyCode::Char('c') | KeyCode::F(5) => return self.resume(Cmd::Continue),
            _ => {}
        }

        // ---- keys of the focused pane ----
        match self.focus {
            Pane::Main => self.key_main(k),
            Pane::Regs => self.key_regs(k),
            Pane::Stack => self.key_stack(k),
            Pane::Hex => self.key_hex(k),
            Pane::Log => self.key_log(k),
            Pane::Target => self.key_target(k),
        }
    }

    fn focus_next(&mut self, dir: isize) {
        let i = Pane::ALL.iter().position(|p| *p == self.focus).unwrap_or(0) as isize;
        let n = Pane::ALL.len() as isize;
        self.focus = Pane::ALL[(i + dir).rem_euclid(n) as usize];
        self.center_pending.set(true);
    }

    pub fn prompt(&self) -> String {
        format!("{}> ", self.focus.name())
    }

    /// Key hints for the focused pane (shown on the bottom bar).
    pub fn pane_hint(&self) -> &'static str {
        match self.focus {
            Pane::Main => match self.mode {
                ViewMode::Graph => "graph: [ ] select call | o follow | u back | Esc live | hjkl scroll | z centre | g or 1-4 view",
                ViewMode::Disasm => "code: g or 1-4 switch view",
                ViewMode::Source => "source: j/k scroll | z back to current line | g or 1-4 switch view",
                ViewMode::Maps | ViewMode::Results => "list: j/k scroll | g or 1-4 switch view",
            },
            Pane::Regs => "regs: hjkl move | Enter hexdump value | v code | p stack | e edit | :set $rax 5",
            Pane::Stack => "stack: j/k select | Enter deref to hexdump | a slot address | v code | e patch | PgUp/PgDn | Home = rsp",
            Pane::Hex => "hexdump: j/k PgUp/PgDn scroll | Enter follow pointer | e write | Home = rsp | :goto :write",
            Pane::Log => "log: j/k PgUp/PgDn scroll | G newest | :clear",
            Pane::Target => "target: Enter or i = type into the program (Ctrl-] leaves) | :send :sendline :clear",
        }
    }

    fn reg_value(&self, name: &str) -> Option<u64> {
        self.snap.as_ref().and_then(|s| s.regs.get(name))
    }

    /// Show the code at `addr` in the main pane's graph.
    fn open_code(&mut self, addr: u64) {
        let dest = self.resolve_callee(addr);
        let _ = self.cmd_tx.send(Cmd::Cfg(dest));
        self.focus = Pane::Main;
        self.mode = ViewMode::Graph;
    }

    fn goto_hex(&mut self, addr: Option<u64>) {
        let _ = self.cmd_tx.send(Cmd::Hex(addr));
    }

    fn set_mode(&mut self, m: ViewMode) {
        if m == ViewMode::Source && !self.syms.has_lines() {
            self.push_log("no DWARF line info: compile the target with -g");
            return;
        }
        self.mode = m;
        self.list_scroll.set(0);
        self.center_pending.set(true);
    }

    fn key_main(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Char('g') => {
                let next = match self.mode {
                    ViewMode::Graph => ViewMode::Disasm,
                    ViewMode::Disasm if self.syms.has_lines() => ViewMode::Source,
                    ViewMode::Disasm | ViewMode::Source => ViewMode::Maps,
                    ViewMode::Maps | ViewMode::Results => ViewMode::Graph,
                };
                self.set_mode(next);
            }
            KeyCode::Char('1') => self.set_mode(ViewMode::Graph),
            KeyCode::Char('2') => self.set_mode(ViewMode::Disasm),
            KeyCode::Char('3') => self.set_mode(ViewMode::Source),
            KeyCode::Char('4') => self.set_mode(ViewMode::Maps),
            KeyCode::Char('z') => {
                self.src_off = 0;
                self.center_pending.set(true);
            }
            KeyCode::Char(']') => self.select_call(1),
            KeyCode::Char('[') => self.select_call(-1),
            KeyCode::Char('o') => self.follow_call(),
            KeyCode::Char('u') | KeyCode::Backspace => self.browse_back(),
            KeyCode::Esc => {
                self.browse.clear();
                self.center_pending.set(true);
            }
            KeyCode::Left | KeyCode::Char('h') => self.scroll_by(-8, 0),
            KeyCode::Right | KeyCode::Char('l') => self.scroll_by(8, 0),
            KeyCode::Up | KeyCode::Char('k') => self.scroll_by(0, -4),
            KeyCode::Down | KeyCode::Char('j') => self.scroll_by(0, 4),
            KeyCode::PageUp => self.scroll_by(0, -12),
            KeyCode::PageDown => self.scroll_by(0, 12),
            KeyCode::Enter => self.run_command(""),
            _ => {}
        }
    }

    fn key_regs(&mut self, k: KeyEvent) {
        let last = REG_ORDER.len() - 1;
        let name = REG_ORDER[self.reg_sel.min(last)];
        let val = self.reg_value(name);
        match k.code {
            KeyCode::Left | KeyCode::Char('h') => self.reg_sel = self.reg_sel.saturating_sub(1),
            KeyCode::Right | KeyCode::Char('l') => self.reg_sel = (self.reg_sel + 1).min(last),
            KeyCode::Up | KeyCode::Char('k') => self.reg_sel = self.reg_sel.saturating_sub(2),
            KeyCode::Down | KeyCode::Char('j') => self.reg_sel = (self.reg_sel + 2).min(last),
            KeyCode::Enter => {
                if let Some(v) = val {
                    self.goto_hex(Some(v));
                    self.focus = Pane::Hex;
                }
            }
            KeyCode::Char('v') => {
                if let Some(v) = val {
                    self.open_code(v);
                }
            }
            KeyCode::Char('p') => {
                if let Some(v) = val {
                    let _ = self.cmd_tx.send(Cmd::Stack(Some(v)));
                    self.stack_sel = 0;
                    self.focus = Pane::Stack;
                }
            }
            KeyCode::Char('e') => {
                self.editing = true;
                self.input = format!("set ${name} ");
            }
            _ => {}
        }
    }

    fn key_stack(&mut self, k: KeyEvent) {
        let n = self.views.as_ref().map_or(0, |v| v.stack.len());
        let row = self.views.as_ref().and_then(|v| v.stack.get(self.stack_sel)).map(|r| (r.addr, r.val));
        let base = self.views.as_ref().and_then(|v| v.stack.first()).map(|r| r.addr);
        match k.code {
            KeyCode::Up | KeyCode::Char('k') => self.stack_sel = self.stack_sel.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => self.stack_sel = (self.stack_sel + 1).min(n.saturating_sub(1)),
            KeyCode::PageUp => {
                if let Some(b) = base {
                    let _ = self.cmd_tx.send(Cmd::Stack(Some(b.wrapping_sub(0x40))));
                }
            }
            KeyCode::PageDown => {
                if let Some(b) = base {
                    let _ = self.cmd_tx.send(Cmd::Stack(Some(b.wrapping_add(0x40))));
                }
            }
            KeyCode::Home => {
                self.stack_sel = 0;
                let _ = self.cmd_tx.send(Cmd::Stack(None));
            }
            KeyCode::Enter => {
                if let Some((_, val)) = row {
                    self.goto_hex(Some(val));
                    self.focus = Pane::Hex;
                }
            }
            KeyCode::Char('a') => {
                if let Some((addr, _)) = row {
                    self.goto_hex(Some(addr));
                    self.focus = Pane::Hex;
                }
            }
            KeyCode::Char('v') => {
                if let Some((_, val)) = row {
                    self.open_code(val);
                }
            }
            KeyCode::Char('e') => {
                if let Some((addr, _)) = row {
                    self.editing = true;
                    self.input = format!("write {addr:#x} ");
                }
            }
            _ => {}
        }
    }

    fn key_hex(&mut self, k: KeyEvent) {
        let base = self.views.as_ref().map(|v| v.hex_addr);
        let first = self
            .views
            .as_ref()
            .and_then(|v| v.hex.get(..8))
            .and_then(|b| <[u8; 8]>::try_from(b).ok())
            .map(u64::from_le_bytes);
        match k.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if let Some(b) = base {
                    self.goto_hex(Some(b.wrapping_sub(8)));
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(b) = base {
                    self.goto_hex(Some(b.wrapping_add(8)));
                }
            }
            KeyCode::PageUp => {
                if let Some(b) = base {
                    self.goto_hex(Some(b.wrapping_sub(64)));
                }
            }
            KeyCode::PageDown => {
                if let Some(b) = base {
                    self.goto_hex(Some(b.wrapping_add(64)));
                }
            }
            KeyCode::Home => self.goto_hex(None),
            KeyCode::Enter => {
                if let Some(p) = first {
                    self.goto_hex(Some(p));
                }
            }
            KeyCode::Char('e') => {
                if let Some(b) = base {
                    self.editing = true;
                    self.input = format!("write {b:#x} ");
                }
            }
            _ => {}
        }
    }

    fn key_log(&mut self, k: KeyEvent) {
        let max = self.log.len().saturating_sub(1);
        match k.code {
            KeyCode::Up | KeyCode::Char('k') => self.log_scroll = (self.log_scroll + 1).min(max),
            KeyCode::Down | KeyCode::Char('j') => self.log_scroll = self.log_scroll.saturating_sub(1),
            KeyCode::PageUp => self.log_scroll = (self.log_scroll + 5).min(max),
            KeyCode::PageDown => self.log_scroll = self.log_scroll.saturating_sub(5),
            KeyCode::Home => self.log_scroll = max,
            KeyCode::End | KeyCode::Char('G') => self.log_scroll = 0,
            KeyCode::Enter => self.run_command(""),
            _ => {}
        }
    }

    fn key_target(&mut self, k: KeyEvent) {
        if matches!(k.code, KeyCode::Enter | KeyCode::Char('i') | KeyCode::Char('t')) {
            self.input_mode = true;
        }
    }

    /// Commands whose meaning depends on the focused pane (goto, follow, clear) and the
    /// register / memory editors. Returns true if the line was handled.
    fn pane_command(&mut self, line: &str) -> bool {
        let line = line.trim();
        let (head, rest) = match line.split_once(char::is_whitespace) {
            Some((h, r)) => (h, r.trim()),
            None => (line, ""),
        };
        let regs = self.snap.as_ref().map(|s| s.regs);
        let syms = self.syms.clone();

        match head {
            "goto" | "go" => {
                if rest.is_empty() {
                    self.push_log("usage: goto <expr>");
                    return true;
                }
                let a = match cmd::eval(rest, regs.as_ref(), &syms) {
                    Ok(a) => a,
                    Err(m) => {
                        self.push_log(m);
                        return true;
                    }
                };
                match self.focus {
                    Pane::Main => self.open_code(a),
                    Pane::Stack => {
                        self.stack_sel = 0;
                        let _ = self.cmd_tx.send(Cmd::Stack(Some(a)));
                    }
                    Pane::Hex => self.goto_hex(Some(a)),
                    Pane::Regs => self.push_log("goto: in the Regs pane use 'follow <reg>' or 'set $reg <expr>'"),
                    Pane::Log | Pane::Target => self.push_log("goto has no meaning in this pane"),
                }
                true
            }
            "follow" => {
                match self.focus {
                    Pane::Regs => {
                        let name = if rest.is_empty() { REG_ORDER[self.reg_sel.min(16)] } else { rest.trim_start_matches('$') };
                        match regs.and_then(|r| r.get(name)) {
                            Some(v) => {
                                self.goto_hex(Some(v));
                                self.focus = Pane::Hex;
                            }
                            None => self.push_log(format!("unknown register: {name}")),
                        }
                    }
                    Pane::Stack => {
                        let idx = rest.parse::<usize>().unwrap_or(self.stack_sel);
                        match self.views.as_ref().and_then(|v| v.stack.get(idx)).map(|r| r.val) {
                            Some(v) => {
                                self.goto_hex(Some(v));
                                self.focus = Pane::Hex;
                            }
                            None => self.push_log("follow: no such stack slot"),
                        }
                    }
                    Pane::Hex => {
                        let first = self
                            .views
                            .as_ref()
                            .and_then(|v| v.hex.get(..8))
                            .and_then(|b| <[u8; 8]>::try_from(b).ok())
                            .map(u64::from_le_bytes);
                        match first {
                            Some(p) => self.goto_hex(Some(p)),
                            None => self.push_log("follow: nothing readable at the hexdump address"),
                        }
                    }
                    _ => self.push_log("follow: use it in the Regs, Stack or Hex pane"),
                }
                true
            }
            "clear" => {
                match self.focus {
                    Pane::Log => {
                        self.log.clear();
                        self.log_scroll = 0;
                    }
                    Pane::Target => {
                        let (r, c) = self.term.screen().size();
                        self.term = vt100::Parser::new(r, c, 0);
                    }
                    _ => self.push_log("clear: focus the Log or Target pane first"),
                }
                true
            }
            "set" => {
                self.cmd_set(rest);
                true
            }
            "write" | "patch" => {
                self.cmd_write(rest);
                true
            }
            name if self.focus == Pane::Regs
                && !rest.is_empty()
                && regs.map_or(false, |r| r.get(name.trim_start_matches('$')).is_some()) =>
            {
                // In the Regs pane, `rax 0x41` is shorthand for `set $rax 0x41`.
                self.cmd_set(&format!("{name} {rest}"));
                true
            }
            _ => false,
        }
    }

    /// `set $rax 0x41`, `set rax = main+4`
    fn cmd_set(&mut self, rest: &str) {
        let norm = rest.replacen('=', " ", 1);
        let Some((r, e)) = norm.trim().split_once(char::is_whitespace) else {
            self.push_log("usage: set $reg <expr>   e.g. set $rax 0x41, set $rip main+4");
            return;
        };
        let name = r.trim_start_matches('$').to_string();
        let regs = self.snap.as_ref().map(|s| s.regs);
        let syms = self.syms.clone();
        if regs.map_or(true, |rg| rg.get(&name).is_none()) {
            self.push_log(format!("unknown register: {name}"));
            return;
        }
        match cmd::eval(e.trim(), regs.as_ref(), &syms) {
            Ok(value) => {
                let _ = self.cmd_tx.send(Cmd::SetReg { name, value });
            }
            Err(m) => self.push_log(m),
        }
    }

    /// `write <addr> <bytes>`; the address expression must not contain spaces.
    fn cmd_write(&mut self, rest: &str) {
        let Some((a, b)) = rest.split_once(char::is_whitespace) else {
            self.push_log("usage: write <addr> <bytes>   e.g. write $rsp 41424344 | write buf \"hi\\n\" | write main \\x90\\x90");
            return;
        };
        let regs = self.snap.as_ref().map(|s| s.regs);
        let syms = self.syms.clone();
        let addr = match cmd::eval(a, regs.as_ref(), &syms) {
            Ok(v) => v,
            Err(m) => {
                self.push_log(m);
                return;
            }
        };
        match cmd::parse_bytes(b) {
            Ok(bytes) if !bytes.is_empty() && bytes.len() <= 4096 => {
                let _ = self.cmd_tx.send(Cmd::WriteMem { addr, bytes });
            }
            Ok(_) => self.push_log("write: 1 to 4096 bytes"),
            Err(m) => self.push_log(m),
        }
    }

    /// The graph on screen: the last followed function, else the live one.
    pub fn shown(&self) -> Option<&GraphView> {
        self.browse.last().or(self.graph.as_ref())
    }

    pub fn crumb(&self) -> String {
        let mut v: Vec<String> = Vec::new();
        if let Some(g) = &self.graph {
            v.push(g.name(&self.syms));
        }
        for b in &self.browse {
            v.push(b.name(&self.syms));
        }
        v.join(" → ")
    }

    fn refresh_shown(&mut self) {
        let rip = self.snap.as_ref().map(|s| s.regs.rip);
        let (hits, syms) = (&self.hits, &self.syms);
        let g = match self.browse.last_mut() {
            Some(g) => Some(g),
            None => self.graph.as_mut(),
        };
        if let Some(g) = g {
            g.refresh(rip, hits, syms);
        }
    }

    fn select_call(&mut self, dir: isize) {
        let g = match self.browse.last_mut() {
            Some(g) => Some(g),
            None => self.graph.as_mut(),
        };
        match g {
            Some(g) if !g.calls.is_empty() => g.select(dir),
            _ => {
                self.push_log("no direct calls in this function");
                return;
            }
        }
        self.refresh_shown();
        self.center_pending.set(true);
    }

    /// `call puts@plt` -> the real `puts` once libc is loaded.
    fn resolve_callee(&self, target: u64) -> u64 {
        if let Some((n, 0)) = self.syms.lookup(target) {
            if let Some(real) = n.strip_suffix("@plt").and_then(|b| self.syms.addr(b)) {
                return real;
            }
        }
        target
    }

    fn follow_call(&mut self) {
        let rip = self.snap.as_ref().map(|s| s.regs.rip);
        let target = self
            .shown()
            .and_then(|g| g.selected().or_else(|| rip.and_then(|r| g.call_at(r))))
            .map(|c| c.1);
        let Some(t) = target else {
            self.push_log("no call selected: press ] to select one (in the Main pane), then o to follow");
            return;
        };
        let dest = self.resolve_callee(t);
        let name = match self.syms.lookup(dest) {
            Some((n, 0)) => format!(" <{n}>"),
            Some((n, off)) => format!(" <{n}+{off:#x}>"),
            None => String::new(),
        };
        self.push_log(format!("following call to {dest:#x}{name}"));
        let _ = self.cmd_tx.send(Cmd::Cfg(dest));
    }

    fn browse_back(&mut self) {
        if self.browse.pop().is_some() {
            self.refresh_shown();
            self.center_pending.set(true);
        }
    }

    /// Where the source view should look: the line at RIP, else the last known one.
    pub fn src_loc(&self) -> Option<(String, u32, bool)> {
        let rip = self.snap.as_ref()?.regs.rip;
        if let Some((p, l)) = self.syms.line(rip) {
            return Some((p.to_string(), l, true));
        }
        self.last_src.clone().map(|(p, l)| (p, l, false))
    }

    pub fn center(&self) {
        self.center_pending.set(false);
        let Some(g) = self.shown() else { return };
        let Some((cx, cy)) = g.focus_pos else { return };
        let (vw, vh) = self.view_size.get();
        self.scroll.set((cx.saturating_sub(vw / 2), cy.saturating_sub(vh / 2)));
    }

    fn scroll_by(&mut self, dx: isize, dy: isize) {
        if self.mode == ViewMode::Source {
            self.src_off += dy.signum() * 3;
            return;
        }
        if matches!(self.mode, ViewMode::Maps | ViewMode::Results) {
            let n = if self.mode == ViewMode::Maps {
                self.maps.len()
            } else {
                self.found.as_ref().map_or(0, |f| f.hits.len())
            };
            let y = self.list_scroll.get() as isize + dy.signum() * 3;
            self.list_scroll.set(y.clamp(0, n.saturating_sub(1) as isize) as usize);
            return;
        }
        self.center_pending.set(false);
        let (w, h) = self.shown().map(|g| (g.width(), g.height())).unwrap_or((0, 0));
        let (x, y) = self.scroll.get();
        let nx = (x as isize + dx).clamp(0, w.saturating_sub(1) as isize) as usize;
        let ny = (y as isize + dy).clamp(0, h.saturating_sub(1) as isize) as usize;
        self.scroll.set((nx, ny));
    }

    fn interrupt(&mut self) {
        if let Some(pid) = self.pid {
            let _ = kill(Pid::from_raw(pid), Signal::SIGSTOP);
            self.push_log("interrupting…");
        }
    }

    fn resume(&mut self, c: Cmd) {
        if !self.alive {
            self.push_log("process is not running");
        } else if self.busy {
            self.push_log("target is running (Ctrl-C to interrupt)");
        } else {
            self.busy = true;
            self.status = "running…".into();
            let _ = self.cmd_tx.send(c);
        }
    }

    fn run_command(&mut self, line: &str) {
        let line = if line.trim().is_empty() {
            self.last_cmd.clone()
        } else {
            self.last_cmd = line.to_string();
            line.to_string()
        };
        if line.is_empty() {
            return;
        }

        if self.pane_command(&line) {
            return;
        }

        let regs = self.snap.as_ref().map(|s| s.regs);
        let syms = self.syms.clone();
        let ev = |e: &str| cmd::eval(e, regs.as_ref(), &syms);

        match cmd::parse(&line) {
            Ok(Command::Step) => self.resume(Cmd::Step),
            Ok(Command::Next) => self.resume(Cmd::Next),
            Ok(Command::Continue) => self.resume(Cmd::Continue),
            Ok(Command::Start) => {
                let target = syms.addr("main").unwrap_or(syms.entry);
                if target == 0 {
                    self.push_log("no symbols or entry point found");
                } else {
                    let _ = self.cmd_tx.send(Cmd::Break(target));
                    self.resume(Cmd::Continue);
                }
            }
            Ok(Command::Break(e)) => match ev(&e) {
                Ok(a) => {
                    let _ = self.cmd_tx.send(Cmd::Break(a));
                }
                Err(m) => self.push_log(m),
            },
            Ok(Command::Delete(e)) => match ev(&e) {
                Ok(a) => {
                    let _ = self.cmd_tx.send(Cmd::Delete(a));
                }
                Err(m) => self.push_log(m),
            },
            Ok(Command::Hex(e)) => match e.map(|e| ev(&e)).transpose() {
                Ok(a) => {
                    let _ = self.cmd_tx.send(Cmd::Hex(a));
                }
                Err(m) => self.push_log(m),
            },
            Ok(Command::Stack(e)) => match e.map(|e| ev(&e)).transpose() {
                Ok(a) => {
                    let _ = self.cmd_tx.send(Cmd::Stack(a));
                }
                Err(m) => self.push_log(m),
            },
            Ok(Command::Graph(e)) => match ev(&e) {
                Ok(a) => {
                    let dest = self.resolve_callee(a);
                    let _ = self.cmd_tx.send(Cmd::Cfg(dest));
                }
                Err(m) => self.push_log(m),
            },
            Ok(Command::Send(text, nl)) => match cmd::unescape(&text) {
                Ok(mut b) => {
                    if nl {
                        b.push(b'\n');
                    }
                    self.send_bytes(&b);
                }
                Err(m) => self.push_log(m),
            },
            Ok(Command::Watch(e, len, kind)) => match ev(&e) {
                Ok(addr) => {
                    // watching a named global: use its size when known, else 8 bytes
                    let len = len.or_else(|| syms.data_size(e.trim())).unwrap_or(8);
                    let _ = self.cmd_tx.send(Cmd::Watch { addr, len, kind });
                }
                Err(m) => self.push_log(m),
            },
            Ok(Command::Watches) => {
                let _ = self.cmd_tx.send(Cmd::Watches);
            }
            Ok(Command::Unwatch(n)) => {
                let _ = self.cmd_tx.send(Cmd::Unwatch(n));
            }
            Ok(Command::Modules) => {
                let lines: Vec<String> = syms
                    .mods
                    .iter()
                    .map(|m| format!("{:#014x}  {}  ({} symbols, {} line rows)", m.base, m.name, m.count, m.lines))
                    .collect();
                for l in lines {
                    self.push_log(l);
                }
            }
            Ok(Command::Sym(e)) => match ev(&e) {
                Ok(a) => match syms.lookup(a) {
                    Some((n, 0)) => self.push_log(format!("{a:#x} = <{n}>")),
                    Some((n, off)) => self.push_log(format!("{a:#x} = <{n}+{off:#x}>")),
                    None => self.push_log(format!("{a:#x}: no symbol")),
                },
                Err(m) => self.push_log(m),
            },
            Ok(Command::Maps(None)) => {
                self.mode = ViewMode::Maps;
                self.list_scroll.set(0);
            }
            Ok(Command::Maps(Some(word))) => {
                let lines: Vec<String> = self
                    .maps
                    .iter()
                    .filter(|m| m.path.contains(&word))
                    .map(|m| format!("{:#014x}-{:#014x} {} {:#9x} {}", m.start, m.end, m.perms, m.end - m.start, m.path))
                    .collect();
                if lines.is_empty() {
                    self.push_log(format!("no mapping matches '{word}'"));
                }
                for l in lines {
                    self.push_log(l);
                }
            }
            Ok(Command::Checksec) => {
                let _ = self.cmd_tx.send(Cmd::Checksec);
            }
            Ok(Command::Find(rest)) => match cmd::parse_find(&rest, regs.as_ref(), &syms) {
                Ok((pat, filter, desc)) => {
                    self.push_log(format!("searching for {desc} ..."));
                    let _ = self.cmd_tx.send(Cmd::Find { pat, filter, desc });
                }
                Err(m) => self.push_log(m),
            },
            Ok(Command::Quit) => self.quit = true,
            Ok(Command::Help) => {
                for l in cmd::HELP {
                    self.push_log(*l);
                }
            }
            Err(m) => self.push_log(m),
        }
    }
}

/// Translate a key press into the bytes a terminal would send.
fn key_bytes(k: &KeyEvent) -> Option<Vec<u8>> {
    let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
    let alt = k.modifiers.contains(KeyModifiers::ALT);
    let mut v: Vec<u8> = match k.code {
        KeyCode::Char(c) if ctrl && c.is_ascii() => vec![(c.to_ascii_lowercase() as u8) & 0x1f],
        KeyCode::Char(c) => c.to_string().into_bytes(),
        KeyCode::Enter => vec![b'\r'],
        KeyCode::Tab => vec![b'\t'],
        KeyCode::BackTab => b"\x1b[Z".to_vec(),
        KeyCode::Backspace => vec![0x7f],
        KeyCode::Esc => vec![0x1b],
        KeyCode::Up => b"\x1b[A".to_vec(),
        KeyCode::Down => b"\x1b[B".to_vec(),
        KeyCode::Right => b"\x1b[C".to_vec(),
        KeyCode::Left => b"\x1b[D".to_vec(),
        KeyCode::Home => b"\x1b[H".to_vec(),
        KeyCode::End => b"\x1b[F".to_vec(),
        KeyCode::Delete => b"\x1b[3~".to_vec(),
        KeyCode::PageUp => b"\x1b[5~".to_vec(),
        KeyCode::PageDown => b"\x1b[6~".to_vec(),
        _ => return None,
    };
    if alt {
        v.insert(0, 0x1b);
    }
    Some(v)
}
