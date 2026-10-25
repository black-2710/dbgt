//! r2-style graph view: rasterises the laid-out CFG into a grid of styled cells.

use crate::analysis::{
    cfg::{Block, Cfg, EdgeKind},
    disasm::Insn,
    layout::{self, Layout, Placed},
    symbols::{short, Symbols},
};
use ratatui::style::{Color, Modifier, Style};
use std::{collections::HashMap, sync::Arc};

#[derive(Clone, Copy)]
pub struct Cell {
    pub ch: char,
    pub style: Style,
}

type Pieces = Vec<(String, Style)>;

pub struct GraphView {
    pub cfg: Arc<Cfg>,
    lay: Layout,
    pub canvas: Vec<Vec<Cell>>,
    /// (x centre of the current block, row of the current instruction)
    pub cur_pos: Option<(usize, usize)>,
    /// Where the viewport should centre: selected call, else RIP, else the entry block.
    pub focus_pos: Option<(usize, usize)>,
    /// Every `call <direct target>` in the function: (instruction address, target).
    pub calls: Vec<(u64, u64)>,
    /// Index into `calls` of the call selected with Tab.
    pub sel: Option<usize>,
}

fn edge_color(k: EdgeKind) -> Color {
    match k {
        EdgeKind::False => Color::Red,
        EdgeKind::True => Color::Green,
        EdgeKind::Jump => Color::Blue,
    }
}

fn mnemonic_style(text: &str) -> Style {
    let mut words = text.split_whitespace();
    let mut mn = words.next().unwrap_or("");
    if matches!(mn, "rep" | "repe" | "repne" | "lock" | "bnd" | "notrack") {
        mn = words.next().unwrap_or(mn);
    }
    let c = if mn == "call" {
        Color::Green
    } else if matches!(mn, "ret" | "retn" | "leave" | "hlt" | "ud2" | "int3") {
        Color::Red
    } else if mn.starts_with('j') {
        Color::Yellow
    } else if matches!(mn, "push" | "pop") {
        Color::Magenta
    } else if mn.starts_with("mov") || mn.starts_with("lea") || mn.starts_with("cmov") {
        Color::LightBlue
    } else if mn.starts_with("cmp") || mn.starts_with("test") {
        Color::Cyan
    } else if mn.starts_with("nop") || mn.starts_with("endbr") {
        Color::DarkGray
    } else {
        Color::LightYellow
    };
    Style::new().fg(c)
}

/// ` ; puts@plt` after `call 0x401030` (and after jumps to a symbol start).
fn branch_note(text: &str, syms: &Symbols) -> Option<String> {
    let first = text.split_whitespace().next()?;
    if first != "call" && !first.starts_with('j') {
        return None;
    }
    let tok = text.split_whitespace().last()?;
    let addr = u64::from_str_radix(tok.strip_prefix("0x")?, 16).ok()?;
    let (n, off) = syms.lookup(addr)?;
    if off == 0 {
        Some(format!(" ; {n}"))
    } else if first == "call" {
        Some(format!(" ; {n}+{off:#x}"))
    } else {
        None
    }
}

/// For each instruction: does a new source line start here? (shown as `; main.c:12`)
fn src_flags(b: &Block, syms: &Symbols) -> Vec<bool> {
    let mut prev: Option<(&str, u32)> = None;
    b.insns
        .iter()
        .map(|i| {
            let cur = syms.line(i.addr);
            let show = cur.is_some() && cur != prev;
            if cur.is_some() {
                prev = cur;
            }
            show
        })
        .collect()
}

fn insn_pieces(ins: &Insn, syms: &Symbols, src: bool) -> Pieces {
    let hex: String = ins.bytes.iter().map(|b| format!("{b:02x}")).collect();
    let hex = if hex.len() > 12 { format!("{}..", &hex[..10]) } else { hex };
    let (mn, rest) = match ins.text.split_once(' ') {
        Some((m, r)) => (m.to_string(), format!(" {r}")),
        None => (ins.text.clone(), String::new()),
    };
    let mut v = vec![
        (format!("{:#010x}", ins.addr), Style::new().fg(Color::Green)),
        (format!(" {hex:<12} "), Style::new().fg(Color::Yellow)),
        (mn, mnemonic_style(&ins.text)),
        (rest, Style::new().fg(Color::White)),
    ];
    if let Some(note) = branch_note(&ins.text, syms) {
        v.push((note, Style::new().fg(Color::Green)));
    }
    if src {
        if let Some((p, l)) = syms.line(ins.addr) {
            v.push((format!("  ; {}:{}", short(p), l), Style::new().fg(Color::Cyan)));
        }
    }
    v
}

fn header_pieces(b: &Block, syms: &Symbols) -> Pieces {
    let mut v = vec![(
        format!("[{:#010x}]", b.start),
        Style::new().fg(Color::White).add_modifier(Modifier::BOLD),
    )];
    if let Some((n, off)) = syms.lookup(b.start) {
        let t = if off == 0 { format!(" <{n}>") } else { format!(" <{n}+{off:#x}>") };
        v.push((t, Style::new().fg(Color::Green)));
    }
    if b.unresolved {
        v.push((" (indirect jmp)".into(), Style::new().fg(Color::DarkGray)));
    }
    v
}

fn width_of(p: &Pieces) -> usize {
    p.iter().map(|(s, _)| s.chars().count()).sum()
}

fn block_size(b: &Block, syms: &Symbols) -> (usize, usize) {
    let hdr = width_of(&header_pieces(b, syms)) + 9; // room for "hit xNNN"
    let flags = src_flags(b, syms);
    let body = b
        .insns
        .iter()
        .zip(flags)
        .map(|(i, f)| width_of(&insn_pieces(i, syms, f)))
        .max()
        .unwrap_or(0);
    let inner = hdr.max(body).clamp(24, 76);
    (inner + 4, b.insns.len() + 3)
}

fn put(cv: &mut [Vec<Cell>], x: usize, y: usize, ch: char, style: Style) {
    if let Some(row) = cv.get_mut(y) {
        if let Some(c) = row.get_mut(x) {
            *c = Cell { ch, style };
        }
    }
}

fn write_pieces(cv: &mut [Vec<Cell>], x: usize, y: usize, pieces: &Pieces, max: usize) {
    let limit = x + max;
    let mut cx = x;
    for (s, st) in pieces {
        for ch in s.chars() {
            if cx >= limit {
                return;
            }
            put(cv, cx, y, ch, *st);
            cx += 1;
        }
    }
}

/// Draws one block; returns the canvas row of `rip` if it's inside this block.
fn draw_block(
    cv: &mut Vec<Vec<Cell>>,
    p: &Placed,
    b: &Block,
    is_cur: bool,
    rip: Option<u64>,
    sel: Option<u64>,
    hits: u32,
    syms: &Symbols,
) -> (Option<usize>, Option<usize>) {
    let bs = if is_cur {
        Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD)
    } else {
        Style::new().fg(Color::White)
    };
    let (x, y, w, h) = (p.x, p.y, p.w, p.h);
    let inner = w - 4;

    put(cv, x, y, '┌', bs);
    for i in 1..w - 1 {
        put(cv, x + i, y, '─', bs);
    }
    put(cv, x + w - 1, y, '┐', bs);

    let mut rip_row = None;
    let mut sel_row = None;
    let flags = src_flags(b, syms);
    for r in 1..h - 1 {
        put(cv, x, y + r, '│', bs);
        put(cv, x + w - 1, y + r, '│', bs);
        for i in 1..w - 1 {
            put(cv, x + i, y + r, ' ', Style::new());
        }
        if r == 1 {
            write_pieces(cv, x + 2, y + r, &header_pieces(b, syms), inner);
            if hits > 0 {
                let s = format!("hit x{hits}");
                let sx = x + 2 + inner - s.chars().count();
                write_pieces(cv, sx, y + r, &vec![(s, Style::new().fg(Color::DarkGray))], inner);
            }
        } else {
            let ins = &b.insns[r - 2];
            write_pieces(cv, x + 2, y + r, &insn_pieces(ins, syms, flags[r - 2]), inner);
            let is_rip = Some(ins.addr) == rip;
            let is_sel = Some(ins.addr) == sel;
            if is_rip {
                rip_row = Some(y + r);
            }
            if is_sel {
                sel_row = Some(y + r);
            }
            if is_rip || is_sel {
                let bg = if is_sel { Color::Blue } else { Color::DarkGray };
                for i in 1..w - 1 {
                    if let Some(c) = cv.get_mut(y + r).and_then(|row| row.get_mut(x + i)) {
                        c.style = c.style.bg(bg);
                    }
                }
            }
        }
    }

    put(cv, x, y + h - 1, '└', bs);
    for i in 1..w - 1 {
        put(cv, x + i, y + h - 1, '─', bs);
    }
    put(cv, x + w - 1, y + h - 1, '┘', bs);
    (rip_row, sel_row)
}

impl GraphView {
    pub fn new(cfg: Arc<Cfg>, syms: &Symbols) -> Self {
        let nodes: Vec<(u64, usize, usize)> = cfg
            .blocks
            .iter()
            .map(|b| {
                let (w, h) = block_size(b, syms);
                (b.start, w, h)
            })
            .collect();
        let edges: Vec<(u64, u64, EdgeKind)> = cfg
            .blocks
            .iter()
            .flat_map(|b| b.succ.iter().map(move |&(t, k)| (b.start, t, k)))
            .collect();
        let lay = layout::layout(&nodes, &edges, cfg.entry);
        let calls: Vec<(u64, u64)> = cfg
            .blocks
            .iter()
            .flat_map(|b| b.insns.iter().filter_map(|i| i.call_target().map(|t| (i.addr, t))))
            .collect();
        let mut g = GraphView {
            cfg,
            lay,
            canvas: Vec::new(),
            cur_pos: None,
            focus_pos: None,
            calls,
            sel: None,
        };
        g.refresh(None, &HashMap::new(), syms);
        g
    }

    /// Function name for the breadcrumb.
    pub fn name(&self, syms: &Symbols) -> String {
        match syms.lookup(self.cfg.entry) {
            Some((n, 0)) => n.to_string(),
            Some((n, off)) => format!("{n}+{off:#x}"),
            None => format!("{:#x}", self.cfg.entry),
        }
    }

    /// Move the call selection (wraps around).
    pub fn select(&mut self, dir: isize) {
        let n = self.calls.len() as isize;
        if n == 0 {
            return;
        }
        let next = match self.sel {
            None => {
                if dir > 0 { 0 } else { n - 1 }
            }
            Some(i) => (i as isize + dir).rem_euclid(n),
        };
        self.sel = Some(next as usize);
    }

    pub fn selected(&self) -> Option<(u64, u64)> {
        self.sel.and_then(|i| self.calls.get(i)).copied()
    }

    pub fn call_at(&self, addr: u64) -> Option<(u64, u64)> {
        self.calls.iter().find(|c| c.0 == addr).copied()
    }

    pub fn width(&self) -> usize {
        self.lay.width
    }

    pub fn height(&self) -> usize {
        self.lay.height
    }

    /// Re-rasterise (current block highlight, RIP row, hit counters).
    pub fn refresh(&mut self, rip: Option<u64>, hits: &HashMap<u64, u32>, syms: &Symbols) {
        let (w, h) = (self.lay.width, self.lay.height);
        let blank = Cell { ch: ' ', style: Style::new() };
        let mut cv = vec![vec![blank; w]; h];

        for c in &self.lay.cells {
            let style = Style::new().fg(edge_color(c.kind));
            if let Some(cell) = cv.get_mut(c.y).and_then(|r| r.get_mut(c.x)) {
                let merged = match (cell.ch, c.ch) {
                    ('─', '│') | ('│', '─') => '┼',
                    (_, n) => n,
                };
                *cell = Cell { ch: merged, style };
            }
        }

        self.cur_pos = None;
        let mut sel_pos = None;
        let mut entry_pos = None;
        let sel_addr = self.sel.and_then(|i| self.calls.get(i)).map(|c| c.0);
        for p in &self.lay.blocks {
            let Ok(i) = self.cfg.blocks.binary_search_by_key(&p.id, |b| b.start) else { continue };
            let b = &self.cfg.blocks[i];
            let is_cur = rip.map(|r| b.insns.iter().any(|x| x.addr == r)).unwrap_or(false);
            let n = hits.get(&b.start).copied().unwrap_or(0);
            let (rr, sr) = draw_block(&mut cv, p, b, is_cur, rip, sel_addr, n, syms);
            if let Some(row) = rr {
                self.cur_pos = Some((p.x + p.w / 2, row));
            }
            if let Some(row) = sr {
                sel_pos = Some((p.x + p.w / 2, row));
            }
            if p.id == self.cfg.entry {
                entry_pos = Some((p.x + p.w / 2, p.y + 1));
            }
        }
        self.focus_pos = sel_pos.or(self.cur_pos).or(entry_pos);
        self.canvas = cv;
    }
}
