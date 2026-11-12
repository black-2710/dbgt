use crate::analysis::symbols::short;
use crate::app::{App, Pane, StaticsTab, ViewMode, REG_ORDER};
use crate::backend::Views;
use std::collections::HashSet;
use ratatui::{
    prelude::*,
    widgets::{Block, Paragraph},
};

pub fn draw(f: &mut Frame, app: &App) {
    let rows = Layout::vertical([Constraint::Min(5), Constraint::Length(4)]).split(f.area());
    let (body, cmd_area) = (rows[0], rows[1]);

    if app.zoom {
        // one pane full screen: Tab / Shift-Tab then flip between them like tabs
        render_pane(f, app, app.focus, body);
    } else {
        let v = Layout::vertical([Constraint::Min(8), Constraint::Length(8), Constraint::Length(8)]).split(body);
        let top = Layout::horizontal([Constraint::Length(46), Constraint::Min(30)]).split(v[0]);
        let mid = Layout::horizontal([Constraint::Min(30), Constraint::Length(52)]).split(v[1]);
        let bot = Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)]).split(v[2]);
        render_pane(f, app, Pane::Regs, top[0]);
        render_pane(f, app, Pane::Main, top[1]);
        render_pane(f, app, Pane::Stack, mid[0]);
        render_pane(f, app, Pane::Hex, mid[1]);
        render_pane(f, app, Pane::Log, bot[0]);
        render_pane(f, app, Pane::Target, bot[1]);
    }
    render_cmdline(f, app, cmd_area);
}

fn render_pane(f: &mut Frame, app: &App, pane: Pane, area: Rect) {
    let focused = app.focus == pane;
    let iw = area.width.saturating_sub(2) as usize;
    let ih = area.height.saturating_sub(2) as usize;

    let (lines, title): (Vec<Line<'static>>, String) = match pane {
        Pane::Regs => (regs_lines(app), " regs ".to_string()),
        Pane::Main => match app.mode {
            ViewMode::Graph => {
                app.view_size.set((iw, ih));
                if app.center_pending.get() {
                    app.center();
                }
                (graph_lines(app, iw, ih), format!(" graph: {} ", app.crumb()))
            }
            ViewMode::Disasm => (code_lines(app, ih), " code ".to_string()),
            ViewMode::Source => source_lines(app, ih, iw),
            ViewMode::Maps => maps_lines(app, ih),
            ViewMode::Results => found_lines(app, ih),
            ViewMode::Gadgets => gadgets_lines(app, ih),
            ViewMode::Statics => statics_lines(app, ih),
        },
        Pane::Stack => {
            let t = app
                .views
                .as_ref()
                .and_then(|v| v.stack.first())
                .map(|r| format!(" stack @ {:#x} ", r.addr))
                .unwrap_or_else(|| " stack ".to_string());
            (stack_lines(app, ih), t)
        }
        Pane::Hex => {
            let t = app
                .views
                .as_ref()
                .map(|v| format!(" hexdump @ {:#x} ", v.hex_addr))
                .unwrap_or_else(|| " hexdump ".to_string());
            (hex_lines(app, ih), t)
        }
        Pane::Log => {
            let total = app.log.len();
            let end = total.saturating_sub(app.log_scroll);
            let start = end.saturating_sub(ih);
            let lines: Vec<Line<'static>> =
                app.log.iter().skip(start).take(end - start).map(|s| Line::from(s.clone())).collect();
            let t = if app.log_scroll > 0 {
                format!(" log (scrolled up {}) ", app.log_scroll)
            } else {
                " log ".to_string()
            };
            (lines, t)
        }
        Pane::Target => {
            app.term_size.set((ih as u16, iw as u16));
            let t = if app.input_mode { " target: INPUT (Ctrl-] to leave) " } else { " target " };
            (term_lines(app, ih as u16, iw as u16), t.to_string())
        }
    };

    let mut block = Block::bordered().title(if focused { format!("▸{title}") } else { title });
    if focused {
        let color = if pane == Pane::Target && app.input_mode { Color::Yellow } else { Color::Cyan };
        block = block.border_style(Style::new().fg(color).add_modifier(Modifier::BOLD));
    }
    f.render_widget(Paragraph::new(lines).block(block), area);

    if pane == Pane::Target && app.input_mode {
        let screen = app.term.screen();
        let (cr, cc) = screen.cursor_position();
        if !screen.hide_cursor() && (cr as usize) < ih && (cc as usize) < iw {
            f.set_cursor_position((area.x + 1 + cc, area.y + 1 + cr));
        }
    }
}

fn render_cmdline(f: &mut Frame, app: &App, area: Rect) {
    let title = format!(" {} ", app.status);
    let lines: Vec<Line> = if app.editing {
        vec![Line::from(format!("{}{}", app.prompt(), app.input))]
    } else {
        vec![
            Line::from(Span::styled(app.pane_hint(), Style::new().fg(Color::Cyan))),
            Line::from(Span::styled(
                "Tab/Shift-Tab pane | s n c step/next/cont | : command | f maximise pane | ? help | q quit",
                Style::new().fg(Color::DarkGray),
            )),
        ]
    };
    f.render_widget(Paragraph::new(lines).block(Block::bordered().title(title)), area);
    if app.editing {
        let x = area.x + 1 + app.prompt().chars().count() as u16 + app.input.chars().count() as u16;
        f.set_cursor_position((x, area.y + 1));
    }
}

/// vmmap: colour by permission; tag mappings that registers point into.
fn maps_lines(app: &App, h: usize) -> (Vec<Line<'static>>, String) {
    let title = format!(" vmmap: {} mappings (j/k scroll, g next view) ", app.maps.len());
    if app.maps.is_empty() {
        return (vec![Line::from("no memory map yet")], title);
    }
    const REGS: [&str; 17] = [
        "rip", "rsp", "rbp", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    ];
    let regs = app.snap.as_ref().map(|s| s.regs);
    let mut lines = vec![Line::from(Span::styled(
        format!("{:<14} {:<14} {:<4} {:>9} {:>8}  object", "start", "end", "perm", "size", "offset"),
        Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    ))];
    for m in app.maps.iter().skip(app.list_scroll.get()).take(h.saturating_sub(1)) {
        let color = if m.perms.contains('x') {
            Color::Red
        } else if m.perms.contains('w') {
            Color::Green
        } else if m.perms.contains('r') {
            Color::White
        } else {
            Color::DarkGray
        };
        let tags: Vec<&str> = regs
            .map(|r| {
                REGS.iter()
                    .copied()
                    .filter(|n| r.get(n).map_or(false, |v| v >= m.start && v < m.end))
                    .collect()
            })
            .unwrap_or_default();
        let path = if m.path.is_empty() { "[anon]" } else { m.path.as_str() };
        let mut spans = vec![Span::styled(
            format!(
                "{:#014x} {:#014x} {:<4} {:>#9x} {:>#8x}  {}",
                m.start,
                m.end,
                m.perms,
                m.end - m.start,
                m.offset,
                path
            ),
            Style::new().fg(color),
        )];
        if !tags.is_empty() {
            spans.push(Span::styled(
                format!("  ◀ {}", tags.join(" ")),
                Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            ));
        }
        lines.push(Line::from(spans));
    }
    (lines, title)
}

/// Hits of the last `find`.
fn found_lines(app: &App, h: usize) -> (Vec<Line<'static>>, String) {
    let Some(f) = &app.found else {
        return (vec![Line::from("nothing searched yet: find <pattern>")], " find ".into());
    };
    let title = format!(
        " find {}: {} hit(s){} (j/k scroll, g next view) ",
        f.desc,
        f.hits.len(),
        if f.truncated { "+" } else { "" }
    );
    let start = app.list_scroll.get();
    let lines = f
        .hits
        .iter()
        .enumerate()
        .skip(start)
        .take(h)
        .map(|(i, (addr, text))| {
            Line::from(vec![
                Span::styled(format!("{:>3} ", i + 1), Style::new().fg(Color::DarkGray)),
                Span::styled(format!("{addr:#014x}  "), Style::new().fg(Color::Blue)),
                Span::raw(text.clone()),
            ])
        })
        .collect();
    (lines, title)
}

/// Hits of the last `rop` search. Gadgets are coloured by the mnemonic in
/// the final instruction (ret = plain, indirect jmp/call = flagged yellow,
/// since the branch target is a register and may be tampered with).
fn gadgets_lines(app: &App, h: usize) -> (Vec<Line<'static>>, String) {
    let Some(g) = &app.gadgets else {
        return (vec![Line::from("nothing searched yet: rop [filter]   e.g. rop pop rdi")], " rop ".into());
    };
    let title = format!(
        " rop{}: {} gadget(s){} (j/k scroll, g or 1-5 switch view) ",
        if g.filter.is_empty() { String::new() } else { format!(" '{}'", g.filter) },
        g.items.len(),
        if g.truncated { "+" } else { "" }
    );
    if g.items.is_empty() {
        return (vec![Line::from("no gadgets matched")], title);
    }
    let start = app.list_scroll.get();
    let lines = g
        .items
        .iter()
        .skip(start)
        .take(h)
        .map(|(addr, text)| {
            let last = text.rsplit(" ; ").next().unwrap_or(text);
            let indirect = last.starts_with("jmp ") || last.starts_with("call ");
            let tail_style = if indirect { Style::new().fg(Color::Yellow) } else { Style::new().fg(Color::Green) };
            Line::from(vec![
                Span::styled(format!("{addr:#014x}  "), Style::new().fg(Color::Blue)),
                Span::styled(text.clone(), tail_style),
            ])
        })
        .collect();
    (lines, title)
}

const TABS: [StaticsTab; 5] =
    [StaticsTab::Sections, StaticsTab::Segments, StaticsTab::Symtab, StaticsTab::Imports, StaticsTab::Strings];

/// A binsider-style tab strip: the active tab highlighted, others dim.
fn tab_strip(active: StaticsTab) -> Line<'static> {
    let mut spans = Vec::new();
    for (i, t) in TABS.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("  "));
        }
        let style = if *t == active {
            Style::new().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(Color::DarkGray)
        };
        spans.push(Span::styled(format!(" {} ", t.label()), style));
    }
    Line::from(spans)
}

/// Static ELF browser: sections / segments / symtab / imports / strings.
/// Tabs switch with `[` / `]`; symtab, imports and strings take a filter
/// via their command (`symtab <f>`, `imports <f>`, `strings <f>`).
fn statics_lines(app: &App, h: usize) -> (Vec<Line<'static>>, String) {
    let tab = app.statics_tab;
    let title = format!(" static: {} ([ ] switch tab, j/k scroll, g or 1-6 switch view) ", tab.label());
    let Some(s) = &app.statics else {
        return (vec![Line::from("running static analysis ..."), tab_strip(tab)], title);
    };

    let head = |cols: &str| Line::from(Span::styled(cols.to_string(), Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
    let start = app.list_scroll.get();
    let body_h = h.saturating_sub(2); // tab strip + header row

    let mut lines = vec![tab_strip(tab)];
    match tab {
        StaticsTab::Sections => {
            lines.push(head(&format!("{:<20} {:<14} {:>10} {:<4}  kind", "name", "addr", "size", "perm")));
            lines.extend(s.sections.iter().skip(start).take(body_h).map(|r| {
                Line::from(vec![
                    Span::styled(format!("{:<20} ", r.name), Style::new().fg(Color::White)),
                    Span::styled(format!("{:#014x} ", r.addr), Style::new().fg(Color::Blue)),
                    Span::raw(format!("{:>10} ", r.size)),
                    Span::styled(format!("{:<4} ", r.perm), perm_color(&r.perm)),
                    Span::styled(r.kind.clone(), Style::new().fg(Color::DarkGray)),
                ])
            }));
        }
        StaticsTab::Segments => {
            lines.push(head(&format!("{:<14} {:<14} {:<14} {:>10} {:>10} {:<4}", "kind", "offset", "vaddr", "filesz", "memsz", "perm")));
            lines.extend(s.segments.iter().skip(start).take(body_h).map(|r| {
                Line::from(vec![
                    Span::styled(format!("{:<14} ", r.kind), Style::new().fg(Color::White)),
                    Span::raw(format!("{:#012x}  ", r.offset)),
                    Span::styled(format!("{:#014x} ", r.vaddr), Style::new().fg(Color::Blue)),
                    Span::raw(format!("{:>10} ", r.filesz)),
                    Span::raw(format!("{:>10} ", r.memsz)),
                    Span::styled(r.perm.clone(), perm_color(&r.perm)),
                ])
            }));
        }
        StaticsTab::Symtab => {
            lines.push(head(&format!("{:<14} {:>8} {:<10} {:<7}  name", "addr", "size", "kind", "bind")));
            lines.extend(
                s.symbols
                    .iter()
                    .filter(|r| r.name.contains(&app.sym_filter))
                    .skip(start)
                    .take(body_h)
                    .map(|r| {
                        Line::from(vec![
                            Span::styled(format!("{:#014x} ", r.addr), Style::new().fg(Color::Blue)),
                            Span::raw(format!("{:>8} ", r.size)),
                            Span::styled(format!("{:<10} ", r.kind), Style::new().fg(Color::Magenta)),
                            Span::styled(format!("{:<7} ", r.bind), Style::new().fg(Color::DarkGray)),
                            Span::raw(r.name.clone()),
                        ])
                    }),
            );
        }
        StaticsTab::Imports => {
            lines.push(head(&format!("{:<14} {:<14}  name", "got", "plt")));
            lines.extend(
                s.imports
                    .iter()
                    .filter(|r| r.name.contains(&app.imp_filter))
                    .skip(start)
                    .take(body_h)
                    .map(|r| {
                        let plt = r.plt.map(|a| format!("{a:#014x}")).unwrap_or_else(|| "-".into());
                        Line::from(vec![
                            Span::styled(format!("{:#014x} ", r.got), Style::new().fg(Color::Green)),
                            Span::styled(format!("{plt:<14} "), Style::new().fg(Color::Blue)),
                            Span::raw(r.name.clone()),
                        ])
                    }),
            );
        }
        StaticsTab::Strings => {
            lines.push(head("addr            text"));
            lines.extend(
                s.strings
                    .iter()
                    .filter(|r| r.text.contains(&app.str_filter))
                    .skip(start)
                    .take(body_h)
                    .map(|r| {
                        Line::from(vec![
                            Span::styled(format!("{:#014x}  ", r.addr), Style::new().fg(Color::Blue)),
                            Span::styled(r.text.clone(), Style::new().fg(Color::Yellow)),
                        ])
                    }),
            );
        }
    }
    (lines, title)
}

fn perm_color(perm: &str) -> Style {
    if perm.contains('x') {
        Style::new().fg(Color::Red)
    } else if perm.contains('w') {
        Style::new().fg(Color::Green)
    } else {
        Style::new().fg(Color::White)
    }
}

fn vt_color(c: vt100::Color) -> Color {
    match c {
        vt100::Color::Default => Color::Reset,
        vt100::Color::Idx(i) => Color::Indexed(i),
        vt100::Color::Rgb(r, g, b) => Color::Rgb(r, g, b),
    }
}

fn term_lines(app: &App, h: u16, w: u16) -> Vec<Line<'static>> {
    let screen = app.term.screen();
    let (rows, cols) = screen.size();
    (0..rows.min(h))
        .map(|r| {
            let mut spans: Vec<Span<'static>> = Vec::new();
            let mut run = String::new();
            let mut cur: Option<Style> = None;
            for c in 0..cols.min(w) {
                let (text, style) = match screen.cell(r, c) {
                    Some(cell) => {
                        if cell.is_wide_continuation() {
                            continue;
                        }
                        let t = cell.contents();
                        let mut st = Style::new().fg(vt_color(cell.fgcolor())).bg(vt_color(cell.bgcolor()));
                        if cell.bold() {
                            st = st.add_modifier(Modifier::BOLD);
                        }
                        if cell.underline() {
                            st = st.add_modifier(Modifier::UNDERLINED);
                        }
                        if cell.inverse() {
                            st = st.add_modifier(Modifier::REVERSED);
                        }
                        (if t.is_empty() { " ".to_string() } else { t }, st)
                    }
                    None => (" ".to_string(), Style::new()),
                };
                if Some(style) != cur {
                    if !run.is_empty() {
                        spans.push(Span::styled(std::mem::take(&mut run), cur.unwrap()));
                    }
                    cur = Some(style);
                }
                run.push_str(&text);
            }
            if !run.is_empty() {
                spans.push(Span::styled(run, cur.unwrap()));
            }
            Line::from(spans)
        })
        .collect()
}

fn graph_lines(app: &App, w: usize, h: usize) -> Vec<Line<'static>> {
    let Some(g) = app.shown() else {
        return vec![Line::from("waiting for target…")];
    };
    if g.canvas.is_empty() {
        return vec![Line::from("no code recovered at this address (try 'g' for linear disasm)")];
    }
    let (sx, sy) = app.scroll.get();
    g.canvas
        .iter()
        .skip(sy)
        .take(h)
        .map(|row| {
            let mut spans: Vec<Span<'static>> = Vec::new();
            let mut run = String::new();
            let mut cur: Option<Style> = None;
            for c in row.iter().skip(sx).take(w) {
                if Some(c.style) != cur {
                    if !run.is_empty() {
                        spans.push(Span::styled(std::mem::take(&mut run), cur.unwrap()));
                    }
                    cur = Some(c.style);
                }
                run.push(c.ch);
            }
            if !run.is_empty() {
                spans.push(Span::styled(run, cur.unwrap()));
            }
            Line::from(spans)
        })
        .collect()
}

fn stack_lines(app: &App, height: usize) -> Vec<Line<'static>> {
    let Some(v) = &app.views else { return Vec::new() };
    let focused = app.focus == Pane::Stack;
    // scroll just enough to keep the selected slot visible
    let off = app.stack_sel.saturating_sub(height.saturating_sub(1));
    v.stack
        .iter()
        .enumerate()
        .skip(off)
        .take(height)
        .map(|(i, r)| {
            let sel = focused && i == app.stack_sel;
            let bg = |st: Style| if sel { st.bg(Color::DarkGray) } else { st };
            Line::from(vec![
                Span::styled(format!("{:#014x}", r.addr), bg(Style::new().fg(Color::Blue))),
                Span::styled(format!(" +{:#05x} ", i * 8), bg(Style::new().fg(Color::DarkGray))),
                Span::styled(format!("{:#018x}", r.val), bg(Style::new())),
                Span::styled(r.desc.clone(), bg(Style::new().fg(Color::Green))),
            ])
        })
        .collect()
}

/// hexyl-style byte class: null bytes dim, printable ASCII cyan, whitespace
/// green, other control bytes yellow, the rest (high/non-ASCII) magenta.
fn byte_class_color(b: u8) -> Color {
    match b {
        0x00 => Color::DarkGray,
        0x20..=0x7e => Color::Cyan,
        0x09 | 0x0a | 0x0d | 0x0b | 0x0c => Color::Green,
        0x01..=0x1f | 0x7f => Color::Yellow,
        _ => Color::Magenta,
    }
}

/// ImHex-style data inspector: the selected byte decoded every which way.
/// Two lines so it fits a narrow pane: integers (hex + decimal) on one,
/// floats and a short ASCII preview on the other.
fn inspector_lines(hex: &[u8], base: u64, sel: usize) -> Vec<Line<'static>> {
    if hex.is_empty() {
        return vec![Line::from("(no bytes here)")];
    }
    let sel = sel.min(hex.len() - 1);
    let avail = hex.len() - sel;
    let take = |n: usize| (avail >= n).then(|| {
        let mut buf = [0u8; 8];
        buf[..n].copy_from_slice(&hex[sel..sel + n]);
        buf
    });
    let u16v = take(2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32v = take(4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    let u64v = take(8).map(u64::from_le_bytes);

    let lab = |s: &str| Span::styled(format!("{s} "), Style::new().fg(Color::DarkGray));
    let val = |s: String| Span::styled(format!("{s}  "), Style::new().fg(Color::White));
    let na = || "-".to_string();

    let line1 = Line::from(vec![
        Span::styled(format!("@{:#014x}  ", base + sel as u64), Style::new().fg(Color::Blue).add_modifier(Modifier::BOLD)),
        lab("u8"),
        val(format!("{:#04x} ({})", hex[sel], hex[sel])),
        lab("i8"),
        val(format!("{}", hex[sel] as i8)),
        lab("u16"),
        val(u16v.map(|v| format!("{v:#06x} ({v})")).unwrap_or_else(na)),
        lab("u32"),
        val(u32v.map(|v| format!("{v:#010x} ({v})")).unwrap_or_else(na)),
        lab("u64"),
        val(u64v.map(|v| format!("{v:#018x}")).unwrap_or_else(na)),
    ]);
    let ascii: String = hex[sel..(sel + 16).min(hex.len())]
        .iter()
        .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
        .collect();
    let line2 = Line::from(vec![
        lab("i32"),
        val(u32v.map(|v| format!("{}", v as i32)).unwrap_or_else(na)),
        lab("i64"),
        val(u64v.map(|v| format!("{}", v as i64)).unwrap_or_else(na)),
        lab("f32"),
        val(u32v.map(|v| format!("{}", f32::from_bits(v))).unwrap_or_else(na)),
        lab("f64"),
        val(u64v.map(|v| format!("{}", f64::from_bits(v))).unwrap_or_else(na)),
        lab("str"),
        Span::styled(format!("\"{ascii}\""), Style::new().fg(Color::Yellow)),
    ]);
    vec![line1, line2]
}

/// A pinned `struct` overlay for the current hexdump view, if one is active
/// and (at least fully) within it. `None` means "nothing pinned": fall back
/// to the plain byte inspector.
fn struct_overlay_lines(app: &App, v: &Views) -> Option<Vec<Line<'static>>> {
    let (name, base) = app.active_struct.as_ref()?;
    let def = app.struct_defs.iter().find(|d| &d.name == name)?;
    if *base < v.hex_addr || *base + def.size as u64 > v.hex_addr + v.hex.len() as u64 {
        return Some(vec![Line::from(Span::styled(
            format!("struct {name} @ {base:#014x} — out of the current hexdump view (x {base:#x} to bring it in)"),
            Style::new().fg(Color::Yellow),
        ))]);
    }
    let off = (*base - v.hex_addr) as usize;
    let fields = crate::structs::decode(def, *base, &v.hex[off..]);
    let mut lines = vec![Line::from(Span::styled(
        format!("struct {name} @ {base:#014x}  ({} field(s) — struct clear to unpin)", fields.len()),
        Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    ))];
    for f in fields.iter().take(8) {
        lines.push(Line::from(vec![
            Span::styled(format!("  {:<10} ", f.name), Style::new().fg(Color::White)),
            Span::styled(format!("{:<9} ", f.ty_label), Style::new().fg(Color::DarkGray)),
            Span::styled(f.value.clone(), Style::new().fg(Color::Yellow)),
        ]));
    }
    if fields.len() > 8 {
        lines.push(Line::from(format!("  ... and {} more field(s) (see the log)", fields.len() - 8)));
    }
    Some(lines)
}

fn hex_lines(app: &App, height: usize) -> Vec<Line<'static>> {
    let Some(v) = &app.views else { return Vec::new() };
    let focused = app.focus == Pane::Hex;
    let mut lines = struct_overlay_lines(app, v).unwrap_or_else(|| inspector_lines(&v.hex, v.hex_addr, app.hex_sel));
    lines.push(Line::from(""));
    let body_h = height.saturating_sub(lines.len());
    lines.extend(v.hex.chunks(8).take(body_h).enumerate().map(|(i, chunk)| {
        let mut spans = vec![Span::styled(format!("{:#014x}", v.hex_addr + 8 * i as u64), Style::new().fg(Color::Blue)), Span::raw("  ")];
        for (col, &b) in chunk.iter().enumerate() {
            let sel = focused && i * 8 + col == app.hex_sel;
            let mut style = Style::new().fg(byte_class_color(b));
            if sel {
                style = style.bg(Color::Cyan).fg(Color::Black).add_modifier(Modifier::BOLD);
            }
            spans.push(Span::styled(format!("{b:02x} "), style));
        }
        for _ in chunk.len()..8 {
            spans.push(Span::raw("   "));
        }
        spans.push(Span::raw(" "));
        for (col, &b) in chunk.iter().enumerate() {
            let ch = if (0x20..0x7f).contains(&b) { b as char } else { '.' };
            let sel = focused && i * 8 + col == app.hex_sel;
            let mut style = Style::new().fg(byte_class_color(b));
            if sel {
                style = style.bg(Color::Cyan).fg(Color::Black).add_modifier(Modifier::BOLD);
            }
            spans.push(Span::styled(ch.to_string(), style));
        }
        Line::from(spans)
    }));
    lines
}

fn flags(v: u64) -> String {
    const F: [(u32, &str); 9] = [
        (0, "CF"), (2, "PF"), (4, "AF"), (6, "ZF"), (7, "SF"),
        (8, "TF"), (9, "IF"), (10, "DF"), (11, "OF"),
    ];
    F.iter()
        .map(|(bit, name)| {
            if ((v >> bit) & 1) == 1 { name.to_uppercase() } else { name.to_lowercase() }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn regs_lines(app: &App) -> Vec<Line<'static>> {
    let Some(snap) = &app.snap else {
        return vec![Line::from("waiting for target…")];
    };
    let r = &snap.regs;
    let prev = app.prev;
    let focused = app.focus == Pane::Regs;

    // one register: name + value, red if it changed, highlighted if the cursor is on it
    let cell = |idx: usize| -> Vec<Span<'static>> {
        let name = REG_ORDER[idx];
        let val = r.get(name).unwrap_or(0);
        let changed = prev.map(|p| p.get(name) != Some(val)).unwrap_or(false);
        let mut vstyle = if name == "rip" {
            Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD)
        } else if changed {
            Style::new().fg(Color::Red).add_modifier(Modifier::BOLD)
        } else {
            Style::new()
        };
        let mut nstyle = Style::new().fg(Color::Cyan);
        if focused && idx == app.reg_sel {
            vstyle = vstyle.bg(Color::DarkGray);
            nstyle = nstyle.bg(Color::DarkGray);
        }
        vec![
            Span::styled(format!("{name:<4}"), nstyle),
            Span::styled(format!("{val:016x}"), vstyle),
        ]
    };

    let mut out: Vec<Line<'static>> = Vec::new();
    for row in 0..8 {
        let mut spans = cell(row * 2);
        spans.push(Span::raw("  "));
        spans.extend(cell(row * 2 + 1));
        out.push(Line::from(spans));
    }
    out.push(Line::from(cell(16)));
    out.push(Line::from(vec![
        Span::styled("eflags ", Style::new().fg(Color::Cyan)),
        Span::raw(format!("{:#x} [{}]", r.eflags, flags(r.eflags))),
    ]));
    out.push(Line::from(format!(
        "cs {:x} ss {:x} ds {:x} es {:x} fs {:x} gs {:x}",
        r.cs, r.ss, r.ds, r.es, r.fs, r.gs
    )));
    out.push(Line::from(format!("fs_base {:#x}", r.fs_base)));
    out.push(Line::from(format!("gs_base {:#x}", r.gs_base)));
    out
}

fn code_lines(app: &App, height: usize) -> Vec<Line<'static>> {
    let rip = app.snap.as_ref().map(|s| s.regs.rip);
    let mut prev: Option<(&str, u32)> = None;
    let new_line: Vec<bool> = app
        .lines
        .iter()
        .map(|i| {
            let cur = app.syms.line(i.addr);
            let show = cur.is_some() && cur != prev;
            if cur.is_some() {
                prev = cur;
            }
            show
        })
        .collect();
    app.lines
        .iter()
        .enumerate()
        .take(height)
        .map(|(idx, ins)| {
            let is_rip = Some(ins.addr) == rip;
            let has_bp = app.bps.contains(&ins.addr);
            let (marker, mstyle) = if is_rip {
                ("▶", Style::new().fg(Color::Yellow))
            } else if has_bp {
                ("●", Style::new().fg(Color::Red))
            } else {
                (" ", Style::new())
            };
            let hex = ins.bytes.iter().take(7).map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
            let body = Style::new().fg(if is_rip { Color::White } else { Color::Gray });
            let mut line = Line::from(vec![
                Span::styled(marker, mstyle),
                Span::raw(" "),
                Span::styled(format!("{:#014x}", ins.addr), Style::new().fg(Color::Blue)),
                Span::raw("  "),
                Span::styled(format!("{hex:<20}"), Style::new().fg(Color::DarkGray)),
                Span::styled(ins.text.clone(), body),
            ]);
            if let Some((n, off)) = app.syms.lookup(ins.addr) {
                let tag = if off == 0 { format!("  <{n}>") } else { format!("  <{n}+{off:#x}>") };
                line.spans.push(Span::styled(tag, Style::new().fg(Color::Green)));
            }
            if let Some(label) = app.session.bookmark_at(ins.addr) {
                line.spans.push(Span::styled(format!("  ★ {label}"), Style::new().fg(Color::Magenta)));
            }
            if new_line[idx] {
                if let Some((p, l)) = app.syms.line(ins.addr) {
                    line.spans.push(Span::styled(format!("  {}:{}", short(p), l), Style::new().fg(Color::Cyan)));
                }
            }
            if is_rip {
                line = line.style(Style::new().bg(Color::DarkGray).add_modifier(Modifier::BOLD));
            }
            line
        })
        .collect()
}

/// Source file around the current line (from DWARF line info; the file is read from disk).
fn source_lines(app: &App, h: usize, w: usize) -> (Vec<Line<'static>>, String) {
    if !app.syms.has_lines() {
        return (vec![Line::from("no DWARF line info: compile the target with -g")], " source ".into());
    }
    let Some((path, line, exact)) = app.src_loc() else {
        return (vec![Line::from("no source location yet (try :start)")], " source ".into());
    };
    let title = format!(
        " source: {}:{}{} ",
        short(&path),
        line,
        if exact { "" } else { " (last known)" }
    );
    let mut cache = app.src_cache.borrow_mut();
    let text = cache.entry(path.clone()).or_insert_with(|| {
        std::fs::read_to_string(&path)
            .ok()
            .map(|t| t.lines().map(|l| l.replace('\t', "    ")).collect())
    });
    let Some(src) = text else {
        return (vec![Line::from(format!("cannot read {path}"))], title);
    };

    let bp_lines: HashSet<u32> = app
        .bps
        .iter()
        .filter_map(|&a| app.syms.line(a))
        .filter(|(p, _)| *p == path.as_str())
        .map(|(_, l)| l)
        .collect();
    let total = src.len();
    let centre = ((line as isize - 1) + app.src_off).clamp(0, total.saturating_sub(1) as isize) as usize;
    let start = centre.saturating_sub(h / 2).min(total.saturating_sub(h));
    let lines = (start..(start + h).min(total))
        .map(|i| {
            let n = i as u32 + 1;
            let is_cur = n == line;
            let marker = if is_cur && exact {
                "▶"
            } else if bp_lines.contains(&n) {
                "●"
            } else {
                " "
            };
            let body: String = src[i].chars().take(w.saturating_sub(8)).collect();
            let mut l = Line::from(vec![
                Span::styled(marker, Style::new().fg(if is_cur { Color::Yellow } else { Color::Red })),
                Span::styled(format!("{n:>5} "), Style::new().fg(Color::DarkGray)),
                Span::raw(body),
            ]);
            if is_cur {
                l = l.style(Style::new().bg(Color::DarkGray).add_modifier(Modifier::BOLD));
            }
            l
        })
        .collect();
    (lines, title)
}
