use crate::analysis::symbols::Symbols;
use crate::backend::{Regs, WatchKind};

pub enum Command {
    Step,
    Next,
    Continue,
    /// Run until the current function returns (frame-pointer walk for the return address).
    Finish,
    /// Frame-pointer backtrace from the current RIP/RBP.
    Backtrace,
    Start,
    Break(String),
    Delete(String),
    Hex(Option<String>),
    Stack(Option<String>),
    /// vmmap [filter]
    Maps(Option<String>),
    Checksec,
    /// rop [filter] — gadget search, optionally filtered by a substring of the disassembly.
    Rop(Option<String>),
    /// Switch the main pane to a static-analysis tab; each carries its own text filter.
    Sections,
    Segments,
    Symtab(Option<String>),
    Imports(Option<String>),
    Strings(Option<String>),
    /// cyclic N | cyclic send N | cyclic -l <leak>
    Cyclic(CyclicOp),
    /// libc <path> <leaked symbol> [leaked addr] — offline libc offset/base helper.
    Libc { path: String, symbol: String, leaked: Option<String> },
    Bookmark(BookmarkOp),
    Note(NoteOp),
    Struct(StructOp),
    Find(String),
    Modules,
    Sym(String),
    Graph(String),
    /// (address expression, explicit length, kind)
    Watch(String, Option<usize>, WatchKind),
    Watches,
    Unwatch(usize),
    /// (text with escapes, append newline)
    Send(String, bool),
    Quit,
    Help,
}

pub enum CyclicOp {
    /// cyclic N — print N bytes of pattern.
    Gen(usize),
    /// cyclic send N — generate N bytes and write them straight to the target.
    Send(usize),
    /// cyclic -l <leak> — offset of a leaked value (hex word or literal text) in the pattern.
    Find(String),
}

pub enum BookmarkOp {
    /// (address expression, label)
    Add(String, String),
    /// address expression
    Del(String),
    List,
}

pub enum NoteOp {
    /// (address expression if `@`-prefixed, text)
    Add(Option<String>, String),
    List,
}

pub enum StructOp {
    /// path to a text file of `struct Name { ... }` blocks
    Load(String),
    List,
    Clear,
    /// (struct name, optional @addr expression)
    Apply(String, Option<String>),
}

fn parse_struct(rest: &str) -> Result<Command, String> {
    const USAGE: &str = "usage: struct load <path> | struct list | struct clear | struct <Name> [@<addr|sym>]";
    let rest = rest.trim();
    if rest.is_empty() {
        return Err(USAGE.into());
    }
    if let Some(p) = rest.strip_prefix("load") {
        let p = p.trim();
        return if p.is_empty() { Err(USAGE.into()) } else { Ok(Command::Struct(StructOp::Load(p.to_string()))) };
    }
    if rest == "list" {
        return Ok(Command::Struct(StructOp::List));
    }
    if rest == "clear" {
        return Ok(Command::Struct(StructOp::Clear));
    }
    let mut parts = rest.splitn(2, char::is_whitespace);
    let name = parts.next().unwrap_or("").trim().to_string();
    if name.is_empty() {
        return Err(USAGE.into());
    }
    let addr = parts.next().map(str::trim).filter(|s| !s.is_empty()).map(|s| s.strip_prefix('@').unwrap_or(s).to_string());
    Ok(Command::Struct(StructOp::Apply(name, addr)))
}

fn parse_bookmark(rest: &str) -> Result<Command, String> {
    const USAGE: &str = "usage: bookmark <addr|sym> <label...> | bookmark del <addr|sym> | bookmark";
    let rest = rest.trim();
    if rest.is_empty() || rest == "list" {
        return Ok(Command::Bookmark(BookmarkOp::List));
    }
    if let Some(e) = rest.strip_prefix("del").or_else(|| rest.strip_prefix("rm")) {
        let e = e.trim();
        return if e.is_empty() { Err(USAGE.into()) } else { Ok(Command::Bookmark(BookmarkOp::Del(e.to_string()))) };
    }
    match rest.split_once(char::is_whitespace) {
        Some((addr, label)) if !label.trim().is_empty() => Ok(Command::Bookmark(BookmarkOp::Add(addr.to_string(), label.trim().to_string()))),
        _ => Err(USAGE.into()),
    }
}

fn parse_note(rest: &str) -> Result<Command, String> {
    let rest = rest.trim();
    if rest.is_empty() || rest == "list" {
        return Ok(Command::Note(NoteOp::List));
    }
    if let Some(r) = rest.strip_prefix('@') {
        let (addr, text) = r.split_once(char::is_whitespace).unwrap_or((r, ""));
        if text.trim().is_empty() {
            return Err("usage: note @<addr|sym> <text...>".into());
        }
        return Ok(Command::Note(NoteOp::Add(Some(addr.to_string()), text.trim().to_string())));
    }
    Ok(Command::Note(NoteOp::Add(None, rest.to_string())))
}

fn parse_cyclic(rest: &str) -> Result<Command, String> {
    const USAGE: &str = "usage: cyclic <N> | cyclic send <N> | cyclic -l <leaked value>";
    let rest = rest.trim();
    if let Some(leak) = rest.strip_prefix("-l").or_else(|| rest.strip_prefix("find")) {
        let leak = leak.trim();
        if leak.is_empty() {
            return Err(USAGE.into());
        }
        return Ok(Command::Cyclic(CyclicOp::Find(leak.to_string())));
    }
    if let Some(n) = rest.strip_prefix("send") {
        return n.trim().parse().map(CyclicOp::Send).map(Command::Cyclic).map_err(|_| USAGE.to_string());
    }
    rest.parse().map(CyclicOp::Gen).map(Command::Cyclic).map_err(|_| USAGE.to_string())
}

pub fn parse(line: &str) -> Result<Command, String> {
    let line = line.trim();
    let (head, rest) = match line.split_once(char::is_whitespace) {
        Some((h, r)) => (h, r.trim()),
        None => (line, ""),
    };
    let opt = || if rest.is_empty() { None } else { Some(rest.to_string()) };
    match head {
        "s" | "si" | "step" | "stepi" => Ok(Command::Step),
        "n" | "ni" | "next" | "nexti" => Ok(Command::Next),
        "c" | "cont" | "continue" => Ok(Command::Continue),
    "finish" | "fin" => Ok(Command::Finish),
    "bt" | "backtrace" | "where" => Ok(Command::Backtrace),
        "start" => Ok(Command::Start),
        "b" | "br" | "break" => match opt() {
            Some(e) => Ok(Command::Break(e)),
            None => Err("usage: b <addr|symbol>   e.g. b main, b main.c:42, b *0x401136, b $rip+4".into()),
        },
        "d" | "del" | "delete" => match opt() {
            Some(e) => Ok(Command::Delete(e)),
            None => Err("usage: d <addr|symbol>".into()),
        },
        "x" | "hexdump" => Ok(Command::Hex(opt())),
        "tele" | "telescope" | "stack" => Ok(Command::Stack(opt())),
        "vmmap" | "maps" => Ok(Command::Maps(opt())),
        "checksec" => Ok(Command::Checksec),
        "rop" | "gadgets" => Ok(Command::Rop(opt())),
        "sections" | "secs" => Ok(Command::Sections),
        "segments" | "phdrs" => Ok(Command::Segments),
        "symtab" | "syms" => Ok(Command::Symtab(opt())),
        "imports" | "got" => Ok(Command::Imports(opt())),
        "strings" | "str" => Ok(Command::Strings(opt())),
        "cyclic" | "pattern" => parse_cyclic(rest),
        "bookmark" | "bm" => parse_bookmark(rest),
        "note" => parse_note(rest),
        "struct" => parse_struct(rest),
        "libc" => {
            const USAGE: &str = "usage: libc <path-to-libc> <leaked symbol> [leaked addr]   e.g. libc ./libc.so.6 printf 0x7f1234561100";
            let mut it = rest.split_whitespace();
            match (it.next(), it.next()) {
                (Some(path), Some(symbol)) => {
                    Ok(Command::Libc { path: path.to_string(), symbol: symbol.to_string(), leaked: it.next().map(str::to_string) })
                }
                _ => Err(USAGE.into()),
            }
        }
        "find" | "search" | "grep" => {
            if rest.is_empty() {
                Err("usage: find [str|hex|u64|u32|u16|u8] <pattern> [in <module|stack|heap>]".into())
            } else {
                Ok(Command::Find(rest.to_string()))
            }
        }
        "send" | "sendline" => {
            if rest.is_empty() {
                Err("usage: send <text>   (escapes: \\n \\r \\t \\xHH \\\\)   sendline appends a newline".into())
            } else {
                Ok(Command::Send(rest.to_string(), head == "sendline"))
            }
        }
        "watch" | "rwatch" | "awatch" => {
            if rest.is_empty() {
                return Ok(Command::Watches);
            }
            let (expr, len) = match rest.rsplit_once(char::is_whitespace) {
                Some((e, l)) if matches!(l, "1" | "2" | "4" | "8") => (e.trim(), l.parse().ok()),
                _ => (rest, None),
            };
            let kind = if head == "watch" { WatchKind::Write } else { WatchKind::ReadWrite };
            Ok(Command::Watch(expr.to_string(), len, kind))
        }
        "unwatch" | "uw" => rest
            .parse::<usize>()
            .map(Command::Unwatch)
            .map_err(|_| "usage: unwatch <number>   (see 'watch' for the list)".to_string()),
        "modules" | "libs" => Ok(Command::Modules),
        "graph" | "cfg" => match opt() {
            Some(e) => Ok(Command::Graph(e)),
            None => Err("usage: graph <addr|symbol>   e.g. graph puts, graph main+0x40".into()),
        },
        "sym" | "info" => match opt() {
            Some(e) => Ok(Command::Sym(e)),
            None => Err("usage: sym <addr|expr>".into()),
        },
        "q" | "quit" | "exit" => Ok(Command::Quit),
        "h" | "help" | "?" => Ok(Command::Help),
        other => Err(format!("unknown command: {other} (try 'help')")),
    }
}

/// Evaluate `0x401136`, `*0x401136`, `main`, `main+0x10`, `$rip`, `$rsp+0x10`, `4198710`...
pub fn eval(expr: &str, regs: Option<&Regs>, syms: &Symbols) -> Result<u64, String> {
    let s = expr.trim().trim_start_matches('*');
    // main.c:42
    if let Some((f, l)) = s.rsplit_once(':') {
        if let Ok(line) = l.parse::<u32>() {
            if !f.is_empty() {
                return syms.resolve_line(f, line).ok_or_else(|| format!("no code for {s} (is the binary built with -g?)"));
            }
        }
    }
    let mut acc: i128 = 0;
    let mut neg = false;
    let mut term = String::new();
    for ch in s.chars().chain(std::iter::once('\0')) {
        if ch == '+' || ch == '-' || ch == '\0' {
            let t = term.trim();
            if !t.is_empty() {
                let v = atom(t, regs, syms)? as i128;
                acc += if neg { -v } else { v };
            }
            term.clear();
            neg = ch == '-';
        } else {
            term.push(ch);
        }
    }
    Ok(acc as u64)
}

fn atom(t: &str, regs: Option<&Regs>, syms: &Symbols) -> Result<u64, String> {
    if let Some(name) = t.strip_prefix('$') {
        let r = regs.ok_or("no register state yet")?;
        return r.get(name).ok_or_else(|| format!("unknown register: ${name}"));
    }
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).map_err(|_| format!("bad hex number: {t}"));
    }
    if let Ok(n) = t.parse::<u64>() {
        return Ok(n);
    }
    syms.addr(t).ok_or_else(|| format!("cannot resolve: {t}"))
}

/// `AAAA\\x41\\n` -> bytes. Surrounding double quotes are optional.
pub fn unescape(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix('"').and_then(|x| x.strip_suffix('"')).unwrap_or(s);
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() {
            match b[i + 1] {
                b'n' => out.push(b'\n'),
                b'r' => out.push(b'\r'),
                b't' => out.push(b'\t'),
                b'0' => out.push(0),
                b'\\' => out.push(b'\\'),
                b'"' => out.push(b'"'),
                b'x' => {
                    let h = s.get(i + 2..i + 4).ok_or("bad \\x escape")?;
                    out.push(u8::from_str_radix(h, 16).map_err(|_| "bad \\x escape".to_string())?);
                    i += 2;
                }
                other => {
                    out.push(b'\\');
                    out.push(other);
                }
            }
            i += 2;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Ok(out)
}

/// `find` arguments -> (bytes, optional mapping filter, description).
///   find /bin/sh            text (escapes allowed)       find hex 4883ec08
///   find u64 $rsp           little-endian integer        find u32 0xdeadbeef in stack
pub fn parse_find(rest: &str, regs: Option<&Regs>, syms: &Symbols) -> Result<(Vec<u8>, Option<String>, String), String> {
    let (pat, filter) = match rest.rsplit_once(" in ") {
        Some((p, f)) => (p.trim(), Some(f.trim().to_string())),
        None => (rest.trim(), None),
    };
    let (kind, arg) = match pat.split_once(char::is_whitespace) {
        Some((k, a)) if matches!(k, "str" | "hex" | "u64" | "u32" | "u16" | "u8") => (k, a.trim()),
        _ => ("str", pat),
    };
    if arg.is_empty() {
        return Err("empty pattern".into());
    }
    let bytes: Vec<u8> = match kind {
        "str" => unescape(arg)?,
        "hex" => {
            let h: String = arg.trim_start_matches("0x").chars().filter(|c| !c.is_whitespace()).collect();
            if h.len() % 2 != 0 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("hex pattern needs an even number of hex digits".into());
            }
            (0..h.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&h[i..i + 2], 16).map_err(|_| "bad hex".to_string()))
                .collect::<Result<Vec<u8>, String>>()?
        }
        k => {
            let v = eval(arg, regs, syms)?;
            let n = match k {
                "u64" => 8,
                "u32" => 4,
                "u16" => 2,
                _ => 1,
            };
            v.to_le_bytes()[..n].to_vec()
        }
    };
    if bytes.is_empty() || bytes.len() > 64 {
        return Err("pattern must be 1-64 bytes".into());
    }
    Ok((bytes, filter, format!("{kind} {arg}")))
}

/// Bytes for `write`: `"text\n"`, `\x41\x42`, or hex digits (`41 42 43`, `0x414243`).
pub fn parse_bytes(spec: &str) -> Result<Vec<u8>, String> {
    let spec = spec.trim();
    if spec.starts_with('"') || spec.contains("\\x") {
        return unescape(spec);
    }
    let h: String = spec.trim_start_matches("0x").chars().filter(|c| !c.is_whitespace()).collect();
    if h.is_empty() || h.len() % 2 != 0 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("bytes: give hex digits (41 42 43), a quoted string, or \\x escapes".into());
    }
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).map_err(|_| "bad hex".to_string()))
        .collect()
}

pub const HELP: &[&str] = &[
    "s | si          step one instruction",
    "n | ni          step over calls",
    "c               continue",
    "start           run to main (or the ELF entry if stripped)",
    "b <addr>        breakpoint: main | main.c:42 | main+4 | 0x401136 | *0x401136 | $rip+4",
    "d <addr>        delete breakpoint",
    "x [addr]        hexdump at addr (no arg: follow rsp); h/l select a byte for the data inspector",
    "tele [addr]     stack telescope at addr (no arg: follow rsp)",
    "vmmap [word]    memory map view (j/k scroll); with a word, list matching mappings in the log",
    "checksec        RELRO / canary / NX / PIE / fortify of the executable",
    "rop [filter]    ROP gadget search in the executable; rop pop rdi filters by text (5 or g to view)",
    "sections | segments | symtab [filter] | imports [filter] | strings [filter]   static ELF browser (6 or g to view, [ ] switch tab)",
    "cyclic <N> | cyclic send <N> | cyclic -l <leak>   De Bruijn pattern / crash-offset finder",
    "libc <path> <leaked symbol> [leaked addr]   offline: symbol offset, base/system/execve/\"/bin/sh\" if given an addr, + onegadget-lite candidates",
    "bt | finish         frame-pointer backtrace | run until the current function returns",
    "bookmark <addr|sym> <label> | bookmark del <addr> | bookmark   add/remove/list, saved to <exe>.dbgt-session",
    "note [@<addr|sym>] <text> | note   add a note (no @: attaches to current pc, or general) | list notes",
    "struct load <path> | struct list | struct clear | struct <Name> [@<addr>]   ImHex-style overlay on the hexdump",
    "find <pat> [in <mod>]   search memory: find /bin/sh | find u64 $rsp | find hex 4883ec in libc",
    "modules         list modules with symbols loaded (libc appears after ld.so maps it)",
    "sym <expr>      what symbol is at this address",
    "send <text>     type into the target (escapes \\n \\xHH); sendline adds a newline",
    "Tab / S-Tab     (keys) next / previous pane; f maximises the focused pane; ? this help",
    "goto <expr>     context command: Main = open function graph, Stack = tele, Hex = x",
    "follow [arg]    context command: Regs = hexdump a register, Stack = hexdump slot n, Hex = follow pointer",
    "clear           context command: Log = clear log, Target = reset terminal",
    "set $reg <expr> change a register (in the Regs pane just type: rax 0x41)",
    "write <addr> <bytes>   patch memory: write $rsp 41424344 | write buf \"hi\\n\" | write 0x401000 \\x90\\x90",
    "watch <addr> [1|2|4|8]   hardware watchpoint (stops when the value changes); no args lists them",
    "rwatch <addr> [len]      stop on any read or write      unwatch <n>   delete watchpoint n",
    "graph <sym>     show that function's CFG (u / Esc to go back)",
    "(pane keys are shown on the bottom line for the focused pane)",
    "<Enter>         repeat last command",
    "q               quit    (Ctrl-C interrupts a running target)",
];
