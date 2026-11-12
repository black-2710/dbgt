//! Bookmarks and notes, persisted next to the target executable so they
//! survive between dbgt runs. Deliberately a small hand-rolled text format
//! rather than pulling in a serialization crate — consistent with how the
//! rest of dbgt hand-parses ELF/DWARF instead of adding dependencies for it,
//! and it means the file is readable/editable without dbgt.
//!
//! Format (one record per line, blank lines and `#` comments ignored):
//!   bookmark <addr> <label...>
//!   note <addr-or- -> <text...>

use std::fmt::Write as _;
use std::path::PathBuf;

pub struct Bookmark {
    pub addr: u64,
    pub label: String,
}

pub struct Note {
    pub addr: Option<u64>,
    pub text: String,
}

#[derive(Default)]
pub struct Session {
    pub bookmarks: Vec<Bookmark>,
    pub notes: Vec<Note>,
    path: Option<PathBuf>,
}

impl Session {
    pub fn path_for(exe: &str) -> PathBuf {
        PathBuf::from(format!("{exe}.dbgt-session"))
    }

    /// Load the session file next to `exe`. Missing or unreadable is not an
    /// error: it just means an empty session that will be created on first save.
    pub fn load(exe: &str) -> Session {
        let path = Self::path_for(exe);
        let mut s = Session { path: Some(path.clone()), ..Default::default() };
        let Ok(text) = std::fs::read_to_string(&path) else { return s };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((head, rest)) = line.split_once(char::is_whitespace) else { continue };
            let rest = rest.trim();
            match head {
                "bookmark" => {
                    if let Some((a, label)) = rest.split_once(char::is_whitespace) {
                        if let Ok(addr) = parse_hex(a) {
                            s.bookmarks.push(Bookmark { addr, label: label.trim().to_string() });
                        }
                    }
                }
                "note" => {
                    if let Some((a, text)) = rest.split_once(char::is_whitespace) {
                        s.notes.push(Note { addr: parse_hex(a).ok(), text: text.trim().to_string() });
                    }
                }
                _ => {}
            }
        }
        s.bookmarks.sort_by_key(|b| b.addr);
        s
    }

    fn save(&self) {
        let Some(path) = &self.path else { return };
        let mut out = String::new();
        let _ = writeln!(out, "# dbgt session — bookmarks and notes (edit by hand if you like)");
        for b in &self.bookmarks {
            let _ = writeln!(out, "bookmark {:#x} {}", b.addr, b.label);
        }
        for n in &self.notes {
            match n.addr {
                Some(a) => {
                    let _ = writeln!(out, "note {a:#x} {}", n.text);
                }
                None => {
                    let _ = writeln!(out, "note - {}", n.text);
                }
            }
        }
        let _ = std::fs::write(path, out); // best-effort: a failed save shouldn't crash the session
    }

    /// Add, or relabel if one already exists at this address.
    pub fn add_bookmark(&mut self, addr: u64, label: String) {
        self.bookmarks.retain(|b| b.addr != addr);
        self.bookmarks.push(Bookmark { addr, label });
        self.bookmarks.sort_by_key(|b| b.addr);
        self.save();
    }

    pub fn remove_bookmark(&mut self, addr: u64) -> bool {
        let before = self.bookmarks.len();
        self.bookmarks.retain(|b| b.addr != addr);
        let changed = self.bookmarks.len() != before;
        if changed {
            self.save();
        }
        changed
    }

    pub fn add_note(&mut self, addr: Option<u64>, text: String) {
        self.notes.push(Note { addr, text });
        self.save();
    }

    pub fn bookmark_at(&self, addr: u64) -> Option<&str> {
        self.bookmarks.iter().find(|b| b.addr == addr).map(|b| b.label.as_str())
    }
}

fn parse_hex(s: &str) -> Result<u64, ()> {
    let s = s.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u64::from_str_radix(s, 16).map_err(|_| ())
}
