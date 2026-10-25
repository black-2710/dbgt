//! DWARF line tables -> address <-> (source file, line), flattened into plain data
//! so it can be cloned and shared between threads.

use anyhow::Result;
use object::{Object, ObjectSection};
use std::{borrow::Cow, collections::HashMap, path::PathBuf};

#[derive(Clone, Copy)]
struct Row {
    addr: u64,
    file: u32,
    /// 0 marks the end of a sequence (no line info beyond this address).
    line: u32,
}

#[derive(Clone, Default)]
pub struct Lines {
    files: Vec<String>,
    index: HashMap<String, u32>,
    /// Sorted by address.
    rows: Vec<Row>,
}

fn file_path<R: gimli::Reader>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    lh: &gimli::LineProgramHeader<R>,
    index: u64,
) -> Option<String> {
    let entry = lh.file(index)?;
    let mut p = PathBuf::new();
    if let Some(d) = &unit.comp_dir {
        p.push(&*d.to_string_lossy().ok()?);
    }
    if let Some(dir) = entry.directory(lh) {
        let s = dwarf.attr_string(unit, dir).ok()?;
        p.push(&*s.to_string_lossy().ok()?); // an absolute dir replaces comp_dir
    }
    let name = dwarf.attr_string(unit, entry.path_name()).ok()?;
    p.push(&*name.to_string_lossy().ok()?);
    Some(p.to_string_lossy().into_owned())
}

impl Lines {
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    fn intern(&mut self, name: String) -> u32 {
        if let Some(&i) = self.index.get(&name) {
            return i;
        }
        let i = self.files.len() as u32;
        self.files.push(name.clone());
        self.index.insert(name, i);
        i
    }

    /// Reads every compilation unit's line program. Returns the number of rows added.
    pub fn add_module(&mut self, file: &object::File, bias: u64) -> Result<usize> {
        if file.section_by_name(".debug_line").is_none() {
            return Ok(0);
        }
        let endian = if file.is_little_endian() {
            gimli::RunTimeEndian::Little
        } else {
            gimli::RunTimeEndian::Big
        };
        let load = |id: gimli::SectionId| -> Result<Cow<[u8]>, gimli::Error> {
            Ok(match file.section_by_name(id.name()) {
                Some(s) => s.uncompressed_data().unwrap_or(Cow::Borrowed(&[][..])),
                None => Cow::Borrowed(&[][..]),
            })
        };
        let dwarf_cow = gimli::Dwarf::load(&load)?;
        let dwarf = dwarf_cow.borrow(|section| gimli::EndianSlice::new(&*section, endian));

        let before = self.rows.len();
        let mut units = dwarf.units();
        while let Some(header) = units.next()? {
            let unit = dwarf.unit(header)?;
            let Some(program) = unit.line_program.clone() else { continue };
            let mut rows = program.rows();
            let mut fmap: HashMap<u64, u32> = HashMap::new();
            let mut in_seq = false;
            let mut skip = false;
            while let Some((lh, row)) = rows.next_row()? {
                if row.end_sequence() {
                    if in_seq && !skip {
                        self.rows.push(Row { addr: row.address() + bias, file: 0, line: 0 });
                    }
                    in_seq = false;
                    skip = false;
                    continue;
                }
                if !in_seq {
                    in_seq = true;
                    skip = row.address() == 0; // code the linker discarded
                }
                if skip || !row.is_stmt() {
                    continue;
                }
                let Some(line) = row.line() else { continue };
                let fi = row.file_index();
                let idx = match fmap.get(&fi) {
                    Some(&i) => i,
                    None => {
                        let name = file_path(&dwarf, &unit, lh, fi).unwrap_or_else(|| format!("?{fi}"));
                        let i = self.intern(name);
                        fmap.insert(fi, i);
                        i
                    }
                };
                self.rows.push(Row { addr: row.address() + bias, file: idx, line: line.get() as u32 });
            }
        }
        self.rows.sort_by_key(|r| r.addr); // stable: later rows at the same address win
        Ok(self.rows.len() - before)
    }

    /// (full source path, line) for the code at `addr`.
    pub fn lookup(&self, addr: u64) -> Option<(&str, u32)> {
        let i = self.rows.partition_point(|r| r.addr <= addr);
        let r = *self.rows.get(i.checked_sub(1)?)?;
        if r.line == 0 {
            return None;
        }
        Some((self.files[r.file as usize].as_str(), r.line))
    }

    /// Address for `file:line` (file may be just a base name). If that exact line has
    /// no code, falls forward to the next line that does, like gdb.
    pub fn resolve(&self, file: &str, line: u32) -> Option<u64> {
        let suffix = format!("/{file}");
        let ok: Vec<bool> = self.files.iter().map(|f| f == file || f.ends_with(&suffix)).collect();
        let mut best: Option<(u32, u64)> = None;
        for r in &self.rows {
            if r.line == 0 || r.line < line || !ok[r.file as usize] {
                continue;
            }
            best = match best {
                None => Some((r.line, r.addr)),
                Some((bl, ba)) if r.line < bl || (r.line == bl && r.addr < ba) => Some((r.line, r.addr)),
                keep => keep,
            };
        }
        best.map(|b| b.1)
    }
}
