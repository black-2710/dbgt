use super::lines::Lines;
use anyhow::Result;
use iced_x86::{Decoder, DecoderOptions, Mnemonic};
use object::{Object, ObjectKind, ObjectSection, ObjectSymbol, RelocationTarget, SymbolKind};
use std::collections::{BTreeMap, HashMap};

#[derive(Clone)]
pub struct ModInfo {
    pub name: String,
    pub base: u64,
    pub count: usize,
    /// DWARF line-table rows loaded from this module.
    pub lines: usize,
}

/// Function symbols from the main executable and every mapped shared object,
/// at runtime addresses. Also synthesises `name@plt` entries for PLT stubs.
#[derive(Clone, Default)]
pub struct Symbols {
    by_addr: BTreeMap<u64, (String, u64)>,
    by_name: HashMap<String, u64>,
    /// Sizes of data symbols (to pick a watchpoint length).
    sizes: HashMap<String, u64>,
    pub mods: Vec<ModInfo>,
    lines: Lines,
    /// Entry point of the main executable.
    pub entry: u64,
}

/// Prefer public-looking names when several symbols share an address.
fn score(n: &str) -> (bool, usize) {
    (n.starts_with('_'), n.len())
}

impl Symbols {
    /// `base` = lowest mapping of the module; only applied to ET_DYN files
    /// (PIE executables and shared objects). Returns the number of symbols added.
    pub fn add_module(&mut self, name: &str, data: &[u8], base: u64, is_main: bool) -> Result<usize> {
        let file = object::File::parse(data)?;
        let bias = if file.kind() == ObjectKind::Dynamic { base } else { 0 };
        if is_main {
            self.entry = file.entry() + bias;
        }
        let mut count = 0;
        for sym in file.symbols().chain(file.dynamic_symbols()) {
            if sym.address() == 0 {
                continue;
            }
            let Ok(n) = sym.name() else { continue };
            if n.is_empty() {
                continue;
            }
            match sym.kind() {
                SymbolKind::Text => {
                    self.insert(n, sym.address() + bias, sym.size());
                    count += 1;
                }
                // Globals: resolvable by name (watch flag, x &buf) but not used for <sym+off> labels.
                SymbolKind::Data => {
                    self.by_name.entry(n.to_string()).or_insert(sym.address() + bias);
                    self.sizes.entry(n.to_string()).or_insert(sym.size());
                }
                _ => {}
            }
        }
        count += self.add_plt(&file, bias);
        let nlines = self.lines.add_module(&file, bias).unwrap_or(0);
        self.mods.push(ModInfo { name: name.to_string(), base, count, lines: nlines });
        Ok(count)
    }

    fn insert(&mut self, name: &str, addr: u64, size: u64) {
        self.by_name.entry(name.to_string()).or_insert(addr);
        match self.by_addr.get_mut(&addr) {
            Some((old, osz)) => {
                if score(name) < score(old) {
                    *old = name.to_string();
                }
                if size > *osz {
                    *osz = size;
                }
            }
            None => {
                self.by_addr.insert(addr, (name.to_string(), size));
            }
        }
    }

    /// Name PLT stubs by following their `jmp [rip+GOT]` to the relocation that
    /// fills that GOT slot (works for .plt, .plt.sec and .plt.got, with or without IBT).
    fn add_plt(&mut self, file: &object::File, bias: u64) -> usize {
        let mut dynsyms: HashMap<usize, String> = HashMap::new();
        for s in file.dynamic_symbols() {
            if let Ok(n) = s.name() {
                if !n.is_empty() {
                    dynsyms.insert(s.index().0, n.to_string());
                }
            }
        }
        let mut got: HashMap<u64, String> = HashMap::new();
        if let Some(relocs) = file.dynamic_relocations() {
            for (off, r) in relocs {
                if let RelocationTarget::Symbol(i) = r.target() {
                    if let Some(n) = dynsyms.get(&i.0) {
                        got.insert(off + bias, n.clone());
                    }
                }
            }
        }
        if got.is_empty() {
            return 0;
        }

        let mut count = 0;
        for (sec_name, stride) in [(".plt", 16usize), (".plt.sec", 16), (".plt.got", 8)] {
            let Some(sec) = file.section_by_name(sec_name) else { continue };
            let Ok(data) = sec.data() else { continue };
            let sbase = sec.address() + bias;
            for (i, chunk) in data.chunks(stride).enumerate() {
                let addr = sbase + (i * stride) as u64;
                let mut dec = Decoder::with_ip(64, chunk, addr, DecoderOptions::NONE);
                while dec.can_decode() {
                    let ins = dec.decode();
                    if ins.is_invalid() {
                        break;
                    }
                    if ins.mnemonic() == Mnemonic::Jmp && ins.is_ip_rel_memory_operand() {
                        if let Some(n) = got.get(&ins.ip_rel_memory_address()) {
                            self.insert(&format!("{n}@plt"), addr, stride as u64);
                            count += 1;
                        }
                        break;
                    }
                }
            }
        }
        count
    }

    /// Size in bytes of a data symbol, if it's 1, 2, 4 or 8 (usable as a watch length).
    pub fn data_size(&self, name: &str) -> Option<usize> {
        self.sizes.get(name).copied().filter(|n| matches!(n, 1 | 2 | 4 | 8)).map(|n| n as usize)
    }

    pub fn addr(&self, name: &str) -> Option<u64> {
        self.by_name.get(name).copied()
    }

    /// Symbol containing `addr`, with the offset into it.
    pub fn lookup(&self, addr: u64) -> Option<(&str, u64)> {
        let (a, (name, size)) = self.by_addr.range(..=addr).next_back()?;
        let off = addr - a;
        if (*size > 0 && off < *size) || (*size == 0 && off < 0x40) {
            Some((name.as_str(), off))
        } else {
            None
        }
    }

    /// (start, size) of the function containing `addr`; size 0x800 if unknown.
    pub fn func_range(&self, addr: u64) -> Option<(u64, u64)> {
        let (a, (_, size)) = self.by_addr.range(..=addr).next_back()?;
        let off = addr - a;
        if (*size > 0 && off < *size) || (*size == 0 && off < 0x40) {
            Some((*a, if *size > 0 { *size } else { 0x800 }))
        } else {
            None
        }
    }

    /// (source path, line) for the code at `addr`, if the module had DWARF line info.
    pub fn line(&self, addr: u64) -> Option<(&str, u32)> {
        self.lines.lookup(addr)
    }

    pub fn resolve_line(&self, file: &str, line: u32) -> Option<u64> {
        self.lines.resolve(file, line)
    }

    pub fn has_lines(&self) -> bool {
        !self.lines.is_empty()
    }

    pub fn is_empty(&self) -> bool {
        self.by_addr.is_empty()
    }
}

/// `/home/me/pwn/main.c` -> `main.c`
pub fn short(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}
