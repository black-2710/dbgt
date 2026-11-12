//! ImHex-style structure overlay. A small C-like definition language:
//!
//!   struct Header {
//!       u32 magic;
//!       u16 version;
//!       char name[16];
//!   }
//!
//! Loaded from a text file with `struct load <path>`, applied to bytes at
//! the hexdump cursor with `struct <Name>`. v1 scope, stated plainly:
//! fixed-size fields only (`char[N]`/`bytes[N]` arrays; no arrays of
//! scalars, no nested structs, no bitfields) and it only decodes bytes
//! already visible in the hexdump pane — it doesn't do a separate memory
//! read, so `struct <Name> @<addr>` moves the hexdump there first.

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
    /// Fixed-size byte run shown as a (NUL-trimmed) string.
    Char(usize),
    /// Fixed-size byte run shown as hex.
    Bytes(usize),
}

impl FieldType {
    pub fn size(self) -> usize {
        match self {
            FieldType::U8 | FieldType::I8 => 1,
            FieldType::U16 | FieldType::I16 => 2,
            FieldType::U32 | FieldType::I32 | FieldType::F32 => 4,
            FieldType::U64 | FieldType::I64 | FieldType::F64 => 8,
            FieldType::Char(n) | FieldType::Bytes(n) => n,
        }
    }
    pub fn label(self) -> String {
        match self {
            FieldType::U8 => "u8".into(),
            FieldType::U16 => "u16".into(),
            FieldType::U32 => "u32".into(),
            FieldType::U64 => "u64".into(),
            FieldType::I8 => "i8".into(),
            FieldType::I16 => "i16".into(),
            FieldType::I32 => "i32".into(),
            FieldType::I64 => "i64".into(),
            FieldType::F32 => "f32".into(),
            FieldType::F64 => "f64".into(),
            FieldType::Char(n) => format!("char[{n}]"),
            FieldType::Bytes(n) => format!("bytes[{n}]"),
        }
    }
}

pub struct Field {
    pub name: String,
    pub ty: FieldType,
    pub offset: usize,
}

pub struct StructDef {
    pub name: String,
    pub fields: Vec<Field>,
    pub size: usize,
}

pub struct FieldView {
    pub addr: u64,
    pub name: String,
    pub ty_label: String,
    pub value: String,
}

/// Parse every `struct Name { ... }` block in `text`.
pub fn parse(text: &str) -> Result<Vec<StructDef>, String> {
    let mut out = Vec::new();
    let mut rest = text;
    loop {
        rest = rest.trim_start();
        if rest.is_empty() {
            break;
        }
        if let Some(after) = rest.strip_prefix("//") {
            rest = after.splitn(2, '\n').nth(1).unwrap_or("");
            continue;
        }
        let Some(after_kw) = rest.strip_prefix("struct") else {
            return Err(format!("expected 'struct', found: {:.30}", rest));
        };
        let after_kw = after_kw.trim_start();
        let name_end = after_kw.find(|c: char| c.is_whitespace() || c == '{').ok_or("expected a struct name")?;
        let name = after_kw[..name_end].trim().to_string();
        if name.is_empty() {
            return Err("expected a struct name".into());
        }
        let after_name = after_kw[name_end..].trim_start();
        let body_start = after_name.strip_prefix('{').ok_or_else(|| format!("expected '{{' after 'struct {name}'"))?;
        let close = body_start.find('}').ok_or_else(|| format!("missing closing '}}' for 'struct {name}'"))?;
        let body = &body_start[..close];
        rest = body_start[close + 1..].trim_start().strip_prefix(';').unwrap_or(body_start[close + 1..].trim_start());

        let mut fields = Vec::new();
        let mut offset = 0usize;
        for raw in body.split(';') {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let ty_tok = parts.next().ok_or_else(|| format!("'{name}': expected a field type"))?;
            let name_tok: String = parts.collect::<Vec<_>>().join(" ");
            if name_tok.is_empty() {
                return Err(format!("'{name}': field with no name ({line})"));
            }
            let (field_name, ty) = parse_field(ty_tok, &name_tok).map_err(|e| format!("'{name}': {e}"))?;
            fields.push(Field { name: field_name, ty, offset });
            offset += ty.size();
        }
        if fields.is_empty() {
            return Err(format!("'{name}': no fields"));
        }
        out.push(StructDef { name, size: offset, fields });
    }
    if out.is_empty() {
        return Err("no 'struct Name { ... }' blocks found".into());
    }
    Ok(out)
}

fn parse_field(ty_tok: &str, name_tok: &str) -> Result<(String, FieldType), String> {
    let (name, arr) = match name_tok.find('[') {
        Some(i) => {
            let n = name_tok[..i].trim();
            let after = &name_tok[i + 1..];
            let close = after.find(']').ok_or_else(|| format!("missing ']' in '{name_tok}'"))?;
            let count: usize = after[..close].trim().parse().map_err(|_| format!("bad array size in '{name_tok}'"))?;
            if count == 0 {
                return Err(format!("array size 0 in '{name_tok}'"));
            }
            (n.to_string(), Some(count))
        }
        None => (name_tok.trim().to_string(), None),
    };
    if name.is_empty() {
        return Err(format!("missing field name before '{name_tok}'"));
    }
    let ty = match ty_tok {
        "u8" | "uint8" | "byte" => FieldType::U8,
        "u16" | "uint16" | "word" => FieldType::U16,
        "u32" | "uint32" | "dword" => FieldType::U32,
        "u64" | "uint64" | "qword" | "ptr" | "addr" => FieldType::U64,
        "i8" | "int8" => FieldType::I8,
        "i16" | "int16" => FieldType::I16,
        "i32" | "int32" => FieldType::I32,
        "i64" | "int64" => FieldType::I64,
        "f32" | "float" => FieldType::F32,
        "f64" | "double" => FieldType::F64,
        "char" => FieldType::Char(arr.unwrap_or(1)),
        "bytes" | "hex" => FieldType::Bytes(arr.unwrap_or(1)),
        other => return Err(format!("unknown field type '{other}'")),
    };
    if arr.is_some() && !matches!(ty, FieldType::Char(_) | FieldType::Bytes(_)) {
        return Err(format!("'{ty_tok} {name_tok}': arrays are only supported for char[N]/bytes[N] (v1 limitation)"));
    }
    Ok((name, ty))
}

/// Decode `def` out of `bytes` (which must start at `base_addr`). A field
/// whose range runs past the end of `bytes` is reported as out of range
/// rather than panicking or reading garbage.
pub fn decode(def: &StructDef, base_addr: u64, bytes: &[u8]) -> Vec<FieldView> {
    def.fields
        .iter()
        .map(|f| {
            let end = f.offset + f.ty.size();
            let value = if end > bytes.len() {
                "?? (past the end of the visible bytes)".to_string()
            } else {
                format_value(f.ty, &bytes[f.offset..end])
            };
            FieldView { addr: base_addr + f.offset as u64, name: f.name.clone(), ty_label: f.ty.label(), value }
        })
        .collect()
}

fn format_value(ty: FieldType, b: &[u8]) -> String {
    match ty {
        FieldType::U8 => format!("{} ({:#04x})", b[0], b[0]),
        FieldType::I8 => format!("{}", b[0] as i8),
        FieldType::U16 => {
            let v = u16::from_le_bytes([b[0], b[1]]);
            format!("{v} ({v:#06x})")
        }
        FieldType::I16 => format!("{}", u16::from_le_bytes([b[0], b[1]]) as i16),
        FieldType::U32 => {
            let v = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            format!("{v} ({v:#010x})")
        }
        FieldType::I32 => format!("{}", u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as i32),
        FieldType::U64 => {
            let v = u64::from_le_bytes(b.try_into().unwrap());
            format!("{v} ({v:#018x})")
        }
        FieldType::I64 => format!("{}", u64::from_le_bytes(b.try_into().unwrap()) as i64),
        FieldType::F32 => format!("{}", f32::from_le_bytes([b[0], b[1], b[2], b[3]])),
        FieldType::F64 => format!("{}", f64::from_le_bytes(b.try_into().unwrap())),
        FieldType::Char(_) => {
            let s: String = b.iter().take_while(|&&c| c != 0).map(|&c| if (0x20..0x7f).contains(&c) { c as char } else { '.' }).collect();
            format!("\"{s}\"")
        }
        FieldType::Bytes(_) => b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" "),
    }
}
