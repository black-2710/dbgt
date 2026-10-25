use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, NasmFormatter};

pub struct Insn {
    pub addr: u64,
    pub bytes: Vec<u8>,
    pub text: String,
}

/// Linear disassembly of `code` (which lives at `ip`), at most `max` instructions.
impl Insn {
    /// Direct target of a `call 0x...` instruction (not `call rax` / `call [mem]`).
    pub fn call_target(&self) -> Option<u64> {
        let mut w = self.text.split_whitespace();
        if w.next()? != "call" {
            return None;
        }
        let tok = w.last()?;
        u64::from_str_radix(tok.strip_prefix("0x")?, 16).ok()
    }
}

pub fn disasm(code: &[u8], ip: u64, max: usize) -> Vec<Insn> {
    let mut dec = Decoder::with_ip(64, code, ip, DecoderOptions::NONE);
    let mut fmt = NasmFormatter::new();
    fmt.options_mut().set_space_after_operand_separator(true);

    let mut out = Vec::new();
    while dec.can_decode() && out.len() < max {
        let ins = dec.decode();
        let off = ins.ip().wrapping_sub(ip) as usize;
        let end = (off + ins.len()).min(code.len());
        let mut text = String::new();
        if ins.is_invalid() {
            text.push_str("(bad)");
        } else {
            fmt.format(&ins, &mut text);
        }
        out.push(Insn {
            addr: ins.ip(),
            bytes: code[off..end].to_vec(),
            text,
        });
    }
    out
}

/// If the instruction at `ip` is a call, return the address right after it
/// (where execution resumes once the callee returns). Used by `ni`.
pub fn call_return_addr(code: &[u8], ip: u64) -> Option<u64> {
    let mut dec = Decoder::with_ip(64, code, ip, DecoderOptions::NONE);
    let ins = dec.decode();
    if !ins.is_invalid() && ins.flow_control() == FlowControl::Call {
        Some(ins.next_ip())
    } else {
        None
    }
}
