//! ROPgadget/ropper-style gadget search. Pure function over the bytes of an
//! executable section: no process, no ptrace. For every `ret` / indirect
//! `jmp`/`call` "tail" byte in the section, we try decoding forward from
//! every start offset within `max_len` bytes before it; a start offset
//! "works" if the instruction stream lands exactly on the tail with no
//! invalid instructions and no earlier control-flow transfer in between.
//! This is the same backward-decode approach ROPgadget and ropper use.

use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, NasmFormatter};

#[derive(Clone)]
pub struct Gadget {
    pub addr: u64,
    /// Instructions joined with " ; ", e.g. "pop rdi ; ret".
    pub text: String,
    pub len: usize,
}

/// One executable region to search: its bytes and the address of `bytes[0]`.
pub struct Region<'a> {
    pub base: u64,
    pub bytes: &'a [u8],
}

const MAX_BACK: usize = 12;
const MAX_INSNS: usize = 6;

/// Byte lengths of the "tail" instructions we anchor on, checked at each
/// position: ret (c3), ret imm16 (c2 xx xx), and the single-byte-ModRM forms
/// of `jmp`/`call` through a register (ff /4, ff /2 with a register operand,
/// encoded as a mod==11 ModRM byte, i.e. 0xc0..=0xff for reg 2 or 4).
fn tail_len_at(b: &[u8]) -> Option<usize> {
    match *b.first()? {
        0xc3 => Some(1),
        0xc2 => (b.len() >= 3).then_some(3),
        0xff => {
            let modrm = *b.get(1)?;
            let reg = (modrm >> 3) & 7;
            let is_reg_operand = modrm >> 6 == 0b11;
            (is_reg_operand && (reg == 2 || reg == 4)).then_some(2) // call/jmp reg
        }
        _ => None,
    }
}

/// Find every gadget ending in a `ret` or indirect `jmp`/`call` within
/// `region`. Results are sorted by address and deduplicated by address.
pub fn find_gadgets(region: &Region, limit: usize) -> (Vec<Gadget>, bool) {
    let Region { base, bytes } = *region;
    let mut out = Vec::new();
    let mut fmt = NasmFormatter::new();
    fmt.options_mut().set_space_after_operand_separator(true);

    'tails: for tail_off in 0..bytes.len() {
        let Some(tail_len) = tail_len_at(&bytes[tail_off..]) else { continue };
        let tail_end = tail_off + tail_len;

        for back in 1..=MAX_BACK.min(tail_off) {
            let start = tail_off - back;
            let start_ip = base + start as u64;
            let tail_ip = base + tail_end as u64;
            let mut dec = Decoder::with_ip(64, &bytes[start..tail_end], start_ip, DecoderOptions::NONE);
            let mut insns = Vec::new();
            let mut ok = true;
            while dec.can_decode() {
                if insns.len() >= MAX_INSNS {
                    ok = false;
                    break;
                }
                let ins = dec.decode();
                if ins.is_invalid() || ins.next_ip() > tail_ip {
                    ok = false;
                    break;
                }
                // Any earlier instruction that itself transfers control
                // breaks the gadget: only the final tail instruction may.
                let is_last = ins.next_ip() == tail_ip;
                if !is_last && !matches!(ins.flow_control(), FlowControl::Next) {
                    ok = false;
                    break;
                }
                insns.push(ins);
                if is_last {
                    break;
                }
            }
            if !ok || insns.last().map(|i| i.next_ip()) != Some(tail_ip) || insns.is_empty() {
                continue;
            }
            let text = insns
                .iter()
                .map(|ins| {
                    let mut s = String::new();
                    fmt.format(ins, &mut s);
                    s
                })
                .collect::<Vec<_>>()
                .join(" ; ");
            out.push(Gadget { addr: base + start as u64, text, len: tail_end - start });
            if out.len() >= limit {
                break 'tails;
            }
        }
    }
    out.sort_by_key(|g| g.addr);
    out.dedup_by_key(|g| g.addr);
    let truncated = out.len() >= limit;
    (out, truncated)
}
