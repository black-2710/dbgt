//! Basic-block recovery by recursive descent over a window of code bytes.

use super::disasm::Insn;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, NasmFormatter, OpKind};
use std::collections::{BTreeMap, BTreeSet, HashSet};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EdgeKind {
    /// Conditional branch not taken (r2's red `f`).
    False,
    /// Conditional branch taken (green `t`).
    True,
    /// Unconditional jump, or falling into a block that has other entries (blue).
    Jump,
}

pub struct Block {
    pub start: u64,
    /// One past the last byte.
    pub end: u64,
    pub insns: Vec<Insn>,
    pub succ: Vec<(u64, EdgeKind)>,
    /// Ends in an indirect jump whose targets we can't know statically.
    pub unresolved: bool,
}

pub struct Cfg {
    pub entry: u64,
    /// Sorted by `start`, non-overlapping.
    pub blocks: Vec<Block>,
    pub truncated: bool,
}

impl Cfg {
    pub fn is_block_start(&self, addr: u64) -> bool {
        self.blocks.binary_search_by_key(&addr, |b| b.start).is_ok()
    }

    /// Is there a recovered instruction exactly at `addr`?
    pub fn has_insn(&self, addr: u64) -> bool {
        let i = self.blocks.partition_point(|b| b.start <= addr);
        i > 0 && self.blocks[i - 1].insns.iter().any(|x| x.addr == addr)
    }
}

const MAX_INSNS: usize = 6000;

struct Rec {
    insn: Insn,
    flow: FlowControl,
    target: Option<u64>,
    next: u64,
}

/// `code` holds the bytes at `base..`. `entries` are the roots to descend from
/// (the first one becomes `Cfg::entry`). Calls are not followed.
pub fn build(code: &[u8], base: u64, entries: &[u64]) -> Cfg {
    let end = base + code.len() as u64;
    let in_win = |a: u64| a >= base && a < end;

    let mut fmt = NasmFormatter::new();
    fmt.options_mut().set_space_after_operand_separator(true);

    let mut recs: BTreeMap<u64, Rec> = BTreeMap::new();
    let mut leaders: BTreeSet<u64> = BTreeSet::new();
    let mut work: Vec<u64> = Vec::new();
    let mut truncated = false;

    for &e in entries {
        if in_win(e) {
            leaders.insert(e);
            work.push(e);
        }
    }

    while let Some(start) = work.pop() {
        let mut addr = start;
        loop {
            if !in_win(addr) || recs.contains_key(&addr) {
                break;
            }
            if recs.len() >= MAX_INSNS {
                truncated = true;
                break;
            }
            let off = (addr - base) as usize;
            let mut dec = Decoder::with_ip(64, &code[off..], addr, DecoderOptions::NONE);
            let ins = dec.decode();
            if ins.is_invalid() {
                break;
            }
            let len = ins.len();
            let mut text = String::new();
            fmt.format(&ins, &mut text);
            let target = match ins.op0_kind() {
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                    Some(ins.near_branch_target())
                }
                _ => None,
            };
            let flow = ins.flow_control();
            let next = ins.next_ip();
            recs.insert(
                addr,
                Rec {
                    insn: Insn { addr, bytes: code[off..off + len].to_vec(), text },
                    flow,
                    target,
                    next,
                },
            );

            match flow {
                FlowControl::Next
                | FlowControl::Call
                | FlowControl::IndirectCall
                | FlowControl::Interrupt
                | FlowControl::XbeginXabortXend => addr = next,
                FlowControl::UnconditionalBranch => {
                    if let Some(t) = target {
                        if in_win(t) {
                            leaders.insert(t);
                            work.push(t);
                        }
                    }
                    break;
                }
                FlowControl::ConditionalBranch => {
                    if let Some(t) = target {
                        if in_win(t) {
                            leaders.insert(t);
                            work.push(t);
                        }
                    }
                    leaders.insert(next);
                    work.push(next);
                    break;
                }
                _ => break, // ret, indirect jmp, ud2/hlt
            }
        }
    }

    // Group consecutive instructions into blocks.
    let mut blocks: Vec<Block> = Vec::new();
    let mut cur: Option<Block> = None; // a block that is still open (can fall through)
    for (addr, rec) in recs {
        let need_new = match &cur {
            None => true,
            Some(b) => leaders.contains(&addr) || b.end != addr,
        };
        if need_new {
            if let Some(mut b) = cur.take() {
                if b.end == addr {
                    b.succ.push((addr, EdgeKind::Jump)); // fell into a leader
                }
                blocks.push(b);
            }
            cur = Some(Block { start: addr, end: addr, insns: Vec::new(), succ: Vec::new(), unresolved: false });
        }
        let b = cur.as_mut().unwrap();
        b.end = rec.next;
        b.insns.push(rec.insn);

        let mut open = true;
        match rec.flow {
            FlowControl::ConditionalBranch => {
                if let Some(t) = rec.target {
                    b.succ.push((t, EdgeKind::True));
                }
                b.succ.push((rec.next, EdgeKind::False));
                open = false;
            }
            FlowControl::UnconditionalBranch => {
                if let Some(t) = rec.target {
                    b.succ.push((t, EdgeKind::Jump));
                }
                open = false;
            }
            FlowControl::IndirectBranch => {
                b.unresolved = true;
                open = false;
            }
            FlowControl::Return | FlowControl::Exception => open = false,
            _ => {}
        }
        if !open {
            blocks.push(cur.take().unwrap());
        }
    }
    if let Some(b) = cur.take() {
        blocks.push(b);
    }

    // Drop edges that leave the recovered code (tail calls, unmapped targets...).
    let starts: HashSet<u64> = blocks.iter().map(|b| b.start).collect();
    for b in &mut blocks {
        b.succ.retain(|(t, _)| starts.contains(t));
    }

    Cfg { entry: entries.first().copied().unwrap_or(0), blocks, truncated }
}
