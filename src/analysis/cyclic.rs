//! `cyclic` / `cyclic -l`: a De Bruijn sequence over the lowercase alphabet
//! with subsequence length 4 (pwntools' defaults). Every 4-byte run in the
//! sequence is unique, so once a crash overwrites RIP (or anything else)
//! with 4 bytes out of the pattern, the position of that 4-byte run is
//! exactly how many bytes of padding preceded it.

const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const SUBLEN: usize = 4;
/// 26^4: the whole sequence repeats after this many bytes.
const PERIOD: usize = 26 * 26 * 26 * 26;

/// Duval's algorithm for a De Bruijn sequence B(k, n), same construction pwntools uses.
fn de_bruijn(alphabet: &[u8], n: usize) -> Vec<u8> {
    let k = alphabet.len();
    let mut a = vec![0usize; n + 1];
    let mut seq = Vec::with_capacity(k.pow(n as u32));
    db(1, 1, n, k, &mut a, &mut seq, alphabet);
    seq
}

fn db(t: usize, p: usize, n: usize, k: usize, a: &mut [usize], seq: &mut Vec<u8>, alphabet: &[u8]) {
    if t > n {
        if n % p == 0 {
            seq.extend(a[1..=p].iter().map(|&i| alphabet[i]));
        }
        return;
    }
    a[t] = a[t - p];
    db(t + 1, p, n, k, a, seq, alphabet);
    for j in (a[t - p] + 1)..k {
        a[t] = j;
        db(t + 1, t, n, k, a, seq, alphabet);
    }
}

/// `len` bytes of the pattern. Lengths beyond the 456,976-byte period repeat
/// the sequence (and stop being unique past the first repeat; `truncated`
/// warns the caller of that, matching pwntools' behaviour).
pub fn generate(len: usize) -> (Vec<u8>, bool) {
    let full = de_bruijn(ALPHABET, SUBLEN);
    debug_assert_eq!(full.len(), PERIOD);
    if len <= full.len() {
        (full[..len].to_vec(), false)
    } else {
        (full.iter().cycle().take(len).copied().collect(), true)
    }
}

/// Offset of `needle` in the (single-period) pattern, if it appears there.
pub fn find(needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    let full = de_bruijn(ALPHABET, SUBLEN);
    full.windows(needle.len()).position(|w| w == needle)
}

/// Parse what `cyclic -l` is usually given: a leaked word like `0x6161616c`
/// (its bytes, little-endian — this is what ends up in a register) or a
/// literal string like `laaa` (its ASCII bytes, as-is).
pub fn parse_leak(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if hex.is_empty() || hex.len() > 16 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("bad hex value: {s}"));
        }
        let nbytes = (hex.len() + 1) / 2;
        let padded = format!("{hex:0>16}");
        let v = u64::from_str_radix(&padded, 16).map_err(|_| format!("bad hex value: {s}"))?;
        Ok(v.to_le_bytes()[..nbytes].to_vec())
    } else if s.is_empty() {
        Err("usage: cyclic -l <leaked value>   e.g. cyclic -l 0x6161616c | cyclic -l laaa".into())
    } else {
        Ok(s.as_bytes().to_vec())
    }
}
