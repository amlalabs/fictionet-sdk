//! IPv4 and IPv6 fragment reassembly (`ip::split_protocols`), with
//! fragments the agent chooses: offsets, lengths, overlaps, duplicates,
//! the "more fragments" flag, timing, and raw bytes.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Piece {
    /// An IPv4 fragment.
    V4 {
        id: u8,
        src: u8,
        proto: u8,
        offset: u16,
        len: u16,
        more: bool,
        df: bool,
        options: u8,
    },
    /// An IPv6 fragment, with extension headers before the fragment header.
    V6 {
        id: u8,
        src: u8,
        offset: u16,
        len: u16,
        more: bool,
        before: Vec<u8>,
        next: u8,
    },
    /// Any bytes.
    Raw(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
struct Step {
    /// Milliseconds since the step before.
    wait: u16,
    piece: Piece,
}

#[allow(clippy::too_many_arguments)]
fn v4(
    id: u8,
    src: u8,
    proto: u8,
    offset: u16,
    len: u16,
    more: bool,
    df: bool,
    options: u8,
) -> Vec<u8> {
    let opts = (options % 11) as usize * 4;
    let ihl = 20 + opts;
    let len = len as usize % 1500;
    let total = (ihl + len).min(65_535);
    let mut p = vec![0u8; ihl];
    p[0] = 0x40 | (ihl / 4) as u8;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[4..6].copy_from_slice(&(id as u16).to_be_bytes());
    let frag = (offset & 0x1fff) | if more { 0x2000 } else { 0 } | if df { 0x4000 } else { 0 };
    p[6..8].copy_from_slice(&frag.to_be_bytes());
    p[8] = 64;
    p[9] = proto;
    p[12..16].copy_from_slice(&[10, 0, 0, src % 4]);
    p[16..20].copy_from_slice(&[10, 0, 0, 1]);
    for b in &mut p[20..] {
        *b = 1;
    }
    p.extend((0..total - ihl).map(|i| i as u8));
    p
}

fn v6(id: u8, src: u8, offset: u16, len: u16, more: bool, before: &[u8], next: u8) -> Vec<u8> {
    // Extension headers before the fragment header: each byte picks one.
    let mut ext = Vec::new();
    let mut first = 44u8;
    let mut kinds: Vec<u8> = before
        .iter()
        .take(4)
        .map(|b| [0u8, 43, 60, 51][*b as usize % 4])
        .collect();
    if let Some(&k) = kinds.first() {
        first = k;
    }
    kinds.push(44);
    for w in kinds.windows(2) {
        let (kind, after) = (w[0], w[1]);
        if kind == 51 {
            // Authentication header: (len + 2) * 4 bytes.
            ext.extend_from_slice(&[after, 0, 0, 0, 0, 0, 0, 0]);
        } else {
            ext.extend_from_slice(&[after, 0, 1, 4, 0, 0, 0, 0]);
        }
    }
    let len = len as usize % 1500;
    let mut frag = vec![next, 0];
    frag.extend_from_slice(&((offset << 3) | more as u16).to_be_bytes());
    frag.extend_from_slice(&(id as u32).to_be_bytes());
    let plen = ext.len() + 8 + len;
    let mut p = vec![0x60, 0, 0, 0];
    p.extend_from_slice(&(plen as u16).to_be_bytes());
    p.push(first);
    p.push(64);
    let mut a = [0u8; 16];
    a[0] = 0xfd;
    a[15] = src % 4;
    p.extend_from_slice(&a);
    a[15] = 0xff;
    p.extend_from_slice(&a);
    p.extend_from_slice(&ext);
    p.extend_from_slice(&frag);
    p.extend((0..len).map(|i| i as u8));
    p
}

fuzz_target!(|steps: Vec<Step>| {
    let mut ms = 0u64;
    let packets = steps.into_iter().map(|s| {
        ms += s.wait as u64;
        let bytes = match s.piece {
            Piece::V4 {
                id,
                src,
                proto,
                offset,
                len,
                more,
                df,
                options,
            } => v4(id, src, proto, offset, len, more, df, options),
            Piece::V6 {
                id,
                src,
                offset,
                len,
                more,
                before,
                next,
            } => v6(id, src, offset, len, more, &before, next),
            Piece::Raw(b) => b,
        };
        (ms, bytes)
    });
    for p in fictionet::fuzzing::reassemble(packets) {
        // A whole packet sorts without trouble, and its header gives its
        // true length: no IP packet is longer than its length field can say.
        let _ = fictionet::fuzzing::sort(&p.0);
        let said = match p.0[0] >> 4 {
            4 => u16::from_be_bytes([p.0[2], p.0[3]]) as usize,
            _ => 40 + u16::from_be_bytes([p.0[4], p.0[5]]) as usize,
        };
        assert_eq!(said, p.0.len(), "the header says {said} bytes");
    }
});
