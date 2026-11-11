//! Resource properties of TCP and below, on sessions built to stress them
//! (verification/README.md, "Resource properties"): fragment reassembly
//! under floods of tiny fragments, in and out of order, and of first
//! fragments that time out; UDP sockets under floods of tiny datagrams;
//! and the blocks a sandbox's packets arrive in. Every step is costed
//! with verification/resources/cost.rs: what is live at any moment stays
//! within the charge, and the bytes a step asks for stay linear in its
//! input. The bounds and their constants are in
//! verification/packet-udp/README.md, "Resource properties".

use std::net::{IpAddr, Ipv4Addr};

use fictionet::stdlib::network::ip::{self, Fields, Intake, Reassembly};
use fictionet::time::{Duration, Instant};
use fictionet::{Chunk, Packet};

use crate::cost::{Charged, Costs, Linear};

/// An IPv4 fragment from `src` with identification `id`: `data` at
/// `offset` bytes, with "more fragments" set when `more`.
fn fragment(src: u32, id: u16, offset: usize, more: bool, data: &[u8]) -> Chunk {
    let p = ip::packet_with(
        IpAddr::V4(Ipv4Addr::from(src)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        17,
        Fields {
            id,
            dont_fragment: false,
            ..Fields::default()
        },
        data,
    );
    let mut bytes = p.into_vec();
    let word = ((offset / 8) as u16) | if more { 0x2000 } else { 0 };
    bytes[6..8].copy_from_slice(&word.to_be_bytes());
    bytes[10..12].copy_from_slice(&[0, 0]);
    let sum = ip::checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&sum.to_be_bytes());
    Packet::new(bytes).into_chunk()
}

/// A step's linear bound. The packet the step takes in is built inside it,
/// as cost.rs asks, so that freeing it is the step's: its bytes and two
/// chunk headers (`fragment`). Then the fragment's data and the first
/// fragment's headers are copied once each, and they are disjoint parts
/// of the packet: two bytes asked for each byte of input in all. Besides,
/// an entry added to a `BTreeMap` may split a node at every level: three
/// trees (the packets, their deadlines, and a packet's pieces, or the
/// first fragments kept), at most 8 levels for the entries 4 MiB can
/// count, and at most 2 KiB a node.
const REASSEMBLY_STEP: Linear = Linear {
    num: 2,
    den: 1,
    fixed: 3 * 8 * 2048 + 2 * Chunk::HEADER,
};

/// What a step hands out, which its taker pays for when it takes it in:
/// a whole packet, or a first fragment kept for an answer, each in a chunk
/// of its own.
fn handed_out(chunk: &Chunk) -> usize {
    chunk.len() + Chunk::HEADER
}

/// One fragment for [`push`]: [`fragment`]'s arguments.
struct Frag<'a> {
    src: u32,
    id: u16,
    offset: usize,
    more: bool,
    data: &'a [u8],
}

/// Builds `f` and pushes it at `now` as one costed step: within
/// `Reassembly::MOST_HELD`, and linear in the packet.
fn push(costs: &mut Costs, r: &mut Reassembly, f: Frag<'_>, now: Instant) -> &'static str {
    let input = 20 + f.data.len();
    costs.step(input, Reassembly::MOST_HELD, REASSEMBLY_STEP, || {
        let packet = fragment(f.src, f.id, f.offset, f.more, f.data);
        let intake = r.push(packet, now);
        let (value, charged) = match &intake {
            Intake::Whole(whole) => ("whole", handed_out(whole)),
            Intake::Waiting => ("waiting", 0),
            Intake::Discarded => ("discarded", 0),
            Intake::Refused { packet, answer } => (
                "refused",
                handed_out(packet) + answer.as_ref().map_or(0, handed_out),
            ),
        };
        drop(intake);
        Charged {
            value,
            charged,
            moved: 0,
        }
    })
}

/// Expires what is due at `now` as one costed step. It copies nothing: it
/// moves each first fragment it keeps, and asks only for the nodes of the
/// map that keeps them, which their count covers. That count is never more
/// than their packets counted, so the step's input is what was counted
/// before it ([`Reassembly::counted`]), one byte asked for each at most.
fn expire(costs: &mut Costs, r: &mut Reassembly, now: Instant) {
    let counted = r.counted();
    let moved = Linear {
        num: 1,
        den: 1,
        fixed: 0,
    };
    costs.step(counted, Reassembly::MOST_HELD, moved, || {
        r.expire(now);
        Charged {
            value: (),
            charged: 0,
            moved: 0,
        }
    });
}

/// Expires what is due at `now`, then takes every first fragment kept, as
/// costed steps.
fn expire_and_take(costs: &mut Costs, r: &mut Reassembly, now: Instant) -> usize {
    expire(costs, r, now);
    let mut taken = 0;
    while costs.step(0, Reassembly::MOST_HELD, REASSEMBLY_STEP, || {
        let first = r.take_expired();
        let charged = first.as_ref().map_or(0, handed_out);
        Charged {
            value: first.is_some(),
            charged,
            moved: 0,
        }
    }) {
        taken += 1;
    }
    taken
}

fn at(secs: u64) -> Instant {
    Instant::from_since_start(Duration::from_secs(secs))
}

/// The cap's own work: more unfinished packets than 4 MiB can count, each
/// one fragment of eight bytes, so every one counts mostly bookkeeping.
#[test]
fn many_tiny_packets_stay_within_most_held() {
    let mut costs = Costs::new("tiny packets");
    let mut r = Reassembly::default();
    for i in 0..40_000u32 {
        let f = Frag {
            src: 0x0a00_0100 + (i >> 16),
            id: i as u16,
            offset: 8,
            more: true,
            data: &[7; 8],
        };
        assert_eq!(push(&mut costs, &mut r, f, at(0)), "waiting");
    }
    expire_and_take(&mut costs, &mut r, at(31));
    eprintln!("cost: tiny packets: {}", costs.summary());
}

/// Many pieces of eight bytes in each packet, with a gap after each so
/// that none completes, in three orders: ascending, descending, and the
/// even pieces up then the odd ones down.
#[test]
fn many_small_pieces_in_any_order_stay_within_most_held() {
    let pieces: Vec<usize> = (0..4000).map(|k| 8 + 16 * k).collect();
    let descending: Vec<usize> = pieces.iter().rev().copied().collect();
    let (even, odd): (Vec<usize>, Vec<usize>) = pieces.iter().partition(|o| (*o / 16) % 2 == 0);
    let interleaved: Vec<usize> = even.into_iter().chain(odd.into_iter().rev()).collect();
    for (name, order) in [
        ("ascending", pieces.clone()),
        ("descending", descending),
        ("interleaved", interleaved),
    ] {
        let mut costs = Costs::new(format!("pieces, {name}"));
        let mut r = Reassembly::default();
        for src in 0..20u32 {
            for &offset in &order {
                let f = Frag {
                    src: 0x0a00_0100 + src,
                    id: 1,
                    offset,
                    more: true,
                    data: &[7; 8],
                };
                push(&mut costs, &mut r, f, at(0));
            }
        }
        eprintln!("cost: pieces, {name}: {}", costs.summary());
    }
}

/// First fragments that time out are kept for their answers; with no one
/// taking them, new packets keep arriving, and the kept fragments count
/// against the cap with what keeps them.
#[test]
fn first_fragments_kept_for_answers_stay_within_most_held() {
    let mut costs = Costs::new("expired first fragments");
    let mut r = Reassembly::default();
    for round in 0..4u64 {
        for i in 0..20_000u32 {
            let src = 0x0a00_0100 + (round as u32) * 4 + (i >> 16);
            let f = Frag {
                src,
                id: i as u16,
                offset: 0,
                more: true,
                data: &[7; 8],
            };
            push(&mut costs, &mut r, f, at(40 * round));
        }
        expire(&mut costs, &mut r, at(40 * round + 31));
    }
    let taken = expire_and_take(&mut costs, &mut r, at(1000));
    assert!(taken > 0, "no first fragment was kept");
    eprintln!("cost: expired first fragments: {}", costs.summary());
}

/// Packets of 8,000 bytes sent as a thousand pieces of eight, shuffled:
/// each completes on its last piece and is handed out whole.
#[test]
fn packets_completed_from_small_pieces_stay_within_most_held() {
    let mut costs = Costs::new("completed from small pieces");
    let mut r = Reassembly::default();
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut whole = 0;
    for src in 0..20u32 {
        let mut offsets: Vec<usize> = (0..1000).map(|k| 8 * k).collect();
        for i in (1..offsets.len()).rev() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            offsets.swap(i, (state % (i as u64 + 1)) as usize);
        }
        for offset in offsets {
            let more = offset != 8 * 999;
            let data = [src as u8; 8];
            let f = Frag {
                src: 0x0a00_0100 + src,
                id: 9,
                offset,
                more,
                data: &data,
            };
            if push(&mut costs, &mut r, f, at(0)) == "whole" {
                whole += 1;
            }
        }
    }
    assert_eq!(whole, 20);
    eprintln!("cost: completed from small pieces: {}", costs.summary());
}
