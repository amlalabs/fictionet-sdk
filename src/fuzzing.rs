//! Entry points for the fuzz targets in `fuzz/`, into code that is not
//! public. Built only under `cfg(fuzzing)`, which `cargo fuzz` sets. Not
//! part of the API.

use crate::stdlib::network::ip::{Intake, Reassembly};
use crate::stdlib::network::packet::Sort;
use crate::time::{Duration, Instant};
use crate::{Chunk, Packet};

/// Feeds packets to fragment reassembly, as `split_protocols` takes them in
/// (with IPv6 extension headers checked and taken out), each at its time in
/// milliseconds since the start, and expires unfinished packets as the
/// time passes. Checks the bookkeeping after every step. Returns the
/// packets that came out changed: those put together from fragments,
/// rewritten as one, or stripped of extension headers, and the ICMPv6
/// "parameter problem" answers.
pub fn reassemble(packets: impl IntoIterator<Item = (u64, Vec<u8>)>) -> Vec<Packet> {
    let mut r = Reassembly::default();
    let mut out = Vec::new();
    for (ms, bytes) in packets {
        let now = Instant::from_since_start(Duration::from_millis(ms));
        if r.next_expiry().is_some_and(|t| t <= now) {
            r.expire(now);
            r.check();
        }
        match r.push(Chunk::unpaid(bytes.clone()), now) {
            Intake::Whole(p) if *p != *bytes => out.push(Packet::from_chunk(p)),
            Intake::Refused {
                answer: Some(answer),
                ..
            } => out.push(Packet::from_chunk(answer)),
            _ => {}
        }
        r.check();
    }
    out
}

/// Which end of `ip::split_protocols` a whole packet goes to.
pub fn sort(packet: &[u8]) -> Sort {
    Sort::of(packet)
}
