//! Entry points for the fuzz targets in `fuzz/`, into code that is not
//! public. Built only under `cfg(fuzzing)`, which `cargo fuzz` sets. Not
//! part of the API.

use crate::Packet;
use crate::stdlib::ip::{Intake, Reassembly, protocol_end};
use crate::time::{Duration, Instant};

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
        match r.push(Packet(bytes.clone()), now) {
            Intake::Whole(p) if p.0 != bytes => out.push(p),
            Intake::Refused {
                answer: Some(answer),
                ..
            } => out.push(answer),
            _ => {}
        }
        r.check();
    }
    out
}

/// Which end of `ip::split_protocols` a whole packet goes to, as a
/// protocol number.
pub fn sort(packet: &[u8]) -> u8 {
    protocol_end(packet)
}
