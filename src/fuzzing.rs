//! Entry points for the fuzz targets in `fuzz/`, into code that is not
//! public. Built only under `cfg(fuzzing)`, which `cargo fuzz` sets. Not
//! part of the API.

use std::cell::Cell;

use crate::Packet;
use crate::stdlib::ip::{Intake, Reassembly, protocol};
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
        match r.intake(Packet(bytes.clone()), now) {
            Intake::Whole(p) if p.0 != bytes => out.push(p),
            Intake::Refused { answer: Some(answer), .. } => out.push(answer),
            _ => {}
        }
        r.check();
    }
    out
}

/// Which end of `ip::split_protocols` a whole packet goes to, as a
/// protocol number.
pub fn sort(packet: &[u8]) -> u8 {
    protocol(packet)
}

thread_local! {
    static SEED: Cell<Option<u64>> = const { Cell::new(None) };
}

/// Makes `Cx::random_u64` on this thread give numbers from `seed` instead
/// of the operating system, so that the world's own random choices repeat
/// from run to run of an input: TCP's initial sequence numbers, ephemeral
/// ports, the randoms rustls takes from the `Cx`. The clock is still the
/// system's, and ring's key exchange still draws its own randomness.
pub fn seed_random(seed: u64) {
    SEED.with(|s| s.set(Some(seed)));
}

/// The next number from the seed (splitmix64), if one was set.
pub(crate) fn next_random() -> Option<u64> {
    SEED.with(|s| {
        let x = s.get()?.wrapping_add(0x9e37_79b9_7f4a_7c15);
        s.set(Some(x));
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        Some(z ^ (z >> 31))
    })
}
