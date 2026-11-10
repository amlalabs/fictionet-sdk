//! Kani proof over `services::stack::Lifetime`, the idle and write clocks
//! the stream runner and `Session` share. Included from
//! `src/stdlib/services/stack/lifetime.rs` under `cfg(kani)` as a child
//! module.

use super::*;
use std::time::Duration;

/// Settles a proof makes, each at a symbolic time after the last.
const SETTLES: usize = 3;

fn any_outstanding() -> Outstanding {
    Outstanding {
        output: kani::any(),
        input: kani::any(),
        work: kani::any(),
        memory: kani::any(),
    }
}

/// Over symbolic `u8` times, limits and flags: the idle deadline is never
/// earlier than an idle limit after the first settle that found the stream
/// quiet after its last busy one, where busy is any of output, input, work
/// or memory; a settle that finds the stream waiting for memory leaves no
/// idle deadline; and memory never moves the write deadline, which a twin
/// lifetime that never waits for memory keeps exactly.
#[kani::proof]
#[kani::unwind(4)]
fn the_idle_clock_stops_while_memory_waits() {
    let idle: u8 = kani::any();
    let write: u8 = kani::any();
    let limits = StreamLimits {
        idle: Some(Duration::from_millis(u64::from(idle))),
        write_timeout: Some(Duration::from_millis(u64::from(write))),
    };
    let mut lifetime = Lifetime::new(limits);
    let mut twin = Lifetime::new(limits);
    let mut now = Instant::ZERO;
    // The first settle that found the stream quiet since it was last busy.
    let mut quiet_from: Option<Instant> = None;
    for _ in 0..SETTLES {
        let step: u8 = kani::any();
        now = now + Duration::from_millis(u64::from(step));
        let outstanding = any_outstanding();
        lifetime.settle(now, outstanding);
        twin.settle(
            now,
            Outstanding {
                memory: false,
                ..outstanding
            },
        );
        let busy =
            outstanding.output || outstanding.input || outstanding.work || outstanding.memory;
        if busy {
            quiet_from = None;
        } else {
            quiet_from.get_or_insert(now);
        }
        if outstanding.memory {
            assert!(lifetime.idle_from.is_none());
        }
        if let Some((at, Expiry::Idle)) = lifetime.deadline() {
            let quiet = quiet_from.expect("an idle deadline only while quiet");
            assert!(at >= quiet + Duration::from_millis(u64::from(idle)));
        }
        assert!(lifetime.stalled_since == twin.stalled_since);
    }
}
