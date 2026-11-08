//! Bounded proofs call the production channel window operations. All u32
//! windows and usize packet lengths are symbolic; there is no small-window
//! assumption. Buffer admission is proved independently of allocation.
use super::*;

fn channel() -> Channel {
    Channel {
        wire: 0,
        peer: 0,
        window: kani::any(),
        max_packet: kani::any(),
        granted: kani::any(),
        receive: kani::any(),
        advertised: kani::any(),
        accepted: kani::any(),
        confirmed: kani::any(),
        eof: kani::any(),
        sent_eof: kani::any(),
        closed: kani::any(),
    }
}

#[kani::proof]
fn ssh_receive_window() {
    let mut c = channel();
    let n: usize = kani::any();
    let before = (c.receive, c.advertised);
    let valid = c.confirmed
        && !c.eof
        && !c.closed
        && n <= PACKET as usize
        && n as u64 <= c.receive
        && n <= c.advertised as usize;
    let result = c.consume_receive(n);
    assert_eq!(result.is_ok(), valid);
    if valid {
        assert_eq!(c.receive + n as u64, before.0);
        assert_eq!(u64::from(c.advertised) + n as u64, u64::from(before.1));
    } else {
        assert_eq!((c.receive, c.advertised), before);
    }
}

#[kani::proof]
fn ssh_send_window() {
    let mut c = channel();
    let n: usize = kani::any();
    let before = (c.granted, c.window);
    let valid = !c.closed
        && !c.sent_eof
        && n as u64 <= c.granted
        && n <= c.window as usize
        && n <= c.max_packet as usize;
    let result = c.consume_send(n);
    assert_eq!(result.is_ok(), valid);
    if valid {
        assert_eq!(c.granted + n as u64, before.0);
        assert_eq!(u64::from(c.window) + n as u64, u64::from(before.1));
    } else {
        assert_eq!((c.granted, c.window), before);
    }
}

#[kani::proof]
fn ssh_output_buffer() {
    let mut out = std::mem::ManuallyDrop::new(Output::default());
    out.bytes = kani::any();
    out.exited = kani::any();
    kani::assume(out.bytes <= OUTPUT_LIMIT);
    let n: usize = kani::any();
    let result = out.next_bytes(n);
    let fits = !out.exited && n <= OUTPUT_LIMIT - out.bytes;
    assert_eq!(result.is_ok(), fits);
    if let Ok(next) = result {
        assert!(next <= OUTPUT_LIMIT);
        assert_eq!(next - out.bytes, n);
    }
    assert_eq!(
        out.available(),
        if out.exited {
            0
        } else {
            OUTPUT_LIMIT - out.bytes
        }
    );
}

// Negative controls remove a guard or change the charged length. Each must
// fail its conservation assertion; they are deliberately separate harnesses.
#[kani::proof]
fn ssh_receive_without_bound() {
    let available: u32 = kani::any();
    let n: u32 = kani::any();
    kani::assume(n <= PACKET);
    let left = available.wrapping_sub(n);
    assert_eq!(u64::from(left) + u64::from(n), u64::from(available));
}

#[kani::proof]
fn ssh_send_without_bound() {
    let available: u32 = kani::any();
    let n: u32 = kani::any();
    let left = available.wrapping_sub(n);
    assert_eq!(u64::from(left) + u64::from(n), u64::from(available));
}

#[kani::proof]
fn ssh_output_without_count() {
    let mut out = std::mem::ManuallyDrop::new(Output::default());
    out.bytes = kani::any();
    kani::assume(out.bytes <= OUTPUT_LIMIT);
    let n: usize = kani::any();
    if let Ok(next) = out.next_bytes(n) {
        // Mutate away the accepted increment, preserving the admission gate.
        let broken = next - n;
        assert_eq!(broken - out.bytes, n);
    }
}
