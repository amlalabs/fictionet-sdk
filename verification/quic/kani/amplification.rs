//! The production path allowance against unbounded-width arithmetic.

use super::amplification_budget;

#[kani::proof]
fn admitted_bytes_stay_within_received_credit() {
    let received: u64 = kani::any();
    let sent: u64 = kani::any();
    let bytes: u64 = kani::any();
    kani::assume(u128::from(sent) <= 3 * u128::from(received));
    let room = amplification_budget(received, sent);
    assert_eq!(
        bytes <= room,
        u128::from(sent) + u128::from(bytes) <= 3 * u128::from(received)
    );
}

#[kani::proof]
fn exhausted_credit_never_admits_more_bytes() {
    let received: u64 = kani::any();
    let sent: u64 = kani::any();
    kani::assume(u128::from(sent) >= 3 * u128::from(received));
    assert_eq!(amplification_budget(received, sent), 0);
}
