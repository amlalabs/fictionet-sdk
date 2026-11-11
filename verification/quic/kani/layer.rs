use super::Flight;

#[kani::proof]
#[kani::unwind(10)]
fn one_datagram_waits_for_its_completion() {
    let mut flight = Flight::default();
    let mut handed = 0u64;
    let mut retired = 0u64;
    for _ in 0..8 {
        if kani::any() {
            let admitted = flight.handoff();
            assert_eq!(admitted, handed == retired);
            if admitted {
                handed += 1;
            }
        } else {
            let count: u64 = kani::any();
            let result = flight.complete(count);
            assert_eq!(result.is_ok(), count <= handed - retired);
            if result.is_ok() {
                retired += count;
            }
        }
        assert!(retired <= handed);
        assert!(handed - retired <= 1);
        assert_eq!(flight.0, handed > retired);
    }
}
