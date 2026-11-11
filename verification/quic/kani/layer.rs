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

#[kani::proof]
#[kani::unwind(10)]
fn application_completion_requires_retirement_and_is_taken_once() {
    use super::DatagramSend;
    let tracked: bool = kani::any();
    let mut send = DatagramSend::Queued(tracked);
    let mut handed = false;
    let mut retired = false;
    let mut reported = false;
    for _ in 0..8 {
        match kani::any::<u8>() {
            0 => {
                send.packet(false);
                handed = true;
            }
            1 => {
                send.completed();
                retired |= handed;
            }
            2 => {
                if !handed {
                    send.retired();
                    retired = true;
                }
            }
            _ => {
                let taken = send.take();
                assert_eq!(taken, tracked && retired && !reported);
                reported |= taken;
            }
        }
        if !retired {
            assert_ne!(send, DatagramSend::Ready);
        }
    }
}
