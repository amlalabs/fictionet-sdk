//! Kani harnesses over the Nuclear PLC's Modbus/TCP server, `PlcServer`
//! (demos/nuclear/world/src/plc.rs:64-149), the layer `plc::stack` puts
//! on `Framed` (plc.rs:52-62).
//!
//! Included from `demos/nuclear/world/src/plc.rs` under `cfg(kani)` as a
//! child module, so it drives the real `PlcServer` through a `Driver`, over
//! a real `Plant`. It offers whole frames, as `Framed` hands them up: that
//! `Framed` cuts bytes into frames in order, once each, is proved in
//! `kani/framed.rs` and modeled in `tla/StreamRunner.tla`. Driving the
//! whole `Chain` with Modbus bytes in one harness did not fit in 10 GiB.
//!
//! Each harness sends two requests with one function code and PDUs of one
//! or two bytes, with any data byte, transaction and unit: function zero,
//! a read of holding registers (0x03), one the controller does not serve
//! (0x07), a write of multiple registers (0x10), device identification
//! (0x2B), and one with the exception flag (0x83). No read or write the
//! controller serves fits in two bytes, so each is answered from
//! `Request::parse`, an exception or the device identification, and the
//! solver never steps the plant's physics. The function is fixed per
//! harness because one symbolic function code over every branch of
//! `Request::parse` did not fit in 10 GiB. Which answer a request gets is
//! not what these check; that each request gets exactly one, in order,
//! with its own transaction and unit, that a request arriving before the
//! answer to the one before is handed back whole, and that the server ends
//! its side after the answers and only once the client's frames are over,
//! is.

extern crate alloc;

use super::*;
use crate::Config;
use alloc::sync::Arc;
use alloc::vec::Vec;
use fictionet::Entropy;
use fictionet::stdlib::layer::{Budget, Driver};
use fictionet::time::Instant;

struct NoEntropy;
impl Entropy for NoEntropy {
    fn fill_random(&self, out: &mut [u8]) {
        out.fill(0);
    }
}

/// A request with a PDU of `LEN` bytes: the function `FUNCTION` and any
/// data byte, transaction and unit.
fn request<const LEN: usize, const FUNCTION: u8>() -> Frame {
    let mut pdu = kani::any::<[u8; LEN]>();
    pdu[0] = FUNCTION;
    Frame {
        transaction: kani::any(),
        unit: kani::any(),
        pdu: pdu.to_vec(),
    }
}

/// Takes the server's next command, if any, as the frame layer does.
fn take(d: &mut Driver<PlcServer>, answers: &mut Vec<Frame>, ended: &mut bool) {
    match d.layer_mut().take_command() {
        Some(MessageCommand::Send(frame)) => {
            assert!(!*ended, "nothing is sent after the end");
            answers.push(frame);
        }
        Some(MessageCommand::End) => {
            assert!(!*ended, "the end is sent once");
            *ended = true;
        }
        None => {}
    }
}

fn server() -> Driver<PlcServer> {
    let plant: Shared = Arc::new(Mutex::new(Plant::new(Config::default())));
    let server = PlcServer::new(Plc::Rcs1, plant, facts::Observer::default(), Source::Modbus);
    Driver::new(
        server,
        Arc::new(NoEntropy),
        Budget::unlimited(),
        Instant::ZERO,
    )
}

fn offer(d: &mut Driver<PlcServer>, frame: &Frame) -> Admit<MessageEvent<Decoded<Frames<Frame>>>> {
    d.deliver(MessageEvent::Message(Ok(frame.clone())))
        .ok()
        .expect("the server never fails")
}

/// Two requests. With `PIPELINED` the second comes before the frame layer
/// took the first answer, and must be handed back whole; otherwise after.
/// Then the end of the client's frames, and everything left taken.
fn answers_in_order<const LEN: usize, const FUNCTION: u8, const PIPELINED: bool>() {
    let mut d = server();
    let requests = [request::<LEN, FUNCTION>(), request::<LEN, FUNCTION>()];
    let mut answers: Vec<Frame> = Vec::new();
    let mut ended = false;
    assert!(matches!(offer(&mut d, &requests[0]), Admit::Taken));
    if PIPELINED {
        match offer(&mut d, &requests[1]) {
            Admit::Blocked(MessageEvent::Message(Ok(back))) => assert_eq!(back, requests[1]),
            _ => panic!("the second request waits for the first answer"),
        }
    }
    take(&mut d, &mut answers, &mut ended);
    assert!(matches!(offer(&mut d, &requests[1]), Admit::Taken));
    take(&mut d, &mut answers, &mut ended);
    assert!(!ended, "the connection stays open while frames may come");
    take(&mut d, &mut answers, &mut ended);
    assert!(!ended, "the connection stays open while frames may come");
    let _ = d.deliver(MessageEvent::Ended);
    take(&mut d, &mut answers, &mut ended);
    assert!(
        ended,
        "the server ends its side once the client's frames are over"
    );
    take(&mut d, &mut answers, &mut ended);
    assert_eq!(answers.len(), requests.len(), "one answer per request");
    for (answer, request) in answers.iter().zip(&requests) {
        assert_eq!(answer.transaction, request.transaction);
        assert_eq!(answer.unit, request.unit);
        assert_eq!(
            answer.function().map(|f| f & 0x7f),
            request.function().map(|f| f & 0x7f)
        );
    }
}

macro_rules! answers {
    ($($name:ident: $len:literal, $function:literal, $pipelined:literal;)*) => {$(
        #[kani::proof]
        #[kani::unwind(8)]
        fn $name() {
            answers_in_order::<$len, $function, $pipelined>();
        }
    )*};
}

answers! {
    each_request_gets_one_answer_in_order_zero_pdu_1: 1, 0x00, false;
    each_request_gets_one_answer_in_order_zero_pdu_2: 2, 0x00, false;
    a_pipelined_request_waits_for_the_answer_before_it_zero: 2, 0x00, true;
    each_request_gets_one_answer_in_order_read_holding_pdu_1: 1, 0x03, false;
    each_request_gets_one_answer_in_order_read_holding_pdu_2: 2, 0x03, false;
    a_pipelined_request_waits_for_the_answer_before_it_read_holding: 2, 0x03, true;
    each_request_gets_one_answer_in_order_unserved_pdu_1: 1, 0x07, false;
    each_request_gets_one_answer_in_order_unserved_pdu_2: 2, 0x07, false;
    a_pipelined_request_waits_for_the_answer_before_it_unserved: 2, 0x07, true;
    each_request_gets_one_answer_in_order_write_multiple_pdu_1: 1, 0x10, false;
    each_request_gets_one_answer_in_order_write_multiple_pdu_2: 2, 0x10, false;
    a_pipelined_request_waits_for_the_answer_before_it_write_multiple: 2, 0x10, true;
    each_request_gets_one_answer_in_order_identification_pdu_1: 1, 0x2B, false;
    each_request_gets_one_answer_in_order_identification_pdu_2: 2, 0x2B, false;
    a_pipelined_request_waits_for_the_answer_before_it_identification: 2, 0x2B, true;
    each_request_gets_one_answer_in_order_exception_flag_pdu_1: 1, 0x83, false;
    each_request_gets_one_answer_in_order_exception_flag_pdu_2: 2, 0x83, false;
    a_pipelined_request_waits_for_the_answer_before_it_exception_flag: 2, 0x83, true;
}
