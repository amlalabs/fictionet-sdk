//! Kani harnesses over the Search time server: `TimeServer`, a layer over
//! `Datagrams<SocketAddr>` (demos/search/world/src/ntp.rs:33-120), with
//! the real `Packet::parse`, `ntp::server_reply` and `Packet::write`
//! (src/stdlib/protocols/ntp.rs:544-593, 621-689).
//!
//! Included from `demos/search/world/src/ntp.rs` under `cfg(kani)` as a
//! child module. What counts as a request is written here from RFC 5905
//! and RFC 4330 on the bytes, not taken from the code: at least the
//! 48-byte header, a trailer of whole 4-byte words, version 1 to 4, and
//! mode 3 (client) or 1 (symmetric active).

extern crate alloc;

use super::*;
use alloc::boxed::Box;
use fictionet::Entropy;
use fictionet::stdlib::layer::{Budget, Driver};
use fictionet::time::Instant;
use std::time::Duration;

struct NoEntropy;
impl Entropy for NoEntropy {
    fn fill_random(&self, out: &mut [u8]) {
        out.fill(0);
    }
}

fn session() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_762_560_000)
}

type Server = TimeServer<fn() -> SystemTime>;

fn server() -> Driver<Server> {
    Driver::new(
        TimeServer::new(session as fn() -> SystemTime),
        Arc::new(NoEntropy),
        Budget::unlimited(),
        Instant::ZERO,
    )
}

fn datagram(bytes: &'static [u8], from: SocketAddr) -> DatagramEvent<SocketAddr> {
    DatagramEvent::Datagram(Datagram::new(Chunk::new(bytes), from))
}

/// The first datagram the server sends now, with where to, and how many it
/// sends.
fn replies(d: &mut Driver<Server>) -> (Option<(Vec<u8>, SocketAddr)>, usize) {
    let mut out = None;
    let mut n = 0;
    d.send_below(|command| {
        match command {
            DatagramCommand::Send(dg) => {
                let (payload, to) = dg.into_parts();
                if n == 0 {
                    out = Some((payload.to_vec(), to));
                }
                n += 1;
            }
            DatagramCommand::End => panic!("the server never closes its socket"),
        }
        Admit::Taken
    });
    (out, n)
}

fn client(port: u16) -> SocketAddr {
    SocketAddr::from(([10, 40, 0, 50], port))
}

/// Means "any first byte" in place of a fixed one.
const ANY: u16 = 256;

/// A datagram of exactly `LEN` bytes from any client port. With `ANY`,
/// every byte is the solver's. With a fixed first byte, the poll, the
/// transmit time and the trailer are the solver's and the other fields
/// zero: every byte the solver chose at once did not fit in 10 GiB.
fn answers_only_requests<const LEN: usize, const FIRST: u16>() {
    let bytes: &'static mut [u8; 52] = if FIRST == ANY {
        Box::leak(Box::new(kani::any()))
    } else {
        let mut b = [0u8; 52];
        b[0] = FIRST as u8;
        b[2] = kani::any();
        let tail: [u8; 12] = kani::any();
        b[40..52].copy_from_slice(&tail);
        Box::leak(Box::new(b))
    };
    let request: &'static [u8] = &bytes[..LEN];
    let from = client(kani::any());
    let mut d = server();
    let admit = d.deliver(datagram(request, from)).unwrap();
    assert!(matches!(admit, Admit::Taken), "a datagram is taken whole");
    // `TimeServer` keeps no timers and does no work of its own, so
    // `Driver::run` has nothing to do between delivery and output.
    let (reply, n) = replies(&mut d);

    let first = request.first().copied().unwrap_or(0);
    let (version, mode) = ((first >> 3) & 7, first & 7);
    let is_request =
        LEN >= 48 && (LEN - 48) % 4 == 0 && (1..=4).contains(&version) && (mode == 3 || mode == 1);
    assert!(
        n == usize::from(is_request),
        "one answer to a request, none to anything else"
    );
    if let Some((payload, to)) = reply {
        assert!(to == from, "the answer goes to the sender");
        assert!(payload.len() == 48);
        assert!(
            payload[24..32] == request[40..48],
            "the origin is the client's transmit time"
        );
        assert!(payload[0] & 7 == if mode == 3 { 4 } else { 2 });
        assert!((payload[0] >> 3) & 7 == version, "the request's version");
        assert!(payload[2] == request[2], "the request's poll");
    }
}

macro_rules! answers {
    ($($name:ident: $len:literal, $first:expr;)*) => {$(
        #[kani::proof]
        #[kani::unwind(54)]
        fn $name() {
            answers_only_requests::<$len, { $first }>();
        }
    )*};
}

// Lengths no request has, with any first byte.
answers! {
    the_time_server_answers_nothing_of_0_bytes: 0, ANY;
    the_time_server_answers_nothing_of_1_byte: 1, ANY;
    the_time_server_answers_nothing_of_47_bytes: 47, ANY;
    the_time_server_answers_nothing_of_49_bytes: 49, ANY;
    the_time_server_answers_nothing_of_50_bytes: 50, ANY;
    the_time_server_answers_nothing_of_51_bytes: 51, ANY;
}

// A whole header: every request (modes 1 and 3, versions 1 to 4) and the
// headers of version 0, which `Packet::parse` refuses. Other headers that
// are not requests did not fit in 10 GiB here; their refusal is proved
// on `Packet::parse` and `ntp::server_reply` in `ntp_reply.rs`.
answers! {
    the_time_server_answers_version_1_mode_1: 48, (1 << 3) | 1;
    the_time_server_answers_version_1_mode_3: 48, (1 << 3) | 3;
    the_time_server_answers_version_2_mode_1: 48, (2 << 3) | 1;
    the_time_server_answers_version_2_mode_3: 48, (2 << 3) | 3;
    the_time_server_answers_version_3_mode_1: 48, (3 << 3) | 1;
    the_time_server_answers_version_3_mode_3: 48, (3 << 3) | 3;
    the_time_server_answers_version_4_mode_1: 48, (4 << 3) | 1;
    the_time_server_answers_version_4_mode_3: 48, (4 << 3) | 3;
    the_time_server_refuses_version_0_mode_0: 48, 0;
    the_time_server_refuses_version_0_mode_1: 48, 1;
    the_time_server_refuses_version_0_mode_2: 48, 2;
    the_time_server_refuses_version_0_mode_3: 48, 3;
    the_time_server_refuses_version_0_mode_4: 48, 4;
    the_time_server_refuses_version_0_mode_5: 48, 5;
    the_time_server_refuses_version_0_mode_6: 48, 6;
    the_time_server_refuses_version_0_mode_7: 48, 7;
    the_time_server_answers_with_a_trailer_mode_3: 52, (4 << 3) | 3;
    the_time_server_answers_with_a_trailer_mode_1: 52, (4 << 3) | 1;
    the_time_server_answers_with_the_leap_bits_set: 48, (3 << 6) | (4 << 3) | 3;
}

/// A client request with a transmit time the solver chooses.
fn request() -> (&'static [u8], [u8; 8]) {
    let transmit: [u8; 8] = kani::any();
    let mut b = [0u8; 48];
    b[0] = (4 << 3) | 3;
    b[40..48].copy_from_slice(&transmit);
    (Box::leak(Box::new(b)), transmit)
}

#[kani::proof]
#[kani::unwind(50)]
fn one_conversation_answers_each_request_in_turn() {
    let mut d = server();
    let (first, t1) = request();
    let (second, t2) = request();
    let (a, b) = (client(kani::any()), client(kani::any()));
    assert!(matches!(
        d.deliver(datagram(first, a)).unwrap(),
        Admit::Taken
    ));
    // The next datagram waits while the answer to the first does, and is
    // handed back whole.
    match d.deliver(datagram(second, b)).unwrap() {
        Admit::Blocked(DatagramEvent::Datagram(back)) => {
            assert_eq!(*back.meta(), b);
            assert_eq!(back.payload(), second);
        }
        _ => panic!("a waiting answer holds up the next datagram"),
    }
    let (one, n) = replies(&mut d);
    assert_eq!(n, 1);
    let (payload, to) = one.unwrap();
    assert_eq!((to, &payload[24..32]), (a, &t1[..]));
    assert!(matches!(
        d.deliver(datagram(second, b)).unwrap(),
        Admit::Taken
    ));
    let (two, n) = replies(&mut d);
    assert_eq!(n, 1);
    let (payload, to) = two.unwrap();
    assert_eq!((to, &payload[24..32]), (b, &t2[..]));
    // The socket closing ends the conversation with nothing more sent.
    assert!(matches!(
        d.deliver(DatagramEvent::Ended).unwrap(),
        Admit::Taken
    ));
    assert_eq!(replies(&mut d).1, 0);
}
