//! Kani proofs over the framing of DNS over TCP in
//! src/stdlib/dissect/protocols/dns.rs: `Dns::next`, the step of
//! `Dns::decode` that finds each message by the two-byte length before it.
//! Compiled only under `cargo kani`, as a child module of dns.rs. What a
//! message decodes to (`dns_display`, the DNS parser and its text) is not
//! in these proofs.

use super::*;

/// The longest input the harness gives the framing.
const INPUT: usize = 6;

/// For any bytes up to six long, with any payload left to skip, after
/// missing bytes or not, and at the end of the stream or not, one step of
/// a TCP direction keeps the `Decode` contract and frames by the length:
///
/// - after missing bytes it stops, and takes nothing;
/// - it never takes more than its input, and never takes nothing as a step;
/// - while skipping a message too long to keep, it takes exactly what is
///   left of it in the input;
/// - otherwise a message is the two bytes of its length and exactly the
///   length they name, or, when that length is more than the buffer keeps
///   and not all there, the two length bytes alone, with the length left
///   to skip;
/// - it asks for more only while the message is not all there.
#[kani::proof]
#[kani::unwind(8)]
fn tcp_messages_take_exactly_what_their_length_names() {
    let bytes: [u8; INPUT] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= INPUT);
    let input = &bytes[..len];
    let (skip, lost): (usize, bool) = (kani::any(), kani::any());
    let mut dns = Dns {
        tcp: true,
        taken: kani::any(),
        skip,
        lost,
    };
    let length = (len >= 2).then(|| usize::from(u16::from_be_bytes([input[0], input[1]])));
    match dns.next(input, kani::any()) {
        Next::Step(Step::End) => assert!(lost),
        Next::Step(Step::Skip(n)) => {
            assert!(!lost && skip != 0);
            assert!(n > 0 && n <= len);
            assert_eq!(n, skip.min(len));
            assert_eq!(dns.skip, skip - n);
        }
        Next::Step(Step::Need) => {
            assert!(!lost);
            assert_eq!(dns.skip, skip);
            if skip != 0 {
                assert_eq!(len, 0);
            } else if let Some(length) = length {
                assert!(length <= MAX_BUFFER - 2 && len < 2 + length);
            }
        }
        Next::Step(Step::Item(never, _)) => match never {},
        Next::Long(n) => {
            assert!(!lost && skip == 0);
            let length = length.unwrap();
            assert_eq!(n, length);
            assert!(length > MAX_BUFFER - 2 && len < 2 + length);
            assert_eq!(dns.skip, length);
        }
        Next::Message(offset, end) => {
            assert!(!lost && skip == 0);
            assert_eq!((offset, end), (2, 2 + length.unwrap()));
            assert!(end <= len);
            assert_eq!(dns.skip, 0);
        }
    }
}

/// A gap stops a TCP direction for good; a datagram's decoder is new for
/// each datagram, so a reset leaves it reading.
#[kani::proof]
fn a_reset_stops_tcp_only() {
    let tcp: bool = kani::any();
    let mut dns = Dns::new(tcp);
    Present::reset(&mut dns);
    let bytes: [u8; 2] = kani::any();
    let stopped = matches!(dns.next(&bytes, false), Next::Step(Step::End));
    assert_eq!(stopped, tcp);
}
