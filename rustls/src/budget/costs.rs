//! The cost of what a connection reads, measured with the counting
//! allocator (verification/resources/alloc.rs) and held to the bounds of
//! verification/resources/cost.rs.

// The files are shared with the SDK's tests, which are std and newer Rust
// than this crate's lints assume.
#[allow(
    unsafe_code,
    unreachable_pub,
    clippy::std_instead_of_core,
    clippy::incompatible_msrv
)]
#[path = "../../../verification/resources/alloc.rs"]
mod alloc;
#[allow(unreachable_pub, clippy::use_self, clippy::incompatible_msrv)]
#[path = "../../../verification/resources/cost.rs"]
mod cost;

use ::alloc::vec::Vec;

use super::testing::Limit;
use crate::msgs::deframer::handshake::FragmentSpan;
use crate::msgs::message::MAX_WIRE_SIZE;
use crate::server::Acceptor;
use cost::{Charged, Costs, Linear};

/// A ClientHello of `len` bytes of body, junk after its header, sent a
/// byte a record: each record its 5-byte header and one byte.
fn hello_a_byte_a_record(len: usize) -> Vec<Vec<u8>> {
    let mut message = Vec::from([1u8]);
    message.extend_from_slice(&u32::try_from(len).unwrap().to_be_bytes()[1..]);
    message.resize(4 + len, 0x42);
    message
        .into_iter()
        .map(|byte| Vec::from([22, 3, 1, 0, 1, byte]))
        .collect()
}

/// The hello's deframer keeps its message's spans between records: the
/// part joined so far and the record arriving, coalesced at once, in the
/// first capacity a vector of them takes (four, for elements this small).
const JOINING_SPANS: usize = 4 * size_of::<FragmentSpan>();

/// What joining a handshake message from records asks of the allocator.
///
/// - `per = 4`: the buffer grows to at least twice its capacity, so all
///   its growths together are at most twice the last, and the last is at
///   most twice what it held, every byte of which was read.
/// - `fixed`: the record arriving is sized to its header's length before
///   its body arrives, at most [`MAX_WIRE_SIZE`], and a growth may come
///   from that size; and the spans.
const JOINING: Linear = Linear {
    num: 4,
    den: 1,
    fixed: 2 * MAX_WIRE_SIZE + JOINING_SPANS,
};

/// A ClientHello sent a byte a record, into an acceptor, is moved to a
/// larger buffer a few times as it is joined, not once a record: the
/// bytes asked for stay linear in the bytes read. And the bytes live at
/// once stay within the most the budget was charged, and the spans. The
/// last record is held back, so that the junk is never parsed.
#[test]
fn a_hello_joined_from_one_byte_records_is_moved_a_few_times() {
    let mut records = hello_a_byte_a_record(10_000);
    records.pop();
    let input: usize = records.iter().map(Vec::len).sum();
    let mut costs = Costs::new("a hello a byte a record");
    // The budget is the caller's, made before the step.
    let limit = Limit::new(1 << 20);
    costs.step(input, JOINING_SPANS, JOINING, || {
        let mut acceptor = Acceptor::with_budget(limit.clone());
        for record in &records {
            let mut rest = &record[..];
            while !rest.is_empty() {
                acceptor.read_tls(&mut rest).unwrap();
            }
            assert!(acceptor.accept().unwrap().is_none());
        }
        Charged {
            value: (),
            charged: limit.most(),
        }
    });
    std::println!("cost: {}", costs.summary());
}

/// A TLS 1.3 ClientHello with `suites` cipher suites, and `big`, an
/// extension (its type, then its body) after the ones every hello needs,
/// in records of at most 2^14 bytes.
fn hello(suites: u16, big: &[u8]) -> Vec<u8> {
    let mut ext = Vec::new();
    // supported_versions: TLS 1.3.
    ext.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
    // supported_groups: x25519.
    ext.extend_from_slice(&[0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d]);
    // signature_algorithms: rsa_pss_rsae_sha256.
    ext.extend_from_slice(&[0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x08, 0x04]);
    if !big.is_empty() {
        ext.extend_from_slice(&big[..2]);
        ext.extend_from_slice(&u16::try_from(big.len() - 2).unwrap().to_be_bytes());
        ext.extend_from_slice(&big[2..]);
    }
    let mut body = Vec::from([0x03, 0x03]);
    body.extend_from_slice(&[0x11; 32]);
    body.push(0);
    body.extend_from_slice(&(2 * (suites + 1)).to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    for suite in 0..suites {
        body.extend_from_slice(&(0x5000 + suite).to_be_bytes());
    }
    body.extend_from_slice(&[0x01, 0x00]);
    body.extend_from_slice(&u16::try_from(ext.len()).unwrap().to_be_bytes());
    body.extend_from_slice(&ext);
    let mut message = Vec::from([1u8]);
    message.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
    message.extend_from_slice(&body);
    let mut wire = Vec::new();
    for part in message.chunks(1 << 14) {
        wire.extend_from_slice(&[22, 3, 1]);
        wire.extend_from_slice(&u16::try_from(part.len()).unwrap().to_be_bytes());
        wire.extend_from_slice(part);
    }
    wire
}

/// An extension of `count` elements, each `element(i)`, after a list
/// length of two bytes.
fn listed(typ: u16, count: u16, element: impl Fn(u16) -> Vec<u8>) -> Vec<u8> {
    let list: Vec<u8> = (0..count).flat_map(element).collect();
    let mut ext = Vec::from(typ.to_be_bytes());
    ext.extend_from_slice(&u16::try_from(list.len()).unwrap().to_be_bytes());
    ext.extend_from_slice(&list);
    ext
}

/// Hellos near the most a message may be, each made of the elements that
/// are largest in memory for their bytes on the wire.
fn large_hellos() -> [(&'static str, Vec<u8>); 3] {
    [
        (
            "one-byte key shares",
            hello(
                0,
                &listed(0x0033, 11_000, |i| {
                    [&(0x1000 + i).to_be_bytes()[..], &[0, 1, 7]].concat()
                }),
            ),
        ),
        (
            "one-byte protocol names",
            hello(0, &listed(0x0010, 30_000, |i| Vec::from([1, i as u8]))),
        ),
        ("cipher suites", hello(30_000, &[])),
    ]
}

/// What reading and accepting a hello asks of the allocator: joining its
/// records ([`JOINING`]), and parsing it (`budget::parse_room`, whose
/// fixed part is in `fixed` and whose 3 x 25 / 2 bytes a byte are in the
/// fraction).
fn accepting() -> Linear {
    Linear {
        num: 2 * JOINING.num + 3 * 25,
        den: 2,
        fixed: JOINING.fixed + super::parse_room(0),
    }
}

/// A hello is charged what parsing it holds, while the acceptor parses it
/// and while the [`Accepted`](crate::server::Accepted) keeps it for the
/// config to be picked: for each hello, the bytes live at once stay
/// within the most the budget was charged and the deframer's spans,
/// through accepting and through reading what the client asked for.
#[test]
fn a_hello_is_charged_what_parsing_it_holds() {
    let mut all = Costs::new("hellos");
    for (name, wire) in large_hellos() {
        let mut costs = Costs::new(name);
        let limit = Limit::new(1 << 24);
        let accepted = costs.step(wire.len(), JOINING_SPANS, accepting(), || {
            let mut acceptor = Acceptor::with_budget(limit.clone());
            let mut rest = &wire[..];
            let accepted = loop {
                if !rest.is_empty() {
                    acceptor.read_tls(&mut rest).unwrap();
                }
                match acceptor.accept() {
                    Ok(None) => assert!(!rest.is_empty(), "{name}: the hello stalled"),
                    Ok(Some(accepted)) => break accepted,
                    Err((error, _)) => panic!("{name}: {error:?}"),
                }
            };
            Charged {
                value: accepted,
                charged: limit.most(),
            }
        });
        // Held while the world picks: what the hello asked for, read.
        costs.step(
            0,
            limit.used() + JOINING_SPANS,
            Linear {
                num: 0,
                den: 1,
                fixed: 0,
            },
            || {
                let hello = accepted.client_hello();
                assert!(hello.cipher_suites().len() <= 30_001);
                Charged {
                    value: (),
                    charged: 0,
                }
            },
        );
        std::println!("cost: {name}: {}", costs.summary());
        all.absorb(&costs);
    }
    std::println!("cost: {}", all.summary());
}
