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
            moved: 0,
        }
    });
    costs.print();
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
                moved: 0,
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
                    moved: 0,
                }
            },
        );
        costs.print();
        all.absorb(&costs);
    }
    all.print();
}

/// A record holding a hello and then 4,000 empty handshake messages, four
/// bytes each, into an acceptor, as one step: the handshake deframer cuts
/// the record a message at a time, so it holds two spans, not one for
/// each message, and the bytes live at once stay within the most the
/// budget was charged and those spans. It held 180,768 bytes against
/// 21,346 charged when it cut the whole record at once.
#[test]
fn a_record_of_many_messages_is_cut_a_message_at_a_time() {
    let wire = hello(0, &[]);
    let mut record = Vec::from(&wire[5..]);
    for _ in 0..4_000 {
        record.extend_from_slice(&[0, 0, 0, 0]);
    }
    let mut framed = Vec::from([22u8, 3, 1]);
    framed.extend_from_slice(&u16::try_from(record.len()).unwrap().to_be_bytes());
    framed.extend_from_slice(&record);
    let mut costs = Costs::new("a record of many messages");
    let limit = Limit::new(1 << 24);
    costs.step(framed.len(), JOINING_SPANS, accepting(), || {
        let mut acceptor = Acceptor::with_budget(limit.clone());
        let mut rest = &framed[..];
        acceptor.read_tls(&mut rest).unwrap();
        // The hello is taken, or refused with what follows it.
        assert!(!matches!(acceptor.accept(), Ok(None)));
        Charged {
            value: (),
            charged: limit.most(),
            moved: 0,
        }
    });
    costs.print();
}

/// The session slots a config keeps: made and paid for once, for a size
/// the config sets, and then a session stored, found or taken costs at
/// most the copy of its encoding handed back, whoever sends it. Seeded
/// sessions, some too large to keep, over a store of four slots, each
/// operation a step.
#[test]
fn session_slots_are_paid_once_and_a_session_costs_at_most_its_copy() {
    use crate::server::{ServerSessionSlots, StoresServerSessions, SLOT_KEY, SLOT_VALUE};

    /// The store's own allocation, beside its slots, which its budget
    /// does not pay for: two reference counts, the lock and what the slots
    /// keep of their vectors (three, with a clock), 256 bytes at most.
    const STORE: usize = 256;
    /// A session stored allocates nothing: it is copied into its slot. One
    /// found or taken is copied out, at most a slot's encoding.
    const SESSION: Linear = Linear {
        num: 0,
        den: 1,
        fixed: SLOT_VALUE,
    };
    let size = 4;
    let limit = Limit::new(1 << 20);
    let mut costs = Costs::new("session slots");
    let store = costs.step(
        0,
        STORE,
        Linear {
            num: 0,
            den: 1,
            fixed: STORE,
        },
        || {
            let store = ServerSessionSlots::with_budget(size, limit.clone()).unwrap();
            Charged {
                value: store,
                charged: limit.most(),
                moved: 0,
            }
        },
    );
    let paid = limit.used();
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = |below: usize| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        (seed % below as u64) as usize
    };
    for _ in 0..200 {
        let key = alloc::unmeasured(|| Vec::from([next(6) as u8; 8]));
        let len = next(SLOT_VALUE + SLOT_KEY);
        let value = alloc::unmeasured(|| Vec::from_iter(core::iter::repeat_n(7, len)));
        let operation = next(3);
        let held = costs.step(0, STORE + paid, SESSION, || Charged {
            value: match operation {
                0 => {
                    store.put(key, value);
                    None
                }
                1 => store.get(&key),
                _ => store.take(&key),
            },
            charged: 0,
            moved: 0,
        });
        alloc::unmeasured(|| drop(held));
        assert_eq!(limit.used(), paid, "the store was charged again");
    }
    costs.print();
}
