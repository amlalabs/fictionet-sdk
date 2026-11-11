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
