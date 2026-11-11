//! What the HTTP servers copy while a unit arrives in pieces: a request
//! head, a request body. Each joins its pieces into storage that doubles
//! when it is full, or grows as far as the budget has room for when it
//! has no room for that, so the bytes it copies stay linear in what
//! arrived (verification/http/README.md, "Resource properties"). The
//! bytes asked of the allocator are counted (`common::alloc`); the inputs
//! are made before the count starts.

use std::sync::Arc;

use bytes::Bytes;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::layer::{Admit, Budget, Chunk, Driver, Harness, StreamEvent};
use fictionet::stdlib::protocols::{hpack, http2};
use fictionet::stdlib::services::stack::Polling;
use fictionet::stdlib::web::httpd::{Http1, Responder};
use fictionet::time::Instant;
use fictionet::{Seed, SeededEntropy};

use crate::common::alloc::measuring;

/// The blocks a unit is joined in come to less than this many times its
/// bytes: a block is replaced only when full, by one at least twice what
/// it held and at most twice what it must hold, so the blocks form a
/// doubling series whose sum is under twice its last, and the last is
/// under twice the unit. A block the budget had no room to double is
/// replaced at most once more, by the largest block that fits, which is
/// at most twice the unit too, and that block is never replaced: twice
/// it does not fit.
const JOIN_PER: usize = 4;

/// The HTTP/1 head pools' slots: a head may be joined in one of each
/// before it needs a block of its own.
const POOL_SLOTS: usize = Http1::SMALL_SLOT + Http1::LARGE_SLOT;

/// The most blocks a head moves through: the delivered chunk, a small
/// and a large pool slot, the doubling blocks from 32 KiB to the 64 KiB
/// limit, and one the budget had room for when it had none for doubling.
/// Each has a backing ([`Chunk::HEADER`]).
const HEAD_BLOCKS: usize = 6;

/// A request head with `fields` fields of `value` bytes each.
fn head(fields: usize, value: usize) -> Vec<u8> {
    let mut wire = b"GET / HTTP/1.1\r\nHost: a.test\r\n".to_vec();
    for field in 0..fields {
        wire.extend_from_slice(format!("x-pad-{field:02}: ").as_bytes());
        wire.extend(std::iter::repeat_n(b'a', value));
        wire.extend_from_slice(b"\r\n");
    }
    wire.extend_from_slice(b"\r\n");
    wire
}

fn answer() -> Arc<impl fictionet::stdlib::web::httpd::Handler> {
    fictionet_test_support::handler(|_, _: http::Request<Bytes>| http::Response::new(Bytes::new()))
}

/// A 58 KB head sent a byte a delivery, while another connection on the
/// same budget leaves it 96 KiB. Once its block reaches 32 KiB, the 64
/// KiB block that doubling asks for no longer fits beside it, while a
/// block one byte larger than what is held does. Taking that block
/// instead copied everything held on each later delivery: 297 MB asked of
/// the allocator for 41 KB of input. The head now takes the largest block
/// the budget has room for, once, and then waits for memory.
#[test]
fn a_head_trickled_into_a_tight_budget_is_copied_linearly() {
    let wire = head(90, 640);
    let budget = Budget::new(1 << 20);
    let mut driver = Driver::new(
        Http1::with(answer(), Default::default()),
        Arc::new(SeededEntropy::new(Seed::from_u64(1))),
        budget.clone(),
        Instant::ZERO,
    );
    driver.run().unwrap();
    let first = Chunk::unpaid(wire[..1].to_vec());
    assert!(matches!(
        driver.deliver(StreamEvent::Data(first)).unwrap(),
        Admit::Taken
    ));
    driver.run().unwrap();
    let room = 96 << 10;
    let _other = budget
        .charge(budget.limit() - budget.used() - room)
        .unwrap();
    let pieces: Vec<Chunk> = wire[1..]
        .iter()
        .map(|byte| Chunk::unpaid(vec![*byte]))
        .collect();
    let (taken, stats) = measuring(|| {
        let mut taken = 1;
        for piece in pieces {
            match driver.deliver(StreamEvent::Data(piece)).unwrap() {
                Admit::Taken => taken += 1,
                Admit::Blocked(_) => break,
                other => panic!("a head byte was {other:?}"),
            }
            driver.run().unwrap();
        }
        taken
    });
    let bound = JOIN_PER * taken + POOL_SLOTS + HEAD_BLOCKS * Chunk::HEADER;
    assert!(
        stats.bytes_requested <= bound,
        "{} bytes asked for to join {taken} bytes of a head, past {bound}",
        stats.bytes_requested
    );
}

/// HTTP/2 frames: the preface and the client's SETTINGS with its
/// acknowledgment, then a POST on stream 1 whose body follows.
fn opening() -> Vec<u8> {
    let mut bytes = http2::PREFACE.to_vec();
    for flags in [0, 1] {
        http2::Settings {
            flags,
            entries: Vec::new(),
        }
        .write(&mut bytes)
        .unwrap();
    }
    let mut fragment = Vec::new();
    for (name, value) in [
        (":method", "POST"),
        (":scheme", "https"),
        (":authority", "a.test"),
        (":path", "/"),
    ] {
        hpack::Field::new(name, value).write(&mut fragment).unwrap();
    }
    http2::Headers {
        stream: 1,
        flags: 4,
        fragment,
        priority: None,
        padding: None,
    }
    .write(&mut bytes)
    .unwrap();
    bytes
}

/// A request body of 20,000 bytes, a byte a DATA frame, all within the
/// stream's window. `Respond` collected it into storage grown to exactly
/// what it held each time: every frame copied the whole body before it,
/// 200 MB asked of the allocator for 200 KB of frames.
#[test]
fn a_body_in_many_data_frames_is_collected_linearly() {
    const FRAMES: usize = 20_000;
    let mut h = Harness::new(Seed::from_u64(1), Responder::shared(answer()).http2())
        .with_worker(Polling::new());
    h.push(&opening()).unwrap();
    let mut frames = Vec::new();
    for i in 0..FRAMES {
        http2::Data {
            stream: 1,
            flags: u8::from(i + 1 == FRAMES),
            data: vec![b'b'],
            padding: None,
        }
        .write(&mut frames)
        .unwrap();
    }
    let (_, stats) = measuring(|| h.push(&frames).unwrap());
    // The harness copies the frames into one delivery. Each frame's data,
    // a slice of that delivery, moves into the child's receive window as
    // bytes of its own (`Chunk::move_into_window`): its byte and a
    // backing. The body is joined within `JOIN_PER` times its bytes.
    // `ANSWER` is the handler's answer, its head block and its frames,
    // once: well under the 64 KiB the connection queues for output.
    const ANSWER: usize = 64 << 10;
    let bound = frames.len() + FRAMES * (1 + Chunk::HEADER) + JOIN_PER * FRAMES + ANSWER;
    assert!(
        stats.bytes_requested <= bound,
        "{} bytes asked for to collect a body of {FRAMES} frames, past {bound}",
        stats.bytes_requested
    );
}
