//! Kani proofs over the TCP socket's stores: the receive store keeps
//! exactly the bytes it accepted, its window is the capacity less what is
//! ready, an acknowledgement lets go of exactly the bytes it covers, and a
//! segment's payload is one chunk's bytes. Compiled only under
//! `cargo kani -p smoltcp`, as a child of `smoltcp/src/socket/tcp.rs`, so
//! every harness calls the stores themselves.
//!
//! The harnesses run fixed sequences of calls over symbolic offsets and
//! lengths, with stores of a few bytes, as the buffer proofs do: a symbolic
//! allocation size takes the solver past the memory cap.

use super::rx::RxStore;
use super::tx::TxStore;
use fictionet_buf::{Budget, Chunk, Pool};

/// The window of the stores the harnesses build.
const WINDOW: usize = 6;

fn pool() -> Pool {
    Pool::new(&Budget::unlimited(), super::rx::SLOT, 0)
}

/// The byte at stream offset `at`: every copy of a byte carries the same.
fn byte(at: usize) -> u8 {
    at as u8 ^ 0x5a
}

/// `len` bytes of the stream from `at`, paid for as they come from below.
fn segment(at: usize, len: usize) -> Chunk {
    let bytes: Vec<u8> = (at..at + len).map(byte).collect();
    Chunk::copy_of(&Budget::unlimited(), &bytes).unwrap()
}

/// Two segments at any offsets and lengths within the window, accepted or
/// overlapping, then what became contiguous taken: the bytes the store
/// holds, waiting or taken, are exactly those of the union of the two
/// ranges, each the stream's byte at its offset, never a second copy.
#[kani::proof]
#[kani::unwind(66)]
#[kani::solver(minisat)]
fn rx_insert_keeps_retained_equal_to_the_union_of_accepted_ranges() {
    let mut store = RxStore::new(WINDOW, Budget::unlimited(), &pool());
    let mut held = [false; WINDOW];
    for _ in 0..2 {
        let at: usize = kani::any();
        let len: usize = kani::any();
        kani::assume(at < WINDOW && len >= 1 && at + len <= WINDOW);
        assert!(store.insert(at, &segment(at, len)).is_ok());
        for i in at..at + len {
            held[i] = true;
        }
    }
    let mut seen = [false; WINDOW];
    for (offset, bytes) in store.waiting() {
        for (i, b) in bytes.iter().enumerate() {
            assert!(!seen[offset + i], "a byte is held twice");
            seen[offset + i] = true;
            assert_eq!(*b, byte(offset + i));
        }
    }
    assert_eq!(seen, held);
}

/// Whatever is committed and read, in any amounts, the window is the
/// capacity less the bytes ready and unread, as the ring's was.
#[kani::proof]
#[kani::unwind(66)]
#[kani::solver(minisat)]
fn rx_window_is_capacity_minus_unread() {
    let mut store = RxStore::new(WINDOW, Budget::unlimited(), &pool());
    let mut unread = 0usize;
    for _ in 0..2 {
        let len: usize = kani::any();
        kani::assume(len >= 1 && len <= store.window());
        assert!(store.insert(0, &segment(0, len)).is_ok());
        let chunk = store.take_contiguous().unwrap();
        assert_eq!(chunk.len(), len);
        store.commit(chunk);
        unread += len;
        assert_eq!(store.window(), WINDOW - unread);
        let most: usize = kani::any();
        kani::assume(most <= WINDOW);
        if let Some(read) = store.pop(most) {
            assert!(read.len() <= most);
            unread -= read.len();
        }
        assert_eq!(store.len(), unread);
        assert_eq!(store.window(), WINDOW - unread);
    }
}

/// After two writes, an acknowledgement of any number of the bytes queued
/// lets go of exactly those: what is queued is the rest, in order, and the
/// window grows by the acknowledged amount.
#[kani::proof]
#[kani::unwind(8)]
#[kani::solver(minisat)]
fn tx_ack_releases_exactly_the_acked_bytes() {
    let mut store = TxStore::new(WINDOW, Budget::unlimited(), &pool());
    let first: usize = kani::any();
    let second: usize = kani::any();
    kani::assume(first >= 1 && second >= 1 && first + second <= WINDOW);
    assert!(store.push(segment(0, first)).is_ok());
    assert!(store.push(segment(first, second)).is_ok());
    let acked: usize = kani::any();
    kani::assume(acked <= first + second);
    store.ack(acked);
    assert_eq!(store.len(), first + second - acked);
    assert_eq!(store.window(), WINDOW - store.len());
    let mut at = 0;
    while at < store.len() {
        let bytes = store.bytes(at, WINDOW);
        assert!(!bytes.is_empty());
        for (i, b) in bytes.iter().enumerate() {
            assert_eq!(*b, byte(acked + at + i));
        }
        at += bytes.len();
    }
}

/// For two writes and any offset and length asked for, the piece a
/// segment is given lies within one chunk: its bytes are those the store
/// names at that offset, no more than asked, cut at the chunk's end.
#[kani::proof]
#[kani::unwind(8)]
#[kani::solver(minisat)]
fn a_piece_never_spans_two_chunks() {
    let mut store = TxStore::new(WINDOW, Budget::unlimited(), &pool());
    let first: usize = kani::any();
    let second: usize = kani::any();
    kani::assume(first >= 1 && second >= 1 && first + second <= WINDOW);
    assert!(store.push(segment(0, first)).is_ok());
    assert!(store.push(segment(first, second)).is_ok());
    let offset: usize = kani::any();
    let len: usize = kani::any();
    kani::assume(offset < first + second && len >= 1 && len <= WINDOW);
    let expected = store.bytes(offset, len).to_vec();
    let ends: Vec<usize> = store.ends().collect();
    let piece = store.piece(offset, len).unwrap();
    assert_eq!(piece.bytes(), &expected[..]);
    assert!(piece.len() <= len);
    let stop = offset + piece.len();
    assert!(
        ends.iter().all(|&end| end <= offset || end >= stop),
        "the piece crosses a chunk's end"
    );
    for (i, b) in piece.bytes().iter().enumerate() {
        assert_eq!(*b, byte(offset + i));
    }
}
