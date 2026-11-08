//! Kani proofs over `scan` in src/stdlib/web/httpd/detect.rs, the part of
//! `Detect` that reads a connection's first bytes until they tell HTTP/2's
//! preface from HTTP/1. Compiled only under `cargo kani`, as a child
//! module of detect.rs, so the harness calls the production function.

use super::*;

/// The longest chunk the harness feeds `scan` at once.
const CHUNK: usize = 4;

/// From any point inside the preface (any number of its bytes already
/// read) and for any chunk of up to four bytes, `scan` takes a prefix of
/// the chunk into `first`, each byte once and in order, and leaves the
/// rest for the server it chooses:
///
/// - with no choice, it took the whole chunk and `first` is still a proper
///   prefix of the preface;
/// - HTTP/2 exactly when `first` is now the whole preface;
/// - HTTP/1 exactly at the first byte that differs from the preface,
///   which it took, so HTTP/1 reads it from `first`;
/// - it stops taking only once it has chosen.
///
/// The successor then reads `first` followed by the bytes not taken
/// (`Detect::handover` and `Admit::Partial`), which is the input exactly.
///
/// Each point is its own run: with a symbolic count of bytes already read,
/// CBMC ran out of 12 GiB.
#[kani::proof]
#[kani::unwind(26)]
fn scan_takes_each_byte_once_and_chooses_at_the_first_difference() {
    for read in 0..PREFACE.len() {
        scan_from(read);
    }
}

fn scan_from(read: usize) {
    // `Detect` reserves the preface's length before the first byte.
    let mut first = Vec::with_capacity(PREFACE.len());
    first.extend_from_slice(&PREFACE[..read]);
    let bytes: [u8; CHUNK] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= CHUNK);
    let bytes = &bytes[..len];
    let (taken, chosen) = scan(&mut first, bytes);
    assert!(taken <= len);
    assert_eq!(first.len(), read + taken);
    assert!(first[..read] == PREFACE[..read]);
    assert!(first[read..] == bytes[..taken]);
    match chosen {
        None => {
            assert_eq!(taken, len);
            assert!(first.len() < PREFACE.len());
            assert!(PREFACE.starts_with(&first));
        }
        Some(true) => assert!(first[..] == PREFACE[..]),
        Some(false) => {
            let last = first.len() - 1;
            assert!(PREFACE.starts_with(&first[..last]));
            assert_ne!(first[last], PREFACE[last]);
        }
    }
    if taken < len {
        assert!(chosen.is_some());
    }
    kani::cover!(chosen.is_none());
    kani::cover!(chosen == Some(true));
    kani::cover!(chosen == Some(false) && taken < len);
}
