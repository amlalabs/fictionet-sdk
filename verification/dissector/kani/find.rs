//! Kani proofs over `Http1::find` in src/stdlib/dissect/protocols/http1.rs,
//! the search for the end of a head that resumes where the last call
//! stopped instead of scanning the buffer again. Compiled only under
//! `cargo kani`, as a child module of http1.rs.

use super::*;

/// The longest buffer the harness searches.
const INPUT: usize = 8;

const END: &[u8] = b"\r\n\r\n";

/// The first end of a head in `input`, scanning from its first byte.
fn first_end(input: &[u8]) -> Option<usize> {
    input.windows(END.len()).position(|w| w == END)
}

/// Whatever the decoder remembers from an earlier call that found no end
/// in the first `scanned` bytes (the same bytes, since a head's bytes stay
/// in the buffer until it is read), a search of a buffer that grew from
/// them finds the same end as a search from the first byte, and then
/// forgets; finding none, it remembers the whole buffer. So a head is found
/// at its first blank line, however its bytes arrive.
#[kani::proof]
#[kani::unwind(10)]
fn a_resumed_search_finds_the_first_end() {
    let bytes: [u8; INPUT] = kani::any();
    let len: usize = kani::any();
    let scanned: usize = kani::any();
    kani::assume(len <= INPUT && scanned <= len);
    kani::assume(first_end(&bytes[..scanned]).is_none());
    let mut http = Http1 {
        scanned,
        ..Http1::default()
    };
    let found = http.find(&bytes[..len], END);
    assert_eq!(found, first_end(&bytes[..len]));
    assert_eq!(http.scanned, if found.is_some() { 0 } else { len });
}
