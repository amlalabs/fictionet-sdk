//! Kani proofs over the handshake readers in src/stdlib/dissect/tls.rs:
//! `whole_messages`, which says how much of a record's handshake bytes are
//! whole messages and how much is held for the next record, and
//! `extensions` and `extensions_at`, which read a hello's extensions.
//! Compiled only under `cargo kani`, as a child module of tls.rs.

use super::*;

/// The longest handshake bytes `whole_messages` is given.
const MESSAGES: usize = 10;
/// The longest hello body `extensions` is given: the 34 bytes of version
/// and random, then a few more.
const HELLO: usize = 44;

/// For any bytes up to ten long, `whole_messages` gives a count that walks
/// from the first byte message by message (four bytes of type and length,
/// then the length), ending exactly at the count, and what is left does
/// not start with a whole message. So a record's whole messages are read
/// now and nothing of them is held, and the part of a message cut across
/// records is held whole.
#[kani::proof]
#[kani::unwind(12)]
fn whole_messages_are_read_and_the_rest_is_held() {
    let bytes: [u8; MESSAGES] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= MESSAGES);
    let b = &bytes[..len];
    let whole = whole_messages(b);
    assert!(whole <= len);
    let length = |at: usize| {
        (usize::from(b[at + 1]) << 16) | (usize::from(b[at + 2]) << 8) | usize::from(b[at + 3])
    };
    let mut at = 0;
    while at < whole {
        at += 4 + length(at);
    }
    assert_eq!(at, whole);
    assert!(len - whole < 4 || whole + 4 + length(whole) > len);
}

/// The longest extension block `extensions_at` is given, with room for
/// three extensions.
const BLOCK: usize = 14;

/// For any bytes up to fourteen long and any place in them where an
/// extension block starts, every extension read lies inside the block the
/// two-byte length there names, in order and without overlap, and is as
/// long as its header says.
#[kani::proof]
#[kani::unwind(16)]
fn an_extension_block_is_read_inside_its_length() {
    let bytes: [u8; BLOCK] = kani::any();
    let len: usize = kani::any();
    let start: usize = kani::any();
    kani::assume(len <= BLOCK && start <= len);
    let m = &bytes[..len];
    let base = m.as_ptr() as usize;
    let block = be16(m, start).map_or(0, |n| start + 2 + usize::from(n));
    let mut end = start + 2;
    for (kind, data) in extensions_at(m, start) {
        let at = data.as_ptr() as usize - base;
        assert!(at >= end + 4);
        assert!(at + data.len() <= block.min(len));
        assert_eq!(usize::from(be16(m, at - 2).unwrap()), data.len());
        assert_eq!(be16(m, at - 4).unwrap(), kind);
        end = at + data.len();
    }
}

/// For any hello body up to 44 bytes, of a client or a server, every
/// extension read lies inside the body, in order and without overlap, and
/// is as long as its header says: the offsets of the session id, cipher
/// suites and compression methods before the extensions are read without
/// a read past the end, however the body lies about their lengths.
#[kani::proof]
#[kani::unwind(14)]
fn extensions_lie_inside_the_hello() {
    let bytes: [u8; HELLO] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= HELLO);
    let m = &bytes[..len];
    let base = m.as_ptr() as usize;
    let mut end = 0;
    for (kind, data) in extensions(m, kani::any()) {
        let at = data.as_ptr() as usize - base;
        assert!(at >= end + 4);
        assert!(at + data.len() <= len);
        assert_eq!(usize::from(be16(m, at - 2).unwrap()), data.len());
        assert_eq!(be16(m, at - 4).unwrap(), kind);
        end = at + data.len();
    }
}
