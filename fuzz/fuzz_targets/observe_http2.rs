//! The dashboard's HTTP/2 decoder (the built-in `http2` protocol of
//! `observe::Registry`), fed through a `Conversation` as TCP payloads. The
//! first byte picks the chunk size; the rest are the client's bytes after
//! the connection preface, then the server's. Nothing may panic, and the
//! time must stay in proportion to the input.
#![no_main]
use fictionet::observe::{Conversation, Decoded, Place, Registry};
use libfuzzer_sys::fuzz_target;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

fuzz_target!(|data: &[u8]| {
    let Some((&chunk, rest)) = data.split_first() else {
        return;
    };
    let chunk = usize::from(chunk).max(1) * 16;
    let mut c = Conversation::with_registry(40000, 80, Registry::default());
    let mut at = [0u64; 2];
    let mut feed = |dir: bool, bytes: &[u8]| {
        for piece in bytes.chunks(chunk) {
            let mut d = Decoded::default();
            let place = Place {
                stream_start: at[usize::from(dir)],
                buf: 0,
                offset: Some(0),
                len: piece.len(),
            };
            c.data(dir, piece, place, &mut d, &[]);
            at[usize::from(dir)] += piece.len() as u64;
            let _ = d.layers_json();
        }
    };
    feed(false, PREFACE);
    let half = rest.len() / 2;
    feed(false, &rest[..half]);
    feed(true, &rest[half..]);
});
