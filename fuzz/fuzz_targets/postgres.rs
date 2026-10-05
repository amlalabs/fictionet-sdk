//! PostgreSQL frontend and backend messages, as a world playing a
//! database server, or a client, reads them.
#![no_main]
#![allow(deprecated)] // Also exercise the unchanged compatibility API.

use fictionet::stdlib::codec::{Wire, contract};
use fictionet::stdlib::postgres::{
    Backend, BackendDecoder, BackendMessages, Decoder, EncryptionReply, Error, Frontend, FrontendMessages,
    SMALL_MESSAGE, SaslInitialResponse, Startup, read_password,
};
use libfuzzer_sys::fuzz_target;

/// Every message a decoder gives, with the errors that drop one message
/// and the error that ends the stream, if any. The stream is fed `chunk`
/// bytes at a time; whatever a feed does not take is fed again once the
/// messages are out. Every few feeds an empty one comes between two
/// messages, as a world that reads and feeds in turn would do it.
fn drain<M>(
    data: &[u8],
    chunk: usize,
    mut feed: impl FnMut(&[u8]) -> usize,
    mut next: impl FnMut() -> Option<Result<M, Error>>,
    held: impl Fn() -> (usize, usize),
) -> Vec<Result<M, Error>> {
    let mut out = Vec::new();
    for mut piece in data.chunks(chunk.max(1)) {
        loop {
            let took = feed(piece);
            piece = &piece[took..];
            let (buffered, capacity) = held();
            assert!(buffered <= capacity);
            let before = out.len();
            while let Some(m) = next() {
                let stop = matches!(&m, Err(e) if !e.is_recoverable());
                out.push(m);
                if stop {
                    return out;
                }
                assert_eq!(feed(&[]), 0);
            }
            if piece.is_empty() {
                break;
            }
            // A full decoder always has a message or an error.
            assert!(took > 0 || out.len() > before, "the decoder is stuck");
        }
    }
    out
}

fn frontend(data: &[u8], chunk: usize) -> Vec<Result<Frontend, Error>> {
    // The smallest limit, so a short input can fill the decoder.
    let d = std::cell::RefCell::new(Decoder::new().with_max_message(SMALL_MESSAGE));
    drain(
        data,
        chunk,
        |b| d.borrow_mut().feed(b),
        || d.borrow_mut().next_message(),
        || (d.borrow().buffered(), d.borrow().capacity()),
    )
}

fn backend(data: &[u8], chunk: usize) -> Vec<Result<Backend, Error>> {
    let d = std::cell::RefCell::new(BackendDecoder::new().with_max_message(SMALL_MESSAGE));
    drain(
        data,
        chunk,
        |b| d.borrow_mut().feed(b),
        || d.borrow_mut().next_message(),
        || (d.borrow().buffered(), d.borrow().capacity()),
    )
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode(|| FrontendMessages::with_limit(64), data);
    contract::check_decode(|| FrontendMessages::typed(64), data);
    contract::check_decode(|| BackendMessages::with_limit(64), data);
    contract::check_decode(
        || {
            let mut messages = BackendMessages::with_limit(64);
            messages.expect_encryption();
            messages
        },
        data,
    );
    contract::check_wire::<Frontend>(data);
    contract::check_wire::<Backend>(data);
    contract::check_wire::<EncryptionReply>(data);
    let text = String::from_utf8_lossy(data.get(..4096).unwrap_or(data)).into_owned();
    contract::check_wire_value(&Frontend::Query(text.clone()));
    contract::check_wire_value(&Backend::CommandComplete(text));
    contract::check_wire_value(&Frontend::CancelRequest {
        process_id: 7,
        secret_key: data.get(..257).unwrap_or(data).to_vec(),
    });
    let good = Frontend::Query("select 1".into());
    contract::check_decode(|| FrontendMessages::typed(64), &Wire::to_bytes(&good).unwrap());

    // The stream, split three ways: all at once, a byte at a time, and in
    // pieces whose size the first byte picks. The second pass puts a
    // StartupMessage in front, so the fuzzer reaches the typed messages.
    let odd = 1 + usize::from(data.first().copied().unwrap_or(0));
    let mut after_startup = Frontend::Startup(Startup::new("u", "d")).to_bytes();
    after_startup.extend_from_slice(data);
    for stream in [data, &after_startup[..]] {
        let whole = frontend(stream, stream.len().max(1));
        assert_eq!(whole, frontend(stream, 1));
        assert_eq!(whole, frontend(stream, odd));
        for m in whole.iter().flatten() {
            contract::check_wire_value(m);
            // A message read can be written, and reads back the same.
            let bytes = m.to_bytes();
            let back = if m.is_startup() { Frontend::parse_startup(&bytes) } else { Frontend::parse(&bytes) };
            assert_eq!(back, Ok(Some((m.clone(), bytes.len()))));
            if let Frontend::Startup(s) = m {
                // The user and database PostgreSQL would use: the last
                // value of each, and the user for an empty database.
                if s.database().is_some() {
                    assert!(s.user().is_some() || s.get("database").is_some_and(|d| !d.is_empty()));
                }
            }
            if let Frontend::AuthResponse(body) = m {
                let _ = read_password(body);
                if let Ok(sasl) = SaslInitialResponse::parse(body) {
                    let Frontend::AuthResponse(again) = sasl.to_message() else { panic!() };
                    assert_eq!(SaslInitialResponse::parse(&again), Ok(sasl));
                }
            }
        }
    }

    let whole = backend(data, data.len().max(1));
    assert_eq!(whole, backend(data, 1));
    assert_eq!(whole, backend(data, odd));
    for m in whole.iter().flatten() {
        contract::check_wire_value(m);
        let bytes = m.to_bytes();
        assert_eq!(Backend::parse(&bytes), Ok(Some((m.clone(), bytes.len()))));
    }

    // Any bytes as a message on their own, and as authentication bodies.
    let _ = Frontend::parse(data);
    let _ = Frontend::parse_startup(data);
    let _ = Backend::parse(data);
    let _ = read_password(data);
    let _ = SaslInitialResponse::parse(data);
});
