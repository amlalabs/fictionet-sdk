//! PostgreSQL frontend and backend messages, as a world playing a
//! database server, or a client, reads them.
#![no_main]

use fictionet::stdlib::postgres::{
    Backend, BackendDecoder, Decoder, Frontend, SaslInitialResponse, Startup, read_password,
};
use libfuzzer_sys::fuzz_target;

/// Every frontend message a server decoder gives, and the error that
/// ends the stream, if any. The stream is fed `chunk` bytes at a time.
fn frontend(data: &[u8], chunk: usize) -> Vec<Result<Frontend, fictionet::stdlib::postgres::Error>> {
    let mut d = Decoder::new();
    let mut out = Vec::new();
    for piece in data.chunks(chunk) {
        d.feed(piece);
        while let Some(m) = d.next_message() {
            let stop = m.is_err();
            out.push(m);
            if stop {
                return out;
            }
        }
    }
    out
}

/// The same for a client decoder reading backend messages.
fn backend(data: &[u8], chunk: usize) -> Vec<Result<Backend, fictionet::stdlib::postgres::Error>> {
    let mut d = BackendDecoder::new();
    let mut out = Vec::new();
    for piece in data.chunks(chunk) {
        d.feed(piece);
        while let Some(m) = d.next_message() {
            let stop = m.is_err();
            out.push(m);
            if stop {
                return out;
            }
        }
    }
    out
}

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time. The
    // second pass puts a StartupMessage in front, so the fuzzer reaches
    // the typed messages.
    let mut after_startup = Frontend::Startup(Startup::new("u", "d")).to_bytes();
    after_startup.extend_from_slice(data);
    for stream in [data, &after_startup[..]] {
        let whole = frontend(stream, stream.len().max(1));
        assert_eq!(whole, frontend(stream, 1));
        for m in whole.iter().flatten() {
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
    for m in whole.iter().flatten() {
        let bytes = m.to_bytes();
        assert_eq!(Backend::parse(&bytes), Ok(Some((m.clone(), bytes.len()))));
    }

    // Any bytes as a message on their own.
    let _ = Frontend::parse(data);
    let _ = Frontend::parse_startup(data);
    let _ = Backend::parse(data);
});
