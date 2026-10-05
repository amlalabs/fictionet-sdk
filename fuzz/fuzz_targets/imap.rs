//! IMAP commands and responses, as a world playing a mail server reads
//! them, and as a world playing a client reads the server's.
#![no_main]

use fictionet::stdlib::imap::{Command, Decoder, Error, Event, Response, ResponseDecoder};
use libfuzzer_sys::fuzz_target;

/// Every event a decoder gives, fed `data` in chunks of `step` bytes,
/// up to and including the first fatal error.
fn events(data: &[u8], step: usize) -> Vec<Result<Event, Error>> {
    let mut d = Decoder::new();
    let mut out = Vec::new();
    for chunk in data.chunks(step.max(1)) {
        d.feed(chunk);
        while let Some(e) = d.next_event() {
            let fatal = matches!(&e, Err(e) if e.is_fatal());
            out.push(e);
            if fatal {
                return out;
            }
        }
    }
    out
}

fn responses(data: &[u8], step: usize) -> Vec<Result<Response, Error>> {
    let mut d = ResponseDecoder::new();
    let mut out = Vec::new();
    for chunk in data.chunks(step.max(1)) {
        d.feed(chunk);
        while let Some(r) = d.next_response() {
            let fatal = matches!(&r, Err(e) if e.is_fatal());
            out.push(r);
            if fatal {
                return out;
            }
        }
    }
    out
}

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time.
    let whole = events(data, data.len());
    assert_eq!(whole, events(data, 1));
    for e in whole.iter().flatten() {
        if let Event::Command(c) = e {
            // A command read can be written, and reads back the same.
            let bytes = c.to_bytes();
            assert_eq!(&Command::parse(&bytes).unwrap(), c);
            assert_eq!(events(&bytes, bytes.len()).last(), Some(&Ok(e.clone())));
        }
    }

    let whole = responses(data, data.len());
    assert_eq!(whole, responses(data, 1));
    for r in whole.iter().flatten() {
        let bytes = r.to_bytes();
        assert_eq!(&Response::parse(&bytes).unwrap(), r);
        assert_eq!(responses(&bytes, bytes.len()), vec![Ok(r.clone())]);
    }

    // Any bytes as one message on their own, and as raw lines.
    let _ = Command::parse(data);
    let _ = Response::parse(data);
    let mut d = Decoder::new();
    d.feed(data);
    while let Some(Ok(_)) = d.next_line() {}
    let _ = d.next_event();
    d.refuse_literal();
});
