//! IMAP commands and responses, as a world playing a mail server reads
//! them, and as a world playing a client reads the server's.
#![no_main]

use fictionet::stdlib::codec::{Wire, contract};
use fictionet::stdlib::imap::{
    Command, Commands, Decoder, Error, Event, MAX_HELD, MAX_LITERAL, MAX_TEXT, Response,
    ResponseDecoder, Responses, Value,
};
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

/// Like [`events`], but after each continuation request the decoder
/// refuses the literal when the matching byte of `choices` is odd.
/// Whether a literal is refused must not depend on how bytes are split.
fn events_refusing(data: &[u8], step: usize, choices: &[u8]) -> Vec<Result<Event, Error>> {
    let mut d = Decoder::new();
    let mut out = Vec::new();
    let mut k = 0;
    for chunk in data.chunks(step.max(1)) {
        d.feed(chunk);
        while let Some(e) = d.next_event() {
            let fatal = matches!(&e, Err(e) if e.is_fatal());
            let waiting = matches!(e, Ok(Event::Continue { .. }));
            out.push(e);
            if fatal {
                return out;
            }
            if waiting && choices.get(k % choices.len().max(1)).is_some_and(|c| c % 2 == 1) {
                assert!(d.refuse_literal());
                assert!(!d.refuse_literal());
            }
            k += 1;
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
    contract::check_decode_with_held_limit(Commands::new, data, MAX_HELD);
    contract::check_decode_with_held_limit(
        || {
            let mut commands = Commands::new();
            commands.expect_line().unwrap();
            commands
        },
        data,
        MAX_HELD,
    );
    contract::check_decode_with_held_limit(Responses::new, data, MAX_HELD);
    contract::check_wire::<Command>(data);
    contract::check_wire::<Response>(data);
    contract::check_wire_value(&Command::new(
        "a",
        "APPEND",
        vec![Value::Literal {
            data: data.get(..MAX_LITERAL + 1).unwrap_or(data).to_vec(),
            non_sync: data.first().is_some_and(|b| b & 1 == 1),
        }],
    ));
    contract::check_wire_value(&Response::greeting(&String::from_utf8_lossy(
        data.get(..MAX_TEXT + 1).unwrap_or(data),
    )));
    // The stream, split two ways: all at once, and a byte at a time.
    let whole = events(data, data.len());
    assert_eq!(whole, events(data, 1));
    for e in whole.iter().flatten() {
        if let Event::Command(c) = e {
            contract::check_wire_value(c);
            if let Ok(bytes) = Wire::to_bytes(c) {
                contract::check_decode_with_held_limit(Commands::new, &bytes, MAX_HELD);
            }
            // A command read can be written, and reads back the same.
            let bytes = c.to_bytes();
            assert_eq!(&Command::parse(&bytes).unwrap(), c);
            assert_eq!(c.to_chunks().concat(), bytes);
            assert_eq!(events(&bytes, bytes.len()).last(), Some(&Ok(e.clone())));
        }
    }

    let whole = responses(data, data.len());
    assert_eq!(whole, responses(data, 1));
    for r in whole.iter().flatten() {
        contract::check_wire_value(r);
        let bytes = r.to_bytes();
        assert_eq!(&Response::parse(&bytes).unwrap(), r);
        assert_eq!(responses(&bytes, bytes.len()), vec![Ok(r.clone())]);
    }

    // Refusing literals, chosen by the input's first bytes.
    let choices = data.get(..8).unwrap_or(data);
    assert_eq!(events_refusing(data, data.len(), choices), events_refusing(data, 1, choices));

    // Any bytes as one message on their own, and as raw lines.
    let _ = Command::parse(data);
    let _ = Response::parse(data);
    let mut d = Decoder::new();
    d.feed(data);
    while let Some(Ok(_)) = d.next_line() {}
    let _ = d.next_event();
    d.refuse_literal();
});
