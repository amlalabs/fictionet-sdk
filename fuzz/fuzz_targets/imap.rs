//! IMAP literals, refusal decisions, raw lines, and strict wire values.
#![no_main]

use fictionet::stdlib::codec::{Decode, Stream, Wire};
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};

use fictionet::stdlib::protocols::imap::{
    Command, Error, FrameError, Input, Inputs, MAX_HELD, MAX_LINE, MAX_LITERAL, MAX_TEXT, Response,
    Responses, Value,
};
use fictionet::stdlib::test_support::{Scripted, decode_all};
use libfuzzer_sys::fuzz_target;

fn refusals(choices: &[u8]) -> impl Decode<Item = Result<Input, Error>, Error = FrameError> + '_ {
    Scripted::new(
        Inputs::new(),
        (0usize, false),
        |commands, (_, refuse)| {
            if core::mem::take(refuse) {
                assert!(commands.refuse_literal());
                assert!(!commands.refuse_literal());
            }
        },
        move |_, (at, refuse), item| {
            let choice = choices.get(*at % choices.len().max(1));
            *refuse =
                matches!(&item, Ok(Input::Continue { .. })) && choice.is_some_and(|b| b & 1 == 1);
            *at = at.saturating_add(1);
            item
        },
    )
}

fuzz_target!(|data: &[u8]| {
    let commands = decode_all(Inputs::new, data);
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Inputs::new()),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.held() <= MAX_HELD);
                assert!(s.allocated() <= 2 * MAX_LINE);
            }
        ),
        commands
    );
    let responses = decode_all(Responses::new, data);
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Responses::new()),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.held() <= MAX_HELD);
                assert!(s.allocated() <= 2 * MAX_LINE);
            }
        ),
        responses
    );
    let raw = || {
        let mut commands = Inputs::new();
        commands.expect_line().unwrap();
        commands
    };
    assert_eq!(
        decode_chunks(&mut Stream::new(raw()), chunks(data, &[1]), |s| {
            assert!(s.held() <= MAX_HELD);
            assert!(s.allocated() <= 2 * MAX_LINE);
        }),
        decode_all(raw, data)
    );
    let choices = data.get(..8).unwrap_or(data);
    assert_eq!(
        decode_chunks(
            &mut Stream::new(refusals(choices)),
            chunks(data, &[1]),
            |s| {
                assert!(s.held() <= MAX_HELD);
                assert!(s.allocated() <= 2 * MAX_LINE);
            }
        ),
        decode_all(|| refusals(choices), data)
    );
    if let Ok(command) = Command::parse(data) {
        let _ = assert_write(&command);
    }
    if let Ok(response) = Response::parse(data) {
        let _ = assert_write(&response);
    }
    for item in commands.0 {
        if let Ok(Input::Command(command)) = item {
            let Ok(bytes) = assert_write(&command) else {
                continue;
            };
            let offsets = Command::continuation_offsets(&bytes).unwrap();
            assert!(offsets.windows(2).all(|w| w[0] < w[1]));
            assert!(offsets.iter().all(|&at| at <= bytes.len()));
            for at in offsets {
                let header = bytes[..at].strip_suffix(b"}\r\n").unwrap();
                let open = header.iter().rposition(|&b| b == b'{').unwrap();
                let size = &header[open + 1..];
                assert!(!size.is_empty() && size.iter().all(u8::is_ascii_digit));
            }
        }
    }
    for response in responses.0.into_iter().flatten() {
        let _ = assert_write(&response);
    }
    let text = String::from_utf8_lossy(data.get(..MAX_TEXT + 1).unwrap_or(data));
    let payload = data.get(..MAX_LITERAL + 1).unwrap_or(data);
    let non_sync = data.first().is_some_and(|b| b & 1 == 1);
    for value in [
        Value::atom(&text),
        Value::string(payload),
        Value::Literal {
            data: payload.to_vec(),
            non_sync,
        },
        Value::Binary {
            data: payload.to_vec(),
            non_sync,
        },
    ] {
        let _ = assert_write(&Command::new("a", "APPEND", vec![value.clone()]));
        let _ = assert_write(&Response::Data(vec![value]));
    }
    let _ = assert_write(&Command::new(&text, &text, vec![]));
    let _ = assert_write(&Response::greeting(&text));
    let _ = assert_write(&Response::continue_req(&text));
});
