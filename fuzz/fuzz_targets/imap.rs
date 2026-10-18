//! IMAP literals, refusal decisions, raw lines, and strict wire values.
#![no_main]

use fictionet::stdlib::codec::{Decode, Wire};
use fictionet::stdlib::test_support::contract;

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
    contract::check_decode_with_alloc_limit(Inputs::new, data, 2 * MAX_LINE);
    contract::check_decode_with_alloc_limit(Responses::new, data, 2 * MAX_LINE);
    contract::check_decode_with_held_limit(Inputs::new, data, MAX_HELD);
    contract::check_decode_with_held_limit(Responses::new, data, MAX_HELD);
    let raw = || {
        let mut commands = Inputs::new();
        commands.expect_line().unwrap();
        commands
    };
    contract::check_decode_with_alloc_limit(raw, data, 2 * MAX_LINE);
    contract::check_decode_with_held_limit(raw, data, MAX_HELD);
    let choices = data.get(..8).unwrap_or(data);
    contract::check_decode_with_alloc_limit(|| refusals(choices), data, 2 * MAX_LINE);
    contract::check_wire::<Command>(data);
    contract::check_wire::<Response>(data);
    for item in decode_all(Inputs::new, data).0 {
        if let Ok(Input::Command(command)) = item {
            let bytes = command.to_bytes().unwrap();
            contract::check_wire::<Command>(&bytes);
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
    for response in decode_all(Responses::new, data).0.into_iter().flatten() {
        contract::check_wire::<Response>(&response.to_bytes().unwrap());
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
        contract::check_wire_value(&Command::new("a", "APPEND", vec![value.clone()]));
        contract::check_wire_value(&Response::Data(vec![value]));
    }
    contract::check_wire_value(&Command::new(&text, &text, vec![]));
    contract::check_wire_value(&Response::greeting(&text));
    contract::check_wire_value(&Response::continue_req(&text));
});
