//! SMTP commands, replies, DATA, and strict wire values.
#![no_main]

use fictionet::stdlib::codec::{Decode, Fail, Wire};
use fictionet::stdlib::test_support::contract;

use fictionet::stdlib::test_support::decode_all;
use fictionet::stdlib::smtp::{
    Command, Data, Error, FrameError, Input, Inputs, MAX_DATA, MAX_DATA_LINE, MAX_LINE,
    MAX_REPLY_TEXT, Replies, Reply, Request,
};
use libfuzzer_sys::fuzz_target;

fn data_server() -> Inputs {
    let mut server = Inputs::new();
    server.start_data().unwrap();
    server
}

fn check_reply(reply: &Reply) {
    contract::check_wire_value(reply);
    if let Ok(bytes) = reply.to_bytes() {
        contract::check_decode_with_held_limit(Replies::new, &bytes, MAX_REPLY_TEXT);
        assert_eq!(
            decode_all(Replies::new, &bytes),
            (vec![Ok(reply.clone())], None)
        );
    }
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(Inputs::new, data, 2 * (MAX_DATA_LINE + 1));
    contract::check_decode_with_alloc_limit(Replies::new, data, 2 * MAX_LINE);
    contract::check_decode_with_alloc_limit(data_server, data, 2 * (MAX_DATA_LINE + 1));
    contract::check_decode_with_held_limit(Inputs::new, data, MAX_DATA);
    contract::check_decode_with_held_limit(Replies::new, data, MAX_REPLY_TEXT);
    contract::check_decode_with_held_limit(data_server, data, MAX_DATA);
    contract::check_wire::<Command>(data);
    contract::check_wire::<Request>(data);
    contract::check_wire::<Reply>(data);
    contract::check_wire::<Data>(data);
    for item in decode_all(Inputs::new, data).0 {
        if let Ok(Input::Command(command)) = item {
            contract::check_wire_value(&command);
            if let Ok(request) = Request::from_command(&command) {
                contract::check_wire_value(&request);
                let bytes = request.to_bytes().unwrap();
                assert_eq!(Request::parse(&bytes), Ok(request));
            }
        }
    }
    let (replies, failure) = decode_all(Replies::new, data);
    match Reply::parse(data) {
        Ok(reply) => assert_eq!(replies.first(), Some(&Ok(reply))),
        Err(Error::Framing(error)) => {
            assert!(replies.is_empty());
            assert_eq!(failure, Some(Fail::Protocol(error)));
        }
        Err(Error::Incomplete) => assert!(replies.is_empty()),
        Err(Error::Trailing) => assert!(matches!(replies.first(), Some(Ok(_)))),
        Err(error) => {
            if let Some(first) = replies.first() {
                assert_eq!(first, &Err(error));
            } else {
                let fatal = match error {
                    Error::LineEnding => FrameError::ReplyLineEnding,
                    Error::Text => FrameError::ReplyText,
                    Error::ReplyCode => FrameError::ReplyCode,
                    Error::ReplyMismatch => FrameError::ReplyMismatch,
                    _ => panic!("{error:?} is not a reply line fault"),
                };
                assert_eq!(failure, Some(Fail::Protocol(fatal)));
            }
        }
    }
    for reply in replies.into_iter().flatten() {
        check_reply(&reply);
    }
    for item in decode_all(data_server, data).0 {
        if let Ok(Input::Message(bytes)) = item {
            let message = Data { bytes };
            contract::check_wire::<Data>(&message.to_bytes().unwrap());
        }
    }
    let text = String::from_utf8_lossy(data);
    let (verb, arg) = text
        .split_once(' ')
        .map_or((text.as_ref(), None), |(v, a)| (v, Some(a)));
    let command = Command::new(verb, arg);
    contract::check_wire_value(&command);
    contract::check_wire_value(&Request::Other(command));
    check_reply(&Reply {
        code: data.first().map_or(250, |b| u16::from(*b) * 3),
        lines: text.split('\n').map(str::to_string).collect(),
    });
    contract::check_wire_value(&Data {
        bytes: data.to_vec(),
    });
    if data.len() <= 4096 {
        let mut body = Vec::new();
        for chunk in data.chunks(MAX_DATA_LINE - 2) {
            body.extend(
                chunk
                    .iter()
                    .copied()
                    .filter(|b| !matches!(b, 0 | b'\r' | b'\n')),
            );
            body.extend_from_slice(b"\r\n");
        }
        let bytes = Data { bytes: body }.to_bytes().unwrap();
        contract::check_wire::<Data>(&bytes);
        contract::check_decode_with_alloc_limit(data_server, &bytes, 2 * data_server().capacity());
    }
});
