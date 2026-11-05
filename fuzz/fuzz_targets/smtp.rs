//! SMTP commands, replies, AUTH lines, DATA, and strict wire values.
#![no_main]

use fictionet::stdlib::codec::{Decode, Fail, Stream, Wire};
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};

use fictionet::stdlib::protocols::smtp::{
    Command, Data, Error, FrameError, Input, Inputs, MAX_AUTH_LINE, MAX_DATA, MAX_DATA_LINE,
    MAX_LINE, MAX_REPLY_TEXT, Replies, Reply, Request,
};
use fictionet::stdlib::test_support::decode_all;
use libfuzzer_sys::fuzz_target;

fn data_server() -> Inputs {
    let mut server = Inputs::new();
    server.start_data().unwrap();
    server
}

fn auth_server() -> Inputs {
    let mut server = Inputs::new();
    server.expect_line().unwrap();
    server
}

fn check_reply(reply: &Reply) {
    if let Ok(bytes) = assert_write(reply) {
        let decoded = decode_chunks(
            &mut Stream::new(Replies::new()),
            chunks(&bytes, &[1]),
            |s| {
                assert!(s.held() <= MAX_REPLY_TEXT);
                assert!(s.allocated() <= 2 * MAX_LINE);
            },
        );
        assert_eq!(decoded, (vec![Ok(reply.clone())], None));
    }
}

fuzz_target!(|data: &[u8]| {
    let commands = decode_chunks(
        &mut Stream::new(Inputs::new()),
        chunks(data, &[1, 7, 64]),
        |s| {
            assert!(s.allocated() <= 2 * (MAX_AUTH_LINE + 2));
            assert!(s.held() <= MAX_DATA);
        },
    );
    assert_eq!(commands, decode_all(Inputs::new, data));
    let replies = decode_chunks(
        &mut Stream::new(Replies::new()),
        chunks(data, &[1, 7, 64]),
        |s| {
            assert!(s.allocated() <= 2 * MAX_LINE);
            assert!(s.held() <= MAX_REPLY_TEXT);
        },
    );
    assert_eq!(replies, decode_all(Replies::new, data));
    let messages = decode_chunks(
        &mut Stream::new(data_server()),
        chunks(data, &[1, 7, 64]),
        |s| {
            assert!(s.allocated() <= 2 * (MAX_AUTH_LINE + 2));
            assert!(s.held() <= MAX_DATA);
        },
    );
    assert_eq!(messages, decode_all(data_server, data));
    let auth = decode_chunks(
        &mut Stream::new(auth_server()),
        chunks(data, &[1, 7, 64]),
        |s| {
            assert!(s.allocated() <= 2 * (MAX_AUTH_LINE + 2));
            assert_eq!(s.held(), 0);
        },
    );
    assert_eq!(auth, decode_all(auth_server, data));
    let (auth, _) = auth;
    for (index, item) in auth.iter().enumerate() {
        if let Ok(Input::Line(line)) = item {
            assert_eq!(index, 0);
            assert!(line.len() <= MAX_AUTH_LINE);
            assert_eq!(data.get(..line.len()), Some(line.as_slice()));
            assert_eq!(
                data.get(line.len()..line.len() + 2),
                Some(b"\r\n".as_slice())
            );
        }
    }
    if let Ok(value) = <Command as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Request as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Reply as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Data as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    for item in commands.0 {
        if let Ok(Input::Command(command)) = item {
            let _ = assert_write(&command);
            if let Ok(request) = Request::from_command(&command) {
                let _ = assert_write(&request);
            }
        }
    }
    let (replies, failure) = replies;
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
    for item in messages.0 {
        if let Ok(Input::Message(bytes)) = item {
            let message = Data { bytes };
            assert_write(&message).unwrap();
        }
    }
    let text = String::from_utf8_lossy(data);
    let (verb, arg) = text
        .split_once(' ')
        .map_or((text.as_ref(), None), |(v, a)| (v, Some(a)));
    let command = Command::new(verb, arg);
    let _ = assert_write(&command);
    let _ = assert_write(&Request::Other(command));
    check_reply(&Reply {
        code: data.first().map_or(250, |b| u16::from(*b) * 3),
        lines: text.split('\n').map(str::to_string).collect(),
    });
    let _ = assert_write(&Data {
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
        let bytes = assert_write(&Data {
            bytes: body.clone(),
        })
        .unwrap();
        let decoded = decode_chunks(&mut Stream::new(data_server()), chunks(&bytes, &[1]), |s| {
            assert!(s.allocated() <= 2 * data_server().capacity());
            assert!(s.held() <= MAX_DATA);
        });
        assert_eq!(decoded, (vec![Ok(Input::Message(body))], None));
    }
});
