//! SMTP commands, replies, DATA and stream chunking invariance.
#![no_main]

use fictionet::stdlib::codec::{Wire, contract};
use fictionet::stdlib::smtp::{
    Command, CommandDecoder, Error, MAX_BUFFERED, MAX_DATA, MAX_REPLY_TEXT, Replies, Reply,
    ReplyDecoder, Request, Server, write_data,
};
use libfuzzer_sys::fuzz_target;

fn commands(data: &[u8], size: usize, drain_each: bool) -> Vec<Result<Command, Error>> {
    let mut decoder = CommandDecoder::new();
    let mut out = Vec::new();
    for mut chunk in data.chunks(size.max(1)) {
        while !chunk.is_empty() {
            let n = decoder.feed(chunk);
            chunk = &chunk[n..];
            assert!(decoder.buffered() <= MAX_BUFFERED);
            if drain_each || !chunk.is_empty() {
                out.extend(std::iter::from_fn(|| decoder.next_command()));
                assert!(n > 0 || decoder.buffered() < MAX_BUFFERED);
            }
        }
    }
    out.extend(std::iter::from_fn(|| decoder.next_command()));
    out
}

fn replies(data: &[u8], size: usize) -> Vec<Result<Reply, Error>> {
    let mut decoder = ReplyDecoder::new();
    let mut out = Vec::new();
    for mut chunk in data.chunks(size.max(1)) {
        while !chunk.is_empty() {
            let n = decoder.feed(chunk);
            chunk = &chunk[n..];
            assert!(decoder.buffered() <= MAX_BUFFERED);
            while let Some(reply) = decoder.next_reply() {
                let failed = reply.is_err();
                out.push(reply);
                if failed {
                    assert_eq!(decoder.buffered(), 0);
                    assert_eq!(decoder.next_reply(), out.last().cloned());
                    return out;
                }
            }
            assert!(n > 0 || decoder.buffered() < MAX_BUFFERED);
        }
    }
    out
}

fn message(data: &[u8], size: usize) -> Option<Result<Vec<u8>, Error>> {
    let mut decoder = CommandDecoder::new();
    decoder.start_data().unwrap();
    for mut chunk in data.chunks(size.max(1)) {
        while !chunk.is_empty() {
            let n = decoder.feed(chunk);
            chunk = &chunk[n..];
            assert!(decoder.buffered() <= MAX_BUFFERED);
            assert!(decoder.data_buffered() <= MAX_DATA);
            if let Some(result) = decoder.next_data() {
                return Some(result);
            }
            assert!(n > 0 || decoder.buffered() < MAX_BUFFERED);
        }
    }
    None
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_held_limit(Server::new, data, MAX_DATA);
    contract::check_decode_with_held_limit(Replies::new, data, MAX_REPLY_TEXT);
    contract::check_decode_with_held_limit(
        || {
            let mut server = Server::new();
            server.start_data().unwrap();
            server
        },
        data,
        MAX_DATA,
    );
    contract::check_wire::<Command>(data);
    contract::check_wire::<Reply>(data);
    let got = commands(data, data.len(), true);
    for (size, drain) in [(1, true), (7, false), (MAX_BUFFERED + 1, false)] {
        assert_eq!(commands(data, size, drain), got);
    }
    for command in got.iter().flatten() {
        let bytes = command.to_bytes().unwrap();
        assert_eq!(commands(&bytes, 1, true), [Ok(command.clone())]);
        if let Ok(request) = Request::from_command(command) {
            let bytes = request.to_bytes().unwrap();
            let back = Command::parse(&bytes[..bytes.len() - 2]).unwrap();
            assert_eq!(Request::from_command(&back), Ok(request));
        }
    }
    let got = replies(data, data.len());
    assert_eq!(replies(data, 1), got);
    for reply in got.iter().flatten() {
        let bytes = reply.to_bytes().unwrap();
        assert_eq!(Reply::parse(&bytes), Ok(Some((reply.clone(), bytes.len()))));
    }
    match Reply::parse(data) {
        Ok(Some((reply, _))) => assert_eq!(got.first(), Some(&Ok(reply))),
        Err(error) => assert_eq!(got.first(), Some(&Err(error))),
        Ok(None) => assert!(got.is_empty()),
    }
    assert_eq!(message(data, data.len()), message(data, 1));
    if let Some(Ok(body)) = message(data, 7) {
        let bytes = write_data(&body).unwrap();
        assert_eq!(message(&bytes, 1), Some(Ok(body)));
    }
    let text = String::from_utf8_lossy(data);
    let (verb, arg) = text
        .split_once(' ')
        .map_or((text.as_ref(), None), |(v, a)| (v, Some(a)));
    let command = Command::new(verb, arg);
    contract::check_wire_value(&command);
    if let Ok(bytes) = command.to_bytes() {
        let mut expected = command;
        expected.verb.make_ascii_uppercase();
        assert_eq!(commands(&bytes, 1, true), [Ok(expected)]);
    }
    let reply = Reply {
        code: 250,
        lines: text.split('\n').map(str::to_string).collect(),
    };
    contract::check_wire_value(&reply);
    if let Ok(bytes) = Wire::to_bytes(&reply) {
        contract::check_decode_with_held_limit(Replies::new, &bytes, MAX_REPLY_TEXT);
    }
    if let Ok(bytes) = reply.to_bytes() {
        assert_eq!(Reply::parse(&bytes), Ok(Some((reply, bytes.len()))));
    }
    if let Ok(bytes) = write_data(data) {
        assert_eq!(message(&bytes, 1), Some(Ok(data.to_vec())));
    }
    // Build valid 8-bit DATA as well as feeding arbitrary framing.
    if data.len() <= 4096 {
        let mut body = Vec::new();
        for chunk in data.chunks(998) {
            body.extend(
                chunk
                    .iter()
                    .copied()
                    .filter(|b| !matches!(b, 0 | b'\r' | b'\n')),
            );
            body.extend_from_slice(b"\r\n");
        }
        let bytes = write_data(&body).unwrap();
        assert_eq!(message(&bytes, 1), Some(Ok(body)));
    }
    let _ = Command::parse(data);
});
