//! Protocol readers whose framing the server changes between items: the
//! change applies to the bytes already read past the item, in the same
//! chunk, as a stack that owns its stream reads them.

use fictionet::stdlib::codec::{Stream, Wire};
use fictionet::stdlib::protocols::{imap, postgres, smtp};

/// Reads SMTP from `stream` as a mail server does, switching to DATA after
/// the DATA command. Returns the messages it queued and what it answered.
fn mail(stream: &mut Stream<smtp::Inputs>, messages: &mut Vec<Vec<u8>>, reply: &mut Vec<u8>) {
    while let Some(item) = stream.next() {
        match item
            .expect("the reader never fails here")
            .expect("every item is valid")
        {
            smtp::Input::Command(command) if command.verb == "DATA" => {
                stream.decoder().start_data().unwrap();
                reply.extend_from_slice(b"354 Send data\r\n");
            }
            smtp::Input::Message(bytes) => {
                messages.push(bytes);
                reply.extend_from_slice(b"250 Queued\r\n");
            }
            _ => {}
        }
    }
}

#[test]
fn smtp_data_changes_the_active_decoder() {
    let mut stream = Stream::new(smtp::Inputs::new());
    let (mut messages, mut reply) = (Vec::new(), Vec::new());
    for chunk in [&b"DATA\r\n"[..], b"..hello\r\n.\r\n"] {
        let _ = stream.push(chunk);
        mail(&mut stream, &mut messages, &mut reply);
    }
    assert_eq!(messages, [b".hello\r\n".to_vec()]);
    assert_eq!(reply, b"354 Send data\r\n250 Queued\r\n");
}

#[test]
fn smtp_auth_challenges_cancel_and_handoff_in_one_chunk() {
    let mut stream = Stream::new(smtp::Inputs::new());
    let input = b"AUTH LOGIN\r\ndGVzdA==\r\ndGVz\r\n*\r\nNOOP\r\nSTARTTLS\r\n\x16\x03\x03\0\x05";
    assert_eq!(stream.push(input), input.len());
    let (mut responses, mut reply) = (Vec::new(), Vec::new());
    while let Some(item) = stream.next() {
        match item
            .expect("the reader never fails here")
            .expect("every item is valid")
        {
            smtp::Input::Command(command) if command.verb == "AUTH" => {
                stream.decoder().expect_line().unwrap();
                reply.extend_from_slice(b"334 \r\n");
            }
            smtp::Input::Line(line) => {
                if line == b"*" {
                    reply.extend_from_slice(b"501 Cancelled\r\n");
                } else {
                    stream.decoder().expect_line().unwrap();
                    reply.extend_from_slice(b"334 \r\n");
                }
                responses.push(line);
            }
            smtp::Input::Command(command) if command.verb == "STARTTLS" => {
                stream.decoder().handoff().unwrap();
                reply.extend_from_slice(b"220 Ready\r\n");
            }
            smtp::Input::Command(_) => reply.extend_from_slice(b"250 OK\r\n"),
            smtp::Input::Message(_) => panic!("DATA was not selected"),
        }
    }
    assert_eq!(
        responses,
        [b"dGVzdA==".to_vec(), b"dGVz".to_vec(), b"*".to_vec()]
    );
    assert_eq!(
        reply,
        b"334 \r\n334 \r\n334 \r\n501 Cancelled\r\n250 OK\r\n220 Ready\r\n"
    );
    // The reader stopped at the handoff: the TLS hello is left for what
    // comes next, unread.
    assert!(stream.is_done());
    assert_eq!(stream.unread(), b"\x16\x03\x03\0\x05");
}

#[test]
fn imap_refused_literal_leaves_the_next_command_readable() {
    let mut stream = Stream::new(imap::Inputs::new());
    let (mut commands, mut reply) = (Vec::new(), Vec::new());
    for chunk in [&b"a APPEND inbox {3}\r\n"[..], b"b NOOP\r\n"] {
        let _ = stream.push(chunk);
        while let Some(item) = stream.next() {
            match item
                .expect("the reader never fails here")
                .expect("every item is valid")
            {
                imap::Input::Continue { .. } => {
                    assert!(stream.decoder().refuse_literal());
                    reply.extend_from_slice(b"a NO refused\r\n");
                }
                imap::Input::Command(command) => commands.push(command.name),
                _ => {}
            }
        }
    }
    assert_eq!(commands, ["NOOP"]);
    assert_eq!(reply, b"a NO refused\r\n");
}

#[test]
fn postgres_refused_ssl_reads_startup_from_the_same_chunk() {
    let mut stream = Stream::new(postgres::FrontendMessages::new());
    let mut bytes = postgres::FrontendMessage::SslRequest.to_bytes().unwrap();
    postgres::FrontendMessage::Startup(postgres::Startup::new("agent", "world"))
        .write(&mut bytes)
        .unwrap();
    assert_eq!(stream.push(&bytes), bytes.len());
    let (mut startups, mut reply) = (0, Vec::new());
    while let Some(item) = stream.next() {
        match item
            .expect("the reader never fails here")
            .expect("every item is valid")
        {
            postgres::FrontendMessage::SslRequest => {
                reply.push(b'N');
                stream.decoder().refuse_encryption();
            }
            postgres::FrontendMessage::Startup(_) => startups += 1,
            _ => {}
        }
    }
    assert_eq!(reply, b"N");
    assert_eq!(startups, 1);
}

/// Each datagram is read with a reader of its own, so a mode the server
/// chose for one datagram does not carry into the next.
#[test]
fn datagram_reading_uses_the_current_datagram() {
    let (mut messages, mut replies) = (Vec::new(), Vec::new());
    for datagram in [&b"DATA\r\none\r\n.\r\n"[..], b"DATA\r\ntwo\r\n.\r\n"] {
        let mut stream = Stream::new(smtp::Inputs::new());
        let _ = stream.push(datagram);
        stream.end();
        let mut reply = Vec::new();
        mail(&mut stream, &mut messages, &mut reply);
        replies.push(reply);
    }
    assert_eq!(messages, [b"one\r\n".to_vec(), b"two\r\n".to_vec()]);
    assert_eq!(
        replies,
        [
            b"354 Send data\r\n250 Queued\r\n".to_vec(),
            b"354 Send data\r\n250 Queued\r\n".to_vec()
        ]
    );
}
