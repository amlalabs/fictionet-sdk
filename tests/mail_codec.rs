//! Mail line codecs, mode boundaries, literals, and strict wire values.

use fictionet::stdlib::{
    codec::{self, Decode, Fail, Step, Stream, Wire, contract, test_support::chunks},
    imap, pop3, smtp,
};

fn read<D: Decode>(
    decoder: D,
    bytes: &[u8],
    pattern: &[usize],
) -> Vec<Result<D::Item, Fail<D::Error>>>
where
    D::Error: Clone,
{
    let mut stream = Stream::new(decoder);
    let mut items = Vec::new();
    for mut part in chunks(bytes, pattern) {
        while !part.is_empty() && !stream.is_done() {
            let used = stream.push(part);
            part = part.get(used..).unwrap();
            items.extend(core::iter::from_fn(|| stream.next()));
            assert!(used > 0 || stream.is_done());
        }
    }
    stream.end();
    items.extend(core::iter::from_fn(|| stream.next()));
    assert!(stream.is_done());
    assert!(stream.next().is_none());
    items
}

// A test world that accepts each DATA command. Apply its decision on the
// next call, after the previous item has been returned to the driver.
#[derive(Default)]
struct AcceptData {
    server: smtp::Server,
    data: bool,
    switch: bool,
}

impl Decode for AcceptData {
    type Item = Result<smtp::Input, smtp::Error>;
    type Error = smtp::DecodeError;
    const NAME: &'static str = "SMTP test world";

    fn capacity(&self) -> usize {
        self.server.capacity()
    }

    fn held(&self) -> usize {
        self.server.held()
    }

    fn decode(&mut self, bytes: &[u8], eof: bool) -> Result<Step<Self::Item>, Self::Error> {
        if core::mem::take(&mut self.switch) {
            if self.data {
                self.server.start_commands().unwrap();
            } else {
                self.server.start_data().unwrap();
            }
            self.data = !self.data;
        }
        let step = self.server.decode(bytes, eof)?;
        if let Step::Item(item, _) = &step {
            self.switch =
                self.data || matches!(item, Ok(smtp::Input::Command(c)) if c.verb == "DATA");
        }
        Ok(step)
    }
}

#[test]
fn smtp_chunked_commands_data_and_replies() {
    let wire =
        b"EHLO example.test\r\n!bad\r\nDATA\r\nSubject: x\r\n\r\n..dot\r\n...two\r\n.\r\nNOOP\r\n";
    contract::check_stack(AcceptData::default, wire);
    contract::check_decode_with_held_limit(AcceptData::default, wire, smtp::MAX_DATA);
    let expected = vec![
        Ok(Ok(smtp::Input::Command(smtp::Command::new(
            "EHLO",
            Some("example.test"),
        )))),
        Ok(Err(smtp::Error::Verb)),
        Ok(Ok(smtp::Input::Command(smtp::Command::new("DATA", None)))),
        Ok(Ok(smtp::Input::Message(
            b"Subject: x\r\n\r\n.dot\r\n..two\r\n".to_vec(),
        ))),
        Ok(Ok(smtp::Input::Command(smtp::Command::new("NOOP", None)))),
    ];
    for pattern in [&[][..], &[1], &[3, 1, 7], &[512]] {
        assert_eq!(read(AcceptData::default(), wire, pattern), expected);
    }
    let mut encoded = Vec::new();
    for input in expected
        .iter()
        .filter_map(|r| r.as_ref().ok()?.as_ref().ok())
    {
        match input {
            smtp::Input::Command(command) => {
                contract::check_wire_value(command);
                Wire::write(command, &mut encoded).unwrap();
            }
            smtp::Input::Message(message) => encoded.extend(smtp::write_data(message).unwrap()),
        }
    }
    assert_eq!(
        read(AcceptData::default(), &encoded, &[1]),
        expected
            .into_iter()
            .filter(|r| !matches!(r, Ok(Err(_))))
            .collect::<Vec<_>>()
    );

    let replies = b"250-first\r\n250-..unchanged\r\n250 last\r\nbad\r\n550 refused\r\n";
    contract::check_decode_with_held_limit(smtp::Replies::new, replies, smtp::MAX_REPLY_TEXT);
    let items = read(smtp::Replies::new(), replies, &[1]);
    assert_eq!(
        items,
        vec![
            Ok(Ok(smtp::Reply {
                code: 250,
                lines: vec!["first".into(), "..unchanged".into(), "last".into()]
            })),
            Ok(Err(smtp::Error::ReplyCode)),
            Ok(Ok(smtp::Reply::new(550, "refused"))),
        ]
    );
    for reply in items.into_iter().filter_map(|r| r.ok()?.ok()) {
        let wire = Wire::to_bytes(&reply).unwrap();
        contract::check_wire::<smtp::Reply>(&wire);
        assert_eq!(read(smtp::Replies::new(), &wire, &[1]), vec![Ok(Ok(reply))]);
    }
}

#[test]
fn smtp_modes_are_world_decisions_and_handoff_keeps_unread_bytes() {
    let mut stream = Stream::new(smtp::Server::new());
    let wire = b"DATA\r\nNOOP\r\nSTARTTLS\r\n\x16\x03\x03";
    assert_eq!(stream.push(wire), wire.len());
    assert!(matches!(stream.next(), Some(Ok(Ok(smtp::Input::Command(c)))) if c.verb == "DATA"));
    // This world refuses DATA. The following line remains a command.
    assert!(matches!(stream.next(), Some(Ok(Ok(smtp::Input::Command(c)))) if c.verb == "NOOP"));
    assert!(matches!(stream.next(), Some(Ok(Ok(smtp::Input::Command(c)))) if c.verb == "STARTTLS"));
    stream.decoder().handoff().unwrap();
    assert_eq!(stream.next(), None);
    assert_eq!(stream.into_parts().0.unread(), b"\x16\x03\x03");

    let mut stream = Stream::new(smtp::Server::new());
    assert_eq!(stream.push(b"NO"), 2);
    assert_eq!(stream.next(), None);
    assert_eq!(stream.decoder().start_data(), Err(smtp::Error::State));
    assert_eq!(stream.decoder().handoff(), Err(smtp::Error::State));
}

fn pop_replies() -> pop3::Replies {
    let mut replies = pop3::Replies::new();
    for multi in [false, true, true, false] {
        replies.expect(multi).unwrap();
    }
    replies
}

#[test]
fn pop3_chunked_expectations_and_dot_stuffing() {
    let bytes =
        b"+OK ready\r\n+OK message\r\n..dot\r\n...two\r\n\r\n.\r\n-ERR missing\r\n+OK done\r\n";
    let expected = vec![
        Ok(Ok(pop3::Reply::ok("ready"))),
        Ok(Ok(
            pop3::Reply::ok("message").with_body(b".dot\r\n..two\r\n\r\n".to_vec())
        )),
        Ok(Ok(pop3::Reply::err("missing"))),
        Ok(Ok(pop3::Reply::ok("done"))),
    ];
    contract::check_stack(pop_replies, bytes);
    contract::check_decode_with_held_limit(pop_replies, bytes, pop3::MAX_REPLY_HELD);
    for pattern in [&[][..], &[1], &[2, 9, 1], &[4096]] {
        assert_eq!(read(pop_replies(), bytes, pattern), expected);
    }
    let mut encoded = Vec::new();
    for item in &expected {
        let reply = item.as_ref().unwrap().as_ref().unwrap();
        contract::check_wire_value(reply);
        let wire = Wire::to_bytes(reply).unwrap();
        contract::check_wire::<pop3::Reply>(&wire);
        encoded.extend(wire);
    }
    assert_eq!(read(pop_replies(), &encoded, &[1]), expected);

    let commands = b"USER alice\r\n!\r\nRETR 1\r\nQUIT\r\n";
    contract::check_decode(pop3::Commands::new, commands);
    let got = read(pop3::Commands::new(), commands, &[1]);
    assert_eq!(got.get(1), Some(&Ok(Err(pop3::CommandError::BadKeyword))));
    for command in got.into_iter().filter_map(|r| r.ok()?.ok()) {
        let wire = Wire::to_bytes(&command).unwrap();
        contract::check_wire::<pop3::Command>(&wire);
        assert_eq!(
            read(pop3::Commands::new(), &wire, &[1]),
            vec![Ok(Ok(command))]
        );
    }
}

#[test]
fn pop3_expectation_queue_is_explicit_bounded_and_transactional() {
    let mut decoder = pop3::Replies::new();
    assert_eq!(
        decoder.decode(b"+OK x\r\n", false),
        Err(pop3::DecodeError::MissingExpectation)
    );
    for _ in 0..pop3::MAX_EXPECTATIONS {
        decoder.expect(false).unwrap();
    }
    assert_eq!(
        decoder.expect(true),
        Err(pop3::DecodeError::ExpectationsFull)
    );
    assert_eq!(decoder.expected(), pop3::MAX_EXPECTATIONS);
    assert!(matches!(
        decoder.decode(b"+OK x\r\n", false),
        Ok(Step::Item(Ok(_), 7))
    ));
    assert_eq!(decoder.expected(), pop3::MAX_EXPECTATIONS - 1);
    decoder.expect(true).unwrap();

    let mut stream = Stream::new(pop3::Replies::new());
    stream.decoder().expect(true).unwrap();
    let bytes = b"+OK x\r\n..x\r\n.\r\n+OK y\r\n";
    assert_eq!(stream.push(bytes), bytes.len());
    assert_eq!(
        stream.next(),
        Some(Ok(Ok(pop3::Reply::ok("x").with_body(b".x\r\n".to_vec()))))
    );
    stream.decoder().expect(false).unwrap();
    assert_eq!(stream.next(), Some(Ok(Ok(pop3::Reply::ok("y")))));
}

#[test]
fn imap_chunked_literals_commands_and_responses() {
    // The first literal contains a line ending. The second is non-synchronizing.
    let bytes = b"a APPEND INBOX {5}\r\nx\r\nyz {3+}\r\nabc\r\nb NOOP\r\ninvalid\r\nc LOGOUT\r\n";
    contract::check_stack(imap::Commands::new, bytes);
    contract::check_decode_with_held_limit(imap::Commands::new, bytes, imap::MAX_HELD);
    let expected = read(imap::Commands::new(), bytes, &[]);
    for pattern in [&[1][..], &[3, 1, 7], &[64]] {
        assert_eq!(read(imap::Commands::new(), bytes, pattern), expected);
    }
    assert!(matches!(
        expected.first(),
        Some(Ok(Ok(imap::Event::Continue { size: 5, .. })))
    ));
    assert!(matches!(
        expected.get(3),
        Some(Ok(Err(imap::Error::Syntax { .. })))
    ));
    let Some(Ok(Ok(imap::Event::Command(command)))) = expected.get(1) else {
        panic!()
    };
    assert_eq!(
        command.args.get(1).and_then(imap::Value::as_bytes),
        Some(&b"x\r\nyz"[..])
    );
    assert_eq!(
        command.args.get(2),
        Some(&imap::Value::Literal {
            data: b"abc".to_vec(),
            non_sync: true
        })
    );
    for command in expected.iter().filter_map(|item| match item {
        Ok(Ok(imap::Event::Command(command))) => Some(command),
        _ => None,
    }) {
        contract::check_wire_value(command);
        let bytes = Wire::to_bytes(command).unwrap();
        contract::check_wire::<imap::Command>(&bytes);
        assert_eq!(
            read(imap::Commands::new(), &bytes, &[1]).last(),
            Some(&Ok(Ok(imap::Event::Command(command.clone()))))
        );
    }

    let response = imap::Response::fetch(
        1,
        vec![
            imap::Value::atom("BINARY[]"),
            imap::Value::Binary {
                data: b"\0\r\n".to_vec(),
                non_sync: false,
            },
        ],
    );
    let mut bytes = Wire::to_bytes(&response).unwrap();
    bytes.extend_from_slice(b"* OK literal-looking text {7}\r\na OK complete\r\n");
    contract::check_decode_with_held_limit(imap::Responses::new, &bytes, imap::MAX_HELD);
    let replies = read(imap::Responses::new(), &bytes, &[1]);
    assert_eq!(replies.first(), Some(&Ok(Ok(response))));
    assert_eq!(replies.len(), 3);
    for reply in replies.into_iter().map(|r| r.unwrap().unwrap()) {
        contract::check_wire_value(&reply);
        let bytes = Wire::to_bytes(&reply).unwrap();
        contract::check_wire::<imap::Response>(&bytes);
        assert_eq!(
            read(imap::Responses::new(), &bytes, &[1]),
            vec![Ok(Ok(reply))]
        );
    }
}

#[test]
fn imap_literal_refusal_zero_length_and_limits() {
    let mut stream = Stream::new(imap::Commands::new());
    let bytes = b"a APPEND {9}\r\nb NOOP\r\n";
    assert_eq!(stream.push(bytes), bytes.len());
    assert!(matches!(
        stream.next(),
        Some(Ok(Ok(imap::Event::Continue { size: 9, .. })))
    ));
    assert!(stream.decoder().refuse_literal());
    assert!(!stream.decoder().refuse_literal());
    assert!(matches!(stream.next(), Some(Ok(Ok(imap::Event::Command(c)))) if c.tag == "b"));

    for bytes in [
        b"a X {0}\r\n\r\n".as_slice(),
        b"a X {0+}\r\n\r\n",
        b"a X {1}\r\nx {0+}\r\n\r\n",
    ] {
        contract::check_decode(imap::Commands::new, bytes);
        contract::check_wire::<imap::Command>(bytes);
        assert!(<imap::Command as Wire>::parse(bytes).is_ok());
    }
    let sync = format!("a X {{{}}}\r\nb NOOP\r\n", imap::MAX_LITERAL + 1);
    let items = read(imap::Commands::new(), sync.as_bytes(), &[1]);
    assert!(matches!(
        items.first(),
        Some(Ok(Err(imap::Error::LiteralTooLarge { waiting: true, .. })))
    ));
    assert!(matches!(
        items.get(1),
        Some(Ok(Ok(imap::Event::Command(_))))
    ));
    for size in [imap::MAX_NON_SYNC_LITERAL + 1, imap::MAX_LITERAL + 1] {
        let bytes = format!("a X {{{size}+}}\r\n");
        contract::check_decode(imap::Commands::new, bytes.as_bytes());
        assert!(matches!(
            read(imap::Commands::new(), bytes.as_bytes(), &[1]).first(),
            Some(Err(Fail::Protocol(imap::DecodeError::Limit(_))))
        ));
    }
    for bytes in [
        b"a X {4}\r\nx".as_slice(),
        b"a X {4+}\r\nxyz",
        b"a X {0+}\r\n",
    ] {
        assert!(matches!(
            read(imap::Commands::new(), bytes, &[1]).last(),
            Some(Err(Fail::Protocol(imap::DecodeError::Incomplete)))
        ));
    }
}

#[test]
fn line_errors_recover_and_overflow_ends_streams() {
    assert_eq!(
        read(smtp::Server::new(), b"NOOP\nQUIT\r\n", &[1]),
        vec![
            Ok(Err(smtp::Error::LineEnding)),
            Ok(Ok(smtp::Input::Command(smtp::Command::new("QUIT", None)))),
        ]
    );
    assert_eq!(
        read(pop3::Commands::new(), b"NOOP\nQUIT\r\n", &[1]),
        vec![
            Ok(Err(pop3::CommandError::BadCharacter)),
            Ok(Ok(pop3::Command {
                keyword: "QUIT".into(),
                argument: None
            })),
        ]
    );
    let imap = read(imap::Commands::new(), b"a NOOP\nb NOOP\r\n", &[1]);
    assert!(matches!(
        imap.first(),
        Some(Ok(Err(imap::Error::Syntax { .. })))
    ));
    assert!(matches!(imap.last(), Some(Ok(Ok(imap::Event::Command(_))))));

    let smtp = vec![b'x'; smtp::MAX_LINE];
    contract::check_decode(smtp::Server::new, &smtp);
    assert!(matches!(
        read(smtp::Server::new(), &smtp, &[1]).as_slice(),
        [Err(Fail::Protocol(smtp::DecodeError::Line(
            codec::LineError::TooLong { .. }
        )))]
    ));
    let pop = vec![b'x'; pop3::MAX_COMMAND_LINE];
    contract::check_decode(pop3::Commands::new, &pop);
    assert!(matches!(
        read(pop3::Commands::new(), &pop, &[1]).as_slice(),
        [Err(Fail::Protocol(pop3::DecodeError::Line(
            codec::LineError::TooLong { .. }
        )))]
    ));
    let imap = vec![b'x'; imap::MAX_LINE];
    contract::check_decode(imap::Commands::new, &imap);
    assert!(matches!(
        read(imap::Commands::new(), &imap, &[1]).as_slice(),
        [Err(Fail::Protocol(imap::DecodeError::Line(
            codec::LineError::TooLong { .. }
        )))]
    ));
}

#[test]
fn exact_wire_and_transactional_writers() {
    for bytes in [b"NOOP".as_slice(), b"NOOP\n", b"NOOP\r\nQUIT\r\n"] {
        assert!(<smtp::Command as Wire>::parse(bytes).is_err());
        assert!(<pop3::Command as Wire>::parse(bytes).is_err());
    }
    assert!(<smtp::Reply as Wire>::parse(b"250 x\r\n250 y\r\n").is_err());
    assert!(<pop3::Reply as Wire>::parse(b"+OK x\r\n.\r\n+OK y\r\n").is_err());
    assert!(<imap::Command as Wire>::parse(b"a NOOP\r\nb NOOP\r\n").is_err());
    assert!(<imap::Response as Wire>::parse(b"a OK x\r\nb OK y\r\n").is_err());

    fn refused<T: Wire + core::fmt::Debug + PartialEq>(value: &T) {
        contract::check_wire_value(value);
        let mut bytes = b"prefix".to_vec();
        assert!(Wire::write(value, &mut bytes).is_err());
        assert_eq!(bytes, b"prefix");
    }
    refused(&smtp::Command::new("noop", None));
    refused(&smtp::Reply {
        code: 250,
        lines: vec!["valid".into(), "invalid\n".into()],
    });
    refused(&pop3::Command {
        keyword: "noop".into(),
        argument: None,
    });
    refused(&pop3::Command {
        keyword: "NOOP".into(),
        argument: Some(String::new()),
    });
    refused(&pop3::Reply::ok("x").with_body(b"bare\n".to_vec()));
    refused(&pop3::Reply::ok("x\r"));
    refused(&imap::Command::new("bad tag", "NOOP", vec![]));
    refused(&imap::Command::new(
        "a",
        "X",
        vec![imap::Value::Quoted(b"x\ny".to_vec())],
    ));
    refused(&imap::Command::new(
        "a",
        "X",
        vec![imap::Value::Literal {
            data: vec![b'x'; imap::MAX_NON_SYNC_LITERAL + 1],
            non_sync: true,
        }],
    ));
    refused(&imap::Response::tagged("a", imap::Status::Bye, "bye"));
    refused(&imap::Response::greeting("bad\ntext"));
}

#[test]
fn smtp_exact_limits_and_assembly_errors() {
    let command = smtp::Command::new("NOOP", Some(&"x".repeat(smtp::MAX_LINE - 7)));
    let bytes = Wire::to_bytes(&command).unwrap();
    assert_eq!(bytes.len(), smtp::MAX_LINE);
    contract::check_wire::<smtp::Command>(&bytes);
    contract::check_decode(smtp::Server::new, &bytes);
    let reply = smtp::Reply::new(250, &"x".repeat(smtp::MAX_LINE - 6));
    let bytes = Wire::to_bytes(&reply).unwrap();
    assert_eq!(bytes.len(), smtp::MAX_LINE);
    contract::check_wire::<smtp::Reply>(&bytes);
    contract::check_decode(smtp::Replies::new, &bytes);

    let mut message = b".".to_vec();
    message.extend(vec![b'x'; smtp::MAX_DATA_LINE - 3]);
    message.extend_from_slice(b"\r\n");
    let mut bytes = b"DATA\r\n".to_vec();
    bytes.extend(smtp::write_data(&message).unwrap());
    bytes.extend_from_slice(b"QUIT\r\n");
    contract::check_decode(AcceptData::default, &bytes);
    let items = read(AcceptData::default(), &bytes, &[1]);
    assert_eq!(items.get(1), Some(&Ok(Ok(smtp::Input::Message(message)))));
    // The extra byte is allowed only when it is a transparency dot.
    let mut oversized = b"DATA\r\n".to_vec();
    oversized.extend(vec![b'x'; smtp::MAX_DATA_LINE - 1]);
    oversized.extend_from_slice(b"\r\n.\r\n");
    assert_eq!(
        read(AcceptData::default(), &oversized, &[1]).last(),
        Some(&Err(Fail::Protocol(smtp::DecodeError::Limit(
            smtp::Error::LineTooLong
        ))))
    );
    let broken = b"DATA\r\nbad\0line\r\n..valid\r\n.\r\nQUIT\r\n";
    contract::check_decode(AcceptData::default, broken);
    let items = read(AcceptData::default(), broken, &[1]);
    assert_eq!(items.get(1), Some(&Ok(Err(smtp::Error::Text))));
    assert!(matches!(items.last(), Some(Ok(Ok(smtp::Input::Command(c)))) if c.verb == "QUIT"));
    assert_eq!(
        read(AcceptData::default(), b"DATA\r\n", &[1]).last(),
        Some(&Err(Fail::Protocol(smtp::DecodeError::Incomplete)))
    );
    assert_eq!(
        read(smtp::Replies::new(), b"250-continue\r\n", &[1]),
        vec![Err(Fail::Protocol(smtp::DecodeError::Incomplete))]
    );
    let mismatch = b"250-first\r\n550 last\r\n250 next\r\n";
    contract::check_decode(smtp::Replies::new, mismatch);
    assert_eq!(
        read(smtp::Replies::new(), mismatch, &[1]),
        vec![
            Ok(Err(smtp::Error::ReplyMismatch)),
            Ok(Ok(smtp::Reply::new(250, "next")))
        ]
    );
    let too_many = b"250-\r\n".repeat(smtp::MAX_REPLY_LINES);
    assert_eq!(
        read(smtp::Replies::new(), &too_many, &[1]),
        vec![Err(Fail::Protocol(smtp::DecodeError::Limit(
            smtp::Error::ReplyLines
        )))]
    );
}

#[test]
fn pop3_exact_limits_and_assembly_errors() {
    let command = pop3::Command {
        keyword: "USER".into(),
        argument: Some("x".repeat(pop3::MAX_COMMAND_LINE - 7)),
    };
    let bytes = Wire::to_bytes(&command).unwrap();
    assert_eq!(bytes.len(), pop3::MAX_COMMAND_LINE);
    contract::check_wire::<pop3::Command>(&bytes);
    contract::check_decode(pop3::Commands::new, &bytes);
    let reply = pop3::Reply::ok(&"x".repeat(pop3::MAX_REPLY_LINE - 6));
    let bytes = Wire::to_bytes(&reply).unwrap();
    assert_eq!(bytes.len(), pop3::MAX_REPLY_LINE);
    contract::check_wire::<pop3::Reply>(&bytes);

    let mut body = b".".to_vec();
    body.extend(vec![b'x'; pop3::MAX_DATA_LINE - 4]);
    body.extend_from_slice(b"\r\n");
    let reply = pop3::Reply::ok("x").with_body(body);
    let bytes = Wire::to_bytes(&reply).unwrap();
    let multi = || {
        let mut replies = pop3::Replies::new();
        replies.expect(true).unwrap();
        replies
    };
    contract::check_wire::<pop3::Reply>(&bytes);
    contract::check_decode(multi, &bytes);
    assert_eq!(read(multi(), &bytes, &[1]), vec![Ok(Ok(reply))]);
    assert_eq!(
        read(multi(), b"+OK x\r\n", &[1]),
        vec![Err(Fail::Protocol(pop3::DecodeError::Incomplete))]
    );
    let mut too_long = b"+OK x\r\n".to_vec();
    too_long.extend(vec![b'x'; pop3::MAX_DATA_LINE - 1]);
    too_long.extend_from_slice(b"\r\n.\r\n");
    contract::check_decode(multi, &too_long);
    assert!(matches!(
        read(multi(), &too_long, &[1]).as_slice(),
        [Err(Fail::Protocol(pop3::DecodeError::Line(
            codec::LineError::TooLong { .. }
        )))]
    ));

    let expected = || {
        let mut replies = multi();
        replies.expect(false).unwrap();
        replies
    };
    for broken in [
        b"+OK x\r\nbare\n.\r\n+OK y\r\n".as_slice(),
        b"bad\r\n+OK y\r\n",
    ] {
        contract::check_decode(expected, broken);
        assert_eq!(
            read(expected(), broken, &[1]),
            vec![
                Ok(Err(pop3::ReplyError::BadStatus)),
                Ok(Ok(pop3::Reply::ok("y")))
            ]
        );
    }
}

#[test]
fn imap_line_text_and_literal_limits() {
    let command = imap::Command::new(
        "a",
        "X",
        vec![imap::Value::atom(&"x".repeat(imap::MAX_LINE - 6))],
    );
    let bytes = Wire::to_bytes(&command).unwrap();
    assert_eq!(bytes.len(), imap::MAX_LINE);
    contract::check_wire::<imap::Command>(&bytes);
    assert!(matches!(
        read(imap::Commands::new(), &bytes, &[1]).as_slice(),
        [Ok(Ok(imap::Event::Command(_)))]
    ));
    for (size, non_sync) in [
        (imap::MAX_LITERAL, false),
        (imap::MAX_NON_SYNC_LITERAL, true),
    ] {
        let command = imap::Command::new(
            "a",
            "X",
            vec![imap::Value::Literal {
                data: vec![b'x'; size],
                non_sync,
            }],
        );
        let bytes = Wire::to_bytes(&command).unwrap();
        contract::check_wire::<imap::Command>(&bytes);
        assert_eq!(
            read(imap::Commands::new(), &bytes, &[1, 65536]).last(),
            Some(&Ok(Ok(imap::Event::Command(command))))
        );
    }
    let text = "x".repeat(imap::MAX_TEXT / 2);
    let bytes = format!("a X {text} {{0+}}\r\n {text}\r\n");
    assert_eq!(
        read(imap::Commands::new(), bytes.as_bytes(), &[1]),
        vec![Err(Fail::Protocol(imap::DecodeError::Limit(
            imap::Error::TooLong
        )))]
    );
    let bytes = b"a X {999999999999999999999999999999999999+}\r\n";
    contract::check_decode(imap::Commands::new, bytes);
    assert!(matches!(
        read(imap::Commands::new(), bytes, &[1]).as_slice(),
        [Err(Fail::Protocol(imap::DecodeError::Limit(
            imap::Error::LiteralTooLarge { .. }
        )))]
    ));
    let broken = b"a X {2+}\r\n\0x\r\nb NOOP\r\n";
    contract::check_decode(imap::Commands::new, broken);
    let items = read(imap::Commands::new(), broken, &[1]);
    assert!(matches!(
        items.first(),
        Some(Ok(Err(imap::Error::Syntax { .. })))
    ));
    assert!(matches!(items.last(), Some(Ok(Ok(imap::Event::Command(c)))) if c.tag == "b"));
    let broken = b"* 1 FETCH (BODY[] {2}\r\nx";
    contract::check_decode(imap::Responses::new, broken);
    assert_eq!(
        read(imap::Responses::new(), broken, &[1]),
        vec![Err(Fail::Protocol(imap::DecodeError::Incomplete))]
    );
}

#[test]
fn unterminated_lines_fail_once() {
    assert!(matches!(
        read(smtp::Server::new(), b"NOOP\r", &[1]).as_slice(),
        [Err(Fail::Protocol(smtp::DecodeError::Line(
            codec::LineError::Unterminated
        )))]
    ));
    assert!(matches!(
        read(pop3::Commands::new(), b"NOOP\r", &[1]).as_slice(),
        [Err(Fail::Protocol(pop3::DecodeError::Line(
            codec::LineError::Unterminated
        )))]
    ));
    assert!(matches!(
        read(imap::Commands::new(), b"a NOOP\r", &[1]).as_slice(),
        [Err(Fail::Protocol(imap::DecodeError::Line(
            codec::LineError::Unterminated
        )))]
    ));
    let mut stream = Stream::new(smtp::Server::new());
    assert_eq!(stream.push(&vec![b'x'; smtp::MAX_LINE]), smtp::MAX_LINE);
    let failure = stream.next().unwrap().unwrap_err();
    assert_eq!(stream.failed(), Some(&failure));
    assert_eq!(stream.next(), None);
    assert_eq!(stream.push(b"QUIT\r\n"), 6);
    assert_eq!(stream.next(), None);
}

#[test]
fn imap_bad_line_end_after_a_counted_literal_keeps_sync() {
    let bytes = b"a X {3+}\r\nabc\nb NOOP\r\n";
    contract::check_decode(imap::Commands::new, bytes);
    let items = read(imap::Commands::new(), bytes, &[1]);
    assert!(
        matches!(items.first(), Some(Ok(Err(imap::Error::Syntax { tag: Some(tag), .. }))) if tag == "a")
    );
    assert!(matches!(items.last(), Some(Ok(Ok(imap::Event::Command(c)))) if c.tag == "b"));
    let status = b"* OK text {3}\n* OK next\r\n";
    contract::check_decode(imap::Responses::new, status);
    let items = read(imap::Responses::new(), status, &[1]);
    assert!(matches!(
        items.first(),
        Some(Ok(Err(imap::Error::Syntax { .. })))
    ));
    assert_eq!(
        items.last(),
        Some(&Ok(Ok(imap::Response::greeting("next"))))
    );
    let broken = b"a X {3+}\nabc\r\n";
    contract::check_decode(imap::Commands::new, broken);
    assert_eq!(
        read(imap::Commands::new(), broken, &[1]),
        vec![Err(Fail::Protocol(imap::DecodeError::Line(
            codec::LineError::BareLf
        )))]
    );
}

#[test]
fn assemblies_stop_at_named_body_limits() {
    let mut smtp = Stream::new(smtp::Server::new());
    smtp.decoder().start_data().unwrap();
    let mut line = vec![b'x'; smtp::MAX_DATA_LINE - 2];
    line.extend_from_slice(b"\r\n");
    for _ in 0..=smtp::MAX_DATA / line.len() {
        let result = codec::pump(&mut smtp, &line, |_| panic!("no terminator sent"));
        assert!(smtp.held() <= smtp::MAX_DATA);
        if let Err(error) = result {
            assert_eq!(
                error,
                Fail::Protocol(smtp::DecodeError::Limit(smtp::Error::TooMuchData))
            );
            break;
        }
    }
    assert!(smtp.failed().is_some());

    let mut pop = Stream::new(pop3::Replies::new());
    pop.decoder().expect(true).unwrap();
    codec::pump(&mut pop, b"+OK body\r\n", |_| panic!("body still pending")).unwrap();
    let mut line = vec![b'x'; pop3::MAX_DATA_LINE - 2];
    line.extend_from_slice(b"\r\n");
    for _ in 0..=pop3::MAX_BODY / line.len() {
        let result = codec::pump(&mut pop, &line, |_| panic!("no terminator sent"));
        assert!(pop.held() <= pop3::MAX_REPLY_HELD);
        if let Err(error) = result {
            assert_eq!(error, Fail::Protocol(pop3::DecodeError::BodyTooLong));
            break;
        }
    }
    assert!(pop.failed().is_some());
}
