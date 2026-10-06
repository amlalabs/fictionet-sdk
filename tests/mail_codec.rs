//! Mail line codecs, mode boundaries, literals, and strict wire values.

use fictionet::stdlib::{
    codec::{self, Decode, Fail, Step, Stream, Wire, contract, test_support::decode_all},
    imap, pop3, smtp,
};

#[test]
fn imap_literal_continuation_reports_tag_and_size() {
    let mut stream = Stream::new(imap::Commands::new());
    let bytes = b"a LOGIN user {4}\r\n";
    assert_eq!(stream.push(bytes), bytes.len());
    assert_eq!(
        stream.next(),
        Some(Ok(Ok(imap::Input::Continue {
            tag: Some("a".into()),
            size: 4,
        })))
    );
}

#[test]
fn mail_write_errors_share_one_variant_and_message() {
    let error = smtp::WriteError::Unwritable;
    assert_eq!(error.to_string(), "mail value cannot be written unchanged");
    let mut out = Vec::new();
    assert_eq!(smtp::Command::new("noop", None).write(&mut out), Err(error));
    assert_eq!(
        pop3::Command {
            keyword: "noop".into(),
            argument: None
        }
        .write(&mut out),
        Err(error)
    );
    assert_eq!(
        imap::Command::new("bad tag", "NOOP", vec![]).write(&mut out),
        Err(error)
    );
}

fn read<D: Decode>(decoder: D, bytes: &[u8]) -> Vec<Result<D::Item, Fail<D::Error>>>
where
    D::Error: Clone,
{
    let (items, failure) = decode_all(|| decoder, bytes);
    items.into_iter().map(Ok).chain(failure.map(Err)).collect()
}

fn read_with<D: Decode, F>(
    decoder: D,
    bytes: &[u8],
    between: F,
) -> Vec<Result<D::Item, Fail<D::Error>>>
where
    D::Error: Clone,
    F: FnMut(&mut D, &D::Item),
{
    struct World<D, F> {
        decoder: D,
        between: F,
    }
    impl<D: Decode, F: FnMut(&mut D, &D::Item)> Decode for World<D, F> {
        type Item = D::Item;
        type Error = D::Error;
        const NAME: &'static str = D::NAME;
        fn capacity(&self) -> usize {
            self.decoder.capacity()
        }
        fn held(&self) -> usize {
            self.decoder.held()
        }
        fn decode(&mut self, bytes: &[u8], eof: bool) -> Result<Step<Self::Item>, Self::Error> {
            let step = self.decoder.decode(bytes, eof)?;
            if let Step::Item(item, _) = &step {
                (self.between)(&mut self.decoder, item);
            }
            Ok(step)
        }
    }
    read(World { decoder, between }, bytes)
}

// A test world that accepts each DATA command. Apply its decision on the
// next call, after the previous item has been returned to the driver.
#[derive(Default)]
struct AcceptData {
    server: smtp::Server,
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
            self.server.start_data().unwrap();
        }
        let step = self.server.decode(bytes, eof)?;
        if let Step::Item(item, _) = &step {
            self.switch = matches!(item, Ok(smtp::Input::Command(c)) if c.verb == "DATA");
        }
        Ok(step)
    }
}

#[test]
fn smtp_chunked_commands_data_and_replies() {
    let wire =
        b"EHLO example.test\r\n!bad\r\nDATA\r\nSubject: x\r\n\r\n..dot\r\n...two\r\n.\r\nNOOP\r\n";
    contract::check_decode_with_alloc_limit(
        AcceptData::default,
        wire,
        AcceptData::default().capacity().saturating_mul(2),
    );
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
    assert_eq!(read(AcceptData::default(), wire), expected);
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
            smtp::Input::Message(message) => smtp::Data {
                bytes: message.clone(),
            }
            .write(&mut encoded)
            .unwrap(),
        }
    }
    assert_eq!(
        read(AcceptData::default(), &encoded),
        expected
            .into_iter()
            .filter(|r| !matches!(r, Ok(Err(_))))
            .collect::<Vec<_>>()
    );

    let replies = b"250-first\r\n250-..unchanged\r\n250 last\r\nbad\r\n550 refused\r\n";
    contract::check_decode_with_held_limit(smtp::Replies::new, replies, smtp::MAX_REPLY_TEXT);
    contract::check_decode_with_alloc_limit(
        smtp::Replies::new,
        replies,
        smtp::Replies::new().capacity().saturating_mul(2),
    );
    let items = read(smtp::Replies::new(), replies);
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
        assert_eq!(read(smtp::Replies::new(), &wire), vec![Ok(Ok(reply))]);
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
    assert_eq!(stream.decoder().start_data(), Err(smtp::DecodeError::State));
    assert_eq!(stream.decoder().handoff(), Err(smtp::DecodeError::State));
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
        Ok(Ok(pop3::Output::Reply(pop3::Reply::ok("ready")))),
        Ok(Ok(pop3::Output::Reply(
            pop3::Reply::ok("message").with_body(b".dot\r\n..two\r\n\r\n".to_vec()),
        ))),
        Ok(Ok(pop3::Output::Reply(pop3::Reply::err("missing")))),
        Ok(Ok(pop3::Output::Reply(pop3::Reply::ok("done")))),
    ];
    contract::check_decode_with_alloc_limit(
        pop_replies,
        bytes,
        pop_replies().capacity().saturating_mul(2),
    );
    contract::check_decode_with_held_limit(pop_replies, bytes, pop3::MAX_REPLY_HELD);
    assert_eq!(read(pop_replies(), bytes), expected);
    let mut encoded = Vec::new();
    for item in &expected {
        let pop3::Output::Reply(reply) = item.as_ref().unwrap().as_ref().unwrap() else {
            panic!()
        };
        contract::check_wire_value(reply);
        let wire = Wire::to_bytes(reply).unwrap();
        contract::check_wire::<pop3::Reply>(&wire);
        encoded.extend(wire);
    }
    assert_eq!(read(pop_replies(), &encoded), expected);

    let commands = b"USER alice\r\n!\r\nRETR 1\r\nQUIT\r\n";
    contract::check_decode_with_alloc_limit(
        pop3::Commands::new,
        commands,
        (pop3::Commands::new)().capacity().saturating_mul(2),
    );
    let got = read(pop3::Commands::new(), commands);
    assert_eq!(got.get(1), Some(&Ok(Err(pop3::CommandError::BadKeyword))));
    for item in got.into_iter().filter_map(|r| r.ok()?.ok()) {
        let pop3::Input::Command(command) = item else {
            panic!()
        };
        let wire = Wire::to_bytes(&command).unwrap();
        contract::check_wire::<pop3::Command>(&wire);
        assert_eq!(
            read(pop3::Commands::new(), &wire),
            vec![Ok(Ok(pop3::Input::Command(command)))]
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
        Some(Ok(Ok(pop3::Output::Reply(
            pop3::Reply::ok("x").with_body(b".x\r\n".to_vec())
        ))))
    );
    stream.decoder().expect(false).unwrap();
    assert_eq!(
        stream.next(),
        Some(Ok(Ok(pop3::Output::Reply(pop3::Reply::ok("y")))))
    );
}

#[test]
fn imap_chunked_literals_commands_and_responses() {
    // The first literal contains a line ending. The second is non-synchronizing.
    let bytes = b"a APPEND INBOX {5}\r\nx\r\nyz {3+}\r\nabc\r\nb NOOP\r\ninvalid\r\nc LOGOUT\r\n";
    contract::check_decode_with_alloc_limit(
        imap::Commands::new,
        bytes,
        imap::Commands::new().capacity().saturating_mul(2),
    );
    contract::check_decode_with_held_limit(imap::Commands::new, bytes, imap::MAX_HELD);
    let expected = read(imap::Commands::new(), bytes);
    assert_eq!(read(imap::Commands::new(), bytes), expected);
    assert!(matches!(
        expected.first(),
        Some(Ok(Ok(imap::Input::Continue { size: 5, .. })))
    ));
    assert!(matches!(
        expected.get(3),
        Some(Ok(Err(imap::Error::Syntax { .. })))
    ));
    let Some(Ok(Ok(imap::Input::Command(command)))) = expected.get(1) else {
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
        Ok(Ok(imap::Input::Command(command))) => Some(command),
        _ => None,
    }) {
        contract::check_wire_value(command);
        let bytes = Wire::to_bytes(command).unwrap();
        contract::check_wire::<imap::Command>(&bytes);
        assert_eq!(
            read(imap::Commands::new(), &bytes).last(),
            Some(&Ok(Ok(imap::Input::Command(command.clone()))))
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
    contract::check_decode_with_alloc_limit(
        imap::Responses::new,
        &bytes,
        imap::Responses::new().capacity().saturating_mul(2),
    );
    let replies = read(imap::Responses::new(), &bytes);
    assert_eq!(replies.first(), Some(&Ok(Ok(response))));
    assert_eq!(replies.len(), 3);
    for reply in replies.into_iter().map(|r| r.unwrap().unwrap()) {
        contract::check_wire_value(&reply);
        let bytes = Wire::to_bytes(&reply).unwrap();
        contract::check_wire::<imap::Response>(&bytes);
        assert_eq!(
            read(imap::Responses::new(), &bytes),
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
        Some(Ok(Ok(imap::Input::Continue { size: 9, .. })))
    ));
    assert!(stream.decoder().refuse_literal());
    assert!(!stream.decoder().refuse_literal());
    assert!(matches!(stream.next(), Some(Ok(Ok(imap::Input::Command(c)))) if c.tag == "b"));

    for bytes in [
        b"a X {0}\r\n\r\n".as_slice(),
        b"a X {0+}\r\n\r\n",
        b"a X {1}\r\nx {0+}\r\n\r\n",
    ] {
        contract::check_decode_with_alloc_limit(
            imap::Commands::new,
            bytes,
            imap::Commands::new().capacity().saturating_mul(2),
        );
        contract::check_wire::<imap::Command>(bytes);
        assert!(<imap::Command as Wire>::parse(bytes).is_ok());
    }
    let sync = format!("a X {{{}}}\r\nb NOOP\r\n", imap::MAX_LITERAL + 1);
    let items = read(imap::Commands::new(), sync.as_bytes());
    assert!(matches!(
        items.first(),
        Some(Ok(Err(imap::Error::LiteralTooLarge { waiting: true, .. })))
    ));
    assert!(matches!(
        items.get(1),
        Some(Ok(Ok(imap::Input::Command(_))))
    ));
    for size in [imap::MAX_NON_SYNC + 1, imap::MAX_LITERAL + 1] {
        let bytes = format!("a X {{{size}+}}\r\n");
        contract::check_decode_with_alloc_limit(
            imap::Commands::new,
            bytes.as_bytes(),
            imap::Commands::new().capacity().saturating_mul(2),
        );
        assert!(matches!(
            read(imap::Commands::new(), bytes.as_bytes()).first(),
            Some(Err(Fail::Protocol(imap::DecodeError::Limit(_))))
        ));
    }
    for bytes in [
        b"a X {4}\r\nx".as_slice(),
        b"a X {4+}\r\nxyz",
        b"a X {0+}\r\n",
    ] {
        assert!(matches!(
            read(imap::Commands::new(), bytes).last(),
            Some(Err(Fail::Protocol(imap::DecodeError::Incomplete)))
        ));
    }
}

#[test]
fn command_line_errors_recover_and_imap_overflow_ends_streams() {
    assert_eq!(
        read(smtp::Server::new(), b"NOOP\nQUIT\r\n"),
        vec![
            Ok(Err(smtp::Error::LineEnding)),
            Ok(Ok(smtp::Input::Command(smtp::Command::new("QUIT", None)))),
        ]
    );
    assert_eq!(
        read(pop3::Commands::new(), b"NOOP\nQUIT\r\n"),
        vec![
            Ok(Err(pop3::CommandError::BadCharacter)),
            Ok(Ok(pop3::Input::Command(pop3::Command {
                keyword: "QUIT".into(),
                argument: None
            }))),
        ]
    );
    let imap = read(imap::Commands::new(), b"a NOOP\nb NOOP\r\n");
    assert!(matches!(
        imap.first(),
        Some(Ok(Err(imap::Error::Syntax { .. })))
    ));
    assert!(matches!(imap.last(), Some(Ok(Ok(imap::Input::Command(_))))));

    let smtp = vec![b'x'; smtp::MAX_LINE];
    contract::check_decode_with_alloc_limit(
        smtp::Server::new,
        &smtp,
        smtp::Server::new().capacity().saturating_mul(2),
    );
    assert!(matches!(
        read(smtp::Server::new(), &smtp).as_slice(),
        [Ok(Err(smtp::Error::LineTooLong))]
    ));
    let pop = vec![b'x'; pop3::MAX_COMMAND_LINE];
    contract::check_decode_with_alloc_limit(
        pop3::Commands::new,
        &pop,
        (pop3::Commands::new)().capacity().saturating_mul(2),
    );
    assert!(matches!(
        read(pop3::Commands::new(), &pop).as_slice(),
        [Ok(Err(pop3::CommandError::LineTooLong))]
    ));
    let imap = vec![b'x'; imap::MAX_LINE];
    contract::check_decode_with_alloc_limit(
        imap::Commands::new,
        &imap,
        imap::Commands::new().capacity().saturating_mul(2),
    );
    assert!(matches!(
        read(imap::Commands::new(), &imap).as_slice(),
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
            data: vec![b'x'; imap::MAX_NON_SYNC + 1],
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
    contract::check_decode_with_alloc_limit(
        smtp::Server::new,
        &bytes,
        smtp::Server::new().capacity().saturating_mul(2),
    );
    let reply = smtp::Reply::new(250, &"x".repeat(smtp::MAX_LINE - 6));
    let bytes = Wire::to_bytes(&reply).unwrap();
    assert_eq!(bytes.len(), smtp::MAX_LINE);
    contract::check_wire::<smtp::Reply>(&bytes);
    contract::check_decode_with_alloc_limit(
        smtp::Replies::new,
        &bytes,
        smtp::Replies::new().capacity().saturating_mul(2),
    );

    let mut message = b".".to_vec();
    message.extend(vec![b'x'; smtp::MAX_DATA_LINE - 3]);
    message.extend_from_slice(b"\r\n");
    let mut bytes = b"DATA\r\n".to_vec();
    smtp::Data {
        bytes: message.clone(),
    }
    .write(&mut bytes)
    .unwrap();
    bytes.extend_from_slice(b"QUIT\r\n");
    contract::check_decode_with_alloc_limit(
        AcceptData::default,
        &bytes,
        AcceptData::default().capacity().saturating_mul(2),
    );
    let items = read(AcceptData::default(), &bytes);
    assert_eq!(items.get(1), Some(&Ok(Ok(smtp::Input::Message(message)))));
    // The extra byte is allowed only when it is a transparency dot.
    let mut oversized = b"DATA\r\n".to_vec();
    oversized.extend(vec![b'x'; smtp::MAX_DATA_LINE - 1]);
    oversized.extend_from_slice(b"\r\n.\r\n");
    assert_eq!(
        read(AcceptData::default(), &oversized).last(),
        Some(&Err(Fail::Protocol(smtp::DecodeError::Limit(
            smtp::Error::LineTooLong
        ))))
    );
    let broken = b"DATA\r\nbad\0line\r\n..valid\r\n.\r\nQUIT\r\n";
    contract::check_decode_with_alloc_limit(
        AcceptData::default,
        broken,
        AcceptData::default().capacity().saturating_mul(2),
    );
    let items = read(AcceptData::default(), broken);
    assert_eq!(items.get(1), Some(&Ok(Err(smtp::Error::Text))));
    assert!(matches!(items.last(), Some(Ok(Ok(smtp::Input::Command(c)))) if c.verb == "QUIT"));
    assert_eq!(
        read(AcceptData::default(), b"DATA\r\n").last(),
        Some(&Err(Fail::Protocol(smtp::DecodeError::Incomplete)))
    );
    assert_eq!(
        read(smtp::Replies::new(), b"250-continue\r\n"),
        vec![Err(Fail::Protocol(smtp::DecodeError::Incomplete))]
    );
    let mismatch = b"250-first\r\n550 last\r\n250 next\r\n";
    contract::check_decode_with_alloc_limit(
        smtp::Replies::new,
        mismatch,
        smtp::Replies::new().capacity().saturating_mul(2),
    );
    assert_eq!(
        read(smtp::Replies::new(), mismatch),
        vec![Err(Fail::Protocol(smtp::DecodeError::Reply(
            smtp::Error::ReplyMismatch
        )))]
    );
    let too_many = b"250-\r\n".repeat(smtp::MAX_REPLY_LINES);
    assert_eq!(
        read(smtp::Replies::new(), &too_many),
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
    contract::check_decode_with_alloc_limit(
        pop3::Commands::new,
        &bytes,
        (pop3::Commands::new)().capacity().saturating_mul(2),
    );
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
    contract::check_decode_with_alloc_limit(multi, &bytes, multi().capacity().saturating_mul(2));
    assert_eq!(
        read(multi(), &bytes),
        vec![Ok(Ok(pop3::Output::Reply(reply)))]
    );
    assert_eq!(
        read(multi(), b"+OK x\r\n"),
        vec![Err(Fail::Protocol(pop3::DecodeError::Incomplete))]
    );
    let mut too_long = b"+OK x\r\n".to_vec();
    too_long.extend(vec![b'x'; pop3::MAX_DATA_LINE - 1]);
    too_long.extend_from_slice(b"\r\n.\r\n");
    contract::check_decode_with_alloc_limit(multi, &too_long, multi().capacity().saturating_mul(2));
    assert!(matches!(
        read(multi(), &too_long).as_slice(),
        [Err(Fail::Protocol(pop3::DecodeError::Line(
            codec::LineError::TooLong { .. }
        )))]
    ));

    let expected = || {
        let mut replies = multi();
        replies.expect(false).unwrap();
        replies
    };
    let broken = b"+OK x\r\nbare\n.\r\n+OK y\r\n";
    contract::check_decode_with_alloc_limit(
        expected,
        broken,
        expected().capacity().saturating_mul(2),
    );
    assert_eq!(
        read(expected(), broken),
        vec![
            Ok(Err(pop3::ReplyItemError::BadBodyLine)),
            Ok(Ok(pop3::Output::Reply(pop3::Reply::ok("y")))),
        ]
    );
    let broken = b"bad\r\n+OK y\r\n";
    contract::check_decode_with_alloc_limit(
        expected,
        broken,
        expected().capacity().saturating_mul(2),
    );
    assert_eq!(
        read(expected(), broken),
        vec![Err(Fail::Protocol(pop3::DecodeError::Reply(
            pop3::ReplyError::BadStatus
        )))]
    );
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
        read(imap::Commands::new(), &bytes).as_slice(),
        [Ok(Ok(imap::Input::Command(_)))]
    ));
    for (size, non_sync) in [(imap::MAX_LITERAL, false), (imap::MAX_NON_SYNC, true)] {
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
            read(imap::Commands::new(), &bytes).last(),
            Some(&Ok(Ok(imap::Input::Command(command))))
        );
    }
    let text = "x".repeat(imap::MAX_TEXT / 2);
    let bytes = format!("a X {text} {{0+}}\r\n {text}\r\n");
    assert_eq!(
        read(imap::Commands::new(), bytes.as_bytes()),
        vec![Err(Fail::Protocol(imap::DecodeError::Limit(
            imap::Error::TooLong
        )))]
    );
    let bytes = b"a X {999999999999999999999999999999999999+}\r\n";
    contract::check_decode_with_alloc_limit(
        imap::Commands::new,
        bytes,
        imap::Commands::new().capacity().saturating_mul(2),
    );
    assert!(matches!(
        read(imap::Commands::new(), bytes).as_slice(),
        [Err(Fail::Protocol(imap::DecodeError::Limit(
            imap::Error::LiteralTooLarge { .. }
        )))]
    ));
    let broken = b"a X {2+}\r\n\0x\r\nb NOOP\r\n";
    contract::check_decode_with_alloc_limit(
        imap::Commands::new,
        broken,
        imap::Commands::new().capacity().saturating_mul(2),
    );
    let items = read(imap::Commands::new(), broken);
    assert!(matches!(
        items.first(),
        Some(Ok(Err(imap::Error::Syntax { .. })))
    ));
    assert!(matches!(items.last(), Some(Ok(Ok(imap::Input::Command(c)))) if c.tag == "b"));
    let broken = b"* 1 FETCH (BODY[] {2}\r\nx";
    contract::check_decode_with_alloc_limit(
        imap::Responses::new,
        broken,
        imap::Responses::new().capacity().saturating_mul(2),
    );
    assert_eq!(
        read(imap::Responses::new(), broken),
        vec![Err(Fail::Protocol(imap::DecodeError::Incomplete))]
    );
}

#[test]
fn unterminated_lines_fail_once() {
    assert!(matches!(
        read(smtp::Server::new(), b"NOOP\r").as_slice(),
        [Err(Fail::Protocol(smtp::DecodeError::Line(
            codec::LineError::Unterminated
        )))]
    ));
    assert!(matches!(
        read(pop3::Commands::new(), b"NOOP\r").as_slice(),
        [Err(Fail::Protocol(pop3::DecodeError::Line(
            codec::LineError::Unterminated
        )))]
    ));
    assert!(matches!(
        read(imap::Commands::new(), b"a NOOP\r").as_slice(),
        [Err(Fail::Protocol(imap::DecodeError::Line(
            codec::LineError::Unterminated
        )))]
    ));
    let mut stream = Stream::new(smtp::Replies::new());
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
    contract::check_decode_with_alloc_limit(
        imap::Commands::new,
        bytes,
        imap::Commands::new().capacity().saturating_mul(2),
    );
    let items = read(imap::Commands::new(), bytes);
    assert!(
        matches!(items.first(), Some(Ok(Err(imap::Error::Syntax { tag: Some(tag), .. }))) if tag == "a")
    );
    assert!(matches!(items.last(), Some(Ok(Ok(imap::Input::Command(c)))) if c.tag == "b"));
    let status = b"* OK text {3}\n* OK next\r\n";
    contract::check_decode_with_alloc_limit(
        imap::Responses::new,
        status,
        imap::Responses::new().capacity().saturating_mul(2),
    );
    let items = read(imap::Responses::new(), status);
    assert!(matches!(
        items.first(),
        Some(Ok(Err(imap::Error::Syntax { .. })))
    ));
    assert_eq!(
        items.last(),
        Some(&Ok(Ok(imap::Response::greeting("next"))))
    );
    let broken = b"a X {3+}\nabc\r\n";
    contract::check_decode_with_alloc_limit(
        imap::Commands::new,
        broken,
        imap::Commands::new().capacity().saturating_mul(2),
    );
    assert_eq!(
        read(imap::Commands::new(), broken),
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

#[test]
fn imap_aggregate_literals_stop_at_the_message_limit() {
    let mut wire = b"a X".to_vec();
    let header = format!(" {{{}}}\r\n", imap::MAX_LITERAL);
    for _ in 0..3 {
        wire.extend_from_slice(header.as_bytes());
        wire.extend(std::iter::repeat_n(b'x', imap::MAX_LITERAL));
    }
    wire.extend_from_slice(header.as_bytes());
    wire.extend_from_slice(b"b NOOP\r\n");
    contract::check_decode_with_alloc_limit(imap::Commands::new, &wire, 2 * imap::MAX_LINE);
    contract::check_decode_with_held_limit(imap::Commands::new, &wire, imap::MAX_HELD);
    let items = read(imap::Commands::new(), &wire);
    assert_eq!(items.len(), 5);
    assert!(
        matches!(items.get(3), Some(Ok(Err(imap::Error::LiteralTooLarge {
        size, waiting: true, ..
    }))) if *size == imap::MAX_LITERAL as u64)
    );
    assert!(matches!(items.last(), Some(Ok(Ok(imap::Input::Command(c)))) if c.tag == "b"));

    wire[..3].copy_from_slice(b"* X");
    contract::check_decode_with_alloc_limit(imap::Responses::new, &wire, 2 * imap::MAX_LINE);
    contract::check_decode_with_held_limit(imap::Responses::new, &wire, imap::MAX_HELD);
    assert!(matches!(
        read(imap::Responses::new(), &wire).as_slice(),
        [Err(Fail::Protocol(imap::DecodeError::Limit(
            imap::Error::LiteralTooLarge { .. }
        )))]
    ));
}

#[test]
fn smtp_long_command_recovers() {
    let bytes = [vec![b'X'; 600], b"\r\nNOOP\r\n".to_vec()].concat();
    assert_eq!(
        read(smtp::Server::new(), &bytes),
        vec![
            Ok(Err(smtp::Error::LineTooLong)),
            Ok(Ok(smtp::Input::Command(smtp::Command::new("NOOP", None)))),
        ]
    );
}

#[test]
fn pop3_long_command_recovers() {
    let bytes = [vec![b'X'; 300], b"\r\nNOOP\r\n".to_vec()].concat();
    let items = read(pop3::Commands::new(), &bytes);
    assert_eq!(
        items.first(),
        Some(&Ok(Err(pop3::CommandError::LineTooLong)))
    );
    assert!(matches!(items.get(1), Some(Ok(Ok(_)))));
    assert_eq!(items.len(), 2);
}

#[test]
fn pop3_auth_answer() {
    let bytes = [
        b"AUTH GSSAPI\r\n".to_vec(),
        vec![b'Y'; 400],
        b"\r\nQUIT\r\n".to_vec(),
    ]
    .concat();
    let items = read_with(pop3::Commands::new(), &bytes, |decoder, item| {
        if matches!(item, Ok(pop3::Input::Command(c)) if c.keyword == "AUTH") {
            decoder.expect_line().unwrap();
        }
    });
    assert!(matches!(items.first(), Some(Ok(Ok(pop3::Input::Command(c)))) if c.keyword == "AUTH"));
    assert_eq!(
        items.get(1),
        Some(&Ok(Ok(pop3::Input::Line(vec![b'Y'; 400]))))
    );
    assert!(matches!(items.get(2), Some(Ok(Ok(pop3::Input::Command(c)))) if c.keyword == "QUIT"));
    assert_eq!(items.len(), 3);
}

#[test]
fn pop3_auth_challenge() {
    for size in [600, 1] {
        let challenge = [b"+ ".to_vec(), vec![b'x'; size]].concat();
        let bytes = [challenge.clone(), b"\r\n+OK done\r\n".to_vec()].concat();
        let mut replies = pop3::Replies::new();
        replies.expect(false).unwrap();
        replies.expect(false).unwrap();
        replies.expect_line().unwrap();
        let items = read_with(replies, &bytes, |decoder, item| {
            assert_eq!(
                decoder.expected(),
                if matches!(item, Ok(pop3::Output::Line(_))) {
                    2
                } else {
                    1
                }
            );
        });
        assert_eq!(
            items,
            vec![
                Ok(Ok(pop3::Output::Line(challenge.clone()))),
                Ok(Ok(pop3::Output::Reply(pop3::Reply::ok("done")))),
            ]
        );
    }
}

#[test]
fn pop3_bad_multiline_status_stops() {
    let expected = || {
        let mut replies = pop3::Replies::new();
        replies.expect(true).unwrap();
        replies.expect(false).unwrap();
        replies
    };
    let bytes = b"+OK \xff\r\n+OK deleted\r\n.\r\n";
    let items = read(expected(), bytes);
    assert!(matches!(items.as_slice(), [Err(Fail::Protocol(_))]));
}

#[test]
fn smtp_bad_multiline_reply_stops() {
    let bytes = b"250-a\r\n250-\xff\r\n250 c\r\n354 go\r\n";
    let items = read(smtp::Replies::new(), bytes);
    assert!(matches!(items.as_slice(), [Err(Fail::Protocol(_))]));
}

#[test]
fn smtp_data_returns_to_commands() {
    for message in [b"x\r\n.\r\n".as_slice(), b".\r\n", b"bad\0line\r\n.\r\n"] {
        let mut stream = Stream::new(smtp::Server::new());
        assert_eq!(stream.push(b"DATA\r\n"), 6);
        assert!(matches!(
            stream.next(),
            Some(Ok(Ok(smtp::Input::Command(_))))
        ));
        stream.decoder().start_data().unwrap();
        assert_eq!(stream.push(message), message.len());
        assert!(matches!(stream.next(), Some(Ok(_))));
        stream.end();
        assert_eq!(stream.next(), None);
        assert!(stream.failed().is_none());
    }
}

#[test]
fn imap_server_non_sync_literals_keep_following_responses() {
    for first in [
        b"* 1 FETCH (BODY[] {3+}\r\n".as_slice(),
        b"* 1 FETCH (BODY[] {5000+}\r\n",
        b"* 1 FETCH (BODY[] {3+}\n",
    ] {
        let bytes = [first, b"* OK a\r\n* OK b\r\n"].concat();
        let items = read(imap::Responses::new(), &bytes);
        assert!(matches!(
            items.first(),
            Some(Ok(Err(imap::Error::Syntax { .. })))
        ));
        assert_eq!(items.get(1), Some(&Ok(Ok(imap::Response::greeting("a")))));
        assert_eq!(items.get(2), Some(&Ok(Ok(imap::Response::greeting("b")))));
        assert_eq!(items.len(), 3);
    }
}

#[test]
fn imap_idle_done() {
    for (command, answer) in [
        ("IDLE", "DONE"),
        ("AUTHENTICATE PLAIN", "YQ=="),
        ("AUTHENTICATE PLAIN", "*"),
    ] {
        let bytes = format!("a {command}\r\n{answer}\r\nb NOOP\r\n");
        let items = read_with(imap::Commands::new(), bytes.as_bytes(), |decoder, item| {
            if matches!(item, Ok(imap::Input::Command(c)) if c.tag == "a") {
                decoder.expect_line().unwrap();
            }
        });
        assert_eq!(
            items.get(1),
            Some(&Ok(Ok(imap::Input::Line(answer.as_bytes().to_vec()))))
        );
        assert!(matches!(items.get(2), Some(Ok(Ok(imap::Input::Command(c)))) if c.tag == "b"));
        assert_eq!(items.len(), 3);
    }
}

#[test]
fn smtp_mode_changes_refuse_overlong_lines_until_skipped() {
    let mut stream = Stream::new(smtp::Server::new());
    assert_eq!(stream.push(&[b'X'; 600]), 600);
    assert_eq!(stream.next(), Some(Ok(Err(smtp::Error::LineTooLong))));
    assert_eq!(stream.decoder().start_data(), Err(smtp::DecodeError::State));
    assert_eq!(stream.decoder().handoff(), Err(smtp::DecodeError::State));
    assert_eq!(stream.next(), None);
    assert_eq!(stream.decoder().start_data(), Err(smtp::DecodeError::State));
    assert_eq!(stream.decoder().handoff(), Err(smtp::DecodeError::State));
    assert_eq!(stream.push(b"\r"), 1);
    assert_eq!(stream.next(), None);
    assert_eq!(stream.decoder().handoff(), Err(smtp::DecodeError::State));
    assert_eq!(stream.push(b"\nNOOP\r\n"), 7);
    assert!(matches!(stream.next(), Some(Ok(Ok(smtp::Input::Command(c)))) if c.verb == "NOOP"));
    stream.decoder().start_data().unwrap();
    assert_eq!(stream.push(b".\r\nSTARTTLS\r\ntls"), 16);
    assert_eq!(stream.next(), Some(Ok(Ok(smtp::Input::Message(vec![])))));
    assert!(matches!(stream.next(), Some(Ok(Ok(smtp::Input::Command(c)))) if c.verb == "STARTTLS"));
    stream.decoder().handoff().unwrap();
    assert_eq!(stream.next(), None);
    assert_eq!(stream.into_parts().0.unread(), b"tls");
}

#[test]
fn raw_line_modes_require_boundaries() {
    let mut commands = pop3::Commands::new();
    assert_eq!(commands.decode(b"AU", false), Ok(Step::Need));
    assert_eq!(commands.expect_line(), Err(pop3::DecodeError::State));
    assert!(matches!(
        commands.decode(b"AUTH GSSAPI\r\n", false),
        Ok(Step::Item(_, _))
    ));
    commands.expect_line().unwrap();
    assert_eq!(commands.expect_line(), Err(pop3::DecodeError::State));
    assert_eq!(
        commands.decode(b"*\r\n", false),
        Ok(Step::Item(Ok(pop3::Input::Line(b"*".to_vec())), 3))
    );

    let mut commands = Stream::new(pop3::Commands::new());
    assert_eq!(commands.push(&[b'X'; 300]), 300);
    assert_eq!(
        commands.next(),
        Some(Ok(Err(pop3::CommandError::LineTooLong)))
    );
    assert_eq!(
        commands.decoder().expect_line(),
        Err(pop3::DecodeError::State)
    );
    assert_eq!(commands.next(), None);
    assert_eq!(
        commands.decoder().expect_line(),
        Err(pop3::DecodeError::State)
    );
    assert_eq!(commands.push(b"\r\n"), 2);
    assert_eq!(commands.next(), None);
    commands.decoder().expect_line().unwrap();

    let mut replies = pop3::Replies::new();
    replies.expect(false).unwrap();
    assert_eq!(replies.decode(b"+O", false), Ok(Step::Need));
    assert_eq!(replies.expect_line(), Err(pop3::DecodeError::State));
    assert!(matches!(
        replies.decode(b"+OK ready\r\n", false),
        Ok(Step::Item(_, _))
    ));
    replies.expect(true).unwrap();
    assert_eq!(replies.decode(b"+OK body\r\n", false), Ok(Step::Skip(10)));
    assert_eq!(replies.expect_line(), Err(pop3::DecodeError::State));
    assert!(matches!(
        replies.decode(b".\r\n", false),
        Ok(Step::Item(_, _))
    ));
    replies.expect_line().unwrap();
    assert_eq!(replies.expect_line(), Err(pop3::DecodeError::State));
    assert_eq!(
        replies.decode(b"+ x\r\n", false),
        Ok(Step::Item(Ok(pop3::Output::Line(b"+ x".to_vec())), 5))
    );
    assert_eq!(replies.expected(), 0);

    let mut commands = imap::Commands::new();
    assert_eq!(commands.decode(b"a AU", false), Ok(Step::Need));
    assert_eq!(commands.expect_line(), Err(imap::DecodeError::State));
    assert!(matches!(
        commands.decode(b"a AUTHENTICATE PLAIN\r\n", false),
        Ok(Step::Item(_, _))
    ));
    commands.expect_line().unwrap();
    assert_eq!(commands.expect_line(), Err(imap::DecodeError::State));
    assert_eq!(
        commands.decode(b"*\r\n", false),
        Ok(Step::Item(Ok(imap::Input::Line(b"*".to_vec())), 3))
    );
    for size in [0, 3] {
        let mut commands = imap::Commands::new();
        let bytes = format!("a X {{{size}}}\r\n");
        assert!(matches!(
            commands.decode(bytes.as_bytes(), false),
            Ok(Step::Item(Ok(imap::Input::Continue { .. }), _))
        ));
        assert_eq!(commands.expect_line(), Err(imap::DecodeError::State));
        assert!(commands.refuse_literal());
        commands.expect_line().unwrap();
    }
}

#[test]
fn raw_lines_are_bounded_and_last_for_one_item() {
    let commands = || {
        let mut decoder = pop3::Commands::new();
        decoder.expect_line().unwrap();
        decoder
    };
    let replies = || {
        let mut decoder = pop3::Replies::new();
        decoder.expect(false).unwrap();
        decoder.expect_line().unwrap();
        decoder
    };
    for size in [0, pop3::MAX_AUTH_LINE, pop3::MAX_AUTH_LINE + 1] {
        let answer = vec![b'Y'; size];
        let wire = [answer.clone(), b"\r\nQUIT\r\n".to_vec()].concat();
        contract::check_decode_with_held_limit(commands, &wire, 0);
        contract::check_decode_with_alloc_limit(
            commands,
            &wire,
            commands().capacity().saturating_mul(2),
        );
        let items = read(commands(), &wire);
        let first = if size <= pop3::MAX_AUTH_LINE {
            Ok(pop3::Input::Line(answer.clone()))
        } else {
            Err(pop3::CommandError::LineTooLong)
        };
        assert_eq!(items.first(), Some(&Ok(first)));
        assert!(
            matches!(items.get(1), Some(Ok(Ok(pop3::Input::Command(c)))) if c.keyword == "QUIT")
        );
        assert_eq!(items.len(), 2);
        // A server's raw line is a challenge: `+` alone, or `+ ` and data.
        let challenge = match size {
            0 => b"+".to_vec(),
            _ => [b"+ ".as_slice(), &answer[2..]].concat(),
        };
        let wire = [challenge.clone(), b"\r\n+OK done\r\n".to_vec()].concat();
        contract::check_decode_with_held_limit(replies, &wire, pop3::MAX_REPLY_HELD);
        contract::check_decode_with_alloc_limit(
            replies,
            &wire,
            replies().capacity().saturating_mul(2),
        );
        let items = read(replies(), &wire);
        if size <= pop3::MAX_AUTH_LINE {
            assert_eq!(
                items,
                vec![
                    Ok(Ok(pop3::Output::Line(challenge.clone()))),
                    Ok(Ok(pop3::Output::Reply(pop3::Reply::ok("done")))),
                ]
            );
        } else {
            assert_eq!(
                items,
                vec![Err(Fail::Protocol(pop3::DecodeError::Line(
                    codec::LineError::TooLong {
                        max: pop3::MAX_AUTH_LINE
                    }
                )))]
            );
        }
    }
    // The command and status limits apply again immediately after a raw line.
    let wire = [b"*\r\n".to_vec(), vec![b'X'; 300], b"\r\nNOOP\r\n".to_vec()].concat();
    assert_eq!(
        read(commands(), &wire).get(1),
        Some(&Ok(Err(pop3::CommandError::LineTooLong)))
    );
    let wire = [b"+ x\r\n".to_vec(), vec![b'X'; 600], b"\r\n".to_vec()].concat();
    assert_eq!(
        read(replies(), &wire).get(1),
        Some(&Err(Fail::Protocol(pop3::DecodeError::Line(
            codec::LineError::TooLong {
                max: pop3::MAX_REPLY_LINE - 2
            }
        ))))
    );
    // A raw line that is not a challenge is a status line, held to the
    // status limit even though a challenge may be longer.
    for line in [vec![b'X'; 600], [b"+OK ".as_slice(), &[b'x'; 600]].concat()] {
        let wire = [line, b"\r\n+OK done\r\n".to_vec()].concat();
        contract::check_decode_with_held_limit(replies, &wire, pop3::MAX_REPLY_HELD);
        contract::check_decode_with_alloc_limit(
            replies,
            &wire,
            replies().capacity().saturating_mul(2),
        );
        assert_eq!(
            read(replies(), &wire),
            vec![Err(Fail::Protocol(pop3::DecodeError::Line(
                codec::LineError::TooLong {
                    max: pop3::MAX_REPLY_LINE - 2
                }
            )))]
        );
    }

    let commands = || {
        let mut decoder = imap::Commands::new();
        decoder.expect_line().unwrap();
        decoder
    };
    for answer in [b"raw {3+}".to_vec(), vec![b'Y'; imap::MAX_LINE - 2], vec![]] {
        let wire = [answer.clone(), b"\r\nb NOOP\r\n".to_vec()].concat();
        contract::check_decode_with_held_limit(commands, &wire, imap::MAX_HELD);
        contract::check_decode_with_alloc_limit(
            commands,
            &wire,
            commands().capacity().saturating_mul(2),
        );
        let items = read(commands(), &wire);
        assert_eq!(
            items.first(),
            Some(&Ok(Ok(imap::Input::Line(answer.clone()))))
        );
        assert!(matches!(items.get(1), Some(Ok(Ok(imap::Input::Command(c)))) if c.tag == "b"));
        assert_eq!(items.len(), 2);
    }
    let wire = [vec![b'Y'; imap::MAX_LINE - 1], b"\r\nb NOOP\r\n".to_vec()].concat();
    contract::check_decode_with_held_limit(commands, &wire, imap::MAX_HELD);
    contract::check_decode_with_alloc_limit(
        commands,
        &wire,
        commands().capacity().saturating_mul(2),
    );
    assert_eq!(
        read(commands(), &wire),
        vec![Err(Fail::Protocol(imap::DecodeError::Line(
            codec::LineError::TooLong {
                max: imap::MAX_LINE - 2
            }
        )))]
    );
}

#[test]
fn reply_parse_reports_invalid_before_trailing() {
    assert_eq!(
        <smtp::Reply as Wire>::parse(b"abc\r\n250 x\r\n"),
        Err(smtp::ParseError::Invalid(smtp::Error::ReplyCode))
    );
    assert_eq!(
        <pop3::Reply as Wire>::parse(b"abc\r\n+OK x\r\n"),
        Err(pop3::ParseError::Reply(pop3::ReplyItemError::Reply(
            pop3::ReplyError::BadStatus
        )))
    );
    let mut replies = pop3::Replies::new();
    replies.expect(false).unwrap();
    replies.expect(false).unwrap();
    assert_eq!(
        read(replies, b"abc\r\n+OK x\r\n"),
        vec![
            Ok(Err(pop3::ReplyItemError::Reply(
                pop3::ReplyError::BadStatus
            ))),
            Ok(Ok(pop3::Output::Reply(pop3::Reply::ok("x")))),
        ]
    );
}

#[test]
fn pop3_auth_bare_lf_rejects_one_item_and_keeps_expectation() {
    let make = || {
        let mut replies = pop3::Replies::new();
        replies.expect(false).unwrap();
        replies.expect_line().unwrap();
        replies
    };
    let bytes = b"+ abc\n+OK done\r\n";
    let rejected = Err(pop3::ReplyItemError::Reply(pop3::ReplyError::BadStatus));
    let reply = Ok(pop3::Output::Reply(pop3::Reply::ok("done")));
    let mut stream = Stream::new(make());
    assert_eq!(stream.push(bytes), bytes.len());
    assert_eq!(stream.next(), Some(Ok(rejected.clone())));
    assert_eq!(stream.decoder().expected(), 1);
    assert_eq!(stream.next(), Some(Ok(reply.clone())));
    assert_eq!(stream.decoder().expected(), 0);
    assert!(stream.failed().is_none());
    contract::check_decode_with_held_limit(make, bytes, pop3::MAX_REPLY_HELD);
    contract::check_decode_with_alloc_limit(make, bytes, make().capacity().saturating_mul(2));
    assert_eq!(
        read(make(), bytes),
        vec![Ok(rejected.clone()), Ok(reply.clone())]
    );
}

#[test]
fn imap_parse_reports_invalid_before_trailing() {
    assert_eq!(
        <imap::Command as Wire>::parse(b"a APPEND x {99999999}\r\nfoo"),
        Err(imap::ParseError::Invalid(imap::Error::LiteralTooLarge {
            tag: Some("a".into()),
            size: 99999999,
            waiting: true,
        }))
    );
    assert!(matches!(
        <imap::Command as Wire>::parse(b"a\r\nb NOOP\r\n"),
        Err(imap::ParseError::Invalid(imap::Error::Syntax { .. }))
    ));
    for bytes in [
        b"bad\r\n* OK next\r\n".as_slice(),
        b"* 1 FETCH (BODY[] {1+}\r\nx)\r\n",
    ] {
        assert!(matches!(
            <imap::Response as Wire>::parse(bytes),
            Err(imap::ParseError::Invalid(imap::Error::Syntax { .. }))
        ));
    }
    assert_eq!(
        <imap::Command as Wire>::parse(b"a NOOP\r\nb NOOP\r\n"),
        Err(imap::ParseError::Trailing)
    );
    assert_eq!(
        <imap::Response as Wire>::parse(b"* OK ready\r\n* OK next\r\n"),
        Err(imap::ParseError::Trailing)
    );
}

#[test]
fn smtp_reply_code_mismatch_is_invalid_in_exact_parse() {
    for bytes in [
        b"250-a\r\n251 b\r\n".as_slice(),
        b"250-a\r\n251 b\r\n250 next\r\n",
    ] {
        assert_eq!(
            <smtp::Reply as Wire>::parse(bytes),
            Err(smtp::ParseError::Invalid(smtp::Error::ReplyMismatch))
        );
        assert_eq!(
            read(smtp::Replies::new(), bytes),
            vec![Err(Fail::Protocol(smtp::DecodeError::Reply(
                smtp::Error::ReplyMismatch
            )))]
        );
    }
}

#[test]
fn command_eof_skips_overlong_lines_and_rejects_short_partials() {
    assert_eq!(
        read(smtp::Server::new(), &vec![b'X'; smtp::MAX_LINE + 1]),
        vec![Ok(Err(smtp::Error::LineTooLong))]
    );
    assert_eq!(
        read(
            pop3::Commands::new(),
            &vec![b'X'; pop3::MAX_COMMAND_LINE + 1]
        ),
        vec![Ok(Err(pop3::CommandError::LineTooLong))]
    );
    assert_eq!(
        read(smtp::Server::new(), b"NOOP\r"),
        vec![Err(Fail::Protocol(smtp::DecodeError::Line(
            codec::LineError::Unterminated
        )))]
    );
    assert_eq!(
        read(pop3::Commands::new(), b"NOOP\r"),
        vec![Err(Fail::Protocol(pop3::DecodeError::Line(
            codec::LineError::Unterminated
        )))]
    );
}

#[test]
fn smtp_data_line_overflow_has_one_fatal_shape() {
    for line in [
        vec![b'x'; 999],
        vec![b'x'; 1000],
        [b".".to_vec(), vec![b'x'; 999]].concat(),
    ] {
        let wire = [b"DATA\r\n".to_vec(), line, b"\r\n.\r\n".to_vec()].concat();
        contract::check_decode_with_held_limit(AcceptData::default, &wire, smtp::MAX_DATA);
        contract::check_decode_with_alloc_limit(
            AcceptData::default,
            &wire,
            AcceptData::default().capacity().saturating_mul(2),
        );
        assert_eq!(
            read(AcceptData::default(), &wire).last(),
            Some(&Err(Fail::Protocol(smtp::DecodeError::Limit(
                smtp::Error::LineTooLong
            ))))
        );
    }
}

type Pop3ReplyItems =
    Vec<Result<Result<pop3::Output, pop3::ReplyItemError>, Fail<pop3::DecodeError>>>;

/// Reads `bytes` as a client that reads the greeting, then sends `AUTH`
/// with one raw line selected and `LIST` behind it. Gives the items and the
/// number of expectations queued after each.
fn pop3_auth_then_list(bytes: &[u8]) -> (Pop3ReplyItems, Vec<usize>) {
    let mut replies = pop3::Replies::new();
    replies.expect(false).unwrap();
    let mut greeted = false;
    let mut seen = Vec::new();
    let items = read_with(replies, bytes, |decoder, _| {
        if !greeted {
            greeted = true;
            decoder.expect(false).unwrap();
            decoder.expect_line().unwrap();
            decoder.expect(true).unwrap();
        }
        seen.push(decoder.expected());
    });
    (items, seen)
}

#[test]
fn pop3_auth_rejected_at_once_keeps_the_reply_queue() {
    // RFC 5034, section 4: the server may answer AUTH with -ERR and no
    // challenge. The raw line selected for a challenge reads it as the
    // final reply, and LIST keeps its own expectation.
    let bytes = b"+OK ready\r\n-ERR unsupported\r\n+OK 1 messages\r\n1 120\r\n.\r\n";
    let list = pop3::Reply::ok("1 messages").with_body(b"1 120\r\n".to_vec());
    let (items, seen) = pop3_auth_then_list(bytes);
    assert_eq!(
        items,
        vec![
            Ok(Ok(pop3::Output::Reply(pop3::Reply::ok("ready")))),
            Ok(Ok(pop3::Output::Reply(pop3::Reply::err("unsupported")))),
            Ok(Ok(pop3::Output::Reply(list.clone()))),
        ]
    );
    assert_eq!(seen, [2, 1, 0]);
}

#[test]
fn pop3_auth_after_a_challenge_keeps_the_reply_queue() {
    let challenge = b"+ PDE4OTYuNjk3MTcwOTUyQHBvc3RvZmZpY2U+";
    let bytes = [
        b"+OK ready\r\n".as_slice(),
        challenge,
        b"\r\n+OK maildrop locked\r\n+OK 1 messages\r\n1 120\r\n.\r\n",
    ]
    .concat();
    let list = pop3::Reply::ok("1 messages").with_body(b"1 120\r\n".to_vec());
    let (items, seen) = pop3_auth_then_list(&bytes);
    assert_eq!(
        items,
        vec![
            Ok(Ok(pop3::Output::Reply(pop3::Reply::ok("ready")))),
            Ok(Ok(pop3::Output::Line(challenge.to_vec()))),
            Ok(Ok(pop3::Output::Reply(pop3::Reply::ok("maildrop locked")))),
            Ok(Ok(pop3::Output::Reply(list.clone()))),
        ]
    );
    assert_eq!(seen, [2, 2, 1, 0]);
}
