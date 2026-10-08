use fictionet::stdlib::codec::{Lcg, Stream, StreamEvent, Wire, finish};
use fictionet::stdlib::sse::{Event, Events, Limits, Line, RawLines};
use fictionet::stdlib::test_support::contract::{
    check_decode, check_decode_with_held_limit, check_wire, check_wire_value, check_written,
};
use fictionet::stdlib::test_support::{chunks, decode_all, mutate};

#[test]
fn decoder_contracts_and_chunking() {
    let limits = Limits {
        line: 32,
        event: 96,
    };
    let samples: &[&[u8]] = &[
        b"\xef\xbb\xbf: ping\r\nevent:endpoint\ndata:/messages\r\rdata:x\n\nid:1\n\ndata:\xff\n\n",
        b"data\n\ndata\ndata\n\ndata:\n",
        b"retry:184467440737095516160000\nid:a\0b\nunknown:x\rdata:a\r\n\r\ndata:pending\n",
        b"\n\xef\xbb\xbfunknown:x\n\ndata:y\n\n",
        b"event:long\ndata:incomplete\rid:uncommitted",
        b"\xef\xbb",
        b"data:\xf0\x90\x80\n\n",
        b"0123456789012345678901234567890123456789\n",
    ];
    for bytes in samples {
        check_decode(|| RawLines::with_limit(limits.line), bytes);
        check_decode(|| Events::with_limits(limits), bytes);
        check_decode_with_held_limit(|| RawLines::with_limit(limits.line), bytes, 0);
        check_decode_with_held_limit(
            || Events::with_limits(limits),
            bytes,
            limits.event + 2 * limits.line,
        );
    }
    // Zero and tiny limits still recognize a split BOM and make progress.
    for line in 0..8 {
        for event in [0, 1, 12, 32] {
            check_decode(
                || RawLines::with_limit(line),
                b"\xef\xbb\xbfdata\r\n\r\ndata:xxx\n\n",
            );
            check_decode(
                || Events::with_limits(Limits { line, event }),
                b"\xef\xbb\xbfdata\r\n\r\ndata:xxx\n\n",
            );
        }
    }
}

#[test]
fn wire_contracts_and_decoded_round_trips() {
    let values = [
        Event::new(""),
        Event::new("line one\nline two\n"),
        Event {
            event: "endpoint".into(),
            data: "/messages".into(),
            id: "session-1".into(),
        },
        Event {
            event: " type".into(),
            data: " \n\0\u{feff}".into(),
            id: " id".into(),
        },
    ];
    for value in values {
        let bytes = check_written(&value);
        assert_eq!(check_decode(Events::default, &bytes), (vec![value], None));
        for line in decode_all(RawLines::default, &bytes).0 {
            let bytes = check_written(&line);
            assert_eq!(check_decode(RawLines::default, &bytes), (vec![line], None));
        }
    }
    for bytes in [
        &b": comment\r\n"[..],
        b"retry:00042\n",
        b"id:bad\0\n",
        b"unknown: x\r",
    ] {
        check_wire::<Line>(bytes);
        let line = Line::parse(bytes).unwrap();
        let bytes = line.to_bytes().unwrap();
        assert_eq!(decode_all(RawLines::default, &bytes), (vec![line], None));
    }
    let input = b"id:old\n\ndata:first\n\ndata:second\n\nid:\ndata:third\n\n";
    let original = decode_all(Events::default, input).0;
    let mut written = Vec::new();
    for event in &original {
        event.write(&mut written).unwrap();
    }
    assert_eq!(decode_all(Events::default, &written), (original, None));
}

#[test]
fn raw_proxy_retains_comments_and_rewrites_data() {
    // A proxy forwards raw lines and skipped bytes, and rewrites data
    // lines with their original ending. A CR that ends a chunk ends its
    // line at once, and the LF after it comes back as skipped bytes, so a
    // rewrite that changed the ending would add a blank line.
    let input = b": ping\r\nevent:message\r\ndata:old\r\nX:no colon normalization\r\n\r\n";
    for sizes in [&[1][..], &[input.len()]] {
        let mut stream = Stream::new(RawLines::default());
        let mut out = Vec::new();
        for chunk in chunks(input, sizes) {
            assert_eq!(stream.push(chunk), chunk.len());
            loop {
                let mut skipped = Vec::new();
                let result = stream.with_next_observed(
                    |line, raw, _| (line, raw.to_vec()),
                    |event| {
                        if let StreamEvent::Skipped { bytes, .. } = event {
                            skipped.extend_from_slice(bytes);
                        }
                    },
                );
                out.extend_from_slice(&skipped);
                let Some(result) = result else { break };
                let (line, raw) = result.unwrap();
                if matches!(line, Line::Data(_)) {
                    let content = raw.trim_ascii_end();
                    let mut new = Vec::new();
                    Line::Data("new".into()).write(&mut new).unwrap();
                    out.extend_from_slice(new.trim_ascii_end());
                    out.extend_from_slice(&raw[content.len()..]);
                } else {
                    out.extend_from_slice(&raw);
                }
            }
        }
        finish(&mut stream, |_| panic!("all lines ended")).unwrap();
        assert_eq!(
            out, b": ping\r\nevent:message\r\ndata:new\r\nX:no colon normalization\r\n\r\n",
            "{sizes:?}"
        );
        assert_eq!(
            decode_all(Events::default, &out),
            (vec![Event::new("new")], None)
        );
    }
}

#[test]
fn mutations_and_small_limit_contracts() {
    let mut rng = Lcg::new(73);
    for _ in 0..160 {
        let mut data =
            b"\xef\xbb\xbf:ping\r\nid:42\nevent:message\rdata:test\n\nretry:01\r\ndata\n\n"
                .to_vec();
        for _ in 0..8 {
            mutate(&mut rng, &mut data);
        }
        check_decode(|| RawLines::with_limit(24), &data);
        check_decode(
            || {
                Events::with_limits(Limits {
                    line: 24,
                    event: 64,
                })
            },
            &data,
        );
        check_wire::<Event>(&data);
        check_wire::<Line>(&data);
        for value in decode_all(Events::default, &data).0 {
            let bytes = value.to_bytes().unwrap();
            assert_eq!(decode_all(Events::default, &bytes), (vec![value], None));
        }
        for value in decode_all(RawLines::default, &data).0 {
            check_wire_value(&value);
            // A later BOM in an unknown name has no context-free encoding.
            if let Ok(bytes) = value.to_bytes() {
                assert_eq!(decode_all(RawLines::default, &bytes), (vec![value], None));
            }
        }
    }
}
