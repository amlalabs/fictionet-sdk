//! POP3 commands and replies, as a world playing a mail server or client
//! reads them.
#![no_main]

use fictionet::stdlib::pop3::{
    Command, CommandDecoder, MAX_AUTH_LINE, MAX_COMMAND_LINE, Reply, ReplyDecoder, Request,
    parse_scan_listing, parse_unique_id_listing, write_scan_listing, write_unique_id_listing,
};
use libfuzzer_sys::fuzz_target;

/// Whether the `i`th reply in the stream has a body if it is `+OK`.
fn multi_line(i: usize) -> bool {
    i % 3 != 1
}

fuzz_target!(|data: &[u8]| {
    // The stream as commands, split two ways: all at once, and a byte at a
    // time. A bad line spoils only itself, so every result is kept.
    let mut whole = CommandDecoder::new();
    whole.feed(data);
    let commands: Vec<_> = std::iter::from_fn(|| whole.next_command()).collect();
    let mut bytewise = CommandDecoder::new();
    let mut again = Vec::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        again.extend(std::iter::from_fn(|| bytewise.next_command()));
        assert!(bytewise.buffered() < MAX_COMMAND_LINE);
    }
    assert_eq!(commands, again);
    // A long run with no line end is not held past MAX_AUTH_LINE bytes.
    if !data.contains(&b'\n') {
        let mut long = CommandDecoder::new();
        long.feed(data);
        long.feed(data);
        assert!(long.buffered() <= MAX_AUTH_LINE);
    }

    for c in commands.iter().flatten() {
        // A command read can be written, and reads back the same, from
        // either writer.
        let mut d = CommandDecoder::new();
        d.feed(&c.to_bytes());
        assert_eq!(d.next_command(), Some(Ok(c.clone())));
        assert_eq!(d.next_command(), None);
        assert_eq!(c.try_to_bytes(), Ok(c.to_bytes()));
        if let Ok(req) = Request::from_command(c) {
            let bytes = req.try_to_bytes().expect("a request read can be written as it is");
            assert_eq!(bytes, req.to_bytes());
            let mut d = CommandDecoder::new();
            d.feed(&bytes);
            let back = d.next_command().unwrap().unwrap();
            assert_eq!(Request::from_command(&back), Ok(req));
        }
    }

    // The stream as replies, up to the first error, split the same two
    // ways, with bodies expected as `multi_line` says.
    let replies = |size: usize| {
        let mut d = ReplyDecoder::new();
        let mut out = Vec::new();
        for chunk in data.chunks(size) {
            d.feed(chunk);
            while let Some(r) = d.next_reply(multi_line(out.len())) {
                let stop = r.is_err();
                out.push(r);
                if stop {
                    return out;
                }
            }
        }
        out
    };
    let got = replies(data.len().max(1));
    assert_eq!(got, replies(1));

    for r in got.iter().flatten() {
        let bytes = r.to_bytes();
        assert_eq!(r.try_to_bytes().as_ref(), Ok(&bytes));
        let (back, used) = Reply::parse(&bytes, r.body.is_some()).unwrap().unwrap();
        assert_eq!(&back, r);
        assert_eq!(used, bytes.len());
        if let Some(code) = &r.code {
            assert!(r.has_code(code) && r.has_code(&code.to_ascii_lowercase()));
        }
        if let Some((count, octets)) = r.drop_listing() {
            assert_eq!(
                Reply::stat(count, octets).drop_listing(),
                Some((count, octets))
            );
        }
        for line in r.lines() {
            if let Some((m, o)) = parse_scan_listing(line) {
                assert_eq!(
                    parse_scan_listing(write_scan_listing(m, o).as_bytes()),
                    Some((m, o))
                );
            }
            if let Some((m, u)) = parse_unique_id_listing(line) {
                let w = write_unique_id_listing(m, &u).expect("a unique-id read can be written");
                assert_eq!(parse_unique_id_listing(w.as_bytes()), Some((m, u)));
            }
        }
    }

    // Any bytes as one line, or one reply, or one AUTH line.
    let _ = Command::parse(data);
    let _ = Reply::parse_line(data);
    let _ = Reply::parse(data, true);
    let _ = Reply::parse(data, false);
    let mut d = ReplyDecoder::new();
    d.feed(data);
    while let Some(Ok(_)) = d.next_line() {}

    // Writers never write what readers refuse, with each field chosen on
    // its own from the input.
    let half = data.len() / 2;
    let (a, b) = data.split_at(half);
    let (sa, sb) = (String::from_utf8_lossy(a), String::from_utf8_lossy(b));
    let pick = data.first().copied().unwrap_or(0);
    let reply = Reply {
        ok: pick & 1 == 0,
        code: match (pick >> 1) % 3 {
            0 => None,
            1 => Some(sa.to_string()),
            _ => Some(sb.to_string()),
        },
        text: if pick & 8 == 0 { sa.to_string() } else { sb.to_string() },
        body: match (pick >> 4) % 3 {
            0 => None,
            1 => Some(a.to_vec()),
            _ => Some(data.to_vec()),
        },
    };
    let has_body = reply.ok && reply.body.is_some();
    let bytes = reply.to_bytes();
    let (back, used) = Reply::parse(&bytes, has_body).unwrap().unwrap();
    assert_eq!(used, bytes.len());
    assert_eq!(back.to_bytes(), bytes);
    if let Ok(strict) = reply.try_to_bytes() {
        assert_eq!(strict, bytes);
        assert_eq!(
            (back.ok, &back.code, &back.text),
            (reply.ok, &reply.code, &reply.text)
        );
    }

    let s = String::from_utf8_lossy(data);
    let mut d = CommandDecoder::new();
    d.feed(
        &Command {
            keyword: s.to_string(),
            argument: Some(s.to_string()),
        }
        .to_bytes(),
    );
    let Some(Ok(back)) = d.next_command() else {
        panic!("a written command did not read back")
    };
    // The keyword is written as given, less what it may not hold, or as
    // NOOP with no argument; never as some other command.
    let want: String = s
        .chars()
        .filter(char::is_ascii_graphic)
        .map(|c| c.to_ascii_uppercase())
        .collect();
    assert!(back.keyword == want || (back.keyword == "NOOP" && back.argument.is_none()));
    // Typed requests, from any text, write lines the parsers take, and
    // try_to_bytes writes only what reads back the same.
    for req in [
        Request::User(sa.to_string()),
        Request::Pass(sb.to_string()),
        Request::Apop {
            name: sb.to_string(),
            digest: [pick; 16],
        },
    ] {
        let line = req.to_bytes();
        let c = Command::parse(line.strip_suffix(b"\r\n").unwrap()).unwrap();
        assert!(Request::from_command(&c).is_ok());
        if let Some(bytes) = req.try_to_bytes() {
            let c = Command::parse(bytes.strip_suffix(b"\r\n").unwrap()).unwrap();
            assert_eq!(Request::from_command(&c), Ok(req));
        }
    }
    if let Some(w) = write_unique_id_listing(std::num::NonZeroU32::MIN, &sa) {
        assert_eq!(
            parse_unique_id_listing(w.as_bytes()).map(|(_, u)| u),
            Some(sa.to_string())
        );
    }
});
