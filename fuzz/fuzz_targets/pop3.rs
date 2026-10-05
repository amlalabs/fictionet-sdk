//! POP3 commands and replies, as a world playing a mail server or client
//! reads them.
#![no_main]

use fictionet::stdlib::pop3::{
    Command, CommandDecoder, Reply, ReplyDecoder, Request, parse_scan_listing,
    parse_unique_id_listing, write_scan_listing, write_unique_id_listing,
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
    }
    assert_eq!(commands, again);

    for c in commands.iter().flatten() {
        // A command read can be written, and reads back the same.
        let mut d = CommandDecoder::new();
        d.feed(&c.to_bytes());
        assert_eq!(d.next_command(), Some(Ok(c.clone())));
        assert_eq!(d.next_command(), None);
        if let Ok(req) = Request::from_command(c) {
            let mut d = CommandDecoder::new();
            d.feed(&req.to_bytes());
            let back = d.next_command().unwrap().unwrap();
            if !matches!(req, Request::Other(_)) {
                assert_eq!(Request::from_command(&back), Ok(req));
            }
        }
    }

    // The stream as replies, up to the first error, split the same two
    // ways, with bodies expected as `multi_line` says.
    let replies = |bytewise: bool| {
        let mut d = ReplyDecoder::new();
        let mut out = Vec::new();
        let chunks: Vec<&[u8]> = if bytewise {
            data.chunks(1).collect()
        } else {
            vec![data]
        };
        for chunk in chunks {
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
    let got = replies(false);
    assert_eq!(got, replies(true));

    for r in got.iter().flatten() {
        let bytes = r.to_bytes();
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
                let w = write_unique_id_listing(m, &u);
                assert_eq!(parse_unique_id_listing(w.as_bytes()), Some((m, u)));
            }
        }
    }

    // Any bytes as one line, or one reply.
    let _ = Command::parse(data);
    let _ = Reply::parse_line(data);
    let _ = Reply::parse(data, true);
    let _ = Reply::parse(data, false);

    // Writers never write what readers refuse.
    let s = String::from_utf8_lossy(data);
    let reply = Reply {
        ok: true,
        code: Some(s.to_string()),
        text: s.to_string(),
        body: Some(data.to_vec()),
    };
    assert!(Reply::parse(&reply.to_bytes(), true).unwrap().is_some());
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
    // NOOP; never as some other command.
    let want: String = s
        .chars()
        .filter(char::is_ascii_graphic)
        .map(|c| c.to_ascii_uppercase())
        .collect();
    assert!(back.keyword == want || back.keyword == "NOOP");
});
