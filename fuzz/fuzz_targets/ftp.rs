//! FTP commands and replies, as a world playing an FTP server or client
//! reads them.
#![no_main]

use fictionet::stdlib::ftp::{
    Command, CommandDecoder, Reply, ReplyDecoder, Request, parse_eprt, parse_port, write_eprt, write_port,
};
use libfuzzer_sys::fuzz_target;

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
            assert_eq!(Request::from_command(&back), Ok(req));
        }
    }

    // The stream as replies, up to the first error, split the same two ways.
    let replies = |bytewise: bool| {
        let mut d = ReplyDecoder::new();
        let mut out = Vec::new();
        let chunks: Vec<&[u8]> = if bytewise { data.chunks(1).collect() } else { vec![data] };
        for chunk in chunks {
            d.feed(chunk);
            while let Some(r) = d.next_reply() {
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
        let (back, used) = Reply::parse(&bytes).unwrap().unwrap();
        assert_eq!(&back, r);
        assert_eq!(used, bytes.len());
        if let Ok(f) = r.features() {
            assert_eq!(Reply::feature_list(&f).features(), Ok(f));
        }
        if let Ok(a) = r.passive_address() {
            assert_eq!(Reply::passive(a).passive_address(), Ok(a));
        }
        if let Ok(p) = r.extended_passive_port() {
            assert_eq!(Reply::extended_passive(p).extended_passive_port(), Ok(p));
        }
    }

    // Any bytes as one line, one reply, or an address.
    let _ = Command::parse(data);
    let _ = Reply::parse(data);
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(a) = parse_port(s) {
            assert_eq!(parse_port(&write_port(a)), Ok(a));
        }
        if let Ok(a) = parse_eprt(s) {
            assert_eq!(parse_eprt(&write_eprt(a)), Ok(a));
        }
    }
});
