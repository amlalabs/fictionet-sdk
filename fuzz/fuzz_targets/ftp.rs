//! FTP commands and replies, as a world playing an FTP server or client
//! reads and writes them.
#![no_main]

use fictionet::stdlib::ftp::{
    Command, CommandDecoder, Feature, MAX_BUFFERED, MAX_LINE, Reply, ReplyDecoder, ReplyError, Request, parse_eprt,
    parse_port, write_eprt, write_port,
};
use libfuzzer_sys::fuzz_target;

/// How a stream is fed: in pieces of `size` bytes (0 means all at once),
/// taking items out after each feed, or only when a feed takes less than
/// it was given.
#[derive(Clone, Copy)]
struct Schedule {
    size: usize,
    drain_each: bool,
}

const SCHEDULES: [Schedule; 4] = [
    Schedule { size: 0, drain_each: true },
    Schedule { size: 1, drain_each: true },
    Schedule { size: 7, drain_each: false },
    Schedule { size: MAX_LINE + 3, drain_each: false },
];

fn commands(data: &[u8], s: Schedule) -> Vec<Result<Command, fictionet::stdlib::ftp::CommandError>> {
    let mut d = CommandDecoder::new();
    let mut out = Vec::new();
    let size = if s.size == 0 { data.len().max(1) } else { s.size };
    for mut chunk in data.chunks(size) {
        while !chunk.is_empty() {
            let n = d.feed(chunk);
            chunk = &chunk[n..];
            assert!(d.buffered() <= MAX_BUFFERED);
            if s.drain_each || !chunk.is_empty() {
                let before = out.len();
                out.extend(std::iter::from_fn(|| d.next_command()));
                assert!(n > 0 || out.len() > before, "a full decoder must give a command");
            }
        }
    }
    out.extend(std::iter::from_fn(|| d.next_command()));
    out
}

/// Replies up to and including the first error that stops the stream.
fn replies(data: &[u8], s: Schedule) -> Vec<Result<Reply, ReplyError>> {
    let mut d = ReplyDecoder::new();
    let mut out = Vec::new();
    let size = if s.size == 0 { data.len().max(1) } else { s.size };
    let drain = |d: &mut ReplyDecoder, out: &mut Vec<_>| {
        while let Some(r) = d.next_reply() {
            let stop = matches!(r, Err(e) if e != ReplyError::TooManyLines);
            out.push(r);
            if stop {
                return true;
            }
        }
        false
    };
    for mut chunk in data.chunks(size) {
        while !chunk.is_empty() {
            let n = d.feed(chunk);
            chunk = &chunk[n..];
            assert!(d.buffered() <= MAX_BUFFERED);
            if (s.drain_each || !chunk.is_empty()) && drain(&mut d, &mut out) {
                return out;
            }
        }
    }
    drain(&mut d, &mut out);
    out
}

/// One reply at the start of `bytes`, which must hold exactly one.
fn one_reply(bytes: &[u8]) -> Reply {
    let (reply, used) = Reply::parse(bytes).unwrap().unwrap();
    assert_eq!(used, bytes.len());
    reply
}

fuzz_target!(|data: &[u8]| {
    // The stream as commands, fed on every schedule. A bad line spoils only
    // itself, so every result is kept, and every schedule agrees.
    let got = commands(data, SCHEDULES[0]);
    for s in &SCHEDULES[1..] {
        assert_eq!(commands(data, *s), got);
    }
    for c in got.iter().flatten() {
        // A command read can be written, and reads back the same.
        let bytes = c.to_bytes().unwrap();
        assert!(bytes.len() <= MAX_LINE);
        assert_eq!(commands(&bytes, SCHEDULES[0]), [Ok(c.clone())]);
        if let Ok(req) = Request::from_command(c) {
            let bytes = req.to_bytes().unwrap();
            let back = commands(&bytes, SCHEDULES[0]);
            assert_eq!(back.len(), 1);
            assert_eq!(Request::from_command(back[0].as_ref().unwrap()), Ok(req));
        }
    }

    // Values built from any text: a writer either refuses them or writes
    // a line that reads back as the same value.
    let text = String::from_utf8_lossy(data);
    let (verb, arg) = text.split_once(' ').unwrap_or((&text, ""));
    let built = Command::new(verb, Some(arg));
    if let Ok(bytes) = built.to_bytes() {
        let mut want = built.clone();
        want.verb.make_ascii_uppercase();
        assert_eq!(commands(&bytes, SCHEDULES[0]), [Ok(want)]);
    }
    let arg = arg.to_string();
    for req in [Request::Dele(arg.clone()), Request::Allo(arg.clone()), Request::Rest(arg.clone()), Request::Opts(arg)]
    {
        if let Ok(bytes) = req.to_bytes() {
            let back = commands(&bytes, SCHEDULES[0]);
            assert_eq!(back.len(), 1);
            assert_eq!(Request::from_command(back[0].as_ref().unwrap()), Ok(req));
        }
    }
    let lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    let code = fictionet::stdlib::ftp::ReplyCode::new(100 + u16::from(data.first().copied().unwrap_or(0)) % 500);
    if let Some(code) = code {
        let built = Reply { code, lines: lines.clone() };
        let bytes = built.to_bytes();
        let back = one_reply(&bytes);
        assert_eq!(back.to_bytes(), bytes);
        let features: Vec<Feature> = lines
            .iter()
            .map(|l| match l.split_once(' ') {
                Some((n, p)) => Feature { name: n.to_string(), params: Some(p.to_string()) },
                None => Feature { name: l.clone(), params: None },
            })
            .collect();
        let list = one_reply(&Reply::feature_list(&features).to_bytes());
        assert_eq!(Reply::feature_list(&list.features().unwrap()).features(), list.features());
    }

    // The stream as replies, on every schedule.
    let got = replies(data, SCHEDULES[0]);
    for s in &SCHEDULES[1..] {
        assert_eq!(replies(data, *s), got);
    }
    for r in got.iter().flatten() {
        // Written and read back, a reply is the same but for a space in
        // front of middle lines that start with three digits.
        let bytes = r.to_bytes();
        let back = one_reply(&bytes);
        assert_eq!(back.to_bytes(), bytes);
        assert_eq!(back.code, r.code);
        assert_eq!(back.lines.len(), r.lines.len());
        if let Ok(f) = r.features() {
            let list = one_reply(&Reply::feature_list(&f).to_bytes());
            assert_eq!(list.features(), Ok(f));
        }
        if let Ok(a) = r.passive_address() {
            assert_eq!(one_reply(&Reply::passive(a).to_bytes()).passive_address(), Ok(a));
        }
        if let Ok(p) = r.extended_passive_port() {
            assert_eq!(one_reply(&Reply::extended_passive(p).to_bytes()).extended_passive_port(), Ok(p));
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
