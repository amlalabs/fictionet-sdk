//! Syslog TCP streams and messages, RFC 5424 and RFC 3164, as a world
//! playing a log collector reads them.
#![no_main]

use fictionet::stdlib::syslog::{
    BsdMessage, Decoder, Entry, Frame, FrameError, Framing, MAX_BUFFERED, MAX_MESSAGE_LEN, Message, Priority,
    SdElement,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The stream, split three ways: all at once, a byte at a time, and in
    // pieces whose sizes the data's own bytes pick.
    let whole = decode(data, |_| usize::MAX);
    assert_eq!(decode(data, |_| 1), whole);
    assert_eq!(decode(data, |at| usize::from(data[at] % 17) + 1), whole);

    let (results, last) = whole;
    for f in results.iter().filter_map(|r| r.as_ref().ok()).chain(&last) {
        assert!(!f.message.is_empty() && f.message.len() <= MAX_MESSAGE_LEN);
        // A frame read can be written, and reads back the same. What is
        // written is whole, even when what was read had been cut.
        let mut d = Decoder::new();
        let bytes = f.to_bytes();
        assert_eq!(d.feed(&bytes), bytes.len());
        let whole = Frame { truncated: false, ..f.clone() };
        assert_eq!(d.next_frame().as_ref(), Some(&Ok(whole)));
        round_trip(&f.message);
    }
    // Any bytes as a message on their own.
    round_trip(data);
    constructed(data);
});

/// Values built from any bytes, not read: what is written reads back, and
/// a frame holds the message as it was.
fn constructed(data: &[u8]) {
    let priority = Priority::from_value(data.first().map_or(13, |&b| b % 192)).unwrap();
    let rest = data.get(1..).unwrap_or(&[]);
    let e = Entry::Bsd(BsdMessage::new(priority, rest));
    assert!(Entry::parse(&e.to_bytes()).is_ok());
    let mut m = Message::new(priority);
    // A long value of backslashes and quotes, near and past the limit.
    let value: String = String::from_utf8_lossy(rest).repeat(1 + MAX_MESSAGE_LEN / (rest.len() + 1) / 2);
    m.structured_data.push(SdElement::new("x@32473").param("p", value));
    let bytes = m.to_bytes();
    assert!(bytes.len() <= MAX_MESSAGE_LEN);
    assert_eq!(Message::parse(&bytes).unwrap().to_bytes(), bytes);
    if !rest.is_empty() {
        for framing in [Framing::OctetCounting, Framing::NonTransparent] {
            let msg = rest[..rest.len().min(MAX_MESSAGE_LEN)].to_vec();
            let mut d = Decoder::new();
            let framed = Frame::new(framing, msg.clone()).to_bytes();
            assert_eq!(d.feed(&framed), framed.len());
            let got = d.next_frame().and_then(Result::ok).or_else(|| d.finish());
            assert_eq!(got.map(|f| f.message), Some(msg));
        }
    }
}

/// Every result a decoder gives for `data`, fed in pieces whose sizes
/// `size` gives from where each starts, up to the first error, and then
/// what `finish` gives.
fn decode(data: &[u8], size: impl Fn(usize) -> usize) -> (Vec<Result<Frame, FrameError>>, Option<Frame>) {
    let mut d = Decoder::new();
    let mut out = Vec::new();
    let mut at = 0;
    'feed: while at < data.len() {
        let end = at + size(at).clamp(1, data.len() - at);
        while at < end {
            // A decoder takes what it has room for; once full, taking
            // frames out always makes room.
            at += d.feed(&data[at..end]);
            assert!(d.buffered() <= MAX_BUFFERED);
            while let Some(r) = d.next_frame() {
                let broken = r.is_err();
                out.push(r);
                if broken {
                    break 'feed;
                }
            }
        }
    }
    let last = d.finish();
    assert_eq!(d.buffered(), 0);
    (out, last)
}

/// A message read can be written, and reads back the same.
fn round_trip(raw: &[u8]) {
    if let Ok(m) = Message::parse(raw) {
        let bytes = m.to_bytes();
        assert_eq!(Message::parse(&bytes).as_ref(), Ok(&m));
        assert_eq!(Message::parse(&bytes).unwrap().to_bytes(), bytes);
    }
    if let Ok(m) = BsdMessage::parse(raw) {
        assert_eq!(BsdMessage::parse(&m.to_bytes()).as_ref(), Ok(&m));
    }
    if let Ok(e) = Entry::parse(raw) {
        assert_eq!(Entry::parse(&e.to_bytes()).as_ref(), Ok(&e));
    }
}
