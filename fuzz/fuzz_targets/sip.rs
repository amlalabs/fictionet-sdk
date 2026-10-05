//! SIP messages over UDP and TCP, and the header values in them, as a
//! world playing a phone or a proxy reads them.
#![no_main]

use fictionet::stdlib::sip::{CSeq, Contacts, Decoder, Error, Message, NameAddr, Uri, Via, same_name};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time.
    let mut whole = Decoder::new();
    whole.feed(data);
    let first = drain(&mut whole);
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        again.extend(drain(&mut bytewise));
        if again.last().is_some_and(Result::is_err) {
            break;
        }
    }
    assert_eq!(first, again);

    for m in first.iter().flatten() {
        round_trip(m);
    }
    // The bytes as one UDP datagram.
    if let Ok(m) = Message::parse(data) {
        round_trip(&m);
    }
    // The bytes as one header value.
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(u) = Uri::parse(s) {
            assert_eq!(Uri::parse(&u.to_value().unwrap()).unwrap(), u);
        }
        if let Ok(a) = NameAddr::parse(s) {
            assert_eq!(NameAddr::parse(&a.to_value().unwrap()).unwrap(), a);
        }
        if let Ok(v) = Via::parse(s) {
            assert_eq!(Via::parse(&v.to_value().unwrap()).unwrap(), v);
        }
        if let Ok(c) = CSeq::parse(s) {
            assert_eq!(CSeq::parse(&c.to_value().unwrap()).unwrap(), c);
        }
        if let Ok(c) = Contacts::parse(s)
            && let Ok(v) = c.to_value()
        {
            assert_eq!(Contacts::parse(&v).unwrap(), c);
        }
    }
});

/// The messages a decoder has, up to and including the first error.
fn drain(d: &mut Decoder) -> Vec<Result<Message, Error>> {
    let mut out = Vec::new();
    while let Some(r) = d.next_message() {
        let stop = r.is_err();
        out.push(r);
        if stop {
            break;
        }
    }
    out
}

/// A message read can be written, unless it was near a size limit, and
/// reads back the same. So do the header values in it.
fn round_trip(m: &Message) {
    let bytes = match m.to_bytes() {
        Ok(b) => b,
        Err(e) => {
            assert!(matches!(e, Error::TooLong | Error::TooMany), "{e:?}");
            return;
        }
    };
    let (back, used) = Message::parse_stream(&bytes).unwrap().unwrap();
    assert_eq!(used, bytes.len());
    assert_eq!(Message::parse(&bytes).unwrap(), back);
    assert_eq!(back.start, m.start);
    assert_eq!(back.body, m.body);
    let others =
        |m: &Message| m.headers.iter().filter(|h| !same_name(&h.name, "Content-Length")).cloned().collect::<Vec<_>>();
    assert_eq!(others(&back), others(m));
    if let Ok(vias) = m.vias() {
        for v in vias {
            assert_eq!(Via::parse(&v.to_value().unwrap()).unwrap(), v);
        }
    }
    for read in [Message::from, Message::to] {
        if let Ok(a) = read(m) {
            assert_eq!(NameAddr::parse(&a.to_value().unwrap()).unwrap(), a);
        }
    }
    if let Ok(c) = m.cseq() {
        assert_eq!(CSeq::parse(&c.to_value().unwrap()).unwrap(), c);
    }
    if let Some(Ok(u)) = m.request_uri().map(Uri::parse) {
        assert_eq!(Uri::parse(&u.to_value().unwrap()).unwrap(), u);
    }
}
