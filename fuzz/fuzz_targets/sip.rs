//! SIP messages over UDP and TCP, and the header values in them, as a
//! world playing a phone or a proxy reads them, and as it writes them.
#![no_main]

use fictionet::stdlib::codec::{Wire, contract};
use fictionet::stdlib::sip::Frames;
use fictionet::stdlib::sip::{
    CSeq, Contacts, Decoder, Error, MAX_HEAD, MAX_MESSAGE, Message, NameAddr, Param, Scheme, Uri, Via, same_name,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode(Frames::new, data);
    contract::check_decode_with_held_limit(Frames::new, data, 0);
    contract::check_wire::<Message>(data);
    let mut message = Message::response(200, "OK");
    message.body = data.get(..fictionet::stdlib::sip::MAX_BODY + 1).unwrap_or(data).to_vec();
    message.push_header("l", &message.body.len().to_string());
    contract::check_wire_value(&message);
    if let Ok(bytes) = Wire::to_bytes(&message) {
        contract::check_wire::<Message>(&bytes);
        contract::check_decode(Frames::new, &bytes);
    }

    // The stream, split two ways: all at once, and a byte at a time.
    let mut whole = Decoder::new();
    let first = feed_all(&mut whole, data);
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    for b in data {
        assert_eq!(bytewise.feed(std::slice::from_ref(b)), 1);
        again.extend(drain(&mut bytewise));
        if again.last().is_some_and(Result::is_err) {
            break;
        }
    }
    assert_eq!(first, again);
    // Fed over and over without being drained, a decoder stays bounded.
    let mut full = Decoder::new();
    for _ in 0..4 {
        let _ = full.feed(data);
        assert!(full.buffered() <= MAX_MESSAGE);
    }

    for m in first.iter().flatten() {
        round_trip(m);
    }
    // The bytes as one UDP datagram.
    if let Ok(m) = Message::parse(data) {
        round_trip(&m);
    }
    // The bytes as one header value.
    if let Ok(s) = std::str::from_utf8(data) {
        values_round_trip(s);
    }
    // The bytes as the parts a world gives the writers.
    writers(data);
});

/// Feeds every byte, taking messages out as a caller does, up to and
/// including the first error.
fn feed_all(d: &mut Decoder, mut bytes: &[u8]) -> Vec<Result<Message, Error>> {
    let mut out = Vec::new();
    loop {
        let n = d.feed(bytes);
        bytes = &bytes[n..];
        assert!(d.buffered() <= MAX_MESSAGE);
        let got = drain(d);
        let stop = got.last().is_some_and(Result::is_err);
        let progress = n > 0 || !got.is_empty();
        out.extend(got);
        if stop || bytes.is_empty() {
            return out;
        }
        assert!(progress, "a full decoder gave nothing");
    }
}

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
/// reads back the same. So do the header values in it, and a reply to it.
fn round_trip(m: &Message) {
    contract::check_wire_value(m);
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
    assert_eq!(back.vias(), m.vias());
    assert_eq!(back.contacts(), m.contacts());
    assert_eq!(back.call_id(), m.call_id());
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
        cseq_round_trip(&c);
    }
    if let Ok(c) = m.contacts() {
        match c.to_value() {
            Ok(v) => assert_eq!(Contacts::parse(&v).unwrap(), c),
            Err(e) => assert_eq!(c, Contacts::List(vec![]), "{e:?}"),
        }
    }
    if let Some(Ok(u)) = m.request_uri().map(Uri::parse) {
        assert_eq!(Uri::parse(&u.to_value().unwrap()).unwrap(), u);
        for p in &u.params {
            assert!(u.param(&p.name).is_some());
        }
    }
    if m.method().is_some() {
        match m.reply(100, "Trying").to_bytes() {
            Ok(b) => assert!(Message::parse(&b).is_ok()),
            Err(e) => assert!(matches!(e, Error::TooLong | Error::TooMany), "{e:?}"),
        }
    }
}

/// A CSeq read writes and reads back, unless its number is one a sender
/// may not use.
fn cseq_round_trip(c: &CSeq) {
    match c.to_value() {
        Ok(v) => assert_eq!(&CSeq::parse(&v).unwrap(), c),
        Err(e) => assert!(c.seq >= 1 << 31, "{e:?}"),
    }
}

/// A value read writes and reads back the same, unless it is near the
/// size limit.
fn values_round_trip(s: &str) {
    let fine = |e: Error| assert_eq!(e, Error::TooLong);
    if let Ok(u) = Uri::parse(s) {
        u.to_value().map_or_else(fine, |v| assert_eq!(Uri::parse(&v).unwrap(), u));
    }
    if let Ok(a) = NameAddr::parse(s) {
        a.to_value().map_or_else(fine, |v| assert_eq!(NameAddr::parse(&v).unwrap(), a));
    }
    if let Ok(v) = Via::parse(s) {
        v.to_value().map_or_else(fine, |t| assert_eq!(Via::parse(&t).unwrap(), v));
    }
    if let Ok(c) = CSeq::parse(s) {
        cseq_round_trip(&c);
    }
    if let Ok(c) = Contacts::parse(s) {
        c.to_value().map_or_else(fine, |v| assert_eq!(Contacts::parse(&v).unwrap(), c));
    }
}

/// Builds values and a message from the bytes, split at 0xff into parts,
/// and checks that whatever the writers write reads back the same.
fn writers(data: &[u8]) {
    let parts: Vec<String> = data.split(|&b| b == 0xff).map(|p| String::from_utf8_lossy(p).into_owned()).collect();
    let part = |i: usize| parts.get(i).cloned().unwrap_or_default();
    let opt = |i: usize| parts.get(i).filter(|p| !p.is_empty()).cloned();
    let params = |from: usize| -> Vec<Param> {
        (from..parts.len().min(from + 6)).step_by(2).map(|i| Param { name: part(i), value: opt(i + 1) }).collect()
    };

    let mut u = Uri::new(if data.first().is_some_and(|b| b & 1 == 1) { Scheme::Sips } else { Scheme::Sip }, &part(0));
    u.user = opt(1);
    u.password = opt(2);
    u.params = params(3);
    if let Ok(text) = u.to_value() {
        assert!(text.len() <= MAX_HEAD);
        assert_eq!(Uri::parse(&text).unwrap(), u, "{text}");
    }

    let a = NameAddr { display: opt(0), uri: part(1), params: params(2) };
    if let Ok(text) = a.to_value() {
        assert_eq!(NameAddr::parse(&text).unwrap(), a, "{text}");
        let list = Contacts::List(vec![a.clone()]);
        if let Ok(text) = list.to_value() {
            assert_eq!(Contacts::parse(&text).unwrap(), list, "{text}");
        }
    }

    let v = Via { transport: part(0), host: part(1), port: None, params: params(2) };
    if let Ok(text) = v.to_value() {
        assert_eq!(Via::parse(&text).unwrap(), v, "{text}");
    }

    let seq = data.iter().fold(0u32, |n, &b| n.rotate_left(8) ^ u32::from(b));
    let c = CSeq { seq, method: part(0) };
    if let Ok(text) = c.to_value() {
        assert_eq!(CSeq::parse(&text).unwrap(), c);
    }

    let mut m = if data.first().is_some_and(|b| b & 2 == 2) {
        Message::request(&part(0), &part(1))
    } else {
        Message::response(u16::from(data.first().copied().unwrap_or(0)) * 3, &part(1))
    };
    for i in (2..parts.len().min(12)).step_by(2) {
        m.push_header(&part(i), &part(i + 1));
    }
    m.body = parts.last().map(|p| p.as_bytes().to_vec()).unwrap_or_default();
    contract::check_wire_value(&m);
    if let Ok(bytes) = m.to_bytes() {
        let back = Message::parse(&bytes).unwrap();
        assert_eq!(Message::parse_stream(&bytes).unwrap().unwrap(), (back.clone(), bytes.len()));
        assert_eq!(back.start, m.start);
        assert_eq!(back.body, m.body);
    }
}
