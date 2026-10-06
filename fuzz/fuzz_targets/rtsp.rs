//! RTSP messages, interleaved frames and the header values in them, as a
//! world playing a camera reads them.
#![no_main]

use fictionet::stdlib::codec::{Wire, contract};
use fictionet::stdlib::rtsp::Frames;
use fictionet::stdlib::rtsp::{Decoder, Error, Item, Message, Range, Session, Transport};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode(Frames::new, data);
    contract::check_decode_with_held_limit(Frames::new, data, 0);
    contract::check_wire::<Message>(data);
    contract::check_wire::<Item>(data);
    contract::check_wire::<fictionet::stdlib::rtsp::Interleaved>(data);
    let frame = fictionet::stdlib::rtsp::Interleaved {
        channel: data.first().copied().unwrap_or(0),
        data: data.get(..fictionet::stdlib::rtsp::MAX_INTERLEAVED + 1).unwrap_or(data).to_vec(),
    };
    contract::check_wire_value(&frame);
    let mut message = Message::response(fictionet::stdlib::rtsp::Version::Rtsp20, 200, "OK");
    message.body = data.get(..fictionet::stdlib::rtsp::MAX_BODY + 1).unwrap_or(data).to_vec();
    message.push_header("Content-Length", &message.body.len().to_string());
    contract::check_wire_value(&message);
    if let Ok(bytes) = Wire::to_bytes(&message) {
        contract::check_wire::<Message>(&bytes);
        contract::check_decode(Frames::new, &bytes);
    }
    message.push_header("X", " leading");
    contract::check_wire_value(&message);

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

    // The stateless reader, drained on its own, gives the same items, so
    // neither side can drop a whole item the other reads.
    let mut stateless = Vec::new();
    let mut rest = data;
    loop {
        match Item::parse(rest) {
            Ok(Some((item, used))) => {
                assert!(used > 0 && used <= rest.len());
                stateless.push(Ok(item));
                rest = &rest[used..];
            }
            Ok(None) => break,
            Err(e) => {
                stateless.push(Err(e));
                break;
            }
        }
    }
    assert_eq!(first, stateless);

    for item in first.iter().flatten() {
        round_trip(item);
    }
    // The bytes as one header value.
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(t) = Transport::parse_list(s) {
            assert_eq!(Transport::parse_list(&Transport::list_to_value(&t).unwrap()).unwrap(), t);
        }
        if let Ok(t) = Transport::parse(s) {
            assert_eq!(Transport::parse(&t.to_value().unwrap()).unwrap(), t);
        }
        if let Ok(r) = Range::parse(s) {
            assert_eq!(Range::parse(&r.to_value().unwrap()).unwrap(), r);
        }
        if let Ok(x) = Session::parse(s) {
            assert_eq!(Session::parse(&x.to_value().unwrap()).unwrap(), x);
        }
    }
});

/// The items a decoder has, up to and including the first error.
fn drain(d: &mut Decoder) -> Vec<Result<Item, Error>> {
    let mut out = Vec::new();
    while let Some(r) = d.next_item() {
        let stop = r.is_err();
        out.push(r);
        if stop {
            break;
        }
    }
    out
}

/// An item read can be written, unless a message was near a size limit,
/// and reads back the same. So do the header values in a message.
fn round_trip(item: &Item) {
    contract::check_wire_value(item);
    let bytes = match item.to_bytes() {
        Ok(b) => b,
        Err(e) => {
            assert!(matches!(e, Error::TooLong | Error::TooMany), "{e:?}");
            return;
        }
    };
    let (back, used) = Item::parse(&bytes).unwrap().unwrap();
    assert_eq!(used, bytes.len());
    let (Item::Message(m), Item::Message(back)) = (item, &back) else {
        assert_eq!(&back, item);
        return;
    };
    assert_eq!(back.start, m.start);
    assert_eq!(back.body, m.body);
    let others = |m: &Message| {
        m.headers.iter().filter(|h| !h.name.eq_ignore_ascii_case("Content-Length")).cloned().collect::<Vec<_>>()
    };
    assert_eq!(others(back), others(m));
    assert_eq!(back.cseq(), m.cseq());
    if let Ok(s) = m.session() {
        assert_eq!(Session::parse(&s.to_value().unwrap()).unwrap(), s);
    }
    if let Ok(r) = m.range() {
        assert_eq!(Range::parse(&r.to_value().unwrap()).unwrap(), r);
    }
    if let Ok(t) = m.transports()
        && !t.is_empty()
    {
        assert_eq!(Transport::parse_list(&Transport::list_to_value(&t).unwrap()).unwrap(), t);
    }
}
