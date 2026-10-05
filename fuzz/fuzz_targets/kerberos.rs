//! Kerberos V5 messages and TCP records, as a world playing a KDC reads
//! them.
#![no_main]

use fictionet::stdlib::asn1::Rules;
use fictionet::stdlib::codec::contract;
use fictionet::stdlib::kerberos::{
    Decoder, EncryptedData, Error, Frame, FrameError, Frames, KdcReqBody, KrbError, MAX_MESSAGE, Message, Ticket, frame,
};
use libfuzzer_sys::fuzz_target;

/// A message read from `b` writes back, and reads back the same.
fn round_trip(b: &[u8]) {
    for rules in [Rules::Der, Rules::Ber] {
        if let Ok(m) = Message::parse_with(b, rules) {
            contract::check_wire_value(&m);
            // Written again, a message near the size limit may grow past it.
            match m.to_der() {
                Ok(der) => assert_eq!(Message::parse(&der), Ok(m.clone())),
                Err(e) => assert_eq!(e, Error::TooLong),
            }
            // A request's body comes back as sent, and reads as the body.
            match (&m, Message::kdc_req_body(b, rules)) {
                (Message::AsReq(r) | Message::TgsReq(r), Ok(body)) => {
                    assert!(b.windows(body.len()).any(|w| w == body));
                    if rules == Rules::Der {
                        assert_eq!(KdcReqBody::parse(body).as_ref(), Ok(&r.body));
                    }
                }
                (Message::AsReq(_) | Message::TgsReq(_), Err(e)) => panic!("no body: {e:?}"),
                (_, got) => assert!(got.is_err()),
            }
        }
    }
}

/// Feeds `data` to a decoder in pieces of the sizes `sizes` gives in turn
/// (all at once if it is empty), taking messages out after every
/// `drain_every` feeds. It returns the records up to and including the
/// first error, and checks that once a length is bad, nothing more is held.
fn split(data: &[u8], sizes: &[usize], drain_every: usize) -> Vec<Result<Vec<u8>, FrameError>> {
    let mut d = Decoder::new();
    let mut out = Vec::new();
    let mut at = 0;
    let mut feeds = 0;
    let mut i = 0;
    let take = |d: &mut Decoder, out: &mut Vec<_>| {
        while out.last().is_none_or(|r: &Result<_, _>| r.is_ok()) {
            match d.next_message() {
                Some(r) => out.push(r),
                None => break,
            }
        }
    };
    while at < data.len() {
        let n = sizes.get(i % sizes.len().max(1)).map_or(data.len(), |&s| s.max(1)).min(data.len() - at);
        i += 1;
        d.feed(&data[at..at + n]);
        at += n;
        feeds += 1;
        assert!(d.buffered() <= at);
        if feeds % drain_every.max(1) == 0 {
            take(&mut d, &mut out);
        }
    }
    take(&mut d, &mut out);
    // After a bad length, what is fed later is dropped.
    if out.last().is_some_and(|r| r.is_err()) {
        let held = d.buffered();
        d.feed(data);
        assert_eq!(d.buffered(), held);
        assert_eq!(d.next_message(), out.last().cloned());
    }
    out
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode(Frames::new, data);
    contract::check_wire::<Message>(data);
    contract::check_wire::<Frame>(data);
    contract::check_wire_value(&Frame(data.get(..MAX_MESSAGE + 1).unwrap_or(data).to_vec()));

    // The stream, split several ways: all at once, a byte at a time, and
    // in pieces the input picks, taking messages out now and then. Each
    // gives the same records and the same error.
    let whole = split(data, &[], 1);
    assert_eq!(whole, split(data, &[1], 1));
    let sizes: Vec<usize> = data.iter().take(8).map(|&b| usize::from(b)).collect();
    assert_eq!(whole, split(data, &sizes, 3));
    for r in whole.iter().flatten() {
        round_trip(r);
    }

    // Any bytes as a UDP datagram, and as the parts a message holds.
    round_trip(data);
    // A negative kvno read near the size limit may not fit written again.
    if let Ok(t) = Ticket::parse(data) {
        match t.to_der() {
            Ok(der) => assert_eq!(Ticket::parse(&der), Ok(t)),
            Err(e) => assert_eq!(e, Error::TooLong),
        }
    }
    if let Ok(e) = EncryptedData::parse(data) {
        match e.to_der() {
            Ok(der) => assert_eq!(EncryptedData::parse(&der), Ok(e)),
            Err(err) => assert_eq!(err, Error::TooLong),
        }
    }
    // Short flags or a signed nonce may write a few bytes longer.
    if let Ok(b) = KdcReqBody::parse(data) {
        match b.to_der() {
            Ok(der) => assert_eq!(KdcReqBody::parse(&der), Ok(b)),
            Err(e) => assert_eq!(e, Error::TooLong),
        }
    }
    if let Ok(p) = KrbError::read_method_data(data) {
        assert_eq!(KrbError::read_method_data(&KrbError::method_data(&p).unwrap()), Ok(p));
    }

    // A record framed for TCP comes back out whole.
    if let Ok(f) = frame(data) {
        let mut d = Decoder::new();
        d.feed(&f);
        assert_eq!(d.next_message(), Some(Ok(data.to_vec())));
    }
});
