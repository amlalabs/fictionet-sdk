//! Kerberos V5 messages and TCP records, as a world playing a KDC reads
//! them.
#![no_main]

use fictionet::stdlib::asn1::Rules;
use fictionet::stdlib::kerberos::{Decoder, EncryptedData, Error, KdcReqBody, KrbError, Message, Ticket, frame};
use libfuzzer_sys::fuzz_target;

/// A message read from `b` writes back, and reads back the same.
fn round_trip(b: &[u8]) {
    for rules in [Rules::Der, Rules::Ber] {
        if let Ok(m) = Message::parse_with(b, rules) {
            // Written again, a message near the size limit may grow past it.
            match m.to_der() {
                Ok(der) => assert_eq!(Message::parse(&der), Ok(m)),
                Err(e) => assert_eq!(e, Error::TooLong),
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time.
    let mut whole = Decoder::new();
    whole.feed(data);
    let mut records = Vec::new();
    while let Some(Ok(r)) = whole.next_message() {
        records.push(r);
    }
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        while let Some(Ok(r)) = bytewise.next_message() {
            again.push(r);
        }
    }
    assert_eq!(records, again);
    for r in &records {
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
