//! Kerberos V5 messages and TCP records, as a world playing a KDC reads
//! them.
#![no_main]

use fictionet::stdlib::codec::{Frames, Stream, Wire, finish, pump};
use fictionet::stdlib::protocols::asn1::Rules;
use fictionet::stdlib::protocols::kerberos::{
    EncryptedData, Error, Frame, KdcReqBody, MAX_MESSAGE, Message, MethodData, Ticket,
};
use fictionet::stdlib::test_support::{assert_write, chunks, decode_all, decode_chunks};
use libfuzzer_sys::fuzz_target;

/// A message read from `b` writes back, and reads back the same.
fn round_trip(b: &[u8]) {
    for rules in [Rules::Der, Rules::Ber] {
        if let Ok(m) = Message::parse_with(b, rules) {
            let _ = assert_write(&m);
            // Written again, a message near the size limit may grow past it.
            match m.to_bytes() {
                Ok(der) => assert_eq!(Message::parse(&der), Ok(m.clone())),
                Err(e) => assert_eq!(e, Error::TooLong),
            }
            // A request's body comes back as sent, and reads as the body.
            match (&m, Message::kdc_req_body(b, rules)) {
                (Message::AsReq(r) | Message::TgsReq(r), Ok(body)) => {
                    assert!(b.windows(body.len()).any(|w| w == body));
                    if rules == Rules::Der {
                        match KdcReqBody::parse(body) {
                            Ok(parsed) => assert_eq!(parsed, r.body),
                            Err(e) => assert_eq!(e, Error::TooLong),
                        }
                    }
                }
                (Message::AsReq(_) | Message::TgsReq(_), Err(e)) => panic!("no body: {e:?}"),
                (_, got) => assert!(got.is_err()),
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    fictionet::stdlib::protocols::asn1::harness::check(data);
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Frames::<Frame>::new()),
            chunks(data, &[1, 7, 64]),
            |_| {}
        ),
        decode_all(Frames::<Frame>::new, data),
    );
    if let Ok(value) = <Message as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Frame as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    let _ = assert_write(&Frame(data.get(..MAX_MESSAGE + 1).unwrap_or(data).to_vec()));

    let mut stream = Stream::new(Frames::<Frame>::new());
    let _ = pump(&mut stream, data, |record| round_trip(&record));
    let _ = finish(&mut stream, |record| round_trip(&record));
    if let Ok(value) = <Ticket as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <EncryptedData as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <KdcReqBody as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <MethodData as Wire>::parse(data) {
        let _ = assert_write(&value);
    }

    // Any bytes as a UDP datagram.
    round_trip(data);

    let frame = Frame(data.to_vec());
    if let Ok(bytes) = frame.to_bytes() {
        assert_eq!(
            decode_chunks(
                &mut Stream::new(Frames::<Frame>::new()),
                chunks(&bytes, &[1, 7, 64]),
                |_| {}
            ),
            decode_all(Frames::<Frame>::new, &bytes),
        );
        assert_eq!(Frame::parse(&bytes), Ok(frame));
    }
});
