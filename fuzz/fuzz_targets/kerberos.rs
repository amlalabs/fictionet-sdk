//! Kerberos V5 messages and TCP records, as a world playing a KDC reads
//! them.
#![no_main]

use fictionet::stdlib::asn1::Rules;
use fictionet::stdlib::codec::{Stream, Wire, contract, finish, pump};
use fictionet::stdlib::kerberos::{
    EncryptedData, Error, Frame, Frames, KdcReqBody, MAX_MESSAGE, Message, PaData, Ticket,
};
use libfuzzer_sys::fuzz_target;

/// A message read from `b` writes back, and reads back the same.
fn round_trip(b: &[u8]) {
    for rules in [Rules::Der, Rules::Ber] {
        if let Ok(m) = Message::parse_with(b, rules) {
            contract::check_wire_value(&m);
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
                        assert_eq!(KdcReqBody::parse(body).as_ref(), Ok(&r.body));
                    }
                }
                (Message::AsReq(_) | Message::TgsReq(_), Err(e)) => panic!("no body: {e:?}"),
                (_, got) => assert!(got.is_err()),
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode(Frames::new, data);
    contract::check_wire::<Message>(data);
    contract::check_wire::<Frame>(data);
    contract::check_wire_value(&Frame(data.get(..MAX_MESSAGE + 1).unwrap_or(data).to_vec()));

    let mut stream = Stream::new(Frames::new());
    let _ = pump(&mut stream, data, |record| round_trip(&record));
    let _ = finish(&mut stream, |record| round_trip(&record));
    contract::check_wire::<Ticket>(data);
    contract::check_wire::<EncryptedData>(data);
    contract::check_wire::<KdcReqBody>(data);
    contract::check_wire::<Vec<PaData>>(data);

    // Any bytes as a UDP datagram, and as the parts a message holds.
    round_trip(data);
    // A negative kvno read near the size limit may not fit written again.
    if let Ok(t) = Ticket::parse(data) {
        match t.to_bytes() {
            Ok(der) => assert_eq!(Ticket::parse(&der), Ok(t)),
            Err(e) => assert_eq!(e, Error::TooLong),
        }
    }
    if let Ok(e) = EncryptedData::parse(data) {
        match e.to_bytes() {
            Ok(der) => assert_eq!(EncryptedData::parse(&der), Ok(e)),
            Err(err) => assert_eq!(err, Error::TooLong),
        }
    }
    // Short flags or a signed nonce may write a few bytes longer.
    if let Ok(b) = KdcReqBody::parse(data) {
        match b.to_bytes() {
            Ok(der) => assert_eq!(KdcReqBody::parse(&der), Ok(b)),
            Err(e) => assert_eq!(e, Error::TooLong),
        }
    }
    if let Ok(p) = <Vec<PaData> as Wire>::parse(data) {
        assert_eq!(<Vec<PaData> as Wire>::parse(&p.to_bytes().unwrap()), Ok(p));
    }

    let frame = Frame(data.to_vec());
    if let Ok(bytes) = frame.to_bytes() {
        contract::check_decode(Frames::new, &bytes);
        assert_eq!(Frame::parse(&bytes), Ok(frame));
    }
});
