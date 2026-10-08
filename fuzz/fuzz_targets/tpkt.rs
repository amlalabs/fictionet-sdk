//! TPKT packets, as a world on port 102 or 3389 reads them, and packets a
//! world builds, as it writes them.
#![no_main]

use fictionet::stdlib::codec::Frames;
use arbitrary::{Result, Unstructured};
use fictionet::stdlib::test_support::contract::{check_decode, check_wire, check_wire_value};
use fictionet::stdlib::codec::{Assembled, Wire};
use fictionet::stdlib::test_support::decode_all;
use fictionet::stdlib::cotp::{Connect, Data, Parameter, Tpdu, Variable};
use fictionet::stdlib::cotp::{messages, over_tpkt};
use fictionet::stdlib::tpkt::{
    Error, HEADER_LEN, Header, MAX_PACKET, MAX_PAYLOAD, MIN_PACKET, MIN_PAYLOAD, Packet,
};
use libfuzzer_sys::fuzz_target;

/// Values a world builds: whatever a writer accepts reads back the same.
fn built(data: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data);
    // A header a writer takes reads back the same.
    let header = Header {
        reserved: u.arbitrary()?,
        length: u.arbitrary()?,
    };
    match header.to_bytes() {
        Ok(bytes) => assert_eq!(<Header as Wire>::parse(&bytes), Ok(header)),
        Err(e) => {
            assert!(usize::from(header.length) < MIN_PACKET);
            assert_eq!(e, Error::PayloadTooShort(header.payload_len()));
        }
    }
    let n = u.int_in_range(0..=300usize)?;
    let packet = Packet {
        reserved: u.arbitrary()?,
        payload: u.bytes(n)?.to_vec(),
    };
    check_wire_value(&packet);
    match packet.to_bytes() {
        Ok(bytes) => assert_eq!(<Packet as Wire>::parse(&bytes), Ok(packet)),
        Err(e) => assert_eq!(e, Error::PayloadTooShort(n)),
    }
    // A data TPDU a world builds, up to and past what one packet holds: the
    // checked writer takes it exactly when it fits, and then it reads back
    // the same.
    let n = u.int_in_range(MAX_PAYLOAD - 300..=MAX_PAYLOAD + 10)?;
    let n = if u.arbitrary()? { n } else { n % 300 };
    let number: u8 = u.arbitrary()?;
    let data = Tpdu::Data(Data {
        eot: u.arbitrary()?,
        number,
        data: vec![0x41; n],
    });
    check_wire_value(&data);
    let fits = n <= MAX_PAYLOAD - 3 && number < 0x80;
    match over_tpkt::from_tpdu(&data) {
        Ok(p) => {
            assert!(fits);
            assert_eq!(over_tpkt::tpdu(&p), Ok(data));
        }
        Err(e) => {
            assert!(!fits);
            assert_eq!(
                e,
                fictionet::stdlib::cotp::Error::Unwritable
            );
        }
    }
    // A connection request a world builds, with any fields, parameters,
    // raw header bytes and data. Whatever the checked writer takes reads
    // back the same, with raw bytes read as the reader reads them.
    let mut connect = Connect {
        credit: u.arbitrary()?,
        dst_ref: u.arbitrary()?,
        src_ref: u.arbitrary()?,
        class: u.arbitrary()?,
        options: u.arbitrary()?,
        variable: Variable::default(),
        data: vec![0x42; u.int_in_range(0..=MAX_PAYLOAD)?],
    };
    let raw = u.arbitrary()?;
    connect.variable = if raw {
        let n = u.int_in_range(0..=300usize)?;
        Variable::Raw(u.bytes(n)?.to_vec())
    } else {
        let mut params = Vec::new();
        for _ in 0..u.int_in_range(0..=4)? {
            let n = u.int_in_range(0..=260usize)?;
            params.push(Parameter {
                code: u.arbitrary()?,
                value: u.bytes(n)?.to_vec(),
            });
        }
        Variable::Parameters(params)
    };
    let t = Tpdu::ConnectionRequest(connect.clone());
    check_wire_value(&t);
    if let Ok(p) = over_tpkt::from_tpdu(&t) {
        assert!(connect.credit < 16 && connect.class < 16 && connect.options < 16);
        if let Variable::Raw(b) = &connect.variable {
            connect.variable = Variable::parse(b);
        }
        assert_eq!(over_tpkt::tpdu(&p), Ok(Tpdu::ConnectionRequest(connect)));
        assert!(p.to_bytes().is_ok());
    }
    // A message cut into data TPDUs reads back whole.
    let tpdu_size = u.int_in_range(0..=MAX_PACKET)?;
    let n = u.int_in_range(0..=4000usize)?;
    let message = u.bytes(n)?;
    let bytes = over_tpkt::write_message(message, tpdu_size).unwrap();
    let (got, failure) = decode_all(|| messages(MAX_PACKET, 4000), &bytes);
    assert_eq!(failure, None);
    assert_eq!(got, [Assembled::Message(message.to_vec())]);
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    check_wire::<Packet>(data);
    check_wire::<Header>(data);
    // The size limit comes from the first two bytes.
    let limit = match data {
        [a, b, ..] => usize::from(u16::from_be_bytes([*a, *b])),
        _ => MAX_PACKET,
    };
    for limit in [MAX_PACKET, limit] {
        check_decode(|| Frames::<Packet>::with_limit(limit), data);
        let (packets, _) = decode_all(|| Frames::<Packet>::with_limit(limit), data);
        for packet in packets {
            assert!(packet.payload.len() + HEADER_LEN <= Frames::<Packet>::with_limit(limit).limit());
            assert!((MIN_PAYLOAD..=MAX_PAYLOAD).contains(&packet.payload.len()));
            check_wire_value(&packet);
            check_wire::<Tpdu>(&packet.payload);
            if let Ok(tpdu) = over_tpkt::tpdu(&packet) {
                assert_eq!(
                    over_tpkt::tpdu(&over_tpkt::from_tpdu(&tpdu).unwrap()),
                    Ok(tpdu)
                );
            }
        }
    }
    let _ = built(data);
});
