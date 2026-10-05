//! TPKT packets, as a world on port 102 or 3389 reads them, and packets a
//! world builds, as it writes them.
#![no_main]

use arbitrary::{Result, Unstructured};
use fictionet::stdlib::cotp::{Connect, Data, Parameter, Reassembler, Tpdu, Variable};
use fictionet::stdlib::tpkt::{
    Decoder, EncodeError, HEADER_LEN, Header, MAX_BUFFERED, MAX_PACKET, MAX_PAYLOAD, MIN_PACKET,
    MIN_PAYLOAD, Packet, TpktError, write_message,
};
use libfuzzer_sys::fuzz_target;

/// Feeds `data` in chunks to a decoder with `limit`, taking packets out
/// after each feed, as a world does. Every packet, then the error that
/// broke the stream, if one did.
fn split(data: &[u8], limit: usize, bytewise: bool) -> (Vec<Packet>, Option<TpktError>) {
    let mut decoder = Decoder::with_limit(limit);
    let mut packets = Vec::new();
    let chunks: Vec<&[u8]> = if bytewise {
        data.chunks(1).collect()
    } else {
        vec![data]
    };
    for chunk in chunks {
        let mut rest = chunk;
        while !rest.is_empty() {
            let took = decoder.feed(rest);
            assert!(decoder.buffered() <= decoder.limit());
            assert!(decoder.buffered() <= MAX_BUFFERED);
            rest = &rest[took..];
            let mut progress = took > 0;
            while let Some(r) = decoder.next_packet() {
                match r {
                    Ok(p) => packets.push(p),
                    Err(e) => return (packets, Some(e)),
                }
                progress = true;
            }
            // A full decoder always gives a packet or an error.
            assert!(progress);
        }
    }
    (packets, None)
}

/// Values a world builds: whatever a writer accepts reads back the same.
fn built(data: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data);
    // A header a writer takes reads back the same.
    let header = Header {
        reserved: u.arbitrary()?,
        length: u.arbitrary()?,
    };
    match header.to_bytes() {
        Ok(bytes) => assert_eq!(Header::parse(&bytes, MAX_PACKET), Ok(Some(header))),
        Err(e) => {
            assert!(usize::from(header.length) < MIN_PACKET);
            assert_eq!(e, EncodeError::TooShort(header.payload_len()));
        }
    }
    let n = u.int_in_range(0..=300usize)?;
    let packet = Packet {
        reserved: u.arbitrary()?,
        payload: u.bytes(n)?.to_vec(),
    };
    match packet.to_bytes() {
        Ok(bytes) => assert_eq!(Packet::parse(&bytes), Ok(Some((packet, bytes.len())))),
        Err(e) => assert_eq!(e, EncodeError::TooShort(n)),
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
    let fits = n <= MAX_PAYLOAD - 3 && number < 0x80;
    match Packet::try_from_tpdu(&data) {
        Ok(p) => {
            assert!(fits);
            assert_eq!(p.tpdu(), Ok(data));
        }
        Err(e) => {
            assert!(!fits);
            assert_eq!(e, EncodeError::Unrepresentable);
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
    if let Ok(p) = Packet::try_from_tpdu(&t) {
        assert!(connect.credit < 16 && connect.class < 16 && connect.options < 16);
        if let Variable::Raw(b) = &connect.variable {
            connect.variable = Variable::parse(b);
        }
        assert_eq!(p.tpdu(), Ok(Tpdu::ConnectionRequest(connect)));
        assert!(p.to_bytes().is_ok());
    }
    // A message cut into data TPDUs reads back whole.
    let tpdu_size = u.int_in_range(0..=MAX_PACKET)?;
    let n = u.int_in_range(0..=4000usize)?;
    let message = u.bytes(n)?;
    let bytes = write_message(message, tpdu_size).unwrap();
    let (packets, err) = split(&bytes, MAX_PACKET, false);
    assert_eq!(err, None);
    let mut reassembler = Reassembler::new();
    let mut whole = None;
    for p in &packets {
        let Ok(Tpdu::Data(d)) = p.tpdu() else {
            panic!("not a data TPDU")
        };
        if let Some(m) = reassembler.push(&d).unwrap() {
            assert!(whole.is_none());
            whole = Some(m);
        }
    }
    assert_eq!(whole.as_deref(), Some(message));
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    // The size limit comes from the first two bytes.
    let limit = match data {
        [a, b, ..] => usize::from(u16::from_be_bytes([*a, *b])),
        _ => MAX_PACKET,
    };
    // The stream, split two ways: all at once, and a byte at a time. Both
    // give the same packets and the same error.
    for limit in [MAX_PACKET, limit] {
        let (packets, err) = split(data, limit, false);
        assert_eq!(split(data, limit, true), (packets.clone(), err));
        for p in &packets {
            assert!(p.payload.len() >= MIN_PAYLOAD && p.payload.len() <= MAX_PAYLOAD);
            assert!(p.payload.len() + HEADER_LEN <= limit.max(HEADER_LEN + MIN_PAYLOAD));
            // A packet read can be written, and reads back the same.
            let bytes = p.to_bytes().unwrap();
            assert_eq!(Packet::parse(&bytes), Ok(Some((p.clone(), bytes.len()))));
            // A TPDU read is written back whole, into a packet that reads
            // back as the same TPDU.
            if let Ok(t) = p.tpdu() {
                let back = Packet::try_from_tpdu(&t).unwrap();
                assert!(back.to_bytes().is_ok());
                assert_eq!(back.tpdu(), Ok(t.clone()));
                assert_eq!(Packet::from_tpdu(&t), back);
            }
        }
    }
    let _ = Packet::parse(data);
    let _ = built(data);
});
