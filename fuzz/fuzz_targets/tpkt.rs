//! TPKT packets, as a world on port 102 or 3389 reads them, and packets a
//! world builds, as it writes them.
#![no_main]

use arbitrary::{Result, Unstructured};
use fictionet::stdlib::cotp::{Reassembler, Tpdu};
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
            // A TPDU read is written back into a packet that reads back.
            if let Ok(t) = p.tpdu() {
                let back = Packet::from_tpdu(&t);
                assert!(back.to_bytes().is_ok());
                // The TPDU may read back tidied, such as with bad parameters
                // dropped, but once tidied it stays the same.
                let again = back.tpdu().unwrap();
                assert_eq!(Packet::from_tpdu(&again).tpdu(), Ok(again));
            }
        }
    }
    let _ = Packet::parse(data);
    let _ = built(data);
});
