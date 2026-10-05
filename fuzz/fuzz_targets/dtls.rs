//! DTLS records, handshake fragments and hellos, as a world playing a
//! DTLS server reads them from UDP datagrams.
#![no_main]

use fictionet::stdlib::dtls::{
    ClientHello, ContentType, Fragment, Handshake, HelloVerifyRequest, MAX_MESSAGE_LEN, MAX_REASSEMBLY_BYTES,
    MAX_RECORDS_PER_DATAGRAM, PlainRecord, Reassembler, ReassemblyError, Record, Sequence, ServerHello, UnifiedRecord,
    parse_datagram, write_datagram,
};
use libfuzzer_sys::fuzz_target;

/// Records built from the bytes, 24 at a time: plain and unified, with and
/// without connection IDs of 0 to 3 bytes, with and without lengths.
fn records_from(data: &[u8]) -> Vec<Record> {
    data.chunks(24)
        .take(MAX_RECORDS_PER_DATAGRAM)
        .map(|c| {
            let k = c[0];
            let cid = c.get(1..1 + usize::from(k >> 6)).unwrap_or(&[]).to_vec();
            let payload = c.get(4..).unwrap_or(&[]).to_vec();
            if k & 1 == 0 {
                let with_cid = k & 2 != 0;
                Record::Plain(PlainRecord {
                    content_type: if with_cid { ContentType::TLS12_CID } else { ContentType::HANDSHAKE },
                    version: 0xfefd,
                    epoch: u16::from(k & 4 != 0),
                    sequence: u64::from(k),
                    connection_id: if with_cid { cid } else { Vec::new() },
                    fragment: payload,
                })
            } else {
                Record::Unified(UnifiedRecord {
                    epoch_bits: (k >> 1) & 3,
                    connection_id: (k & 2 != 0).then_some(cid),
                    sequence: Sequence::Short(k),
                    has_length: k & 8 != 0,
                    payload,
                })
            }
        })
        .collect()
}

/// The length of the connection ID a record carries, if it carries one.
fn cid_of(r: &Record) -> Option<usize> {
    match r {
        Record::Plain(p) if p.content_type == ContentType::TLS12_CID => Some(p.connection_id.len()),
        Record::Plain(_) => None,
        Record::Unified(u) => u.connection_id.as_ref().map(Vec::len),
    }
}

fuzz_target!(|data: &[u8]| {
    // The first byte picks the connection ID length; the rest is a datagram.
    let Some((&cid_len, data)) = data.split_first() else { return };

    // A record read writes back to the same bytes, and reads the same.
    if let Ok((r, used)) = Record::parse(data, cid_len) {
        let bytes = r.to_bytes();
        assert_eq!(bytes, data[..used]);
        assert_eq!(Record::parse(&bytes, cid_len), Ok((r, used)));
    }
    if let Ok(records) = parse_datagram(data, cid_len) {
        assert_eq!(write_datagram(&records), data);
    }

    // Records built from the bytes write to a datagram that reads back as
    // the ones the writer keeps: those with the first connection ID
    // length, up to and with the first unified record without a length.
    let built = records_from(data);
    let first_cid = built.iter().find_map(cid_of);
    let mut kept = Vec::new();
    for r in &built {
        if cid_of(r).is_some_and(|n| Some(n) != first_cid) {
            continue;
        }
        kept.push(r.clone());
        if matches!(r, Record::Unified(u) if !u.has_length) {
            break;
        }
    }
    let bytes = write_datagram(&built);
    assert_eq!(parse_datagram(&bytes, first_cid.unwrap_or(0) as u8), Ok(kept));

    // The bytes as a handshake record's payload. Fragments write back the
    // same, and a reassembler takes them without holding too much. The
    // next message expected still goes in afterward.
    if let Ok(fragments) = Fragment::parse_all(data) {
        let bytes: Vec<u8> = fragments.iter().flat_map(|f| f.to_bytes()).collect();
        assert_eq!(bytes, data);
        let mut r = Reassembler::new();
        for f in &fragments {
            let _ = r.add(f);
            assert!(r.buffered() <= MAX_REASSEMBLY_BYTES);
            while let Some(m) = r.next_message() {
                let _ = m.parse_body();
            }
        }
        let body = data[..data.len().min(MAX_MESSAGE_LEN)].to_vec();
        let next = Handshake { msg_type: cid_len, message_seq: r.next_seq(), body };
        match r.add(&next.to_fragment()) {
            Ok(_) => assert!(r.next_message().is_some()),
            Err(e) => assert_eq!(e, ReassemblyError::Conflict),
        }
        assert!(r.buffered() <= MAX_REASSEMBLY_BYTES);
    }

    // The bytes as a message, sent a byte at a time, come back whole.
    // Writers cut longer messages, so those would not.
    if data.len() <= MAX_MESSAGE_LEN {
        let m = Handshake { msg_type: cid_len, message_seq: 0, body: data.to_vec() };
        let mut r = Reassembler::new();
        for f in m.fragments(1) {
            r.add(&f).unwrap();
        }
        assert_eq!(r.next_message(), Some(m));
    }

    // The bytes as hello bodies.
    if let Ok(h) = ClientHello::parse(data) {
        assert_eq!(h.to_bytes(), data);
        assert!(!h.cipher_suites.is_empty() && !h.compression_methods.is_empty());
        let _ = h.supported_versions();
    }
    if let Ok(h) = ServerHello::parse(data) {
        assert_eq!(h.to_bytes(), data);
        let _ = (h.selected_version(), h.is_hello_retry_request());
    }
    if let Ok(h) = HelloVerifyRequest::parse(data) {
        assert_eq!(h.to_bytes(), data);
    }
});
