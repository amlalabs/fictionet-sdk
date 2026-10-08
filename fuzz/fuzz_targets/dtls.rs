//! DTLS records, handshake fragments and hellos, as a world playing a
//! DTLS server reads them from UDP datagrams.
#![no_main]

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::test_support::contract;
use fictionet::stdlib::dtls::{
    ClientHello, ContentType, Datagram, Error, Fragment, Fragments, Handshake, HelloVerifyRequest,
    MAX_MESSAGE_LEN, MAX_REASSEMBLY_BYTES, MAX_RECORDS_PER_DATAGRAM, PlainRecord, Reassembler,
    Record, Sequence, ServerHello, UnifiedRecord,
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

/// Checks the runtime CID length and strict datagram construction.
fn records(data: &[u8], cid_len: u8) {
    if let Ok(record) = Record::read(data, cid_len) {
        let datagram = record.datagram(cid_len).unwrap();
        contract::check_wire_value(&datagram);
        assert_eq!(datagram.to_bytes().unwrap(), data);
    }
    if let Ok(records) = Datagram::read(data, cid_len) {
        let datagram = Datagram::new(&records, cid_len).unwrap();
        contract::check_wire_value(&datagram);
        assert_eq!(datagram.to_bytes().unwrap(), data);
    }
    let built = records_from(data);
    for record in &built {
        if let Ok(datagram) = record.datagram(cid_len) {
            contract::check_wire_value(&datagram);
            assert_eq!(Record::read(&datagram.to_bytes().unwrap(), cid_len).as_ref(), Ok(record));
        }
    }
    if let Ok(datagram) = Datagram::new(&built, cid_len) {
        contract::check_wire_value(&datagram);
        assert_eq!(Datagram::read(&datagram.to_bytes().unwrap(), cid_len), Ok(built));
    }
}

fuzz_target!(|data: &[u8]| {
    contract::check_wire::<Datagram>(data);
    records(data, 0);
    records(data, 1);
    records(data, 8);
    contract::check_wire::<Fragment>(data);
    contract::check_wire::<Fragments>(data);
    contract::check_wire::<Handshake>(data);
    contract::check_wire::<ClientHello>(data);
    contract::check_wire::<ServerHello>(data);
    contract::check_wire::<HelloVerifyRequest>(data);
    let Some((&cid_len, data)) = data.split_first() else {
        return;
    };
    records(data, cid_len);

    // The bytes as a handshake record's payload. Fragments write back the
    // same, and a reassembler takes them without holding too much. The
    // next message expected still goes in afterward.
    if let Ok(Fragments(fragments)) = Fragments::parse(data) {
        let bytes: Vec<u8> = fragments
            .iter()
            .flat_map(|f| f.to_bytes().unwrap())
            .collect();
        assert_eq!(bytes, data);
        let mut r = Reassembler::new();
        for f in &fragments {
            let _ = r.add(f);
            assert!(r.buffered() <= MAX_REASSEMBLY_BYTES);
            while let Some(m) = r.next_message() {
                let _ = m.parse_body();
                contract::check_wire_value(&m);
            }
        }
        let body = data[..data.len().min(MAX_MESSAGE_LEN)].to_vec();
        let next = Handshake { msg_type: cid_len, message_seq: r.next_seq(), body };
        match r.add(&next.to_fragment().unwrap()) {
            Ok(_) => assert!(r.next_message().is_some()),
            Err(e) => assert_eq!(e, Error::FragmentConflict),
        }
        assert!(r.buffered() <= MAX_REASSEMBLY_BYTES);
    }

    // The bytes as a message, sent a byte at a time, come back whole.
    // Fragment constructors refuse bodies above the message limit.
    if data.len() <= MAX_MESSAGE_LEN {
        let m = Handshake { msg_type: cid_len, message_seq: 0, body: data.to_vec() };
        let mut r = Reassembler::new();
        for f in m.fragments(1).unwrap() {
            contract::check_wire_value(&f);
            r.add(&f).unwrap();
        }
        assert_eq!(r.next_message(), Some(m));
    }

    // The bytes as hello bodies.
    if let Ok(h) = ClientHello::parse(data) {
        assert_eq!(h.to_bytes().unwrap(), data);
        assert!(!h.cipher_suites.is_empty() && !h.compression_methods.is_empty());
        let _ = h.supported_versions();
    }
    if let Ok(h) = ServerHello::parse(data) {
        assert_eq!(h.to_bytes().unwrap(), data);
        let _ = (h.selected_version(), h.is_hello_retry_request());
    }
    if let Ok(h) = HelloVerifyRequest::parse(data) {
        assert_eq!(h.to_bytes().unwrap(), data);
    }
});
