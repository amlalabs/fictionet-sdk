//! DTLS records, handshake fragments and hellos, as a world playing a
//! DTLS server reads them from UDP datagrams.
#![no_main]

use fictionet::stdlib::codec::{Wire, contract};
use fictionet::stdlib::dtls::{
    ClientHello, ContentType, Datagram, Fragment, Fragments, Handshake, HelloVerifyRequest,
    MAX_MESSAGE_LEN, MAX_REASSEMBLY_BYTES, MAX_RECORDS_PER_DATAGRAM, PlainRecord, Reassembler,
    ReassemblyError, Record, Sequence, ServerHello, UnifiedRecord,
};
use libfuzzer_sys::fuzz_target;

/// Records built from the bytes, 24 at a time: plain and unified, with and
/// without connection IDs of 0 to 3 bytes, with and without lengths.
fn records_from<const CID_LEN: u8>(data: &[u8]) -> Vec<Record<CID_LEN>> {
    data.chunks(24)
        .take(MAX_RECORDS_PER_DATAGRAM)
        .map(|c| {
            let k = c[0];
            let cid = c.get(1..1 + usize::from(k >> 6)).unwrap_or(&[]).to_vec();
            let payload = c.get(4..).unwrap_or(&[]).to_vec();
            if k & 1 == 0 {
                let with_cid = k & 2 != 0;
                Record::Plain(PlainRecord {
                    content_type: if with_cid {
                        ContentType::TLS12_CID
                    } else {
                        ContentType::HANDSHAKE
                    },
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

/// Checks a selected CID length and constructed records through the strict writer.
fn records<const CID_LEN: u8>(data: &[u8]) {
    contract::check_wire::<Record<CID_LEN>>(data);
    contract::check_wire::<Datagram<CID_LEN>>(data);
    if let Ok(record) = Record::<CID_LEN>::parse(data) {
        assert_eq!(record.to_bytes().unwrap(), data);
    }
    if let Ok(datagram) = Datagram::<CID_LEN>::parse(data) {
        assert_eq!(datagram.to_bytes().unwrap(), data);
    }
    let built = records_from::<CID_LEN>(data);
    for record in &built {
        contract::check_wire_value(record);
    }
    contract::check_wire_value(&Datagram(built));
}

fuzz_target!(|data: &[u8]| {
    contract::check_wire::<Record<0>>(data);
    contract::check_wire::<Record<1>>(data);
    contract::check_wire::<Record<8>>(data);
    contract::check_wire::<Datagram<0>>(data);
    contract::check_wire::<Datagram<1>>(data);
    contract::check_wire::<Datagram<8>>(data);
    contract::check_wire::<Fragment>(data);
    contract::check_wire::<Fragments>(data);
    contract::check_wire::<Handshake>(data);
    contract::check_wire::<ClientHello>(data);
    contract::check_wire::<ServerHello>(data);
    contract::check_wire::<HelloVerifyRequest>(data);
    let Some((&cid_len, data)) = data.split_first() else {
        return;
    };
    // Cover short, long and maximum CID lengths with concrete Wire units.
    match cid_len {
        0 => records::<0>(data),
        1 => records::<1>(data),
        2 => records::<2>(data),
        3 => records::<3>(data),
        4 => records::<4>(data),
        5 => records::<5>(data),
        6 => records::<6>(data),
        7 => records::<7>(data),
        8 => records::<8>(data),
        9 => records::<9>(data),
        10 => records::<10>(data),
        11 => records::<11>(data),
        12 => records::<12>(data),
        13 => records::<13>(data),
        14 => records::<14>(data),
        15 => records::<15>(data),
        16 => records::<16>(data),
        17 => records::<17>(data),
        18 => records::<18>(data),
        19 => records::<19>(data),
        20 => records::<20>(data),
        21 => records::<21>(data),
        22 => records::<22>(data),
        23 => records::<23>(data),
        24 => records::<24>(data),
        25 => records::<25>(data),
        26 => records::<26>(data),
        27 => records::<27>(data),
        28 => records::<28>(data),
        29 => records::<29>(data),
        30 => records::<30>(data),
        31 => records::<31>(data),
        32 => records::<32>(data),
        64 => records::<64>(data),
        128 => records::<128>(data),
        254 => records::<254>(data),
        _ => records::<255>(data),
    }

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
        let next = Handshake {
            msg_type: cid_len,
            message_seq: r.next_seq(),
            body,
        };
        match r.add(&next.to_fragment().unwrap()) {
            Ok(_) => assert!(r.next_message().is_some()),
            Err(e) => assert_eq!(e, ReassemblyError::Conflict),
        }
        assert!(r.buffered() <= MAX_REASSEMBLY_BYTES);
    }

    // The bytes as a message, sent a byte at a time, come back whole.
    // Fragment constructors refuse bodies above the message limit.
    if data.len() <= MAX_MESSAGE_LEN {
        let m = Handshake {
            msg_type: cid_len,
            message_seq: 0,
            body: data.to_vec(),
        };
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
