//! DTLS records, handshake fragments and hellos, as a world playing a
//! DTLS server reads them from UDP datagrams.
#![no_main]

use fictionet::stdlib::dtls::{
    ContentType, Handshake, MAX_MESSAGE_LEN, MAX_RECORDS_PER_DATAGRAM, PlainRecord, Record,
    Sequence, UnifiedRecord, harness,
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

/// Checks the runtime CID length and strict datagram construction.
fn records(data: &[u8], cid_len: u8) {
    harness::records(data, cid_len);
    harness::record_values(&records_from(data), cid_len);
}

fuzz_target!(|data: &[u8]| {
    harness::wire(data);
    records(data, 0);
    records(data, 1);
    records(data, 8);
    let Some((&cid_len, data)) = data.split_first() else {
        return;
    };
    records(data, cid_len);

    harness::fragments(data, cid_len);

    // The bytes as a message, sent a byte at a time, come back whole.
    // Fragment constructors refuse bodies above the message limit.
    if data.len() <= MAX_MESSAGE_LEN {
        let m = Handshake {
            msg_type: cid_len,
            message_seq: 0,
            body: data.to_vec(),
        };
        harness::reassemble(&m, &m.fragments(1).unwrap());
    }

    harness::hellos(data);
});
