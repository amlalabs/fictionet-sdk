//! RIP and RIPng messages, as a world playing a router reads them.
#![no_main]

use fictionet::stdlib::protocols::rip::{
    Entries, MAX_PREFIX_LEN, Message, NgEntries, NgEntry, NgMessage, Received,
};
use fictionet::stdlib::test_support::{assert_write, chunks, decode_all, decode_chunks};
use fictionet::stdlib::{
    codec::{Collect, Stream, Wire},
    protocols::rip,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let bound = 2 * (rip::MAX_MESSAGE + 1);
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Collect::<rip::Message>::new(rip::MAX_MESSAGE)),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= bound);
            }
        ),
        decode_all(|| Collect::<rip::Message>::new(rip::MAX_MESSAGE), data),
    );
    if let Ok(value) = <rip::Message as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    let bound = 2 * (rip::MAX_NG_MESSAGE + 1);
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Collect::<rip::NgMessage>::new(rip::MAX_NG_MESSAGE)),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= bound);
            }
        ),
        decode_all(|| Collect::<rip::NgMessage>::new(rip::MAX_NG_MESSAGE), data),
    );
    if let Ok(value) = <rip::NgMessage as Wire>::parse(data) {
        let _ = assert_write(&value);
    }

    let message = Message {
        command: rip::Command::Request,
        version: rip::Version::V2,
        auth: Some(rip::Auth::Other {
            kind: data.first().copied().map_or(0, u16::from),
            data: [0; 16],
        }),
        entries: Entries::WholeTable,
    };
    let _ = assert_write(&message);
    let parsed = Message::parse(data);
    if let Ok(m) = &parsed {
        assert_eq!(m.fits_datagram(), data.len() <= rip::MAX_DATAGRAM);
        let mut stream = Stream::new(Collect::<Message>::new(rip::MAX_MESSAGE));
        assert_eq!(stream.push(data), data.len());
        stream.end();
        assert_eq!(
            stream.with_next(|message, raw, span| {
                assert_eq!(raw, data);
                assert_eq!(span, 0..data.len() as u64);
                message
            }),
            Some(Ok(m.clone()))
        );
        let bytes = m.to_bytes().unwrap();
        assert_eq!(bytes.len(), data.len());
        assert_eq!(Message::parse(&bytes).as_ref(), Ok(m));
        // Reading as a router does agrees on every message parse takes.
        assert_eq!(
            Message::receive(data),
            Ok(Received {
                message: m.clone(),
                skipped: vec![]
            })
        );
    }
    // A router keeps only routes that pass the checks.
    if let Ok(r) = Message::receive(data)
        && let Entries::Routes(routes) = &r.message.entries
    {
        for x in routes {
            assert!(r.message.command.allows_metric(u32::from(x.metric)));
            let inv = !u32::from(x.mask);
            assert_eq!(inv & inv.wrapping_add(1), 0);
        }
    }

    // The same bytes as a RIPng message.
    let parsed = NgMessage::parse(data);
    if let Ok(m) = &parsed {
        let bytes = m.to_bytes().unwrap();
        assert_eq!(bytes.len(), data.len());
        assert_eq!(NgMessage::parse(&bytes).as_ref(), Ok(m));
        assert_eq!(
            NgMessage::receive(data),
            Ok(Received {
                message: m.clone(),
                skipped: vec![]
            })
        );
    }
    // RFC 2080: next hops are link-local or ::, and kept routes are valid.
    if let Ok(r) = NgMessage::receive(data)
        && let NgEntries::Entries(entries) = &r.message.entries
    {
        for e in entries {
            match e {
                NgEntry::NextHop(a) => {
                    assert!(a.is_unspecified() || a.segments()[0] & 0xffc0 == 0xfe80)
                }
                NgEntry::Route(x) => {
                    assert!(x.prefix_len <= MAX_PREFIX_LEN);
                    assert!(r.message.command.allows_metric(u32::from(x.metric)));
                }
            }
        }
    }
});
