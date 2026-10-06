//! RIP and RIPng messages, as a world playing a router reads them.
#![no_main]

use fictionet::stdlib::rip::{
    Entries, MAX_PREFIX_LEN, Message, NgEntries, NgEntry, NgMessage, Received,
};
use fictionet::stdlib::{codec::{Wire, Collect, contract}, rip};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(|| Collect::<rip::Message>::new(rip::MAX_MESSAGE), data, 2 * (rip::MAX_MESSAGE + 1));
    contract::check_wire::<rip::Message>(data);
    contract::check_decode_with_alloc_limit(|| Collect::<rip::NgMessage>::new(rip::MAX_NG_MESSAGE), data, 2 * (rip::MAX_NG_MESSAGE + 1));
    contract::check_wire::<rip::NgMessage>(data);

    let message = Message {
        command: rip::Command::Request,
        version: rip::Version::V2,
        auth: Some(rip::Auth::Other {
            kind: data.first().copied().map_or(0, u16::from),
            data: [0; 16],
        }),
        entries: Entries::WholeTable,
    };
    contract::check_wire_value(&message);
    let parsed = Message::parse(data);
    if let Ok(m) = &parsed {
        let bytes = m.to_bytes().unwrap();
        assert_eq!(bytes.len(), data.len());
        assert_eq!(Message::parse(&bytes).as_ref(), Ok(m));
        // Reading as a router does agrees on every message parse takes.
        assert_eq!(Message::receive(data), Ok(Received { message: m.clone(), skipped: vec![] }));
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
        assert_eq!(NgMessage::receive(data), Ok(Received { message: m.clone(), skipped: vec![] }));
    }
    // RFC 2080: next hops are link-local or ::, and kept routes are valid.
    if let Ok(r) = NgMessage::receive(data)
        && let NgEntries::Entries(entries) = &r.message.entries
    {
        for e in entries {
            match e {
                NgEntry::NextHop(a) => assert!(a.is_unspecified() || a.segments()[0] & 0xffc0 == 0xfe80),
                NgEntry::Route(x) => {
                    assert!(x.prefix_len <= MAX_PREFIX_LEN);
                    assert!(r.message.command.allows_metric(u32::from(x.metric)));
                }
            }
        }
    }
});
