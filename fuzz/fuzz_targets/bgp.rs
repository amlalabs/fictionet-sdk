//! BGP-4 messages, as a world playing a router reads them, in two-octet
//! and four-octet AS sessions, and UPDATEs built from fuzzed fields the
//! way world code builds them.
#![no_main]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use fictionet::stdlib::bgp::{
    Attribute, Context, EncodeError, Frame, Frames, MAX_BODY_LEN, Message, MpReach,
    Nlri, Open, Origin, Prefix, Segment, SegmentKind, Update, afi, kind, safi,
};
use fictionet::stdlib::codec::{Decode, Wire, contract, test_support::decode_all};
use libfuzzer_sys::fuzz_target;

fn encode(message: &Message, context: &Context) -> Result<Vec<u8>, EncodeError> {
    message.to_frame(context)?.to_bytes()
}

/// Every combination of the session settings.
const CONTEXTS: [Context; 4] = [
    Context { four_octet_as: false, enhanced_route_refresh: false },
    Context { four_octet_as: true, enhanced_route_refresh: false },
    Context { four_octet_as: false, enhanced_route_refresh: true },
    Context { four_octet_as: true, enhanced_route_refresh: true },
];

/// Whether an UPDATE mixes kinds of routes, which a reader takes from
/// older speakers but a writer refuses (RFC 7606 section 5.1).
fn mixes(m: &Message) -> bool {
    let Message::Update(u) = m else { return false };
    let mp = u.attributes.iter().filter(|a| matches!(a, Attribute::MpReach(_) | Attribute::MpUnreach(_))).count();
    usize::from(!u.withdrawn.is_empty()) + usize::from(!u.nlri.is_empty()) + mp > 1
}

/// An UPDATE built from the bytes as world code would build one, with
/// fields a reader would never give: prefixes with bits past their
/// length, empty communities, AS 0, long withdrawn lists, odd flags.
fn update_from(data: &[u8]) -> Update {
    let mut it = data.iter().copied();
    let mut byte = move || it.next().unwrap_or(0);
    let prefix = |b: &mut dyn FnMut() -> u8| {
        let addr = Ipv4Addr::new(b(), b(), b(), b());
        Prefix { addr: IpAddr::V4(addr), length: b() % 34 }
    };
    let what = byte();
    let withdrawn = (0..usize::from(byte()) * 17).map(|_| prefix(&mut byte)).collect();
    let mut attributes = Vec::new();
    if what & 1 != 0 {
        attributes.push(Attribute::MpReach(MpReach {
            afi: if byte() % 2 == 0 { afi::IPV4 } else { afi::IPV6 },
            safi: safi::UNICAST,
            next_hop: vec![0x20; usize::from(byte() % 40)],
            nlri: Nlri::Prefixes(vec![Prefix::new(IpAddr::V6(Ipv6Addr::LOCALHOST), byte() % 129).unwrap()]),
        }));
    }
    if what & 2 != 0 {
        attributes.push(Attribute::Origin(Origin::Igp));
        attributes
            .push(Attribute::AsPath(vec![Segment { kind: SegmentKind::Sequence, asns: vec![u32::from(byte() % 3)] }]));
        attributes.push(Attribute::NextHop(Ipv4Addr::new(byte(), 0, 0, 1)));
    }
    if what & 4 != 0 {
        let values = (0..byte() % 3).map(|n| u32::from(n)).collect();
        attributes.push(Attribute::Communities { values, partial: byte() % 2 == 0 });
    }
    if what & 8 != 0 {
        attributes.push(Attribute::Aggregator {
            asn: u32::from(byte() % 3),
            address: Ipv4Addr::LOCALHOST,
            partial: byte() % 2 == 0,
        });
    }
    if what & 16 != 0 {
        let value = (0..byte() % 12).map(|_| byte()).collect();
        attributes.push(Attribute::Unknown { flags: byte(), kind: 16 + byte() % 4, value });
    }
    let nlri = if what & 32 != 0 { vec![prefix(&mut byte)] } else { vec![] };
    Update { withdrawn, attributes, nlri }
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(|| Frames, data, 2 * Frames.capacity());
    contract::check_wire::<Frame>(data);
    contract::check_wire::<Open>(data);
    contract::check_decode_with_alloc_limit(|| Frames.map(|frame| Message::decode(&frame, &Context::default())), data, 2 * Frames.capacity());
    let built = Frame {
        kind: data.first().copied().unwrap_or(0),
        body: data.iter().take(MAX_BODY_LEN + 1).copied().collect(),
    };
    contract::check_wire_value(&built);

    let frames = decode_all(|| Frames, data).0;

    // Any bytes as the body of each message type, too.
    let bodies = (1..=6).map(|kind| Frame { kind, body: data.to_vec() });
    for f in frames.into_iter().chain(bodies) {
        for ctx in CONTEXTS {
            let strict = Message::decode(&f, &ctx);
            // RFC 7606 closes the connection only for errors the strict
            // reader has too, and reads the same UPDATE when it has none.
            if f.kind == kind::UPDATE {
                match Update::receive(&f.body, &ctx) {
                    Ok(r) => {
                        if r.withdraw.is_some() {
                            assert!(strict.is_err());
                        }
                        if let Ok(m) = &strict {
                            assert_eq!(*m, Message::Update(r.update));
                        }
                    }
                    Err(e) => {
                        assert!(strict.is_err());
                        assert!(encode(&Message::Notification(e.notification()), &ctx).is_ok());
                    }
                }
            }
            match strict {
                // A message read can be written, unless it mixes kinds of
                // routes, and reads back the same.
                Ok(m) => {
                    if mixes(&m) {
                        assert!(matches!(encode(&m, &ctx), Err(EncodeError::Unwritable)));
                        continue;
                    }
                    let bytes = encode(&m, &ctx).unwrap();
                    let back = Frame::parse(&bytes).unwrap();
                    assert_eq!(Message::decode(&back, &ctx), Ok(m));
                }
                // An error's notification can always be sent.
                Err(e) => {
                    let n = Message::Notification(e.notification());
                    assert!(encode(&n, &ctx).is_ok());
                }
            }
        }
    }
    // The body readers on their own, given bodies of any length: what
    // they read can be written, and their errors can be sent.
    let ctx = CONTEXTS[1];
    let read = [Open::parse(data).map(Message::Open), Update::parse(data, &ctx).map(Message::Update)];
    for r in read {
        match r {
            Ok(m) => assert!(mixes(&m) || encode(&m, &ctx).is_ok()),
            Err(e) => assert!(encode(&Message::Notification(e.notification()), &ctx).is_ok()),
        }
    }
    // An UPDATE built from public fields: a frame the writer gives fits in
    // a message and reads back as the same value.
    let u = Message::Update(update_from(data));
    for ctx in CONTEXTS {
        if let Ok(frame) = u.to_frame(&ctx) {
            assert!(frame.body.len() <= MAX_BODY_LEN);
            assert_eq!(Message::decode(&frame, &ctx).as_ref(), Ok(&u));
        }
    }
});
