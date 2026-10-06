//! VRRP advertisements, as a world playing a router reads and writes them.
//!
//! The checks do not trust the module alone. Checksums are worked out here
//! from RFC 3768 and RFC 9568 and compared with the module's. Fixed packets
//! with known outcomes are read on every run. Advertisements to write are
//! built straight from the fuzz bytes, not only from what the parser
//! accepts, so the writer sees values the parser never makes.
#![no_main]

use std::net::{Ipv4Addr, Ipv6Addr};

use fictionet::stdlib::vrrp::{
    Addresses, Advertisement, AdvertisementV2, AdvertisementV3, Endpoints, GROUP_V4, GROUP_V6, MAX_ADDRESSES,
    VrrpError, checksum, checksum_rfc5798,
};
use fictionet::stdlib::{codec::{Wire, Collect, Decode, contract}, vrrp};
use libfuzzer_sys::fuzz_target;

const LINK_LOCAL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);

fuzz_target!(|data: &[u8]| {
    known_packets();
    let ends = [
        Endpoints::V4 { source: Ipv4Addr::new(192, 168, 1, 2), destination: GROUP_V4 },
        Endpoints::V6 { source: LINK_LOCAL, destination: GROUP_V6 },
        endpoints_from(data),
    ];
    for e in &ends {
        check(data, e);
        // The same bytes with the checksum set right, both ways, so the
        // parser looks past it.
        for c in [oracle(data, e, false), oracle(data, e, true)].into_iter().flatten() {
            let mut fixed = data.to_vec();
            fixed[6..8].copy_from_slice(&c.to_be_bytes());
            check(&fixed, e);
        }
        write(data, e);
    }
});

/// Ones' complement sum of 16-bit words, a zero byte added to an odd
/// length.
fn add(mut sum: u64, b: &[u8]) -> u64 {
    for w in b.chunks(2) {
        sum += u64::from(w[0]) << 8 | u64::from(*w.get(1).unwrap_or(&0));
    }
    sum
}

/// The checksum per RFC 3768 section 5.3.7 and RFC 9568 section 5.2.8,
/// written apart from the module. `rfc5798` adds the IPv4 pseudo-header
/// that RFC 5798 routers use on version 3.
fn oracle(b: &[u8], e: &Endpoints, rfc5798: bool) -> Option<u16> {
    if b.len() < 8 || b.len() > 8 + 255 * 16 {
        return None;
    }
    let mut sum = add(add(0, &b[..6]), &b[8..]);
    if b[0] >> 4 == 3 {
        match e {
            Endpoints::V6 { source, destination } => {
                sum = add(sum, &source.octets());
                sum = add(sum, &destination.octets());
                sum = add(sum, &(b.len() as u32).to_be_bytes());
                sum = add(sum, &[0, 0, 0, 112]);
            }
            Endpoints::V4 { source, destination } if rfc5798 => {
                sum = add(sum, &source.octets());
                sum = add(sum, &destination.octets());
                sum = add(sum, &[0, 112]);
                sum = add(sum, &(b.len() as u16).to_be_bytes());
            }
            Endpoints::V4 { .. } => {}
        }
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    Some(!(sum as u16))
}

/// Packets worked out by hand, with the outcome each must have.
fn known_packets() {
    let v4 = Endpoints::V4 { source: Ipv4Addr::new(192, 168, 1, 2), destination: GROUP_V4 };
    // RFC 9568 checksum over IPv4: the message alone.
    let standard = [0x31, 1, 100, 1, 0, 100, 0xa8, 0xef, 192, 168, 1, 1];
    assert!(Advertisement::parse(&standard, &v4).is_ok());
    // The same with the RFC 5798 IPv4 pseudo-header checksum.
    let rfc5798 = [0x31, 1, 100, 1, 0, 100, 0x06, 0xb6, 192, 168, 1, 1];
    assert!(Advertisement::parse(&rfc5798, &v4).is_ok());
    // Version 2 with no addresses.
    let empty = [0x21, 1, 100, 0, 0, 1, 0x7a, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(Advertisement::parse(&empty, &v4), Err(VrrpError::NoAddresses));
    // Version 2 with authentication type 255.
    let auth = [0x21, 1, 100, 1, 0xff, 1, 0xba, 0x51, 192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(Advertisement::parse(&auth, &v4), Err(VrrpError::AuthType(255)));
    // Version 3 over IPv6 from a global source.
    let global = Endpoints::V6 { source: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2), destination: GROUP_V6 };
    let mut v6 = vec![0x31, 1, 100, 1, 0, 100, 0, 0];
    v6.extend_from_slice(&Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).octets());
    let c = oracle(&v6, &global, false).unwrap();
    v6[6..8].copy_from_slice(&c.to_be_bytes());
    assert_eq!(Advertisement::parse(&v6, &global), Err(VrrpError::LinkLocal));
}

/// Endpoints taken from the first bytes: IPv4 or IPv6, any source.
fn endpoints_from(data: &[u8]) -> Endpoints {
    let mut o = [0u8; 16];
    for (i, x) in data.iter().rev().take(16).enumerate() {
        o[i] = *x;
    }
    if data.last().is_some_and(|x| x & 1 == 0) {
        Endpoints::V4 { source: Ipv4Addr::new(o[0], o[1], o[2], o[3]), destination: GROUP_V4 }
    } else {
        Endpoints::V6 { source: Ipv6Addr::from(o), destination: GROUP_V6 }
    }
}

fn check(data: &[u8], e: &Endpoints) {
    contract::check_decode_with_alloc_limit(|| Collect::<vrrp::Datagram>::new(vrrp::MAX_MESSAGE), data, 2 * (vrrp::MAX_MESSAGE + 1));
    contract::check_decode_with_alloc_limit(
        || Collect::<vrrp::Datagram>::new(vrrp::MAX_MESSAGE)
            .map(|datagram| Advertisement::parse(&datagram.0, e)),
        data,
        2 * (vrrp::MAX_MESSAGE + 1),
    );
    contract::check_wire::<vrrp::Datagram>(data);
    contract::check_wire_value(&vrrp::Datagram(
        data.iter().take(vrrp::MAX_MESSAGE + 1).copied().collect(),
    ));

    let parsed = Advertisement::parse(data, e);

    // A checksum neither formula gives is never taken.
    let got = data.get(6..8).map(|c| u16::from_be_bytes([c[0], c[1]]));
    if let (Ok(_), Some(got)) = (&parsed, got) {
        let ok = |w: Option<u16>| w.is_some_and(|w| got == w || (w == 0 && got == 0xffff));
        assert!(ok(oracle(data, e, false)) || ok(oracle(data, e, true)));
    }

    if let Ok(a) = &parsed {
        // An advertisement read can be written, and reads back the same.
        let bytes = a.frame(e).and_then(|frame| frame.to_bytes()).unwrap();
        assert_eq!(bytes.len(), data.len());
        written(a, &bytes, e);
    }
}

/// What every written advertisement must satisfy.
fn written(a: &Advertisement, bytes: &[u8], e: &Endpoints) {
    let field = Some(u16::from_be_bytes([bytes[6], bytes[7]]));
    assert_eq!(field, oracle(bytes, e, false));
    assert_eq!(checksum(bytes, e), oracle(bytes, e, false));
    assert_eq!(checksum_rfc5798(bytes, e), oracle(bytes, e, true));
    assert_eq!(Advertisement::parse(bytes, e).as_ref(), Ok(a));
    assert_eq!(a.addresses().len(), a.address_count());
    if let Endpoints::V6 { source, .. } = e {
        assert_eq!(source.segments()[0] & 0xffc0, 0xfe80);
        assert_eq!(bytes[8], 0xfe);
        assert_eq!(bytes[9] & 0xc0, 0x80);
    }
    if a.version() == 2 {
        assert!(bytes[4] <= 2);
    }
    assert_ne!(bytes[3], 0);
}

/// Builds an advertisement from the fuzz bytes, as a caller might, and
/// checks that what the writer returns reads back, and that what it
/// refuses breaks a rule.
fn write(data: &[u8], e: &Endpoints) {
    let byte = |i: usize| data.get(i).copied().unwrap_or(0);
    // Up to a few more than the limit, without building huge lists.
    let n = usize::from(byte(3)) + usize::from(byte(4) & 3);
    let ad = if byte(0) & 1 == 0 {
        Advertisement::V2(AdvertisementV2 {
            vrid: byte(1),
            priority: byte(2),
            auth_type: byte(5) & 7,
            interval: byte(6),
            addresses: (0..n).map(|i| Ipv4Addr::new(byte(i), byte(i + 1), 1, 1)).collect(),
            auth_data: [byte(7); 8],
        })
    } else {
        let addresses = if byte(0) & 2 == 0 {
            Addresses::V4((0..n).map(|i| Ipv4Addr::new(byte(i), 2, 2, 2)).collect())
        } else {
            Addresses::V6(
                (0..n)
                    .map(|i| Ipv6Addr::new(u16::from(byte(i)) << 8 | u16::from(byte(i + 1)), 0, 0, 0, 0, 0, 0, 1))
                    .collect(),
            )
        };
        let interval = u16::from(byte(5)) << 8 | u16::from(byte(6));
        Advertisement::V3(AdvertisementV3 { vrid: byte(1), priority: byte(2), interval, addresses })
    };
    match ad.frame(e).and_then(|frame| frame.to_bytes()) {
        Ok(bytes) => {
            assert_eq!(Ok(bytes.len()), ad.encoded_len(e));
            written(&ad, &bytes, e);
        }
        Err(err) => {
            assert_eq!(ad.encoded_len(e), Err(err));
            let count = ad.address_count();
            let v6_bad = match (&ad, e) {
                (Advertisement::V3(a), Endpoints::V6 { source, .. }) => {
                    let first = match &a.addresses {
                        Addresses::V6(v) => v.first().map(|x| x.segments()[0] & 0xffc0 != 0xfe80),
                        Addresses::V4(_) => None,
                    };
                    first == Some(true) || source.segments()[0] & 0xffc0 != 0xfe80
                }
                _ => false,
            };
            let broken = ad.vrid() == 0
                || count == 0
                || count > MAX_ADDRESSES
                || v6_bad
                || match (&ad, e) {
                    (Advertisement::V2(a), Endpoints::V4 { .. }) => a.auth_type > 2,
                    (Advertisement::V2(_), Endpoints::V6 { .. }) => true,
                    (Advertisement::V3(a), _) => {
                        a.interval > 0x0fff
                            || matches!(
                                (&a.addresses, e),
                                (Addresses::V4(_), Endpoints::V6 { .. }) | (Addresses::V6(_), Endpoints::V4 { .. })
                            )
                    }
                };
            assert!(broken, "{ad:?} refused with {err:?}");
        }
    }
}
