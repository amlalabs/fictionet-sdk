//! OSPFv2 and OSPFv3 packets and LSAs, as a world playing a router reads
//! them, and values a world builds, as it writes them.
#![no_main]

use std::net::{Ipv4Addr, Ipv6Addr};

use arbitrary::{Result, Unstructured};
use fictionet::stdlib::ospf::{
    ALL_SPF_ROUTERS_V4, ALL_SPF_ROUTERS_V6, AsExternalLsa, AsExternalLsaV3, Auth, Body, DatabaseDescription,
    Endpoints, ExternalRoute, Header, HelloV2, HelloV3, InterAreaPrefixLsa, InterAreaRouterLsa, IntraAreaPrefixLsa,
    LSA_HEADER_LEN, LinkLsa, Lsa, LsaBody, LsaHeader, LsaKey, MAX_LSA, MAX_MESSAGE, MAX_PACKET, NetworkLsa,
    NetworkLsaV3, OPTION_L_V2, OPTION_L_V3, OspfError, Packet, Prefix, RouterInterface, RouterLink, RouterLsa,
    RouterLsaV3, SummaryLsa, TosMetric, Version, checksum, lsa_checksum, lsa_type_v2, lsa_type_v3,
};
use fictionet::stdlib::{codec::{Wire, Collect, Decode, contract}, ospf};
use libfuzzer_sys::fuzz_target;

fn ends() -> [Endpoints; 2] {
    [
        Endpoints::V4 { source: Ipv4Addr::new(10, 0, 0, 1), destination: ALL_SPF_ROUTERS_V4 },
        Endpoints::V6 { source: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), destination: ALL_SPF_ROUTERS_V6 },
    ]
}

fn check(data: &[u8], e: &Endpoints) {
    contract::check_decode_with_alloc_limit(|| Collect::<ospf::Datagram>::new(ospf::MAX_MESSAGE), data, 2 * (ospf::MAX_MESSAGE + 1));
    contract::check_decode_with_alloc_limit(
        || Collect::<ospf::Datagram>::new(ospf::MAX_MESSAGE)
            .map(|datagram| Packet::parse(&datagram.0, e)),
        data,
        2 * (ospf::MAX_MESSAGE + 1),
    );
    contract::check_wire::<ospf::Datagram>(data);
    contract::check_wire_value(&ospf::Datagram(
        data.iter().take(ospf::MAX_MESSAGE + 1).copied().collect(),
    ));

    let parsed = Packet::parse(data, e);

    if let Ok(p) = &parsed {
        // A packet read can be written, and reads back the same. LSAs an
        // update drops and a signaling block with a wrong checksum make it
        // shorter.
        let bytes = p.frame(e).and_then(|frame| frame.to_bytes()).unwrap();
        assert!(bytes.len() <= data.len());
        assert_eq!(Packet::parse(&bytes, e).as_ref(), Ok(p));
    }
}

fn check_lsa(data: &[u8], v: Version) {
    contract::check_wire::<ospf::LsaFrame>(data);
    contract::check_wire::<ospf::LsaBodyFrame>(data);
    if let Ok((lsa, n)) = Lsa::parse(data, v) {
        // An LSA read writes back to the same bytes, so its header is the
        // one received (RFC 2328 sections 13.1 and 13.7).
        assert!(n <= data.len());
        let bytes = lsa.frame(v).and_then(|frame| frame.to_bytes()).unwrap();
        assert_eq!(bytes, data[..n]);
        let h = lsa.header(v).unwrap();
        assert_eq!((h.checksum, usize::from(h.length)), (u16::from_be_bytes([data[16], data[17]]), n));
    }
    // The bytes after a header as a body, read directly: it is capped at
    // what an LSA holds, and a body read writes back to the same bytes.
    if data.len() >= LSA_HEADER_LEN {
        let body = &data[LSA_HEADER_LEN..];
        let t = match v {
            Version::V2 => u16::from(data[3]),
            Version::V3 => u16::from_be_bytes([data[2], data[3]]),
        };
        match LsaBody::parse(body, v, t) {
            Ok(b) => assert_eq!(b.frame(v, t).and_then(|frame| frame.to_bytes()).as_deref(), Ok(body)),
            Err(e) => assert!(body.len() <= MAX_LSA - LSA_HEADER_LEN || e == OspfError::TooLong),
        }
    }
}

fn ip4(u: &mut Unstructured) -> Result<Ipv4Addr> {
    Ok(Ipv4Addr::from(u.arbitrary::<u32>()?))
}

fn ip6(u: &mut Unstructured) -> Result<Ipv6Addr> {
    Ok(Ipv6Addr::from(u.arbitrary::<u128>()?))
}

/// A list of up to `max` items made by `f`.
fn list<T>(u: &mut Unstructured, max: usize, mut f: impl FnMut(&mut Unstructured) -> Result<T>) -> Result<Vec<T>> {
    let n = u.int_in_range(0..=max)?;
    (0..n).map(|_| f(u)).collect()
}

/// A prefix built with `Prefix::new` or directly, so its address may have
/// bits past its length, and its length may be out of range.
fn prefix(u: &mut Unstructured) -> Result<Prefix> {
    if u.arbitrary()? {
        Ok(Prefix::new(u.arbitrary()?, u.arbitrary()?, ip6(u)?))
    } else {
        Ok(Prefix { length: u.arbitrary()?, options: u.arbitrary()?, address: ip6(u)? })
    }
}

/// An LSA body built from fuzz bytes, valid or not, with an LS type that
/// usually fits it.
fn lsa_body(u: &mut Unstructured, v: Version) -> Result<(u16, LsaBody)> {
    let any: u16 = u.arbitrary()?;
    let (fit, body) = match (v, u.int_in_range(0..=5u8)?) {
        (Version::V2, 0) => (
            lsa_type_v2::ROUTER,
            LsaBody::Router(RouterLsa {
                flags: u.arbitrary()?,
                links: list(u, 8, |u| {
                    Ok(RouterLink {
                        id: ip4(u)?,
                        data: ip4(u)?,
                        kind: u.arbitrary()?,
                        metric: u.arbitrary()?,
                        tos: list(u, 300, |u| Ok(TosMetric { tos: u.arbitrary()?, metric: u.arbitrary()? }))?,
                    })
                })?,
            }),
        ),
        (Version::V2, 1) => (
            lsa_type_v2::NETWORK,
            LsaBody::Network(NetworkLsa { network_mask: ip4(u)?, attached_routers: list(u, 20, ip4)? }),
        ),
        (Version::V2, 2) => (
            lsa_type_v2::SUMMARY_NETWORK,
            LsaBody::Summary(SummaryLsa {
                network_mask: ip4(u)?,
                metric: u.arbitrary()?,
                tos: list(u, 8, |u| Ok((u.arbitrary()?, u.arbitrary()?)))?,
            }),
        ),
        (Version::V2, 3) => (
            lsa_type_v2::AS_EXTERNAL,
            LsaBody::AsExternal(AsExternalLsa {
                network_mask: ip4(u)?,
                routes: list(u, 4, |u| {
                    Ok(ExternalRoute {
                        type2: u.arbitrary()?,
                        tos: u.arbitrary()?,
                        metric: u.arbitrary()?,
                        forwarding_address: ip4(u)?,
                        route_tag: u.arbitrary()?,
                    })
                })?,
            }),
        ),
        (Version::V3, 0) => (
            lsa_type_v3::ROUTER,
            LsaBody::RouterV3(RouterLsaV3 {
                flags: u.arbitrary()?,
                options: u.arbitrary()?,
                interfaces: list(u, 8, |u| {
                    Ok(RouterInterface {
                        kind: u.arbitrary()?,
                        metric: u.arbitrary()?,
                        interface_id: u.arbitrary()?,
                        neighbor_interface_id: u.arbitrary()?,
                        neighbor_router_id: ip4(u)?,
                    })
                })?,
            }),
        ),
        (Version::V3, 1) => (
            lsa_type_v3::NETWORK,
            LsaBody::NetworkV3(NetworkLsaV3 { options: u.arbitrary()?, attached_routers: list(u, 20, ip4)? }),
        ),
        (Version::V3, 2) => (
            lsa_type_v3::INTER_AREA_PREFIX,
            LsaBody::InterAreaPrefix(InterAreaPrefixLsa { metric: u.arbitrary()?, prefix: prefix(u)? }),
        ),
        (Version::V3, 3) => (
            lsa_type_v3::INTER_AREA_ROUTER,
            LsaBody::InterAreaRouter(InterAreaRouterLsa {
                options: u.arbitrary()?,
                metric: u.arbitrary()?,
                destination: ip4(u)?,
            }),
        ),
        (Version::V3, 4) => (
            lsa_type_v3::AS_EXTERNAL,
            LsaBody::AsExternalV3(AsExternalLsaV3 {
                type2: u.arbitrary()?,
                metric: u.arbitrary()?,
                prefix: prefix(u)?,
                forwarding_address: if u.arbitrary()? { Some(ip6(u)?) } else { None },
                route_tag: u.arbitrary()?,
                referenced: if u.arbitrary()? { Some((u.arbitrary()?, ip4(u)?)) } else { None },
            }),
        ),
        (Version::V3, 5) => {
            if u.arbitrary()? {
                (
                    lsa_type_v3::LINK,
                    LsaBody::Link(LinkLsa {
                        priority: u.arbitrary()?,
                        options: u.arbitrary()?,
                        link_local_address: ip6(u)?,
                        prefixes: list(u, 8, prefix)?,
                    }),
                )
            } else {
                (
                    lsa_type_v3::INTRA_AREA_PREFIX,
                    LsaBody::IntraAreaPrefix(IntraAreaPrefixLsa {
                        referenced_ls_type: u.arbitrary()?,
                        referenced_link_state_id: ip4(u)?,
                        referenced_advertising_router: ip4(u)?,
                        prefixes: list(u, 8, |u| Ok((prefix(u)?, u.arbitrary()?)))?,
                    }),
                )
            }
        }
        _ => {
            let n = u.int_in_range(0..=64usize)?;
            (any, LsaBody::Other(u.bytes(n)?.to_vec()))
        }
    };
    Ok((if u.ratio(1, 8)? { any } else { fit }, body))
}

fn lsa(u: &mut Unstructured, v: Version) -> Result<Lsa> {
    let (ls_type, body) = lsa_body(u, v)?;
    Ok(Lsa {
        age: u.arbitrary()?,
        options: if v == Version::V2 || u.ratio(1, 8)? { u.arbitrary()? } else { 0 },
        ls_type,
        link_state_id: ip4(u)?,
        advertising_router: ip4(u)?,
        sequence: u.arbitrary()?,
        body,
    })
}

fn lsa_header(u: &mut Unstructured) -> Result<LsaHeader> {
    Ok(LsaHeader {
        age: u.arbitrary()?,
        options: u.arbitrary()?,
        ls_type: u.arbitrary()?,
        link_state_id: ip4(u)?,
        advertising_router: ip4(u)?,
        sequence: u.arbitrary()?,
        checksum: u.arbitrary()?,
        length: u.arbitrary()?,
    })
}

/// A packet built from fuzz bytes, valid or not.
fn packet(u: &mut Unstructured, v: Version) -> Result<Packet> {
    let mut body = match u.int_in_range(0..=5u8)? {
        0 => Body::HelloV2(HelloV2 {
            network_mask: ip4(u)?,
            hello_interval: u.arbitrary()?,
            options: u.arbitrary()?,
            priority: u.arbitrary()?,
            dead_interval: u.arbitrary()?,
            designated_router: ip4(u)?,
            backup_designated_router: ip4(u)?,
            neighbors: list(u, 20, ip4)?,
        }),
        1 => Body::HelloV3(HelloV3 {
            interface_id: u.arbitrary()?,
            priority: u.arbitrary()?,
            options: u.arbitrary()?,
            hello_interval: u.arbitrary()?,
            dead_interval: u.arbitrary()?,
            designated_router: ip4(u)?,
            backup_designated_router: ip4(u)?,
            neighbors: list(u, 20, ip4)?,
        }),
        2 => Body::DatabaseDescription(DatabaseDescription {
            mtu: u.arbitrary()?,
            options: u.arbitrary()?,
            flags: u.arbitrary()?,
            sequence: u.arbitrary()?,
            headers: list(u, 8, lsa_header)?,
        }),
        3 => Body::LinkStateRequest(list(u, 8, |u| {
            Ok(LsaKey { ls_type: u.arbitrary()?, link_state_id: ip4(u)?, advertising_router: ip4(u)? })
        })?),
        4 => Body::LinkStateUpdate(list(u, 4, |u| lsa(u, v))?),
        _ => Body::LinkStateAck(list(u, 8, lsa_header)?),
    };
    let header = match v {
        Version::V2 => Header::V2 {
            auth: match u.int_in_range(0..=3u8)? {
                0 => Auth::Null,
                1 => Auth::Simple(u.arbitrary()?),
                2 => {
                    let n = u.int_in_range(0..=300usize)?;
                    Auth::Cryptographic {
                        key_id: u.arbitrary()?,
                        sequence: u.arbitrary()?,
                        digest: u.bytes(n)?.to_vec(),
                    }
                }
                _ => Auth::Other { kind: u.arbitrary()?, data: u.arbitrary()? },
            },
        },
        Version::V3 => Header::V3 { instance_id: u.arbitrary()? },
    };
    // Sometimes a signaling block, usually with the L bit set to go with
    // it.
    let lls = if u.ratio(1, 4)? {
        if u.arbitrary()? {
            match &mut body {
                Body::HelloV2(h) => h.options |= OPTION_L_V2,
                Body::HelloV3(h) => h.options |= OPTION_L_V3,
                Body::DatabaseDescription(d) => {
                    d.options |= if v == Version::V2 { u32::from(OPTION_L_V2) } else { OPTION_L_V3 }
                }
                _ => {}
            }
        }
        let n = u.int_in_range(0..=64usize)?;
        Some(u.bytes(n)?.to_vec())
    } else {
        None
    };
    Ok(Packet { router_id: ip4(u)?, area_id: ip4(u)?, header, lls, body })
}

/// Values a world builds: whatever a writer accepts reads back the same.
fn built(data: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data);
    for e in &ends() {
        let v = if u.ratio(1, 8)? { Version::V2 } else { e.version() };
        let p = packet(&mut u, v)?;
        if let Ok(bytes) = p.frame(e).and_then(|frame| frame.to_bytes()) {
            assert!(bytes.len() <= MAX_MESSAGE);
            assert!(usize::from(u16::from_be_bytes([bytes[2], bytes[3]])) <= MAX_PACKET);
            assert_eq!(Packet::parse(&bytes, e).as_ref(), Ok(&p));
        }
        let l = lsa(&mut u, e.version())?;
        if let Ok(bytes) = l.frame(e.version()).and_then(|frame| frame.to_bytes()) {
            let n = bytes.len();
            assert_eq!(Lsa::parse(&bytes, e.version()), Ok((l, n)));
        }
    }
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    for e in &ends() {
        check(data, e);
        // The same bytes with the checksum set right, so the parser looks
        // past it.
        if let Some(c) = checksum(data, e) {
            let mut fixed = data.to_vec();
            fixed[12..14].copy_from_slice(&c.to_be_bytes());
            check(&fixed, e);
        }
    }
    // The bytes as one LSA, with its Fletcher checksum set right.
    let mut lsa = data.to_vec();
    if let Some(c) = lsa_checksum(&lsa) {
        lsa[16..18].copy_from_slice(&c.to_be_bytes());
    }
    for v in [Version::V2, Version::V3] {
        check_lsa(data, v);
        check_lsa(&lsa, v);
    }
    let _ = built(data);
});
