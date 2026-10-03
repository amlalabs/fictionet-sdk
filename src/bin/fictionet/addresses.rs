//! How `--type tap` hands a VM the addresses given as flags: a DHCP server
//! for IPv4, and router advertisements plus a DHCPv6 server for IPv6.
//!
//! These are small servers for one client on one link. Each always hands
//! out the same lease, so there is no lease table: a VM that asks again,
//! after a reboot or with a new client ID, gets the same answer.

use std::net::{Ipv4Addr, Ipv6Addr};

use fictionet::stdlib::dhcp::{self, opt};

use crate::args::Lease;
use crate::ether;

/// How long a lease lasts, in seconds, for both families. The VM renews
/// it halfway through, and attach answers the renewal with the same lease.
const LEASE_SECS: u32 = 86_400;

// DHCP for IPv4

/// The netmask of an IPv4 prefix length, 0 to 32.
pub(crate) fn mask4(prefix: u8) -> u32 {
    u32::MAX.checked_shl(32 - prefix.min(32) as u32).unwrap_or(0)
}

/// The address attach answers DHCP from, which the VM sends its renewals
/// to. It is the gateway when there is one. Otherwise it is the DNS
/// server, or else the subnet's first address that is not the VM's.
/// Attach answers ARP for any address, so this address only has to be
/// stable.
pub(crate) fn server_id(lease: &Lease<Ipv4Addr>) -> Ipv4Addr {
    if let Some(gw) = lease.gateway.or(lease.dns) {
        return gw;
    }
    let mask = mask4(lease.addr.prefix);
    let first = (u32::from(lease.addr.addr) & mask) + 1;
    let pick = if first == u32::from(lease.addr.addr) { first + 1 } else { first };
    Ipv4Addr::from(pick)
}

/// The answer to one DHCP message from the VM, as an IPv4 packet, and
/// whether it goes to the broadcast MAC. `None` when no answer is due: a
/// release, a decline, a request meant for another server, or a message
/// that is not a request.
pub(crate) fn dhcp4(lease: &Lease<Ipv4Addr>, mtu: u16, request: &[u8]) -> Option<(Vec<u8>, bool)> {
    let m = dhcp::Message::parse(request)?;
    if m.op != dhcp::BOOTREQUEST || m.htype != 1 || m.hlen != 6 {
        return None;
    }
    let server = server_id(lease);
    let addr = lease.addr.addr;
    let kind = match m.message_type()? {
        dhcp::DISCOVER => dhcp::OFFER,
        dhcp::REQUEST => {
            if m.option_addr(opt::SERVER_ID).is_some_and(|s| s != server) {
                // The VM chose another server's offer.
                return None;
            }
            let wanted = m.option_addr(opt::REQUESTED_IP).unwrap_or(m.ciaddr);
            if wanted == addr { dhcp::ACK } else { dhcp::NAK }
        }
        dhcp::INFORM => dhcp::INFORM,
        _ => return None,
    };
    let mut r = dhcp::Message::new(dhcp::BOOTREPLY, m.xid);
    r.flags = m.flags;
    r.giaddr = m.giaddr;
    r.chaddr = m.chaddr;
    if kind == dhcp::INFORM {
        r.ciaddr = m.ciaddr;
    } else if kind != dhcp::NAK {
        r.yiaddr = addr;
    }
    r.push(opt::MESSAGE_TYPE, [if kind == dhcp::INFORM { dhcp::ACK } else { kind }]);
    r.push(opt::SERVER_ID, server.octets());
    if kind != dhcp::NAK {
        if kind != dhcp::INFORM {
            r.push(opt::LEASE_TIME, LEASE_SECS.to_be_bytes());
            r.push(opt::RENEWAL_TIME, (LEASE_SECS / 2).to_be_bytes());
            r.push(opt::REBINDING_TIME, (LEASE_SECS / 8 * 7).to_be_bytes());
        }
        let mask = mask4(lease.addr.prefix);
        r.push(opt::SUBNET_MASK, mask.to_be_bytes());
        if let Some(gw) = lease.gateway {
            r.push(opt::ROUTER, gw.octets());
        }
        if let Some(dns) = lease.dns {
            r.push(opt::DNS, dns.octets());
        }
        r.push(INTERFACE_MTU, mtu.to_be_bytes());
    }
    // A VM that already has its address (a renewal, or INFORM) gets the
    // answer at that address. Every other answer is broadcast, which a
    // client with no address yet always receives.
    let unicast = kind != dhcp::NAK && !m.ciaddr.is_unspecified();
    let to = if unicast { m.ciaddr } else { Ipv4Addr::BROADCAST };
    Some((ether::udp4(server, dhcp::SERVER_PORT, to, dhcp::CLIENT_PORT, &r.to_bytes()), !unicast))
}

/// DHCP option 26: the interface MTU.
const INTERFACE_MTU: u8 = 26;

// Router advertisements

/// A router advertisement for the VM's link, as an IPv6 packet from
/// attach's link-local address to all nodes. It says:
///
/// - addresses come from DHCPv6 (the "managed" and "other" flags), so the
///   VM takes the one address attach hands out, not one of its own making;
/// - the subnet of `--ip-addr-v6` is on the link, so the VM reaches the
///   rest of that subnet directly;
/// - attach is the default router, unless `--no-gateway-v6` was given;
/// - the MTU, and the DNS server from `--dns-v6`, if there is one.
pub(crate) fn router_advert(lease: &Lease<Ipv6Addr>, mtu: u16) -> Vec<u8> {
    let lifetime: u16 = if lease.gateway.is_some() { 1800 } else { 0 };
    let mut b = vec![ether::ROUTER_ADVERTISEMENT, 0, 0, 0, 64, 0xc0];
    b.extend_from_slice(&lifetime.to_be_bytes());
    b.extend_from_slice(&[0; 8]);
    // Source link-layer address.
    b.extend_from_slice(&[1, 1]);
    b.extend_from_slice(&ether::GATEWAY_MAC);
    // MTU.
    b.extend_from_slice(&[5, 1, 0, 0]);
    b.extend_from_slice(&(mtu as u32).to_be_bytes());
    // Prefix information: on-link, but not for making addresses.
    let prefix = lease.addr.prefix;
    let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
    let net = Ipv6Addr::from(u128::from(lease.addr.addr) & mask);
    b.extend_from_slice(&[3, 4, prefix, 0x80]);
    b.extend_from_slice(&u32::MAX.to_be_bytes());
    b.extend_from_slice(&u32::MAX.to_be_bytes());
    b.extend_from_slice(&[0; 4]);
    b.extend_from_slice(&net.octets());
    if let Some(dns) = lease.dns {
        // Recursive DNS server (RFC 8106).
        b.extend_from_slice(&[25, 3, 0, 0]);
        b.extend_from_slice(&u32::MAX.to_be_bytes());
        b.extend_from_slice(&dns.octets());
    }
    ether::icmp6(ether::link_local(ether::GATEWAY_MAC), ALL_NODES, b)
}

const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

// DHCPv6

pub(crate) const DHCP6_SERVER_PORT: u16 = 547;
pub(crate) const DHCP6_CLIENT_PORT: u16 = 546;

mod msg6 {
    pub(super) const SOLICIT: u8 = 1;
    pub(super) const ADVERTISE: u8 = 2;
    pub(super) const REQUEST: u8 = 3;
    pub(super) const CONFIRM: u8 = 4;
    pub(super) const RENEW: u8 = 5;
    pub(super) const REBIND: u8 = 6;
    pub(super) const REPLY: u8 = 7;
    pub(super) const RELEASE: u8 = 8;
    pub(super) const DECLINE: u8 = 9;
    pub(super) const INFORMATION_REQUEST: u8 = 11;
}

mod opt6 {
    pub(super) const CLIENT_ID: u16 = 1;
    pub(super) const SERVER_ID: u16 = 2;
    pub(super) const IA_NA: u16 = 3;
    pub(super) const IAADDR: u16 = 5;
    pub(super) const STATUS_CODE: u16 = 13;
    pub(super) const RAPID_COMMIT: u16 = 14;
    pub(super) const DNS_SERVERS: u16 = 23;
}

/// The options of a DHCPv6 message. `None` if one runs past the end.
fn options6(mut b: &[u8]) -> Option<Vec<(u16, &[u8])>> {
    let mut out = Vec::new();
    while !b.is_empty() {
        if b.len() < 4 {
            return None;
        }
        let code = u16::from_be_bytes([b[0], b[1]]);
        let len = u16::from_be_bytes([b[2], b[3]]) as usize;
        let value = b.get(4..4 + len)?;
        out.push((code, value));
        b = &b[4 + len..];
    }
    Some(out)
}

fn push6(out: &mut Vec<u8>, code: u16, value: &[u8]) {
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}

/// Attach's DHCPv6 server ID: a DUID made from its MAC (DUID-LL).
fn server_duid() -> [u8; 10] {
    let mut d = [0, 3, 0, 1, 0, 0, 0, 0, 0, 0];
    d[4..].copy_from_slice(&ether::GATEWAY_MAC);
    d
}

/// The answer to one DHCPv6 message from the VM, as the UDP payload.
/// `None` when no answer is due: a message for another server, one with no
/// client ID, or a type a server does not answer.
pub(crate) fn dhcp6(lease: &Lease<Ipv6Addr>, request: &[u8]) -> Option<Vec<u8>> {
    if request.len() < 4 {
        return None;
    }
    let kind = request[0];
    let options = options6(&request[4..])?;
    let find = |code| options.iter().find(|(c, _)| *c == code).map(|(_, v)| *v);
    let client = find(opt6::CLIENT_ID);
    if client.is_none() && kind != msg6::INFORMATION_REQUEST {
        return None;
    }
    // A DUID is at most 130 bytes (RFC 8415). The answer copies it, so a
    // longer one is refused rather than let the answer grow.
    if client.is_some_and(|c| c.len() > MAX_DUID) {
        return None;
    }
    if find(opt6::SERVER_ID).is_some_and(|s| s != server_duid()) {
        return None;
    }
    let rapid = kind == msg6::SOLICIT && find(opt6::RAPID_COMMIT).is_some();
    let (reply, lease_it, status) = match kind {
        msg6::SOLICIT if rapid => (msg6::REPLY, true, false),
        msg6::SOLICIT => (msg6::ADVERTISE, true, false),
        msg6::REQUEST | msg6::RENEW | msg6::REBIND => (msg6::REPLY, true, false),
        msg6::CONFIRM => return confirm(lease, request, client?, &options),
        msg6::RELEASE | msg6::DECLINE => (msg6::REPLY, false, true),
        msg6::INFORMATION_REQUEST => (msg6::REPLY, false, false),
        _ => return None,
    };
    let mut out = vec![reply, request[1], request[2], request[3]];
    if let Some(c) = client {
        push6(&mut out, opt6::CLIENT_ID, c);
    }
    push6(&mut out, opt6::SERVER_ID, &server_duid());
    if rapid {
        push6(&mut out, opt6::RAPID_COMMIT, &[]);
    }
    if status {
        // Success.
        push6(&mut out, opt6::STATUS_CODE, &[0, 0]);
    }
    let iaaddr = |addr: Ipv6Addr, secs: u32| {
        let mut a = Vec::with_capacity(24);
        a.extend_from_slice(&addr.octets());
        a.extend_from_slice(&secs.to_be_bytes());
        a.extend_from_slice(&secs.to_be_bytes());
        a
    };
    // Any other address the VM still holds, from a lease it kept across a
    // restore or a change of flags, comes back with lifetimes of 0 in a
    // Request, Renew or Rebind, so the VM drops it (RFC 8415, section
    // 18.3.4). Attach passes packets only from the address it hands out.
    // An answer to the agent's own VM may grow with its request; it harms
    // no one else.
    let retire = matches!(kind, msg6::REQUEST | msg6::RENEW | msg6::REBIND);
    let ias = options.iter().filter(|(c, v)| *c == opt6::IA_NA && v.len() >= 12).map(|(_, v)| *v);
    for (i, ia) in ias.enumerate() {
        // The first IA_NA the VM asked for gets the address.
        let first = i == 0 && lease_it;
        if !first && !retire {
            continue;
        }
        let stale: Vec<Ipv6Addr> = if retire {
            ia_addresses(ia).into_iter().filter(|a| *a != lease.addr.addr).collect()
        } else {
            Vec::new()
        };
        if !first && stale.is_empty() {
            continue;
        }
        let mut na = Vec::with_capacity(40);
        na.extend_from_slice(&ia[0..4]);
        let (t1, t2) = if first { (LEASE_SECS / 2, LEASE_SECS / 5 * 4) } else { (0, 0) };
        na.extend_from_slice(&t1.to_be_bytes());
        na.extend_from_slice(&t2.to_be_bytes());
        if first {
            push6(&mut na, opt6::IAADDR, &iaaddr(lease.addr.addr, LEASE_SECS));
        }
        for other in stale {
            push6(&mut na, opt6::IAADDR, &iaaddr(other, 0));
        }
        push6(&mut out, opt6::IA_NA, &na);
    }
    if let (Some(dns), false) = (lease.dns, matches!(kind, msg6::RELEASE | msg6::DECLINE)) {
        push6(&mut out, opt6::DNS_SERVERS, &dns.octets());
    }
    Some(out)
}

/// The longest DUID a client may send.
const MAX_DUID: usize = 130;

/// The addresses in one IA_NA option's value.
fn ia_addresses(ia: &[u8]) -> Vec<Ipv6Addr> {
    let Some(options) = ia.get(12..).and_then(options6) else { return Vec::new() };
    options
        .iter()
        .filter(|(code, v)| *code == opt6::IAADDR && v.len() >= 24)
        .map(|(_, v)| Ipv6Addr::from(<[u8; 16]>::try_from(&v[..16]).unwrap()))
        .collect()
}

/// The answer to a Confirm: is the VM's address still right for this link?
/// Success if every address in its IA_NAs is the one `--ip-addr-v6` gives,
/// NotOnLink if one is not, and no answer if it names no address (RFC
/// 8415, section 18.3.3). Attach passes packets only from that one
/// address, so an address it did not hand out is not usable on this link,
/// even inside the prefix. NotOnLink sends the VM back to Solicit, which
/// gets it the right one.
fn confirm(lease: &Lease<Ipv6Addr>, request: &[u8], client: &[u8], options: &[(u16, &[u8])]) -> Option<Vec<u8>> {
    let mut addrs = Vec::new();
    for (_, ia) in options.iter().filter(|(c, v)| *c == opt6::IA_NA && v.len() >= 12) {
        options6(&ia[12..])?;
        addrs.extend(ia_addresses(ia));
    }
    if addrs.is_empty() {
        return None;
    }
    let on_link = addrs.iter().all(|a| *a == lease.addr.addr);
    let mut out = vec![msg6::REPLY, request[1], request[2], request[3]];
    push6(&mut out, opt6::CLIENT_ID, client);
    push6(&mut out, opt6::SERVER_ID, &server_duid());
    // Success, or NotOnLink.
    push6(&mut out, opt6::STATUS_CODE, if on_link { &[0, 0] } else { &[0, 4] });
    Some(out)
}

/// The DHCPv6 answer as a packet: from attach's link-local address to the
/// VM's, which sent `request_packet`.
pub(crate) fn dhcp6_packet(request_packet: &[u8], answer: &[u8]) -> Vec<u8> {
    let to = ether::source_v6(request_packet);
    ether::udp6(ether::link_local(ether::GATEWAY_MAC), DHCP6_SERVER_PORT, to, DHCP6_CLIENT_PORT, answer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::Cidr;
    use crate::ether::tests::{VM, v6_checksum_ok};

    fn lease4() -> Lease<Ipv4Addr> {
        Lease {
            addr: Cidr { addr: Ipv4Addr::new(10, 0, 0, 2), prefix: 24 },
            gateway: Some(Ipv4Addr::new(10, 0, 0, 1)),
            dns: Some(Ipv4Addr::new(10, 0, 0, 1)),
        }
    }

    fn client(kind: u8) -> dhcp::Message {
        let mut m = dhcp::Message::new(dhcp::BOOTREQUEST, 0x1234_5678);
        m.chaddr[..6].copy_from_slice(&VM);
        m.push(opt::MESSAGE_TYPE, [kind]);
        m
    }

    /// The DHCP message in an answer packet, and the packet's destination.
    fn answer(packet: &[u8]) -> (dhcp::Message, Ipv4Addr) {
        let (port, payload) = ether::udp_to(packet).unwrap();
        assert_eq!(port, dhcp::CLIENT_PORT);
        assert_eq!(&packet[12..16], &[10, 0, 0, 1], "from the server ID");
        (dhcp::Message::parse(payload).unwrap(), Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]))
    }

    #[test]
    fn discover_request_ack() {
        let (offer, broadcast) = dhcp4(&lease4(), 1500, &client(dhcp::DISCOVER).to_bytes()).unwrap();
        assert!(broadcast);
        let (m, to) = answer(&offer);
        assert_eq!(to, Ipv4Addr::BROADCAST);
        assert_eq!(m.op, dhcp::BOOTREPLY);
        assert_eq!(m.xid, 0x1234_5678);
        assert_eq!(&m.chaddr[..6], &VM);
        assert_eq!(m.message_type(), Some(dhcp::OFFER));
        assert_eq!(m.yiaddr, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(m.option_addr(opt::SUBNET_MASK), Some(Ipv4Addr::new(255, 255, 255, 0)));
        assert_eq!(m.option_addr(opt::ROUTER), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(m.option_addr(opt::DNS), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(m.option_addr(opt::SERVER_ID), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(m.option_u32(opt::LEASE_TIME), Some(86_400));
        assert_eq!(m.option(INTERFACE_MTU), Some(&[5, 220][..]));

        let mut req = client(dhcp::REQUEST);
        req.push(opt::REQUESTED_IP, [10, 0, 0, 2]);
        req.push(opt::SERVER_ID, [10, 0, 0, 1]);
        let (ack, _) = dhcp4(&lease4(), 1500, &req.to_bytes()).unwrap();
        assert_eq!(answer(&ack).0.message_type(), Some(dhcp::ACK));

        // A renewal comes from the address, and the answer goes back to it.
        let mut renew = client(dhcp::REQUEST);
        renew.ciaddr = Ipv4Addr::new(10, 0, 0, 2);
        let (ack, broadcast) = dhcp4(&lease4(), 1500, &renew.to_bytes()).unwrap();
        assert!(!broadcast);
        let (m, to) = answer(&ack);
        assert_eq!((m.message_type(), to), (Some(dhcp::ACK), Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn wrong_address_is_nakked_and_other_servers_are_left_alone() {
        let mut req = client(dhcp::REQUEST);
        req.push(opt::REQUESTED_IP, [10, 0, 0, 9]);
        let (nak, broadcast) = dhcp4(&lease4(), 1500, &req.to_bytes()).unwrap();
        assert!(broadcast);
        let (m, _) = answer(&nak);
        assert_eq!(m.message_type(), Some(dhcp::NAK));
        assert_eq!(m.yiaddr, Ipv4Addr::UNSPECIFIED);
        assert_eq!(m.option(opt::ROUTER), None);

        let mut other = client(dhcp::REQUEST);
        other.push(opt::REQUESTED_IP, [10, 0, 0, 2]);
        other.push(opt::SERVER_ID, [10, 0, 0, 254]);
        assert!(dhcp4(&lease4(), 1500, &other.to_bytes()).is_none());
        for kind in [dhcp::RELEASE, dhcp::DECLINE, dhcp::OFFER] {
            assert!(dhcp4(&lease4(), 1500, &client(kind).to_bytes()).is_none(), "{kind}");
        }
        let mut reply = client(dhcp::DISCOVER);
        reply.op = dhcp::BOOTREPLY;
        assert!(dhcp4(&lease4(), 1500, &reply.to_bytes()).is_none());
        assert!(dhcp4(&lease4(), 1500, &[0; 100]).is_none());
        assert!(dhcp4(&lease4(), 1500, &client(dhcp::DISCOVER).to_bytes()[..239]).is_none());
    }

    #[test]
    fn inform_and_turned_off_settings() {
        let mut inform = client(dhcp::INFORM);
        inform.ciaddr = Ipv4Addr::new(10, 0, 0, 2);
        let (ack, _) = dhcp4(&lease4(), 9000, &inform.to_bytes()).unwrap();
        let (m, _) = answer(&ack);
        assert_eq!(m.message_type(), Some(dhcp::ACK));
        assert_eq!(m.yiaddr, Ipv4Addr::UNSPECIFIED);
        assert_eq!(m.option(opt::LEASE_TIME), None);
        assert_eq!(m.option(INTERFACE_MTU), Some(&9000u16.to_be_bytes()[..]));

        let bare = Lease { gateway: None, dns: None, ..lease4() };
        assert_eq!(server_id(&bare), Ipv4Addr::new(10, 0, 0, 1));
        let (offer, _) = dhcp4(&bare, 1500, &client(dhcp::DISCOVER).to_bytes()).unwrap();
        let (_, payload) = ether::udp_to(&offer).unwrap();
        let m = dhcp::Message::parse(payload).unwrap();
        assert_eq!(m.option(opt::ROUTER), None);
        assert_eq!(m.option(opt::DNS), None);
        let at_first = Lease { addr: Cidr { addr: Ipv4Addr::new(10, 0, 0, 1), prefix: 24 }, ..bare };
        assert_eq!(server_id(&at_first), Ipv4Addr::new(10, 0, 0, 2));
    }

    fn lease6() -> Lease<Ipv6Addr> {
        Lease {
            addr: Cidr { addr: "fd00::2".parse().unwrap(), prefix: 64 },
            gateway: Some("fd00::1".parse().unwrap()),
            dns: Some("fd00::53".parse().unwrap()),
        }
    }

    #[test]
    fn router_advert_says_managed_on_link_and_dns() {
        let p = router_advert(&lease6(), 1500);
        assert!(v6_checksum_ok(&p));
        assert_eq!(p[7], 255);
        assert_eq!(ether::source_v6(&p), ether::link_local(ether::GATEWAY_MAC));
        assert_eq!(&p[24..40], &ALL_NODES.octets());
        let ra = &p[40..];
        assert_eq!(ra[0], ether::ROUTER_ADVERTISEMENT);
        assert_eq!(ra[5], 0xc0, "managed and other");
        assert_eq!(u16::from_be_bytes([ra[6], ra[7]]), 1800);
        let opts = &ra[16..];
        assert_eq!(&opts[0..8], &[1, 1, 0x02, 0x66, 0x6e, 0, 0, 1]);
        assert_eq!(&opts[8..16], &[5, 1, 0, 0, 0, 0, 5, 220]);
        assert_eq!(&opts[16..20], &[3, 4, 64, 0x80], "on-link, no autoconfiguration");
        assert_eq!(&opts[32..48], &"fd00::".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(&opts[48..52], &[25, 3, 0, 0]);
        assert_eq!(&opts[56..72], &"fd00::53".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(opts.len(), 72);

        let p = router_advert(&Lease { gateway: None, dns: None, ..lease6() }, 1500);
        assert_eq!(u16::from_be_bytes([p[46], p[47]]), 0, "not a default router");
        assert_eq!(p.len(), 40 + 16 + 48, "no DNS option");
    }

    fn msg6(kind: u8, options: &[(u16, &[u8])]) -> Vec<u8> {
        let mut m = vec![kind, 0xab, 0xcd, 0xef];
        for (c, v) in options {
            push6(&mut m, *c, v);
        }
        m
    }

    const CLIENT: &[u8] = &[0, 3, 0, 1, 0x52, 0x54, 0, 0x12, 0x34, 0x56];
    const IA: &[u8] = &[0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0];

    #[test]
    fn dhcp6_solicit_advertise_request_reply() {
        let adv = dhcp6(&lease6(), &msg6(msg6::SOLICIT, &[(opt6::CLIENT_ID, CLIENT), (opt6::IA_NA, IA)])).unwrap();
        assert_eq!(&adv[..4], &[msg6::ADVERTISE, 0xab, 0xcd, 0xef]);
        let opts = options6(&adv[4..]).unwrap();
        let get = |code| opts.iter().find(|(c, _)| *c == code).map(|(_, v)| *v);
        assert_eq!(get(opt6::CLIENT_ID), Some(CLIENT));
        assert_eq!(get(opt6::SERVER_ID), Some(&server_duid()[..]));
        assert_eq!(get(opt6::DNS_SERVERS), Some(&"fd00::53".parse::<Ipv6Addr>().unwrap().octets()[..]));
        let na = get(opt6::IA_NA).unwrap();
        assert_eq!(&na[..4], &[0, 0, 0, 7], "the client's IAID");
        let inner = options6(&na[12..]).unwrap();
        assert_eq!(inner[0].0, opt6::IAADDR);
        assert_eq!(&inner[0].1[..16], &"fd00::2".parse::<Ipv6Addr>().unwrap().octets());

        let reply = dhcp6(
            &lease6(),
            &msg6(msg6::REQUEST, &[(opt6::CLIENT_ID, CLIENT), (opt6::SERVER_ID, &server_duid()), (opt6::IA_NA, IA)]),
        )
        .unwrap();
        assert_eq!(reply[0], msg6::REPLY);
        assert!(options6(&reply[4..]).unwrap().iter().any(|(c, _)| *c == opt6::IA_NA));

        // Rapid commit: the solicit gets a reply at once.
        let rapid = dhcp6(
            &lease6(),
            &msg6(msg6::SOLICIT, &[(opt6::CLIENT_ID, CLIENT), (opt6::IA_NA, IA), (opt6::RAPID_COMMIT, &[])]),
        )
        .unwrap();
        assert_eq!(rapid[0], msg6::REPLY);
        assert!(options6(&rapid[4..]).unwrap().iter().any(|(c, _)| *c == opt6::RAPID_COMMIT));
    }

    #[test]
    fn dhcp6_leaves_other_servers_and_bad_messages_alone() {
        let other = [0, 3, 0, 1, 1, 2, 3, 4, 5, 6];
        let m = msg6(msg6::REQUEST, &[(opt6::CLIENT_ID, CLIENT), (opt6::SERVER_ID, &other), (opt6::IA_NA, IA)]);
        assert!(dhcp6(&lease6(), &m).is_none());
        assert!(dhcp6(&lease6(), &msg6(msg6::SOLICIT, &[(opt6::IA_NA, IA)])).is_none(), "no client ID");
        assert!(dhcp6(&lease6(), &msg6(msg6::ADVERTISE, &[(opt6::CLIENT_ID, CLIENT)])).is_none());
        let mut cut = msg6(msg6::SOLICIT, &[(opt6::CLIENT_ID, CLIENT)]);
        cut.pop();
        assert!(dhcp6(&lease6(), &cut).is_none(), "an option past the end");
        assert!(dhcp6(&lease6(), &[1, 2]).is_none());
        // A release gets a plain success, and no address or DNS.
        let r = dhcp6(&lease6(), &msg6(msg6::RELEASE, &[(opt6::CLIENT_ID, CLIENT), (opt6::IA_NA, IA)])).unwrap();
        let opts = options6(&r[4..]).unwrap();
        assert!(opts.iter().any(|(c, v)| *c == opt6::STATUS_CODE && *v == [0, 0]));
        assert!(!opts.iter().any(|(c, _)| *c == opt6::IA_NA || *c == opt6::DNS_SERVERS));
        // Information-request needs no client ID.
        let r = dhcp6(&lease6(), &msg6(msg6::INFORMATION_REQUEST, &[])).unwrap();
        assert!(options6(&r[4..]).unwrap().iter().any(|(c, _)| *c == opt6::DNS_SERVERS));
    }

    fn ia_with(addr: &str) -> Vec<u8> {
        let mut a: Vec<u8> = addr.parse::<Ipv6Addr>().unwrap().octets().to_vec();
        a.extend_from_slice(&[0; 8]);
        let mut ia = IA.to_vec();
        push6(&mut ia, opt6::IAADDR, &a);
        ia
    }

    #[test]
    fn dhcp6_confirm_checks_the_address() {
        let status = |r: &[u8]| {
            let opts = options6(&r[4..]).unwrap();
            opts.iter().find(|(c, _)| *c == opt6::STATUS_CODE).map(|(_, v)| v.to_vec())
        };
        let ok = dhcp6(&lease6(), &msg6(msg6::CONFIRM, &[(opt6::CLIENT_ID, CLIENT), (opt6::IA_NA, &ia_with("fd00::2"))]));
        assert_eq!(status(&ok.unwrap()), Some(vec![0, 0]));
        let off = dhcp6(&lease6(), &msg6(msg6::CONFIRM, &[(opt6::CLIENT_ID, CLIENT), (opt6::IA_NA, &ia_with("2001:db8:99::2"))]));
        assert_eq!(status(&off.unwrap()), Some(vec![0, 4]), "NotOnLink");
        assert!(dhcp6(&lease6(), &msg6(msg6::CONFIRM, &[(opt6::CLIENT_ID, CLIENT), (opt6::IA_NA, IA)])).is_none());
        // A cached lease inside the prefix, but not the address attach hands
        // out and lets through: NotOnLink, so the VM asks again.
        let cached = dhcp6(&lease6(), &msg6(msg6::CONFIRM, &[(opt6::CLIENT_ID, CLIENT), (opt6::IA_NA, &ia_with("fd00::77"))]));
        assert_eq!(status(&cached.unwrap()), Some(vec![0, 4]), "NotOnLink");
    }

    #[test]
    fn dhcp6_renew_and_rebind_retire_an_address_attach_did_not_hand_out() {
        for kind in [msg6::RENEW, msg6::REBIND, msg6::REQUEST] {
            let mut options: Vec<(u16, &[u8])> = vec![(opt6::CLIENT_ID, CLIENT)];
            let ia = ia_with("fd00::77");
            options.push((opt6::IA_NA, &ia));
            let r = dhcp6(&lease6(), &msg6(kind, &options)).unwrap();
            let opts = options6(&r[4..]).unwrap();
            let na = opts.iter().find(|(c, _)| *c == opt6::IA_NA).unwrap().1;
            let addrs: Vec<(Ipv6Addr, u32, u32)> = options6(&na[12..])
                .unwrap()
                .iter()
                .filter(|(c, _)| *c == opt6::IAADDR)
                .map(|(_, v)| {
                    let secs = |i: usize| u32::from_be_bytes(v[i..i + 4].try_into().unwrap());
                    (Ipv6Addr::from(<[u8; 16]>::try_from(&v[..16]).unwrap()), secs(16), secs(20))
                })
                .collect();
            assert_eq!(
                addrs,
                vec![("fd00::2".parse().unwrap(), LEASE_SECS, LEASE_SECS), ("fd00::77".parse().unwrap(), 0, 0)],
                "{kind}"
            );
        }
        // Every stale address, in every IA_NA, however many.
        let many: Vec<Vec<u8>> = (3..15).map(|i| ia_with(&format!("fd00::{i:x}"))).collect();
        let mut options: Vec<(u16, &[u8])> = vec![(opt6::CLIENT_ID, CLIENT)];
        let mut second = ia_with("fd00::99");
        second[3] = 8;
        let mut first = IA.to_vec();
        for ia in &many {
            first.extend_from_slice(&ia[12..]);
        }
        options.push((opt6::IA_NA, &first));
        options.push((opt6::IA_NA, &second));
        let r = dhcp6(&lease6(), &msg6(msg6::RENEW, &options)).unwrap();
        let opts = options6(&r[4..]).unwrap();
        let nas: Vec<&[u8]> = opts.iter().filter(|(c, _)| *c == opt6::IA_NA).map(|(_, v)| *v).collect();
        assert_eq!(nas.len(), 2);
        assert_eq!(options6(&nas[0][12..]).unwrap().len(), 1 + 12);
        assert_eq!(&nas[1][..12], &[0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0]);
        let inner = options6(&nas[1][12..]).unwrap();
        assert_eq!(inner.len(), 1);
        assert_eq!(&inner[0].1[..16], &"fd00::99".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(&inner[0].1[16..24], &[0; 8]);
        // A Solicit names no stale address.
        let s = dhcp6(&lease6(), &msg6(msg6::SOLICIT, &[(opt6::CLIENT_ID, CLIENT), (opt6::IA_NA, &first)])).unwrap();
        let opts = options6(&s[4..]).unwrap();
        let na = opts.iter().find(|(c, _)| *c == opt6::IA_NA).unwrap().1;
        assert_eq!(options6(&na[12..]).unwrap().len(), 1);
        // The address attach hands out is not named twice.
        let ia = ia_with("fd00::2");
        let r = dhcp6(&lease6(), &msg6(msg6::RENEW, &[(opt6::CLIENT_ID, CLIENT), (opt6::IA_NA, &ia)])).unwrap();
        let opts = options6(&r[4..]).unwrap();
        let na = opts.iter().find(|(c, _)| *c == opt6::IA_NA).unwrap().1;
        assert_eq!(options6(&na[12..]).unwrap().len(), 1);
    }

    #[test]
    fn dhcp6_refuses_an_oversized_client_id() {
        let long = vec![7u8; MAX_DUID + 1];
        assert!(dhcp6(&lease6(), &msg6(msg6::SOLICIT, &[(opt6::CLIENT_ID, &long), (opt6::IA_NA, IA)])).is_none());
        let max = vec![7u8; MAX_DUID];
        let r = dhcp6(&lease6(), &msg6(msg6::SOLICIT, &[(opt6::CLIENT_ID, &max), (opt6::IA_NA, IA)])).unwrap();
        assert!(r.len() < 300);
    }

    #[test]
    fn masks() {
        assert_eq!(mask4(0), 0);
        assert_eq!(mask4(24), 0xffff_ff00);
        assert_eq!(mask4(32), u32::MAX);
    }

    #[test]
    fn dhcp6_answer_goes_to_the_asker() {
        let vm_ll = ether::link_local(VM);
        let req = ether::udp6(vm_ll, 546, "ff02::1:2".parse().unwrap(), 547, b"x");
        let p = dhcp6_packet(&req, b"answer");
        assert!(v6_checksum_ok(&p));
        assert_eq!(&p[24..40], &vm_ll.octets());
        assert_eq!(ether::udp_to(&p), Some((DHCP6_CLIENT_PORT, &b"answer"[..])));
    }
}
