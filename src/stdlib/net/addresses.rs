use super::udp_packet;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::dhcp::{self, opt};
use fictionet::stdlib::route::Prefix;
use fictionet::sync::Mutex;
use fictionet::{Error, Packet};
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

/// How long a DHCP lease lasts. The binding itself lasts until the sandbox
/// detaches; the lease time only tells the client when to renew.
const LEASE: u32 = 3600;

/// Where hosts without an IPv4 [`super::Host::at`] get their addresses:
/// `198.18.0.0/15`.
pub(super) const AUTO: Prefix = Prefix {
    addr: IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)),
    len: 15,
};

/// Where hosts without an IPv6 [`super::Host::at`] get theirs: `2001:2::/48`,
/// the IPv6 range set aside for benchmarking (RFC 5180).
pub(super) const AUTO6: Prefix = Prefix {
    addr: IpAddr::V6(Ipv6Addr::new(0x2001, 2, 0, 0, 0, 0, 0, 0)),
    len: 48,
};

/// The sandboxes' subnet.
#[derive(Clone, Copy, Debug)]
pub(super) struct Subnet {
    pub(super) prefix: Prefix,
    pub(super) gateway: Ipv4Addr,
}

impl Subnet {
    pub(super) fn new(p: Prefix) -> Result<Subnet, Error> {
        let IpAddr::V4(a) = p.addr else {
            return Err(fictionet::Error::msg(format!(
                "the sandboxes' subnet {}/{} must be IPv4",
                p.addr, p.len
            )));
        };
        if !(8..=30).contains(&p.len) {
            return Err(fictionet::Error::msg(format!(
                "the sandboxes' subnet {a}/{} must have a length from 8 to 30",
                p.len
            )));
        }
        let IpAddr::V4(gateway) = p.nth(1).expect("a sandbox subnet has a gateway") else {
            unreachable!("an IPv4 subnet has an IPv4 gateway")
        };
        Ok(Subnet {
            prefix: p.canonical(),
            gateway,
        })
    }

    pub(super) fn contains(&self, a: Ipv4Addr) -> bool {
        self.prefix.contains(a.into())
    }

    fn broadcast(&self) -> Ipv4Addr {
        self.prefix
            .broadcast()
            .expect("an IPv4 sandbox subnet has a broadcast")
    }

    fn is_sandbox(&self, a: Ipv4Addr) -> bool {
        self.contains(a)
            && IpAddr::V4(a) != self.prefix.network()
            && a != self.broadcast()
            && a != self.gateway
    }

    fn sandboxes(&self) -> impl Iterator<Item = Ipv4Addr> {
        (u32::from(self.gateway) + 1..u32::from(self.broadcast())).map(Ipv4Addr::from)
    }

    fn mask(&self) -> Ipv4Addr {
        let IpAddr::V4(mask) = self.prefix.mask() else {
            unreachable!("an IPv4 subnet has an IPv4 mask")
        };
        mask
    }
}

/// The sandboxes' IPv6 subnet.
#[derive(Clone, Copy, Debug)]
pub(super) struct Subnet6 {
    pub(super) prefix: Prefix,
    pub(super) gateway: Ipv6Addr,
}

impl Subnet6 {
    pub(super) fn new(p: Prefix) -> Result<Subnet6, Error> {
        let IpAddr::V6(a) = p.addr else {
            return Err(fictionet::Error::msg(format!(
                "the sandboxes' IPv6 subnet {}/{} must be IPv6",
                p.addr, p.len
            )));
        };
        if !(8..=126).contains(&p.len) {
            return Err(fictionet::Error::msg(format!(
                "the sandboxes' IPv6 subnet {a}/{} must have a length from 8 to 126",
                p.len
            )));
        }
        let IpAddr::V6(network) = p.network() else {
            unreachable!("an IPv6 subnet has an IPv6 network address")
        };
        let net = u128::from(network);
        let global = net >> 125 == 0b001;
        let ula = net >> 121 == 0b111_1110;
        if !(global || ula) {
            return Err(fictionet::Error::msg(format!(
                "the sandboxes' IPv6 subnet {a}/{} must lie inside 2000::/3 or fc00::/7",
                p.len
            )));
        }
        let IpAddr::V6(gateway) = p.nth(1).expect("a sandbox subnet has a gateway") else {
            unreachable!("an IPv6 subnet has an IPv6 gateway")
        };
        Ok(Subnet6 {
            prefix: p.canonical(),
            gateway,
        })
    }

    pub(super) fn contains(&self, a: Ipv6Addr) -> bool {
        self.prefix.contains(a.into())
    }

    fn is_sandbox(&self, a: Ipv6Addr) -> bool {
        self.contains(a) && IpAddr::V6(a) != self.prefix.network() && a != self.gateway
    }
}

/// A host's addresses. A name with a host has at least one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Placed {
    pub(super) v4: Option<Ipv4Addr>,
    pub(super) v6: Option<Ipv6Addr>,
}

pub(super) fn may_serve_v4(a: Ipv4Addr, subnet: &Subnet) -> bool {
    !(subnet.contains(a)
        || a.is_unspecified()
        || a.is_broadcast()
        || a.is_multicast()
        || a.is_loopback())
}

pub(super) fn may_serve_v6(a: Ipv6Addr, subnet: &Subnet6) -> bool {
    !(subnet.contains(a)
        || a.is_unspecified()
        || a.is_loopback()
        || a.is_multicast()
        || a.is_unicast_link_local()
        || a.to_ipv4_mapped().is_some())
}

/// Automatic host address cursors. Occupied addresses come from installation.
pub(super) struct Allocator {
    pub(super) next_auto: u32,
    pub(super) next_auto6: u128,
    pub(super) auto_full: bool,
}

impl Default for Allocator {
    fn default() -> Self {
        Self {
            next_auto: 1,
            next_auto6: 1,
            auto_full: false,
        }
    }
}

impl Allocator {
    pub(super) fn free_auto<T>(
        &mut self,
        subnet: &Subnet,
        occupied: &BTreeMap<IpAddr, T>,
    ) -> Option<Ipv4Addr> {
        if self.auto_full {
            return None;
        }
        let size = u32::try_from(AUTO.size().expect("the IPv4 pool has a finite size"))
            .expect("the IPv4 pool size fits in u32");
        for _ in 0..size {
            let n = self.next_auto;
            self.next_auto = (self.next_auto + 1) % size;
            if n == 0 || n == size - 1 {
                continue;
            }
            let IpAddr::V4(a) = AUTO
                .nth(n.into())
                .expect("the cursor is inside the IPv4 pool")
            else {
                unreachable!("the IPv4 pool contains IPv4 addresses")
            };
            if !subnet.contains(a) && !occupied.contains_key(&a.into()) {
                return Some(a);
            }
        }
        self.auto_full = true;
        None
    }

    pub(super) fn free_auto6<T>(
        &mut self,
        subnet: &Subnet6,
        occupied: &BTreeMap<IpAddr, T>,
    ) -> Option<Ipv6Addr> {
        let size = AUTO6.size().expect("the IPv6 pool has a finite size");
        if subnet.prefix.len <= AUTO6.len && subnet.prefix.overlaps(AUTO6) {
            return None;
        }
        for _ in 0..occupied.len() + 4 {
            let n = self.next_auto6;
            self.next_auto6 = (self.next_auto6 + 1) % size;
            if n == 0 {
                continue;
            }
            let IpAddr::V6(a) = AUTO6.nth(n).expect("the cursor is inside the IPv6 pool") else {
                unreachable!("the IPv6 pool contains IPv6 addresses")
            };
            if subnet.contains(a) {
                let IpAddr::V6(last) = subnet.prefix.last() else {
                    unreachable!("an IPv6 subnet has an IPv6 last address")
                };
                self.next_auto6 = (n + (u128::from(last) - u128::from(a)) + 1) % size;
                continue;
            }
            if !occupied.contains_key(&a.into()) {
                return Some(a);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Address binding and DHCP

/// Which attachment holds which address.
#[derive(Default)]
pub(super) struct Leases {
    by_addr: HashMap<Ipv4Addr, (u64, bool)>,
    by_owner: HashMap<u64, Ipv4Addr>,
    by_addr6: HashMap<Ipv6Addr, u64>,
    by_owner6: HashMap<u64, Ipv6Addr>,
    next_owner: u64,
}

impl Leases {
    fn new_owner(&mut self) -> u64 {
        self.next_owner += 1;
        self.next_owner
    }

    fn of(&self, owner: u64) -> Option<(Ipv4Addr, bool)> {
        let a = *self.by_owner.get(&owner)?;
        Some((a, self.by_addr[&a].1))
    }

    fn free_for(&self, owner: u64, a: Ipv4Addr) -> bool {
        self.by_addr.get(&a).is_none_or(|(o, _)| *o == owner)
    }

    fn set(&mut self, owner: u64, a: Ipv4Addr, bound: bool) {
        self.release(owner);
        self.by_addr.insert(a, (owner, bound));
        self.by_owner.insert(owner, a);
    }

    fn release(&mut self, owner: u64) {
        if let Some(a) = self.by_owner.remove(&owner) {
            self.by_addr.remove(&a);
        }
    }

    fn release_all(&mut self, owner: u64) {
        self.release(owner);
        if let Some(a) = self.by_owner6.remove(&owner) {
            self.by_addr6.remove(&a);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Bind {
    New,
    Already,
    Refused,
}

/// Sandbox address ownership and DHCP, independent of host installation.
#[derive(Clone)]
pub(super) struct Bindings {
    pub(super) subnet: Subnet,
    pub(super) subnet6: Option<Subnet6>,
    leases: Arc<Mutex<Leases>>,
}

impl Bindings {
    pub(super) fn new(
        subnet: Subnet,
        subnet6: Option<Subnet6>,
        leases: Arc<Mutex<Leases>>,
    ) -> Self {
        Self {
            subnet,
            subnet6,
            leases,
        }
    }

    pub(super) fn new_owner(&self) -> u64 {
        self.leases.lock().new_owner()
    }

    pub(super) fn bound(&self, owner: u64) -> Placed {
        let leases = self.leases.lock();
        Placed {
            v4: leases.of(owner).and_then(|(a, bound)| bound.then_some(a)),
            v6: leases.by_owner6.get(&owner).copied(),
        }
    }

    pub(super) fn release(&self, owner: u64) {
        self.leases.lock().release_all(owner);
    }

    fn offer(&self, owner: u64, requested: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
        let mut leases = self.leases.lock();
        let mine = leases.of(owner);
        if let Some((a, true)) = mine {
            return Some(a);
        }
        if let Some(r) = requested
            && self.subnet.is_sandbox(r)
            && leases.free_for(owner, r)
        {
            leases.set(owner, r, false);
            return Some(r);
        }
        if let Some((a, false)) = mine {
            return Some(a);
        }
        let a = self
            .subnet
            .sandboxes()
            .find(|a| !leases.by_addr.contains_key(a))?;
        leases.set(owner, a, false);
        Some(a)
    }

    pub(super) fn may_bind(&self, owner: u64, a: Ipv4Addr) -> bool {
        let leases = self.leases.lock();
        !matches!(leases.of(owner), Some((_, true)))
            && self.subnet.is_sandbox(a)
            && leases.free_for(owner, a)
    }

    pub(super) fn bind(&self, owner: u64, a: Ipv4Addr) -> Bind {
        let mut leases = self.leases.lock();
        if let Some((b, true)) = leases.of(owner) {
            return if a == b { Bind::Already } else { Bind::Refused };
        }
        if self.subnet.is_sandbox(a) && leases.free_for(owner, a) {
            leases.set(owner, a, true);
            Bind::New
        } else {
            Bind::Refused
        }
    }

    pub(super) fn bind6(&self, owner: u64, a: Ipv6Addr) -> Bind {
        let Some(subnet) = &self.subnet6 else {
            return Bind::Refused;
        };
        let mut leases = self.leases.lock();
        if let Some(b) = leases.by_owner6.get(&owner) {
            return if a == *b {
                Bind::Already
            } else {
                Bind::Refused
            };
        }
        if subnet.is_sandbox(a) && !leases.by_addr6.contains_key(&a) {
            leases.by_addr6.insert(a, owner);
            leases.by_owner6.insert(owner, a);
            Bind::New
        } else {
            Bind::Refused
        }
    }

    pub(super) fn dhcp(
        &self,
        owner: u64,
        src: Ipv4Addr,
        m: &dhcp::Message,
    ) -> (Option<Packet>, Option<Ipv4Addr>) {
        if m.op != dhcp::BOOTREQUEST {
            return (None, None);
        }
        match m.message_type() {
            Some(dhcp::DISCOVER) => match self.offer(owner, m.option_addr(opt::REQUESTED_IP)) {
                Some(a) => (Some(self.dhcp_reply(m, dhcp::Reply::Offer(a))), None),
                None => (None, None),
            },
            Some(dhcp::REQUEST) => {
                if m.option_addr(opt::SERVER_ID)
                    .is_some_and(|s| s != self.subnet.gateway)
                {
                    return (None, None);
                }
                let wanted = m
                    .option_addr(opt::REQUESTED_IP)
                    .or((!m.ciaddr.is_unspecified()).then_some(m.ciaddr));
                let Some(wanted) = wanted else {
                    return (None, None);
                };
                match self.bind(owner, wanted) {
                    Bind::New => (
                        Some(self.dhcp_reply(m, dhcp::Reply::Ack(wanted))),
                        Some(wanted),
                    ),
                    Bind::Already => (Some(self.dhcp_reply(m, dhcp::Reply::Ack(wanted))), None),
                    Bind::Refused => (Some(self.dhcp_reply(m, dhcp::Reply::Nak)), None),
                }
            }
            Some(dhcp::INFORM) if !m.ciaddr.is_unspecified() && m.ciaddr == src => {
                (Some(self.dhcp_reply(m, dhcp::Reply::Inform)), None)
            }
            _ => (None, None),
        }
    }

    fn dhcp_reply(&self, request: &dhcp::Message, reply: dhcp::Reply) -> Packet {
        let gateway = self.subnet.gateway;
        let (m, to) = dhcp::ReplyConfig {
            server: gateway,
            lease_secs: LEASE,
            subnet_mask: self.subnet.mask(),
            router: Some(gateway),
            dns: Some(gateway),
            mtu: None,
        }
        .build(request, reply);
        udp_packet(
            gateway,
            dhcp::SERVER_PORT,
            to,
            dhcp::CLIENT_PORT,
            &m.to_bytes().expect("a reply with distinct options writes"),
        )
    }
}

fictionet::cfg_std! {
#[cfg(test)]
mod tests {
    use super::*;
    use super::super::*;
    use super::super::hosts::{Lookup, PortSpec, UdpStart};
    use fictionet::stdlib::test_support::{assert_linear, rounds};

    #[test]
    fn failed_hosts_reuse_automatic_addresses_even_without_negative_caching() {
        fictionet::block_on(fictionet::lab(fictionet::Seed::from_u64(1), |fcx| async move {
            let shared = Arc::new(Shared {
                fcx: fcx.clone(),
                resolver: Some(Arc::new(|name| Some(match name {
                    "address.test" => Host::new(name).at(Ipv6Addr::LOCALHOST),
                    "bind.test" => {
                        let mut host = Host::new(name);
                        let start: UdpStart = Arc::new(|_, _, _, _| panic!("not committed"));
                        host.ports.push((0, PortSpec::Udp(start.clone())));
                        host.ports.push((49152, PortSpec::Udp(start)));
                        host
                    }
                    _ => Host::new(name),
                }))),
                subnet: Subnet::new("10.0.0.0/24".parse().unwrap()).unwrap(),
                subnet6: Some(Subnet6::new("2001:db8::/64".parse().unwrap()).unwrap()),
                router: route::router(&fcx, Vec::new()),
                world: Arc::new(Mutex::new(World::new(MAX_HOSTS))),
                leases: Arc::default(),
                gateway_tcp: Arc::default(),
                hooks: Arc::new(Hooks {
                    by_addr: Mutex::default(),
                    conns: AtomicU64::new(0),
                    attached: Mutex::default(),
                }),
                fixed: Vec::new(),
                peers: Peers::new(Limits::default().connections_per_peer),
                limits: Limits::default(),
                lans: BTreeMap::new(),
            });
            shared.world.lock().max_unknown = 0;
            for name in ["address.test", "bind.test", "bind.test"] {
                assert!(matches!(shared.lookup(name), Lookup::NoHost));
                let world = shared.world.lock();
                assert!(world.machines.is_empty());
                assert!(world.names.is_empty());
                assert_eq!(world.resolved, 0);
                assert_eq!((world.addresses.next_auto, world.addresses.next_auto6), (1, 1));
                assert!(!world.addresses.auto_full);
            }
            let Lookup::Host(placed) = shared.lookup("good.test") else {
                panic!("a valid host fits after rejected hosts");
            };
            assert_eq!(placed.v4, Some("198.18.0.1".parse().unwrap()));
            assert_eq!(placed.v6, Some("2001:2::1".parse().unwrap()));
            fcx.cancel();
            Ok(())
        })).unwrap();
    }

    #[test]
    fn failed_hosts_remember_an_exhausted_automatic_range() {
        fictionet::block_on(fictionet::lab(fictionet::Seed::from_u64(1), |fcx| async move {
            let shared = Arc::new(Shared {
                fcx: fcx.clone(),
                resolver: Some(Arc::new(|name| Some(Host::new(name)))),
                subnet: Subnet::new("198.18.0.0/15".parse().unwrap()).unwrap(),
                subnet6: None,
                router: route::router(&fcx, Vec::new()),
                world: Arc::new(Mutex::new(World::new(MAX_HOSTS))),
                leases: Arc::default(),
                gateway_tcp: Arc::default(),
                hooks: Arc::new(Hooks {
                    by_addr: Mutex::default(),
                    conns: AtomicU64::new(0),
                    attached: Mutex::default(),
                }),
                fixed: Vec::new(),
                peers: Peers::new(Limits::default().connections_per_peer),
                limits: Limits::default(),
                lans: BTreeMap::new(),
            });
            shared.world.lock().max_unknown = 0;
            for name in ["first.test", "second.test"] {
                assert!(matches!(shared.lookup(name), Lookup::NoHost));
                let world = shared.world.lock();
                assert!(world.addresses.auto_full);
                assert!(world.machines.is_empty());
                assert!(world.names.is_empty());
                assert_eq!(world.resolved, 0);
                assert_eq!((world.addresses.next_auto, world.addresses.next_auto6), (1, 1));
            }
            fcx.cancel();
            Ok(())
        })).unwrap();
    }

    #[test]
    fn a_full_automatic_range_is_not_scanned_again() {
        assert_linear(
            "a_full_automatic_range_is_not_scanned_again",
            rounds(2_000_000),
            |size| {
                let mut w = World::new(MAX_HOSTS);
                let subnet = Subnet::new(Prefix {
                    addr: Ipv4Addr::new(198, 0, 0, 0).into(),
                    len: 8,
                })
                .unwrap();
                assert_eq!(w.free_auto(&subnet), None);
                assert!(w.addresses.auto_full);
                for _ in 0..size {
                    assert_eq!(std::hint::black_box(&mut w).free_auto(&subnet), None);
                }
            },
        );
    }

    fn subnet6(s: &str) -> Result<Subnet6, Error> {
        Subnet6::new(s.parse().unwrap())
    }

    #[test]
    fn ipv6_subnets_must_be_global_or_unique_local() {
        let s = subnet6("2001:db8::/64").unwrap();
        assert_eq!(s.gateway, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        assert!(s.is_sandbox("2001:db8::2".parse().unwrap()));
        for not in ["2001:db8::", "2001:db8::1", "2001:db8:0:1::2"] {
            assert!(!s.is_sandbox(not.parse().unwrap()), "{not}");
        }
        for bad in [
            "fe80::/64",
            "ff02::/16",
            "::/8",
            "::ffff:0:0/96",
            "2001:db8::/127",
            "2000::/4",
            "10.0.0.0/24",
        ] {
            assert!(subnet6(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn automatic_pool_boundaries() {
        let mut w = World::new(MAX_HOSTS);
        let subnet = Subnet::new("10.0.0.0/24".parse().unwrap()).unwrap();
        w.addresses.next_auto = (1 << 17) - 2;
        assert_eq!(
            w.free_auto(&subnet),
            Some("198.19.255.254".parse().unwrap())
        );
        assert_eq!(w.free_auto(&subnet), Some("198.18.0.1".parse().unwrap()));
        let inside = Subnet::new("198.18.0.0/16".parse().unwrap()).unwrap();
        assert_eq!(w.free_auto(&inside), Some("198.19.0.0".parse().unwrap()));
        assert_eq!(
            World::new(MAX_HOSTS)
                .free_auto(&Subnet::new("198.18.0.0/15".parse().unwrap()).unwrap()),
            None
        );

        let subnet = subnet6("2001:db8::/64").unwrap();
        w.addresses.next_auto6 = (1 << 80) - 1;
        assert_eq!(
            w.free_auto6(&subnet),
            Some("2001:2:0:ffff:ffff:ffff:ffff:ffff".parse().unwrap())
        );
        assert_eq!(w.free_auto6(&subnet), Some("2001:2::1".parse().unwrap()));
        w.addresses.next_auto6 = (1 << 80) - 2;
        let end = subnet6("2001:2:0:ffff:ffff:ffff:ffff:fffc/126").unwrap();
        assert_eq!(w.free_auto6(&end), Some("2001:2::1".parse().unwrap()));
        assert_eq!(w.free_auto6(&subnet6("2001:2::/48").unwrap()), None);
    }

    #[test]
    fn sandbox_address_boundaries() {
        let s = Subnet::new(Prefix {
            addr: "10.0.0.3".parse().unwrap(),
            len: 30,
        })
        .unwrap();
        assert_eq!(s.gateway, "10.0.0.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(s.mask(), Ipv4Addr::new(255, 255, 255, 252));
        assert_eq!(
            s.sandboxes().collect::<Vec<_>>(),
            vec![Ipv4Addr::new(10, 0, 0, 2)]
        );
        for n in 0..=4 {
            assert_eq!(s.is_sandbox(Ipv4Addr::new(10, 0, 0, n)), n == 2);
        }
        let s = Subnet6::new(Prefix {
            addr: "2001:db8::3".parse().unwrap(),
            len: 126,
        })
        .unwrap();
        for n in 0..=4 {
            assert_eq!(
                s.is_sandbox(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, n)),
                n == 2 || n == 3
            );
        }
    }

    #[test]
    fn automatic_ipv6_addresses_count_up_and_skip_the_subnet() {
        let mut w = World::new(MAX_HOSTS);
        let s = subnet6("2001:db8::/64").unwrap();
        assert_eq!(w.free_auto6(&s), Some("2001:2::1".parse().unwrap()));
        assert_eq!(w.free_auto6(&s), Some("2001:2::2".parse().unwrap()));
        let mut w = World::new(MAX_HOSTS);
        let inside = subnet6("2001:2::/120").unwrap();
        assert_eq!(w.free_auto6(&inside), Some("2001:2::100".parse().unwrap()));
        assert_eq!(
            World::new(MAX_HOSTS).free_auto6(&subnet6("2001::/16").unwrap()),
            None
        );
    }

    #[test]
    fn hosts_cannot_have_addresses_a_host_cannot_have() {
        let s = subnet6("2001:db8::/64").unwrap();
        assert!(may_serve_v6("2a02:ec80:300:ed1a::1".parse().unwrap(), &s));
        for bad in [
            "::",
            "::1",
            "ff02::1",
            "fe80::1",
            "::ffff:1.2.3.4",
            "2001:db8::5",
        ] {
            assert!(!may_serve_v6(bad.parse().unwrap(), &s), "{bad}");
        }
    }

    #[test]
    fn prefixes_contain_their_addresses() {
        let p: Prefix = "10.0.0.50/32".parse().unwrap();
        assert!(p.contains("10.0.0.50".parse().unwrap()));
        assert!(!p.contains("10.0.0.51".parse().unwrap()));
        let p: Prefix = "10.0.9.0/24".parse().unwrap();
        assert!(p.contains("10.0.9.200".parse().unwrap()));
        assert!(!p.contains("2001:db8::1".parse().unwrap()));
    }
}
}
