use super::{Pools, udp_packet};
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::network::route::Prefix;
use fictionet::stdlib::protocols::dhcp::{self, opt};
use fictionet::stdlib::protocols::dns::rr::rdata::{A, AAAA};
use fictionet::stdlib::protocols::dns::rr::{Name, RData, Record, RecordSet};
use fictionet::sync::Mutex;
use fictionet::{Error, Packet};
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

/// How long a DHCP lease lasts. The binding itself lasts until the sandbox
/// detaches; the lease time only tells the client when to renew.
const LEASE: u32 = 3600;

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

/// A placed host's addresses. A placed host has at least one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Placed {
    /// Its IPv4 address, if it has one.
    pub v4: Option<Ipv4Addr>,
    /// Its IPv6 address, if it has one.
    pub v6: Option<Ipv6Addr>,
}

impl Placed {
    /// The A and AAAA RRsets that give `name` these addresses, with `ttl`:
    /// one for each address the host has.
    pub fn rrsets(&self, name: &Name, ttl: u32) -> Vec<RecordSet> {
        let rdata = self
            .v4
            .map(|a| RData::A(A(a)))
            .into_iter()
            .chain(self.v6.map(|a| RData::AAAA(AAAA(a))));
        rdata
            .map(|rdata| {
                let mut set = RecordSet::with_ttl(name.clone(), rdata.record_type(), ttl);
                set.set_records(vec![Record::from_rdata(name.clone(), ttl, rdata)]);
                set
            })
            .collect()
    }
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

/// Prefixes inside which no host may have an IPv4 address, beside the
/// sandboxes' subnet: `0.0.0.0`, loopback, multicast and the limited
/// broadcast address. [`may_serve_v4`] refuses the same addresses.
const NOT_HOSTS_V4: [Prefix; 4] = [
    Prefix {
        addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        len: 32,
    },
    Prefix {
        addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
        len: 8,
    },
    Prefix {
        addr: IpAddr::V4(Ipv4Addr::new(224, 0, 0, 0)),
        len: 4,
    },
    Prefix {
        addr: IpAddr::V4(Ipv4Addr::BROADCAST),
        len: 32,
    },
];

/// Prefixes inside which no host may have an IPv6 address, beside the
/// sandboxes' subnet: `::` and `::1`, IPv4-mapped addresses, link-local
/// unicast and multicast. [`may_serve_v6`] refuses the same addresses.
const NOT_HOSTS_V6: [Prefix; 4] = [
    Prefix {
        addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        len: 127,
    },
    Prefix {
        addr: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0)),
        len: 96,
    },
    Prefix {
        addr: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)),
        len: 10,
    },
    Prefix {
        addr: IpAddr::V6(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0)),
        len: 8,
    },
];

/// Checks the world's pools: each of its own family, with room for a
/// host. An IPv4 pool's first and last addresses are never handed out,
/// nor an IPv6 pool's first.
pub(super) fn check_pools(pools: &Pools) -> Result<(), Error> {
    if let Some(p) = pools.v4
        && (!p.addr.is_ipv4() || p.len > 30)
    {
        return Err(Error::msg(format!(
            "the IPv4 pool {}/{} must be IPv4 with a length of at most 30",
            p.addr, p.len
        )));
    }
    if let Some(p) = pools.v6
        && (!p.addr.is_ipv6() || p.len > 127)
    {
        return Err(Error::msg(format!(
            "the IPv6 pool {}/{} must be IPv6 with a length of at most 127",
            p.addr, p.len
        )));
    }
    Ok(())
}

/// Automatic host addresses from the world's pools, with their cursors:
/// each the offset from its pool's first address of the next one to try.
/// Occupied addresses come from installation.
pub(super) struct Allocator {
    pools: Pools,
    pub(super) next_auto: u32,
    pub(super) next_auto6: u128,
    pub(super) auto_full: bool,
}

impl Allocator {
    /// Cursors at the start of `pools`, which [`check_pools`] accepted.
    pub(super) fn new(pools: Pools) -> Allocator {
        Allocator {
            pools: Pools {
                v4: pools.v4.map(Prefix::canonical),
                v6: pools.v6.map(Prefix::canonical),
            },
            next_auto: 1,
            next_auto6: 1,
            auto_full: false,
        }
    }

    /// The next free IPv4 address of the pool, after the last one handed
    /// out: not the pool's first or last address, not occupied, and one a
    /// host may have here. Ranges no host may have are stepped over whole,
    /// as in [`Allocator::free_auto6`]. `None` when there is no pool or it
    /// is full; a full pool is remembered, so it is not searched again.
    pub(super) fn free_auto<T>(
        &mut self,
        subnet: &Subnet,
        occupied: &BTreeMap<IpAddr, T>,
    ) -> Option<Ipv4Addr> {
        let pool = self.pools.v4?;
        if self.auto_full {
            return None;
        }
        let mut skipped = NOT_HOSTS_V4.to_vec();
        skipped.push(subnet.prefix);
        if skipped
            .iter()
            .any(|s| s.len <= pool.len && s.overlaps(pool))
        {
            self.auto_full = true;
            return None;
        }
        // The offset of the pool's last address. Its length is at most 30.
        let last = u32::MAX >> pool.len;
        let step = |n: u32| if n >= last { 0 } else { n + 1 };
        // One pass meets each occupied address once, the pool's first and
        // last addresses and each range at most twice.
        for _ in 0..occupied.len() + 2 * skipped.len() + 4 {
            let n = self.next_auto;
            self.next_auto = step(n);
            if n == 0 || n == last {
                continue;
            }
            let IpAddr::V4(a) = pool
                .nth(n.into())
                .expect("the cursor is inside the IPv4 pool")
            else {
                unreachable!("the IPv4 pool contains IPv4 addresses")
            };
            if let Some(range) = skipped.iter().find(|s| s.contains(a.into())) {
                let IpAddr::V4(end) = range.last() else {
                    unreachable!("an IPv4 range has an IPv4 last address")
                };
                // Prefixes nest, and none covers the pool, so the range
                // ends inside it.
                let past = n + (u32::from(end) - u32::from(a));
                self.next_auto = if past >= last { 0 } else { past + 1 };
                continue;
            }
            debug_assert!(may_serve_v4(a, subnet));
            if !occupied.contains_key(&a.into()) {
                return Some(a);
            }
        }
        self.auto_full = true;
        None
    }

    /// The next free IPv6 address of the pool, after the last one handed
    /// out: not the pool's first address, not occupied, and one a host may
    /// have here. Ranges no host may have are stepped over whole, so the
    /// search takes at most one step per occupied address and two per such
    /// range. `None` when there is no pool or it is full.
    pub(super) fn free_auto6<T>(
        &mut self,
        subnet: &Subnet6,
        occupied: &BTreeMap<IpAddr, T>,
    ) -> Option<Ipv6Addr> {
        let pool = self.pools.v6?;
        let mut skipped = NOT_HOSTS_V6.to_vec();
        skipped.push(subnet.prefix);
        if skipped
            .iter()
            .any(|s| s.len <= pool.len && s.overlaps(pool))
        {
            return None;
        }
        // The offset of the pool's last address. Its length is at most 127.
        let last = u128::MAX >> pool.len;
        for _ in 0..occupied.len() + 2 * skipped.len() + 2 {
            let n = self.next_auto6;
            self.next_auto6 = n.wrapping_add(1) & last;
            if n == 0 {
                continue;
            }
            let IpAddr::V6(a) = pool.nth(n).expect("the cursor is inside the IPv6 pool") else {
                unreachable!("the IPv6 pool contains IPv6 addresses")
            };
            if let Some(range) = skipped.iter().find(|s| s.contains(a.into())) {
                let IpAddr::V6(end) = range.last() else {
                    unreachable!("an IPv6 range has an IPv6 last address")
                };
                self.next_auto6 = n
                    .wrapping_add(u128::from(end) - u128::from(a))
                    .wrapping_add(1)
                    & last;
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

#[cfg(test)]
mod tests {
    use super::super::hosts::{PortSpec, UdpStart};
    use super::super::*;
    use super::*;
    use fictionet::stdlib::test_support::rounds;

    fn pools(v4: &str, v6: &str) -> Pools {
        Pools {
            v4: Some(v4.parse().unwrap()),
            v6: Some(v6.parse().unwrap()),
        }
    }

    /// The network's shared state with no hosts, on `subnet` and `subnet6`.
    fn network(fcx: &Cx, subnet: &str, subnet6: Option<&str>) -> Arc<Shared> {
        let subnet = Subnet::new(subnet.parse().unwrap()).unwrap();
        let subnet6 = subnet6.map(|s| Subnet6::new(s.parse().unwrap()).unwrap());
        let world = Arc::new(Mutex::new(World::new(TEST_POOLS)));
        Arc::new(Shared {
            fcx: fcx.clone(),
            subnet,
            subnet6,
            router: route::router(fcx, Vec::new()),
            world: world.clone(),
            leases: Arc::default(),
            gateway_tcp: Arc::default(),
            hooks: Arc::new(Hooks {
                http_observe: None,
                tls_observe: None,
                attachment_observe: None,
                dns_observe: None,
                refused_observe: None,
                by_addr: Mutex::default(),
                routes: Mutex::default(),
                conns: AtomicU64::new(0),
                attached: Mutex::default(),
                destinations: super::super::attachments::Destinations {
                    subnets: std::iter::once(subnet.prefix)
                        .chain(subnet6.map(|s| s.prefix))
                        .collect(),
                    gateways: std::iter::once(std::net::IpAddr::V4(subnet.gateway))
                        .chain(subnet6.map(|s| IpAddr::V6(s.gateway)))
                        .collect(),
                    trusted: Vec::new(),
                    machines: super::super::hosts::Machines::new(world),
                },
            }),
            peers: Peers::new(Limits::default().connections_per_peer),
            limits: Limits::default(),
            egress: None,
            lans: BTreeMap::new(),
        })
    }

    #[test]
    fn automatic_addresses_come_from_the_supplied_pools() {
        let subnet = Subnet::new("10.0.0.0/24".parse().unwrap()).unwrap();
        let s6 = subnet6("2001:db8::/64").unwrap();
        for (pools, first, first6) in [
            (TEST_POOLS, "104.18.0.1", "2606:4700:100::1"),
            (
                pools("23.32.0.0/11", "2a02:26f0::/32"),
                "23.32.0.1",
                "2a02:26f0::1",
            ),
        ] {
            let mut w = World::new(pools);
            assert_eq!(w.free_auto(&subnet), Some(first.parse().unwrap()));
            assert_eq!(w.free_auto6(&s6), Some(first6.parse().unwrap()));
        }
        let mut w = World::new(Pools::NONE);
        assert_eq!(w.free_auto(&subnet), None);
        assert_eq!(w.free_auto6(&s6), None);
    }

    #[test]
    fn pools_are_checked_for_family_and_room() {
        for good in [
            Pools::NONE,
            TEST_POOLS,
            pools("0.0.0.0/0", "::/0"),
            pools("192.0.2.0/30", "2001:db8:1::/127"),
        ] {
            assert!(check_pools(&good).is_ok(), "{good:?}");
        }
        for bad in [
            pools("192.0.2.0/31", "2001:db8:1::/64"),
            pools("192.0.2.0/24", "2001:db8:1::/128"),
            pools("2001:db8:1::/64", "2001:db8:1::/64"),
            pools("192.0.2.0/24", "192.0.2.0/24"),
        ] {
            assert!(check_pools(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn whole_address_space_pools_wrap_without_overflow() {
        let subnet = Subnet::new("10.0.0.0/24".parse().unwrap()).unwrap();
        let s6 = subnet6("2001:db8::/64").unwrap();
        let mut w = World::new(pools("0.0.0.0/0", "::/0"));
        assert_eq!(w.free_auto(&subnet), Some("0.0.0.1".parse().unwrap()));
        w.addresses.next_auto = u32::MAX - 1;
        assert_eq!(
            w.free_auto(&subnet),
            Some("255.255.255.254".parse().unwrap())
        );
        assert_eq!(w.free_auto(&subnet), Some("0.0.0.1".parse().unwrap()));
        // Loopback, the subnet and multicast are stepped over whole.
        for (from, want) in [
            ("127.0.0.0", "128.0.0.0"),
            ("10.0.0.7", "10.0.1.0"),
            ("224.0.0.0", "240.0.0.0"),
        ] {
            w.addresses.next_auto = u32::from(from.parse::<Ipv4Addr>().unwrap());
            assert_eq!(w.free_auto(&subnet), Some(want.parse().unwrap()));
        }
        // `::1` is loopback, so `::2` is the first.
        assert_eq!(w.free_auto6(&s6), Some("::2".parse().unwrap()));
        // Multicast runs to the end of the space; the search wraps to the start.
        w.addresses.next_auto6 = u128::MAX - 1;
        assert_eq!(w.free_auto6(&s6), Some("::2".parse().unwrap()));
        // The subnet and link-local space are stepped over whole.
        w.addresses.next_auto6 = u128::from("2001:db8::5".parse::<Ipv6Addr>().unwrap());
        assert_eq!(w.free_auto6(&s6), Some("2001:db8:0:1::".parse().unwrap()));
        w.addresses.next_auto6 = u128::from("fe80::".parse::<Ipv6Addr>().unwrap());
        assert_eq!(w.free_auto6(&s6), Some("fec0::".parse().unwrap()));
    }

    #[test]
    fn the_smallest_pools_hand_out_their_usable_addresses() {
        let subnet = Subnet::new("10.0.0.0/24".parse().unwrap()).unwrap();
        let s6 = subnet6("2001:db8::/64").unwrap();
        let mut w = World::new(pools("192.0.2.4/30", "2001:db8:1::/127"));
        let mut occupied = BTreeMap::new();
        for want in ["192.0.2.5", "192.0.2.6"] {
            let a = w.addresses.free_auto(&subnet, &occupied).unwrap();
            assert_eq!(a, want.parse::<Ipv4Addr>().unwrap());
            occupied.insert(IpAddr::V4(a), ());
        }
        assert_eq!(w.addresses.free_auto(&subnet, &occupied), None);
        assert!(w.addresses.auto_full);
        let a = w.addresses.free_auto6(&s6, &occupied).unwrap();
        assert_eq!(a, "2001:db8:1::1".parse::<Ipv6Addr>().unwrap());
        occupied.insert(IpAddr::V6(a), ());
        assert_eq!(w.addresses.free_auto6(&s6, &occupied), None);
        let mut w = World::new(pools("192.0.2.0/24", "fe80:1::/64"));
        assert_eq!(
            w.free_auto6(&s6),
            None,
            "no host may have link-local addresses"
        );
    }

    #[test]
    fn failed_hosts_give_their_automatic_addresses_back() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            |fcx| async move {
                let shared = network(&fcx, "10.0.0.0/24", Some("2001:db8::/64"));
                let bind = || {
                    let mut host = Host::new("bind.test").dns_name("bind.test");
                    let start: UdpStart = Arc::new(|_, _, _| panic!("not committed"));
                    host.ports.push((0, PortSpec::Udp(start.clone())));
                    host.ports.push((49152, PortSpec::Udp(start)));
                    host
                };
                let rejected = [
                    Host::new("address.test")
                        .dns_name("address.test")
                        .at(Ipv6Addr::LOCALHOST),
                    bind(),
                    bind(),
                ];
                for host in rejected {
                    let mut world = shared.world.lock();
                    assert!(shared.place(&mut world, host).is_err());
                    assert!(world.machines.is_empty());
                    assert!(world.declared.is_empty());
                    assert_eq!(
                        (world.addresses.next_auto, world.addresses.next_auto6),
                        (1, 1)
                    );
                    assert!(!world.addresses.auto_full);
                }
                let placed = shared
                    .place(&mut shared.world.lock(), Host::new("good.test"))
                    .expect("a valid host fits after rejected hosts");
                assert_eq!(placed.v4, Some("104.18.0.1".parse().unwrap()));
                assert_eq!(placed.v6, Some("2606:4700:100::1".parse().unwrap()));
                fcx.cancel();
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn failed_hosts_remember_an_exhausted_automatic_range() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            |fcx| async move {
                let shared = network(&fcx, "104.18.0.0/15", None);
                for name in ["first.test", "second.test"] {
                    let mut world = shared.world.lock();
                    assert!(
                        shared
                            .place(&mut world, Host::new(name).dns_name(name))
                            .is_err()
                    );
                    assert!(world.addresses.auto_full);
                    assert!(world.machines.is_empty());
                    assert!(world.declared.is_empty());
                    assert_eq!(
                        (world.addresses.next_auto, world.addresses.next_auto6),
                        (1, 1)
                    );
                }
                fcx.cancel();
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn pools_no_host_may_use_are_full_at_once() {
        let subnet = Subnet::new("10.0.0.0/24".parse().unwrap()).unwrap();
        for pool in ["224.0.0.0/4", "127.0.0.0/16", "10.0.0.0/28"] {
            let mut w = World::new(pools(pool, "2001:db8:1::/64"));
            assert_eq!(w.free_auto(&subnet), None, "{pool}");
            assert!(w.addresses.auto_full, "{pool}");
        }
    }

    #[test]
    fn a_full_automatic_range_is_not_scanned_again() {
        for size in [rounds(2_000_000), 4 * (rounds(2_000_000))] {
            let mut w = World::new(TEST_POOLS);
            let subnet = Subnet::new(Prefix {
                addr: Ipv4Addr::new(104, 0, 0, 0).into(),
                len: 8,
            })
            .unwrap();
            assert_eq!(w.free_auto(&subnet), None);
            assert!(w.addresses.auto_full);
            for _ in 0..size {
                assert_eq!(std::hint::black_box(&mut w).free_auto(&subnet), None);
            }
        }
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
        let mut w = World::new(TEST_POOLS);
        let subnet = Subnet::new("10.0.0.0/24".parse().unwrap()).unwrap();
        w.addresses.next_auto = (1 << 17) - 2;
        assert_eq!(
            w.free_auto(&subnet),
            Some("104.19.255.254".parse().unwrap())
        );
        assert_eq!(w.free_auto(&subnet), Some("104.18.0.1".parse().unwrap()));
        let inside = Subnet::new("104.18.0.0/16".parse().unwrap()).unwrap();
        assert_eq!(w.free_auto(&inside), Some("104.19.0.0".parse().unwrap()));
        assert_eq!(
            World::new(TEST_POOLS)
                .free_auto(&Subnet::new("104.18.0.0/15".parse().unwrap()).unwrap()),
            None
        );

        let subnet = subnet6("2001:db8::/64").unwrap();
        w.addresses.next_auto6 = (1 << 80) - 1;
        assert_eq!(
            w.free_auto6(&subnet),
            Some("2606:4700:100:ffff:ffff:ffff:ffff:ffff".parse().unwrap())
        );
        assert_eq!(
            w.free_auto6(&subnet),
            Some("2606:4700:100::1".parse().unwrap())
        );
        w.addresses.next_auto6 = (1 << 80) - 2;
        let end = subnet6("2606:4700:100:ffff:ffff:ffff:ffff:fffc/126").unwrap();
        assert_eq!(
            w.free_auto6(&end),
            Some("2606:4700:100::1".parse().unwrap())
        );
        assert_eq!(w.free_auto6(&subnet6("2606:4700:100::/48").unwrap()), None);
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
        let mut w = World::new(TEST_POOLS);
        let s = subnet6("2001:db8::/64").unwrap();
        assert_eq!(w.free_auto6(&s), Some("2606:4700:100::1".parse().unwrap()));
        assert_eq!(w.free_auto6(&s), Some("2606:4700:100::2".parse().unwrap()));
        let mut w = World::new(TEST_POOLS);
        let inside = subnet6("2606:4700:100::/120").unwrap();
        assert_eq!(
            w.free_auto6(&inside),
            Some("2606:4700:100::100".parse().unwrap())
        );
        assert_eq!(
            World::new(TEST_POOLS).free_auto6(&subnet6("2606::/16").unwrap()),
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
