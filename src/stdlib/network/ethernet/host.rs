//! A host on an Ethernet segment: the host's side of the link-layer
//! protocols that [`Link`](super::Link) runs from the router's side.
//!
//! A world that owns a network card sees whole Ethernet frames. Before it
//! can exchange IP packets with the rest of the internet it has to do what
//! every host on a segment does: answer ARP and neighbor solicitations for
//! its own addresses, check that no other node uses its IPv6 addresses,
//! tell switches which multicast groups it listens to, and find the MAC
//! address of its gateway. A [`Host`] does all of that, and nothing else.
//! It does no I/O and has no clock: the caller passes in each frame and
//! the current time, and takes out IP packets for the world and frames to
//! send.
//!
//! # Driving it
//!
//! - [`Host::receive`] reads one frame from the segment. It returns the IP
//!   packet inside when the packet is for the world, and keeps ARP and
//!   neighbor discovery for itself.
//! - [`Host::transmit`] returns the next frame to send: answers to what
//!   [`receive`](Host::receive) read, and the messages the host's timers
//!   call for. Call it until it returns `None` after every call to
//!   `receive`, and again at [`Host::poll_at`].
//! - [`Host::send`] puts an Ethernet header on an IP packet from the world.
//! - [`Host::accepts`] is the host's receive filter, for a card that can
//!   filter frames itself.
//!
//! Any call can move [`poll_at`](Host::poll_at) earlier, so read it again
//! after each one.
//!
//! # What it does
//!
//! It answers ARP requests for its IPv4 address
//! ([RFC 826](https://www.rfc-editor.org/rfc/rfc826)), including probes
//! from hosts that check the address is free
//! ([RFC 5227](https://www.rfc-editor.org/rfc/rfc5227)), and neighbor
//! solicitations for its IPv6 addresses
//! ([RFC 4861](https://www.rfc-editor.org/rfc/rfc4861) section 7.2.4),
//! including duplicate address detection from other nodes, which it
//! answers to all nodes.
//!
//! It has two IPv6 addresses: the global one it was given, and the
//! link-local one it makes from its MAC
//! ([RFC 4291](https://www.rfc-editor.org/rfc/rfc4291) appendix A). It
//! runs duplicate address detection on both
//! ([RFC 4862](https://www.rfc-editor.org/rfc/rfc4862) section 5.4): one
//! neighbor solicitation from the unspecified address each, then one
//! [`RETRANS_TIMER`] of waiting. Until it passes, an address is
//! tentative: packets to it are dropped and packets from it are not sent.
//! An address that fails stays unused for the life of the `Host`; the
//! host does not pick another. When the link-local address fails, the
//! host stops all IPv6 on the segment, as RFC 4862 section 5.4.5 says,
//! because the MAC it comes from is in use by another node.
//!
//! Before it checks an address, the host joins the address's
//! solicited-node multicast group
//! ([RFC 4861](https://www.rfc-editor.org/rfc/rfc4861) section 7.2.1),
//! where neighbor solicitations for the address go. It says so in an MLDv2
//! report ([RFC 3810](https://www.rfc-editor.org/rfc/rfc3810) section
//! 6.1), from the unspecified address while its link-local address is
//! tentative, and sends the report [`MLD_ROBUSTNESS`] times. It also
//! listens to the all-nodes group, which is never reported. It does not
//! answer MLD queries.
//!
//! It finds its gateways' MACs: by ARP for IPv4, and by a neighbor
//! solicitation to the gateway's solicited-node group for IPv6, both again
//! every [`RETRANS_TIMER`] until answered. RFC 4861 section 7.2.2 gives up
//! after three solicitations and starts over with the next packet; a host
//! always has packets for its gateway, so this one keeps asking. Once
//! known, each gateway's entry follows the reachability states of RFC 4861
//! section 7.3 (reachable, stale, delay and probe), the same way for both
//! families, as Linux does for ARP. Solicited advertisements and ARP
//! replies to the host confirm the gateway. Other messages that carry the
//! gateway's MAC (its ARP requests, its neighbor solicitations for the
//! host's addresses, its router advertisements, and unsolicited
//! advertisements) teach or change the MAC as RFC 4861 sections 6.3.4,
//! 7.2.3 and 7.2.5 say. It keeps no other neighbors.
//!
//! The IPv6 gateway is either configured, or learned from router
//! advertisements ([`Ipv6Gateway`]). To learn it, the host sends up to
//! [`MAX_RTR_SOLICITATIONS`] router solicitations
//! ([RFC 4861](https://www.rfc-editor.org/rfc/rfc4861) section 6.3.7),
//! then takes the first router that advertises a lifetime other than zero
//! as its default router, for as long as that lifetime lasts. It keeps the
//! router until the lifetime ends, the router advertises a lifetime of
//! zero, or it says it is no longer a router; then it waits for the next
//! advertisement. It takes no prefixes, MTU, hop limit or timers from
//! advertisements, and ignores redirects: its address and MTU are
//! configured, and it keeps the RFC's default timers.
//!
//! Every packet the world sends goes to the gateway of its family, whatever
//! its destination, as on a host whose only route is the default route.
//! Packets to a multicast or broadcast destination go to the group's MAC
//! instead. Packets are dropped, as Linux drops them while a neighbor is
//! unresolved, until the gateway's MAC is known, and when they are longer
//! than the MTU or come from an address the host may not use.
//!
//! Where the RFCs ask for a random delay so that hosts that start together
//! do not send at the same moment, the host, which has no randomness, sends
//! its first message at once and waits the whole interval before a repeat.
//! Where they ask for a random reachable time around [`REACHABLE_TIME`], it
//! uses `REACHABLE_TIME`.
//!
//! Every frame is read as hostile input: every length is checked before it
//! is read, and the neighbor discovery checksum is checked.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use fictionet::stdlib::network::ip::Header;
use fictionet::stdlib::protocols::arp;
use fictionet::stdlib::protocols::mld::{self, Record, RecordType, Report};
use fictionet::stdlib::protocols::ndp::{
    self, Envelope, Message, NdOption, NeighborAdvertisement, NeighborSolicitation,
    RouterSolicitation,
};
use fictionet::time::{Duration, Instant};

use super::frame::{self, Frame, Mac, Upper};

/// How long the host waits for an answer before it asks again:
/// RETRANS_TIMER, 1 second
/// ([RFC 4861](https://www.rfc-editor.org/rfc/rfc4861) section 10). It is
/// the wait between neighbor solicitations and between ARP requests (the
/// shortest [RFC 1122](https://www.rfc-editor.org/rfc/rfc1122) section
/// 2.3.2.1 allows for one address), and the wait after duplicate address
/// detection's last solicitation
/// ([RFC 4862](https://www.rfc-editor.org/rfc/rfc4862) section 5.4).
pub const RETRANS_TIMER: Duration = Duration::from_secs(1);

/// How long a gateway counts as reachable after it confirmed it:
/// REACHABLE_TIME, 30 seconds
/// ([RFC 4861](https://www.rfc-editor.org/rfc/rfc4861) section 10).
pub const REACHABLE_TIME: Duration = Duration::from_secs(30);

/// How long the host keeps sending to a stale gateway before it checks
/// that the gateway is still there: DELAY_FIRST_PROBE_TIME, 5 seconds
/// ([RFC 4861](https://www.rfc-editor.org/rfc/rfc4861) section 10).
pub const DELAY_FIRST_PROBE_TIME: Duration = Duration::from_secs(5);

/// How many unicast solicitations the host sends to check a stale gateway
/// before it forgets its MAC: MAX_UNICAST_SOLICIT, 3
/// ([RFC 4861](https://www.rfc-editor.org/rfc/rfc4861) section 10).
pub const MAX_UNICAST_SOLICIT: u8 = 3;

/// How long the host waits between router solicitations:
/// RTR_SOLICITATION_INTERVAL, 4 seconds
/// ([RFC 4861](https://www.rfc-editor.org/rfc/rfc4861) section 10).
pub const RTR_SOLICITATION_INTERVAL: Duration = Duration::from_secs(4);

/// How many router solicitations the host sends before it waits for
/// routers to advertise on their own: MAX_RTR_SOLICITATIONS, 3
/// ([RFC 4861](https://www.rfc-editor.org/rfc/rfc4861) section 10).
pub const MAX_RTR_SOLICITATIONS: u8 = 3;

/// How many neighbor solicitations duplicate address detection sends for
/// each address: DupAddrDetectTransmits, whose default is 1
/// ([RFC 4862](https://www.rfc-editor.org/rfc/rfc4862) section 5.1).
pub const DUP_ADDR_DETECT_TRANSMITS: u8 = 1;

/// How many times the host sends the report that joins its groups: the
/// Robustness Variable, whose default is 2
/// ([RFC 3810](https://www.rfc-editor.org/rfc/rfc3810) sections 6.1 and
/// 9.1).
pub const MLD_ROBUSTNESS: u8 = 2;

/// The longest wait between the reports that join the host's groups: the
/// Unsolicited Report Interval, 1 second
/// ([RFC 3810](https://www.rfc-editor.org/rfc/rfc3810) section 9.11).
pub const UNSOLICITED_REPORT_INTERVAL: Duration = Duration::from_secs(1);

/// What a [`Host`] is: its MAC, its IP configuration, and the largest IP
/// packet it sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// The host's MAC.
    pub mac: Mac,
    /// The largest IP packet the host sends, in bytes: 1500 on most
    /// Ethernet segments.
    pub mtu: u16,
    /// The host's IPv4 configuration, or `None` for no IPv4.
    pub ipv4: Option<Ipv4Config>,
    /// The host's IPv6 configuration, or `None` for no IPv6.
    pub ipv6: Option<Ipv6Config>,
}

/// A host's IPv4 address and gateway.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Config {
    /// The host's address.
    pub address: Ipv4Addr,
    /// The gateway every packet goes to. It must be on the segment.
    pub gateway: Ipv4Addr,
}

/// A host's global IPv6 address and gateway. Its link-local address
/// comes from its MAC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv6Config {
    /// The host's global address.
    pub address: Ipv6Addr,
    /// Where the host's gateway comes from.
    pub gateway: Ipv6Gateway,
}

/// Where a host's IPv6 gateway comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv6Gateway {
    /// A gateway at this address, which must be on the segment, such as
    /// `fe80::1` on Hetzner.
    Configured(Ipv6Addr),
    /// The first router that advertises itself as a default router, as on
    /// AWS and Google Cloud.
    FromRouterAdvertisements,
}

/// Why a [`Config`] cannot make a [`Host`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// The MAC is all zeros or a group address.
    Mac(Mac),
    /// An IPv4 address or gateway is unspecified, broadcast, multicast or
    /// loopback, or the gateway is the host's own address.
    Ipv4(Ipv4Addr),
    /// An IPv6 address or gateway is unspecified, multicast or loopback,
    /// the address is link-local, or the gateway is one of the host's own
    /// addresses.
    Ipv6(Ipv6Addr),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Mac(mac) => write!(f, "{mac:02x?} cannot be a host's MAC"),
            ConfigError::Ipv4(a) => write!(f, "{a} cannot be the host's IPv4 address or gateway"),
            ConfigError::Ipv6(a) => write!(f, "{a} cannot be the host's IPv6 address or gateway"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Where duplicate address detection stands for one of the host's IPv6
/// addresses ([RFC 4862](https://www.rfc-editor.org/rfc/rfc4862) section
/// 5.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressState {
    /// Being checked: not used yet.
    Tentative,
    /// Checked, and in use.
    Preferred,
    /// Another node uses it: never used.
    Duplicate,
}

/// What a frame from the segment is for.
#[derive(Debug, PartialEq, Eq)]
pub enum Received<'a> {
    /// An IP packet for the world, without the Ethernet header and padding.
    World(&'a [u8]),
    /// ARP or neighbor discovery, which the host took in. Any answer is
    /// waiting at [`Host::transmit`].
    Handled,
    /// Dropped.
    Drop(Dropped),
}

/// Why the host dropped a frame from the segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dropped {
    /// Shorter than an Ethernet header, an ARP packet that is not
    /// Ethernet/IPv4, a broken IP header, or a neighbor discovery message
    /// that is invalid, fragmented, has a wrong checksum, or names a group
    /// MAC as a node's.
    Malformed,
    /// From a group MAC or all zeros, which no node sends from.
    BadSource,
    /// From the host's own MAC: a copy of a frame it sent, looped back.
    Looped,
    /// To a MAC the host does not [accept](Host::accepts).
    NotForUs,
    /// Neither ARP, IPv4 nor IPv6 (VLAN tags and LLDP, for example).
    OtherType,
    /// For a family the host does not have, or IPv6 after the link-local
    /// address failed duplicate address detection.
    Off,
    /// To an IP address the host does not have, or has but may not use:
    /// tentative or duplicate.
    NotOurs,
}

/// Why [`Host::send`] did not frame a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsent {
    /// Not a whole IPv4 or IPv6 packet.
    Malformed,
    /// Longer than the MTU.
    TooBig,
    /// For a family the host does not have, or IPv6 after the link-local
    /// address failed duplicate address detection.
    Off,
    /// From an address that is not the host's, or is tentative or
    /// duplicate.
    Source,
    /// The gateway's MAC is not known yet, or no router has advertised
    /// itself.
    Unresolved,
}

/// One host on one Ethernet segment. See the [module](self) for what it
/// does.
#[derive(Debug)]
pub struct Host {
    mac: Mac,
    mtu: u16,
    v4: Option<V4>,
    v6: Option<V6>,
    /// Frames waiting for [`Host::transmit`].
    outbox: VecDeque<Vec<u8>>,
}

#[derive(Debug)]
struct V4 {
    address: Ipv4Addr,
    gateway: Ipv4Addr,
    neighbor: Neighbor,
}

#[derive(Debug)]
struct V6 {
    link_local: Address,
    global: Address,
    /// The reports that join the solicited-node groups.
    reports: Repeat,
    gateway: Gateway,
}

#[derive(Debug)]
struct Address {
    addr: Ipv6Addr,
    dad: Dad,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Dad {
    /// `sent` solicitations are out; the next one, or the end of the
    /// check, is at `next`.
    Tentative {
        sent: u8,
        next: Instant,
    },
    Preferred,
    Duplicate,
}

/// A message sent `left` more times, the next at `next`.
#[derive(Clone, Copy, Debug)]
struct Repeat {
    left: u8,
    next: Instant,
}

#[derive(Debug)]
enum Gateway {
    Configured {
        addr: Ipv6Addr,
        neighbor: Neighbor,
    },
    Learned {
        solicitations: Repeat,
        router: Option<Router>,
    },
}

#[derive(Debug)]
struct Router {
    addr: Ipv6Addr,
    until: Instant,
    neighbor: Neighbor,
}

/// A gateway's entry in the neighbor cache, in the states of RFC 4861
/// section 7.3.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Neighbor {
    /// The MAC is not known; the next multicast solicitation is at `next`.
    Incomplete { next: Instant },
    /// Confirmed until `until`.
    Reachable { mac: Mac, until: Instant },
    /// Known, but not confirmed lately.
    Stale { mac: Mac },
    /// Used while stale; checked at `probe`.
    Delay { mac: Mac, probe: Instant },
    /// Being checked: `sent` unicast solicitations are out, and the next
    /// one is at `next`.
    Probe { mac: Mac, sent: u8, next: Instant },
}

/// The solicitation a neighbor entry calls for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Solicit {
    /// To everyone who might have the address: broadcast ARP, or the
    /// address's solicited-node group.
    Multicast,
    /// To the MAC the entry holds, to check it.
    Unicast(Mac),
}

impl Neighbor {
    fn new(now: Instant) -> Neighbor {
        Neighbor::Incomplete { next: now }
    }

    fn mac(&self) -> Option<Mac> {
        match *self {
            Neighbor::Incomplete { .. } => None,
            Neighbor::Reachable { mac, .. }
            | Neighbor::Stale { mac }
            | Neighbor::Delay { mac, .. }
            | Neighbor::Probe { mac, .. } => Some(mac),
        }
    }

    /// When the entry next calls for a solicitation.
    fn due(&self) -> Option<Instant> {
        match *self {
            Neighbor::Incomplete { next } | Neighbor::Probe { next, .. } => Some(next),
            Neighbor::Delay { probe, .. } => Some(probe),
            Neighbor::Reachable { .. } | Neighbor::Stale { .. } => None,
        }
    }

    /// A reachable entry turns stale when its time is up (RFC 4861 section
    /// 7.3.3).
    fn expire(&mut self, now: Instant) {
        if let Neighbor::Reachable { mac, until } = *self
            && now >= until
        {
            *self = Neighbor::Stale { mac };
        }
    }

    /// The solicitation due at `now`, if any. After [`MAX_UNICAST_SOLICIT`]
    /// unanswered probes the entry is deleted and resolution starts over
    /// (RFC 4861 section 7.3.3).
    fn fire(&mut self, now: Instant) -> Option<Solicit> {
        let next = now + RETRANS_TIMER;
        match *self {
            Neighbor::Incomplete { next: at } if now >= at => {
                *self = Neighbor::Incomplete { next };
                Some(Solicit::Multicast)
            }
            Neighbor::Delay { mac, probe } if now >= probe => {
                *self = Neighbor::Probe { mac, sent: 1, next };
                Some(Solicit::Unicast(mac))
            }
            Neighbor::Probe {
                mac,
                sent,
                next: at,
            } if now >= at => {
                if sent >= MAX_UNICAST_SOLICIT {
                    *self = Neighbor::Incomplete { next };
                    Some(Solicit::Multicast)
                } else {
                    *self = Neighbor::Probe {
                        mac,
                        sent: sent + 1,
                        next,
                    };
                    Some(Solicit::Unicast(mac))
                }
            }
            _ => None,
        }
    }

    /// The gateway sent a message that carries its MAC but does not
    /// confirm it is reachable: a new or changed MAC makes the entry stale,
    /// and the same MAC changes nothing (RFC 4861 sections 6.3.4 and
    /// 7.2.3).
    fn heard(&mut self, mac: Mac) {
        if self.mac() != Some(mac) {
            *self = Neighbor::Stale { mac };
        }
    }

    /// A neighbor advertisement from the gateway, or an ARP reply, which
    /// counts as a solicited advertisement that overrides (RFC 4861 section
    /// 7.2.5).
    ///
    /// Returns whether the advertisement updated the entry. Only then does
    /// its Router flag count: an advertisement without a MAC for an
    /// incomplete entry is discarded, and one that names another MAC without
    /// the Override flag at most makes the entry stale and "does not update
    /// the entry in any other way".
    #[must_use]
    fn advertised(
        &mut self,
        now: Instant,
        mac: Option<Mac>,
        solicited: bool,
        overrides: bool,
    ) -> bool {
        let reachable = |mac| Neighbor::Reachable {
            mac,
            until: now + REACHABLE_TIME,
        };
        let Some(known) = self.mac() else {
            let Some(mac) = mac else {
                return false;
            };
            *self = if solicited {
                reachable(mac)
            } else {
                Neighbor::Stale { mac }
            };
            return true;
        };
        let changed = mac.is_some_and(|mac| mac != known);
        if changed && !overrides {
            if let Neighbor::Reachable { .. } = self {
                *self = Neighbor::Stale { mac: known };
            }
            return false;
        }
        let mac = mac.unwrap_or(known);
        if solicited {
            *self = reachable(mac);
        } else if changed {
            *self = Neighbor::Stale { mac };
        }
        true
    }

    /// A packet went to the gateway: a stale entry starts the wait before
    /// it is checked (RFC 4861 section 7.3.3).
    fn used(&mut self, now: Instant) {
        if let Neighbor::Stale { mac } = *self {
            *self = Neighbor::Delay {
                mac,
                probe: now + DELAY_FIRST_PROBE_TIME,
            };
        }
    }
}

impl Address {
    fn tentative(addr: Ipv6Addr, now: Instant) -> Address {
        Address {
            addr,
            dad: Dad::Tentative { sent: 0, next: now },
        }
    }

    fn state(&self) -> AddressState {
        match self.dad {
            Dad::Tentative { .. } => AddressState::Tentative,
            Dad::Preferred => AddressState::Preferred,
            Dad::Duplicate => AddressState::Duplicate,
        }
    }

    /// The check passes when the last solicitation got no answer for
    /// [`RETRANS_TIMER`] (RFC 4862 section 5.4).
    fn expire(&mut self, now: Instant) {
        if let Dad::Tentative { sent, next } = self.dad
            && sent >= DUP_ADDR_DETECT_TRANSMITS
            && now >= next
        {
            self.dad = Dad::Preferred;
        }
    }

    fn due(&self) -> Option<Instant> {
        match self.dad {
            Dad::Tentative { next, .. } => Some(next),
            _ => None,
        }
    }
}

impl V6 {
    fn addresses(&self) -> [&Address; 2] {
        [&self.link_local, &self.global]
    }

    fn state(&self, addr: Ipv6Addr) -> Option<AddressState> {
        self.addresses()
            .into_iter()
            .find(|a| a.addr == addr)
            .map(Address::state)
    }

    fn uses(&self, addr: Ipv6Addr) -> bool {
        self.state(addr) == Some(AddressState::Preferred)
    }

    /// Whether IPv6 still runs: not after the link-local address failed
    /// duplicate address detection (RFC 4862 section 5.4.5).
    fn enabled(&self) -> bool {
        self.link_local.dad != Dad::Duplicate
    }

    /// When the host can send from its link-local address: neighbor and
    /// router solicitations wait for it.
    fn ready(&self) -> Instant {
        match self.link_local.dad {
            Dad::Tentative { next, .. } => next,
            _ => Instant::ZERO,
        }
    }

    /// The groups the host listens to: all nodes, and the solicited-node
    /// group of each address.
    fn groups(&self) -> [Ipv6Addr; 3] {
        [
            ndp::ALL_NODES,
            ndp::solicited_node(self.link_local.addr),
            ndp::solicited_node(self.global.addr),
        ]
    }

    /// The gateway's address and entry, when there is one.
    fn gateway(&mut self) -> Option<(Ipv6Addr, &mut Neighbor)> {
        match &mut self.gateway {
            Gateway::Configured { addr, neighbor } => Some((*addr, neighbor)),
            Gateway::Learned {
                router: Some(r), ..
            } => Some((r.addr, &mut r.neighbor)),
            Gateway::Learned { router: None, .. } => None,
        }
    }

    fn expire(&mut self, now: Instant) {
        self.link_local.expire(now);
        self.global.expire(now);
        if let Gateway::Learned { router, .. } = &mut self.gateway
            && router.as_ref().is_some_and(|r| now >= r.until)
        {
            *router = None;
        }
        if let Some((_, neighbor)) = self.gateway() {
            neighbor.expire(now);
        }
    }
}

/// Whether a MAC can be a node's own: not all zeros and not a group.
fn station(mac: Mac) -> bool {
    mac != [0; 6] && !frame::is_group(&mac)
}

impl Host {
    /// A host as `config` describes it, starting at `now`. Its first frames
    /// are due at once.
    pub fn new(config: Config, now: Instant) -> Result<Host, ConfigError> {
        if !station(config.mac) {
            return Err(ConfigError::Mac(config.mac));
        }
        let v4 = config.ipv4.map(|c| -> Result<V4, ConfigError> {
            let bad = |a: Ipv4Addr| {
                a.is_unspecified() || a.is_broadcast() || a.is_multicast() || a.is_loopback()
            };
            for a in [c.address, c.gateway] {
                if bad(a) {
                    return Err(ConfigError::Ipv4(a));
                }
            }
            if c.gateway == c.address {
                return Err(ConfigError::Ipv4(c.gateway));
            }
            Ok(V4 {
                address: c.address,
                gateway: c.gateway,
                neighbor: Neighbor::new(now),
            })
        });
        let link_local = frame::link_local(config.mac);
        let v6 = config.ipv6.map(|c| -> Result<V6, ConfigError> {
            let bad = |a: Ipv6Addr| a.is_unspecified() || a.is_multicast() || a.is_loopback();
            if bad(c.address) || c.address.is_unicast_link_local() {
                return Err(ConfigError::Ipv6(c.address));
            }
            let gateway = match c.gateway {
                Ipv6Gateway::Configured(addr) => {
                    if bad(addr) || addr == c.address || addr == link_local {
                        return Err(ConfigError::Ipv6(addr));
                    }
                    Gateway::Configured {
                        addr,
                        neighbor: Neighbor::new(now),
                    }
                }
                Ipv6Gateway::FromRouterAdvertisements => Gateway::Learned {
                    solicitations: Repeat {
                        left: MAX_RTR_SOLICITATIONS,
                        next: now,
                    },
                    router: None,
                },
            };
            Ok(V6 {
                link_local: Address::tentative(link_local, now),
                global: Address::tentative(c.address, now),
                reports: Repeat {
                    left: MLD_ROBUSTNESS,
                    next: now,
                },
                gateway,
            })
        });
        Ok(Host {
            mac: config.mac,
            mtu: config.mtu,
            v4: v4.transpose()?,
            v6: v6.transpose()?,
            outbox: VecDeque::new(),
        })
    }

    /// The host's MAC.
    pub fn mac(&self) -> Mac {
        self.mac
    }

    /// The host's IPv6 link-local address, made from its MAC.
    pub fn link_local(&self) -> Ipv6Addr {
        frame::link_local(self.mac)
    }

    /// Where duplicate address detection stands for `addr`, or `None` if it
    /// is not one of the host's IPv6 addresses.
    pub fn address_state(&self, addr: Ipv6Addr) -> Option<AddressState> {
        self.v6.as_ref()?.state(addr)
    }

    /// The IPv4 gateway's MAC, once known.
    pub fn ipv4_gateway(&self) -> Option<Mac> {
        self.v4.as_ref()?.neighbor.mac()
    }

    /// The IPv6 gateway's address, when there is one, and its MAC, once
    /// known.
    pub fn ipv6_gateway(&self) -> Option<(Ipv6Addr, Option<Mac>)> {
        match &self.v6.as_ref()?.gateway {
            Gateway::Configured { addr, neighbor } => Some((*addr, neighbor.mac())),
            Gateway::Learned { router, .. } => router.as_ref().map(|r| (r.addr, r.neighbor.mac())),
        }
    }

    /// Whether the host takes in a frame to `dst`: its own MAC, broadcast,
    /// or the multicast MAC of an IPv6 group it listens to
    /// ([RFC 2464](https://www.rfc-editor.org/rfc/rfc2464) section 7).
    pub fn accepts(&self, dst: Mac) -> bool {
        dst == self.mac
            || dst == frame::BROADCAST
            || self.v6.as_ref().is_some_and(|v6| {
                v6.enabled() && v6.groups().iter().any(|g| frame::multicast_mac(*g) == dst)
            })
    }

    /// Applies what time alone changes: finished address checks, expired
    /// routers and reachable entries gone stale.
    fn expire(&mut self, now: Instant) {
        if let Some(v4) = &mut self.v4 {
            v4.neighbor.expire(now);
        }
        if let Some(v6) = &mut self.v6 {
            v6.expire(now);
        }
    }

    /// Reads one frame from the segment at `now`.
    pub fn receive<'a>(&mut self, now: Instant, bytes: &'a [u8]) -> Received<'a> {
        self.expire(now);
        let Some(f) = Frame::parse(bytes) else {
            return Received::Drop(Dropped::Malformed);
        };
        if !station(f.src) {
            return Received::Drop(Dropped::BadSource);
        }
        if f.src == self.mac {
            return Received::Drop(Dropped::Looped);
        }
        if !self.accepts(f.dst) {
            return Received::Drop(Dropped::NotForUs);
        }
        match f.ethertype {
            frame::ARP => self.arp(now, f.payload),
            frame::IPV4 => self.ipv4(f.payload),
            frame::IPV6 => self.ipv6(now, f.src, f.payload),
            _ => Received::Drop(Dropped::OtherType),
        }
    }

    fn arp<'a>(&mut self, now: Instant, payload: &[u8]) -> Received<'a> {
        let Some(v4) = &mut self.v4 else {
            return Received::Drop(Dropped::Off);
        };
        let Ok(p) = arp::Packet::receive(payload) else {
            return Received::Drop(Dropped::Malformed);
        };
        if !station(p.sender_mac) {
            return Received::Drop(Dropped::Malformed);
        }
        if p.sender_ip == v4.gateway {
            // A reply to the host confirms the gateway, as a solicited
            // advertisement does; anything else only names its MAC.
            if p.operation == arp::Operation::Reply
                && p.target_ip == v4.address
                && p.target_mac == self.mac
            {
                // A reply carries a MAC and overrides, so it always applies.
                let _ = v4.neighbor.advertised(now, Some(p.sender_mac), true, true);
            } else {
                v4.neighbor.heard(p.sender_mac);
            }
        }
        // An announcement asks nothing. Probes, from 0.0.0.0, are answered
        // so the prober sees the address is taken (RFC 5227 section 2.1.1).
        if p.operation == arp::Operation::Request
            && p.target_ip == v4.address
            && !p.is_announcement()
        {
            let reply = p.reply(self.mac);
            self.outbox.push_back(frame::frame(
                p.sender_mac,
                self.mac,
                frame::ARP,
                &reply.encode(),
            ));
        }
        Received::Handled
    }

    fn ipv4<'a>(&self, payload: &'a [u8]) -> Received<'a> {
        let Some(v4) = &self.v4 else {
            return Received::Drop(Dropped::Off);
        };
        let Some(p) = frame::ip_packet(frame::IPV4, payload) else {
            return Received::Drop(Dropped::Malformed);
        };
        if Ipv4Addr::new(p[16], p[17], p[18], p[19]) != v4.address {
            return Received::Drop(Dropped::NotOurs);
        }
        Received::World(p)
    }

    fn ipv6<'a>(&mut self, now: Instant, src: Mac, payload: &'a [u8]) -> Received<'a> {
        if !self.v6.as_ref().is_some_and(V6::enabled) {
            return Received::Drop(Dropped::Off);
        }
        let Some(p) = frame::ip_packet(frame::IPV6, payload) else {
            return Received::Drop(Dropped::Malformed);
        };
        // Neighbor discovery stays with the host. Anything else to its
        // address goes to the world, whose stack decides what to do with
        // headers it cannot read.
        match frame::upper(p) {
            Ok(Upper::Icmp6 {
                kind,
                msg,
                fragment,
            }) if frame::is_neighbor_discovery(kind) => {
                // Neighbor discovery is never fragmented (RFC 6980).
                if fragment {
                    return Received::Drop(Dropped::Malformed);
                }
                return self.neighbor_discovery(now, src, p, msg);
            }
            Ok(Upper::Problem) if frame::problem_hides_neighbor_discovery(p) => {
                return Received::Drop(Dropped::Malformed);
            }
            _ => {}
        }
        let v6 = self.v6.as_ref().expect("checked above");
        if !v6.uses(frame::destination_v6(p)) {
            return Received::Drop(Dropped::NotOurs);
        }
        Received::World(p)
    }

    fn neighbor_discovery<'a>(
        &mut self,
        now: Instant,
        src: Mac,
        packet: &[u8],
        msg: &[u8],
    ) -> Received<'a> {
        let Some(envelope) = Envelope::of(packet) else {
            return Received::Drop(Dropped::Malformed);
        };
        let Ok(message) = Message::receive(&envelope, msg) else {
            return Received::Drop(Dropped::Malformed);
        };
        let source_ll = message.source_link_layer();
        let target_ll = message.target_link_layer();
        if source_ll.is_some_and(|m| !station(m)) || target_ll.is_some_and(|m| !station(m)) {
            return Received::Drop(Dropped::Malformed);
        }
        let v6 = self.v6.as_mut().expect("the caller checked IPv6 is on");
        let mut answer = None;
        match message {
            Message::NeighborSolicitation(ns) => match v6.state(ns.target) {
                // Another node checks the same address: it is a duplicate.
                // A solicitation from a unicast address is address
                // resolution for an address the host does not use yet, and
                // goes unanswered (RFC 4862 section 5.4.3).
                Some(AddressState::Tentative) => {
                    if envelope.source.is_unspecified() {
                        Host::duplicate(v6, ns.target);
                    }
                }
                Some(AddressState::Preferred) => {
                    if let (Some(mac), Some((gateway, neighbor))) = (source_ll, v6.gateway())
                        && envelope.source == gateway
                    {
                        neighbor.heard(mac);
                    }
                    answer = Some((envelope.source, ns.target, source_ll.unwrap_or(src)));
                }
                Some(AddressState::Duplicate) | None => {}
            },
            Message::NeighborAdvertisement(na) => match v6.state(na.target) {
                // Another node already has the address (RFC 4862 section
                // 5.4.4).
                Some(AddressState::Tentative) => Host::duplicate(v6, na.target),
                Some(_) => {}
                None => {
                    if let Some((gateway, neighbor)) = v6.gateway()
                        && na.target == gateway
                    {
                        let applied =
                            neighbor.advertised(now, target_ll, na.solicited, na.overrides);
                        // A learned router that says, in an advertisement
                        // that updates its entry, that it is no longer one
                        // leaves the default router list (RFC 4861 section
                        // 7.2.5).
                        if let Gateway::Learned { router, .. } = &mut v6.gateway
                            && applied
                            && !na.router
                        {
                            *router = None;
                        }
                    }
                }
            },
            Message::RouterAdvertisement(ra) => {
                let from = envelope.source;
                let lifetime = Duration::from_secs(u64::from(ra.router_lifetime));
                match &mut v6.gateway {
                    Gateway::Configured { addr, neighbor } => {
                        if let Some(mac) = source_ll
                            && from == *addr
                        {
                            neighbor.heard(mac);
                        }
                    }
                    Gateway::Learned {
                        solicitations,
                        router,
                    } => match router {
                        Some(r) if r.addr == from => {
                            if lifetime.is_zero() {
                                *router = None;
                            } else {
                                r.until = now + lifetime;
                                if let Some(mac) = source_ll {
                                    r.neighbor.heard(mac);
                                }
                            }
                        }
                        // One default router at a time.
                        Some(_) => {}
                        None if !lifetime.is_zero() => {
                            let mut neighbor = Neighbor::new(now);
                            if let Some(mac) = source_ll {
                                neighbor.heard(mac);
                            }
                            *router = Some(Router {
                                addr: from,
                                until: now + lifetime,
                                neighbor,
                            });
                            solicitations.left = 0;
                        }
                        None => {}
                    },
                }
            }
            // Hosts ignore router solicitations (RFC 4861 section 6.2.6 is
            // for routers), and this host ignores redirects.
            Message::RouterSolicitation(_) | Message::Redirect(_) => {}
        }
        if let Some((source, target, mac)) = answer {
            self.advertise(source, target, mac);
        }
        Received::Handled
    }

    fn duplicate(v6: &mut V6, addr: Ipv6Addr) {
        for a in [&mut v6.link_local, &mut v6.global] {
            if a.addr == addr {
                a.dad = Dad::Duplicate;
            }
        }
    }

    /// Answers a neighbor solicitation from `source` for `target`, one of
    /// the host's addresses, as RFC 4861 section 7.2.4 says: to all nodes
    /// when the solicitation is duplicate address detection from the
    /// unspecified address, and otherwise to the source, at `mac`.
    fn advertise(&mut self, source: Ipv6Addr, target: Ipv6Addr, mac: Mac) {
        let to_all = source.is_unspecified();
        let na = Message::NeighborAdvertisement(NeighborAdvertisement {
            router: false,
            solicited: !to_all,
            overrides: true,
            target,
            options: vec![NdOption::TargetLinkLayer(self.mac)],
        });
        let (dst, dst_mac) = if to_all {
            (ndp::ALL_NODES, frame::multicast_mac(ndp::ALL_NODES))
        } else {
            (source, mac)
        };
        // A source no answer can go to, such as a multicast one, gets none.
        if let Ok(packet) = na.packet(target, dst) {
            self.outbox
                .push_back(frame::frame(dst_mac, self.mac, frame::IPV6, &packet));
        }
    }

    /// The next frame to send at `now`, or `None` when there is nothing to
    /// send until [`poll_at`](Host::poll_at) or the next frame in.
    pub fn transmit(&mut self, now: Instant) -> Option<Vec<u8>> {
        self.expire(now);
        self.run_timers(now);
        self.outbox.pop_front()
    }

    /// Queues the frames the timers call for at `now`.
    fn run_timers(&mut self, now: Instant) {
        let mac = self.mac;
        let mut out = Vec::new();
        if let Some(v6) = &mut self.v6
            && v6.enabled()
        {
            let link_local = v6.link_local.addr;
            let ll_ready = v6.link_local.dad == Dad::Preferred;
            // Join the groups before checking the addresses (RFC 4862
            // section 5.4.2).
            if v6.reports.left > 0 && now >= v6.reports.next {
                let source = if ll_ready {
                    link_local
                } else {
                    Ipv6Addr::UNSPECIFIED
                };
                out.push(report(mac, source, v6));
                v6.reports.left -= 1;
                v6.reports.next = now + UNSOLICITED_REPORT_INTERVAL;
            }
            for a in [&mut v6.link_local, &mut v6.global] {
                if let Dad::Tentative { sent, next } = a.dad
                    && sent < DUP_ADDR_DETECT_TRANSMITS
                    && now >= next
                {
                    out.push(solicitation(
                        mac,
                        Ipv6Addr::UNSPECIFIED,
                        a.addr,
                        Solicit::Multicast,
                        false,
                    ));
                    a.dad = Dad::Tentative {
                        sent: sent + 1,
                        next: now + RETRANS_TIMER,
                    };
                }
            }
            if ll_ready {
                if let Gateway::Learned {
                    solicitations,
                    router: None,
                } = &mut v6.gateway
                    && solicitations.left > 0
                    && now >= solicitations.next
                {
                    out.push(router_solicitation(mac, link_local));
                    solicitations.left -= 1;
                    solicitations.next = now + RTR_SOLICITATION_INTERVAL;
                }
                if let Some((gateway, neighbor)) = v6.gateway()
                    && let Some(how) = neighbor.fire(now)
                {
                    out.push(solicitation(mac, link_local, gateway, how, true));
                }
            }
        }
        if let Some(v4) = &mut self.v4
            && let Some(how) = v4.neighbor.fire(now)
        {
            let request = arp::Packet {
                operation: arp::Operation::Request,
                sender_mac: mac,
                sender_ip: v4.address,
                target_mac: [0; 6],
                target_ip: v4.gateway,
            };
            let dst = match how {
                Solicit::Multicast => frame::BROADCAST,
                Solicit::Unicast(m) => m,
            };
            out.push(frame::frame(dst, mac, frame::ARP, &request.encode()));
        }
        self.outbox.extend(out);
    }

    /// When the host's timers next call for a frame, or `None` if they do
    /// not until a frame comes in. Call [`transmit`](Host::transmit) then.
    pub fn poll_at(&self) -> Option<Instant> {
        let mut times = Vec::new();
        if let Some(v4) = &self.v4 {
            times.extend(v4.neighbor.due());
        }
        if let Some(v6) = &self.v6
            && v6.enabled()
        {
            if v6.reports.left > 0 {
                times.push(v6.reports.next);
            }
            times.extend(v6.addresses().iter().filter_map(|a| a.due()));
            // Solicitations wait for the link-local address.
            let ready = v6.ready();
            match &v6.gateway {
                Gateway::Configured { neighbor, .. } => {
                    times.extend(neighbor.due().map(|t| t.max(ready)));
                }
                Gateway::Learned {
                    router: Some(r), ..
                } => times.extend(r.neighbor.due().map(|t| t.max(ready))),
                Gateway::Learned {
                    solicitations,
                    router: None,
                } => {
                    if solicitations.left > 0 {
                        times.push(solicitations.next.max(ready));
                    }
                }
            }
        }
        times.into_iter().min()
    }

    /// The frame that carries `packet`, an IP packet from the world, at
    /// `now`: to the gateway of its family, or to the group MAC of a
    /// multicast or broadcast destination.
    pub fn send(&mut self, now: Instant, packet: &[u8]) -> Result<Vec<u8>, Unsent> {
        self.expire(now);
        let header = Header::parse(packet).ok_or(Unsent::Malformed)?;
        if packet.len() > usize::from(self.mtu) {
            return Err(Unsent::TooBig);
        }
        let neighbor = match header.src {
            IpAddr::V4(src) => {
                let v4 = self.v4.as_mut().ok_or(Unsent::Off)?;
                if src != v4.address {
                    return Err(Unsent::Source);
                }
                Some(&mut v4.neighbor)
            }
            IpAddr::V6(src) => {
                let v6 = self
                    .v6
                    .as_mut()
                    .filter(|v6| v6.enabled())
                    .ok_or(Unsent::Off)?;
                if !v6.uses(src) {
                    return Err(Unsent::Source);
                }
                v6.gateway().map(|(_, n)| n)
            }
        };
        let gateway = neighbor.as_ref().and_then(|n| n.mac());
        let (dst, ethertype) =
            frame::destination(packet, gateway, None).ok_or(Unsent::Unresolved)?;
        if let Some(n) = neighbor
            && Some(dst) == gateway
        {
            n.used(now);
        }
        Ok(frame::frame(dst, self.mac, ethertype, packet))
    }
}

/// The MLDv2 report that joins the solicited-node groups of the host's
/// addresses, with the record a join sends: change to exclude, with no
/// sources (RFC 3810 section 6.1). The all-nodes group is never reported
/// (RFC 3810 section 6).
fn report(mac: Mac, source: Ipv6Addr, v6: &V6) -> Vec<u8> {
    let mut groups: Vec<Ipv6Addr> = v6.groups()[1..].to_vec();
    groups.dedup();
    let report = Report {
        records: groups
            .into_iter()
            .map(|group| Record {
                kind: RecordType::ChangeToExclude,
                group,
                sources: vec![],
            })
            .collect(),
    };
    let packet = report
        .packet(source)
        .expect("a report from the link-local or unspecified address is valid");
    let dst = frame::multicast_mac(mld::ALL_MLDV2_ROUTERS);
    frame::frame(dst, mac, frame::IPV6, &packet)
}

/// A neighbor solicitation from `source` for `target`: to the target's
/// solicited-node group, or to the target at a known MAC. Duplicate
/// address detection sends from the unspecified address, without the
/// source link-layer address (RFC 4861 section 7.2.2; RFC 4862 section
/// 5.4.2).
fn solicitation(
    mac: Mac,
    source: Ipv6Addr,
    target: Ipv6Addr,
    how: Solicit,
    with_mac: bool,
) -> Vec<u8> {
    let ns = Message::NeighborSolicitation(NeighborSolicitation {
        target,
        options: if with_mac {
            vec![NdOption::SourceLinkLayer(mac)]
        } else {
            vec![]
        },
    });
    let (dst, dst_mac) = match how {
        Solicit::Multicast => {
            let group = ndp::solicited_node(target);
            (group, frame::multicast_mac(group))
        }
        Solicit::Unicast(m) => (target, m),
    };
    let packet = ns
        .packet(source, dst)
        .expect("a solicitation for a configured unicast address is valid");
    frame::frame(dst_mac, mac, frame::IPV6, &packet)
}

/// A router solicitation to all routers, from the link-local address with
/// the host's MAC (RFC 4861 section 6.3.7).
fn router_solicitation(mac: Mac, source: Ipv6Addr) -> Vec<u8> {
    let rs = Message::RouterSolicitation(RouterSolicitation {
        options: vec![NdOption::SourceLinkLayer(mac)],
    });
    let packet = rs
        .packet(source, ndp::ALL_ROUTERS)
        .expect("a router solicitation from a link-local address is valid");
    frame::frame(
        frame::multicast_mac(ndp::ALL_ROUTERS),
        mac,
        frame::IPV6,
        &packet,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::network::ip;
    use fictionet::stdlib::protocols::ndp::RouterAdvertisement;

    const MAC: Mac = [0x02, 0, 0, 0x12, 0x34, 0x56];
    const GW_MAC: Mac = [0x02, 0, 0, 0, 0, 0x01];
    const OTHER_MAC: Mac = [0x02, 0, 0, 0, 0, 0x77];
    const ADDR4: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);
    const GW4: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
    const ADDR6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10);
    const GW6: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    const REMOTE4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 5);
    const REMOTE6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 5);

    fn at(ms: u64) -> Instant {
        Instant::ZERO + Duration::from_millis(ms)
    }

    fn config(gateway: Ipv6Gateway) -> Config {
        Config {
            mac: MAC,
            mtu: 1500,
            ipv4: Some(Ipv4Config {
                address: ADDR4,
                gateway: GW4,
            }),
            ipv6: Some(Ipv6Config {
                address: ADDR6,
                gateway,
            }),
        }
    }

    fn host(gateway: Ipv6Gateway) -> Host {
        Host::new(config(gateway), Instant::ZERO).unwrap()
    }

    fn ll() -> Ipv6Addr {
        frame::link_local(MAC)
    }

    fn drain(h: &mut Host, now: Instant) -> Vec<Vec<u8>> {
        std::iter::from_fn(|| h.transmit(now)).collect()
    }

    /// A host whose addresses passed duplicate address detection, with
    /// what it sent at 0 and at 1 s.
    fn settled(gateway: Ipv6Gateway) -> (Host, Vec<Vec<u8>>) {
        let mut h = host(gateway);
        let mut sent = drain(&mut h, at(0));
        sent.extend(drain(&mut h, at(1000)));
        assert_eq!(h.address_state(ll()), Some(AddressState::Preferred));
        assert_eq!(h.address_state(ADDR6), Some(AddressState::Preferred));
        (h, sent)
    }

    /// What one sent frame is.
    #[derive(Debug, PartialEq, Eq)]
    enum Sent {
        Arp(Mac, arp::Packet),
        Nd(Mac, Envelope, Message),
        Mld(Mac, Ipv6Addr, Report),
        Ip(Mac, Vec<u8>),
    }

    fn read(f: &[u8]) -> Sent {
        let fr = Frame::parse(f).unwrap();
        assert_eq!(fr.src, MAC, "every frame is from the host's MAC");
        match fr.ethertype {
            frame::ARP => Sent::Arp(fr.dst, arp::Packet::receive(fr.payload).unwrap()),
            frame::IPV6 => {
                let p = frame::ip_packet(frame::IPV6, fr.payload).unwrap();
                if let Ok(report) = Report::from_packet(p) {
                    return Sent::Mld(fr.dst, frame::source_v6(p), report);
                }
                match frame::upper(p) {
                    Ok(Upper::Icmp6 { kind, msg, .. }) if frame::is_neighbor_discovery(kind) => {
                        let env = Envelope::of(p).unwrap();
                        Sent::Nd(fr.dst, env, Message::receive(&env, msg).unwrap())
                    }
                    _ => Sent::Ip(fr.dst, p.to_vec()),
                }
            }
            _ => Sent::Ip(
                fr.dst,
                frame::ip_packet(fr.ethertype, fr.payload).unwrap().to_vec(),
            ),
        }
    }

    fn eth(src: Mac, dst: Mac, ethertype: u16, payload: &[u8]) -> Vec<u8> {
        frame::frame(dst, src, ethertype, payload)
    }

    fn nd(src_mac: Mac, dst_mac: Mac, src: Ipv6Addr, dst: Ipv6Addr, m: Message) -> Vec<u8> {
        eth(src_mac, dst_mac, frame::IPV6, &m.packet(src, dst).unwrap())
    }

    fn arp_frame(
        dst: Mac,
        op: arp::Operation,
        sender: (Mac, Ipv4Addr),
        target: (Mac, Ipv4Addr),
    ) -> Vec<u8> {
        let p = arp::Packet {
            operation: op,
            sender_mac: sender.0,
            sender_ip: sender.1,
            target_mac: target.0,
            target_ip: target.1,
        };
        eth(sender.0, dst, frame::ARP, &p.encode())
    }

    fn ns(target: Ipv6Addr, mac: Option<Mac>) -> Message {
        Message::NeighborSolicitation(NeighborSolicitation {
            target,
            options: mac.map(NdOption::SourceLinkLayer).into_iter().collect(),
        })
    }

    fn na(
        target: Ipv6Addr,
        mac: Option<Mac>,
        router: bool,
        solicited: bool,
        overrides: bool,
    ) -> Message {
        Message::NeighborAdvertisement(NeighborAdvertisement {
            router,
            solicited,
            overrides,
            target,
            options: mac.map(NdOption::TargetLinkLayer).into_iter().collect(),
        })
    }

    fn ra(lifetime: u16, mac: Option<Mac>) -> Message {
        Message::RouterAdvertisement(RouterAdvertisement {
            cur_hop_limit: 64,
            managed: false,
            other: false,
            router_lifetime: lifetime,
            reachable_time: 0,
            retrans_timer: 0,
            options: mac.map(NdOption::SourceLinkLayer).into_iter().collect(),
        })
    }

    /// The gateway's solicited advertisement for itself, to the host.
    fn gateway_na(router: bool) -> Vec<u8> {
        nd(
            GW_MAC,
            MAC,
            GW6,
            ll(),
            na(GW6, Some(GW_MAC), router, true, true),
        )
    }

    fn arp_reply_from_gateway(mac: Mac) -> Vec<u8> {
        arp_frame(MAC, arp::Operation::Reply, (mac, GW4), (MAC, ADDR4))
    }

    fn packet4(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        ip::packet(src.into(), dst.into(), 17, &[0; 8]).0
    }

    fn packet6(src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
        ip::packet(src.into(), dst.into(), 17, &[0; 8]).0
    }

    fn sn_mac(addr: Ipv6Addr) -> Mac {
        frame::multicast_mac(ndp::solicited_node(addr))
    }

    #[test]
    fn config_refuses_addresses_a_host_cannot_use() {
        let base = config(Ipv6Gateway::Configured(GW6));
        let try_with = |f: &dyn Fn(&mut Config)| {
            let mut c = base;
            f(&mut c);
            Host::new(c, Instant::ZERO).err()
        };
        assert_eq!(try_with(&|_| {}), None);
        for mac in [[0; 6], frame::BROADCAST, [0x33, 0x33, 0, 0, 0, 1]] {
            assert_eq!(try_with(&|c| c.mac = mac), Some(ConfigError::Mac(mac)));
        }
        for bad in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::LOCALHOST,
            ADDR4,
        ] {
            assert_eq!(
                try_with(&|c| c.ipv4.as_mut().unwrap().gateway = bad),
                Some(ConfigError::Ipv4(bad))
            );
        }
        assert_eq!(
            try_with(&|c| c.ipv4.as_mut().unwrap().address = Ipv4Addr::UNSPECIFIED),
            Some(ConfigError::Ipv4(Ipv4Addr::UNSPECIFIED))
        );
        for bad in [
            Ipv6Addr::UNSPECIFIED,
            Ipv6Addr::LOCALHOST,
            ndp::ALL_NODES,
            GW6,
        ] {
            assert_eq!(
                try_with(&|c| c.ipv6.as_mut().unwrap().address = bad),
                Some(ConfigError::Ipv6(bad))
            );
        }
        for bad in [Ipv6Addr::UNSPECIFIED, ndp::ALL_ROUTERS, ADDR6, ll()] {
            assert_eq!(
                try_with(&|c| c.ipv6.as_mut().unwrap().gateway = Ipv6Gateway::Configured(bad)),
                Some(ConfigError::Ipv6(bad))
            );
        }
    }

    #[test]
    fn startup_joins_groups_then_checks_addresses_and_asks_for_the_gateway() {
        let mut h = host(Ipv6Gateway::Configured(GW6));
        let sent: Vec<Sent> = drain(&mut h, at(0)).iter().map(|f| read(f)).collect();
        let groups = [ndp::solicited_node(ll()), ndp::solicited_node(ADDR6)];
        assert_eq!(
            sent,
            vec![
                Sent::Mld(
                    frame::multicast_mac(mld::ALL_MLDV2_ROUTERS),
                    Ipv6Addr::UNSPECIFIED,
                    Report {
                        records: groups
                            .iter()
                            .map(|&group| Record {
                                kind: RecordType::ChangeToExclude,
                                group,
                                sources: vec![],
                            })
                            .collect()
                    }
                ),
                Sent::Nd(
                    sn_mac(ll()),
                    Envelope {
                        source: Ipv6Addr::UNSPECIFIED,
                        destination: ndp::solicited_node(ll()),
                        hop_limit: 255
                    },
                    ns(ll(), None)
                ),
                Sent::Nd(
                    sn_mac(ADDR6),
                    Envelope {
                        source: Ipv6Addr::UNSPECIFIED,
                        destination: ndp::solicited_node(ADDR6),
                        hop_limit: 255
                    },
                    ns(ADDR6, None)
                ),
                Sent::Arp(
                    frame::BROADCAST,
                    arp::Packet {
                        operation: arp::Operation::Request,
                        sender_mac: MAC,
                        sender_ip: ADDR4,
                        target_mac: [0; 6],
                        target_ip: GW4,
                    }
                ),
            ]
        );
        // Both addresses are tentative until RetransTimer passes.
        assert_eq!(h.address_state(ll()), Some(AddressState::Tentative));
        assert_eq!(h.address_state(ADDR6), Some(AddressState::Tentative));
        assert_eq!(h.poll_at(), Some(at(1000)));
        assert!(drain(&mut h, at(999)).is_empty());
        assert_eq!(h.address_state(ADDR6), Some(AddressState::Tentative));
    }

    #[test]
    fn addresses_that_share_a_solicited_node_group_report_it_once() {
        let mut c = config(Ipv6Gateway::Configured(GW6));
        // The same low 24 bits as the link-local address.
        let shared: Ipv6Addr = "2001:db8::12:3456".parse().unwrap();
        assert_eq!(ndp::solicited_node(shared), ndp::solicited_node(ll()));
        c.ipv6.as_mut().unwrap().address = shared;
        let mut h = Host::new(c, Instant::ZERO).unwrap();
        let Sent::Mld(_, _, report) = read(&drain(&mut h, at(0))[0]) else {
            panic!("the report comes first");
        };
        assert_eq!(
            report.records,
            vec![Record {
                kind: RecordType::ChangeToExclude,
                group: ndp::solicited_node(ll()),
                sources: vec![],
            }]
        );
    }

    #[test]
    fn mld_report_is_sent_twice_then_stops() {
        let mut h = host(Ipv6Gateway::Configured(GW6));
        drain(&mut h, at(0));
        let reports: Vec<Ipv6Addr> = drain(&mut h, at(1000))
            .iter()
            .filter_map(|f| match read(f) {
                Sent::Mld(_, src, _) => Some(src),
                _ => None,
            })
            .collect();
        // The repeat goes from the link-local address, which passed its
        // check at the same moment.
        assert_eq!(reports, vec![ll()]);
        for t in [2000, 3000, 10_000] {
            assert!(
                drain(&mut h, at(t))
                    .iter()
                    .all(|f| !matches!(read(f), Sent::Mld(..))),
                "no report at {t} ms"
            );
        }
    }

    #[test]
    fn dad_passes_and_then_the_ipv6_gateway_is_resolved() {
        let (mut h, sent) = settled(Ipv6Gateway::Configured(GW6));
        let at_1s: Vec<Sent> = sent
            .iter()
            .map(|f| read(f))
            .filter(|s| !matches!(s, Sent::Mld(..) | Sent::Arp(..)))
            .collect();
        assert_eq!(
            at_1s[2..],
            [Sent::Nd(
                sn_mac(GW6),
                Envelope {
                    source: ll(),
                    destination: ndp::solicited_node(GW6),
                    hop_limit: 255
                },
                ns(GW6, Some(MAC))
            )]
        );
        assert_eq!(h.ipv6_gateway(), Some((GW6, None)));
        // Packets to and from the checked address now flow.
        let inbound = eth(GW_MAC, MAC, frame::IPV6, &packet6(REMOTE6, ADDR6));
        assert!(matches!(h.receive(at(1000), &inbound), Received::World(_)));
    }

    #[test]
    fn tentative_addresses_are_not_used() {
        let mut h = host(Ipv6Gateway::Configured(GW6));
        drain(&mut h, at(0));
        let inbound = eth(GW_MAC, MAC, frame::IPV6, &packet6(REMOTE6, ADDR6));
        assert_eq!(
            h.receive(at(500), &inbound),
            Received::Drop(Dropped::NotOurs)
        );
        assert_eq!(
            h.send(at(500), &packet6(ADDR6, REMOTE6)),
            Err(Unsent::Source)
        );
        // No gateway solicitation before the link-local address is checked.
        assert!(drain(&mut h, at(500)).is_empty());
    }

    #[test]
    fn dad_conflict_from_another_check_marks_the_address_duplicate() {
        let mut h = host(Ipv6Gateway::Configured(GW6));
        drain(&mut h, at(0));
        let probe = nd(
            OTHER_MAC,
            sn_mac(ADDR6),
            Ipv6Addr::UNSPECIFIED,
            ndp::solicited_node(ADDR6),
            ns(ADDR6, None),
        );
        assert_eq!(h.receive(at(300), &probe), Received::Handled);
        assert!(
            drain(&mut h, at(300)).is_empty(),
            "a duplicate is not defended"
        );
        assert_eq!(h.address_state(ADDR6), Some(AddressState::Duplicate));
        drain(&mut h, at(1000));
        assert_eq!(
            h.address_state(ADDR6),
            Some(AddressState::Duplicate),
            "for good"
        );
        assert_eq!(h.address_state(ll()), Some(AddressState::Preferred));
        // The duplicate is neither used nor answered for.
        let inbound = eth(GW_MAC, MAC, frame::IPV6, &packet6(REMOTE6, ADDR6));
        assert_eq!(
            h.receive(at(1000), &inbound),
            Received::Drop(Dropped::NotOurs)
        );
        h.receive(at(1000), &gateway_na(true));
        assert_eq!(
            h.send(at(1000), &packet6(ADDR6, REMOTE6)),
            Err(Unsent::Source)
        );
        let ask = nd(
            GW_MAC,
            sn_mac(ADDR6),
            GW6,
            ndp::solicited_node(ADDR6),
            ns(ADDR6, Some(GW_MAC)),
        );
        assert_eq!(h.receive(at(1000), &ask), Received::Handled);
        assert!(drain(&mut h, at(1000)).is_empty());
    }

    #[test]
    fn link_local_conflict_turns_ipv6_off() {
        let mut h = host(Ipv6Gateway::FromRouterAdvertisements);
        drain(&mut h, at(0));
        // Another node advertises the link-local address.
        let claim = nd(
            OTHER_MAC,
            frame::multicast_mac(ndp::ALL_NODES),
            ll(),
            ndp::ALL_NODES,
            na(ll(), Some(OTHER_MAC), false, false, true),
        );
        assert_eq!(h.receive(at(200), &claim), Received::Handled);
        assert_eq!(h.address_state(ll()), Some(AddressState::Duplicate));
        // No router solicitation, and no IPv6 frames in or out.
        let sent: Vec<Sent> = drain(&mut h, at(1000)).iter().map(|f| read(f)).collect();
        assert!(sent.iter().all(|s| matches!(s, Sent::Arp(..))), "{sent:?}");
        assert!(!h.accepts(sn_mac(ADDR6)) && !h.accepts(frame::multicast_mac(ndp::ALL_NODES)));
        assert!(h.accepts(MAC) && h.accepts(frame::BROADCAST));
        assert_eq!(h.send(at(1000), &packet6(ADDR6, REMOTE6)), Err(Unsent::Off));
        let inbound = eth(GW_MAC, MAC, frame::IPV6, &packet6(REMOTE6, ADDR6));
        assert_eq!(h.receive(at(1000), &inbound), Received::Drop(Dropped::Off));
        assert_eq!(h.poll_at(), Some(at(2000)), "ARP keeps going");
    }

    #[test]
    fn address_resolution_for_a_tentative_address_and_looped_checks_are_ignored() {
        let mut h = host(Ipv6Gateway::Configured(GW6));
        let own = drain(&mut h, at(0));
        // Its own check, looped back by the segment.
        let looped = own.iter().find(|f| matches!(read(f), Sent::Nd(_, _, Message::NeighborSolicitation(ref n)) if n.target == ADDR6)).unwrap();
        assert_eq!(h.receive(at(100), looped), Received::Drop(Dropped::Looped));
        // Address resolution from a unicast source (RFC 4862 section 5.4.3).
        let ask = nd(
            GW_MAC,
            sn_mac(ADDR6),
            GW6,
            ndp::solicited_node(ADDR6),
            ns(ADDR6, Some(GW_MAC)),
        );
        assert_eq!(h.receive(at(100), &ask), Received::Handled);
        assert!(
            drain(&mut h, at(100)).is_empty(),
            "not answered while tentative"
        );
        drain(&mut h, at(1000));
        assert_eq!(h.address_state(ADDR6), Some(AddressState::Preferred));
    }

    #[test]
    fn arp_requests_for_the_host_are_answered() {
        let (mut h, _) = settled(Ipv6Gateway::Configured(GW6));
        let ask = |sender: Ipv4Addr, target: Ipv4Addr| {
            arp_frame(
                frame::BROADCAST,
                arp::Operation::Request,
                (OTHER_MAC, sender),
                ([0; 6], target),
            )
        };
        assert_eq!(h.receive(at(1000), &ask(REMOTE4, ADDR4)), Received::Handled);
        assert_eq!(
            drain(&mut h, at(1000))
                .iter()
                .map(|f| read(f))
                .collect::<Vec<_>>(),
            vec![Sent::Arp(
                OTHER_MAC,
                arp::Packet {
                    operation: arp::Operation::Reply,
                    sender_mac: MAC,
                    sender_ip: ADDR4,
                    target_mac: OTHER_MAC,
                    target_ip: REMOTE4,
                }
            )]
        );
        // A probe for the address is answered, so the prober sees it is taken.
        h.receive(at(1000), &ask(Ipv4Addr::UNSPECIFIED, ADDR4));
        let reply = drain(&mut h, at(1000));
        assert!(
            matches!(&read(&reply[0]), Sent::Arp(OTHER_MAC, p) if p.target_ip.is_unspecified() && p.sender_ip == ADDR4)
        );
        // Other addresses, announcements and replies get no answer.
        for f in [
            ask(REMOTE4, Ipv4Addr::new(203, 0, 113, 11)),
            ask(ADDR4, ADDR4),
            arp_frame(
                MAC,
                arp::Operation::Reply,
                (OTHER_MAC, REMOTE4),
                (MAC, ADDR4),
            ),
        ] {
            assert_eq!(h.receive(at(1000), &f), Received::Handled);
            assert!(drain(&mut h, at(1000)).is_empty());
        }
        // An answer goes to the MAC the request names.
        let mut named = ask(REMOTE4, ADDR4);
        named[6..12].copy_from_slice(&[0x02, 9, 9, 9, 9, 9]);
        h.receive(at(1000), &named);
        assert!(matches!(
            read(&drain(&mut h, at(1000))[0]),
            Sent::Arp(OTHER_MAC, _)
        ));
    }

    #[test]
    fn neighbor_solicitations_for_the_host_are_answered() {
        let (mut h, _) = settled(Ipv6Gateway::Configured(GW6));
        let answer =
            |h: &mut Host| -> Vec<Sent> { drain(h, at(1000)).iter().map(|f| read(f)).collect() };
        // Address resolution, to the source at the MAC it gives.
        for target in [ADDR6, ll()] {
            let f = nd(
                OTHER_MAC,
                sn_mac(target),
                REMOTE6,
                ndp::solicited_node(target),
                ns(target, Some([0x02, 5, 5, 5, 5, 5])),
            );
            assert_eq!(h.receive(at(1000), &f), Received::Handled);
            assert_eq!(
                answer(&mut h),
                vec![Sent::Nd(
                    [0x02, 5, 5, 5, 5, 5],
                    Envelope {
                        source: target,
                        destination: REMOTE6,
                        hop_limit: 255
                    },
                    na(target, Some(MAC), false, true, true)
                )]
            );
        }
        // Unicast reachability checks without the option go to the frame's
        // source MAC.
        let f = nd(OTHER_MAC, MAC, REMOTE6, ADDR6, ns(ADDR6, None));
        h.receive(at(1000), &f);
        assert!(
            matches!(&answer(&mut h)[..], [Sent::Nd(OTHER_MAC, e, _)] if e.destination == REMOTE6)
        );
        // Duplicate address detection by another node is answered to all
        // nodes, unsolicited.
        let f = nd(
            OTHER_MAC,
            sn_mac(ADDR6),
            Ipv6Addr::UNSPECIFIED,
            ndp::solicited_node(ADDR6),
            ns(ADDR6, None),
        );
        h.receive(at(1000), &f);
        assert_eq!(
            answer(&mut h),
            vec![Sent::Nd(
                frame::multicast_mac(ndp::ALL_NODES),
                Envelope {
                    source: ADDR6,
                    destination: ndp::ALL_NODES,
                    hop_limit: 255
                },
                na(ADDR6, Some(MAC), false, false, true)
            )]
        );
        assert_eq!(h.address_state(ADDR6), Some(AddressState::Preferred));
        // Not for the host's address: no answer.
        let other: Ipv6Addr = "2001:db8::99".parse().unwrap();
        let f = nd(
            OTHER_MAC,
            sn_mac(other),
            REMOTE6,
            ndp::solicited_node(other),
            ns(other, Some(OTHER_MAC)),
        );
        assert_eq!(
            h.receive(at(1000), &f),
            Received::Drop(Dropped::NotForUs),
            "not a group it joined"
        );
        let f = nd(OTHER_MAC, MAC, REMOTE6, other, ns(other, Some(OTHER_MAC)));
        assert_eq!(h.receive(at(1000), &f), Received::Handled);
        assert!(answer(&mut h).is_empty());
    }

    #[test]
    fn ipv4_gateway_is_asked_every_second_until_it_answers() {
        let mut h = host(Ipv6Gateway::Configured(GW6));
        let arps = |h: &mut Host, t| {
            drain(h, at(t))
                .iter()
                .filter(|f| matches!(read(f), Sent::Arp(frame::BROADCAST, _)))
                .count()
        };
        assert_eq!(arps(&mut h, 0), 1);
        assert_eq!(arps(&mut h, 500), 0);
        assert_eq!(arps(&mut h, 1000), 1);
        assert_eq!(arps(&mut h, 1999), 0);
        assert_eq!(arps(&mut h, 2000), 1);
        assert_eq!(arps(&mut h, 3000), 1);
        assert_eq!(
            h.send(at(3000), &packet4(ADDR4, REMOTE4)),
            Err(Unsent::Unresolved)
        );
        assert_eq!(
            h.receive(at(3200), &arp_reply_from_gateway(GW_MAC)),
            Received::Handled
        );
        assert_eq!(h.ipv4_gateway(), Some(GW_MAC));
        for t in [4000, 5000, 20_000] {
            assert_eq!(arps(&mut h, t), 0, "no more requests at {t} ms");
        }
        let f = h.send(at(20_000), &packet4(ADDR4, REMOTE4)).unwrap();
        assert_eq!(read(&f), Sent::Ip(GW_MAC, packet4(ADDR4, REMOTE4)));
    }

    #[test]
    fn ipv6_gateway_is_asked_every_second_until_it_answers() {
        let (mut h, _) = settled(Ipv6Gateway::Configured(GW6));
        let solicitations = |h: &mut Host, t| {
            drain(h, at(t))
                .iter()
                .filter(|f| matches!(read(f), Sent::Nd(m, _, Message::NeighborSolicitation(ref n)) if m == sn_mac(GW6) && n.target == GW6))
                .count()
        };
        assert_eq!(h.poll_at(), Some(at(2000)));
        for t in [2000, 3000, 4000, 5000] {
            assert!(h.poll_at() <= Some(at(t)));
            assert_eq!(solicitations(&mut h, t), 1, "at {t} ms");
        }
        assert_eq!(
            h.send(at(5000), &packet6(ADDR6, REMOTE6)),
            Err(Unsent::Unresolved)
        );
        assert_eq!(h.receive(at(5100), &gateway_na(true)), Received::Handled);
        assert_eq!(h.ipv6_gateway(), Some((GW6, Some(GW_MAC))));
        assert_eq!(solicitations(&mut h, 6000), 0);
        let f = h.send(at(6000), &packet6(ADDR6, REMOTE6)).unwrap();
        assert_eq!(read(&f), Sent::Ip(GW_MAC, packet6(ADDR6, REMOTE6)));
        // From the link-local address too.
        assert!(h.send(at(6000), &packet6(ll(), REMOTE6)).is_ok());
    }

    #[test]
    fn router_solicitations_then_a_router_advertisement() {
        let (mut h, sent) = settled(Ipv6Gateway::FromRouterAdvertisements);
        let rs = |s: &Sent| matches!(s, Sent::Nd(m, e, Message::RouterSolicitation(r)) if *m == frame::multicast_mac(ndp::ALL_ROUTERS) && e.source == ll() && e.destination == ndp::ALL_ROUTERS && r.options == vec![NdOption::SourceLinkLayer(MAC)]);
        assert_eq!(
            sent.iter().filter(|f| rs(&read(f))).count(),
            1,
            "the first at 1 s"
        );
        assert_eq!(h.ipv6_gateway(), None);
        let count = |h: &mut Host, t| drain(h, at(t)).iter().filter(|f| rs(&read(f))).count();
        assert_eq!(count(&mut h, 4999), 0);
        assert_eq!(count(&mut h, 5000), 1);
        assert_eq!(count(&mut h, 9000), 1);
        assert_eq!(count(&mut h, 13_000), 0, "MAX_RTR_SOLICITATIONS sent");
        assert_eq!(count(&mut h, 60_000), 0);
        assert_eq!(h.poll_at(), Some(at(61_000)), "only ARP is left");
        assert_eq!(
            h.send(at(60_000), &packet6(ADDR6, REMOTE6)),
            Err(Unsent::Unresolved)
        );
        // A router advertises itself with its MAC.
        let advert = nd(
            GW_MAC,
            frame::multicast_mac(ndp::ALL_NODES),
            GW6,
            ndp::ALL_NODES,
            ra(1800, Some(GW_MAC)),
        );
        assert_eq!(h.receive(at(61_000), &advert), Received::Handled);
        assert_eq!(h.ipv6_gateway(), Some((GW6, Some(GW_MAC))));
        let f = h.send(at(61_000), &packet6(ADDR6, REMOTE6)).unwrap();
        assert_eq!(read(&f), Sent::Ip(GW_MAC, packet6(ADDR6, REMOTE6)));
        // It stops being the router when it says so.
        let gone = nd(
            GW_MAC,
            frame::multicast_mac(ndp::ALL_NODES),
            GW6,
            ndp::ALL_NODES,
            ra(0, Some(GW_MAC)),
        );
        h.receive(at(62_000), &gone);
        assert_eq!(h.ipv6_gateway(), None);
        assert_eq!(
            h.send(at(62_000), &packet6(ADDR6, REMOTE6)),
            Err(Unsent::Unresolved)
        );
        // And when its lifetime runs out.
        h.receive(
            at(63_000),
            &nd(
                GW_MAC,
                frame::multicast_mac(ndp::ALL_NODES),
                GW6,
                ndp::ALL_NODES,
                ra(10, Some(GW_MAC)),
            ),
        );
        assert!(h.send(at(72_999), &packet6(ADDR6, REMOTE6)).is_ok());
        assert_eq!(
            h.send(at(73_000), &packet6(ADDR6, REMOTE6)),
            Err(Unsent::Unresolved)
        );
        // A router that advertises lifetime 0 is never taken.
        h.receive(at(74_000), &gone);
        assert_eq!(h.ipv6_gateway(), None);
    }

    #[test]
    fn an_advertisement_stops_router_solicitations() {
        let (mut h, _) = settled(Ipv6Gateway::FromRouterAdvertisements);
        let advert = nd(GW_MAC, MAC, GW6, ll(), ra(1800, Some(GW_MAC)));
        h.receive(at(2000), &advert);
        let sent: Vec<Sent> = drain(&mut h, at(5000)).iter().map(|f| read(f)).collect();
        assert!(
            !sent
                .iter()
                .any(|s| matches!(s, Sent::Nd(_, _, Message::RouterSolicitation(_))))
        );
    }

    #[test]
    fn a_router_without_its_mac_is_resolved() {
        let (mut h, _) = settled(Ipv6Gateway::FromRouterAdvertisements);
        let advert = nd(
            GW_MAC,
            frame::multicast_mac(ndp::ALL_NODES),
            GW6,
            ndp::ALL_NODES,
            ra(1800, None),
        );
        h.receive(at(1500), &advert);
        assert_eq!(h.ipv6_gateway(), Some((GW6, None)));
        assert_eq!(h.poll_at(), Some(at(1500)));
        let sent: Vec<Sent> = drain(&mut h, at(1500)).iter().map(|f| read(f)).collect();
        assert_eq!(
            sent,
            vec![Sent::Nd(
                sn_mac(GW6),
                Envelope {
                    source: ll(),
                    destination: ndp::solicited_node(GW6),
                    hop_limit: 255
                },
                ns(GW6, Some(MAC))
            )]
        );
        h.receive(at(1600), &gateway_na(true));
        assert_eq!(h.ipv6_gateway(), Some((GW6, Some(GW_MAC))));
        // A router that says it is no longer one is dropped.
        h.receive(at(1700), &gateway_na(false));
        assert_eq!(h.ipv6_gateway(), None);
    }

    /// An unsolicited advertisement for the router with R=0, from another
    /// node on the segment, to all nodes.
    fn not_a_router(mac: Option<Mac>) -> Vec<u8> {
        nd(
            OTHER_MAC,
            frame::multicast_mac(ndp::ALL_NODES),
            GW6,
            ndp::ALL_NODES,
            na(GW6, mac, false, false, false),
        )
    }

    #[test]
    fn an_advertisement_without_a_mac_for_an_unresolved_router_is_discarded() {
        let (mut h, _) = settled(Ipv6Gateway::FromRouterAdvertisements);
        let advert = nd(
            GW_MAC,
            frame::multicast_mac(ndp::ALL_NODES),
            GW6,
            ndp::ALL_NODES,
            ra(1800, None),
        );
        h.receive(at(1500), &advert);
        assert_eq!(h.ipv6_gateway(), Some((GW6, None)));
        // RFC 4861 section 7.2.5: with the entry INCOMPLETE and no target
        // link-layer address, the advertisement is discarded, IsRouter
        // included.
        assert_eq!(h.receive(at(1600), &not_a_router(None)), Received::Handled);
        assert_eq!(h.ipv6_gateway(), Some((GW6, None)));
    }

    #[test]
    fn an_advertisement_that_does_not_override_leaves_the_router() {
        let (mut h, _) = settled(Ipv6Gateway::FromRouterAdvertisements);
        let advert = nd(
            GW_MAC,
            frame::multicast_mac(ndp::ALL_NODES),
            GW6,
            ndp::ALL_NODES,
            ra(1800, Some(GW_MAC)),
        );
        h.receive(at(1500), &advert);
        h.receive(at(1600), &gateway_na(true));
        assert_eq!(h.ipv6_gateway(), Some((GW6, Some(GW_MAC))));
        // RFC 4861 section 7.2.5: O=0 with another MAC only makes the entry
        // stale and does not update it in any other way.
        h.receive(at(1700), &not_a_router(Some(OTHER_MAC)));
        assert_eq!(h.ipv6_gateway(), Some((GW6, Some(GW_MAC))));
        let f = h.send(at(1700), &packet6(ADDR6, REMOTE6)).unwrap();
        assert_eq!(read(&f), Sent::Ip(GW_MAC, packet6(ADDR6, REMOTE6)));
    }

    #[test]
    fn gateway_macs_are_learned_from_unsolicited_messages() {
        // An ARP request from the gateway to someone else.
        let mut h = host(Ipv6Gateway::Configured(GW6));
        let f = arp_frame(
            frame::BROADCAST,
            arp::Operation::Request,
            (GW_MAC, GW4),
            ([0; 6], REMOTE4),
        );
        assert_eq!(h.receive(at(0), &f), Received::Handled);
        assert_eq!(h.ipv4_gateway(), Some(GW_MAC));

        // The gateway resolving the host's address.
        let (mut h, _) = settled(Ipv6Gateway::Configured(GW6));
        let f = nd(
            GW_MAC,
            sn_mac(ADDR6),
            GW6,
            ndp::solicited_node(ADDR6),
            ns(ADDR6, Some(GW_MAC)),
        );
        h.receive(at(1000), &f);
        assert_eq!(h.ipv6_gateway(), Some((GW6, Some(GW_MAC))));

        // A router advertisement from the configured gateway.
        let (mut h, _) = settled(Ipv6Gateway::Configured(GW6));
        h.receive(
            at(1000),
            &nd(
                GW_MAC,
                frame::multicast_mac(ndp::ALL_NODES),
                GW6,
                ndp::ALL_NODES,
                ra(0, Some(GW_MAC)),
            ),
        );
        assert_eq!(h.ipv6_gateway(), Some((GW6, Some(GW_MAC))));
        // An unsolicited advertisement that overrides moves the gateway.
        let moved = [0x02, 0, 0, 0, 0, 0x02];
        let f = nd(
            moved,
            frame::multicast_mac(ndp::ALL_NODES),
            GW6,
            ndp::ALL_NODES,
            na(GW6, Some(moved), true, false, true),
        );
        h.receive(at(1100), &f);
        assert_eq!(h.ipv6_gateway(), Some((GW6, Some(moved))));
        // One that does not override leaves it.
        let f = nd(
            GW_MAC,
            frame::multicast_mac(ndp::ALL_NODES),
            GW6,
            ndp::ALL_NODES,
            na(GW6, Some(GW_MAC), true, false, false),
        );
        h.receive(at(1200), &f);
        assert_eq!(h.ipv6_gateway(), Some((GW6, Some(moved))));
        // An unsolicited advertisement before the MAC is known teaches it.
        let mut h = host(Ipv6Gateway::Configured(GW6));
        drain(&mut h, at(0));
        h.receive(
            at(100),
            &nd(
                GW_MAC,
                frame::multicast_mac(ndp::ALL_NODES),
                GW6,
                ndp::ALL_NODES,
                na(GW6, Some(GW_MAC), true, false, true),
            ),
        );
        assert_eq!(h.ipv6_gateway(), Some((GW6, Some(GW_MAC))));
        // A new ARP MAC from the gateway replaces the old one.
        h.receive(at(100), &arp_reply_from_gateway(GW_MAC));
        h.receive(
            at(200),
            &arp_frame(
                frame::BROADCAST,
                arp::Operation::Request,
                (moved, GW4),
                ([0; 6], ADDR4),
            ),
        );
        assert_eq!(h.ipv4_gateway(), Some(moved));
    }

    #[test]
    fn other_senders_teach_nothing() {
        let (mut h, _) = settled(Ipv6Gateway::FromRouterAdvertisements);
        // ARP from other addresses.
        h.receive(
            at(1000),
            &arp_frame(
                frame::BROADCAST,
                arp::Operation::Request,
                (OTHER_MAC, REMOTE4),
                ([0; 6], GW4),
            ),
        );
        h.receive(
            at(1000),
            &arp_frame(
                MAC,
                arp::Operation::Reply,
                (OTHER_MAC, REMOTE4),
                (MAC, ADDR4),
            ),
        );
        assert_eq!(h.ipv4_gateway(), None);
        // Advertisements for other targets.
        h.receive(
            at(1000),
            &nd(
                OTHER_MAC,
                MAC,
                GW6,
                ll(),
                na(GW6, Some(OTHER_MAC), true, true, true),
            ),
        );
        assert_eq!(h.ipv6_gateway(), None, "no router yet");
        h.receive(
            at(1000),
            &nd(
                GW_MAC,
                frame::multicast_mac(ndp::ALL_NODES),
                GW6,
                ndp::ALL_NODES,
                ra(1800, Some(GW_MAC)),
            ),
        );
        let other: Ipv6Addr = "fe80::2".parse().unwrap();
        h.receive(
            at(1000),
            &nd(
                OTHER_MAC,
                MAC,
                other,
                ll(),
                na(other, Some(OTHER_MAC), true, true, true),
            ),
        );
        // A second router while the first one lasts.
        h.receive(
            at(1000),
            &nd(
                OTHER_MAC,
                frame::multicast_mac(ndp::ALL_NODES),
                other,
                ndp::ALL_NODES,
                ra(1800, Some(OTHER_MAC)),
            ),
        );
        assert_eq!(h.ipv6_gateway(), Some((GW6, Some(GW_MAC))));
        // A solicitation from another node for the host carries its MAC,
        // but it is not the gateway's.
        h.receive(
            at(1000),
            &nd(
                OTHER_MAC,
                sn_mac(ADDR6),
                other,
                ndp::solicited_node(ADDR6),
                ns(ADDR6, Some(OTHER_MAC)),
            ),
        );
        assert_eq!(h.ipv6_gateway(), Some((GW6, Some(GW_MAC))));
    }

    #[test]
    fn a_stale_gateway_is_probed_and_forgotten_when_silent() {
        let mut h = host(Ipv6Gateway::Configured(GW6));
        drain(&mut h, at(0));
        h.receive(at(0), &arp_reply_from_gateway(GW_MAC));
        let arps = |h: &mut Host, t| -> Vec<Mac> {
            drain(h, at(t))
                .iter()
                .filter_map(|f| match read(f) {
                    Sent::Arp(dst, p) if p.target_ip == GW4 => Some(dst),
                    _ => None,
                })
                .collect()
        };
        // Reachable for REACHABLE_TIME, then stale: still used, not asked.
        assert!(h.send(at(29_999), &packet4(ADDR4, REMOTE4)).is_ok());
        assert!(arps(&mut h, 40_000).is_empty());
        // Used while stale: DELAY_FIRST_PROBE_TIME, then unicast probes.
        assert!(h.send(at(40_000), &packet4(ADDR4, REMOTE4)).is_ok());
        assert!(arps(&mut h, 44_999).is_empty());
        assert_eq!(arps(&mut h, 45_000), vec![GW_MAC]);
        assert!(
            h.send(at(45_500), &packet4(ADDR4, REMOTE4)).is_ok(),
            "used while probed"
        );
        assert_eq!(arps(&mut h, 46_000), vec![GW_MAC]);
        assert_eq!(arps(&mut h, 47_000), vec![GW_MAC]);
        // Three unanswered probes: forgotten, and asked for by broadcast.
        assert_eq!(arps(&mut h, 48_000), vec![frame::BROADCAST]);
        assert_eq!(h.ipv4_gateway(), None);
        assert_eq!(
            h.send(at(48_000), &packet4(ADDR4, REMOTE4)),
            Err(Unsent::Unresolved)
        );

        // A probe that is answered makes it reachable again.
        let mut h = host(Ipv6Gateway::Configured(GW6));
        drain(&mut h, at(0));
        h.receive(at(0), &arp_reply_from_gateway(GW_MAC));
        h.send(at(30_000), &packet4(ADDR4, REMOTE4)).unwrap();
        assert_eq!(arps(&mut h, 35_000), vec![GW_MAC]);
        h.receive(at(35_100), &arp_reply_from_gateway(GW_MAC));
        assert!(arps(&mut h, 36_000).is_empty());
        assert!(arps(&mut h, 60_000).is_empty());
    }

    #[test]
    fn the_ipv6_gateway_is_probed_with_unicast_solicitations() {
        let (mut h, _) = settled(Ipv6Gateway::Configured(GW6));
        h.receive(at(1000), &gateway_na(true));
        h.send(at(31_000), &packet6(ADDR6, REMOTE6)).unwrap();
        let sent: Vec<Sent> = drain(&mut h, at(36_000))
            .iter()
            .map(|f| read(f))
            .filter(|s| !matches!(s, Sent::Arp(..)))
            .collect();
        assert_eq!(
            sent,
            vec![Sent::Nd(
                GW_MAC,
                Envelope {
                    source: ll(),
                    destination: GW6,
                    hop_limit: 255
                },
                ns(GW6, Some(MAC))
            )]
        );
    }

    #[test]
    fn sending_needs_a_resolved_gateway_a_usable_source_and_room() {
        let (mut h, _) = settled(Ipv6Gateway::Configured(GW6));
        assert_eq!(
            h.send(at(1000), &packet4(ADDR4, REMOTE4)),
            Err(Unsent::Unresolved)
        );
        assert_eq!(
            h.send(at(1000), &packet6(ADDR6, REMOTE6)),
            Err(Unsent::Unresolved)
        );
        h.receive(at(1000), &arp_reply_from_gateway(GW_MAC));
        h.receive(at(1000), &gateway_na(true));
        assert_eq!(
            h.send(at(1000), &packet4(REMOTE4, ADDR4)),
            Err(Unsent::Source)
        );
        assert_eq!(
            h.send(at(1000), &packet6(REMOTE6, ADDR6)),
            Err(Unsent::Source)
        );
        assert_eq!(h.send(at(1000), &[0x45, 0, 0]), Err(Unsent::Malformed));
        let full = ip::packet(ADDR4.into(), REMOTE4.into(), 17, &[0; 1480]).0;
        assert!(h.send(at(1000), &full).is_ok());
        let over = ip::packet(ADDR4.into(), REMOTE4.into(), 17, &[0; 1481]).0;
        assert_eq!(h.send(at(1000), &over), Err(Unsent::TooBig));
        // Multicast and broadcast go to the group's MAC.
        let f = h.send(at(1000), &packet6(ADDR6, ndp::ALL_NODES)).unwrap();
        assert!(matches!(read(&f), Sent::Ip(m, _) if m == frame::multicast_mac(ndp::ALL_NODES)));
        let f = h
            .send(at(1000), &packet4(ADDR4, Ipv4Addr::BROADCAST))
            .unwrap();
        assert!(matches!(read(&f), Sent::Ip(frame::BROADCAST, _)));
        // A family the host does not have.
        let mut c = config(Ipv6Gateway::Configured(GW6));
        c.ipv6 = None;
        let mut h4 = Host::new(c, Instant::ZERO).unwrap();
        assert_eq!(h4.send(at(0), &packet6(ADDR6, REMOTE6)), Err(Unsent::Off));
        let inbound = eth(GW_MAC, MAC, frame::IPV6, &packet6(REMOTE6, ADDR6));
        assert_eq!(h4.receive(at(0), &inbound), Received::Drop(Dropped::Off));
        assert!(!h4.accepts(frame::multicast_mac(ndp::ALL_NODES)));
        c.ipv4 = None;
        c.ipv6 = Some(Ipv6Config {
            address: ADDR6,
            gateway: Ipv6Gateway::Configured(GW6),
        });
        let mut h6 = Host::new(c, Instant::ZERO).unwrap();
        assert_eq!(h6.send(at(0), &packet4(ADDR4, REMOTE4)), Err(Unsent::Off));
        let arp = arp_frame(
            frame::BROADCAST,
            arp::Operation::Request,
            (GW_MAC, GW4),
            ([0; 6], ADDR4),
        );
        assert_eq!(h6.receive(at(0), &arp), Received::Drop(Dropped::Off));
    }

    #[test]
    fn the_receive_filter_takes_the_host_broadcast_and_joined_groups() {
        let h = host(Ipv6Gateway::Configured(GW6));
        for mac in [
            MAC,
            frame::BROADCAST,
            frame::multicast_mac(ndp::ALL_NODES),
            sn_mac(ll()),
            sn_mac(ADDR6),
        ] {
            assert!(h.accepts(mac), "{mac:02x?}");
        }
        for mac in [
            OTHER_MAC,
            frame::multicast_mac(ndp::ALL_ROUTERS),
            frame::multicast_mac(mld::ALL_MLDV2_ROUTERS),
            sn_mac("2001:db8::99".parse().unwrap()),
            [0x01, 0x00, 0x5e, 0, 0, 1],
        ] {
            assert!(!h.accepts(mac), "{mac:02x?}");
        }
    }

    #[test]
    fn received_packets_go_to_the_world_only_when_addressed_to_the_host() {
        let (mut h, _) = settled(Ipv6Gateway::Configured(GW6));
        let p = packet4(REMOTE4, ADDR4);
        // Padding is cut off.
        assert_eq!(
            h.receive(at(1000), &eth(GW_MAC, MAC, frame::IPV4, &p)),
            Received::World(&p[..])
        );
        let elsewhere = eth(
            GW_MAC,
            MAC,
            frame::IPV4,
            &packet4(REMOTE4, Ipv4Addr::new(203, 0, 113, 11)),
        );
        assert_eq!(
            h.receive(at(1000), &elsewhere),
            Received::Drop(Dropped::NotOurs)
        );
        for dst in [ADDR6, ll()] {
            let p = packet6(REMOTE6, dst);
            assert_eq!(
                h.receive(at(1000), &eth(GW_MAC, MAC, frame::IPV6, &p)),
                Received::World(&p[..])
            );
        }
        let p = packet6(REMOTE6, ndp::ALL_NODES);
        let f = eth(
            GW_MAC,
            frame::multicast_mac(ndp::ALL_NODES),
            frame::IPV6,
            &p,
        );
        assert_eq!(h.receive(at(1000), &f), Received::Drop(Dropped::NotOurs));
        // Neighbor discovery to the host's address never reaches the world.
        let f = nd(GW_MAC, MAC, GW6, ADDR6, ns(ADDR6, Some(GW_MAC)));
        assert_eq!(h.receive(at(1000), &f), Received::Handled);
    }

    #[test]
    fn hostile_frames_are_dropped_without_panics() {
        let (mut h, _) = settled(Ipv6Gateway::FromRouterAdvertisements);
        let all_nodes = frame::multicast_mac(ndp::ALL_NODES);
        let samples = vec![
            arp_frame(
                frame::BROADCAST,
                arp::Operation::Request,
                (GW_MAC, GW4),
                ([0; 6], ADDR4),
            ),
            nd(
                GW_MAC,
                sn_mac(ADDR6),
                GW6,
                ndp::solicited_node(ADDR6),
                ns(ADDR6, Some(GW_MAC)),
            ),
            nd(
                GW_MAC,
                all_nodes,
                GW6,
                ndp::ALL_NODES,
                ra(1800, Some(GW_MAC)),
            ),
            nd(
                GW_MAC,
                MAC,
                GW6,
                ll(),
                na(GW6, Some(GW_MAC), true, true, true),
            ),
            eth(GW_MAC, MAC, frame::IPV4, &packet4(REMOTE4, ADDR4)),
            eth(GW_MAC, MAC, frame::IPV6, &packet6(REMOTE6, ADDR6)),
        ];
        for f in &samples {
            for cut in 0..f.len() {
                h.receive(at(1000), &f[..cut]);
            }
            for i in 0..f.len() {
                for v in [0x00, 0x01, 0x80, 0xff] {
                    let mut g = f.clone();
                    g[i] = v;
                    h.receive(at(1000), &g);
                }
            }
            drain(&mut h, at(1000));
        }
        // The sweep can teach the router: a changed source MAC still
        // carries a valid advertisement. The checks below start afresh.
        let (mut h, _) = settled(Ipv6Gateway::FromRouterAdvertisements);
        assert_eq!(
            h.receive(at(1000), &[0; 13]),
            Received::Drop(Dropped::Malformed)
        );
        // Source MACs no node sends from.
        for src in [[0; 6], frame::BROADCAST, [0x33, 0x33, 0, 0, 0, 1]] {
            assert_eq!(
                h.receive(
                    at(1000),
                    &eth(src, MAC, frame::IPV4, &packet4(REMOTE4, ADDR4))
                ),
                Received::Drop(Dropped::BadSource)
            );
        }
        assert_eq!(
            h.receive(at(1000), &eth(GW_MAC, MAC, 0x8100, &[0; 46])),
            Received::Drop(Dropped::OtherType)
        );
        assert_eq!(
            h.receive(
                at(1000),
                &eth(GW_MAC, OTHER_MAC, frame::IPV4, &packet4(REMOTE4, ADDR4))
            ),
            Received::Drop(Dropped::NotForUs)
        );
        // ARP that is not Ethernet/IPv4, or names a group MAC as its sender.
        let mut bad = samples[0].clone();
        bad[14] = 9;
        assert_eq!(
            h.receive(at(1000), &bad),
            Received::Drop(Dropped::Malformed)
        );
        let group_sender = arp_frame(
            frame::BROADCAST,
            arp::Operation::Request,
            (GW_MAC, GW4),
            ([0; 6], ADDR4),
        );
        let mut group_sender = group_sender;
        group_sender[22] = 0x01;
        assert_eq!(
            h.receive(at(1000), &group_sender),
            Received::Drop(Dropped::Malformed)
        );
        assert!(drain(&mut h, at(1000)).is_empty());
        // Neighbor discovery that was forwarded (hop limit 64) or has a wrong
        // checksum teaches nothing.
        let mut forwarded = samples[2].clone();
        forwarded[14 + 7] = 64;
        assert_eq!(
            h.receive(at(1000), &forwarded),
            Received::Drop(Dropped::Malformed)
        );
        let mut sum = samples[2].clone();
        sum[14 + 40 + 2] ^= 0xff;
        assert_eq!(
            h.receive(at(1000), &sum),
            Received::Drop(Dropped::Malformed)
        );
        assert_eq!(h.ipv6_gateway(), None);
        // A fragmented advertisement.
        let p = ra(1800, Some(GW_MAC)).packet(GW6, ndp::ALL_NODES).unwrap();
        let mut body = vec![58, 0, 0, 0, 0, 0, 0, 42];
        body.extend_from_slice(&p[40..]);
        let fragment = ip::packet_with(
            GW6.into(),
            ndp::ALL_NODES.into(),
            44,
            ip::Fields {
                ttl: 255,
                ..ip::Fields::default()
            },
            &body,
        )
        .0;
        assert_eq!(
            h.receive(at(1000), &eth(GW_MAC, all_nodes, frame::IPV6, &fragment)),
            Received::Drop(Dropped::Malformed)
        );
        assert_eq!(h.ipv6_gateway(), None);
        // An advertisement that names a group MAC for the router.
        let group = nd(
            GW_MAC,
            all_nodes,
            GW6,
            ndp::ALL_NODES,
            ra(1800, Some([0x01, 0, 0, 0, 0, 1])),
        );
        assert_eq!(
            h.receive(at(1000), &group),
            Received::Drop(Dropped::Malformed)
        );
        assert_eq!(h.ipv6_gateway(), None);
        // A solicitation for the host that names a group MAC gets no answer.
        let group = nd(
            OTHER_MAC,
            sn_mac(ADDR6),
            REMOTE6,
            ndp::solicited_node(ADDR6),
            ns(ADDR6, Some(frame::BROADCAST)),
        );
        assert_eq!(
            h.receive(at(1000), &group),
            Received::Drop(Dropped::Malformed)
        );
        assert!(
            drain(&mut h, at(1000))
                .iter()
                .all(|f| !matches!(read(f), Sent::Nd(_, _, Message::NeighborAdvertisement(_))))
        );
    }
}
