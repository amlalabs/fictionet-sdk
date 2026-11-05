//! Network identities a world can give its hosts and its gateway.
//!
//! ```
//! use fictionet::stdlib::network::ethernet::{Family, Link};
//! use fictionet::stdlib::world::net::Net;
//! use fictionet_extras::network;
//!
//! let net = Net::new(network::cdn_pools());
//! let link = Link::new(network::UBIQUITI_ROUTER, Family::FromWorld, Family::Off, 1500)?;
//! # Ok::<(), fictionet::Error>(())
//! ```

use fictionet::stdlib::network::ethernet::frame::Mac;
use fictionet::stdlib::network::route::Prefix;
use fictionet::stdlib::world::net::Pools;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Ordinary guests use only the gateway's resolver. This predicate is
/// applied outside the gateway and does not see server-to-server traffic.
pub fn corporate_egress(destination: std::net::SocketAddr) -> bool {
    !matches!(destination.port(), 53 | 853)
        && !(destination.port() == 443
            && crate::dns::public::PUBLIC_RESOLVERS.iter().any(|resolver| {
                resolver.addresses.iter().any(|address| {
                    destination.ip() == IpAddr::V4(address.v4)
                        || destination.ip() == IpAddr::V6(address.v6)
                })
            }))
}

/// Public CDN space for hosts without a fixed address: `104.18.0.0/15`
/// and `2606:4700:100::/48`, Cloudflare's, where many real sites are.
pub fn cdn_pools() -> Pools {
    Pools {
        v4: Some(Prefix {
            addr: IpAddr::V4(Ipv4Addr::new(104, 18, 0, 0)),
            len: 15,
        }),
        v6: Some(Prefix {
            addr: IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x100, 0, 0, 0, 0, 0)),
            len: 48,
        }),
    }
}

/// A Ubiquiti router's MAC, for a virtual machine's gateway
/// ([`Link::new`](fictionet::stdlib::network::ethernet::Link::new)): a
/// universally administered unicast address under a Ubiquiti prefix.
pub const UBIQUITI_ROUTER: Mac = [0x74, 0x83, 0xc2, 0x9a, 0x47, 0xd1];

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::network::ip::non_public_address;

    #[test]
    fn corporate_dns_policy_covers_both_address_families() {
        for resolver in crate::dns::public::PUBLIC_RESOLVERS {
            for address in resolver.addresses {
                for ip in [IpAddr::V4(address.v4), IpAddr::V6(address.v6)] {
                    for port in [53, 853, 443] {
                        assert!(!corporate_egress(std::net::SocketAddr::new(ip, port)));
                    }
                }
            }
        }
        for ip in ["198.41.0.4", "2001:503:ba3e::2:30", "93.184.215.14"] {
            let ip = ip.parse().unwrap();
            for port in [53, 853] {
                assert!(!corporate_egress(std::net::SocketAddr::new(ip, port)));
            }
            for port in [22, 80, 443] {
                assert!(corporate_egress(std::net::SocketAddr::new(ip, port)));
            }
        }
    }

    #[test]
    fn cdn_pools_avoid_non_public_ranges() {
        // Non-public IPv4 ranges are /24 or larger, and IPv6 ones /48 or
        // larger, apart from `::1`: one address of each /24 of the IPv4
        // pool, and the ends of the /48 IPv6 pool, find any overlap.
        let pools = cdn_pools();
        let v4 = pools.v4.unwrap();
        for n in (0..v4.size().unwrap()).step_by(256) {
            let a = v4.nth(n).unwrap();
            assert!(!non_public_address(a), "{a}");
        }
        let v6 = pools.v6.unwrap();
        assert_eq!(v6.len, 48);
        assert!(!non_public_address(v6.addr));
        assert!(!non_public_address(v6.last()));
    }

    #[test]
    fn the_router_mac_is_a_universal_unicast_address() {
        assert_eq!(UBIQUITI_ROUTER[0] & 3, 0);
        assert_eq!(&UBIQUITI_ROUTER[..3], &[0x74, 0x83, 0xc2]);
        assert!(
            !UBIQUITI_ROUTER
                .windows(2)
                .any(|bytes| bytes == [0x66, 0x6e])
        );
    }
}
