// Kani harnesses over `Prefix`, included into `route`'s test module.
//
// Every route lookup, LAN membership test and reverse-path check in the
// network rests on `Prefix`'s bit arithmetic. The address and the length
// are symbolic in every harness, lengths past the width included, so each
// is a proof over every prefix of the family, not a sample.

fn v4_bits(len: u8) -> u32 {
    if len == 0 {
        0
    } else if len >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - u32::from(len))
    }
}

fn v6_bits(len: u8) -> u128 {
    if len == 0 {
        0
    } else if len >= 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - u32::from(len))
    }
}

fn any_v4_prefix() -> (Prefix, u32, u8) {
    let addr: u32 = kani::any();
    let len: u8 = kani::any();
    (
        Prefix {
            addr: Ipv4Addr::from(addr).into(),
            len,
        },
        addr,
        len,
    )
}

fn any_v6_prefix() -> (Prefix, u128, u8) {
    let addr: u128 = kani::any();
    let len: u8 = kani::any();
    (
        Prefix {
            addr: Ipv6Addr::from(addr).into(),
            len,
        },
        addr,
        len,
    )
}

/// An IPv4 prefix holds an address exactly when they agree on the first
/// `len` bits, all 32 for a length past the width, and never an IPv6
/// address. Its mask is those bits.
#[kani::proof]
fn ipv4_contains_compares_the_prefix_bits() {
    let (prefix, p, len) = any_v4_prefix();
    let a: u32 = kani::any();
    assert_eq!(
        prefix.contains(Ipv4Addr::from(a).into()),
        (p ^ a) & v4_bits(len) == 0
    );
    assert_eq!(prefix.mask(), IpAddr::V4(Ipv4Addr::from(v4_bits(len))));
    let other: u128 = kani::any();
    assert!(!prefix.contains(Ipv6Addr::from(other).into()));
}

/// The same for an IPv6 prefix, over all 128 bits.
#[kani::proof]
fn ipv6_contains_compares_the_prefix_bits() {
    let (prefix, p, len) = any_v6_prefix();
    let a: u128 = kani::any();
    assert_eq!(
        prefix.contains(Ipv6Addr::from(a).into()),
        (p ^ a) & v6_bits(len) == 0
    );
    assert_eq!(prefix.mask(), IpAddr::V6(Ipv6Addr::from(v6_bits(len))));
    let other: u32 = kani::any();
    assert!(!prefix.contains(Ipv4Addr::from(other).into()));
}

/// Canonical form clears the host bits and clamps the length to the width.
/// It is a fixed point, its address is the network address, and it holds
/// exactly the addresses the prefix held, with the same mask, network, last
/// address and size.
#[kani::proof]
fn canonical_keeps_what_the_prefix_holds() {
    let (prefix, _, len) = any_v4_prefix();
    let c = prefix.canonical();
    assert_eq!(c.canonical(), c);
    assert_eq!(c.len, len.min(32));
    assert_eq!(c.addr, prefix.network());
    assert!(c.contains(prefix.addr));
    let a: u32 = kani::any();
    let a = IpAddr::V4(Ipv4Addr::from(a));
    assert_eq!(c.contains(a), prefix.contains(a));
    assert_eq!(c.mask(), prefix.mask());
    assert_eq!(c.network(), prefix.network());
    assert_eq!(c.last(), prefix.last());
    assert_eq!(c.size(), prefix.size());
    assert_eq!(c.broadcast(), prefix.broadcast());

    let (prefix, _, len) = any_v6_prefix();
    let c = prefix.canonical();
    assert_eq!(c.canonical(), c);
    assert_eq!(c.len, len.min(128));
    assert_eq!(c.addr, prefix.network());
    let a: u128 = kani::any();
    let a = IpAddr::V6(Ipv6Addr::from(a));
    assert_eq!(c.contains(a), prefix.contains(a));
    assert_eq!(c.last(), prefix.last());
    assert_eq!(c.size(), prefix.size());
}

/// Two prefixes overlap exactly when some address is in both: an address
/// in both means overlap, overlap means the longer one's network address
/// is in both, and overlap is symmetric. Prefixes of different families
/// never overlap.
#[kani::proof]
fn overlap_is_a_shared_address() {
    let (p, _, plen) = any_v4_prefix();
    let (q, _, qlen) = any_v4_prefix();
    assert_eq!(p.overlaps(q), q.overlaps(p));
    let a: u32 = kani::any();
    let a = IpAddr::V4(Ipv4Addr::from(a));
    if p.contains(a) && q.contains(a) {
        assert!(p.overlaps(q));
    }
    if p.overlaps(q) {
        let longer = if plen.min(32) >= qlen.min(32) {
            p.network()
        } else {
            q.network()
        };
        assert!(p.contains(longer) && q.contains(longer));
    }
    let (six, _, _) = any_v6_prefix();
    assert!(!p.overlaps(six));
    assert!(!six.overlaps(p));
}

/// Offsets into an IPv4 prefix: `nth` is defined for exactly the offsets
/// below `size`, gives the address that far from the network address,
/// which the prefix holds; offset 0 is the network address and the last
/// offset is `last`. The directed broadcast address is `last` for a /30
/// or shorter and nothing for a longer prefix.
#[kani::proof]
fn ipv4_offsets_size_last_and_broadcast_agree() {
    let (prefix, _, len) = any_v4_prefix();
    let size = prefix.size().expect("every IPv4 prefix has a size");
    assert_eq!(size, 1u128 << (32 - u32::from(len.min(32))));
    let IpAddr::V4(network) = prefix.network() else {
        unreachable!("an IPv4 prefix has an IPv4 network address")
    };
    let n: u128 = kani::any();
    match prefix.nth(n) {
        Some(IpAddr::V4(x)) => {
            assert!(n < size);
            assert!(prefix.contains(x.into()));
            assert_eq!(u128::from(u32::from(x)) - u128::from(u32::from(network)), n);
        }
        Some(IpAddr::V6(_)) => unreachable!("an IPv4 prefix has IPv4 addresses"),
        None => assert!(n >= size),
    }
    assert_eq!(prefix.nth(0), Some(prefix.network()));
    assert_eq!(prefix.nth(size - 1), Some(prefix.last()));
    match prefix.broadcast() {
        Some(b) => {
            assert!(len < 31);
            assert_eq!(IpAddr::V4(b), prefix.last());
        }
        None => assert!(len >= 31),
    }
}

/// Offsets into an IPv6 prefix: a /0 has no size, and `nth` is defined for
/// every offset the network address can reach; every other prefix has size
/// 2^(128 - len), with `nth` defined exactly below it. The address given is
/// in the prefix at that offset, and IPv6 has no broadcast address.
#[kani::proof]
fn ipv6_offsets_and_size_agree() {
    let (prefix, _, len) = any_v6_prefix();
    let IpAddr::V6(network) = prefix.network() else {
        unreachable!("an IPv6 prefix has an IPv6 network address")
    };
    let n: u128 = kani::any();
    let result = prefix.nth(n);
    match prefix.size() {
        None => {
            assert_eq!(len, 0);
            assert_eq!(network, Ipv6Addr::UNSPECIFIED);
            assert_eq!(result, Some(IpAddr::V6(Ipv6Addr::from(n))));
        }
        Some(size) => {
            assert!(len > 0);
            assert_eq!(size, 1u128 << (128 - u32::from(len.min(128))));
            match result {
                Some(IpAddr::V6(x)) => {
                    assert!(n < size);
                    assert!(prefix.contains(x.into()));
                    assert_eq!(u128::from(x) - u128::from(network), n);
                }
                Some(IpAddr::V4(_)) => unreachable!("an IPv6 prefix has IPv6 addresses"),
                None => assert!(n >= size),
            }
            assert_eq!(prefix.nth(size - 1), Some(prefix.last()));
        }
    }
    assert_eq!(prefix.nth(0), Some(prefix.network()));
    assert_eq!(prefix.broadcast(), None);
}
