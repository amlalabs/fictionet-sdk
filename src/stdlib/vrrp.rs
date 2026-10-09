//! VRRP: reading and writing virtual router advertisements, with no I/O.
//!
//! Advertisement readers and writers handle complete values, with `Vec<u8>` as
//! the byte representation. There is no protocol stream decoder, master/backup state
//! machine, election timer, router `Service`, or live transport.
//!
//! VRRP (the Virtual Router Redundancy Protocol, IP protocol 112) lets
//! several routers on a link share one gateway address. The routers form a
//! virtual router, named by a number from 1 to 255 (the VRID). The one with
//! the highest priority is the master: it answers for the shared addresses
//! and sends an advertisement every interval. The others are backups. Each
//! backup runs a timer, Master_Down_Timer, that each advertisement it heeds
//! restarts. When the timer runs out, the backup takes over. A backup set to
//! preempt ignores advertisements of a lower priority than its own, so its
//! timer runs out and it takes over. A master that shuts down sends one last
//! advertisement with priority 0, which cuts the backups' timers short.
//!
//! VRRP has two versions in use. Version 2 (RFC 3768) is for IPv4 only. It
//! gives the interval in seconds and carries an authentication type and 8
//! bytes of authentication data. Version 3 (RFC 9568, which replaced RFC
//! 5798) works over IPv4 and IPv6. It gives the interval in centiseconds and
//! has no authentication. Over IPv6 its checksum also covers the IPv6
//! pseudo-header, so the source and destination addresses must be known to
//! read or write one. Over IPv4 the checksum covers the message alone, as in
//! version 2. Many routers built to RFC 5798 add an IPv4 pseudo-header
//! instead: see [`checksum_rfc5798`].
//!
//! Nothing here reads a socket. A world that plays a router hands each
//! VRRP payload (the bytes after the IP header) to [`Advertisement::parse`]
//! with the packet's [`Endpoints`], looks at the [`Advertisement`], and
//! prepares the bytes with [`Advertisement::frame`].
//! Use protocol [`PROTOCOL`] and a TTL or hop limit of [`HOP_LIMIT`], to the
//! address [`Advertisement::destination`] gives. For pieces of one payload,
//! use [`codec::Collect::bytes`](fictionet::stdlib::codec::Collect::bytes) in a stream
//! and a limit of [`MAX_MESSAGE`]. Map through [`Advertisement::parse`]
//! and call `end` at the IP boundary. Which virtual routers exist, their
//! priorities, and the timers that decide when a backup takes over are
//! up to world code.
//!
//! Every reader checks the version, type, VRID, address count, length and
//! checksum, because the agent can send any bytes it likes. A version 2
//! advertisement must have a known authentication type (see [`auth`]). Over
//! IPv6, the source and the first address must be link-local. The payload
//! must be exactly as long as its address count says. The reserved bits of
//! a version 3 advertisement are ignored when read and written as zero.
//! Writers check the same rules as readers, so bytes they return always
//! read back.
//!
//! ```
//! use fictionet::stdlib::ip::Endpoints;
//! use std::net::{IpAddr, Ipv4Addr};
//! use fictionet::stdlib::vrrp::{
//!     Addresses, Advertisement, AdvertisementV3, GROUP_V4, PRIORITY_STOP,
//! };
//!
//! /// What a backup router does with its Master_Down_Timer when it hears
//! /// an advertisement (RFC 9568 section 6.4.2). It takes over only when
//! /// that timer runs out, which the world's clock reports.
//! #[derive(Debug, PartialEq)]
//! enum Timer {
//!     /// Leave the timer running: the advertisement is not heeded.
//!     Keep,
//!     /// Restart it at Master_Down_Interval, from the advertised interval.
//!     Restart,
//!     /// Set it to Skew_Time: the master has stopped.
//!     Skew,
//! }
//!
//! /// The timer change for a backup with priority `mine` on virtual router
//! /// `vrid`, which preempts lower priorities if `preempt` is set.
//! fn on_advertisement(vrid: u8, mine: u8, preempt: bool, ad: &Advertisement) -> Timer {
//!     if ad.vrid() != vrid {
//!         Timer::Keep
//!     } else if ad.priority() == PRIORITY_STOP {
//!         Timer::Skew
//!     } else if !preempt || ad.priority() >= mine {
//!         Timer::Restart
//!     } else {
//!         Timer::Keep
//!     }
//! }
//!
//! // The master, 192.168.1.2, advertises 192.168.1.1 for virtual router 1
//! // at priority 100, once a second (100 centiseconds).
//! let master = Endpoints::V4 { source: Ipv4Addr::new(192, 168, 1, 2), destination: GROUP_V4 };
//! let bytes = [0x31, 1, 100, 1, 0, 100, 0xa8, 0xef, 192, 168, 1, 1];
//! let ad = Advertisement::parse(&bytes, &master).unwrap();
//! assert_eq!(
//!     ad,
//!     Advertisement::V3(AdvertisementV3 {
//!         vrid: 1,
//!         priority: 100,
//!         interval: 100,
//!         addresses: Addresses::V4(vec![Ipv4Addr::new(192, 168, 1, 1)]),
//!     })
//! );
//! assert_eq!(ad.destination(), IpAddr::V4(GROUP_V4));
//! assert_eq!(on_advertisement(1, 90, true, &ad), Timer::Restart);
//! assert_eq!(on_advertisement(1, 110, true, &ad), Timer::Keep);
//! assert_eq!(on_advertisement(1, 110, false, &ad), Timer::Restart);
//! assert_eq!(on_advertisement(2, 90, true, &ad), Timer::Keep);
//! // Written back, the advertisement is the same bytes.
//! assert_eq!(ad.frame(&master).unwrap(), bytes);
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The IP protocol number of VRRP.
pub const PROTOCOL: u8 = 112;
/// The TTL (IPv4) or hop limit (IPv6) every advertisement is sent with. A
/// receiver drops an advertisement that arrives with any other, since it
/// came from off the link.
pub const HOP_LIMIT: u8 = 255;
/// The IPv4 multicast group advertisements are sent to.
pub const GROUP_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 18);
/// The IPv6 multicast group advertisements are sent to.
pub const GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x12);
/// The length of the fixed header, before the addresses.
pub const HEADER_LEN: usize = 8;
/// The length of the authentication data at the end of a version 2
/// advertisement.
pub const AUTH_DATA_LEN: usize = 8;
/// The most addresses one advertisement can carry: its count is one byte.
pub const MAX_ADDRESSES: usize = 255;
/// The longest advertisement: version 3 with [`MAX_ADDRESSES`] IPv6
/// addresses.
pub const MAX_MESSAGE: usize = HEADER_LEN + MAX_ADDRESSES * 16;
/// The largest version 3 interval, in centiseconds: the field is 12 bits.
pub const MAX_INTERVAL_V3: u16 = 0x0fff;
/// The only message type VRRP defines: an advertisement.
pub const TYPE_ADVERTISEMENT: u8 = 1;
/// The priority of the router that owns the virtual router's addresses.
pub const PRIORITY_OWNER: u8 = 255;
/// The priority a master sends when it stops being master.
pub const PRIORITY_STOP: u8 = 0;
/// The priority a backup router has unless set otherwise.
pub const PRIORITY_DEFAULT: u8 = 100;

/// Version 2 authentication types. These three are the only ones VRRP has
/// defined. Readers and writers reject any other, since no router can be
/// set up to use it (RFC 3768 section 7.1).
pub mod auth {
    /// No authentication. The authentication data is zero.
    pub const NONE: u8 = 0;
    /// A plain-text password in the authentication data (RFC 2338). RFC
    /// 3768 removed it and reserves the value.
    pub const SIMPLE_TEXT: u8 = 1;
    /// The IP Authentication Header (RFC 2338). RFC 3768 removed it and
    /// reserves the value.
    pub const IP_AH: u8 = 2;
}

use fictionet::stdlib::ip::Endpoints;

/// A version 2 advertisement (RFC 3768). It is always carried over IPv4.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AdvertisementV2 {
    /// The virtual router: 1 to 255.
    pub vrid: u8,
    /// The sender's priority. See [`PRIORITY_OWNER`], [`PRIORITY_STOP`]
    /// and [`PRIORITY_DEFAULT`].
    pub priority: u8,
    /// The authentication type: one of the values in [`auth`]. A receiver
    /// drops an advertisement whose type differs from its own.
    pub auth_type: u8,
    /// How often the master advertises, in seconds.
    pub interval: u8,
    /// The virtual router's addresses: 1 to [`MAX_ADDRESSES`] of them.
    pub addresses: Vec<Ipv4Addr>,
    /// The authentication data. RFC 3768 sends zeros and ignores what
    /// comes, and RFC 2338 put a plain-text password here.
    pub auth_data: [u8; AUTH_DATA_LEN],
}

/// The addresses of a version 3 advertisement: all IPv4 or all IPv6, the
/// same family as the packet that carries it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Addresses {
    /// IPv4 addresses.
    V4(Vec<Ipv4Addr>),
    /// IPv6 addresses. The first is the virtual router's link-local
    /// address (in fe80::/10), and readers and writers check that it is.
    V6(Vec<Ipv6Addr>),
}

/// The addresses of an advertisement as [`IpAddr`] values, borrowed one at
/// a time, from [`Addresses::iter`] or [`Advertisement::addresses`].
#[derive(Clone, Debug)]
pub enum IpAddrs<'a> {
    /// IPv4 addresses.
    V4(std::slice::Iter<'a, Ipv4Addr>),
    /// IPv6 addresses.
    V6(std::slice::Iter<'a, Ipv6Addr>),
}

impl Iterator for IpAddrs<'_> {
    type Item = IpAddr;

    fn next(&mut self) -> Option<IpAddr> {
        match self {
            IpAddrs::V4(i) => i.next().map(|x| IpAddr::V4(*x)),
            IpAddrs::V6(i) => i.next().map(|x| IpAddr::V6(*x)),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            IpAddrs::V4(i) => i.size_hint(),
            IpAddrs::V6(i) => i.size_hint(),
        }
    }
}

impl ExactSizeIterator for IpAddrs<'_> {}

/// Whether `a` is a unicast link-local IPv6 address: in fe80::/10.
fn is_link_local(a: &Ipv6Addr) -> bool {
    a.segments()[0] & 0xffc0 == 0xfe80
}

impl Addresses {
    /// How many addresses there are.
    pub fn len(&self) -> usize {
        match self {
            Addresses::V4(a) => a.len(),
            Addresses::V6(a) => a.len(),
        }
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The addresses, as [`IpAddr`] values. It borrows them and allocates
    /// nothing.
    pub fn iter(&self) -> IpAddrs<'_> {
        match self {
            Addresses::V4(a) => IpAddrs::V4(a.iter()),
            Addresses::V6(a) => IpAddrs::V6(a.iter()),
        }
    }
}

/// A version 3 advertisement (RFC 5798), over IPv4 or IPv6.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AdvertisementV3 {
    /// The virtual router: 1 to 255.
    pub vrid: u8,
    /// The sender's priority. See [`PRIORITY_OWNER`], [`PRIORITY_STOP`]
    /// and [`PRIORITY_DEFAULT`].
    pub priority: u8,
    /// How often the master advertises, in centiseconds, up to
    /// [`MAX_INTERVAL_V3`].
    pub interval: u16,
    /// The virtual router's addresses: 1 to [`MAX_ADDRESSES`] of them.
    pub addresses: Addresses,
}

/// One VRRP advertisement, version 2 or 3.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Advertisement {
    /// Version 2, IPv4 only, with authentication fields.
    V2(AdvertisementV2),
    /// Version 3, IPv4 or IPv6.
    V3(AdvertisementV3),
}

/// Why bytes are not a VRRP advertisement, or an advertisement cannot be
/// written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// The payload exceeds [`MAX_MESSAGE`].
    TooLong,
    /// The bytes end before the advertisement does.
    Truncated,
    /// The bytes go on past the end the address count gives.
    Trailing {
        /// Number of bytes after the VRRP advertisement.
        remaining: usize,
    },
    /// The version was not 2 or 3.
    Version(u8),
    /// The type was not [`TYPE_ADVERTISEMENT`].
    Type(u8),
    /// The VRID was 0. Virtual routers are numbered from 1.
    Vrid,
    /// An advertisement had no addresses. Both versions ask for at least
    /// one.
    NoAddresses,
    /// A version 2 advertisement had an authentication type other than
    /// those in [`auth`].
    AuthType(u8),
    /// A version 3 advertisement over IPv6 came from a source that is not
    /// link-local, or its first address was not link-local.
    LinkLocal,
    /// An advertisement to be written had more than [`MAX_ADDRESSES`].
    TooManyAddresses(usize),
    /// A version 3 interval to be written was above [`MAX_INTERVAL_V3`].
    Interval(u16),
    /// A version 2 advertisement came over IPv6, or an advertisement to be
    /// written had addresses of a different family than its packet.
    Family,
    /// The checksum was wrong.
    Checksum,
}

impl From<AdvertisementV2> for Advertisement {
    fn from(a: AdvertisementV2) -> Advertisement {
        Advertisement::V2(a)
    }
}

impl From<AdvertisementV3> for Advertisement {
    fn from(a: AdvertisementV3) -> Advertisement {
        Advertisement::V3(a)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::TooLong => write!(f, "VRRP payload exceeds {MAX_MESSAGE} bytes"),
            Error::Truncated => write!(f, "the advertisement is cut short"),
            Error::Trailing { remaining } => {
                write!(f, "{remaining} bytes after the VRRP advertisement")
            }
            Error::Version(v) => write!(f, "version {v}, not 2 or 3"),
            Error::Type(t) => write!(f, "type {t}, not 1 (advertisement)"),
            Error::Vrid => write!(f, "VRID 0, outside 1..=255"),
            Error::NoAddresses => write!(f, "an advertisement with no addresses"),
            Error::AuthType(t) => write!(f, "authentication type {t}, not 0, 1 or 2"),
            Error::LinkLocal => write!(f, "an IPv6 source or first address that is not link-local"),
            Error::TooManyAddresses(n) => write!(f, "{n} addresses, more than {MAX_ADDRESSES}"),
            Error::Interval(i) => write!(f, "interval {i}, above {MAX_INTERVAL_V3}"),
            Error::Family => write!(
                f,
                "the addresses and the IP packet are of different families"
            ),
            Error::Checksum => write!(f, "the checksum is wrong"),
        }
    }
}

impl std::error::Error for Error {}

/// Adds `b` to a ones' complement sum, as 16-bit words with a zero byte
/// added to an odd length.
fn sum_words(mut sum: u64, b: &[u8]) -> u64 {
    let (words, rest) = b.as_chunks::<2>();
    for w in words {
        sum += u64::from(u16::from_be_bytes([w[0], w[1]]));
    }
    if let [last] = rest {
        sum += u64::from(*last) << 8;
    }
    sum
}

fn fold(mut sum: u64) -> u16 {
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// The checksum the advertisement in `b` should carry (RFC 9568 section
/// 5.2.8), worked out with its checksum field (bytes 6 and 7) taken as
/// zero. A version 3 advertisement (a first byte whose high four bits are
/// 3) over IPv6 includes the pseudo-header of RFC 8200 section 8.1, with
/// next header [`PROTOCOL`]. Over IPv4, and for any other version, the sum
/// covers the message alone. Writers always use this checksum. It returns
/// `None` if `b` is shorter than [`HEADER_LEN`] or longer than
/// [`MAX_MESSAGE`].
pub fn checksum(b: &[u8], endpoints: &Endpoints) -> Option<u16> {
    sum_with(b, endpoints, false)
}

/// The checksum many routers built to RFC 5798 put on a version 3
/// advertisement over IPv4: the sum also covers an IPv4 pseudo-header
/// (source, destination, a zero byte, [`PROTOCOL`] and a 16-bit length).
/// Keepalived does this unless set to `v3_checksum_as_v2`. RFC 9568 left
/// the pseudo-header out. For anything other than version 3 over IPv4 it
/// is the same as [`checksum`].
///
/// [`Advertisement::parse`] takes either checksum on a version 3
/// advertisement over IPv4. To send to a router that wants this one,
/// prepare the bytes with [`Advertisement::frame`] and put this checksum
/// in bytes 6 and 7.
pub fn checksum_rfc5798(b: &[u8], endpoints: &Endpoints) -> Option<u16> {
    sum_with(b, endpoints, true)
}

fn sum_with(b: &[u8], endpoints: &Endpoints, v4_pseudo_header: bool) -> Option<u16> {
    if b.len() < HEADER_LEN || b.len() > MAX_MESSAGE {
        return None;
    }
    let mut sum = sum_words(0, &b[..6]);
    sum = sum_words(sum, &b[HEADER_LEN..]);
    if b[0] >> 4 == 3 {
        // MAX_MESSAGE fits in 16 bits, so the length does too.
        let len = b.len() as u16;
        match endpoints {
            Endpoints::V4 {
                source,
                destination,
            } => {
                if v4_pseudo_header {
                    sum = sum_words(sum, &source.octets());
                    sum = sum_words(sum, &destination.octets());
                    sum = sum_words(sum, &[0, PROTOCOL]);
                    sum = sum_words(sum, &len.to_be_bytes());
                }
            }
            Endpoints::V6 {
                source,
                destination,
            } => {
                sum = sum_words(sum, &source.octets());
                sum = sum_words(sum, &destination.octets());
                sum = sum_words(sum, &u32::from(len).to_be_bytes());
                sum = sum_words(sum, &[0, 0, 0, PROTOCOL]);
            }
        }
    }
    Some(!fold(sum))
}

/// Whether the checksum field `got` matches `want`. In ones' complement
/// 0xffff and 0x0000 are both zero, so a sum of the whole message passes
/// with either.
fn checksum_matches(got: u16, want: Option<u16>) -> bool {
    match want {
        Some(w) => got == w || (w == 0 && got == 0xffff),
        None => false,
    }
}

/// Checks a complete header and returns the advertisement's full length.
/// Refuses missing fields and invalid version, type, address family,
/// source, VRID, count, or authentication type.
fn check_header(b: &[u8], endpoints: &Endpoints) -> Result<usize, Error> {
    let Some(&first) = b.first() else {
        return Err(Error::Truncated);
    };
    let version = first >> 4;
    if version != 2 && version != 3 {
        return Err(Error::Version(version));
    }
    if first & 0x0f != TYPE_ADVERTISEMENT {
        return Err(Error::Type(first & 0x0f));
    }
    match endpoints {
        Endpoints::V6 { .. } if version == 2 => return Err(Error::Family),
        Endpoints::V6 { source, .. } if !is_link_local(source) => return Err(Error::LinkLocal),
        _ => {}
    }
    if b.len() < HEADER_LEN {
        // Keep field errors ahead of truncation when those fields arrived.
        return Err(match b {
            [_, 0, ..] => Error::Vrid,
            [_, _, _, 0, ..] => Error::NoAddresses,
            [_, _, _, _, t, ..] if version == 2 && *t > auth::IP_AH => Error::AuthType(*t),
            _ => Error::Truncated,
        });
    }
    if b[1] == 0 {
        return Err(Error::Vrid);
    }
    let count = b[3];
    if count == 0 {
        return Err(Error::NoAddresses);
    }
    if version == 2 && b[4] > auth::IP_AH {
        return Err(Error::AuthType(b[4]));
    }
    // At most 8 + 255 * 16, so this cannot overflow.
    let auth = if version == 2 { AUTH_DATA_LEN } else { 0 };
    Ok(HEADER_LEN + usize::from(count) * endpoints.address_len() + auth)
}

impl Advertisement {
    /// Reads the advertisement in `b`, the whole VRRP payload of one IP
    /// packet, sent from and to `endpoints`. The checksum must be right,
    /// and `b` must end where the address count says. A version 3
    /// advertisement over IPv4 may carry either [`checksum`] or
    /// [`checksum_rfc5798`]. A checksum of 0xffff is taken where 0x0000 is
    /// due, since the two are equal in ones' complement.
    pub fn parse(b: &[u8], endpoints: &Endpoints) -> Result<Advertisement, Error> {
        let len = check_header(b, endpoints)?;
        if b.len() < len {
            return Err(Error::Truncated);
        }
        if b.len() > len {
            return Err(Error::Trailing {
                remaining: b.len() - len,
            });
        }
        let got = u16::from_be_bytes([b[6], b[7]]);
        if !checksum_matches(got, checksum(b, endpoints))
            && !checksum_matches(got, checksum_rfc5798(b, endpoints))
        {
            return Err(Error::Checksum);
        }
        let (vrid, priority, count) = (b[1], b[2], usize::from(b[3]));
        let body = &b[HEADER_LEN..];
        if b[0] >> 4 == 2 {
            let (addrs, auth_data) = body.split_at(count * 4);
            let mut data = [0u8; AUTH_DATA_LEN];
            data.copy_from_slice(auth_data);
            return Ok(Advertisement::V2(AdvertisementV2 {
                vrid,
                priority,
                auth_type: b[4],
                interval: b[5],
                addresses: v4_addresses(addrs),
                auth_data: data,
            }));
        }
        let interval = u16::from_be_bytes([b[4] & 0x0f, b[5]]);
        let addresses = match endpoints {
            Endpoints::V4 { .. } => Addresses::V4(v4_addresses(body)),
            Endpoints::V6 { .. } => {
                let v6: Vec<Ipv6Addr> = body
                    .as_chunks::<16>()
                    .0
                    .iter()
                    .map(|c| {
                        let mut o = [0u8; 16];
                        o.copy_from_slice(c);
                        Ipv6Addr::from(o)
                    })
                    .collect();
                // RFC 9568 section 5.2.9: the first address MUST be the
                // virtual router's link-local address.
                if !v6.first().is_some_and(is_link_local) {
                    return Err(Error::LinkLocal);
                }
                Addresses::V6(v6)
            }
        };
        Ok(Advertisement::V3(AdvertisementV3 {
            vrid,
            priority,
            interval,
            addresses,
        }))
    }

    /// The VRRP version: 2 or 3.
    pub fn version(&self) -> u8 {
        match self {
            Advertisement::V2(_) => 2,
            Advertisement::V3(_) => 3,
        }
    }

    /// The virtual router the advertisement is for.
    pub fn vrid(&self) -> u8 {
        match self {
            Advertisement::V2(a) => a.vrid,
            Advertisement::V3(a) => a.vrid,
        }
    }

    /// The sender's priority.
    pub fn priority(&self) -> u8 {
        match self {
            Advertisement::V2(a) => a.priority,
            Advertisement::V3(a) => a.priority,
        }
    }

    /// The interval in centiseconds, for either version. A version 2
    /// interval is in seconds, so it is multiplied by 100.
    pub fn interval_centiseconds(&self) -> u32 {
        match self {
            Advertisement::V2(a) => u32::from(a.interval) * 100,
            Advertisement::V3(a) => u32::from(a.interval),
        }
    }

    /// How many addresses the advertisement carries.
    pub fn address_count(&self) -> usize {
        match self {
            Advertisement::V2(a) => a.addresses.len(),
            Advertisement::V3(a) => a.addresses.len(),
        }
    }

    /// The virtual router's addresses, as [`IpAddr`] values. It borrows
    /// them and allocates nothing.
    pub fn addresses(&self) -> IpAddrs<'_> {
        match self {
            Advertisement::V2(a) => IpAddrs::V4(a.addresses.iter()),
            Advertisement::V3(a) => a.addresses.iter(),
        }
    }

    /// Where the advertisement is sent: [`GROUP_V6`] for a version 3
    /// advertisement of IPv6 addresses, and [`GROUP_V4`] otherwise.
    pub fn destination(&self) -> IpAddr {
        match self {
            Advertisement::V3(AdvertisementV3 {
                addresses: Addresses::V6(_),
                ..
            }) => IpAddr::V6(GROUP_V6),
            _ => IpAddr::V4(GROUP_V4),
        }
    }

    /// The size of the frame prepared for `endpoints`, or why its fields
    /// cannot be encoded. See [`Advertisement::frame`].
    pub fn encoded_len(&self, endpoints: &Endpoints) -> Result<usize, Error> {
        let (vrid, count, auth) = match self {
            Advertisement::V2(a) => {
                if matches!(endpoints, Endpoints::V6 { .. }) {
                    return Err(Error::Family);
                }
                if a.auth_type > auth::IP_AH {
                    return Err(Error::AuthType(a.auth_type));
                }
                (a.vrid, a.addresses.len(), AUTH_DATA_LEN)
            }
            Advertisement::V3(a) => {
                let family_ok = matches!(
                    (&a.addresses, endpoints),
                    (Addresses::V4(_), Endpoints::V4 { .. })
                        | (Addresses::V6(_), Endpoints::V6 { .. })
                );
                if !family_ok {
                    return Err(Error::Family);
                }
                if a.interval > MAX_INTERVAL_V3 {
                    return Err(Error::Interval(a.interval));
                }
                if let (Addresses::V6(v6), Endpoints::V6 { source, .. }) = (&a.addresses, endpoints)
                    && v6
                        .first()
                        .is_some_and(|first| !is_link_local(first) || !is_link_local(source))
                {
                    return Err(Error::LinkLocal);
                }
                (a.vrid, a.addresses.len(), 0)
            }
        };
        if vrid == 0 {
            return Err(Error::Vrid);
        }
        if count == 0 {
            return Err(Error::NoAddresses);
        }
        if count > MAX_ADDRESSES {
            return Err(Error::TooManyAddresses(count));
        }
        Ok(HEADER_LEN + count * endpoints.address_len() + auth)
    }

    /// Prepares an advertisement frame, to go from and to `endpoints`, with the
    /// checksum filled in (see [`checksum`]). It fails if the VRID is 0,
    /// there are no addresses or more than [`MAX_ADDRESSES`], a version 2
    /// authentication type is not in [`auth`], a version 3 interval is
    /// above [`MAX_INTERVAL_V3`], the addresses are not of the packet's
    /// family, or over IPv6 the source or first address is not link-local.
    /// Nothing is allocated before those checks pass.
    pub fn frame(&self, endpoints: &Endpoints) -> Result<Vec<u8>, Error> {
        let len = self.encoded_len(endpoints)?;
        let mut out = Vec::with_capacity(len);
        match self {
            Advertisement::V2(a) => {
                out.extend_from_slice(&[
                    0x20 | TYPE_ADVERTISEMENT,
                    a.vrid,
                    a.priority,
                    a.addresses.len() as u8,
                ]);
                out.extend_from_slice(&[a.auth_type, a.interval, 0, 0]);
                for x in &a.addresses {
                    out.extend_from_slice(&x.octets());
                }
                out.extend_from_slice(&a.auth_data);
            }
            Advertisement::V3(a) => {
                out.extend_from_slice(&[
                    0x30 | TYPE_ADVERTISEMENT,
                    a.vrid,
                    a.priority,
                    a.addresses.len() as u8,
                ]);
                out.extend_from_slice(&a.interval.to_be_bytes());
                out.extend_from_slice(&[0, 0]);
                match &a.addresses {
                    Addresses::V4(v) => v.iter().for_each(|x| out.extend_from_slice(&x.octets())),
                    Addresses::V6(v) => v.iter().for_each(|x| out.extend_from_slice(&x.octets())),
                }
            }
        }
        // The length was checked above, so the checksum is always there.
        let c = checksum(&out, endpoints).unwrap_or(0);
        out[6..8].copy_from_slice(&c.to_be_bytes());
        Ok(out)
    }
}

fn v4_addresses(b: &[u8]) -> Vec<Ipv4Addr> {
    b.as_chunks::<4>()
        .0
        .iter()
        .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{Collect, CollectError, Fail, Lcg};
    use fictionet::stdlib::test_support::contract;
    use fictionet::stdlib::test_support::rounds;
    use fictionet::stdlib::test_support::{decode_all, mutate};

    fn collect(b: &[u8], e: &Endpoints) -> Result<Advertisement, Error> {
        use fictionet::stdlib::codec::Decode;
        let make = || Collect::bytes(MAX_MESSAGE).map(|d| Advertisement::parse(&d, e));
        contract::check_decode_with_alloc_limit(make, b, 2 * (MAX_MESSAGE + 1));
        assert_eq!(
            fictionet::stdlib::test_support::decode_all(|| Collect::bytes(MAX_MESSAGE), b),
            if b.len() <= MAX_MESSAGE {
                (vec![b.to_vec()], None)
            } else {
                (
                    vec![],
                    Some(Fail::Protocol(CollectError::TooLong { limit: MAX_MESSAGE })),
                )
            }
        );
        let parsed = Advertisement::parse(b, e);
        let (items, failure) = decode_all(make, b);
        if b.len() <= MAX_MESSAGE {
            assert_eq!(failure, None);
            assert_eq!(items, vec![parsed.clone()]);
        } else {
            assert_eq!(
                failure,
                Some(Fail::Protocol(CollectError::TooLong { limit: MAX_MESSAGE }))
            );
        }
        parsed
    }

    fn ip4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    fn v4_ends() -> Endpoints {
        Endpoints::V4 {
            source: ip4(192, 168, 1, 2),
            destination: GROUP_V4,
        }
    }

    fn v6_ends() -> Endpoints {
        Endpoints::V6 {
            source: "fe80::2".parse().unwrap(),
            destination: GROUP_V6,
        }
    }

    /// `b` with its checksum field set right.
    fn fix(mut b: Vec<u8>, e: &Endpoints) -> Vec<u8> {
        if let Some(c) = checksum(&b, e) {
            b[6..8].copy_from_slice(&c.to_be_bytes());
        }
        b
    }

    fn round_trip(a: &Advertisement, e: &Endpoints) -> Vec<u8> {
        let b = a.frame(e).unwrap();
        assert_eq!(b.len(), a.encoded_len(e).unwrap());
        assert_eq!(Advertisement::parse(&b, e).as_ref(), Ok(a));
        b
    }

    #[test]
    fn module_example() {
        // The doctest's bytes, checked here too. Over IPv4 the checksum
        // covers the message alone (RFC 9568 section 5.2.8). The words are
        // 0x3101 + 0x6401 + 0x0064 + 0xc0a8 + 0x0101 = 0x1570f, folded
        // 0x5710, and its complement 0xa8ef.
        let bytes = [0x31, 1, 100, 1, 0, 100, 0xa8, 0xef, 192, 168, 1, 1];
        let ad = Advertisement::parse(&bytes, &v4_ends()).unwrap();
        let want = Advertisement::V3(AdvertisementV3 {
            vrid: 1,
            priority: 100,
            interval: 100,
            addresses: Addresses::V4(vec![ip4(192, 168, 1, 1)]),
        });
        assert_eq!(ad, want);
        assert_eq!(ad.frame(&v4_ends()).unwrap(), bytes);
        assert_eq!(ad.destination(), IpAddr::V4(GROUP_V4));
        assert_eq!(ad.interval_centiseconds(), 100);
    }

    #[test]
    fn v2_example() {
        // RFC 3768 section 5.1 layout: version 2, type 1, VRID 1, priority
        // 100, one address, no authentication, interval 1 second.
        let mut b = vec![0x21, 1, 100, 1, auth::NONE, 1, 0, 0, 192, 168, 0, 1];
        b.extend_from_slice(&[0; 8]);
        // 0x2101 + 0x6401 = 0x8502, + 0x0001 = 0x8503, + 0xc0a8 = 0x145ab,
        // + 0x0001 = 0x145ac. Folded 0x45ad, complement 0xba52.
        b[6] = 0xba;
        b[7] = 0x52;
        let ad = Advertisement::parse(&b, &v4_ends()).unwrap();
        let want = Advertisement::V2(AdvertisementV2 {
            vrid: 1,
            priority: 100,
            auth_type: auth::NONE,
            interval: 1,
            addresses: vec![ip4(192, 168, 0, 1)],
            auth_data: [0; 8],
        });
        assert_eq!(ad, want);
        assert_eq!(ad.frame(&v4_ends()).unwrap(), b);
        // Version 2 has no pseudo-header: any IPv4 endpoints read it.
        let other = Endpoints::V4 {
            source: ip4(10, 0, 0, 9),
            destination: ip4(10, 0, 0, 255),
        };
        assert_eq!(Advertisement::parse(&b, &other), Ok(ad.clone()));
        assert_eq!(ad.interval_centiseconds(), 100);
        assert_eq!(ad.version(), 2);
    }

    #[test]
    fn v2_simple_text_password() {
        // RFC 2338 put an 8-byte password in the authentication data.
        let ad = Advertisement::V2(AdvertisementV2 {
            vrid: 51,
            priority: PRIORITY_OWNER,
            auth_type: auth::SIMPLE_TEXT,
            interval: 3,
            addresses: vec![ip4(10, 0, 0, 1), ip4(10, 0, 0, 2)],
            auth_data: *b"secret\0\0",
        });
        let b = round_trip(&ad, &v4_ends());
        assert_eq!(b.len(), 8 + 8 + 8);
        assert_eq!(&b[16..], b"secret\0\0");
        assert_eq!(b[4], 1);
    }

    #[test]
    fn v3_ipv6_example() {
        let ends = v6_ends();
        let ad = Advertisement::V3(AdvertisementV3 {
            vrid: 7,
            priority: PRIORITY_DEFAULT,
            interval: 100,
            addresses: Addresses::V6(vec![
                "fe80::1".parse().unwrap(),
                "2001:db8::1".parse().unwrap(),
            ]),
        });
        let b = round_trip(&ad, &ends);
        assert_eq!(b.len(), 8 + 32);
        assert_eq!(&b[..6], &[0x31, 7, 100, 2, 0, 100]);
        assert_eq!(ad.destination(), IpAddr::V6(GROUP_V6));
        // The checksum covers the pseudo-header, worked out by hand here.
        let Endpoints::V6 {
            source,
            destination,
        } = ends
        else {
            panic!()
        };
        let mut ph = Vec::new();
        ph.extend_from_slice(&source.octets());
        ph.extend_from_slice(&destination.octets());
        ph.extend_from_slice(&(b.len() as u32).to_be_bytes());
        ph.extend_from_slice(&[0, 0, 0, 112]);
        ph.extend_from_slice(&b);
        assert_eq!(fold(sum_words(0, &ph)), 0xffff);
        // Another source makes the checksum wrong.
        let moved = Endpoints::V6 {
            source: "fe80::3".parse().unwrap(),
            destination: GROUP_V6,
        };
        assert_eq!(Advertisement::parse(&b, &moved), Err(Error::Checksum));
        // And the same bytes over IPv4 have the wrong length.
        assert_eq!(
            Advertisement::parse(&b, &v4_ends()),
            Err(Error::Trailing { remaining: 24 })
        );
    }

    #[test]
    fn v3_reserved_bits_ignored() {
        let b = vec![0x31, 1, 100, 1, 0xf0, 100, 0, 0, 192, 168, 1, 1];
        let b = fix(b, &v4_ends());
        let ad = Advertisement::parse(&b, &v4_ends()).unwrap();
        let Advertisement::V3(a) = &ad else { panic!() };
        assert_eq!(a.interval, 100);
        // Written back with the bits clear.
        assert_eq!(ad.frame(&v4_ends()).unwrap()[4], 0);
    }

    #[test]
    fn errors() {
        let e = v4_ends();
        let good = fix(vec![0x31, 1, 100, 1, 0, 100, 0, 0, 192, 168, 1, 1], &e);
        assert_eq!(Advertisement::parse(&[], &e), Err(Error::Truncated));
        let mut b = good.clone();
        b[0] = 0x11;
        assert_eq!(
            Advertisement::parse(&fix(b, &e), &e),
            Err(Error::Version(1))
        );
        let mut b = good.clone();
        b[0] = 0x32;
        assert_eq!(Advertisement::parse(&fix(b, &e), &e), Err(Error::Type(2)));
        let mut b = good.clone();
        b[1] = 0;
        assert_eq!(Advertisement::parse(&fix(b, &e), &e), Err(Error::Vrid));
        let mut b = good.clone();
        b[3] = 0;
        b.truncate(8);
        assert_eq!(
            Advertisement::parse(&fix(b, &e), &e),
            Err(Error::NoAddresses)
        );
        let mut b = good.clone();
        b.push(0);
        assert_eq!(
            Advertisement::parse(&b, &e),
            Err(Error::Trailing { remaining: 1 })
        );
        let mut b = good.clone();
        b[7] ^= 1;
        assert_eq!(Advertisement::parse(&b, &e), Err(Error::Checksum));
        // Version 2 over IPv6.
        let mut v2 = vec![0x21, 1, 100, 1, 0, 1, 0, 0, 10, 0, 0, 1];
        v2.extend_from_slice(&[0; 8]);
        let v2 = fix(v2, &e);
        assert!(Advertisement::parse(&v2, &e).is_ok());
        assert_eq!(Advertisement::parse(&v2, &v6_ends()), Err(Error::Family));

        // Writer errors.
        let v3 = |vrid, interval, addresses| {
            Advertisement::V3(AdvertisementV3 {
                vrid,
                priority: 1,
                interval,
                addresses,
            })
        };
        let one = Addresses::V4(vec![ip4(1, 2, 3, 4)]);
        assert_eq!(v3(0, 1, one.clone()).frame(&e), Err(Error::Vrid));
        assert_eq!(
            v3(1, 0x1000, one.clone()).frame(&e),
            Err(Error::Interval(0x1000))
        );
        assert_eq!(
            v3(1, 1, Addresses::V4(vec![])).frame(&e),
            Err(Error::NoAddresses)
        );
        assert_eq!(v3(1, 1, one.clone()).frame(&v6_ends()), Err(Error::Family));
        assert_eq!(
            v3(1, 1, Addresses::V4(vec![ip4(1, 1, 1, 1); 256])).frame(&e),
            Err(Error::TooManyAddresses(256))
        );
        assert!(
            v3(
                1,
                MAX_INTERVAL_V3,
                Addresses::V4(vec![ip4(1, 1, 1, 1); 255])
            )
            .frame(&e)
            .is_ok()
        );
        let mut most = vec![Ipv6Addr::LOCALHOST; MAX_ADDRESSES];
        most[0] = "fe80::1".parse().unwrap();
        let max6 = v3(255, 1, Addresses::V6(most));
        assert_eq!(round_trip(&max6, &v6_ends()).len(), MAX_MESSAGE);
        let v2 = |vrid, n| {
            Advertisement::V2(AdvertisementV2 {
                vrid,
                priority: 1,
                auth_type: 0,
                interval: 1,
                addresses: vec![ip4(1, 1, 1, 1); n],
                auth_data: [0; 8],
            })
        };
        assert_eq!(v2(0, 1).frame(&e), Err(Error::Vrid));
        assert_eq!(v2(1, 256).frame(&e), Err(Error::TooManyAddresses(256)));
        assert_eq!(v2(1, 1).frame(&v6_ends()), Err(Error::Family));
        // A version 2 advertisement needs an address too (RFC 3768
        // section 5.3.9).
        assert_eq!(v2(1, 0).frame(&e), Err(Error::NoAddresses));
        // Every error has a message.
        for err in [
            Error::Truncated,
            Error::Family,
            Error::Checksum,
            Error::Version(9),
        ] {
            assert!(!err.to_string().is_empty());
        }
    }

    #[test]
    fn negative_zero_checksum() {
        // 0x2101 + 0x6401 + 0x0001 + 0x7afc = 0xffff, so the checksum is
        // 0x0000. In ones' complement 0xffff is the same number, and a
        // receiver that sums the whole message accepts either.
        let mut b = vec![0x21, 1, 100, 1, 0, 1, 0, 0, 0x7a, 0xfc, 0, 0];
        b.extend_from_slice(&[0; 8]);
        let e = v4_ends();
        assert_eq!(checksum(&b, &e), Some(0));
        let ad = Advertisement::parse(&b, &e).unwrap();
        b[6] = 0xff;
        b[7] = 0xff;
        assert_eq!(Advertisement::parse(&b, &e), Ok(ad.clone()));
        assert_eq!(collect(&b, &e), Ok(ad.clone()));
        // The writer always sends 0x0000.
        assert_eq!(&ad.frame(&e).unwrap()[6..8], &[0, 0]);
        // 0xffff is not taken for any other checksum.
        let good = fix(vec![0x31, 1, 100, 1, 0, 100, 0, 0, 192, 168, 1, 1], &e);
        let mut bad = good.clone();
        bad[6] = 0xff;
        bad[7] = 0xff;
        assert_ne!(good[6..8], [0xff, 0xff]);
        assert_eq!(Advertisement::parse(&bad, &e), Err(Error::Checksum));
    }

    #[test]
    fn checksum_bounds() {
        assert_eq!(checksum(&[0x31; 7], &v4_ends()), None);
        assert_eq!(checksum(&vec![0x31; MAX_MESSAGE + 1], &v4_ends()), None);
        assert!(checksum(&vec![0x31; MAX_MESSAGE], &v6_ends()).is_some());
    }

    fn samples() -> Vec<(Advertisement, Endpoints)> {
        vec![
            (
                Advertisement::V2(AdvertisementV2 {
                    vrid: 1,
                    priority: 100,
                    auth_type: 0,
                    interval: 1,
                    addresses: vec![ip4(192, 168, 0, 1), ip4(192, 168, 0, 2)],
                    auth_data: [0; 8],
                }),
                v4_ends(),
            ),
            (
                Advertisement::V3(AdvertisementV3 {
                    vrid: 9,
                    priority: 0,
                    interval: 4095,
                    addresses: Addresses::V4(vec![ip4(10, 0, 0, 1)]),
                }),
                v4_ends(),
            ),
            (
                Advertisement::V3(AdvertisementV3 {
                    vrid: 255,
                    priority: 255,
                    interval: 0,
                    addresses: Addresses::V6(vec!["fe80::1".parse().unwrap()]),
                }),
                v6_ends(),
            ),
        ]
    }

    #[test]
    fn every_truncated_prefix_fails() {
        for (a, e) in samples() {
            let b = a.frame(&e).unwrap();
            for n in 0..b.len() {
                let p = &b[..n];
                assert_eq!(
                    Advertisement::parse(p, &e),
                    Err(Error::Truncated),
                    "{a:?} prefix {n}"
                );
                assert_eq!(
                    Advertisement::parse(&fix(p.to_vec(), &e), &e),
                    Err(Error::Truncated)
                );
                assert_eq!(collect(p, &e), Err(Error::Truncated));
            }
        }
    }

    #[test]
    fn collection_matches_parse() {
        for (a, e) in samples() {
            let mut b = a.frame(&e).unwrap();
            assert_eq!(collect(&b, &e), Ok(a));
            b.push(0);
            assert_eq!(collect(&b, &e), Err(Error::Trailing { remaining: 1 }));
        }
        assert_eq!(collect(&[0x41], &v4_ends()), Err(Error::Version(4)));
        let mut b = vec![0; 10_000];
        b[..4].copy_from_slice(&[0x31, 1, 1, 255]);
        assert!(collect(&b, &v6_ends()).is_err());
    }

    #[test]
    fn accessors() {
        let e = Endpoints::new(IpAddr::V4(ip4(192, 168, 1, 2)), IpAddr::V4(GROUP_V4)).unwrap();
        assert_eq!(e, v4_ends());
        assert_eq!(e.source(), IpAddr::V4(ip4(192, 168, 1, 2)));
        assert_eq!(e.destination(), IpAddr::V4(GROUP_V4));
        let e6 = Endpoints::new("fe80::2".parse().unwrap(), IpAddr::V6(GROUP_V6)).unwrap();
        assert_eq!(e6, v6_ends());
        assert_eq!(e6.destination(), IpAddr::V6(GROUP_V6));
        assert_eq!(
            Endpoints::new(IpAddr::V4(GROUP_V4), IpAddr::V6(GROUP_V6)),
            None
        );
        for (a, e) in samples() {
            assert_eq!(a.address_count(), a.addresses().len());
            assert_eq!(a.address_count(), a.addresses().count());
            let b = a.frame(&e).unwrap();
            assert_eq!(usize::from(b[3]), a.address_count());
        }
        let v3 = AdvertisementV3 {
            vrid: 1,
            priority: 1,
            interval: 1,
            addresses: Addresses::V6(vec![Ipv6Addr::LOCALHOST]),
        };
        assert_eq!(
            v3.addresses.iter().collect::<Vec<_>>(),
            vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]
        );
        let a: Advertisement = v3.clone().into();
        assert_eq!(a, Advertisement::V3(v3));
        assert_eq!(
            a.addresses().collect::<Vec<_>>(),
            vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]
        );
        let v2 = AdvertisementV2 {
            vrid: 1,
            priority: 1,
            auth_type: 0,
            interval: 1,
            addresses: vec![ip4(1, 2, 3, 4)],
            auth_data: [0; 8],
        };
        let a: Advertisement = v2.clone().into();
        assert_eq!(a, Advertisement::V2(v2));
        assert_eq!(
            a.addresses().collect::<Vec<_>>(),
            vec![IpAddr::V4(ip4(1, 2, 3, 4))]
        );
        // The accessors borrow: a huge caller-made list is walked, not
        // copied.
        let n = rounds(100_000);
        let huge = Addresses::V4(vec![Ipv4Addr::LOCALHOST; n]);
        assert_eq!(huge.iter().len(), n);
        assert_eq!(
            huge.iter().nth(99_999),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        // Every error has a message.
        for err in [
            Error::Truncated,
            Error::Trailing { remaining: 1 },
            Error::Version(9),
            Error::Type(2),
            Error::Vrid,
            Error::NoAddresses,
            Error::AuthType(3),
            Error::LinkLocal,
            Error::TooManyAddresses(256),
            Error::Interval(5000),
            Error::Family,
            Error::Checksum,
        ] {
            assert!(!err.to_string().is_empty());
        }
    }

    #[test]
    fn v4_v3_checksum_is_message_only() {
        // RFC 9568 section 5.2.8: over IPv4 the sum covers the message
        // alone, so the endpoints do not change it.
        let bytes = [0x31, 1, 100, 1, 0, 100, 0xa8, 0xef, 192, 168, 1, 1];
        let e = v4_ends();
        assert_eq!(checksum(&bytes, &e), Some(0xa8ef));
        let ad = Advertisement::parse(&bytes, &e).unwrap();
        let other = Endpoints::V4 {
            source: ip4(10, 0, 0, 9),
            destination: ip4(10, 0, 0, 255),
        };
        assert_eq!(Advertisement::parse(&bytes, &other), Ok(ad.clone()));
        assert_eq!(ad.frame(&other).unwrap(), bytes);
    }

    #[test]
    fn v4_v3_checksum_rfc5798() {
        // RFC 5798 routers such as Keepalived add an IPv4 pseudo-header.
        // The pseudo-header words are 0xc0a8 + 0x0102 + 0xe000 + 0x0012 +
        // 0x0070 + 0x000c = 0x1a238. With the message's 0x1570f that is
        // 0x2f947, folded 0xf949, and its complement 0x06b6.
        let e = v4_ends();
        let rfc5798 = [0x31, 1, 100, 1, 0, 100, 0x06, 0xb6, 192, 168, 1, 1];
        assert_eq!(checksum_rfc5798(&rfc5798, &e), Some(0x06b6));
        let ad = Advertisement::parse(&rfc5798, &e).unwrap();
        assert_eq!(collect(&rfc5798, &e), Ok(ad.clone()));
        // Written, it carries the RFC 9568 checksum.
        assert_eq!(&ad.frame(&e).unwrap()[6..8], &[0xa8, 0xef]);
        // The RFC 5798 sum depends on the endpoints.
        let other = Endpoints::V4 {
            source: ip4(10, 0, 0, 9),
            destination: GROUP_V4,
        };
        assert_eq!(Advertisement::parse(&rfc5798, &other), Err(Error::Checksum));
        // Version 2 and IPv6 have one checksum each: the RFC 5798 sum is
        // the same.
        let mut v2 = vec![0x21, 1, 100, 1, 0, 1, 0, 0, 192, 168, 0, 1];
        v2.extend_from_slice(&[0; 8]);
        assert_eq!(checksum_rfc5798(&v2, &e), checksum(&v2, &e));
        let v6 = samples()[2].0.frame(&v6_ends()).unwrap();
        assert_eq!(checksum_rfc5798(&v6, &v6_ends()), checksum(&v6, &v6_ends()));
    }

    #[test]
    fn v2_needs_an_address() {
        // RFC 3768 section 5.3.9: one or more addresses.
        let mut v2 = vec![0x21, 1, 100, 0, 0, 1, 0, 0];
        v2.extend_from_slice(&[0; 8]);
        let v2 = fix(v2, &v4_ends());
        assert_eq!(
            Advertisement::parse(&v2, &v4_ends()),
            Err(Error::NoAddresses)
        );
        assert_eq!(collect(&v2[..4], &v4_ends()), Err(Error::NoAddresses));
    }

    #[test]
    fn v6_link_local() {
        let ad = |first: &str| {
            Advertisement::V3(AdvertisementV3 {
                vrid: 1,
                priority: 100,
                interval: 100,
                addresses: Addresses::V6(vec![
                    first.parse().unwrap(),
                    "2001:db8::9".parse().unwrap(),
                ]),
            })
        };
        let global = Endpoints::V6 {
            source: "2001:db8::2".parse().unwrap(),
            destination: GROUP_V6,
        };
        // The writer checks the first address and the source.
        assert_eq!(ad("2001:db8::1").frame(&v6_ends()), Err(Error::LinkLocal));
        assert_eq!(ad("fe80::1").frame(&global), Err(Error::LinkLocal));
        // Later addresses may be global; fe80::/10 runs to febf.
        round_trip(&ad("febf::1"), &v6_ends());
        assert_eq!(ad("fec0::1").frame(&v6_ends()), Err(Error::LinkLocal));
        // The reader checks both too, with a right checksum.
        let mut b = vec![0x31, 1, 100, 1, 0, 100, 0, 0];
        b.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(
            Advertisement::parse(&fix(b.clone(), &v6_ends()), &v6_ends()),
            Err(Error::LinkLocal)
        );
        assert_eq!(
            collect(&fix(b, &v6_ends()), &v6_ends()),
            Err(Error::LinkLocal)
        );
        let good = ad("fe80::1").frame(&v6_ends()).unwrap();
        assert_eq!(
            Advertisement::parse(&fix(good.clone(), &global), &global),
            Err(Error::LinkLocal)
        );
        // A source that is not link-local fails on the first byte.
        assert_eq!(collect(&good[..1], &global), Err(Error::LinkLocal));
    }

    #[test]
    fn v2_unknown_auth_type() {
        // RFC 3768 section 5.3.6 defines types 0, 1 and 2 only.
        let mut b = vec![0x21, 1, 100, 1, 0xff, 1, 0, 0, 192, 168, 1, 1];
        b.extend_from_slice(&[0; 8]);
        let b = fix(b, &v4_ends());
        assert_eq!(
            Advertisement::parse(&b, &v4_ends()),
            Err(Error::AuthType(255))
        );
        assert_eq!(collect(&b[..5], &v4_ends()), Err(Error::AuthType(255)));
        let ad = |auth_type| {
            Advertisement::V2(AdvertisementV2 {
                vrid: 1,
                priority: 100,
                auth_type,
                interval: 1,
                addresses: vec![ip4(192, 168, 1, 1)],
                auth_data: [0; 8],
            })
        };
        assert_eq!(ad(3).frame(&v4_ends()), Err(Error::AuthType(3)));
        for t in [auth::NONE, auth::SIMPLE_TEXT, auth::IP_AH] {
            round_trip(&ad(t), &v4_ends());
        }
    }

    trait Samples {
        fn v6(&mut self) -> Ipv6Addr;
        fn link_local(&mut self) -> Ipv6Addr;
        fn endpoints(&mut self) -> Endpoints;
        fn any_endpoints(&mut self) -> Endpoints;
    }

    impl Samples for Lcg {
        fn v6(&mut self) -> Ipv6Addr {
            let hi = u64::from(self.next() as u32) << 32 | u64::from(self.next() as u32);
            let lo = u64::from(self.next() as u32) << 32 | u64::from(self.next() as u32);
            Ipv6Addr::from(u128::from(hi) << 64 | u128::from(lo))
        }
        /// A random IPv6 address in fe80::/10.
        fn link_local(&mut self) -> Ipv6Addr {
            let mut s = self.v6().segments();
            s[0] = 0xfe80 | (s[0] & 0x003f);
            Ipv6Addr::from(s)
        }
        /// Endpoints a writer accepts: an IPv6 source is link-local.
        fn endpoints(&mut self) -> Endpoints {
            if !self.coin() {
                Endpoints::V4 {
                    source: Ipv4Addr::from(self.next() as u32),
                    destination: GROUP_V4,
                }
            } else {
                Endpoints::V6 {
                    source: self.link_local(),
                    destination: GROUP_V6,
                }
            }
        }
        /// Endpoints of any kind, an IPv6 source of any address included.
        fn any_endpoints(&mut self) -> Endpoints {
            match self.index(3) {
                0 => Endpoints::V6 {
                    source: self.v6(),
                    destination: GROUP_V6,
                },
                _ => self.endpoints(),
            }
        }
    }

    /// A random advertisement the writer accepts for `e`.
    fn random_ad(rng: &mut Lcg, e: &Endpoints) -> Advertisement {
        let vrid = (rng.index(255) + 1) as u8;
        let priority = rng.next() as u8;
        if matches!(e, Endpoints::V4 { .. }) && !rng.coin() {
            let mut auth_data = [0u8; 8];
            rng.fill(&mut auth_data);
            return Advertisement::V2(AdvertisementV2 {
                vrid,
                priority,
                auth_type: rng.index(3) as u8,
                interval: rng.next() as u8,
                addresses: (0..rng.index(5) + 1)
                    .map(|_| Ipv4Addr::from(rng.next() as u32))
                    .collect(),
                auth_data,
            });
        }
        let n = rng.index(5) + 1;
        let addresses = match e {
            Endpoints::V4 { .. } => {
                Addresses::V4((0..n).map(|_| Ipv4Addr::from(rng.next() as u32)).collect())
            }
            Endpoints::V6 { .. } => Addresses::V6(
                (0..n)
                    .map(|i| if i == 0 { rng.link_local() } else { rng.v6() })
                    .collect(),
            ),
        };
        let interval = rng.index(usize::from(MAX_INTERVAL_V3) + 1) as u16;
        Advertisement::V3(AdvertisementV3 {
            vrid,
            priority,
            interval,
            addresses,
        })
    }

    fn check_bytes(data: &[u8], e: &Endpoints) {
        let parsed = Advertisement::parse(data, e);
        if let Ok(a) = &parsed {
            // An advertisement read can be written, and reads back the same.
            let out = a.frame(e).unwrap();
            assert_eq!(out.len(), data.len());
            assert_eq!(Advertisement::parse(&out, e).as_ref(), Ok(a));
        }
        assert_eq!(collect(data, e), parsed);
    }

    #[test]
    fn fuzz_loop() {
        let mut rng = Lcg::new(0x5798_3768_0112);
        for _ in 0..4000 {
            let e = rng.endpoints();
            let a = random_ad(&mut rng, &e);
            let b = round_trip(&a, &e);
            check_bytes(&b, &e);
            // Flip some bytes, cut or extend, and fix the checksum most of
            // the time so the parser looks past it.
            let mut mutated = b.clone();
            for _ in 0..1 + rng.index(4) {
                mutate(&mut rng, &mut mutated);
            }
            if rng.index(4) != 0 {
                mutated = fix(mutated, &e);
            }
            check_bytes(&mutated, &e);
            // The same bytes read with other endpoints, maybe another
            // family or a source that is not link-local.
            let other = rng.any_endpoints();
            check_bytes(&mutated, &other);
            // Plain random bytes, with a likely first byte and a right
            // checksum.
            let mut raw = rng.bytes(80);
            if let Some(t) = raw.first_mut() {
                *t = [0x21, 0x31, rng.next() as u8][rng.index(3)];
            }
            if let Some(c) = raw.get_mut(3) {
                *c %= 8;
            }
            check_bytes(&fix(raw, &e), &e);
        }
    }
}
