//! VRRP: reading and writing virtual router advertisements, with no I/O.
//!
//! VRRP (the Virtual Router Redundancy Protocol, IP protocol 112) lets
//! several routers on a link share one gateway address. The routers form a
//! virtual router, named by a number from 1 to 255 (the VRID). The one with
//! the highest priority is the master: it answers for the shared addresses
//! and sends an advertisement every interval. The others are backups. A
//! backup that stops hearing advertisements takes over, and one with a
//! higher priority than the master may take over at once. A master that
//! shuts down sends one last advertisement with priority 0.
//!
//! VRRP has two versions in use. Version 2 (RFC 3768) is for IPv4 only. It
//! gives the interval in seconds and carries an authentication type and 8
//! bytes of authentication data. Version 3 (RFC 5798) works over IPv4 and
//! IPv6. It gives the interval in centiseconds and has no authentication.
//! Its checksum also covers a pseudo-header made from the IP header, so the
//! source and destination addresses must be known to read or write one.
//!
//! Nothing here reads a socket. A world that plays a router hands each
//! VRRP payload (the bytes after the IP header) to [`Advertisement::parse`]
//! with the packet's [`Endpoints`], looks at the [`Advertisement`], and
//! sends the bytes [`Advertisement::to_bytes`] returns in an IP packet with
//! protocol [`PROTOCOL`] and a TTL or hop limit of [`HOP_LIMIT`], to the
//! address [`Advertisement::destination`] gives. A [`Decoder`] reads a
//! payload that comes in pieces and reports a bad header as soon as the
//! bytes show it. Which virtual routers exist, their priorities, and when
//! a backup takes over are up to world code.
//!
//! Every reader checks the version, type, VRID, address count, length and
//! checksum, because the agent can send any bytes it likes. The payload
//! must be exactly as long as its address count says. The reserved bits of
//! a version 3 advertisement are ignored when read and written as zero.
//! Writers check the same rules as readers, so bytes they return always
//! read back.
//!
//! ```
//! use std::net::{IpAddr, Ipv4Addr};
//! use fictionet::stdlib::vrrp::{Addresses, Advertisement, AdvertisementV3, Endpoints, GROUP_V4};
//!
//! /// Whether a backup router with priority `mine` takes over when it
//! /// hears `ad` for its virtual router `vrid`.
//! fn take_over(vrid: u8, mine: u8, ad: &Advertisement) -> bool {
//!     ad.vrid() == vrid && (ad.priority() == 0 || ad.priority() < mine)
//! }
//!
//! // The master, 192.168.1.2, advertises 192.168.1.1 for virtual router 1
//! // at priority 100, once a second (100 centiseconds).
//! let master = Endpoints::V4 { source: Ipv4Addr::new(192, 168, 1, 2), destination: GROUP_V4 };
//! let bytes = [0x31, 1, 100, 1, 0, 100, 0x06, 0xb6, 192, 168, 1, 1];
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
//! assert!(!take_over(1, 90, &ad));
//! assert!(take_over(1, 110, &ad));
//! // Written back, the advertisement is the same bytes.
//! assert_eq!(ad.to_bytes(&master).unwrap(), bytes);
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

/// Version 2 authentication types.
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

/// The IP source and destination of the packet that carries an
/// advertisement. Version 3 checksums cover them, and they say whether a
/// version 3 advertisement's addresses are IPv4 or IPv6.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Endpoints {
    /// An IPv4 packet.
    V4 {
        /// The sending router's own address on the link.
        source: Ipv4Addr,
        /// Usually [`GROUP_V4`].
        destination: Ipv4Addr,
    },
    /// An IPv6 packet.
    V6 {
        /// The sending router's link-local address.
        source: Ipv6Addr,
        /// Usually [`GROUP_V6`].
        destination: Ipv6Addr,
    },
}

impl Endpoints {
    /// The length of one address in an advertisement this packet carries:
    /// 4 for IPv4 and 16 for IPv6.
    pub fn address_len(&self) -> usize {
        match self {
            Endpoints::V4 { .. } => 4,
            Endpoints::V6 { .. } => 16,
        }
    }

    /// The endpoints of a packet from `source` to `destination`, or `None`
    /// if the two are of different families.
    pub fn new(source: IpAddr, destination: IpAddr) -> Option<Endpoints> {
        match (source, destination) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => Some(Endpoints::V4 { source, destination }),
            (IpAddr::V6(source), IpAddr::V6(destination)) => Some(Endpoints::V6 { source, destination }),
            _ => None,
        }
    }

    /// The packet's source address.
    pub fn source(&self) -> IpAddr {
        match self {
            Endpoints::V4 { source, .. } => IpAddr::V4(*source),
            Endpoints::V6 { source, .. } => IpAddr::V6(*source),
        }
    }

    /// The packet's destination address.
    pub fn destination(&self) -> IpAddr {
        match self {
            Endpoints::V4 { destination, .. } => IpAddr::V4(*destination),
            Endpoints::V6 { destination, .. } => IpAddr::V6(*destination),
        }
    }
}

/// A version 2 advertisement (RFC 3768). It is always carried over IPv4.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AdvertisementV2 {
    /// The virtual router: 1 to 255.
    pub vrid: u8,
    /// The sender's priority. See [`PRIORITY_OWNER`], [`PRIORITY_STOP`]
    /// and [`PRIORITY_DEFAULT`].
    pub priority: u8,
    /// The authentication type, one of the values in [`auth`] or another.
    /// A receiver drops an advertisement whose type differs from its own.
    pub auth_type: u8,
    /// How often the master advertises, in seconds.
    pub interval: u8,
    /// The virtual router's addresses. At most [`MAX_ADDRESSES`].
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
    /// address.
    V6(Vec<Ipv6Addr>),
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

    /// The addresses, as [`IpAddr`] values.
    pub fn to_ip_addrs(&self) -> Vec<IpAddr> {
        match self {
            Addresses::V4(a) => a.iter().map(|x| IpAddr::V4(*x)).collect(),
            Addresses::V6(a) => a.iter().map(|x| IpAddr::V6(*x)).collect(),
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
pub enum VrrpError {
    /// The bytes end before the advertisement does.
    Truncated,
    /// The bytes go on past the end the address count gives.
    Trailing,
    /// The version was not 2 or 3.
    Version(u8),
    /// The type was not [`TYPE_ADVERTISEMENT`].
    Type(u8),
    /// The VRID was 0. Virtual routers are numbered from 1.
    Vrid,
    /// A version 3 advertisement had no addresses. RFC 5798 asks for at
    /// least one.
    NoAddresses,
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

impl std::fmt::Display for VrrpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VrrpError::Truncated => write!(f, "the advertisement is cut short"),
            VrrpError::Trailing => write!(f, "bytes follow the end of the advertisement"),
            VrrpError::Version(v) => write!(f, "version {v}, not 2 or 3"),
            VrrpError::Type(t) => write!(f, "type {t}, not 1 (advertisement)"),
            VrrpError::Vrid => write!(f, "VRID 0, outside 1..=255"),
            VrrpError::NoAddresses => write!(f, "a version 3 advertisement with no addresses"),
            VrrpError::TooManyAddresses(n) => write!(f, "{n} addresses, more than {MAX_ADDRESSES}"),
            VrrpError::Interval(i) => write!(f, "interval {i}, above {MAX_INTERVAL_V3}"),
            VrrpError::Family => write!(f, "the addresses and the IP packet are of different families"),
            VrrpError::Checksum => write!(f, "the checksum is wrong"),
        }
    }
}

impl std::error::Error for VrrpError {}

/// Adds `b` to a ones' complement sum, as 16-bit words with a zero byte
/// added to an odd length.
fn sum_words(mut sum: u64, b: &[u8]) -> u64 {
    let mut words = b.chunks_exact(2);
    for w in &mut words {
        sum += u64::from(u16::from_be_bytes([w[0], w[1]]));
    }
    if let [last] = words.remainder() {
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

/// The checksum the advertisement in `b` should carry, worked out with its
/// checksum field (bytes 6 and 7) taken as zero. A version 3 advertisement
/// (a first byte whose high four bits are 3) includes the pseudo-header of
/// RFC 2460 section 8.1 for IPv6, or its IPv4 equivalent (source,
/// destination, a zero byte, the protocol and a 16-bit length), with
/// protocol [`PROTOCOL`]. Any other version covers the message alone. It
/// returns `None` if `b` is shorter than [`HEADER_LEN`] or longer than
/// [`MAX_MESSAGE`].
pub fn checksum(b: &[u8], endpoints: &Endpoints) -> Option<u16> {
    if b.len() < HEADER_LEN || b.len() > MAX_MESSAGE {
        return None;
    }
    let mut sum = sum_words(0, &b[..6]);
    sum = sum_words(sum, &b[HEADER_LEN..]);
    if b[0] >> 4 == 3 {
        // MAX_MESSAGE fits in 16 bits, so the length does too.
        let len = b.len() as u16;
        match endpoints {
            Endpoints::V4 { source, destination } => {
                sum = sum_words(sum, &source.octets());
                sum = sum_words(sum, &destination.octets());
                sum = sum_words(sum, &[0, PROTOCOL]);
                sum = sum_words(sum, &len.to_be_bytes());
            }
            Endpoints::V6 { source, destination } => {
                sum = sum_words(sum, &source.octets());
                sum = sum_words(sum, &destination.octets());
                sum = sum_words(sum, &u32::from(len).to_be_bytes());
                sum = sum_words(sum, &[0, 0, 0, PROTOCOL]);
            }
        }
    }
    Some(!fold(sum))
}

/// Checks the header fields the bytes so far hold, in the order they come.
/// Once the count is known it returns the advertisement's full length.
/// Every error it gives holds for any bytes that could follow, which lets
/// [`Decoder`] stop early and still agree with [`Advertisement::parse`].
fn check_header(b: &[u8], endpoints: &Endpoints) -> Result<Option<usize>, VrrpError> {
    let Some(&first) = b.first() else { return Ok(None) };
    let version = first >> 4;
    if version != 2 && version != 3 {
        return Err(VrrpError::Version(version));
    }
    if first & 0x0f != TYPE_ADVERTISEMENT {
        return Err(VrrpError::Type(first & 0x0f));
    }
    if version == 2 && matches!(endpoints, Endpoints::V6 { .. }) {
        return Err(VrrpError::Family);
    }
    match b.get(1) {
        None => return Ok(None),
        Some(0) => return Err(VrrpError::Vrid),
        Some(_) => {}
    }
    let Some(&count) = b.get(3) else { return Ok(None) };
    if version == 3 && count == 0 {
        return Err(VrrpError::NoAddresses);
    }
    // At most 8 + 255 * 16, so this cannot overflow.
    let auth = if version == 2 { AUTH_DATA_LEN } else { 0 };
    Ok(Some(HEADER_LEN + usize::from(count) * endpoints.address_len() + auth))
}

impl Advertisement {
    /// Reads the advertisement in `b`, the whole VRRP payload of one IP
    /// packet, sent from and to `endpoints`. The checksum must be right,
    /// and `b` must end where the address count says. A checksum of 0xffff
    /// is taken where 0x0000 is due, since the two are equal in ones'
    /// complement.
    pub fn parse(b: &[u8], endpoints: &Endpoints) -> Result<Advertisement, VrrpError> {
        let len = check_header(b, endpoints)?.ok_or(VrrpError::Truncated)?;
        if b.len() < len {
            return Err(VrrpError::Truncated);
        }
        if b.len() > len {
            return Err(VrrpError::Trailing);
        }
        let want = checksum(b, endpoints).ok_or(VrrpError::Truncated)?;
        let got = u16::from_be_bytes([b[6], b[7]]);
        // In ones' complement 0xffff and 0x0000 are both zero, so a sum of
        // the whole message passes with either.
        if got != want && !(want == 0 && got == 0xffff) {
            return Err(VrrpError::Checksum);
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
            Endpoints::V6 { .. } => Addresses::V6(
                body.chunks_exact(16)
                    .map(|c| {
                        let mut o = [0u8; 16];
                        o.copy_from_slice(c);
                        Ipv6Addr::from(o)
                    })
                    .collect(),
            ),
        };
        Ok(Advertisement::V3(AdvertisementV3 { vrid, priority, interval, addresses }))
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

    /// The virtual router's addresses, as [`IpAddr`] values.
    pub fn addresses(&self) -> Vec<IpAddr> {
        match self {
            Advertisement::V2(a) => a.addresses.iter().map(|x| IpAddr::V4(*x)).collect(),
            Advertisement::V3(a) => a.addresses.to_ip_addrs(),
        }
    }

    /// Where the advertisement is sent: [`GROUP_V6`] for a version 3
    /// advertisement of IPv6 addresses, and [`GROUP_V4`] otherwise.
    pub fn destination(&self) -> IpAddr {
        match self {
            Advertisement::V3(AdvertisementV3 { addresses: Addresses::V6(_), .. }) => IpAddr::V6(GROUP_V6),
            _ => IpAddr::V4(GROUP_V4),
        }
    }

    /// How many bytes [`Advertisement::to_bytes`] writes, or why it cannot
    /// write the advertisement to go from and to `endpoints`.
    pub fn encoded_len(&self, endpoints: &Endpoints) -> Result<usize, VrrpError> {
        let (vrid, count, auth) = match self {
            Advertisement::V2(a) => {
                if matches!(endpoints, Endpoints::V6 { .. }) {
                    return Err(VrrpError::Family);
                }
                (a.vrid, a.addresses.len(), AUTH_DATA_LEN)
            }
            Advertisement::V3(a) => {
                let family_ok = matches!(
                    (&a.addresses, endpoints),
                    (Addresses::V4(_), Endpoints::V4 { .. }) | (Addresses::V6(_), Endpoints::V6 { .. })
                );
                if !family_ok {
                    return Err(VrrpError::Family);
                }
                if a.interval > MAX_INTERVAL_V3 {
                    return Err(VrrpError::Interval(a.interval));
                }
                if a.addresses.is_empty() {
                    return Err(VrrpError::NoAddresses);
                }
                (a.vrid, a.addresses.len(), 0)
            }
        };
        if vrid == 0 {
            return Err(VrrpError::Vrid);
        }
        if count > MAX_ADDRESSES {
            return Err(VrrpError::TooManyAddresses(count));
        }
        Ok(HEADER_LEN + count * endpoints.address_len() + auth)
    }

    /// The advertisement's bytes, to go from and to `endpoints`, with the
    /// checksum filled in. It fails if the VRID is 0, there are more than
    /// [`MAX_ADDRESSES`] addresses, a version 3 advertisement has none or
    /// an interval above [`MAX_INTERVAL_V3`], or the addresses are not of
    /// the packet's family. Nothing is allocated before those checks pass.
    pub fn to_bytes(&self, endpoints: &Endpoints) -> Result<Vec<u8>, VrrpError> {
        let len = self.encoded_len(endpoints)?;
        let mut out = Vec::with_capacity(len);
        match self {
            Advertisement::V2(a) => {
                out.extend_from_slice(&[0x20 | TYPE_ADVERTISEMENT, a.vrid, a.priority, a.addresses.len() as u8]);
                out.extend_from_slice(&[a.auth_type, a.interval, 0, 0]);
                for x in &a.addresses {
                    out.extend_from_slice(&x.octets());
                }
                out.extend_from_slice(&a.auth_data);
            }
            Advertisement::V3(a) => {
                out.extend_from_slice(&[0x30 | TYPE_ADVERTISEMENT, a.vrid, a.priority, a.addresses.len() as u8]);
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
    b.chunks_exact(4).map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3])).collect()
}

/// Reads one advertisement that comes in pieces. Feed it the bytes in
/// order, then call [`Decoder::finish`]. It fails as soon as the bytes show
/// a bad version, type, VRID or address count, or run past the length the
/// count gives. It holds at most [`MAX_MESSAGE`] plus one bytes.
#[derive(Clone, Debug)]
pub struct Decoder {
    endpoints: Endpoints,
    buf: Vec<u8>,
    failed: Option<VrrpError>,
}

impl Decoder {
    /// A decoder for an advertisement sent from and to `endpoints`,
    /// holding no bytes.
    pub fn new(endpoints: Endpoints) -> Decoder {
        Decoder { endpoints, buf: Vec::new(), failed: None }
    }

    /// Adds the next bytes of the advertisement. It returns the error once
    /// the bytes show one, and the same error on every later call; bytes
    /// fed after that are dropped.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), VrrpError> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        // One byte past the longest advertisement is enough to know it is
        // too long.
        let room = (MAX_MESSAGE + 1).saturating_sub(self.buf.len());
        self.buf.extend_from_slice(&bytes[..bytes.len().min(room)]);
        match check_header(&self.buf, &self.endpoints) {
            Err(e) => Err(self.fail(e)),
            Ok(Some(len)) if self.buf.len() > len => Err(self.fail(VrrpError::Trailing)),
            Ok(_) => Ok(()),
        }
    }

    fn fail(&mut self, e: VrrpError) -> VrrpError {
        self.failed = Some(e);
        self.buf = Vec::new();
        e
    }

    /// How many bytes are held.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Whether the bytes held are exactly as long as the header says the
    /// advertisement is. The checksum is not checked until
    /// [`Decoder::finish`].
    pub fn is_complete(&self) -> bool {
        self.failed.is_none() && matches!(check_header(&self.buf, &self.endpoints), Ok(Some(n)) if n == self.buf.len())
    }

    /// The endpoints the decoder was made for.
    pub fn endpoints(&self) -> &Endpoints {
        &self.endpoints
    }

    /// The advertisement, when no more bytes will come. It gives the same
    /// result as [`Advertisement::parse`] on all the bytes fed.
    pub fn finish(self) -> Result<Advertisement, VrrpError> {
        match self.failed {
            Some(e) => Err(e),
            None => Advertisement::parse(&self.buf, &self.endpoints),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    fn v4_ends() -> Endpoints {
        Endpoints::V4 { source: ip4(192, 168, 1, 2), destination: GROUP_V4 }
    }

    fn v6_ends() -> Endpoints {
        Endpoints::V6 { source: "fe80::2".parse().unwrap(), destination: GROUP_V6 }
    }

    /// `b` with its checksum field set right.
    fn fix(mut b: Vec<u8>, e: &Endpoints) -> Vec<u8> {
        if let Some(c) = checksum(&b, e) {
            b[6..8].copy_from_slice(&c.to_be_bytes());
        }
        b
    }

    fn decode_chunked(b: &[u8], e: &Endpoints, size: usize) -> Result<Advertisement, VrrpError> {
        let mut d = Decoder::new(*e);
        for c in b.chunks(size.max(1)) {
            let _ = d.feed(c);
        }
        d.finish()
    }

    fn decode_whole(b: &[u8], e: &Endpoints) -> Result<Advertisement, VrrpError> {
        let mut d = Decoder::new(*e);
        let _ = d.feed(b);
        d.finish()
    }

    fn round_trip(a: &Advertisement, e: &Endpoints) -> Vec<u8> {
        let b = a.to_bytes(e).unwrap();
        assert_eq!(b.len(), a.encoded_len(e).unwrap());
        assert_eq!(Advertisement::parse(&b, e).as_ref(), Ok(a));
        b
    }

    #[test]
    fn module_example() {
        // The doctest's bytes, checked here too. The message words are
        // 0x3101 + 0x6401 + 0x0064 + 0xc0a8 + 0x0101 = 0x1570f. The
        // pseudo-header words are 0xc0a8 + 0x0102 + 0xe000 + 0x0012 +
        // 0x0070 + 0x000c = 0x1a238. Together 0x2f947, folded 0xf949, and
        // its complement 0x06b6.
        let bytes = [0x31, 1, 100, 1, 0, 100, 0x06, 0xb6, 192, 168, 1, 1];
        let ad = Advertisement::parse(&bytes, &v4_ends()).unwrap();
        let want = Advertisement::V3(AdvertisementV3 {
            vrid: 1,
            priority: 100,
            interval: 100,
            addresses: Addresses::V4(vec![ip4(192, 168, 1, 1)]),
        });
        assert_eq!(ad, want);
        assert_eq!(ad.to_bytes(&v4_ends()).unwrap(), bytes);
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
        assert_eq!(ad.to_bytes(&v4_ends()).unwrap(), b);
        // Version 2 has no pseudo-header: any IPv4 endpoints read it.
        let other = Endpoints::V4 { source: ip4(10, 0, 0, 9), destination: ip4(10, 0, 0, 255) };
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
            addresses: Addresses::V6(vec!["fe80::1".parse().unwrap(), "2001:db8::1".parse().unwrap()]),
        });
        let b = round_trip(&ad, &ends);
        assert_eq!(b.len(), 8 + 32);
        assert_eq!(&b[..6], &[0x31, 7, 100, 2, 0, 100]);
        assert_eq!(ad.destination(), IpAddr::V6(GROUP_V6));
        // The checksum covers the pseudo-header, worked out by hand here.
        let Endpoints::V6 { source, destination } = ends else { panic!() };
        let mut ph = Vec::new();
        ph.extend_from_slice(&source.octets());
        ph.extend_from_slice(&destination.octets());
        ph.extend_from_slice(&(b.len() as u32).to_be_bytes());
        ph.extend_from_slice(&[0, 0, 0, 112]);
        ph.extend_from_slice(&b);
        assert_eq!(fold(sum_words(0, &ph)), 0xffff);
        // Another source makes the checksum wrong.
        let moved = Endpoints::V6 { source: "fe80::3".parse().unwrap(), destination: GROUP_V6 };
        assert_eq!(Advertisement::parse(&b, &moved), Err(VrrpError::Checksum));
        // And the same bytes over IPv4 have the wrong length.
        assert_eq!(Advertisement::parse(&b, &v4_ends()), Err(VrrpError::Trailing));
    }

    #[test]
    fn v3_reserved_bits_ignored() {
        let b = vec![0x31, 1, 100, 1, 0xf0, 100, 0, 0, 192, 168, 1, 1];
        let b = fix(b, &v4_ends());
        let ad = Advertisement::parse(&b, &v4_ends()).unwrap();
        let Advertisement::V3(a) = &ad else { panic!() };
        assert_eq!(a.interval, 100);
        // Written back with the bits clear.
        assert_eq!(ad.to_bytes(&v4_ends()).unwrap()[4], 0);
    }

    #[test]
    fn errors() {
        let e = v4_ends();
        let good = fix(vec![0x31, 1, 100, 1, 0, 100, 0, 0, 192, 168, 1, 1], &e);
        assert_eq!(Advertisement::parse(&[], &e), Err(VrrpError::Truncated));
        let mut b = good.clone();
        b[0] = 0x11;
        assert_eq!(Advertisement::parse(&fix(b, &e), &e), Err(VrrpError::Version(1)));
        let mut b = good.clone();
        b[0] = 0x32;
        assert_eq!(Advertisement::parse(&fix(b, &e), &e), Err(VrrpError::Type(2)));
        let mut b = good.clone();
        b[1] = 0;
        assert_eq!(Advertisement::parse(&fix(b, &e), &e), Err(VrrpError::Vrid));
        let mut b = good.clone();
        b[3] = 0;
        b.truncate(8);
        assert_eq!(Advertisement::parse(&fix(b, &e), &e), Err(VrrpError::NoAddresses));
        let mut b = good.clone();
        b.push(0);
        assert_eq!(Advertisement::parse(&b, &e), Err(VrrpError::Trailing));
        let mut b = good.clone();
        b[7] ^= 1;
        assert_eq!(Advertisement::parse(&b, &e), Err(VrrpError::Checksum));
        // Version 2 over IPv6.
        let mut v2 = vec![0x21, 1, 100, 0, 0, 1, 0, 0];
        v2.extend_from_slice(&[0; 8]);
        let v2 = fix(v2, &e);
        assert!(Advertisement::parse(&v2, &e).is_ok());
        assert_eq!(Advertisement::parse(&v2, &v6_ends()), Err(VrrpError::Family));

        // Writer errors.
        let v3 =
            |vrid, interval, addresses| Advertisement::V3(AdvertisementV3 { vrid, priority: 1, interval, addresses });
        let one = Addresses::V4(vec![ip4(1, 2, 3, 4)]);
        assert_eq!(v3(0, 1, one.clone()).to_bytes(&e), Err(VrrpError::Vrid));
        assert_eq!(v3(1, 0x1000, one.clone()).to_bytes(&e), Err(VrrpError::Interval(0x1000)));
        assert_eq!(v3(1, 1, Addresses::V4(vec![])).to_bytes(&e), Err(VrrpError::NoAddresses));
        assert_eq!(v3(1, 1, one.clone()).to_bytes(&v6_ends()), Err(VrrpError::Family));
        assert_eq!(
            v3(1, 1, Addresses::V4(vec![ip4(1, 1, 1, 1); 256])).to_bytes(&e),
            Err(VrrpError::TooManyAddresses(256))
        );
        assert!(v3(1, MAX_INTERVAL_V3, Addresses::V4(vec![ip4(1, 1, 1, 1); 255])).to_bytes(&e).is_ok());
        let max6 = v3(255, 1, Addresses::V6(vec![Ipv6Addr::LOCALHOST; MAX_ADDRESSES]));
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
        assert_eq!(v2(0, 1).to_bytes(&e), Err(VrrpError::Vrid));
        assert_eq!(v2(1, 256).to_bytes(&e), Err(VrrpError::TooManyAddresses(256)));
        assert_eq!(v2(1, 1).to_bytes(&v6_ends()), Err(VrrpError::Family));
        // A version 2 advertisement may carry no addresses.
        round_trip(&v2(1, 0), &e);
        // Every error has a message.
        for err in [VrrpError::Truncated, VrrpError::Family, VrrpError::Checksum, VrrpError::Version(9)] {
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
        assert_eq!(decode_chunked(&b, &e, 1), Ok(ad.clone()));
        // The writer always sends 0x0000.
        assert_eq!(&ad.to_bytes(&e).unwrap()[6..8], &[0, 0]);
        // 0xffff is not taken for any other checksum.
        let good = fix(vec![0x31, 1, 100, 1, 0, 100, 0, 0, 192, 168, 1, 1], &e);
        let mut bad = good.clone();
        bad[6] = 0xff;
        bad[7] = 0xff;
        assert_ne!(good[6..8], [0xff, 0xff]);
        assert_eq!(Advertisement::parse(&bad, &e), Err(VrrpError::Checksum));
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
            let b = a.to_bytes(&e).unwrap();
            for n in 0..b.len() {
                let p = &b[..n];
                assert_eq!(Advertisement::parse(p, &e), Err(VrrpError::Truncated), "{a:?} prefix {n}");
                assert_eq!(Advertisement::parse(&fix(p.to_vec(), &e), &e), Err(VrrpError::Truncated));
                assert_eq!(decode_chunked(p, &e, 1), Err(VrrpError::Truncated));
            }
        }
    }

    #[test]
    fn decoder_matches_parse() {
        for (a, e) in samples() {
            let b = a.to_bytes(&e).unwrap();
            assert_eq!(decode_whole(&b, &e), Ok(a.clone()));
            for size in 1..6 {
                assert_eq!(decode_chunked(&b, &e, size), Ok(a.clone()));
            }
            // Bytes past the end fail as soon as they come, and stay failed.
            let mut d = Decoder::new(e);
            d.feed(&b).unwrap();
            assert_eq!(d.buffered(), b.len());
            assert_eq!(d.feed(&[0]), Err(VrrpError::Trailing));
            assert_eq!(d.feed(&[0]), Err(VrrpError::Trailing));
            assert_eq!(d.buffered(), 0);
            assert_eq!(d.finish(), Err(VrrpError::Trailing));
        }
        // A bad first byte fails at once.
        let mut d = Decoder::new(v4_ends());
        assert_eq!(d.feed(&[0x41]), Err(VrrpError::Version(4)));
        // A flood never grows the buffer past the limit.
        let mut d = Decoder::new(v6_ends());
        let _ = d.feed(&[0x31, 1, 1, 255]);
        for _ in 0..100 {
            let _ = d.feed(&[0; 100]);
        }
        assert!(d.buffered() <= MAX_MESSAGE + 1);
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
        assert_eq!(Endpoints::new(IpAddr::V4(GROUP_V4), IpAddr::V6(GROUP_V6)), None);
        for (a, e) in samples() {
            assert_eq!(a.address_count(), a.addresses().len());
            let b = a.to_bytes(&e).unwrap();
            assert_eq!(usize::from(b[3]), a.address_count());
            let mut d = Decoder::new(e);
            assert_eq!(d.endpoints(), &e);
            for (i, x) in b.iter().enumerate() {
                assert!(!d.is_complete());
                d.feed(std::slice::from_ref(x)).unwrap();
                assert_eq!(d.is_complete(), i + 1 == b.len());
            }
            let _ = d.feed(&[0]);
            assert!(!d.is_complete());
        }
        let v3 =
            AdvertisementV3 { vrid: 1, priority: 1, interval: 1, addresses: Addresses::V6(vec![Ipv6Addr::LOCALHOST]) };
        assert_eq!(v3.addresses.to_ip_addrs(), vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]);
        let a: Advertisement = v3.clone().into();
        assert_eq!(a, Advertisement::V3(v3));
        assert_eq!(a.addresses(), vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]);
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
        assert_eq!(a.addresses(), vec![IpAddr::V4(ip4(1, 2, 3, 4))]);
        // Every error has a message.
        for err in [
            VrrpError::Truncated,
            VrrpError::Trailing,
            VrrpError::Version(9),
            VrrpError::Type(2),
            VrrpError::Vrid,
            VrrpError::NoAddresses,
            VrrpError::TooManyAddresses(256),
            VrrpError::Interval(5000),
            VrrpError::Family,
            VrrpError::Checksum,
        ] {
            assert!(!err.to_string().is_empty());
        }
    }

    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }
        fn below(&mut self, n: usize) -> usize {
            self.next() as usize % n.max(1)
        }
        fn v6(&mut self) -> Ipv6Addr {
            let hi = u64::from(self.next()) << 32 | u64::from(self.next());
            let lo = u64::from(self.next()) << 32 | u64::from(self.next());
            Ipv6Addr::from(u128::from(hi) << 64 | u128::from(lo))
        }
        fn endpoints(&mut self) -> Endpoints {
            if self.below(2) == 0 {
                Endpoints::V4 { source: Ipv4Addr::from(self.next()), destination: GROUP_V4 }
            } else {
                Endpoints::V6 { source: self.v6(), destination: GROUP_V6 }
            }
        }
    }

    /// A random advertisement the writer accepts for `e`.
    fn random_ad(rng: &mut Lcg, e: &Endpoints) -> Advertisement {
        let vrid = (rng.below(255) + 1) as u8;
        let priority = rng.next() as u8;
        if matches!(e, Endpoints::V4 { .. }) && rng.below(2) == 0 {
            let mut auth_data = [0u8; 8];
            auth_data.iter_mut().for_each(|x| *x = rng.next() as u8);
            return Advertisement::V2(AdvertisementV2 {
                vrid,
                priority,
                auth_type: rng.next() as u8,
                interval: rng.next() as u8,
                addresses: (0..rng.below(6)).map(|_| Ipv4Addr::from(rng.next())).collect(),
                auth_data,
            });
        }
        let n = rng.below(5) + 1;
        let addresses = match e {
            Endpoints::V4 { .. } => Addresses::V4((0..n).map(|_| Ipv4Addr::from(rng.next())).collect()),
            Endpoints::V6 { .. } => Addresses::V6((0..n).map(|_| rng.v6()).collect()),
        };
        let interval = rng.below(usize::from(MAX_INTERVAL_V3) + 1) as u16;
        Advertisement::V3(AdvertisementV3 { vrid, priority, interval, addresses })
    }

    fn check_bytes(data: &[u8], e: &Endpoints) {
        let parsed = Advertisement::parse(data, e);
        if let Ok(a) = &parsed {
            // An advertisement read can be written, and reads back the same.
            let out = a.to_bytes(e).unwrap();
            assert_eq!(out.len(), data.len());
            assert_eq!(Advertisement::parse(&out, e).as_ref(), Ok(a));
        }
        assert_eq!(decode_whole(data, e), parsed);
        assert_eq!(decode_chunked(data, e, 1), parsed);
        assert_eq!(decode_chunked(data, e, data.len() % 7 + 2), parsed);
    }

    #[test]
    fn fuzz_loop() {
        let mut rng = Lcg(0x5798_3768_0112);
        for _ in 0..4000 {
            let e = rng.endpoints();
            let a = random_ad(&mut rng, &e);
            let b = round_trip(&a, &e);
            check_bytes(&b, &e);
            // Flip some bytes, cut or extend, and fix the checksum most of
            // the time so the parser looks past it.
            let mut mutated = b.clone();
            for _ in 0..rng.below(4) {
                let i = rng.below(mutated.len());
                mutated[i] = rng.next() as u8;
            }
            match rng.below(4) {
                0 => mutated.truncate(rng.below(mutated.len() + 1)),
                1 => mutated.extend((0..rng.below(20)).map(|_| rng.next() as u8)),
                _ => {}
            }
            if rng.below(4) != 0 {
                mutated = fix(mutated, &e);
            }
            check_bytes(&mutated, &e);
            // The same bytes read with the other family.
            let other = rng.endpoints();
            check_bytes(&mutated, &other);
            // Plain random bytes, with a likely first byte and a right
            // checksum.
            let n = rng.below(60);
            let mut raw: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
            if let Some(t) = raw.first_mut() {
                *t = [0x21, 0x31, rng.next() as u8][rng.below(3)];
            }
            if let Some(c) = raw.get_mut(3) {
                *c %= 8;
            }
            check_bytes(&fix(raw, &e), &e);
        }
    }
}
