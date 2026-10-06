//! VXLAN and VXLAN-GPE: reading and writing the headers that carry one
//! network's frames inside UDP datagrams, with no I/O.
//!
//! VXLAN stretches a layer 2 network across a layer 3 one. A tunnel
//! endpoint (a VTEP: a hypervisor, a switch, a container host) takes an
//! Ethernet frame, puts an 8-byte VXLAN header in front of it, and sends
//! the result to another endpoint in a UDP datagram, usually to port 4789.
//! The header's main field is the VNI, a 24-bit number that says which
//! virtual network the frame belongs to, much as a VLAN tag does. Its I
//! flag says the VNI is valid. VXLAN-GPE (Generic Protocol Extension) uses
//! the same 8 bytes on port 4790, and adds a version, a next-protocol
//! field that says what the inner packet is (Ethernet, IPv4, IPv6 or NSH),
//! and flags for broadcast and multicast traffic (B) and OAM packets (O).
//! This module follows RFC 7348 (VXLAN) and draft-ietf-nvo3-vxlan-gpe-12.
//!
//! A VXLAN datagram is a [`Packet`], and a VXLAN-GPE datagram is a
//! [`GpePacket`]. Each keeps the header's fields and hands back the inner
//! frame or packet as bytes, for the world to read with another module or
//! by hand. The two headers look alike, so which one a datagram carries
//! is known from the UDP port it came to ([`PORT`] or [`GPE_PORT`]).
//! VXLAN-GPE shim headers (next-protocol values 0x80 to 0xFF) are not
//! read here. They stay at the front of the payload.
//!
//! Nothing here reads a socket. A world that plays a tunnel endpoint takes
//! each UDP datagram it receives, reads it with [`Packet::parse`] or
//! [`GpePacket::parse`], and sends the bytes of what it answers. Which
//! networks exist, and what is on them, is up to world code.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. Reserved bits are ignored on receipt and written as zero, as both
//! specifications say, so a packet read and written again may differ from
//! the bytes it came from only in those bits. Writers return an error,
//! rather than change the packet, when a field does not fit: a VNI wider
//! than 24 bits, a payload longer than [`MAX_PAYLOAD`], or the reserved
//! next-protocol value 0.
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::vxlan::{GpePacket, Packet, next_protocol};
//!
//! // A datagram to port 4789: VNI 5001, then a 14-byte Ethernet header
//! // (broadcast destination, a source, EtherType ARP) and no body.
//! let mut datagram = vec![0x08, 0, 0, 0, 0x00, 0x13, 0x89, 0];
//! datagram.extend_from_slice(&[0xff; 6]);
//! datagram.extend_from_slice(&[0x02, 0, 0, 0, 0, 1, 0x08, 0x06]);
//! let packet = Packet::parse(&datagram).unwrap();
//! assert_eq!(packet.vni, 5001);
//! assert_eq!(packet.frame.len(), 14);
//! assert_eq!(packet.frame[12..], [0x08, 0x06]);
//! assert_eq!(packet.to_bytes().unwrap(), datagram);
//!
//! // The same network over VXLAN-GPE, carrying an IPv4 packet instead.
//! let gpe = GpePacket {
//!     vni: 5001,
//!     next_protocol: Some(next_protocol::IPV4),
//!     bum: false,
//!     oam: false,
//!     payload: vec![0x45, 0, 0, 20],
//! };
//! let bytes = gpe.to_bytes().unwrap();
//! assert_eq!(bytes[..8], [0x0c, 0, 0, 0x01, 0x00, 0x13, 0x89, 0]);
//! assert_eq!(GpePacket::parse(&bytes), Ok(gpe));
//! ```

use fictionet::stdlib::codec::Wire;

/// The UDP port VXLAN endpoints listen on (RFC 7348).
pub const PORT: u16 = 4789;
/// The UDP port VXLAN-GPE endpoints listen on.
pub const GPE_PORT: u16 = 4790;
/// The length of a VXLAN or VXLAN-GPE header, before the inner frame.
pub const HEADER_LEN: usize = 8;
/// The longest datagram a reader takes: the most a UDP datagram can
/// carry, 65535 bytes less its 8-byte header.
pub const MAX_DATAGRAM: usize = 65_527;
/// The longest inner frame or packet: the longest datagram less the
/// VXLAN header.
pub const MAX_PAYLOAD: usize = MAX_DATAGRAM - HEADER_LEN;
/// The largest VNI: the field is 24 bits wide.
pub const MAX_VNI: u32 = 0x00ff_ffff;
/// The only VXLAN-GPE version there is.
pub const GPE_VERSION: u8 = 0;

/// The flag bits in the header's first byte.
pub mod flags {
    /// The I flag: the VNI is valid. Both headers must have it.
    pub const I: u8 = 0x08;
    /// VXLAN-GPE only: the next-protocol field is there.
    pub const P: u8 = 0x04;
    /// VXLAN-GPE only: the packet is broadcast, unknown unicast or
    /// multicast traffic, copied to each endpoint by the sender.
    pub const B: u8 = 0x02;
    /// VXLAN-GPE only: the packet is an OAM (operations and
    /// maintenance) packet.
    pub const O: u8 = 0x01;
    /// VXLAN-GPE only: the two bits that hold the version.
    pub const VERSION: u8 = 0x30;
}

/// Values of the VXLAN-GPE next-protocol field. 0x00 is reserved, 0x7E
/// and 0x7F are for experiments, and 0x80 to 0xFF name shim headers that
/// sit in front of the inner packet. Readers keep any value but 0 as
/// given. With the P flag set, 0 names no protocol, so readers reject it
/// and writers refuse to write it.
pub mod next_protocol {
    /// An IPv4 packet.
    pub const IPV4: u8 = 0x01;
    /// An IPv6 packet.
    pub const IPV6: u8 = 0x02;
    /// An Ethernet frame.
    pub const ETHERNET: u8 = 0x03;
    /// A Network Service Header (RFC 8300), then what it carries.
    pub const NSH: u8 = 0x04;
}

/// One VXLAN datagram (RFC 7348): the network it is for and the Ethernet
/// frame it carries. The default is VNI 0 with an empty frame.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Packet {
    /// The VXLAN Network Identifier: which virtual network the frame
    /// belongs to. At most [`MAX_VNI`]: writers reject a wider value.
    pub vni: u32,
    /// The inner Ethernet frame, from its destination address on, with no
    /// frame check sequence. Readers do not look inside it.
    pub frame: Vec<u8>,
}

/// One VXLAN-GPE datagram: the network it is for, what it carries, its
/// flags and the inner packet. The default is VNI 0, an Ethernet payload
/// named with the P flag (next protocol [`next_protocol::ETHERNET`]), the
/// B and O flags clear and an empty payload. The draft also allows
/// Ethernet with the P flag clear (`next_protocol: None`), but Linux GPE
/// endpoints drop such packets, so the default sets the flag.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GpePacket {
    /// The VXLAN Network Identifier, as in [`Packet::vni`]. At most
    /// [`MAX_VNI`]: writers reject a wider value.
    pub vni: u32,
    /// What the payload is, one of the [`next_protocol`] values or another
    /// byte but the reserved 0, when the P flag is set. `None` when the P
    /// flag is clear, which means the payload is an Ethernet frame.
    pub next_protocol: Option<u8>,
    /// The B flag: broadcast, unknown unicast or multicast traffic.
    pub bum: bool,
    /// The O flag: an OAM packet.
    pub oam: bool,
    /// The inner packet or frame. Readers do not look inside it.
    pub payload: Vec<u8>,
}

impl Default for GpePacket {
    fn default() -> GpePacket {
        GpePacket { vni: 0, next_protocol: Some(next_protocol::ETHERNET), bum: false, oam: false, payload: Vec::new() }
    }
}

/// Why a VXLAN or VXLAN-GPE packet cannot be read or written. A real
/// endpoint drops an unreadable datagram and sends nothing back.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// The value cannot be written without changing it.
    Unwritable,
    /// The datagram was shorter than the 8-byte header. It holds how long
    /// it was.
    Truncated(usize),
    /// The datagram was longer than [`MAX_DATAGRAM`], so no UDP datagram
    /// could have carried it. It holds how long it was.
    TooLong(usize),
    /// The I flag was clear, so the header names no valid network.
    NoVni,
    /// VXLAN-GPE only: a version other than 0. It holds the version.
    Version(u8),
    /// VXLAN-GPE only: the P flag was clear but the next-protocol field
    /// was not zero. It holds the field.
    NextProtocolWithoutP(u8),
    /// VXLAN-GPE only: the P flag was set with the next-protocol field 0,
    /// a value the draft reserves, so the header names no protocol. The
    /// writer reports [`Error::Unwritable`] for `next_protocol: Some(0)`.
    ReservedNextProtocol,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unwritable => f.write_str("value cannot be written without changing it"),
            Error::Truncated(n) => write!(f, "{n} bytes, shorter than the {HEADER_LEN}-byte VXLAN header"),
            Error::TooLong(n) => write!(f, "{n} bytes, longer than a UDP datagram can carry"),
            Error::NoVni => write!(f, "I flag clear, so no valid VNI"),
            Error::Version(v) => write!(f, "VXLAN-GPE version {v}, not 0"),
            Error::NextProtocolWithoutP(p) => write!(f, "next protocol {p} with the P flag clear"),
            Error::ReservedNextProtocol => write!(f, "next protocol 0, which is reserved, with the P flag set"),
        }
    }
}

impl GpePacket {
    /// What the payload is, with the P flag's absence read as Ethernet.
    pub fn protocol(&self) -> u8 {
        self.next_protocol.unwrap_or(next_protocol::ETHERNET)
    }
}

/// Checks a datagram's length and splits it into the flags byte, the VNI
/// and what follows the header.
fn split(b: &[u8]) -> Result<(u8, u32, &[u8]), Error> {
    if b.len() > MAX_DATAGRAM {
        return Err(Error::TooLong(b.len()));
    }
    let Some((header, rest)) = b.split_first_chunk::<HEADER_LEN>() else {
        return Err(Error::Truncated(b.len()));
    };
    let vni = u32::from_be_bytes([0, header[4], header[5], header[6]]);
    Ok((header[0], vni, rest))
}

/// Writes a header with the given flags byte, next-protocol field and
/// VNI, then the payload. Checks the VNI and the payload's length before
/// it allocates.
fn write(first: u8, next: u8, vni: u32, payload: &[u8]) -> Result<Vec<u8>, Error> {
    if vni > MAX_VNI {
        return Err(Error::Unwritable);
    }
    if payload.len() > MAX_PAYLOAD {
        return Err(Error::Unwritable);
    }
    let v = vni.to_be_bytes();
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&[first, 0, 0, next, v[1], v[2], v[3], 0]);
    out.extend_from_slice(payload);
    Ok(out)
}

impl Wire for Packet {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a whole VXLAN datagram, the UDP payload. Reserved bits are
    /// ignored, as RFC 7348 says.
    /// Refuses invalid headers and lengths. Reads the whole input.
    fn parse(b: &[u8]) -> Result<Packet, Error> {
        let (first, vni, frame) = split(b)?;
        if first & flags::I == 0 {
            return Err(Error::NoVni);
        }
        Ok(Packet { vni, frame: frame.to_vec() })
    }

    /// Appends the VXLAN header and Ethernet frame. Refuses VNIs wider than 24 bits
    /// and frames above [`MAX_PAYLOAD`]. Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let out = write(flags::I, 0, self.vni, &self.frame)?;

        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for GpePacket {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a whole VXLAN-GPE datagram, the UDP payload. Reserved bits
    /// are ignored, as the draft says.
    /// Refuses invalid headers and lengths. Reads the whole input.
    fn parse(b: &[u8]) -> Result<GpePacket, Error> {
        let (first, vni, payload) = split(b)?;
        let version = (first & flags::VERSION) >> 4;
        if version != GPE_VERSION {
            return Err(Error::Version(version));
        }
        if first & flags::I == 0 {
            return Err(Error::NoVni);
        }
        // split checked that b holds at least the header.
        let field = b[3];
        let next_protocol = if first & flags::P != 0 {
            if field == 0 {
                return Err(Error::ReservedNextProtocol);
            }
            Some(field)
        } else if field != 0 {
            return Err(Error::NextProtocolWithoutP(field));
        } else {
            None
        };
        Ok(GpePacket {
            vni,
            next_protocol,
            bum: first & flags::B != 0,
            oam: first & flags::O != 0,
            payload: payload.to_vec(),
        })
    }

    /// Appends the GPE header and payload. Refuses VNIs wider than 24 bits,
    /// payloads above [`MAX_PAYLOAD`] and next protocol Some(0).
    /// Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        if self.next_protocol == Some(0) {
            return Err(Error::Unwritable);
        }
        let mut first = flags::I;
        if self.next_protocol.is_some() {
            first |= flags::P;
        }
        if self.bum {
            first |= flags::B;
        }
        if self.oam {
            first |= flags::O;
        }
        let out = write(first, self.next_protocol.unwrap_or(0), self.vni, &self.payload)?;

        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{contract, test_support::Lcg};

    /// The ARP request from the module doc: VNI 5001 and a 14-byte frame.
    fn example() -> Vec<u8> {
        let mut d = vec![0x08, 0, 0, 0, 0x00, 0x13, 0x89, 0];
        d.extend_from_slice(&[0xff; 6]);
        d.extend_from_slice(&[0x02, 0, 0, 0, 0, 1, 0x08, 0x06]);
        d
    }

    #[test]
    fn rfc7348_header() {
        // Section 5: flags 0x08 (I), 24 reserved bits, the VNI, 8 reserved bits.
        let d = example();
        let p = Packet::parse(&d).unwrap();
        assert_eq!(p.vni, 5001);
        assert_eq!(p.frame, d[8..]);
        assert_eq!(p.to_bytes(), Ok(d));
        // The largest VNI.
        let p = Packet::parse(&[0x08, 0, 0, 0, 0xff, 0xff, 0xff, 0]).unwrap();
        assert_eq!(p, Packet { vni: MAX_VNI, frame: vec![] });
    }

    #[test]
    fn reserved_bits_are_ignored_and_written_as_zero() {
        let d = [0xf7 | flags::I, 0xaa, 0xbb, 0xcc, 0, 0, 7, 0xdd, 1, 2];
        let p = Packet::parse(&d).unwrap();
        assert_eq!(p, Packet { vni: 7, frame: vec![1, 2] });
        assert_eq!(p.to_bytes().unwrap(), [0x08, 0, 0, 0, 0, 0, 7, 0, 1, 2]);
        // In VXLAN-GPE: the two high bits, the 16 reserved bits and the
        // last byte.
        let d = [0xc0 | flags::I | flags::P, 0xaa, 0xbb, 0x02, 0, 0, 9, 0xdd];
        let g = GpePacket::parse(&d).unwrap();
        assert_eq!(g.next_protocol, Some(next_protocol::IPV6));
        assert_eq!(g.to_bytes().unwrap(), [0x0c, 0, 0, 0x02, 0, 0, 9, 0]);
    }

    #[test]
    fn gpe_header() {
        // Every flag set, NSH next.
        let d = [0x0f, 0, 0, 0x04, 0x12, 0x34, 0x56, 0, 9, 9];
        let g = GpePacket::parse(&d).unwrap();
        assert_eq!(
            g,
            GpePacket {
                vni: 0x123456,
                next_protocol: Some(next_protocol::NSH),
                bum: true,
                oam: true,
                payload: vec![9, 9]
            }
        );
        assert_eq!(g.to_bytes().unwrap(), d);
        assert_eq!(g.protocol(), next_protocol::NSH);
        // P clear: the payload is Ethernet, and the field is zero.
        let d = [0x08, 0, 0, 0, 0, 0, 1, 0];
        let g = GpePacket::parse(&d).unwrap();
        assert_eq!(g.next_protocol, None);
        assert_eq!(g.protocol(), next_protocol::ETHERNET);
        assert!(!g.bum && !g.oam);
        assert_eq!(g.to_bytes().unwrap(), d);
        // A plain VXLAN header reads as VXLAN-GPE with P clear.
        let g = GpePacket::parse(&example()).unwrap();
        assert_eq!(g.to_bytes(), Ok(example()));
        // An unassigned next protocol is kept as it is.
        let d = [0x0c, 0, 0, 0x99, 0, 0, 1, 0];
        assert_eq!(GpePacket::parse(&d).unwrap().next_protocol, Some(0x99));
    }

    #[test]
    fn errors() {
        assert_eq!(Packet::parse(&[]), Err(Error::Truncated(0)));
        assert_eq!(GpePacket::parse(&[0x08; 7]), Err(Error::Truncated(7)));
        assert_eq!(Packet::parse(&[0, 0, 0, 0, 0, 0, 1, 0]), Err(Error::NoVni));
        assert_eq!(GpePacket::parse(&[0x04, 0, 0, 1, 0, 0, 1, 0]), Err(Error::NoVni));
        assert_eq!(GpePacket::parse(&[0x18, 0, 0, 0, 0, 0, 1, 0]), Err(Error::Version(1)));
        assert_eq!(GpePacket::parse(&[0x38, 0, 0, 0, 0, 0, 1, 0]), Err(Error::Version(3)));
        assert_eq!(GpePacket::parse(&[0x08, 0, 0, 3, 0, 0, 1, 0]), Err(Error::NextProtocolWithoutP(3)));
        let mut big = vec![0x08, 0, 0, 0, 0, 0, 1, 0];
        big.resize(MAX_DATAGRAM, 0);
        assert!(Packet::parse(&big).is_ok());
        assert!(GpePacket::parse(&big).is_ok());
        big.push(0);
        assert_eq!(Packet::parse(&big), Err(Error::TooLong(MAX_DATAGRAM + 1)));
        assert_eq!(GpePacket::parse(&big), Err(Error::TooLong(MAX_DATAGRAM + 1)));
        for e in [
            Error::Truncated(3),
            Error::TooLong(70_000),
            Error::NoVni,
            Error::Version(2),
            Error::NextProtocolWithoutP(1),
            Error::ReservedNextProtocol,
            Error::Unwritable,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn every_truncated_prefix() {
        let d = example();
        for n in 0..=d.len() {
            let prefix = &d[..n];
            match Packet::parse(prefix) {
                Err(Error::Truncated(m)) => assert!(n < HEADER_LEN && m == n),
                Ok(p) => {
                    assert!(n >= HEADER_LEN);
                    assert_eq!(p.frame, d[HEADER_LEN..n]);
                }
                Err(e) => panic!("{n} bytes: {e}"),
            }
            let g = GpePacket::parse(prefix);
            assert_eq!(g.is_ok(), n >= HEADER_LEN, "{n} bytes");
        }
    }

    #[test]
    fn writers_reject_a_vni_wider_than_24_bits() {
        // RFC 7348 section 5: the VNI is 24 bits. Masking would send the
        // frame to another network, so the writer refuses.
        let p = Packet { vni: 0x0100_0001, frame: vec![0; 60] };
        assert_eq!(p.to_bytes(), Err(Error::Unwritable));
        let g = GpePacket { vni: 0xab00_0001, ..GpePacket::default() };
        assert_eq!(g.to_bytes(), Err(Error::Unwritable));
        let p = Packet { vni: MAX_VNI, frame: vec![] };
        assert_eq!(p.to_bytes(), Ok(vec![0x08, 0, 0, 0, 0xff, 0xff, 0xff, 0]));
    }

    #[test]
    fn writers_reject_a_payload_too_long_for_a_datagram() {
        // The longest payload fits, at exactly the longest datagram.
        let p = Packet { vni: 1, frame: vec![1; MAX_PAYLOAD] };
        let bytes = p.to_bytes().unwrap();
        assert_eq!(bytes.len(), MAX_DATAGRAM);
        assert_eq!(Packet::parse(&bytes), Ok(p));
        let g = GpePacket { vni: 2, payload: vec![2; MAX_PAYLOAD], ..GpePacket::default() };
        let bytes = g.to_bytes().unwrap();
        assert_eq!(bytes.len(), MAX_DATAGRAM);
        assert_eq!(GpePacket::parse(&bytes), Ok(g));
        // One byte more is an error, not a cut frame.
        let p = Packet { vni: 1, frame: vec![1; MAX_PAYLOAD + 1] };
        assert_eq!(p.to_bytes(), Err(Error::Unwritable));
        let g = GpePacket { vni: 2, payload: vec![2; 70_000], ..GpePacket::default() };
        assert_eq!(g.to_bytes(), Err(Error::Unwritable));
    }

    #[test]
    fn reserved_next_protocol_zero_is_rejected() {
        // Draft-12 section 11.2 reserves 0x00. With P set it names no
        // protocol: the reader rejects it and the writer will not write it.
        assert_eq!(GpePacket::parse(&[0x0c, 0, 0, 0, 0, 0, 1, 0]), Err(Error::ReservedNextProtocol));
        assert_eq!(GpePacket::parse(&[0x0f, 0, 0, 0, 0, 0, 1, 0, 9]), Err(Error::ReservedNextProtocol));
        let g = GpePacket { vni: 1, next_protocol: Some(0), ..GpePacket::default() };
        assert_eq!(g.to_bytes(), Err(Error::Unwritable));
        // P clear with a zero field is still implicit Ethernet.
        let g = GpePacket { vni: 1, next_protocol: None, ..GpePacket::default() };
        assert_eq!(g.to_bytes(), Ok(vec![0x08, 0, 0, 0, 0, 0, 1, 0]));
        assert_eq!(g.protocol(), next_protocol::ETHERNET);
    }

    #[test]
    fn defaults_write_valid_headers() {
        let p = Packet::default();
        assert_eq!(p.to_bytes(), Ok(vec![0x08, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(Packet::parse(&p.to_bytes().unwrap()), Ok(p));
        // The GPE default names Ethernet with the P flag, as Linux GPE
        // endpoints require: P=1, next protocol 3.
        let g = GpePacket::default();
        assert_eq!(g.next_protocol, Some(next_protocol::ETHERNET));
        assert_eq!(g.protocol(), next_protocol::ETHERNET);
        assert_eq!(g.to_bytes(), Ok(vec![0x0c, 0, 0, 0x03, 0, 0, 0, 0]));
        assert_eq!(GpePacket::parse(&g.to_bytes().unwrap()), Ok(g));
        let g = GpePacket { vni: 1, payload: vec![0xff; 14], ..GpePacket::default() };
        assert_eq!(g.to_bytes().unwrap()[..8], [0x0c, 0, 0, 0x03, 0, 0, 1, 0]);
    }

    fn check(data: &[u8]) {
        contract::check_wire::<Packet>(data);
        contract::check_wire::<GpePacket>(data);

        if let Ok(p) = Packet::parse(data) {
            let bytes = p.to_bytes().unwrap();
            assert_eq!(bytes.len(), data.len());
            assert_eq!(Packet::parse(&bytes), Ok(p));
        }
        if let Ok(g) = GpePacket::parse(data) {
            let bytes = g.to_bytes().unwrap();
            assert_eq!(bytes.len(), data.len());
            assert_eq!(GpePacket::parse(&bytes), Ok(g));
        }
    }

    #[test]
    fn fuzz_loop() {
        let mut rng = Lcg::new(0x5eed_4789);
        let mut parsed = 0;
        for _ in 0..20_000 {
            let len = rng.index(40);
            let mut data = vec![0; len];
            rng.fill(&mut data);
            // Often set the I flag and clear the version, so many buffers
            // get past the header checks.
            if !data.is_empty() && rng.coin() {
                data[0] = (data[0] | flags::I) & !flags::VERSION;
            }
            check(&data);
            if Packet::parse(&data).is_ok() {
                parsed += 1;
            }
            // The datagram growing a byte at a time: every prefix. Below
            // the header length each one is Truncated. Once the header is
            // in, each one gets the same answer as the whole datagram.
            let whole = (Packet::parse(&data).map(|_| ()), GpePacket::parse(&data).map(|_| ()));
            for n in 0..data.len() {
                check(&data[..n]);
                let part = (Packet::parse(&data[..n]).map(|_| ()), GpePacket::parse(&data[..n]).map(|_| ()));
                if n < HEADER_LEN {
                    assert_eq!(part, (Err(Error::Truncated(n)), Err(Error::Truncated(n))));
                } else {
                    assert_eq!(part, whole);
                }
            }
        }
        assert!(parsed > 1000, "{parsed}");
        // Random packets, any VNI and any next protocol, written and
        // read back. A write either keeps the whole value or fails.
        for _ in 0..5_000 {
            let vni = u32::from_be_bytes([rng.index(4) as u8, (rng.next() as u8), (rng.next() as u8), (rng.next() as u8)]);
            let payload: Vec<u8> = rng.bytes(31);
            let p = Packet { vni, frame: payload.clone() };
            match p.to_bytes() {
                Ok(bytes) => assert_eq!(Packet::parse(&bytes), Ok(p)),
                Err(e) => assert!(vni > MAX_VNI && e == Error::Unwritable),
            }
            let flags = rng.next() as u8;
            let g = GpePacket {
                vni,
                next_protocol: if flags & 1 == 0 { None } else { Some(rng.index(8) as u8) },
                bum: flags & 2 != 0,
                oam: flags & 4 != 0,
                payload,
            };
            match g.to_bytes() {
                Ok(bytes) => assert_eq!(GpePacket::parse(&bytes), Ok(g)),
                Err(Error::Unwritable) => assert!(vni > MAX_VNI || g.next_protocol == Some(0)),
                Err(e) => panic!("{e}"),
            }
        }
    }
}
