//! UDP datagram parsing and encoding, shared by sockets, Net and TAP.

use std::net::{IpAddr, SocketAddr};

use fictionet::stdlib::network::ip::{self, protocol};

/// A complete UDP datagram borrowed from an IP payload.
///
/// Parsing checks the UDP length, but leaves checksum and fragment policy
/// to the caller. Pass only a complete or reassembled IP payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Datagram<'a> {
    bytes: &'a [u8],
}

impl<'a> Datagram<'a> {
    /// Reads the UDP header and declared datagram boundary without allocating.
    ///
    /// Returns `None` if the header is short, the length is below eight, or
    /// the datagram extends beyond `bytes`. Bytes after the declared length
    /// are ignored. IPv6 jumbograms with a zero UDP length are not supported.
    /// This does not check the checksum; use [`Self::checksum_ok`] for that.
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }
        let len = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
        if len < 8 || len > bytes.len() {
            return None;
        }
        Some(Self {
            bytes: &bytes[..len],
        })
    }

    /// The header and payload, ending at the declared UDP length.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The sender's port.
    pub fn source_port(&self) -> u16 {
        u16::from_be_bytes([self.bytes[0], self.bytes[1]])
    }

    /// The recipient's port.
    pub fn destination_port(&self) -> u16 {
        u16::from_be_bytes([self.bytes[2], self.bytes[3]])
    }

    /// The payload, excluding the eight-byte UDP header.
    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[8..]
    }

    /// Checks the checksum over the declared datagram and the IP addresses.
    ///
    /// An IPv4 zero checksum means no checksum and is accepted. IPv6
    /// requires a nonzero checksum field. Mixed address families fail.
    pub fn checksum_ok(&self, src: IpAddr, dst: IpAddr) -> bool {
        src.is_ipv4() == dst.is_ipv4() && ip::udp_checksum_ok(src, dst, self.bytes)
    }
}

/// Why a UDP datagram cannot be encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The source and destination have different IP versions.
    AddressFamily,
    /// The payload cannot fit in one IP packet with a basic IP header.
    Length,
    /// The caller's output buffer cannot hold the datagram.
    BufferTooSmall,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AddressFamily => "UDP addresses have different IP versions",
            Self::Length => "UDP datagram exceeds one IP packet",
            Self::BufferTooSmall => "UDP output buffer is too small",
        })
    }
}

impl std::error::Error for Error {}

/// The bytes needed to encode `payload_len` bytes from `src` to `dst`.
///
/// Rejects mixed address families and payloads above 65,507 bytes for IPv4
/// or 65,527 for IPv6. These limits allow a basic IP header, with no IPv4
/// options or IPv6 extension headers. The caller chooses its allocation
/// and must apply any smaller MTU or header budget itself.
pub fn encoded_len(src: IpAddr, dst: IpAddr, payload_len: usize) -> Result<usize, Error> {
    if src.is_ipv4() != dst.is_ipv4() {
        return Err(Error::AddressFamily);
    }
    let max = if src.is_ipv4() { 65_507 } else { 65_527 };
    if payload_len > max {
        return Err(Error::Length);
    }
    Ok(8 + payload_len)
}

/// Writes one UDP datagram at the start of `out`, returning its length.
///
/// Checks [`encoded_len`] and the output capacity before writing anything.
/// On failure, `out` is unchanged. On success, bytes after the datagram are
/// unchanged. This does not allocate, build an IP header, or fragment.
/// The checksum includes the IP addresses. A computed zero is written as
/// `0xffff` for both IP versions, as RFC 768 requires.
pub fn encode(
    src: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let len = encoded_len(src.ip(), dst.ip(), payload.len())?;
    let bytes = out.get_mut(..len).ok_or(Error::BufferTooSmall)?;
    bytes[..2].copy_from_slice(&src.port().to_be_bytes());
    bytes[2..4].copy_from_slice(&dst.port().to_be_bytes());
    bytes[4..6].copy_from_slice(&(len as u16).to_be_bytes());
    bytes[6..8].fill(0);
    bytes[8..].copy_from_slice(payload);
    let sum = ip::transport_checksum(src.ip(), dst.ip(), protocol::UDP, bytes);
    bytes[6..8].copy_from_slice(&if sum == 0 { 0xffff } else { sum }.to_be_bytes());
    Ok(len)
}
