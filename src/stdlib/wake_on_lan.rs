//! Wake-on-LAN: finding and writing magic packets, with no I/O.
//!
//! A machine that is asleep or switched off can keep its network card
//! powered and listening. When the card sees a "magic packet" for its own
//! address, it wakes the machine. The magic packet is a sync stream of six
//! 0xFF bytes followed by the card's 6-byte MAC address repeated sixteen
//! times: 102 bytes in all. The card does not parse any header to find it.
//! It scans the frame, and the sync stream may start anywhere in it. This
//! module follows the AMD Magic Packet Technology white paper.
//!
//! Senders usually put the packet in a UDP datagram sent to a broadcast
//! address. The port is most often 9 ([`PORT`]), sometimes 7
//! ([`ALT_PORT`]) or 0. Some senders put the packet straight in an
//! Ethernet frame with EtherType 0x0842 ([`ETHERTYPE`]). Some cards also
//! take a SecureOn password: 4 or 6 bytes placed right after the sixteenth
//! repeat of the address. A card with a password set wakes only when the
//! bytes there match it.
//!
//! Nothing here reads a socket. A world that plays a sleeping host passes
//! each payload it receives to [`wakes`] with the host's MAC address and
//! password, and wakes the host when that returns true. A world that plays
//! a tool or a router reads payloads with [`MagicPacket::parse`] or
//! [`MagicPacket::find`], or feeds them in pieces to a [`Scanner`], and
//! writes packets with [`MagicPacket::to_bytes`].
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. A payload longer than [`MAX_PAYLOAD`] is refused. What the
//! writer produces, the reader reads back the same.
//!
//! New stacks use [`Packets`] with [`codec::Stream`] for one datagram
//! ending at EOF. [`Wire`] for [`MagicPacket`] reads exactly one packet
//! at offset zero. The inherent parsers still search the payload.
//!
//! ```
//! use fictionet::stdlib::wake_on_lan::{wakes, MagicPacket, Password, PACKET_LEN, PORT};
//!
//! let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
//! let packet = MagicPacket::new(mac);
//! let bytes = packet.to_bytes();
//! assert_eq!(bytes.len(), PACKET_LEN);
//! assert_eq!(&bytes[..6], &[0xff; 6]);
//! assert_eq!(&bytes[6..12], &mac);
//! assert_eq!(MagicPacket::parse(&bytes), Ok(packet));
//!
//! // The packet may sit anywhere in a datagram sent to port 9.
//! assert_eq!(PORT, 9);
//! let mut datagram = b"hello".to_vec();
//! datagram.extend_from_slice(&bytes);
//! datagram.extend_from_slice(b"bye");
//! assert_eq!(MagicPacket::find(&datagram), Ok((5, packet)));
//!
//! // A host with a SecureOn password wakes only when the password follows.
//! let password = Password::Four([1, 2, 3, 4]);
//! assert!(!wakes(&bytes, mac, Some(&password)));
//! let locked = MagicPacket::with_password(mac, password).to_bytes();
//! assert!(wakes(&locked, mac, Some(&password)));
//! // A host with no password ignores the bytes that follow.
//! assert!(wakes(&locked, mac, None));
//! assert!(!wakes(&locked, [0x00, 0x11, 0x22, 0x33, 0x44, 0x56], None));
//! ```

extern crate alloc;

use super::codec::{self, Decode, Wire};
use alloc::vec::Vec;

/// The UDP port senders use most often, the discard port.
pub const PORT: u16 = 9;
/// The other UDP port senders use, the echo port.
pub const ALT_PORT: u16 = 7;
/// The EtherType of a magic packet sent straight in an Ethernet frame.
pub const ETHERTYPE: u16 = 0x0842;
/// The length of a MAC address.
pub const MAC_LEN: usize = 6;
/// The length of the sync stream of 0xFF bytes that starts a packet.
pub const SYNC_LEN: usize = 6;
/// How many times the MAC address follows the sync stream.
pub const REPEATS: usize = 16;
/// The length of a magic packet without a password: 102 bytes.
pub const PACKET_LEN: usize = SYNC_LEN + REPEATS * MAC_LEN;
/// The longest SecureOn password.
pub const MAX_PASSWORD: usize = 6;
/// The length of the longest magic packet, with a 6-byte password.
pub const MAX_PACKET_LEN: usize = PACKET_LEN + MAX_PASSWORD;
/// The longest payload the readers take: the largest value of the 16-bit
/// length fields in IP and UDP headers. No UDP datagram or Ethernet frame
/// carries more. Longer payloads are refused.
pub const MAX_PAYLOAD: usize = 65_535;

/// The byte the sync stream is made of.
const SYNC: u8 = 0xff;

/// A 6-byte MAC address, in the order it goes on the wire.
pub type Mac = [u8; MAC_LEN];

/// A SecureOn password: the 4 or 6 bytes that follow the sixteenth repeat
/// of the MAC address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Password {
    /// A 4-byte password, often written like an IPv4 address.
    Four([u8; 4]),
    /// A 6-byte password, often written like a MAC address.
    Six([u8; 6]),
}

impl Password {
    /// The password made of `bytes`, if there are 4 or 6 of them.
    pub fn from_bytes(bytes: &[u8]) -> Option<Password> {
        match bytes.len() {
            4 => Some(Password::Four(bytes.try_into().ok()?)),
            6 => Some(Password::Six(bytes.try_into().ok()?)),
            _ => None,
        }
    }

    /// The password's bytes, as they go on the wire.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Password::Four(b) => b,
            Password::Six(b) => b,
        }
    }
}

/// One magic packet: the MAC address of the card it wakes, and the
/// SecureOn password that follows it, if there is one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MagicPacket {
    /// The MAC address repeated sixteen times.
    pub mac: Mac,
    /// The password after the last repeat, if any.
    pub password: Option<Password>,
}

/// Why a payload holds no magic packet a reader could take.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParseError {
    /// The payload is longer than [`MAX_PAYLOAD`].
    TooLong,
    /// No sync stream followed by sixteen repeats of one address appears
    /// anywhere in the payload.
    NotFound,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ParseError::TooLong => write!(f, "payload longer than {MAX_PAYLOAD} bytes"),
            ParseError::NotFound => write!(f, "no magic packet in the payload"),
        }
    }
}

impl core::error::Error for ParseError {}

/// The address of the magic packet that starts at `bytes[0]`, if one does.
/// The packet must be whole: `bytes` holds at least [`PACKET_LEN`] bytes.
fn packet_at(bytes: &[u8]) -> Option<Mac> {
    let packet = bytes.get(..PACKET_LEN)?;
    let (sync, repeats) = packet.split_at(SYNC_LEN);
    if sync.iter().any(|&b| b != SYNC) {
        return None;
    }
    let mac: Mac = repeats.get(..MAC_LEN)?.try_into().ok()?;
    if repeats.chunks_exact(MAC_LEN).all(|c| c == mac) {
        Some(mac)
    } else {
        None
    }
}

/// The offset and address of each magic packet in `payload`, first to
/// last. Packets may overlap, as in a run of 0xFF bytes.
fn packets(payload: &[u8]) -> impl Iterator<Item = (usize, Mac)> + '_ {
    let last = payload.len().checked_sub(PACKET_LEN);
    (0..last.map_or(0, |l| l.saturating_add(1)))
        .filter_map(move |i| payload.get(i..).and_then(packet_at).map(|mac| (i, mac)))
}

impl MagicPacket {
    /// A packet for `mac` with no password.
    pub fn new(mac: Mac) -> MagicPacket {
        MagicPacket {
            mac,
            password: None,
        }
    }

    /// A packet for `mac` followed by `password`.
    pub fn with_password(mac: Mac, password: Password) -> MagicPacket {
        MagicPacket {
            mac,
            password: Some(password),
        }
    }

    /// The length of the packet's bytes: 102, 106 or 108.
    pub fn len(&self) -> usize {
        PACKET_LEN + self.password.map_or(0, |p| p.as_bytes().len())
    }

    /// Always false: a packet is never empty. Here because `len` is.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// The packet's bytes: the sync stream, sixteen repeats of the address,
    /// then the password, if there is one. A payload of exactly these bytes
    /// reads back as this packet.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.len());
        out.extend_from_slice(&[SYNC; SYNC_LEN]);
        for _ in 0..REPEATS {
            out.extend_from_slice(&self.mac);
        }
        if let Some(p) = &self.password {
            out.extend_from_slice(p.as_bytes());
        }
        out
    }

    /// The first magic packet in `payload`, and the offset its sync stream
    /// starts at.
    ///
    /// The packet may start anywhere. The bytes after its last repeat are
    /// read as a password only when exactly 4 or 6 of them end the payload.
    /// Otherwise the packet has no password, since a reader cannot tell a
    /// password from other data. So pass the payload alone: the UDP data,
    /// or the Ethernet data without the frame check sequence. A host that
    /// knows its own password should call [`wakes`] instead, which checks
    /// the bytes after the packet whatever follows them.
    pub fn find(payload: &[u8]) -> Result<(usize, MagicPacket), ParseError> {
        if payload.len() > MAX_PAYLOAD {
            return Err(ParseError::TooLong);
        }
        let (offset, mac) = packets(payload).next().ok_or(ParseError::NotFound)?;
        let rest = offset
            .checked_add(PACKET_LEN)
            .and_then(|end| payload.get(end..))
            .unwrap_or(&[]);
        Ok((
            offset,
            MagicPacket {
                mac,
                password: Password::from_bytes(rest),
            },
        ))
    }

    /// The first magic packet in `payload`, as [`MagicPacket::find`] reads
    /// it, without its offset.
    pub fn parse(payload: &[u8]) -> Result<MagicPacket, ParseError> {
        MagicPacket::find(payload).map(|(_, p)| p)
    }
}

/// Why bytes are not exactly one magic packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketError {
    /// The length is not 102, 106, or 108 bytes.
    Length,
    /// The sync bytes or repeated addresses do not match.
    Malformed,
}

impl core::fmt::Display for PacketError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Length => "magic packet length must be 102, 106, or 108 bytes",
            Self::Malformed => "invalid magic packet sync or address repeats",
        })
    }
}

impl core::error::Error for PacketError {}

impl Wire for MagicPacket {
    type ParseError = PacketError;
    type WriteError = core::convert::Infallible;

    /// Reads one packet at offset zero, with an optional 4 or 6 byte password.
    /// The inherent parser still searches an entire payload.
    fn parse(bytes: &[u8]) -> Result<Self, PacketError> {
        let tail = bytes.get(PACKET_LEN..).ok_or(PacketError::Length)?;
        let password = if tail.is_empty() {
            None
        } else {
            Some(Password::from_bytes(tail).ok_or(PacketError::Length)?)
        };
        let mac = packet_at(bytes).ok_or(PacketError::Malformed)?;
        Ok(Self { mac, password })
    }

    /// Appends at most [`MAX_PACKET_LEN`] bytes. Every packet is representable.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Self::WriteError> {
        out.extend_from_slice(&self.to_bytes());
        Ok(())
    }
}

/// Finds the first magic packet in one payload ending at EOF.
///
/// Use a fresh [`codec::Stream`] for each datagram. The item contains its
/// offset and packet, as [`MagicPacket::find`] returns them. Passwords are
/// determined at EOF. Missing packets and oversized payloads are terminal
/// [`ParseError`]s. No input is retained outside the stream's buffer.
/// Capacity is [`MAX_PAYLOAD`] plus one byte to detect an oversized payload.
#[derive(Clone, Copy, Debug, Default)]
pub struct Packets {
    done: bool,
}

impl Packets {
    /// Creates a decoder for one datagram payload.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Decode for Packets {
    type Item = (usize, MagicPacket);
    type Error = ParseError;
    const NAME: &'static str = "Wake-on-LAN";

    fn capacity(&self) -> usize {
        MAX_PAYLOAD + 1
    }

    fn decode(&mut self, input: &[u8], eof: bool) -> Result<codec::Step<Self::Item>, ParseError> {
        if self.done {
            return Ok(codec::Step::End);
        }
        if input.len() > MAX_PAYLOAD {
            return Err(ParseError::TooLong);
        }
        if !eof {
            return Ok(codec::Step::Need);
        }
        let packet = MagicPacket::find(input)?;
        self.done = true;
        Ok(codec::Step::Item(packet, input.len()))
    }
}

/// Whether `payload` wakes a card with address `mac` and, if it has one
/// set, SecureOn `password`, as the card itself decides.
///
/// It does if a magic packet for `mac` appears anywhere in the payload and,
/// when the card has a password, the password's bytes follow that packet
/// directly. Bytes after those do not matter. A payload longer than
/// [`MAX_PAYLOAD`] never wakes a card. A card also checks that the frame
/// is one it would receive: sent to its own address, to a broadcast
/// address or to a multicast address. That check is left to the world,
/// since only the payload is passed here.
pub fn wakes(payload: &[u8], mac: Mac, password: Option<&Password>) -> bool {
    if payload.len() > MAX_PAYLOAD {
        return false;
    }
    packets(payload).any(|(offset, found)| {
        if found != mac {
            return false;
        }
        let Some(p) = password else { return true };
        let pw = p.as_bytes();
        let start = offset.saturating_add(PACKET_LEN);
        start
            .checked_add(pw.len())
            .and_then(|end| payload.get(start..end))
            == Some(pw)
    })
}

/// Reads one payload handed over in pieces, as a card scans a frame while
/// it arrives. It holds at most [`PACKET_LEN`] bytes of the payload at a
/// time, and gives the same answer as [`MagicPacket::find`] would on the
/// whole payload.
/// This compatibility type retains its early [`Scanner::found`] result
/// and repeated [`Scanner::finish`] calls. Use [`Packets`] with
/// [`codec::Stream`] for the EOF-driven interface.
#[derive(Clone, Debug, PartialEq, Eq)]
#[deprecated(note = "use codec::Stream with wake_on_lan::Packets for one payload ending at EOF")]
pub struct Scanner {
    /// How many bytes of the payload have been fed, up to one past
    /// [`MAX_PAYLOAD`].
    seen: usize,
    /// The last bytes fed, until a packet is found.
    window: [u8; PACKET_LEN],
    /// How many bytes of `window` are filled.
    filled: usize,
    /// The offset and address of the first packet, once one is found.
    found: Option<(usize, Mac)>,
    /// The first bytes after the packet.
    tail: [u8; MAX_PASSWORD],
    /// How many bytes followed the packet, up to one past [`MAX_PASSWORD`].
    tail_len: usize,
}

#[allow(deprecated)]
impl Default for Scanner {
    fn default() -> Self {
        Scanner::new()
    }
}

#[allow(deprecated)]
impl Scanner {
    /// A scanner at the start of a payload.
    pub fn new() -> Scanner {
        Scanner {
            seen: 0,
            window: [0; PACKET_LEN],
            filled: 0,
            found: None,
            tail: [0; MAX_PASSWORD],
            tail_len: 0,
        }
    }

    /// Reads the next bytes of the payload. Bytes past [`MAX_PAYLOAD`] are
    /// counted but not read, and make [`Scanner::finish`] refuse the
    /// payload.
    pub fn feed(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if self.seen > MAX_PAYLOAD {
                return;
            }
            self.seen = self.seen.saturating_add(1);
            if self.seen > MAX_PAYLOAD {
                return;
            }
            if self.found.is_some() {
                if let Some(slot) = self.tail.get_mut(self.tail_len) {
                    *slot = b;
                }
                self.tail_len = self.tail_len.saturating_add(1).min(MAX_PASSWORD + 1);
                continue;
            }
            if self.filled == PACKET_LEN {
                self.window.copy_within(1.., 0);
                self.window[PACKET_LEN - 1] = b;
            } else {
                self.window[self.filled] = b;
                self.filled += 1;
            }
            if let Some(mac) = packet_at(&self.window[..self.filled]) {
                self.found = Some((self.seen.saturating_sub(PACKET_LEN), mac));
            }
        }
    }

    /// How many bytes have been fed, counting at most one past
    /// [`MAX_PAYLOAD`].
    pub fn seen(&self) -> usize {
        self.seen
    }

    /// The offset and address of the first packet, as soon as its last
    /// repeat has been fed. Its password, if any, is known only at the end.
    pub fn found(&self) -> Option<(usize, Mac)> {
        if self.seen > MAX_PAYLOAD {
            None
        } else {
            self.found
        }
    }

    /// The first packet in everything fed, and its offset, read as
    /// [`MagicPacket::find`] reads a whole payload.
    pub fn finish(&self) -> Result<(usize, MagicPacket), ParseError> {
        if self.seen > MAX_PAYLOAD {
            return Err(ParseError::TooLong);
        }
        let (offset, mac) = self.found.ok_or(ParseError::NotFound)?;
        let password = self
            .tail
            .get(..self.tail_len)
            .and_then(Password::from_bytes);
        Ok((offset, MagicPacket { mac, password }))
    }
}

#[cfg(test)]
#[allow(deprecated)] // These tests cover the compatibility API.
mod tests {
    use super::*;

    const MAC: Mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

    fn scan(payload: &[u8], piece: usize) -> Result<(usize, MagicPacket), ParseError> {
        let mut s = Scanner::new();
        for chunk in payload.chunks(piece.max(1)) {
            s.feed(chunk);
        }
        s.finish()
    }

    fn check_all_ways(payload: &[u8]) -> Result<(usize, MagicPacket), ParseError> {
        let whole = MagicPacket::find(payload);
        assert_eq!(scan(payload, payload.len()), whole);
        assert_eq!(scan(payload, 1), whole);
        assert_eq!(scan(payload, 7), whole);
        assert_eq!(MagicPacket::parse(payload), whole.map(|(_, p)| p));
        whole
    }

    /// The white paper's example: a frame of destination and source
    /// addresses and other data, then the sync stream and sixteen repeats
    /// of 11h 22h 33h 44h 55h 66h, then more data.
    #[test]
    fn white_paper_example() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // destination
        frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // source
        frame.extend_from_slice(&[0x08, 0x00, 0x45, 0x00, 0x00]); // other data
        frame.extend_from_slice(&[0xff; 6]);
        for _ in 0..16 {
            frame.extend_from_slice(&MAC);
        }
        frame.extend_from_slice(&[0xaa, 0xbb, 0xcc]); // more data
        assert_eq!(check_all_ways(&frame), Ok((17, MagicPacket::new(MAC))));
        assert!(wakes(&frame, MAC, None));
        assert!(!wakes(&frame, [0x11, 0x22, 0x33, 0x44, 0x55, 0x67], None));
    }

    #[test]
    fn constants() {
        assert_eq!(PACKET_LEN, 102);
        assert_eq!(MAX_PACKET_LEN, 108);
        assert_eq!((PORT, ALT_PORT, ETHERTYPE), (9, 7, 0x0842));
        // The 16-bit length field bounds every payload.
        assert_eq!(MAX_PAYLOAD, u16::MAX as usize);
    }

    #[test]
    fn round_trips() {
        let cases = [
            MagicPacket::new(MAC),
            MagicPacket::new([0; 6]),
            MagicPacket::new([0xff; 6]),
            MagicPacket::with_password(MAC, Password::Four([192, 168, 1, 1])),
            MagicPacket::with_password(MAC, Password::Six([1, 2, 3, 4, 5, 6])),
            MagicPacket::with_password([0xff; 6], Password::Four([0xff; 4])),
            MagicPacket::with_password([0xff; 6], Password::Six([0xff; 6])),
            MagicPacket::with_password([0; 6], Password::Six([0; 6])),
        ];
        for p in cases {
            let bytes = p.to_bytes();
            assert_eq!(bytes.len(), p.len());
            assert!(!p.is_empty());
            assert_eq!(check_all_ways(&bytes), Ok((0, p)));
            assert!(wakes(&bytes, p.mac, p.password.as_ref()));
            assert!(wakes(&bytes, p.mac, None));
        }
    }

    #[test]
    fn password_bytes() {
        assert_eq!(
            Password::from_bytes(&[1, 2, 3, 4]),
            Some(Password::Four([1, 2, 3, 4]))
        );
        assert_eq!(
            Password::from_bytes(&[1, 2, 3, 4, 5, 6]),
            Some(Password::Six([1, 2, 3, 4, 5, 6]))
        );
        for n in [0, 1, 2, 3, 5, 7, 8, 100] {
            assert_eq!(Password::from_bytes(&vec![9; n]), None);
        }
        assert_eq!(Password::Four([1, 2, 3, 4]).as_bytes(), &[1, 2, 3, 4]);
    }

    #[test]
    fn trailing_bytes_other_than_four_or_six_are_not_a_password() {
        let base = MagicPacket::new(MAC).to_bytes();
        for n in 0..20 {
            let mut p = base.clone();
            p.extend((0..n).map(|i| i as u8));
            let expect = match n {
                4 => Some(Password::Four([0, 1, 2, 3])),
                6 => Some(Password::Six([0, 1, 2, 3, 4, 5])),
                _ => None,
            };
            assert_eq!(
                check_all_ways(&p),
                Ok((
                    0,
                    MagicPacket {
                        mac: MAC,
                        password: expect
                    }
                ))
            );
        }
    }

    #[test]
    fn error_not_found() {
        assert_eq!(check_all_ways(&[]), Err(ParseError::NotFound));
        assert_eq!(check_all_ways(&[0xff; 6]), Err(ParseError::NotFound));
        // One repeat wrong.
        let mut p = MagicPacket::new(MAC).to_bytes();
        p[50] ^= 1;
        assert_eq!(check_all_ways(&p), Err(ParseError::NotFound));
        // A sync byte wrong.
        let mut p = MagicPacket::new(MAC).to_bytes();
        p[3] = 0xfe;
        assert_eq!(check_all_ways(&p), Err(ParseError::NotFound));
        // Only fifteen repeats.
        let p = &MagicPacket::new(MAC).to_bytes()[..96];
        assert_eq!(check_all_ways(p), Err(ParseError::NotFound));
        assert!(!wakes(p, MAC, None));
        assert_eq!(
            ParseError::NotFound.to_string(),
            "no magic packet in the payload"
        );
    }

    #[test]
    fn error_too_long() {
        let mut p = vec![0u8; MAX_PAYLOAD - PACKET_LEN];
        p.extend_from_slice(&MagicPacket::new(MAC).to_bytes());
        assert_eq!(p.len(), MAX_PAYLOAD);
        assert_eq!(
            check_all_ways(&p),
            Ok((MAX_PAYLOAD - PACKET_LEN, MagicPacket::new(MAC)))
        );
        assert!(wakes(&p, MAC, None));
        p.push(0);
        assert_eq!(check_all_ways(&p), Err(ParseError::TooLong));
        assert!(!wakes(&p, MAC, None));
        let mut s = Scanner::new();
        s.feed(&p);
        assert_eq!(s.found(), None);
        assert_eq!(s.seen(), MAX_PAYLOAD + 1);
        s.feed(&p);
        assert_eq!(s.seen(), MAX_PAYLOAD + 1);
        assert_eq!(s.finish(), Err(ParseError::TooLong));
        assert!(ParseError::TooLong.to_string().contains("65535"));
    }

    #[test]
    fn every_truncated_prefix() {
        for p in [
            MagicPacket::new(MAC),
            MagicPacket::with_password(MAC, Password::Four([7, 8, 9, 10])),
            MagicPacket::with_password(MAC, Password::Six([7, 8, 9, 10, 11, 12])),
        ] {
            let bytes = p.to_bytes();
            for n in 0..bytes.len() {
                let prefix = &bytes[..n];
                let got = check_all_ways(prefix);
                if n < PACKET_LEN {
                    assert_eq!(got, Err(ParseError::NotFound), "prefix {n}");
                    assert!(!wakes(prefix, MAC, None));
                } else {
                    let password = Password::from_bytes(&bytes[PACKET_LEN..n]);
                    assert_eq!(
                        got,
                        Ok((0, MagicPacket { mac: MAC, password })),
                        "prefix {n}"
                    );
                    assert!(wakes(prefix, MAC, None));
                    // A password cut short does not wake a locked card.
                    if let Some(pw) = &p.password {
                        assert!(!wakes(prefix, MAC, Some(pw)));
                    }
                }
            }
        }
    }

    #[test]
    fn first_packet_wins_and_wakes_checks_every_one() {
        let other = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01];
        let mut p = MagicPacket::new(other).to_bytes();
        p.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7]);
        p.extend_from_slice(
            &MagicPacket::with_password(MAC, Password::Four([9, 9, 9, 9])).to_bytes(),
        );
        p.extend_from_slice(&[0, 0, 0]);
        assert_eq!(check_all_ways(&p), Ok((0, MagicPacket::new(other))));
        assert!(wakes(&p, other, None));
        assert!(wakes(&p, MAC, None));
        // The password after the second packet is checked though data
        // follows it.
        assert!(wakes(&p, MAC, Some(&Password::Four([9, 9, 9, 9]))));
        assert!(!wakes(&p, MAC, Some(&Password::Four([9, 9, 9, 8]))));
        assert!(!wakes(&p, MAC, Some(&Password::Six([9, 9, 9, 9, 0, 1]))));
        assert!(wakes(&p, other, Some(&Password::Six([1, 2, 3, 4, 5, 6]))));
    }

    #[test]
    fn every_password_byte_is_checked() {
        for sent in [
            Password::Four([1, 2, 3, 4]),
            Password::Six([1, 2, 3, 4, 5, 6]),
        ] {
            let bytes = MagicPacket::with_password(MAC, sent).to_bytes();
            assert!(wakes(&bytes, MAC, Some(&sent)));
            for i in 0..sent.as_bytes().len() {
                let mut wrong = sent.as_bytes().to_vec();
                wrong[i] ^= 0x80;
                let wrong = Password::from_bytes(&wrong).unwrap();
                assert!(!wakes(&bytes, MAC, Some(&wrong)), "byte {i} of {sent:?}");
            }
        }
    }

    #[test]
    fn long_runs_of_ff() {
        // Extra 0xFF bytes before the sync stream move the packet on.
        let mut p = vec![0xff; 3];
        p.extend_from_slice(&MagicPacket::new(MAC).to_bytes());
        assert_eq!(check_all_ways(&p), Ok((3, MagicPacket::new(MAC))));
        // A run of 110 0xFF bytes is a packet for ff:ff:ff:ff:ff:ff at
        // offset 0, followed by 8 bytes: no password.
        let p = vec![0xff; 110];
        assert_eq!(check_all_ways(&p), Ok((0, MagicPacket::new([0xff; 6]))));
        assert!(wakes(&p, [0xff; 6], Some(&Password::Six([0xff; 6]))));
    }

    #[test]
    fn scanner_reports_found_early() {
        let bytes = MagicPacket::with_password(MAC, Password::Six([1; 6])).to_bytes();
        let mut s = Scanner::default();
        for (i, b) in bytes.iter().enumerate() {
            assert_eq!(s.found().is_some(), i >= PACKET_LEN);
            s.feed(&[*b]);
        }
        assert_eq!(s.found(), Some((0, MAC)));
        assert_eq!(s.seen(), MAX_PACKET_LEN);
        assert_eq!(
            s.finish(),
            Ok((0, MagicPacket::with_password(MAC, Password::Six([1; 6]))))
        );
    }

    /// The largest payload, all 0xFF bytes, holds a packet at every offset.
    /// Each reader still does a bounded amount of work per byte.
    #[test]
    fn largest_payload_of_ff() {
        let p = vec![0xff; MAX_PAYLOAD];
        let ff = MagicPacket::new([0xff; 6]);
        assert_eq!(check_all_ways(&p), Ok((0, ff)));
        assert!(wakes(&p, [0xff; 6], Some(&Password::Six([0xff; 6]))));
        assert!(!wakes(&p, MAC, None));
        // Pieces fed after the limit is passed change nothing.
        let mut s = Scanner::new();
        s.feed(&p);
        let before = s.clone();
        assert_eq!(s.finish(), Ok((0, ff)));
        s.feed(&[0xff]);
        assert_ne!(s, before);
        let after = s.clone();
        s.feed(&p);
        assert_eq!(s, after);
        assert_eq!(s.finish(), Err(ParseError::TooLong));
    }

    /// A small linear congruential generator, so the loop below is the
    /// same on every run.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() as usize) % n.max(1)
        }
    }

    #[test]
    fn lcg_fuzz() {
        let mut rng = Lcg(0x5eed);
        let mut found = 0;
        for round in 0..4000 {
            let len = rng.below(400);
            // Bytes from a small alphabet, so sync streams and repeats turn
            // up often.
            let alphabet: [u8; 4] = [0xff, MAC[0], rng.next() as u8, 0];
            let mut buf: Vec<u8> = (0..len).map(|_| alphabet[rng.below(4)]).collect();
            if round % 3 == 0 {
                let mac: Mac = if rng.below(2) == 0 { MAC } else { [0xff; 6] };
                let pw = match rng.below(3) {
                    0 => None,
                    1 => Some(Password::Four([rng.next() as u8; 4])),
                    _ => Some(Password::Six([rng.next() as u8; 6])),
                };
                let at = rng.below(buf.len() + 1);
                let packet = MagicPacket { mac, password: pw }.to_bytes();
                buf.splice(at..at, packet);
                if rng.below(4) == 0 {
                    let i = rng.below(buf.len());
                    buf[i] ^= 1 << rng.below(8);
                }
            }
            let got = check_all_ways(&buf);
            if let Ok((offset, p)) = got {
                found += 1;
                assert!(offset + PACKET_LEN <= buf.len());
                assert_eq!(packet_at(&buf[offset..]), Some(p.mac));
                assert!(wakes(&buf, p.mac, None));
                assert!(wakes(&buf, p.mac, p.password.as_ref()));
                // Written alone, it reads back the same.
                assert_eq!(MagicPacket::find(&p.to_bytes()), Ok((0, p)));
                // No packet starts before it.
                assert!((0..offset).all(|i| packet_at(&buf[i..]).is_none()));
            } else {
                assert_eq!(got, Err(ParseError::NotFound));
                assert!(!wakes(&buf, MAC, None));
                assert!(!wakes(&buf, [0xff; 6], None));
            }
            // Every prefix gives the same answer all ways too.
            if round % 50 == 0 {
                for n in 0..buf.len() {
                    let _ = check_all_ways(&buf[..n]);
                }
            }
        }
        assert!(found > 1000, "found {found}");
    }
}
