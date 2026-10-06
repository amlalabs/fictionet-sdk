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
//! a tool or a router reads exact packets with [`MagicPacket::parse`],
//! searches payloads with [`MagicPacket::find`], or uses
//! [`Stream<Packets>`](fictionet::stdlib::codec::Stream) for a payload ending at EOF,
//! and writes packets with [`MagicPacket::write`].
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. A payload longer than [`MAX_PAYLOAD`] is refused. What the
//! writer produces, the reader reads back the same.
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::wake_on_lan::{wakes, MagicPacket, Password, PACKET_LEN, PORT};
//!
//! let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
//! let packet = MagicPacket::new(mac);
//! let bytes = packet.to_bytes().unwrap();
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
//! let locked = MagicPacket::with_password(mac, password).to_bytes().unwrap();
//! assert!(wakes(&locked, mac, Some(&password)));
//! // A host with no password ignores the bytes that follow.
//! assert!(wakes(&locked, mac, None));
//! assert!(!wakes(&locked, [0x00, 0x11, 0x22, 0x33, 0x44, 0x56], None));
//! ```

extern crate alloc;

use fictionet::stdlib::codec::{self, Decode, Wire};
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
    /// Refuses any other length, invalid sync bytes, or unequal address repeats.
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

    /// Appends the sync stream, sixteen address repeats, and any password.
    /// Produces at most [`MAX_PACKET_LEN`] bytes. No packet value is refused.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Self::WriteError> {
        out.extend_from_slice(&[SYNC; SYNC_LEN]);
        for _ in 0..REPEATS {
            out.extend_from_slice(&self.mac);
        }
        if let Some(password) = &self.password {
            out.extend_from_slice(password.as_bytes());
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use codec::{
        Stream, contract,
        test_support::{Lcg, decode_all, mutate},
    };

    const MAC: Mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

    fn check_payload(payload: &[u8]) -> Result<(usize, MagicPacket), ParseError> {
        // Adapter consistency only: Packets delegates to find at EOF.
        let whole = MagicPacket::find(payload);
        let expected = match whole {
            Ok(packet) => (vec![packet], None),
            Err(error) => (vec![], Some(codec::Fail::Protocol(error))),
        };
        assert_eq!(decode_all(Packets::new, payload), expected);
        contract::check_decode_with_alloc_limit(Packets::new, payload, 2 * (MAX_PAYLOAD + 1));
        contract::check_wire::<MagicPacket>(payload);
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
        assert_eq!(check_payload(&frame), Ok((17, MagicPacket::new(MAC))));
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
            let bytes = p.to_bytes().unwrap();
            assert_eq!(bytes.len(), p.len());
            assert!(!p.is_empty());
            assert_eq!(check_payload(&bytes), Ok((0, p)));
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
        let base = MagicPacket::new(MAC).to_bytes().unwrap();
        for n in 0..20 {
            let mut p = base.clone();
            p.extend((0..n).map(|i| i as u8));
            let expect = match n {
                4 => Some(Password::Four([0, 1, 2, 3])),
                6 => Some(Password::Six([0, 1, 2, 3, 4, 5])),
                _ => None,
            };
            assert_eq!(
                check_payload(&p),
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
        assert_eq!(check_payload(&[]), Err(ParseError::NotFound));
        assert_eq!(check_payload(&[0xff; 6]), Err(ParseError::NotFound));
        // One repeat wrong.
        let mut p = MagicPacket::new(MAC).to_bytes().unwrap();
        p[50] ^= 1;
        assert_eq!(check_payload(&p), Err(ParseError::NotFound));
        // A sync byte wrong.
        let mut p = MagicPacket::new(MAC).to_bytes().unwrap();
        p[3] = 0xfe;
        assert_eq!(check_payload(&p), Err(ParseError::NotFound));
        // Only fifteen repeats.
        let p = &MagicPacket::new(MAC).to_bytes().unwrap()[..96];
        assert_eq!(check_payload(p), Err(ParseError::NotFound));
        assert!(!wakes(p, MAC, None));
        assert_eq!(
            ParseError::NotFound.to_string(),
            "no magic packet in the payload"
        );
    }

    #[test]
    fn error_too_long() {
        let mut p = vec![0u8; MAX_PAYLOAD - PACKET_LEN];
        p.extend_from_slice(&MagicPacket::new(MAC).to_bytes().unwrap());
        assert_eq!(p.len(), MAX_PAYLOAD);
        assert_eq!(
            check_payload(&p),
            Ok((MAX_PAYLOAD - PACKET_LEN, MagicPacket::new(MAC)))
        );
        assert!(wakes(&p, MAC, None));
        p.push(0);
        assert_eq!(check_payload(&p), Err(ParseError::TooLong));
        assert!(!wakes(&p, MAC, None));
        let mut s = Stream::new(Packets::new());
        assert_eq!(s.push(&p), MAX_PAYLOAD + 1);
        assert_eq!(
            s.next(),
            Some(Err(codec::Fail::Protocol(ParseError::TooLong)))
        );
        assert_eq!(s.push(&p), p.len());
        assert_eq!(s.next(), None);
        assert_eq!(
            s.failed(),
            Some(&codec::Fail::Protocol(ParseError::TooLong))
        );
        assert!(ParseError::TooLong.to_string().contains("65535"));
    }

    #[test]
    fn every_truncated_prefix() {
        for p in [
            MagicPacket::new(MAC),
            MagicPacket::with_password(MAC, Password::Four([7, 8, 9, 10])),
            MagicPacket::with_password(MAC, Password::Six([7, 8, 9, 10, 11, 12])),
        ] {
            let bytes = p.to_bytes().unwrap();
            for n in 0..bytes.len() {
                let prefix = &bytes[..n];
                let got = check_payload(prefix);
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
        let mut p = MagicPacket::new(other).to_bytes().unwrap();
        p.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7]);
        p.extend_from_slice(
            &MagicPacket::with_password(MAC, Password::Four([9, 9, 9, 9]))
                .to_bytes()
                .unwrap(),
        );
        p.extend_from_slice(&[0, 0, 0]);
        assert_eq!(check_payload(&p), Ok((0, MagicPacket::new(other))));
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
            let bytes = MagicPacket::with_password(MAC, sent).to_bytes().unwrap();
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
        p.extend_from_slice(&MagicPacket::new(MAC).to_bytes().unwrap());
        assert_eq!(check_payload(&p), Ok((3, MagicPacket::new(MAC))));
        // A run of 110 0xFF bytes is a packet for ff:ff:ff:ff:ff:ff at
        // offset 0, followed by 8 bytes: no password.
        let p = vec![0xff; 110];
        assert_eq!(check_payload(&p), Ok((0, MagicPacket::new([0xff; 6]))));
        assert!(wakes(&p, [0xff; 6], Some(&Password::Six([0xff; 6]))));
    }

    #[test]
    fn packet_waits_for_password_at_eof() {
        let packet = MagicPacket::with_password(MAC, Password::Six([1; 6]));
        let bytes = packet.to_bytes().unwrap();
        let mut s = Stream::new(Packets::new());
        assert_eq!(s.push(&bytes[..PACKET_LEN]), PACKET_LEN);
        assert_eq!(s.next(), None);
        assert_eq!(s.push(&bytes[PACKET_LEN..]), MAX_PASSWORD);
        assert_eq!(s.next(), None);
        s.end();
        assert_eq!(s.next(), Some(Ok((0, packet))));
        assert_eq!(s.next(), None);
    }

    /// The largest payload, all 0xFF bytes, holds a packet at every offset.
    /// Each reader still does a bounded amount of work per byte.
    #[test]
    fn largest_payload_of_ff() {
        let p = vec![0xff; MAX_PAYLOAD];
        let ff = MagicPacket::new([0xff; 6]);
        assert_eq!(check_payload(&p), Ok((0, ff)));
        assert!(wakes(&p, [0xff; 6], Some(&Password::Six([0xff; 6]))));
        assert!(!wakes(&p, MAC, None));
        let mut over = p;
        over.push(0xff);
        assert_eq!(check_payload(&over), Err(ParseError::TooLong));
    }

    #[test]
    fn lcg_fuzz() {
        let mut rng = Lcg::new(0x5eed);
        let mut found = 0;
        for round in 0..4000 {
            let len = rng.index(400);
            // Bytes from a small alphabet, so sync streams and repeats turn
            // up often.
            let alphabet: [u8; 4] = [0xff, MAC[0], rng.next() as u8, 0];
            let mut buf: Vec<u8> = (0..len).map(|_| alphabet[rng.index(4)]).collect();
            if round % 3 == 0 {
                let mac: Mac = if rng.coin() { MAC } else { [0xff; 6] };
                let pw = match rng.index(3) {
                    0 => None,
                    1 => Some(Password::Four([rng.next() as u8; 4])),
                    _ => Some(Password::Six([rng.next() as u8; 6])),
                };
                let at = rng.index(buf.len() + 1);
                let packet = MagicPacket { mac, password: pw }.to_bytes().unwrap();
                buf.splice(at..at, packet);
                if rng.index(4) == 0 {
                    mutate(&mut rng, &mut buf);
                }
            }
            let got = check_payload(&buf);
            if let Ok((offset, p)) = got {
                found += 1;
                assert!(offset + PACKET_LEN <= buf.len());
                assert_eq!(packet_at(&buf[offset..]), Some(p.mac));
                assert!(wakes(&buf, p.mac, None));
                assert!(wakes(&buf, p.mac, p.password.as_ref()));
                // Written alone, it reads back the same.
                assert_eq!(MagicPacket::find(&p.to_bytes().unwrap()), Ok((0, p)));
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
                    let _ = check_payload(&buf[..n]);
                }
            }
        }
        assert!(found > 1000, "found {found}");
    }
}
