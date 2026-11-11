//! Reading the client's Version Information from its first flight
//!
//! A server choosing a compatible version must know the client's Available
//! Versions before its TLS session answers the ClientHello, since the
//! server's own Version Information goes in that answer and names the
//! negotiated version. This reads the client's Initial crypto stream as it
//! has arrived so far, across however many packets and CRYPTO frames carry
//! it: the ClientHello, the QUIC transport parameters extension and the
//! Version Information parameter. Nothing is copied or allocated.
//!
//! Clients may split the ClientHello over several packets, and some leave
//! part of it for a later packet on purpose. So the reader distinguishes an
//! offer still arriving from a ClientHello that has fully arrived without
//! one. A ClientHello without a readable offer, or anything unexpected
//! about it, makes the server keep the client's version, which RFC 9368
//! permits. The TLS session and the transport parameter decoder still check
//! the whole ClientHello afterwards.

use super::{VersionInformation, VersionList};

/// TLS HandshakeType client_hello (RFC 8446 section 4)
const CLIENT_HELLO: u8 = 1;

/// TLS ExtensionType quic_transport_parameters (RFC 9001 section 8.2)
const QUIC_TRANSPORT_PARAMETERS: u16 = 0x39;

/// The Version Information transport parameter (RFC 9368 section 3)
const VERSION_INFORMATION: u64 = 0x11;

/// The client's Initial crypto stream as received so far
pub(crate) trait Received {
    /// The stream byte at `position`, if it has arrived
    fn byte(&self, position: u64) -> Option<u8>;
    /// How many bytes from the start of the stream have all arrived
    fn prefix(&self) -> u64;
}

/// What the received part of a first flight says about the client's offer
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Offer {
    /// The client's Version Information
    Found(VersionInformation),
    /// More of the ClientHello must arrive before the offer can be read
    Arriving,
    /// The stream does not start with a ClientHello, or the whole
    /// ClientHello arrived without a well-formed offer
    Absent,
}

/// The client's offer in the `received` part of its Initial crypto stream
pub(crate) fn client_offer<R: Received + ?Sized>(received: &R) -> Offer {
    if let Some(info) = client_version_information(received) {
        return Offer::Found(info);
    }
    let mut header = Cursor::new(received);
    match header.u8() {
        None => Offer::Arriving,
        Some(CLIENT_HELLO) => match header.u24() {
            Some(len) if received.prefix() >= 4 + len => Offer::Absent,
            _ => Offer::Arriving,
        },
        Some(_) => Offer::Absent,
    }
}

/// The client's Version Information, when the received bytes it depends on
/// have arrived and the ClientHello carries one
fn client_version_information<R: Received + ?Sized>(received: &R) -> Option<VersionInformation> {
    let mut hello = Cursor::new(received);
    if hello.u8()? != CLIENT_HELLO {
        return None;
    }
    let len = hello.u24()?;
    let mut hello = hello.limit(len)?;
    hello.skip(2 + 32)?; // legacy_version, random
    let session_id = hello.u8()?;
    hello.skip(u64::from(session_id))?;
    let cipher_suites = hello.u16()?;
    hello.skip(u64::from(cipher_suites))?;
    let compression = hello.u8()?;
    hello.skip(u64::from(compression))?;
    let extensions = hello.u16()?;
    let mut extensions = hello.limit(u64::from(extensions))?;
    while !extensions.is_empty() {
        let kind = extensions.u16()?;
        let len = u64::from(extensions.u16()?);
        if kind == QUIC_TRANSPORT_PARAMETERS {
            return transport_parameter(extensions.limit(len)?);
        }
        extensions.skip(len)?;
    }
    None
}

/// Find and read Version Information among transport parameters
fn transport_parameter<R: Received + ?Sized>(
    mut params: Cursor<'_, R>,
) -> Option<VersionInformation> {
    while !params.is_empty() {
        let id = params.var()?;
        let len = params.var()?;
        if id == VERSION_INFORMATION {
            return version_information(params.limit(len)?);
        }
        params.skip(len)?;
    }
    None
}

/// Version Information as a client sends it (RFC 9368 section 4): nonzero
/// entries in whole words, with the Chosen Version among the available ones
fn version_information<R: Received + ?Sized>(
    mut body: Cursor<'_, R>,
) -> Option<VersionInformation> {
    let chosen = body.u32()?;
    let mut available = VersionList::EMPTY;
    let mut unknown_available = false;
    let mut includes_chosen = false;
    while !body.is_empty() {
        let version = body.u32()?;
        if version == 0 {
            return None;
        }
        includes_chosen |= version == chosen;
        unknown_available |= !available.push(version);
    }
    (chosen != 0 && includes_chosen).then_some(VersionInformation {
        chosen,
        available,
        unknown_available,
    })
}

/// A contiguous stream that has wholly arrived
impl Received for [u8] {
    fn byte(&self, position: u64) -> Option<u8> {
        self.get(usize::try_from(position).ok()?).copied()
    }

    fn prefix(&self) -> u64 {
        self.len() as u64
    }
}

/// A bounded reader over received bytes, failing at the bound or a missing
/// byte
struct Cursor<'a, R: Received + ?Sized> {
    received: &'a R,
    position: u64,
    end: u64,
}

impl<R: Received + ?Sized> Clone for Cursor<'_, R> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<R: Received + ?Sized> Copy for Cursor<'_, R> {}

impl<'a, R: Received + ?Sized> Cursor<'a, R> {
    fn new(received: &'a R) -> Self {
        Self {
            received,
            position: 0,
            end: u64::MAX,
        }
    }

    fn is_empty(&self) -> bool {
        self.position >= self.end
    }

    /// A cursor over the next `len` bytes, advancing this one past them
    fn limit(&mut self, len: u64) -> Option<Self> {
        let end = self
            .position
            .checked_add(len)
            .filter(|&end| end <= self.end)?;
        let inner = Self { end, ..*self };
        self.position = end;
        Some(inner)
    }

    fn skip(&mut self, len: u64) -> Option<()> {
        self.limit(len).map(|_| ())
    }

    fn u8(&mut self) -> Option<u8> {
        if self.is_empty() {
            return None;
        }
        let byte = self.received.byte(self.position)?;
        self.position += 1;
        Some(byte)
    }

    fn uint(&mut self, bytes: usize) -> Option<u64> {
        let mut value = 0;
        for _ in 0..bytes {
            value = value << 8 | u64::from(self.u8()?);
        }
        Some(value)
    }

    fn u16(&mut self) -> Option<u16> {
        self.uint(2).map(|value| value as u16)
    }

    fn u24(&mut self) -> Option<u64> {
        self.uint(3)
    }

    fn u32(&mut self) -> Option<u32> {
        self.uint(4).map(|value| value as u32)
    }

    /// A QUIC variable-length integer (RFC 9000 section 16)
    fn var(&mut self) -> Option<u64> {
        let first = self.u8()?;
        let extra = (1usize << (first >> 6)) - 1;
        let mut value = u64::from(first & 0x3f);
        for _ in 0..extra {
            value = value << 8 | u64::from(self.u8()?);
        }
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        coding::BufMutExt,
        version::{QUIC_V1, QUIC_V2},
    };

    /// Pieces of a stream by offset, in the order they arrived
    struct Pieces<'a>(Vec<(u64, &'a [u8])>);

    impl Received for Pieces<'_> {
        fn byte(&self, position: u64) -> Option<u8> {
            self.0.iter().find_map(|&(offset, bytes)| {
                bytes
                    .get(usize::try_from(position.checked_sub(offset)?).ok()?)
                    .copied()
            })
        }

        fn prefix(&self) -> u64 {
            let mut end = 0;
            while let Some(next) = self
                .0
                .iter()
                .filter(|&&(offset, _)| offset <= end)
                .map(|&(offset, bytes)| offset + bytes.len() as u64)
                .find(|&next| next > end)
            {
                end = next;
            }
            end
        }
    }

    /// A ClientHello carrying `params` as its QUIC transport parameters,
    /// after another extension
    fn client_hello(params: &[u8]) -> Vec<u8> {
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
        extensions.extend_from_slice(&QUIC_TRANSPORT_PARAMETERS.to_be_bytes());
        extensions.extend_from_slice(&(params.len() as u16).to_be_bytes());
        extensions.extend_from_slice(params);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7; 32]);
        body.extend_from_slice(&[4, 1, 2, 3, 4]); // session id
        body.extend_from_slice(&[0, 2, 0x13, 0x01]); // one cipher suite
        body.extend_from_slice(&[1, 0]); // null compression
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut hello = vec![CLIENT_HELLO];
        hello.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hello.extend_from_slice(&body);
        hello
    }

    fn params(chosen: u32, available: &[u32]) -> Vec<u8> {
        let mut params = Vec::new();
        params.write_var(0x04);
        params.write_var(2);
        params.write_var(1000);
        params.write_var(VERSION_INFORMATION);
        params.write_var(4 * (1 + available.len() as u64));
        params.extend_from_slice(&chosen.to_be_bytes());
        for version in available {
            params.extend_from_slice(&version.to_be_bytes());
        }
        params
    }

    fn found(offer: Offer) -> VersionInformation {
        match offer {
            Offer::Found(info) => info,
            other => panic!("no offer: {other:?}"),
        }
    }

    #[test]
    fn reads_the_client_offer_from_a_whole_hello() {
        let hello = client_hello(&params(QUIC_V1, &[QUIC_V2, 0x1a2a_3a4a, QUIC_V1]));
        let info = found(client_offer(hello.as_slice()));
        assert_eq!(info.chosen, QUIC_V1);
        assert_eq!(info.available.as_slice(), &[QUIC_V2, QUIC_V1]);
        assert!(info.unknown_available);
    }

    #[test]
    fn reads_an_offer_from_shuffled_pieces_across_packets() {
        let hello = client_hello(&params(QUIC_V1, &[QUIC_V1, QUIC_V2]));
        let (a, rest) = hello.split_at(40);
        let (b, c) = rest.split_at(17);
        let pieces = Pieces(vec![(57, c), (0, a), (40, b)]);
        assert_eq!(pieces.prefix(), hello.len() as u64);
        let info = found(client_offer(&pieces));
        assert_eq!(info.available.as_slice(), &[QUIC_V1, QUIC_V2]);
    }

    #[test]
    fn an_offer_is_read_while_another_part_of_the_hello_is_missing() {
        // As ngtcp2 does, the first packet leaves out some bytes of the
        // ClientHello before the transport parameters.
        let hello = client_hello(&params(QUIC_V1, &[QUIC_V2, QUIC_V1]));
        let pieces = Pieces(vec![(0, &hello[..8]), (16, &hello[16..])]);
        assert_eq!(pieces.prefix(), 8);
        assert_eq!(found(client_offer(&pieces)).chosen, QUIC_V1);
    }

    #[test]
    fn an_incomplete_hello_without_its_offer_is_still_arriving() {
        let hello = client_hello(&params(QUIC_V1, &[QUIC_V2, QUIC_V1]));
        assert_eq!(client_offer(&hello[..hello.len() - 1]), Offer::Arriving);
        assert_eq!(client_offer(&hello[..2]), Offer::Arriving);
        assert_eq!(client_offer(&[] as &[u8]), Offer::Arriving);
        // The offer's bytes arrive after the rest.
        let split = hello.len() - 3;
        let pieces = Pieces(vec![(0, &hello[..split])]);
        assert_eq!(client_offer(&pieces), Offer::Arriving);
        let pieces = Pieces(vec![(0, &hello[..split]), (split as u64, &hello[split..])]);
        assert_eq!(found(client_offer(&pieces)).chosen, QUIC_V1);
    }

    #[test]
    fn a_whole_hello_without_a_valid_offer_has_none() {
        // The client's Chosen Version must be among its available versions.
        let missing = client_hello(&params(QUIC_V1, &[QUIC_V2]));
        assert_eq!(client_offer(missing.as_slice()), Offer::Absent);
        let zero = client_hello(&params(QUIC_V1, &[QUIC_V1, 0]));
        assert_eq!(client_offer(zero.as_slice()), Offer::Absent);
        let none = client_hello(&[0x04, 0x02, 0x43, 0xe8]);
        assert_eq!(client_offer(none.as_slice()), Offer::Absent);
        // A transport parameter extension longer than its ClientHello.
        let hello = client_hello(&params(QUIC_V1, &[QUIC_V2, QUIC_V1]));
        let mut long = hello.clone();
        let at = long.len() - params(QUIC_V1, &[QUIC_V2, QUIC_V1]).len() - 2;
        long[at..at + 2].copy_from_slice(&0xffffu16.to_be_bytes());
        assert_eq!(client_offer(long.as_slice()), Offer::Absent);
        // Not a ClientHello at all.
        assert_eq!(client_offer(&[2u8, 0, 0, 0] as &[u8]), Offer::Absent);
    }

    #[cfg(feature = "rustls-ring")]
    #[test]
    fn the_rfc9369_sample_client_hello_has_parameters_but_no_offer() {
        // RFC 9369 Appendix A.2: its transport parameters lack Version
        // Information, so the server keeps the client's version. The sample
        // is one CRYPTO frame at offset 0 with a two-byte length.
        let frame = &crate::packet::rfc9369_vectors::CLIENT_CRYPTO;
        assert_eq!(frame[..2], [0x06, 0x00]);
        let len = usize::from(u16::from_be_bytes([frame[2], frame[3]]) & 0x3fff);
        let hello = &frame[4..4 + len];
        assert_eq!(hello[0], CLIENT_HELLO);
        assert_eq!(client_offer(hello), Offer::Absent);
    }

    /// The reader allocates nothing on any first flight: a whole offer,
    /// shuffled pieces, pieces with a gap before the offer, every
    /// truncation of it and every byte of it flipped, each read as a step
    /// with nothing allowed
    #[test]
    fn the_reader_allocates_nothing_on_any_first_flight() {
        use crate::cost::{Charged, Costs, Linear};
        let hello = client_hello(&params(QUIC_V1, &[QUIC_V2, QUIC_V1]));
        let (a, rest) = hello.split_at(40);
        let (b, c) = rest.split_at(17);
        let mut streams = vec![
            Pieces(vec![(0, &hello[..])]),
            Pieces(vec![(57, c), (0, a), (40, b)]),
            Pieces(vec![(0, &hello[..8]), (16, &hello[16..])]),
        ];
        streams.extend((0..hello.len()).map(|len| Pieces(vec![(0, &hello[..len])])));
        let flipped = (0..hello.len())
            .map(|at| {
                let mut flipped = hello.clone();
                flipped[at] ^= 0xff;
                flipped
            })
            .collect::<Vec<_>>();
        streams.extend(flipped.iter().map(|bytes| Pieces(vec![(0, &bytes[..])])));
        let nothing = Linear {
            num: 0,
            den: 1,
            fixed: 0,
        };
        let mut costs = Costs::new("QUIC first flight");
        let mut offers = 0;
        for stream in &streams {
            let offer = costs.step(stream.prefix() as usize, 0, nothing, || Charged {
                value: client_offer(stream),
                charged: 0,
                moved: 0,
            });
            offers += usize::from(matches!(offer, Offer::Found(_)));
        }
        // The whole offer, the shuffled one and the one with a gap are read.
        assert!(offers >= 3);
        eprintln!("cost: QUIC first flight: {}", costs.summary());
    }
}

#[cfg(kani)]
#[path = "../../../verification/quic/kani/first_flight_storage.rs"]
mod first_flight_storage_proofs;
