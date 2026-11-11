//! Reading the client's Version Information from its first Initial packet
//!
//! A server choosing a compatible version must know the client's Available
//! Versions before its TLS session answers the ClientHello, since the
//! server's own Version Information goes in that answer and names the
//! negotiated version. This reads the decrypted payload of the client's
//! first Initial packet in place: its CRYPTO frames, the ClientHello they
//! carry, the QUIC transport parameters extension and the Version
//! Information parameter. Nothing is copied or allocated.
//!
//! When the ClientHello does not fit in that packet, or anything about it
//! is unexpected, there is no answer and the server keeps the client's
//! version, which RFC 9368 permits. The TLS session and the transport
//! parameter decoder still check the whole ClientHello afterwards.

use super::{VersionInformation, VersionList};

/// CRYPTO frames read from one packet; more leave the first flight unread
const MAX_CRYPTO_FRAMES: usize = 8;

/// TLS HandshakeType client_hello (RFC 8446 section 4)
const CLIENT_HELLO: u8 = 1;

/// TLS ExtensionType quic_transport_parameters (RFC 9001 section 8.2)
const QUIC_TRANSPORT_PARAMETERS: u16 = 0x39;

/// The Version Information transport parameter (RFC 9368 section 3)
const VERSION_INFORMATION: u64 = 0x11;

/// The client's Version Information, when the decrypted Initial `payload`
/// holds the whole ClientHello and the ClientHello carries one
pub(crate) fn client_version_information(payload: &[u8]) -> Option<VersionInformation> {
    let crypto = CryptoData::read(payload)?;
    let mut hello = crypto.cursor(0);
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
fn transport_parameter(mut params: Cursor<'_>) -> Option<VersionInformation> {
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
fn version_information(mut body: Cursor<'_>) -> Option<VersionInformation> {
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

/// The CRYPTO frames of one Initial packet, by stream offset
struct CryptoData<'a> {
    frames: [(u64, &'a [u8]); MAX_CRYPTO_FRAMES],
    count: usize,
}

impl<'a> CryptoData<'a> {
    /// Collect the CRYPTO frames of an Initial packet payload. Initial
    /// packets carry only PADDING, PING, ACK, CRYPTO and CONNECTION_CLOSE
    /// (RFC 9000 section 12.4); any other frame leaves the payload unread.
    fn read(payload: &'a [u8]) -> Option<Self> {
        let mut data = Self {
            frames: [(0, &[]); MAX_CRYPTO_FRAMES],
            count: 0,
        };
        let mut r = Cursor::contiguous(payload);
        while !r.is_empty() {
            match r.var()? {
                0x00 | 0x01 => {}
                ty @ (0x02 | 0x03) => {
                    r.var()?; // largest acknowledged
                    r.var()?; // delay
                    let ranges = r.var()?;
                    r.var()?; // first range
                    for _ in 0..ranges {
                        r.var()?;
                        r.var()?;
                    }
                    if ty == 0x03 {
                        for _ in 0..3 {
                            r.var()?;
                        }
                    }
                }
                0x06 => {
                    let offset = r.var()?;
                    let len = r.var()?;
                    let bytes = r.slice(len)?;
                    if data.count == MAX_CRYPTO_FRAMES {
                        return None;
                    }
                    data.frames[data.count] = (offset, bytes);
                    data.count += 1;
                }
                _ => return None,
            }
        }
        Some(data)
    }

    fn cursor(&self, position: u64) -> Cursor<'_> {
        Cursor {
            source: Source::Crypto(self),
            position,
            end: u64::MAX,
        }
    }

    /// The stream byte at `position`, if a frame carries it
    fn byte(&self, position: u64) -> Option<u8> {
        self.frames[..self.count]
            .iter()
            .find_map(|&(offset, bytes)| {
                let index = position.checked_sub(offset)?;
                bytes.get(usize::try_from(index).ok()?).copied()
            })
    }
}

#[derive(Clone, Copy)]
enum Source<'a> {
    Contiguous(&'a [u8]),
    Crypto(&'a CryptoData<'a>),
}

/// A bounded reader over a source, failing at the bound or a missing byte
#[derive(Clone, Copy)]
struct Cursor<'a> {
    source: Source<'a>,
    position: u64,
    end: u64,
}

impl<'a> Cursor<'a> {
    fn contiguous(bytes: &'a [u8]) -> Self {
        Self {
            source: Source::Contiguous(bytes),
            position: 0,
            end: bytes.len() as u64,
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
        let byte = match self.source {
            Source::Contiguous(bytes) => *bytes.get(usize::try_from(self.position).ok()?)?,
            Source::Crypto(data) => data.byte(self.position)?,
        };
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

    /// The next `len` bytes of a contiguous source
    fn slice(&mut self, len: u64) -> Option<&'a [u8]> {
        let Source::Contiguous(bytes) = self.source else {
            return None;
        };
        let start = usize::try_from(self.position).ok()?;
        let range = self.limit(len)?;
        bytes.get(start..usize::try_from(range.end).ok()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        coding::BufMutExt,
        version::{QUIC_V1, QUIC_V2},
    };

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

    fn crypto_frame(offset: u64, data: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.write_var(0x06);
        frame.write_var(offset);
        frame.write_var(data.len() as u64);
        frame.extend_from_slice(data);
        frame
    }

    #[test]
    fn reads_the_client_offer_from_one_crypto_frame_and_padding() {
        let hello = client_hello(&params(QUIC_V1, &[QUIC_V2, 0x1a2a_3a4a, QUIC_V1]));
        let mut payload = crypto_frame(0, &hello);
        payload.resize(1162, 0);
        let info = client_version_information(&payload).unwrap();
        assert_eq!(info.chosen, QUIC_V1);
        assert_eq!(info.available.as_slice(), &[QUIC_V2, QUIC_V1]);
        assert!(info.unknown_available);
    }

    #[test]
    fn reads_shuffled_crypto_frames_around_ping_and_ack() {
        let hello = client_hello(&params(QUIC_V1, &[QUIC_V1, QUIC_V2]));
        let (a, rest) = hello.split_at(40);
        let (b, c) = rest.split_at(17);
        let mut payload = vec![0x01];
        payload.extend(crypto_frame(57, c));
        payload.extend([0x02, 0x05, 0x00, 0x01, 0x00, 0x01, 0x01]);
        payload.extend(crypto_frame(0, a));
        payload.extend([0x00, 0x00]);
        payload.extend(crypto_frame(40, b));
        let info = client_version_information(&payload).unwrap();
        assert_eq!(info.available.as_slice(), &[QUIC_V1, QUIC_V2]);
    }

    #[test]
    fn a_hello_that_is_incomplete_or_malformed_gives_no_offer() {
        let hello = client_hello(&params(QUIC_V1, &[QUIC_V2, QUIC_V1]));
        // A gap: the last byte belongs to a later packet.
        assert!(client_version_information(&crypto_frame(0, &hello[..hello.len() - 1])).is_none());
        // The client's Chosen Version must be among its available versions.
        let missing = client_hello(&params(QUIC_V1, &[QUIC_V2]));
        assert!(client_version_information(&crypto_frame(0, &missing)).is_none());
        let zero = client_hello(&params(QUIC_V1, &[QUIC_V1, 0]));
        assert!(client_version_information(&crypto_frame(0, &zero)).is_none());
        let none = client_hello(&[0x04, 0x02, 0x43, 0xe8]);
        assert!(client_version_information(&crypto_frame(0, &none)).is_none());
        // A STREAM frame cannot appear in an Initial packet.
        let mut stream = crypto_frame(0, &hello);
        stream.extend([0x08, 0x00, 0x00]);
        assert!(client_version_information(&stream).is_none());
        // A transport parameter extension longer than its ClientHello.
        let mut long = hello.clone();
        let at = long.len() - params(QUIC_V1, &[QUIC_V2, QUIC_V1]).len() - 2;
        long[at..at + 2].copy_from_slice(&0xffffu16.to_be_bytes());
        assert!(client_version_information(&crypto_frame(0, &long)).is_none());
    }

    #[cfg(feature = "rustls-ring")]
    #[test]
    fn the_rfc9369_sample_client_hello_has_parameters_but_no_offer() {
        // RFC 9369 Appendix A.2: its transport parameters lack Version
        // Information, so the server keeps the client's version.
        let mut payload = crate::packet::rfc9369_vectors::CLIENT_CRYPTO.to_vec();
        payload.resize(1162, 0);
        assert!(CryptoData::read(&payload).is_some());
        assert!(client_version_information(&payload).is_none());
    }
}
