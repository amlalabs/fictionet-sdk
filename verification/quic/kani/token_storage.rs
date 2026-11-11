//! Storage of Retry tokens (RFC 9000 section 8.1.2): a server seals a token
//! in the buffer it sends the Retry from and opens a returned one on the
//! stack, so neither allocates.
//!
//! The key stands in for the AEAD: it masks the bytes and tags them with a
//! sum that `open` checks, so a token round-trips only through the same
//! key, nonce and version. The real key does the same through ring in place
//! (`crypto/ring_like.rs`); its tag length is `TOKEN_TAG_LEN`.
use super::*;
use crate::counting::{counted_proof, measure};
use crate::crypto::CryptoError;

struct MaskKey(u8);

impl MaskKey {
    fn mask(&self, random: &[u8], aad: &[u8]) -> u8 {
        random
            .iter()
            .chain(aad)
            .fold(self.0, |mask, byte| mask.wrapping_add(*byte))
    }
}

impl HandshakeTokenKey for MaskKey {
    fn seal(
        &self,
        random_bytes: &[u8],
        data: &mut [u8],
        additional_data: &[u8],
    ) -> Result<[u8; TOKEN_TAG_LEN], CryptoError> {
        let mask = self.mask(random_bytes, additional_data);
        let mut sum = mask;
        for byte in data.iter_mut() {
            sum = sum.wrapping_add(*byte);
            *byte ^= mask;
        }
        Ok([sum; TOKEN_TAG_LEN])
    }

    fn open<'a>(
        &self,
        random_bytes: &[u8],
        data: &'a mut [u8],
        additional_data: &[u8],
    ) -> Result<&'a mut [u8], CryptoError> {
        let mask = self.mask(random_bytes, additional_data);
        let split = data.len().checked_sub(TOKEN_TAG_LEN).ok_or(CryptoError)?;
        let (plain, tag) = data.split_at_mut(split);
        let mut sum = mask;
        for byte in plain.iter_mut() {
            *byte ^= mask;
            sum = sum.wrapping_add(*byte);
        }
        if tag.iter().any(|t| *t != sum) {
            return Err(CryptoError);
        }
        Ok(plain)
    }
}

counted_proof! {
    /// A Retry token for any IPv4 address and an 8-byte connection ID is
    /// sealed into the send buffer, which needs at most `MAX_ENCODED` bytes
    /// of room, and opened again for the same version, without allocating.
    #[kani::unwind(70)]
    fn a_retry_token_is_sealed_and_opened_in_place() {
        let octets: [u8; 4] = kani::any();
        let port: u16 = kani::any();
        let cid: [u8; 8] = kani::any();
        let secs: u32 = kani::any();
        let nonce: u128 = kani::any();
        let version: u32 = kani::any();
        let key = MaskKey(kani::any());
        let address = SocketAddr::new(IpAddr::from(octets), port);
        let token = Token {
            payload: TokenPayload::Retry {
                address,
                orig_dst_cid: ConnectionId::new(&cid),
                issued: UNIX_EPOCH + Duration::from_secs(secs.into()),
            },
            nonce,
        };
        let mut buf = Vec::with_capacity(Token::MAX_ENCODED);
        let (decoded, cost) = measure(|| {
            token.encode_into(&key, version, &mut buf);
            Token::decode(&key, version, &buf)
        });
        assert!(cost.requested <= 0);
        assert!(cost.peak <= 0);
        assert!(buf.len() <= Token::MAX_ENCODED);
        let decoded = decoded.unwrap();
        assert!(decoded.nonce == nonce);
        let TokenPayload::Retry {
            address: decoded_address,
            orig_dst_cid,
            issued,
        } = decoded.payload
        else {
            panic!("a Retry token decoded as another kind");
        };
        assert!(decoded_address == address);
        assert!(orig_dst_cid[..] == cid);
        assert!(issued == UNIX_EPOCH + Duration::from_secs(secs.into()));
        std::mem::forget(buf);
    }
}

counted_proof! {
    /// A returned token longer than any this server seals is refused
    /// before it is copied, and a shorter one is opened on the stack: no
    /// token, however long, makes the server allocate.
    #[kani::unwind(100)]
    fn a_returned_token_never_allocates() {
        let bytes: [u8; Token::MAX_ENCODED + 1] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        let version: u32 = kani::any();
        let key = MaskKey(kani::any());
        let (decoded, cost) = measure(|| Token::decode(&key, version, &bytes[..len]));
        if len > Token::MAX_ENCODED {
            assert!(decoded.is_none());
        }
        assert!(cost.requested <= 0);
        assert!(cost.peak <= 0);
        std::mem::forget(decoded);
    }
}
