#[cfg(feature = "ring")]
use ring::{aead, error, hkdf, hmac};

use crate::crypto::{self, CryptoError};

impl crypto::HmacKey for hmac::Key {
    fn sign(&self, data: &[u8], out: &mut [u8]) {
        out.copy_from_slice(hmac::sign(self, data).as_ref());
    }

    fn signature_len(&self) -> usize {
        32
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        Ok(hmac::verify(self, data, signature)?)
    }
}

impl crypto::HandshakeTokenKey for hkdf::Prk {
    fn seal(
        &self,
        random_bytes: &[u8],
        data: &mut [u8],
        additional_data: &[u8],
    ) -> Result<[u8; crypto::TOKEN_TAG_LEN], CryptoError> {
        let tag = token_key(self, random_bytes).seal_in_place_separate_tag(
            aead::Nonce::assume_unique_for_key([0u8; 12]),
            aead::Aad::from(additional_data),
            data,
        )?;
        let mut out = [0; crypto::TOKEN_TAG_LEN];
        out.copy_from_slice(tag.as_ref());
        Ok(out)
    }

    fn open<'a>(
        &self,
        random_bytes: &[u8],
        data: &'a mut [u8],
        additional_data: &[u8],
    ) -> Result<&'a mut [u8], CryptoError> {
        Ok(token_key(self, random_bytes).open_in_place(
            aead::Nonce::assume_unique_for_key([0u8; 12]),
            aead::Aad::from(additional_data),
            data,
        )?)
    }
}

/// The AEAD key of one token, derived from its random bytes; it lives on
/// the stack
fn token_key(prk: &hkdf::Prk, random_bytes: &[u8]) -> aead::LessSafeKey {
    let mut key_buffer = [0u8; 32];
    let info = [random_bytes];
    let okm = prk.expand(&info, hkdf::HKDF_SHA256).unwrap();
    okm.fill(&mut key_buffer).unwrap();
    aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &key_buffer).unwrap())
}

impl From<error::Unspecified> for CryptoError {
    fn from(_: error::Unspecified) -> Self {
        Self
    }
}
