//! Connection IDs depend on supplied entropy and reject malformed lengths.

use super::*;

struct Entropy {
    bytes: [u8; MAX_CID_SIZE],
    consumed: usize,
}

impl rand::TryRng for Entropy {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), Self::Error> {
        out.copy_from_slice(&self.bytes[self.consumed..self.consumed + out.len()]);
        self.consumed += out.len();
        Ok(())
    }
}

#[kani::proof]
#[kani::unwind(21)]
fn random_ids_use_the_supplied_bytes() {
    let bytes = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= MAX_CID_SIZE);
    let mut entropy = Entropy { bytes, consumed: 0 };
    let id = RandomConnectionIdGenerator::new(len).generate_cid(&mut entropy);
    assert_eq!(id.len(), len);
    assert_eq!(&id[..], &bytes[..len]);
    assert_eq!(entropy.consumed, len);
}

#[kani::proof]
#[kani::unwind(21)]
fn keyed_ids_validate_with_their_own_key() {
    let mut entropy = Entropy {
        bytes: kani::any(),
        consumed: 0,
    };
    let mut generator = HashedConnectionIdGenerator::new(&mut entropy);
    let id = generator.generate_cid(&mut entropy);
    assert_eq!(id.len(), generator.cid_len());
    assert!(generator.validate(&id).is_ok());
    assert_eq!(entropy.consumed, 8 + NONCE_LEN);
}

#[kani::proof]
#[kani::unwind(21)]
fn keyed_ids_reject_wrong_lengths() {
    let generator = HashedConnectionIdGenerator::from_key(kani::any());
    let bytes: [u8; MAX_CID_SIZE] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= MAX_CID_SIZE && len != generator.cid_len());
    assert!(generator
        .validate(&ConnectionId::new(&bytes[..len]))
        .is_err());
}
