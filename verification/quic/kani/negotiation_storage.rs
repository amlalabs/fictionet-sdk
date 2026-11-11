//! Storage of version negotiation (RFC 9368, RFC 9369): the other version's
//! Initial keys are charged before they are derived and freed before their
//! charge is released, and the negotiation decisions allocate nothing.
//!
//! The keys here stand in for the crypto provider's: each is a fixed block
//! that asserts, as it is freed, that the charge is still held. That the real
//! derivation holds no more than `initial_keys_charge` is the replay
//! `initial_key_derivations_stay_within_their_charge` in `crypto/rustls.rs`.
use super::*;
use crate::counting::{counted_proof, measure};
use crate::crypto::{CryptoError, HeaderKey, KeyPair, PacketKey};
use crate::version::{QUIC_V1, QUIC_V2};
use bytes::BytesMut;

/// What one fake key occupies
const KEY: usize = 32;
/// What a derivation of four fake keys is charged
const CHARGE: usize = 4 * KEY;

/// A key that checks, when freed, that `budget` still holds at least `held`
struct FakeKey {
    budget: Budget,
    held: usize,
    _pad: [u8; KEY - size_of::<Budget>() - size_of::<usize>()],
}

impl Drop for FakeKey {
    fn drop(&mut self) {
        assert!(self.budget.used() >= self.held, "a key outlived its charge");
    }
}

impl HeaderKey for FakeKey {
    fn decrypt(&self, _: usize, _: &mut [u8]) {}
    fn encrypt(&self, _: usize, _: &mut [u8]) {}
    fn sample_size(&self) -> usize {
        16
    }
    fn heap_size(&self) -> usize {
        0
    }
}

impl PacketKey for FakeKey {
    fn encrypt(&self, _: u64, _: &mut [u8], _: usize) {}
    fn decrypt(&self, _: u64, _: &[u8], _: &mut BytesMut) -> Result<(), CryptoError> {
        Ok(())
    }
    fn tag_len(&self) -> usize {
        16
    }
    fn confidentiality_limit(&self) -> u64 {
        0
    }
    fn integrity_limit(&self) -> u64 {
        0
    }
    fn heap_size(&self) -> usize {
        0
    }
}

/// Four keys, each checking on its free that `budget` holds `held`
fn fake_keys(budget: &Budget, held: usize) -> Keys {
    let key = || FakeKey {
        budget: budget.clone(),
        held,
        _pad: [0; KEY - size_of::<Budget>() - size_of::<usize>()],
    };
    Keys {
        header: KeyPair {
            local: Box::new(key()),
            remote: Box::new(key()),
        },
        packet: KeyPair {
            local: Box::new(key()),
            remote: Box::new(key()),
        },
    }
}

counted_proof! {
    /// A budget without room for a derivation refuses it before anything
    /// is derived or allocated; with room, the derivation never holds more
    /// than the charge, and the keys are freed before it is released.
    #[kani::unwind(5)]
    fn other_initial_keys_are_charged_before_they_are_derived() {
        assert!(size_of::<FakeKey>() == KEY);
        // One byte short of the charge, or room for it and more.
        let limit = if kani::any() { CHARGE - 1 } else { 2 * CHARGE };
        let budget = Budget::new(limit);
        let mut derived = false;
        let ((used_while_held, used_after), cost) = measure(|| {
            let other = OtherInitial::derive(QUIC_V1, Some(&budget), CHARGE, || {
                derived = true;
                Ok(fake_keys(&budget, CHARGE))
            });
            let held = other.is_some();
            let used = budget.used();
            drop(other);
            (held.then_some(used), budget.used())
        });
        if limit < CHARGE {
            assert!(used_while_held.is_none());
            assert!(!derived);
            assert!(cost.requested <= 0);
        } else {
            assert!(used_while_held.is_some_and(|used| used >= CHARGE));
            assert!(cost.peak <= CHARGE);
            // Four keys, whatever the input: no copy grows with it.
            assert!(cost.requested <= CHARGE);
        }
        assert!(used_after == 0);
        assert!(cost.live == 0);
        std::mem::forget(budget);
    }
}

counted_proof! {
    /// Installing tried keys frees the keys they replace while the charge
    /// is held, then releases it: no moment holds both sets uncharged.
    #[kani::unwind(5)]
    fn installed_keys_free_the_old_ones_before_the_charge_goes() {
        let budget = Budget::new(CHARGE);
        let ((version, used), cost) = measure(|| {
            // The connection's own keys, paid for when it opened.
            let mut slot = Some(fake_keys(&budget, CHARGE));
            let other =
                OtherInitial::derive(QUIC_V2, Some(&budget), CHARGE, || Ok(fake_keys(&budget, 0)))
                    .unwrap();
            let version = other.install(&mut slot);
            let used = budget.used();
            std::mem::forget(slot);
            (version, used)
        });
        assert!(version == QUIC_V2);
        assert!(used == 0);
        // The connection's keys and the tried ones, never more.
        assert!(cost.peak <= 2 * CHARGE);
        std::mem::forget(budget);
    }
}

counted_proof! {
    /// A refused derivation of a transient key charge (a restart after
    /// Version Negotiation, a Retry) holds nothing; a granted one is
    /// released when dropped.
    #[kani::unwind(3)]
    fn a_key_charge_is_all_or_nothing() {
        let limit = if kani::any() { CHARGE - 1 } else { 2 * CHARGE };
        let budget = Budget::new(limit);
        let (granted, cost) = measure(|| {
            let charge = KeyCharge::take(Some(&budget), CHARGE);
            let granted = charge.is_some();
            assert!(budget.used() == if granted { CHARGE } else { 0 });
            drop(charge);
            granted
        });
        assert!(granted == (limit >= CHARGE));
        assert!(budget.used() == 0);
        assert!(cost.requested <= 0);
        std::mem::forget(budget);
    }
}

counted_proof! {
    /// A client reads a Version Negotiation packet, decides how to react,
    /// admits long headers and says what it can decode without allocating.
    /// (A failed check of the server's Version Information allocates the
    /// reason of the error that closes the connection, as every transport
    /// error does.)
    #[kani::unwind(6)]
    fn negotiation_decisions_allocate_nothing() {
        let listed: [u32; 3] = kani::any();
        let payload: [u8; 12] = {
            let mut bytes = [0; 12];
            for (chunk, version) in bytes.chunks_exact_mut(4).zip(listed) {
                chunk.copy_from_slice(&version.to_be_bytes());
            }
            bytes
        };
        let version: u32 = kani::any();
        let reacted: bool = kani::any();
        let kind = match kani::any::<u8>() % 4 {
            0 => LongKind::Initial,
            1 => LongKind::ZeroRtt,
            2 => LongKind::Handshake,
            _ => LongKind::Retry,
        };
        let supported = [QUIC_V1, QUIC_V2];
        let ((), cost) = measure(|| {
            let preference = VersionList::new(&[QUIC_V2, QUIC_V1]).unwrap();
            let client =
                Negotiation::client(QUIC_V1, preference, reacted, TransportParameters::default());
            let lists = |v: u32| payload.chunks_exact(4).any(|x| x == v.to_be_bytes());
            let reaction = client.react(lists, &supported);
            if reacted || listed.contains(&QUIC_V1) {
                assert!(reaction == Reaction::Ignore);
            }
            let _ = client.admit(Side::Client, QUIC_V1, kind, version);
            let _ = client.decodable(Side::Client, QUIC_V1);
            let server = Negotiation::server(QUIC_V1, TransportParameters::default());
            let _ = server.admit(Side::Server, version, kind, QUIC_V1);
        });
        assert!(cost.requested <= 0);
        assert!(cost.peak <= 0);
    }
}
