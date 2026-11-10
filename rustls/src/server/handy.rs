use alloc::vec::Vec;
use core::fmt::Debug;

use crate::server::ClientHello;
use crate::sync::Arc;
use crate::{server, sign};

/// Something which never stores sessions.
#[derive(Debug)]
pub struct NoServerSessionStorage {}

impl server::StoresServerSessions for NoServerSessionStorage {
    fn put(&self, _id: Vec<u8>, _sec: Vec<u8>) -> bool {
        false
    }
    fn get(&self, _id: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn take(&self, _id: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn can_cache(&self) -> bool {
        false
    }
}

#[cfg(any(feature = "std", feature = "hashbrown"))]
mod cache {
    use alloc::vec::Vec;
    use core::fmt::{Debug, Formatter};

    use crate::lock::Mutex;
    use crate::sync::Arc;
    use crate::{limited_cache, server};

    /// An implementer of `StoresServerSessions` that stores everything
    /// in memory.  It enforces a limit on the number of stored sessions
    /// to bound memory usage.
    pub struct ServerSessionMemoryCache {
        cache: Mutex<limited_cache::LimitedCache<Vec<u8>, Vec<u8>>>,
    }

    impl ServerSessionMemoryCache {
        /// Make a new ServerSessionMemoryCache.  `size` is the maximum
        /// number of stored sessions, and may be rounded-up for
        /// efficiency.
        #[cfg(feature = "std")]
        pub fn new(size: usize) -> Arc<Self> {
            Arc::new(Self {
                cache: Mutex::new(limited_cache::LimitedCache::new(size)),
            })
        }

        /// Make a new ServerSessionMemoryCache.  `size` is the maximum
        /// number of stored sessions, and may be rounded-up for
        /// efficiency.
        #[cfg(not(feature = "std"))]
        pub fn new<M: crate::lock::MakeMutex>(size: usize) -> Arc<Self> {
            Arc::new(Self {
                cache: Mutex::new::<M>(limited_cache::LimitedCache::new(size)),
            })
        }
    }

    impl server::StoresServerSessions for ServerSessionMemoryCache {
        fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
            self.cache.lock().unwrap().insert(key, value);
            true
        }

        fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.cache.lock().unwrap().get(key).cloned()
        }

        fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.cache.lock().unwrap().remove(key)
        }

        fn can_cache(&self) -> bool {
            true
        }
    }

    impl Debug for ServerSessionMemoryCache {
        fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("ServerSessionMemoryCache").finish()
        }
    }

    /// The most bytes of a session's key a slot holds: rustls's session
    /// ids and stateful ticket ids are 32 bytes.
    pub const SLOT_KEY: usize = 32;

    /// The most bytes of a session a slot holds: a session without client
    /// certificates or resumption data, whose name and protocol are each at
    /// most 255 bytes, encodes in less.
    pub const SLOT_VALUE: usize = 1024;

    /// One session: its key and its encoding, in place.
    struct Slot {
        key: [u8; SLOT_KEY],
        key_len: u8,
        value: [u8; SLOT_VALUE],
        value_len: u16,
        /// When it was put, to drop the oldest first; 0 while free.
        put: u64,
    }

    /// Sessions in slots made and paid for once, when the store is made: a
    /// connection that stores, finds or takes a session allocates nothing
    /// the store keeps, so nothing a connection made stays allocated after
    /// it is gone. A session whose key or encoding does not fit a slot is
    /// not kept. When every slot is taken, the oldest session goes.
    pub struct ServerSessionSlots {
        slots: Mutex<(Vec<Slot>, u64)>,
        _paid: crate::budget::Paid,
    }

    impl ServerSessionSlots {
        /// A store for `size` sessions, paid for by `budget` now and for
        /// its life: `size` slots of [`SLOT_KEY`] and [`SLOT_VALUE`] bytes.
        /// `None`, making nothing, if the budget has no room.
        #[cfg(feature = "std")]
        pub fn with_budget(
            size: usize,
            budget: Arc<dyn crate::budget::BufferBudget>,
        ) -> Option<Arc<Self>> {
            let mut paid = crate::budget::Paid::open(&Some(budget));
            if !paid.grow_by(size.checked_mul(size_of::<Slot>())?) {
                return None;
            }
            let mut slots = Vec::with_capacity(size);
            slots.extend((0..size).map(|_| Slot {
                key: [0; SLOT_KEY],
                key_len: 0,
                value: [0; SLOT_VALUE],
                value_len: 0,
                put: 0,
            }));
            Some(Arc::new(Self {
                slots: Mutex::new((slots, 0)),
                _paid: paid,
            }))
        }

        fn find<'a>(slots: &'a mut [Slot], key: &[u8]) -> Option<&'a mut Slot> {
            slots
                .iter_mut()
                .find(|slot| slot.put != 0 && &slot.key[..usize::from(slot.key_len)] == key)
        }
    }

    impl server::StoresServerSessions for ServerSessionSlots {
        fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
            if key.len() > SLOT_KEY || value.len() > SLOT_VALUE {
                return false;
            }
            let mut guard = self.slots.lock().unwrap();
            let (slots, clock) = &mut *guard;
            *clock += 1;
            let now = *clock;
            let slot = match slots
                .iter()
                .position(|slot| slot.put != 0 && slot.key[..usize::from(slot.key_len)] == key[..])
            {
                Some(found) => &mut slots[found],
                // A free slot, or the oldest.
                None => match slots.iter_mut().min_by_key(|slot| slot.put) {
                    Some(slot) => slot,
                    None => return false,
                },
            };
            slot.key[..key.len()].copy_from_slice(&key);
            slot.key_len = key.len() as u8;
            slot.value[..value.len()].copy_from_slice(&value);
            slot.value_len = value.len() as u16;
            slot.put = now;
            true
        }

        fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
            let mut guard = self.slots.lock().unwrap();
            let slot = Self::find(&mut guard.0, key)?;
            Some(slot.value[..usize::from(slot.value_len)].to_vec())
        }

        fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
            let mut guard = self.slots.lock().unwrap();
            let slot = Self::find(&mut guard.0, key)?;
            slot.put = 0;
            Some(slot.value[..usize::from(slot.value_len)].to_vec())
        }

        fn can_cache(&self) -> bool {
            true
        }
    }

    impl Debug for ServerSessionSlots {
        fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("ServerSessionSlots").finish()
        }
    }

    #[cfg(test)]
    mod tests {
        use std::vec;

        use super::*;
        use crate::budget::testing::Limit;
        use crate::server::StoresServerSessions;

        /// The slot store is charged once, when it is made, and never
        /// again; it refuses to be made without room. Against a model of
        /// the most recent `size` sessions, over seeded puts, gets, takes
        /// and sessions too large to keep, it finds what the model finds.
        #[test]
        fn slots_are_paid_once_and_keep_the_latest_sessions() {
            let size = 4;
            let limit = Limit::new(1 << 10);
            assert!(ServerSessionSlots::with_budget(size, limit.clone()).is_none());
            assert_eq!(limit.used(), 0);

            let limit = Limit::new(1 << 20);
            let store = ServerSessionSlots::with_budget(size, limit.clone()).unwrap();
            let paid = limit.used();
            assert!(paid >= size * (SLOT_KEY + SLOT_VALUE));

            // (key, value, when put), the model of what the store keeps.
            let mut model: Vec<(Vec<u8>, Vec<u8>, u64)> = Vec::new();
            let mut seed = 0x9e37_79b9_7f4a_7c15u64;
            let mut next = |n: u64| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed % n
            };
            for step in 1..2000u64 {
                let key = vec![next(8) as u8; 1 + next(SLOT_KEY as u64) as usize];
                match next(4) {
                    0 | 1 => {
                        let len = match next(10) {
                            0 => SLOT_VALUE + 1,
                            _ => next(SLOT_VALUE as u64 + 1) as usize,
                        };
                        let value = vec![step as u8; len];
                        let kept = store.put(key.clone(), value.clone());
                        assert_eq!(kept, len <= SLOT_VALUE, "step {step}");
                        if kept {
                            model.retain(|(k, _, _)| *k != key);
                            if model.len() == size {
                                let oldest = (0..model.len()).min_by_key(|&i| model[i].2).unwrap();
                                model.remove(oldest);
                            }
                            model.push((key, value, step));
                        }
                    }
                    2 => {
                        let expected = model
                            .iter()
                            .find(|(k, _, _)| *k == key)
                            .map(|(_, v, _)| v.clone());
                        assert_eq!(store.get(&key), expected, "step {step}");
                    }
                    _ => {
                        let expected = model
                            .iter()
                            .position(|(k, _, _)| *k == key)
                            .map(|i| model.remove(i).1);
                        assert_eq!(store.take(&key), expected, "step {step}");
                    }
                }
                assert_eq!(limit.used(), paid, "step {step}: the store's charge moved");
            }
            drop(store);
            assert_eq!(limit.used(), 0);
        }

        #[test]
        fn test_serversessionmemorycache_accepts_put() {
            let c = ServerSessionMemoryCache::new(4);
            assert!(c.put(vec![0x01], vec![0x02]));
        }

        #[test]
        fn test_serversessionmemorycache_persists_put() {
            let c = ServerSessionMemoryCache::new(4);
            assert!(c.put(vec![0x01], vec![0x02]));
            assert_eq!(c.get(&[0x01]), Some(vec![0x02]));
            assert_eq!(c.get(&[0x01]), Some(vec![0x02]));
        }

        #[test]
        fn test_serversessionmemorycache_overwrites_put() {
            let c = ServerSessionMemoryCache::new(4);
            assert!(c.put(vec![0x01], vec![0x02]));
            assert!(c.put(vec![0x01], vec![0x04]));
            assert_eq!(c.get(&[0x01]), Some(vec![0x04]));
        }

        /// After five sessions are put into a cache of size 2, exactly the
        /// two most recently added sessions remain.
        #[test]
        fn test_serversessionmemorycache_drops_to_maintain_size_invariant() {
            let c = ServerSessionMemoryCache::new(2);
            assert!(c.put(vec![0x01], vec![0x02]));
            assert!(c.put(vec![0x03], vec![0x04]));
            assert!(c.put(vec![0x05], vec![0x06]));
            assert!(c.put(vec![0x07], vec![0x08]));
            assert!(c.put(vec![0x09], vec![0x0a]));

            assert_eq!(c.get(&[0x01]), None);
            assert_eq!(c.get(&[0x03]), None);
            assert_eq!(c.get(&[0x05]), None);
            assert_eq!(c.get(&[0x07]), Some(vec![0x08]));
            assert_eq!(c.get(&[0x09]), Some(vec![0x0a]));
        }

        /// A cache of size 1 keeps the session put into it, and a second
        /// put replaces it.
        #[test]
        fn test_serversessionmemorycache_size_one_retains_session() {
            let c = ServerSessionMemoryCache::new(1);
            assert!(c.put(vec![0x01], vec![0x02]));
            assert_eq!(c.get(&[0x01]), Some(vec![0x02]));

            assert!(c.put(vec![0x03], vec![0x04]));
            assert_eq!(c.get(&[0x01]), None);
            assert_eq!(c.get(&[0x03]), Some(vec![0x04]));
        }
    }
}

#[cfg(any(feature = "std", feature = "hashbrown"))]
pub use cache::{ServerSessionMemoryCache, ServerSessionSlots, SLOT_KEY, SLOT_VALUE};

/// Something which never produces tickets.
#[derive(Debug)]
pub(super) struct NeverProducesTickets {}

impl server::ProducesTickets for NeverProducesTickets {
    fn enabled(&self) -> bool {
        false
    }
    fn lifetime(&self) -> u32 {
        0
    }
    fn encrypt(&self, _bytes: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn decrypt(&self, _bytes: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

/// An exemplar `ResolvesServerCert` implementation that always resolves to a single
/// [RFC 7250] raw public key.
///
/// [RFC 7250]: https://tools.ietf.org/html/rfc7250
#[derive(Clone, Debug)]
pub struct AlwaysResolvesServerRawPublicKeys(Arc<sign::CertifiedKey>);

impl AlwaysResolvesServerRawPublicKeys {
    /// Create a new `AlwaysResolvesServerRawPublicKeys` instance.
    pub fn new(certified_key: Arc<sign::CertifiedKey>) -> Self {
        Self(certified_key)
    }
}

impl server::ResolvesServerCert for AlwaysResolvesServerRawPublicKeys {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<sign::CertifiedKey>> {
        Some(self.0.clone())
    }

    fn most_chain(&self) -> Option<usize> {
        Some(self.0.flight_bytes())
    }

    fn only_raw_public_keys(&self) -> bool {
        true
    }
}

#[cfg(any(feature = "std", feature = "hashbrown"))]
mod sni_resolver {
    use alloc::string::{String, ToString};
    use core::fmt::Debug;

    use pki_types::{DnsName, ServerName};

    use crate::error::Error;
    use crate::hash_map::HashMap;
    use crate::server::ClientHello;
    use crate::sync::Arc;
    use crate::webpki::{verify_server_name, ParsedCertificate};
    use crate::{server, sign};

    /// Something that resolves do different cert chains/keys based
    /// on client-supplied server name (via SNI).
    #[derive(Debug)]
    pub struct ResolvesServerCertUsingSni {
        by_name: HashMap<String, Arc<sign::CertifiedKey>>,
        /// The most [`sign::CertifiedKey::flight_bytes`] of any chain added.
        most_chain: usize,
    }

    impl ResolvesServerCertUsingSni {
        /// Create a new and empty (i.e., knows no certificates) resolver.
        pub fn new() -> Self {
            Self {
                by_name: HashMap::new(),
                most_chain: 0,
            }
        }

        /// Add a new `sign::CertifiedKey` to be used for the given SNI `name`.
        ///
        /// This function fails if `name` is not a valid DNS name, or if
        /// it's not valid for the supplied certificate, or if the certificate
        /// chain is syntactically faulty.
        pub fn add(&mut self, name: &str, ck: sign::CertifiedKey) -> Result<(), Error> {
            let server_name = {
                let checked_name = DnsName::try_from(name)
                    .map_err(|_| Error::General("Bad DNS name".into()))
                    .map(|name| name.to_lowercase_owned())?;
                ServerName::DnsName(checked_name)
            };

            // Check the certificate chain for validity:
            // - it should be non-empty list
            // - the first certificate should be parsable as a x509v3,
            // - the first certificate should quote the given server name
            //   (if provided)
            //
            // These checks are not security-sensitive.  They are the
            // *server* attempting to detect accidental misconfiguration.

            ck.end_entity_cert()
                .and_then(ParsedCertificate::try_from)
                .and_then(|cert| verify_server_name(&cert, &server_name))?;

            if let ServerName::DnsName(name) = server_name {
                self.most_chain = self.most_chain.max(ck.flight_bytes());
                self.by_name.insert(name.as_ref().to_string(), Arc::new(ck));
            }
            Ok(())
        }
    }

    impl server::ResolvesServerCert for ResolvesServerCertUsingSni {
        fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<sign::CertifiedKey>> {
            if let Some(name) = client_hello.server_name() {
                self.by_name.get(name).cloned()
            } else {
                // This kind of resolver requires SNI
                None
            }
        }

        fn most_chain(&self) -> Option<usize> {
            Some(self.most_chain)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::server::ResolvesServerCert;

        #[test]
        fn test_resolvesservercertusingsni_requires_sni() {
            let rscsni = ResolvesServerCertUsingSni::new();
            assert!(rscsni
                .resolve(ClientHello {
                    server_name: &None,
                    signature_schemes: &[],
                    alpn: None,
                    server_cert_types: None,
                    client_cert_types: None,
                    cipher_suites: &[],
                    certificate_authorities: None,
                    named_groups: None,
                })
                .is_none());
        }

        #[test]
        fn test_resolvesservercertusingsni_handles_unknown_name() {
            let rscsni = ResolvesServerCertUsingSni::new();
            let name = DnsName::try_from("hello.com").unwrap().to_owned();
            assert!(rscsni
                .resolve(ClientHello {
                    server_name: &Some(name),
                    signature_schemes: &[],
                    alpn: None,
                    server_cert_types: None,
                    client_cert_types: None,
                    cipher_suites: &[],
                    certificate_authorities: None,
                    named_groups: None,
                })
                .is_none());
        }
    }
}

#[cfg(any(feature = "std", feature = "hashbrown"))]
pub use sni_resolver::ResolvesServerCertUsingSni;

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;
    use crate::server::{ProducesTickets, StoresServerSessions};

    #[test]
    fn test_noserversessionstorage_drops_put() {
        let c = NoServerSessionStorage {};
        assert!(!c.put(vec![0x01], vec![0x02]));
    }

    #[test]
    fn test_noserversessionstorage_denies_gets() {
        let c = NoServerSessionStorage {};
        c.put(vec![0x01], vec![0x02]);
        assert_eq!(c.get(&[]), None);
        assert_eq!(c.get(&[0x01]), None);
        assert_eq!(c.get(&[0x02]), None);
    }

    #[test]
    fn test_noserversessionstorage_denies_takes() {
        let c = NoServerSessionStorage {};
        assert_eq!(c.take(&[]), None);
        assert_eq!(c.take(&[0x01]), None);
        assert_eq!(c.take(&[0x02]), None);
    }

    #[test]
    fn test_neverproducestickets_does_nothing() {
        let npt = NeverProducesTickets {};
        assert!(!npt.enabled());
        assert_eq!(0, npt.lifetime());
        assert_eq!(None, npt.encrypt(&[]));
        assert_eq!(None, npt.decrypt(&[]));
    }
}
