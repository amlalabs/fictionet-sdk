//! What a resolver remembers between questions: RRsets, negative answers,
//! and failures, each until its TTL runs out.

use std::collections::BTreeMap;
use std::time::Duration;

use fictionet::stdlib::protocols::dns::EdeCode;
use fictionet::stdlib::protocols::dns::dnssec::Validation;
use fictionet::stdlib::protocols::dns::rr::{DNSClass, LowerName, Record, RecordSet, RecordType};
use fictionet::time::Instant;

use super::super::exchange::Generation;
use super::super::zone::negative_ttl;

/// What the cache holds an entry under: an owner name, a type, and a
/// class. Names are lowercase, so the key ignores case.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key {
    /// The owner name.
    pub name: LowerName,
    /// The type.
    pub rtype: RecordType,
    /// The class.
    pub class: DNSClass,
}

impl Key {
    /// The key of `name`, `rtype`, and `class`.
    pub fn new(name: LowerName, rtype: RecordType, class: DNSClass) -> Key {
        Key { name, rtype, class }
    }
}

/// How far cached data is trusted, lowest first (RFC 2181 §5.4.1).
///
/// Data replaces data for the same key only at equal or higher rank, so a
/// referral's glue never overwrites what an authoritative server said.
/// Data below [`Rank::NonAuthAnswer`] is used to find servers and is never
/// an answer to a client.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rank {
    /// Addresses from the additional section, such as a referral's glue.
    Glue,
    /// The authority section of a reply without AA, such as a referral's
    /// NS RRset.
    NonAuthAuthority,
    /// The answer section of a reply without AA, as a forwarder sends.
    NonAuthAnswer,
    /// The authority section of an authoritative reply.
    AuthAuthority,
    /// The answer section of an authoritative reply.
    AuthAnswer,
}

/// Which negative answer a server gave.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Negative {
    /// The name does not exist (RFC 2308 §2.1).
    NxDomain,
    /// The name exists without records of the type (RFC 2308 §2.2).
    NoData,
}

/// Why a resolution failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FailureKind {
    /// No server for the zone answered: each timed out or could not be
    /// reached (RFC 8914 §4.23).
    NoReachableAuthority,
    /// The resolution sent all the queries [`Work`](super::Work) allows.
    WorkExceeded,
    /// Servers answered, but none with data for the question: each replied
    /// SERVFAIL, REFUSED, or something that did not fit what it was asked.
    Unknown,
}

impl FailureKind {
    /// The Extended DNS Error a resolver sends with this failure
    /// (RFC 8914 §4).
    pub fn ede(self) -> EdeCode {
        match self {
            FailureKind::NoReachableAuthority | FailureKind::Unknown => {
                EdeCode::NO_REACHABLE_AUTHORITY
            }
            FailureKind::WorkExceeded => EdeCode::OTHER,
        }
    }
}

/// One cached entry.
#[derive(Clone, Debug, PartialEq)]
pub enum Entry {
    /// An RRset, with its RRSIGs.
    Positive {
        /// The RRset, owners in lowercase and every record at the RRset's
        /// TTL.
        set: RecordSet,
        /// Where it came from.
        rank: Rank,
        /// When it stops being served.
        expires: Instant,
        /// What validation established about it. An RRset not yet checked
        /// is [`Validation::NotPerformed`].
        validation: Validation,
        /// Records that support it: the NSEC or NSEC3 records that show a
        /// wildcard answer had no closer match (RFC 4035 §5.3.4), or the
        /// DNAME a CNAME was synthesized from (RFC 6672 §3.4).
        proof: Vec<RecordSet>,
    },
    /// A negative answer.
    Negative {
        /// Which negative.
        kind: Negative,
        /// The zone's SOA RRset, at the negative TTL.
        soa: RecordSet,
        /// Where it came from: an authoritative server's answer, or a
        /// forwarder's.
        rank: Rank,
        /// The NSEC or NSEC3 records that prove it, with their RRSIGs.
        denial: Vec<RecordSet>,
        /// When it stops being served.
        expires: Instant,
        /// What validation established about it.
        validation: Validation,
    },
    /// A resolution that failed. It answers SERVFAIL until `until`, and
    /// never as a negative (RFC 9520 §3).
    Failure {
        /// Why.
        why: FailureKind,
        /// When it stops being served.
        until: Instant,
    },
}

impl Entry {
    /// When the entry stops being served.
    pub fn expires(&self) -> Instant {
        match self {
            Entry::Positive { expires, .. } | Entry::Negative { expires, .. } => *expires,
            Entry::Failure { until, .. } => *until,
        }
    }

    /// The rank the entry holds its key at. A negative answer ranks as
    /// the answer it came in. A failure is no data and ranks lowest, so
    /// any data replaces it.
    pub fn rank(&self) -> Rank {
        match self {
            Entry::Positive { rank, .. } | Entry::Negative { rank, .. } => *rank,
            Entry::Failure { .. } => Rank::Glue,
        }
    }
}

/// What a resolution offers the cache.
#[derive(Clone, Debug, PartialEq)]
pub enum Offer {
    /// An RRset.
    Positive {
        /// The RRset with its RRSIGs, as it arrived.
        set: RecordSet,
        /// Where it came from.
        rank: Rank,
        /// What validation established about it.
        validation: Validation,
        /// Records that support it, as in [`Entry::Positive`].
        proof: Vec<RecordSet>,
        /// Whether the reply had TC set.
        truncated: bool,
    },
    /// A negative answer for `key`. NXDOMAIN applies to every type at the
    /// name, so it is stored under type ANY, found again through
    /// [`Cache::nxdomain_above`], and under the type asked as well.
    Negative {
        /// What it answers.
        key: Key,
        /// Which negative.
        kind: Negative,
        /// The zone's SOA RRset from the authority section, if it had one.
        soa: Option<RecordSet>,
        /// Where it came from, as in [`Entry::Negative`].
        rank: Rank,
        /// The NSEC or NSEC3 records from the authority section.
        denial: Vec<RecordSet>,
        /// What validation established about it.
        validation: Validation,
        /// Whether the reply had TC set.
        truncated: bool,
    },
    /// A failed resolution of `key`.
    Failure {
        /// What failed.
        key: Key,
        /// Why.
        why: FailureKind,
    },
}

/// The data a validation was made over. Its result applies to an entry
/// only while the entry still holds that data: an RRset that expired and
/// was fetched again while the validation waited may hold other data,
/// which nothing has checked (RFC 4035 §4.3).
#[derive(Clone, Debug, PartialEq)]
pub enum Checked {
    /// An RRset, with its RRSIGs.
    Rrset(RecordSet),
    /// A negative answer's SOA RRset and the denial records that prove
    /// it, each with its RRSIGs.
    Denial {
        /// The zone's SOA RRset, if the answer had one.
        soa: Option<RecordSet>,
        /// The NSEC or NSEC3 records.
        denial: Vec<RecordSet>,
    },
}

impl Checked {
    /// Whether `entry` holds this data, whatever the TTLs and the case of
    /// the owners.
    pub fn held_by(&self, entry: &Entry) -> bool {
        match (self, entry) {
            (Checked::Rrset(checked), Entry::Positive { set, .. }) => same_rrset(checked, set),
            (
                Checked::Denial {
                    soa: checked_soa,
                    denial: checked_denial,
                },
                Entry::Negative { soa, denial, .. },
            ) => {
                checked_soa
                    .as_ref()
                    .is_some_and(|checked| same_rrset(checked, soa))
                    && same_rrsets(checked_denial, denial)
            }
            _ => false,
        }
    }

    /// Whether `other` is the same data, whatever the TTLs and the case of
    /// the owners.
    pub fn same(&self, other: &Checked) -> bool {
        match (self, other) {
            (Checked::Rrset(a), Checked::Rrset(b)) => same_rrset(a, b),
            (
                Checked::Denial {
                    soa: a_soa,
                    denial: a_denial,
                },
                Checked::Denial {
                    soa: b_soa,
                    denial: b_denial,
                },
            ) => {
                let soa = match (a_soa, b_soa) {
                    (Some(a), Some(b)) => same_rrset(a, b),
                    (None, None) => true,
                    _ => false,
                };
                soa && same_rrsets(a_denial, b_denial)
            }
            _ => false,
        }
    }
}

/// Whether `a` and `b` are the same RRset with the same RRSIGs, whatever
/// the TTLs, the order of the records, and the case of the owners.
pub(super) fn same_rrset(a: &RecordSet, b: &RecordSet) -> bool {
    let same = |a: Vec<&Record>, b: Vec<&Record>| {
        a.iter().all(|x| b.iter().any(|y| x.data == y.data))
            && b.iter().all(|y| a.iter().any(|x| x.data == y.data))
    };
    LowerName::new(a.name()) == LowerName::new(b.name())
        && a.record_type() == b.record_type()
        && a.dns_class() == b.dns_class()
        && same(
            a.records_without_rrsigs().collect(),
            b.records_without_rrsigs().collect(),
        )
        && same(a.rrsigs().iter().collect(), b.rrsigs().iter().collect())
}

/// Whether `a` and `b` hold the same RRsets, in any order, by
/// [`same_rrset`].
pub(super) fn same_rrsets(a: &[RecordSet], b: &[RecordSet]) -> bool {
    a.iter().all(|x| b.iter().any(|y| same_rrset(x, y)))
        && b.iter().all(|y| a.iter().any(|x| same_rrset(x, y)))
}

/// The limits on what the cache keeps, from the resolver's
/// [`Config`](super::Config).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The longest any data is kept (RFC 8767 §4: at most 604800 seconds).
    pub max_ttl: Duration,
    /// The longest a negative answer is kept, below `max_ttl`.
    pub max_negative_ttl: Duration,
    /// How long a failure is kept (RFC 9520 §3.2: 1 to 300 seconds).
    pub failure_ttl: Duration,
    /// How long expired data is kept past its TTL for serving stale
    /// (RFC 8767 §4), or zero to keep none.
    pub stale: Duration,
}

/// The validated NSEC records of one zone.
#[derive(Clone, Debug)]
struct SecureNsec {
    soa: RecordSet,
    soa_expires: Instant,
    sets: BTreeMap<LowerName, (RecordSet, Instant)>,
}

/// A stored entry and the generation that wrote it.
#[derive(Clone, Debug)]
struct Stored {
    entry: Entry,
    /// The expired data a failure was laid over, which may still be
    /// served stale (RFC 8767 §4).
    under: Option<Entry>,
    /// The live data below [`Rank::NonAuthAnswer`], such as glue or a
    /// referral's NS RRset, that a failure or a negative answer was laid
    /// over. Neither is data about how a zone's servers are reached: a
    /// negative answer for a name server's own name says nothing of how
    /// its parent reaches it, so this still finds the zone's servers
    /// (RFC 2181 §5.4.1, RFC 1034 §5.3.3).
    glue: Option<Entry>,
    /// When the entry was stored.
    at: Instant,
    generation: Generation,
}

/// A resolver's cache, by owner name, type, and class.
///
/// The rules of RFC 1035, RFC 2181, RFC 2308, RFC 4035, RFC 8767,
/// RFC 9077, and RFC 9520, applied when data is offered:
///
/// - Data with TTL 0 is used for the answer it came in and not stored
///   (RFC 1035 §7.4). A TTL with the top bit set reads as 0 (RFC 2181 §8).
///   TTLs are capped at [`Limits::max_ttl`].
/// - An RRset whose records have different TTLs takes the lowest
///   (RFC 2181 §5.2), and duplicate records collapse to one (RFC 2181 §5).
/// - Truncated replies are not stored (RFC 2181 §9), and neither are
///   negative answers without an SOA (RFC 2308 §5).
/// - A negative answer lives min(SOA TTL, MINIMUM) (RFC 2308 §5), and no
///   longer than the NSEC or NSEC3 records that prove it (RFC 9077 §3).
/// - A Secure RRset lives no longer than the RRSIGs that verified it
///   (RFC 4035 §5.3.3).
/// - A failure lives [`Limits::failure_ttl`] (RFC 9520 §3.2), and so does
///   data that validated Bogus or Indeterminate.
/// - Data replaces a live entry for its key only at equal or higher
///   [`Rank`] (RFC 2181 §5.4.1). A failure is no data: any data replaces
///   it, and it is laid over any live entry that does not answer clients,
///   so it is cached whenever a resolution fails (RFC 9520 §3.2). A
///   failure or a negative answer laid over data below
///   [`Rank::NonAuthAnswer`] keeps that data beneath it, for finding
///   servers. Data or NODATA at a name ends a live NXDOMAIN at that name
///   or above it at no higher rank, under every type it is kept under,
///   since the name exists after all (RFC 8020 §2). An NXDOMAIN replaces
///   the entry of the type it answered, and is not kept at all when live
///   data or NODATA of higher rank, of any type, at the name or below it
///   shows the name exists.
/// - Every entry records the generation that wrote it, and a new
///   generation starts empty.
#[derive(Clone, Debug)]
pub struct Cache {
    limits: Limits,
    generation: Generation,
    entries: BTreeMap<Key, Stored>,
    /// Validated NSEC records by zone, for synthesizing negative answers
    /// (RFC 8198).
    nsec: BTreeMap<LowerName, SecureNsec>,
    /// How many entries there were after the last sweep of dead ones.
    swept: usize,
}

impl Cache {
    /// An empty cache in generation 0.
    pub fn new(limits: Limits) -> Cache {
        Cache {
            limits,
            generation: Generation(0),
            entries: BTreeMap::new(),
            nsec: BTreeMap::new(),
            swept: 0,
        }
    }

    /// The generation the cache serves.
    pub fn generation(&self) -> Generation {
        self.generation
    }

    /// Starts `generation`: nothing of the old one is served again.
    pub fn advance(&mut self, generation: Generation) {
        self.generation = generation;
        self.entries.clear();
        self.nsec.clear();
        self.swept = 0;
    }

    /// Offers `offer` at `now`, under the rules of [`Cache`].
    pub fn insert(&mut self, now: Instant, offer: Offer) {
        // An NXDOMAIN is kept under type ANY, for every type at the name,
        // and under the type it answered, whose entry it replaces.
        let asked = match &offer {
            Offer::Negative {
                key,
                kind: Negative::NxDomain,
                ..
            } if key.rtype != RecordType::ANY => Some(key.clone()),
            _ => None,
        };
        let Some((key, entry)) = self.entry_for(now, offer) else {
            return;
        };
        // Live data or NODATA of higher rank at the name, of any type, or
        // at a name below it shows the name exists, so such an NXDOMAIN
        // is not kept at all.
        if let Some(asked) = &asked
            && self.shows_exists(asked, entry.rank(), now)
        {
            return;
        }
        if let Some(old) = self.live(&key, now) {
            let kept = match entry {
                // A failure never displaces live data that answers
                // clients.
                Entry::Failure { .. } => old.rank() >= Rank::NonAuthAnswer,
                _ => entry.rank() < old.rank(),
            };
            if kept {
                return;
            }
        }
        // A failure is no data (RFC 9520 §3), so it takes away neither
        // live glue nor expired data that may still be served stale
        // (RFC 8767 §4): they are kept beside the failure. Data that
        // answers clients under a failure has expired, since it would
        // have kept the failure out while live.
        let under = match &entry {
            Entry::Failure { .. } => self
                .stale(&key, now)
                .filter(|old| old.rank() >= Rank::NonAuthAnswer)
                .cloned(),
            _ => None,
        };
        // Neither is a failure or a negative answer data about how a
        // zone's servers are reached, so live glue stays beside them.
        let glue = |cache: &Cache, key: &Key| match &entry {
            Entry::Positive { .. } => None,
            Entry::Negative { .. } | Entry::Failure { .. } => cache.glue(key, now).cloned(),
        };
        // Data at a name, or NODATA for it, shows that the name and every
        // name above it exist, so it ends an NXDOMAIN cached for any of
        // them at no higher rank, as newer data for a key replaces older.
        if matches!(
            entry,
            Entry::Positive { .. }
                | Entry::Negative {
                    kind: Negative::NoData,
                    ..
                }
        ) {
            self.exists(&key, entry.rank(), now);
        }
        if let Some(asked) = asked {
            let stored = Stored {
                entry: entry.clone(),
                under: None,
                glue: glue(self, &asked),
                at: now,
                generation: self.generation,
            };
            self.entries.insert(asked, stored);
        }
        let glue = glue(self, &key);
        self.entries.insert(
            key,
            Stored {
                entry,
                under,
                glue,
                at: now,
                generation: self.generation,
            },
        );
        if self.entries.len() >= 2 * self.swept.max(64) {
            self.sweep(now);
        }
    }

    /// The live entry for `key` at `now`, if any.
    pub fn get(&self, key: &Key, now: Instant) -> Option<&Entry> {
        self.live(key, now)
    }

    /// The live RRset for `key` at `now`, looking past a failure or a
    /// negative answer cached over it. A failed lookup takes away nothing
    /// the cache knew (RFC 9520 §3), and a negative answer for a name
    /// server's name does not take away the glue that says where the
    /// server is (RFC 2181 §5.4.1), so this is what finding servers reads.
    pub fn data(&self, key: &Key, now: Instant) -> Option<&Entry> {
        let stored = self.stored(key)?;
        [Some(&stored.entry), stored.glue.as_ref()]
            .into_iter()
            .flatten()
            .find(|entry| matches!(entry, Entry::Positive { .. }) && now < entry.expires())
    }

    /// The live glue stored for `key` at `now`: an RRset below
    /// [`Rank::NonAuthAnswer`], as the entry or beneath it.
    fn glue(&self, key: &Key, now: Instant) -> Option<&Entry> {
        let stored = self.stored(key)?;
        [Some(&stored.entry), stored.glue.as_ref()]
            .into_iter()
            .flatten()
            .find(|entry| {
                matches!(entry, Entry::Positive { rank, .. } if *rank < Rank::NonAuthAnswer)
                    && now < entry.expires()
            })
    }

    /// What is stored for `key` in this generation.
    fn stored(&self, key: &Key) -> Option<&Stored> {
        self.entries
            .get(key)
            .filter(|stored| stored.generation == self.generation)
    }

    /// An entry for `key` that expired at most [`Limits::stale`] before
    /// `now`, or is still live, for serving stale (RFC 8767 §4). Failures
    /// are never stale data.
    pub fn stale(&self, key: &Key, now: Instant) -> Option<&Entry> {
        self.stored_data(key)
            .filter(|entry| now < entry.expires() + self.limits.stale)
    }

    /// The data stored for `key` in this generation, live or not: the
    /// entry, or what a failure was laid over.
    fn stored_data(&self, key: &Key) -> Option<&Entry> {
        let stored = self.stored(key)?;
        match &stored.entry {
            Entry::Failure { .. } => stored.under.as_ref(),
            entry => Some(entry),
        }
    }

    /// A live NXDOMAIN cached for `name`, or a Secure one cached for a
    /// name above it, with the name it is cached at: nothing exists below
    /// a name that does not exist (RFC 8020 §2).
    ///
    /// Only a Secure NXDOMAIN denies the names below it, as Unbound's
    /// `harden-below-nxdomain` uses it. An NXDOMAIN that did not validate,
    /// or that an NSEC3 opt-out span only covers, may come from a server
    /// that denies empty non-terminals or the apex of a zone it does not
    /// know is delegated, and the names below it may well exist.
    pub fn nxdomain_above(
        &self,
        name: &LowerName,
        class: DNSClass,
        now: Instant,
    ) -> Option<(&LowerName, &Entry)> {
        let mut at = name.clone();
        loop {
            let key = Key::new(at.clone(), RecordType::ANY, class);
            if let Some(
                entry @ Entry::Negative {
                    kind: Negative::NxDomain,
                    validation,
                    ..
                },
            ) = self.live(&key, now)
                && (at == *name || *validation == Validation::Secure)
            {
                let (key, _) = self.entries.get_key_value(&key)?;
                return Some((&key.name, entry));
            }
            if at.is_root() {
                return None;
            }
            at = at.base_name();
        }
    }

    /// Records what validation established about `checked`, the data the
    /// validation was made over, at `key`. The result applies only while
    /// the live entry there still holds that data: data stored at the key
    /// meanwhile has not been checked, and keeps what it had.
    ///
    /// A Secure RRset then lives no longer than `signatures_expire`, the
    /// first expiration of the RRSIGs that proved it, nor longer than
    /// `ttl`, the smallest own TTL or Original TTL among those RRSIGs, from
    /// when it was stored (RFC 4035 §5.3.3). RRSIGs that did not prove it
    /// bound nothing. A Bogus or Indeterminate RRset lives no longer than
    /// [`Limits::failure_ttl`]: the result is a failure, so it is answered
    /// as one for that long and then fetched and validated again
    /// (RFC 9520 §3.2, RFC 4035 §4.7). The result of an NXDOMAIN,
    /// kept under type ANY, holds for its copies under the types it
    /// answered too.
    pub fn validated(
        &mut self,
        key: &Key,
        checked: &Checked,
        result: Validation,
        signatures_expire: Option<Instant>,
        ttl: Option<u32>,
        now: Instant,
    ) {
        let mut keys = vec![key.clone()];
        if key.rtype == RecordType::ANY {
            keys.extend(self.nxdomain_copies(key));
        }
        for key in keys {
            self.validated_one(&key, checked, result, signatures_expire, ttl, now);
        }
    }

    /// The keys of the copies of the NXDOMAIN kept under `key`, of type
    /// ANY, under the types it answered at the same name.
    fn nxdomain_copies(&self, key: &Key) -> Vec<Key> {
        self.entries
            .range(Key::new(key.name.clone(), RecordType::from(0), key.class)..)
            .take_while(|(other, _)| other.name == key.name)
            .filter(|(other, stored)| {
                other.class == key.class
                    && other.rtype != RecordType::ANY
                    && matches!(
                        stored.entry,
                        Entry::Negative {
                            kind: Negative::NxDomain,
                            ..
                        }
                    )
            })
            .map(|(other, _)| other.clone())
            .collect()
    }

    /// [`validated`](Cache::validated) for the entry at `key` alone.
    fn validated_one(
        &mut self,
        key: &Key,
        checked: &Checked,
        result: Validation,
        signatures_expire: Option<Instant>,
        ttl: Option<u32>,
        now: Instant,
    ) {
        let generation = self.generation;
        let Some(stored) = self.entries.get_mut(key) else {
            return;
        };
        if stored.generation != generation
            || now >= stored.entry.expires()
            || !checked.held_by(&stored.entry)
        {
            return;
        }
        let ttl = ttl.map(|ttl| stored.at + seconds(ttl));
        let signatures_expire = match (signatures_expire, ttl) {
            (Some(expire), Some(ttl)) => Some(expire.min(ttl)),
            (expire, ttl) => expire.or(ttl),
        };
        match &mut stored.entry {
            Entry::Positive {
                validation,
                expires,
                ..
            }
            | Entry::Negative {
                validation,
                expires,
                ..
            } => {
                *validation = result;
                let cap = match result {
                    Validation::Secure => signatures_expire,
                    Validation::Bogus(_) | Validation::Indeterminate => {
                        Some(now + self.limits.failure_ttl)
                    }
                    Validation::Insecure(_) | Validation::NotPerformed => None,
                };
                if let Some(cap) = cap {
                    *expires = (*expires).min(cap);
                }
            }
            Entry::Failure { .. } => {}
        }
    }

    /// Keeps `nsec`, NSEC RRsets that validated Secure with the zone's
    /// `soa`, until their TTL runs out, so that names they cover are denied
    /// without asking (RFC 8198 §5.1). Each, and the SOA, is kept no
    /// longer than the time given with it, when its RRSIGs stop making it
    /// Secure (RFC 4035 §5.3.3, RFC 8198 §5.4).
    pub fn add_secure_nsec(
        &mut self,
        soa: &RecordSet,
        soa_until: Option<Instant>,
        nsec: &[(RecordSet, Option<Instant>)],
        now: Instant,
    ) {
        let zone = LowerName::new(soa.name());
        let soa = normalized(soa);
        let capped =
            |expires: Instant, until: Option<Instant>| until.map_or(expires, |u| expires.min(u));
        let soa_expires = capped(
            now + seconds(soa.ttl()).min(self.limits.max_negative_ttl),
            soa_until,
        );
        let entry = self.nsec.entry(zone).or_insert_with(|| SecureNsec {
            soa: soa.clone(),
            soa_expires,
            sets: BTreeMap::new(),
        });
        entry.soa = soa;
        entry.soa_expires = soa_expires;
        for (set, until) in nsec {
            let set = normalized(set);
            let expires = capped(
                now + seconds(set.ttl()).min(self.limits.max_negative_ttl),
                *until,
            );
            entry
                .sets
                .insert(LowerName::new(set.name()), (set, expires));
        }
    }

    /// The deepest zone holding `name` with validated NSEC records live at
    /// `now`: its apex, its SOA RRset with the TTL left, and those records
    /// with theirs.
    pub fn secure_nsec(
        &self,
        name: &LowerName,
        now: Instant,
    ) -> Option<(&LowerName, RecordSet, Vec<RecordSet>)> {
        let mut at = name.clone();
        loop {
            if let Some((zone, entry)) = self.nsec.get_key_value(&at)
                && now < entry.soa_expires
            {
                let sets: Vec<RecordSet> = entry
                    .sets
                    .values()
                    .filter(|(_, expires)| now < *expires)
                    .map(|(set, expires)| {
                        let mut set = set.clone();
                        set.set_ttl(ttl_left(*expires, now));
                        set
                    })
                    .collect();
                if !sets.is_empty() {
                    let mut soa = entry.soa.clone();
                    soa.set_ttl(ttl_left(entry.soa_expires, now));
                    return Some((zone, soa, sets));
                }
            }
            if at.is_root() {
                return None;
            }
            at = at.base_name();
        }
    }

    /// How long a negative answer with `soa` and `denial` lives:
    /// min(SOA TTL, MINIMUM) (RFC 2308 §5), no longer than the denial
    /// records (RFC 9077 §3), and within the limits.
    pub fn negative_ttl(&self, soa: &RecordSet, denial: &[RecordSet]) -> Duration {
        denial
            .iter()
            .map(|set| seconds(set.ttl()))
            .fold(seconds(negative_ttl(soa)), Duration::min)
            .min(self.limits.max_ttl)
            .min(self.limits.max_negative_ttl)
    }

    /// Every live entry at `now`, in key order.
    pub fn entries(&self, now: Instant) -> impl Iterator<Item = (&Key, &Entry)> {
        self.entries
            .iter()
            .filter(move |(_, stored)| {
                stored.generation == self.generation && now < stored.entry.expires()
            })
            .map(|(key, stored)| (key, &stored.entry))
    }

    fn live(&self, key: &Key, now: Instant) -> Option<&Entry> {
        self.entries
            .get(key)
            .filter(|stored| stored.generation == self.generation)
            .map(|stored| &stored.entry)
            .filter(|entry| now < entry.expires())
    }

    /// Whether live data or NODATA ranked above `rank`, at `key`'s name or
    /// below it in `key`'s class, shows that the name exists. Names below
    /// a name follow it in the key order.
    fn shows_exists(&self, key: &Key, rank: Rank, now: Instant) -> bool {
        self.entries
            .range(Key::new(key.name.clone(), RecordType::from(0), key.class)..)
            .take_while(|(other, _)| key.name.zone_of(&other.name))
            .any(|(other, stored)| {
                other.class == key.class
                    && stored.generation == self.generation
                    && now < stored.entry.expires()
                    && stored.entry.rank() > rank
                    && matches!(
                        stored.entry,
                        Entry::Positive { .. }
                            | Entry::Negative {
                                kind: Negative::NoData,
                                ..
                            }
                    )
            })
    }

    /// Drops each live NXDOMAIN at `key`'s name or above it whose rank is
    /// at most `rank`, with its copies under the types it answered.
    fn exists(&mut self, key: &Key, rank: Rank, now: Instant) {
        let mut at = key.name.clone();
        loop {
            let nxdomain = Key::new(at.clone(), RecordType::ANY, key.class);
            if let Some(
                entry @ Entry::Negative {
                    kind: Negative::NxDomain,
                    ..
                },
            ) = self.live(&nxdomain, now)
                && entry.rank() <= rank
            {
                for copy in self.nxdomain_copies(&nxdomain) {
                    self.entries.remove(&copy);
                }
                self.entries.remove(&nxdomain);
            }
            if at.is_root() {
                return;
            }
            at = at.base_name();
        }
    }

    /// Drops entries past any use: expired, and past the stale window.
    fn sweep(&mut self, now: Instant) {
        let stale = self.limits.stale;
        let generation = self.generation;
        self.entries.retain(|_, stored| {
            let last = [stored.under.as_ref(), stored.glue.as_ref()]
                .into_iter()
                .flatten()
                .map(Entry::expires)
                .fold(stored.entry.expires(), Instant::max);
            stored.generation == generation && now < last + stale
        });
        self.swept = self.entries.len();
    }

    /// The entry an offer makes at `now`, or `None` when it may not be
    /// stored.
    fn entry_for(&self, now: Instant, offer: Offer) -> Option<(Key, Entry)> {
        match offer {
            Offer::Positive {
                set,
                rank,
                validation,
                proof,
                truncated,
            } => {
                let set = normalized(&set);
                let ttl = seconds(set.ttl()).min(self.limits.max_ttl);
                if truncated || ttl.is_zero() {
                    return None;
                }
                let key = Key::new(
                    LowerName::new(set.name()),
                    set.record_type(),
                    set.dns_class(),
                );
                let entry = Entry::Positive {
                    set,
                    rank,
                    expires: now + ttl,
                    validation,
                    proof,
                };
                Some((key, entry))
            }
            Offer::Negative {
                key,
                kind,
                soa,
                rank,
                denial,
                validation,
                truncated,
            } => {
                let soa = normalized(&soa?);
                let ttl = self.negative_ttl(&soa, &denial);
                if truncated || ttl.is_zero() {
                    return None;
                }
                let mut soa = soa;
                soa.set_ttl(u32::try_from(ttl.as_secs()).unwrap_or(u32::MAX));
                let denial = denial.iter().map(normalized).collect();
                let key = match kind {
                    Negative::NxDomain => Key::new(key.name, RecordType::ANY, key.class),
                    Negative::NoData => key,
                };
                let entry = Entry::Negative {
                    kind,
                    soa,
                    rank,
                    denial,
                    expires: now + ttl,
                    validation,
                };
                Some((key, entry))
            }
            Offer::Failure { key, why } => {
                let until = now + self.limits.failure_ttl;
                Some((key, Entry::Failure { why, until }))
            }
        }
    }
}

/// The TTL a client sees at `now` for data that expires at `expires`. The
/// count is on a clock of whole seconds, as Unbound keeps it: data shows
/// its full TTL for the rest of the second it arrived in, and every answer
/// of one second, fresh or cached, shows the same TTL.
pub(super) fn ttl_left(expires: Instant, now: Instant) -> u32 {
    let left = expires
        .since_start()
        .as_secs()
        .saturating_sub(now.since_start().as_secs());
    u32::try_from(left).unwrap_or(u32::MAX)
}

/// A TTL as a duration. A TTL with the top bit set reads as 0
/// (RFC 2181 §8).
fn seconds(ttl: u32) -> Duration {
    if ttl & 0x8000_0000 != 0 {
        Duration::ZERO
    } else {
        Duration::from_secs(u64::from(ttl))
    }
}

/// `set` with its owner and every record's owner in lowercase, every
/// record at the lowest TTL among them (RFC 2181 §5.2), duplicates
/// collapsed (RFC 2181 §5), and its RRSIGs kept. The RRSIGs are an RRset
/// of their own and do not shorten the data: each keeps its own TTL, at
/// most the data's, for validation to bound a Secure RRset by the RRSIG
/// that verified it (RFC 4035 §5.3.3).
pub(super) fn normalized(set: &RecordSet) -> RecordSet {
    let owner = set.name().to_lowercase();
    let readable = |ttl: u32| if ttl & 0x8000_0000 != 0 { 0 } else { ttl };
    let ttl = set
        .records_without_rrsigs()
        .map(|record| record.ttl)
        .chain(std::iter::once(set.ttl()))
        .map(readable)
        .min()
        .unwrap_or(0);
    let mut out = RecordSet::with_ttl(owner.clone(), set.record_type(), ttl);
    out.set_dns_class(set.dns_class());
    let mut records = Vec::new();
    for record in set.records_without_rrsigs() {
        if records.iter().all(|kept: &Record| kept.data != record.data) {
            let mut record = record.clone();
            record.name = owner.clone();
            record.ttl = ttl;
            records.push(record);
        }
    }
    out.set_records(records);
    for rrsig in set.rrsigs() {
        let mut rrsig = rrsig.clone();
        rrsig.name = owner.clone();
        rrsig.ttl = readable(rrsig.ttl).min(ttl);
        out.insert_rrsig(rrsig);
    }
    out
}
