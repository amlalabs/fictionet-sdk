//! What a resolver remembers between questions: RRsets, negative answers,
//! and failures, each until its TTL runs out.

use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use fictionet::stdlib::protocols::dns::EdeCode;
use fictionet::stdlib::protocols::dns::dnssec::Validation;
use fictionet::stdlib::protocols::dns::rr::{DNSClass, LowerName, Record, RecordSet, RecordType};
use fictionet::stdlib::protocols::dns::serialize::binary::BinEncodable;
use fictionet::time::Instant;

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
        /// Whether the queries that failed had CD set, as in
        /// [`Offer::Failure`].
        cd: bool,
        /// When it stops being served.
        until: Instant,
        /// How long it is served: [`Limits::failure_ttl`], or twice as
        /// long as the failure before it for a failure that persists.
        lasts: Duration,
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

    /// The octets of the records the entry holds, by [`octets`].
    fn bytes(&self) -> usize {
        match self {
            Entry::Positive { set, proof, .. } => {
                octets(set) + proof.iter().map(octets).sum::<usize>()
            }
            Entry::Negative { soa, denial, .. } => {
                octets(soa) + denial.iter().map(octets).sum::<usize>()
            }
            Entry::Failure { .. } => 0,
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
        /// Whether the queries that failed had CD set. A server that
        /// validates may fail a query without CD that it answers with CD
        /// (RFC 4035 §3.2.2), so its error replies to queries without CD
        /// say nothing of the same question with CD.
        cd: bool,
        /// How long the failure before it lasted, when the resolution
        /// began while that one persisted ([`Cache::persisting`]).
        follows: Option<Duration>,
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
    /// The most the cache holds at once: entries, each NSEC zone, and
    /// each NSEC RRset count one.
    pub max_entries: usize,
    /// The most octets the cache holds at once: the records of every
    /// entry, of what an entry was laid over, of the records that support
    /// it, and of every NSEC zone, each as a message carries it with its
    /// owner written out uncompressed.
    pub max_bytes: usize,
}

/// The longest a failure that persists is kept (RFC 9520 §3.2: up to 5
/// minutes), unless [`Limits::failure_ttl`] is longer.
const MAX_FAILURE_TTL: Duration = Duration::from_secs(300);

/// The validated NSEC records of one zone, by owner in canonical order.
#[derive(Clone, Debug)]
struct SecureNsec {
    soa: RecordSet,
    soa_expires: Instant,
    /// The octets of `soa`.
    soa_bytes: usize,
    sets: BTreeMap<LowerName, Nsec>,
}

/// A validated NSEC RRset and when it stops proving anything.
#[derive(Clone, Debug)]
pub(super) struct Nsec {
    set: RecordSet,
    expires: Instant,
    /// The octets of `set`.
    bytes: usize,
}

impl Borrow<RecordSet> for Nsec {
    fn borrow(&self) -> &RecordSet {
        &self.set
    }
}

/// The validated NSEC records of the zone [`Cache::secure_nsec`] found,
/// borrowed from the cache. Nothing is copied until an answer picks the
/// records it carries.
pub(super) struct ZoneNsecs<'a> {
    /// The zone's apex.
    pub(super) zone: &'a LowerName,
    nsec: &'a SecureNsec,
    now: Instant,
}

impl<'a> ZoneNsecs<'a> {
    /// The zone's SOA RRset, and the TTL it has left.
    pub(super) fn soa(&self) -> (&'a RecordSet, u32) {
        (&self.nsec.soa, ttl_left(self.nsec.soa_expires, self.now))
    }

    /// The NSEC RRsets still live, by owner in canonical order.
    pub(super) fn live(&self) -> impl Iterator<Item = &'a Nsec> + Clone + use<'a> {
        let now = self.now;
        self.nsec
            .sets
            .values()
            .filter(move |nsec| now < nsec.expires)
    }

    /// The TTL `nsec`, one of [`live`](ZoneNsecs::live), has left.
    pub(super) fn ttl_left(&self, nsec: &Nsec) -> u32 {
        ttl_left(nsec.expires, self.now)
    }
}

/// A stored entry, with what it was laid over.
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
    /// The octets of all three.
    bytes: usize,
}

impl Stored {
    fn new(entry: Entry, under: Option<Entry>, glue: Option<Entry>) -> Stored {
        let bytes = [Some(&entry), under.as_ref(), glue.as_ref()]
            .into_iter()
            .flatten()
            .map(Entry::bytes)
            .sum();
        Stored {
            entry,
            under,
            glue,
            bytes,
        }
    }

    /// When it is past any use at all: expired, past the stale window,
    /// and for a failure, past the time a failure after it would count as
    /// persisting, and the same for what it was laid over.
    fn useless_at(&self, stale: Duration) -> Instant {
        let persists = match self.entry {
            Entry::Failure { until, lasts, .. } => until + lasts,
            _ => self.entry.expires(),
        };
        let last = [self.under.as_ref(), self.glue.as_ref()]
            .into_iter()
            .flatten()
            .map(Entry::expires)
            .fold(persists, Instant::max);
        last + stale
    }
}

/// Something the cache holds, in [`Cache::drops`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Slot {
    /// The entry at a key.
    Entry(Key),
    /// An NSEC zone, by apex, with every RRset it holds.
    Zone(LowerName),
    /// One NSEC RRset: its zone's apex and its owner.
    Nsec(LowerName, LowerName),
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
///   So does an RRset with the records that support it, such as a
///   wildcard answer's NSEC records, whose TTLs are never raised
///   (RFC 2181 §8).
/// - A Secure RRset lives no longer than the RRSIGs that verified it
///   (RFC 4035 §5.3.3).
/// - A failure lives [`Limits::failure_ttl`], and so does data that
///   validated Bogus or Indeterminate. A failure that persists lives
///   longer each time, as RFC 9520 §3.2 asks: one whose
///   [`Offer::Failure`] says how long the failure before it lasted
///   (`follows`) lives twice as long, up to 5 minutes or
///   [`Limits::failure_ttl`], whichever is longer. The resolution reads
///   that with [`persisting`](Cache::persisting) when it begins, since
///   the failure before may end while it runs.
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
///
/// It holds at most [`Limits::max_entries`] things and
/// [`Limits::max_bytes`] octets. Past either, what is soonest of no use
/// goes first: data past any use, then live data that expires first.
/// Data past any use is dropped as time passes, whether or not anything
/// new arrives ([`expire`](Cache::expire)).
#[derive(Clone, Debug)]
pub struct Cache {
    limits: Limits,
    entries: BTreeMap<Key, Stored>,
    /// Validated NSEC records by zone, for synthesizing negative answers
    /// (RFC 8198).
    nsec: BTreeMap<LowerName, SecureNsec>,
    /// Everything held, each entry, NSEC zone, and NSEC RRset once, by
    /// when it is past any use, soonest first.
    drops: BTreeSet<(Instant, Slot)>,
    /// The octets of everything held.
    bytes: usize,
}

impl Cache {
    /// An empty cache.
    pub fn new(limits: Limits) -> Cache {
        Cache {
            limits,
            entries: BTreeMap::new(),
            nsec: BTreeMap::new(),
            drops: BTreeSet::new(),
            bytes: 0,
        }
    }

    /// Forgets everything, as a resolver does when its session changes:
    /// nothing learned before is served again.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.nsec.clear();
        self.drops.clear();
        self.bytes = 0;
    }

    /// Drops everything past any use at `now`: entries expired, past the
    /// stale window, and for a failure, past the time a failure after it
    /// would count as persisting; NSEC records expired, and NSEC zones
    /// whose SOA expired or that hold no live records. Nothing dropped
    /// could serve a read at `now` or later.
    pub fn expire(&mut self, now: Instant) {
        while let Some((at, _)) = self.drops.first()
            && *at <= now
        {
            self.drop_first();
        }
    }

    /// Drops what is soonest of no use until the cache is within its
    /// limits.
    fn fit(&mut self) {
        while self.drops.len() > self.limits.max_entries || self.bytes > self.limits.max_bytes {
            self.drop_first();
        }
    }

    /// Drops what is soonest of no use.
    fn drop_first(&mut self) {
        let Some((_, slot)) = self.drops.first().cloned() else {
            return;
        };
        match slot {
            Slot::Entry(key) => {
                self.take(&key);
            }
            Slot::Zone(zone) => self.drop_zone(&zone),
            Slot::Nsec(zone, owner) => self.drop_nsec(&zone, &owner),
        }
    }

    /// Stores `stored` at `key`, in place of what was there.
    fn put(&mut self, key: Key, stored: Stored) {
        self.take(&key);
        self.bytes += stored.bytes;
        self.drops.insert((
            stored.useless_at(self.limits.stale),
            Slot::Entry(key.clone()),
        ));
        self.entries.insert(key, stored);
    }

    /// Removes what is stored at `key`.
    fn take(&mut self, key: &Key) -> Option<Stored> {
        let stored = self.entries.remove(key)?;
        self.bytes -= stored.bytes;
        self.drops.remove(&(
            stored.useless_at(self.limits.stale),
            Slot::Entry(key.clone()),
        ));
        Some(stored)
    }

    /// Removes the NSEC zone at `apex`, with every RRset it holds.
    fn drop_zone(&mut self, apex: &LowerName) {
        let Some(zone) = self.nsec.remove(apex) else {
            return;
        };
        self.bytes -= zone.soa_bytes;
        self.drops
            .remove(&(zone.soa_expires, Slot::Zone(apex.clone())));
        for (owner, nsec) in zone.sets {
            self.bytes -= nsec.bytes;
            self.drops
                .remove(&(nsec.expires, Slot::Nsec(apex.clone(), owner)));
        }
    }

    /// Removes the NSEC RRset at `owner` in the zone at `apex`, and the
    /// zone when that leaves it no records.
    fn drop_nsec(&mut self, apex: &LowerName, owner: &LowerName) {
        let Some(zone) = self.nsec.get_mut(apex) else {
            return;
        };
        let Some(nsec) = zone.sets.remove(owner) else {
            return;
        };
        let empty = zone.sets.is_empty();
        self.bytes -= nsec.bytes;
        self.drops
            .remove(&(nsec.expires, Slot::Nsec(apex.clone(), owner.clone())));
        if empty {
            self.drop_zone(apex);
        }
    }

    /// Offers `offer` at `now`, under the rules of [`Cache`].
    pub fn insert(&mut self, now: Instant, offer: Offer) {
        self.expire(now);
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
        if matches!(
            entry,
            Entry::Negative {
                kind: Negative::NxDomain,
                ..
            }
        ) && self.shows_exists(&key, entry.rank(), now)
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
            let stored = Stored::new(entry.clone(), None, glue(self, &asked));
            self.put(asked, stored);
        }
        let glue = glue(self, &key);
        self.put(key, Stored::new(entry, under, glue));
        self.fit();
    }

    /// How long the failure cached for `key` lasts, when a resolution of
    /// `key` that begins at `now` finds it persisting: it is served still,
    /// or ended less than its own length ago. A failure that persists is
    /// cached twice as long as the one before it, up to 5 minutes, unless
    /// [`Limits::failure_ttl`] is longer (RFC 9520 §3.2). The resolution
    /// that fails again may take longer than that, as one waiting on
    /// servers that never reply does, so this is read when it begins and
    /// offered with its failure ([`Offer::Failure`]).
    pub fn persisting(&self, key: &Key, now: Instant) -> Option<Duration> {
        match self.stored(key).map(|stored| &stored.entry) {
            Some(Entry::Failure { until, lasts, .. }) if now < *until + *lasts => Some(*lasts),
            _ => None,
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

    /// What is stored for `key`.
    fn stored(&self, key: &Key) -> Option<&Stored> {
        self.entries.get(key)
    }

    /// An entry for `key` that expired at most [`Limits::stale`] before
    /// `now`, or is still live, for serving stale (RFC 8767 §4). Failures
    /// are never stale data.
    pub fn stale(&self, key: &Key, now: Instant) -> Option<&Entry> {
        self.stored_data(key)
            .filter(|entry| now < entry.expires() + self.limits.stale)
    }

    /// The data stored for `key`, live or not: the
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
    /// A Secure RRset then lives no longer than `secure_until`, when the
    /// RRSIGs that proved it stop making it Secure: the first of them
    /// expires, or the smallest own TTL or Original TTL among them runs
    /// out, counted from when the TTLs of the data that was checked were
    /// current (RFC 4035 §5.3.3). RRSIGs that did not prove it bound
    /// nothing. A Bogus or Indeterminate RRset lives no longer than
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
        secure_until: Option<Instant>,
        now: Instant,
    ) {
        let mut keys = vec![key.clone()];
        if key.rtype == RecordType::ANY {
            keys.extend(self.nxdomain_copies(key));
        }
        for key in keys {
            self.validated_one(&key, checked, result, secure_until, now);
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
        secure_until: Option<Instant>,
        now: Instant,
    ) {
        // Taken out and put back, so that a shorter life is indexed.
        let Some(mut stored) = self.take(key) else {
            return;
        };
        if now < stored.entry.expires() && checked.held_by(&stored.entry) {
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
                        Validation::Secure => secure_until,
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
        self.put(key.clone(), stored);
    }

    /// Keeps `nsec`, NSEC RRsets that validated Secure with the zone's
    /// `soa`, until their TTL runs out, counted from `at`, when their TTLs
    /// were current, so that names they cover are denied without asking
    /// (RFC 8198 §5.1). Each, and the SOA, is kept no longer than the time
    /// given with it, when its RRSIGs stop making it Secure
    /// (RFC 4035 §5.3.3, RFC 8198 §5.4).
    pub fn add_secure_nsec(
        &mut self,
        soa: &RecordSet,
        soa_until: Option<Instant>,
        nsec: &[(RecordSet, Option<Instant>)],
        at: Instant,
    ) {
        let zone = LowerName::new(soa.name());
        let soa = normalized(soa);
        let capped =
            |expires: Instant, until: Option<Instant>| until.map_or(expires, |u| expires.min(u));
        let soa_expires = capped(
            at + seconds(soa.ttl()).min(self.limits.max_negative_ttl),
            soa_until,
        );
        if let Some(old) = self.nsec.get(&zone) {
            self.bytes -= old.soa_bytes;
            self.drops
                .remove(&(old.soa_expires, Slot::Zone(zone.clone())));
        }
        let soa_bytes = octets(&soa);
        self.bytes += soa_bytes;
        self.drops.insert((soa_expires, Slot::Zone(zone.clone())));
        let entry = self.nsec.entry(zone.clone()).or_insert_with(|| SecureNsec {
            soa: soa.clone(),
            soa_expires,
            soa_bytes,
            sets: BTreeMap::new(),
        });
        entry.soa = soa;
        entry.soa_expires = soa_expires;
        entry.soa_bytes = soa_bytes;
        for (set, until) in nsec {
            let set = normalized(set);
            let expires = capped(
                at + seconds(set.ttl()).min(self.limits.max_negative_ttl),
                *until,
            );
            let owner = LowerName::new(set.name());
            if let Some(old) = entry.sets.remove(&owner) {
                self.bytes -= old.bytes;
                self.drops
                    .remove(&(old.expires, Slot::Nsec(zone.clone(), owner.clone())));
            }
            let bytes = octets(&set);
            self.bytes += bytes;
            self.drops
                .insert((expires, Slot::Nsec(zone.clone(), owner.clone())));
            entry.sets.insert(
                owner,
                Nsec {
                    set,
                    expires,
                    bytes,
                },
            );
        }
        if entry.sets.is_empty() {
            self.drop_zone(&zone);
        }
        self.fit();
    }

    /// The deepest zone holding `name` with validated NSEC records live at
    /// `now`, with its SOA RRset, borrowed.
    pub(super) fn secure_nsec(&self, name: &LowerName, now: Instant) -> Option<ZoneNsecs<'_>> {
        let mut at = name.clone();
        loop {
            if let Some((zone, nsec)) = self.nsec.get_key_value(&at)
                && now < nsec.soa_expires
            {
                let found = ZoneNsecs { zone, nsec, now };
                if found.live().next().is_some() {
                    return Some(found);
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
            .filter(move |(_, stored)| now < stored.entry.expires())
            .map(|(key, stored)| (key, &stored.entry))
    }

    fn live(&self, key: &Key, now: Instant) -> Option<&Entry> {
        self.entries
            .get(key)
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
    /// at most `rank`, with its copies under the types it answered. A copy
    /// is dropped on its own terms: a later NXDOMAIN of another type
    /// replaces the entry under ANY with a shorter one, and the copy of
    /// the first outlives it.
    fn exists(&mut self, key: &Key, rank: Rank, now: Instant) {
        let mut at = key.name.clone();
        loop {
            let nxdomain = Key::new(at.clone(), RecordType::ANY, key.class);
            let mut kept = self.nxdomain_copies(&nxdomain);
            kept.push(nxdomain);
            for key in kept {
                if self
                    .live(&key, now)
                    .is_some_and(|entry| entry.rank() <= rank)
                {
                    self.take(&key);
                }
            }
            if at.is_root() {
                return;
            }
            at = at.base_name();
        }
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
                let proof: Vec<RecordSet> = proof.iter().map(normalized).collect();
                // The proof goes out with the RRset, at the TTL left on
                // it, so the entry lasts no longer than the proof's own
                // TTL, which is never raised (RFC 2181 §8).
                let ttl = std::iter::once(&set)
                    .chain(&proof)
                    .map(|set| seconds(set.ttl()))
                    .fold(self.limits.max_ttl, Duration::min);
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
            Offer::Failure {
                key,
                why,
                cd,
                follows,
            } => {
                let first = self.limits.failure_ttl;
                let lasts = match follows {
                    Some(lasts) => (lasts * 2).min(MAX_FAILURE_TTL.max(first)),
                    None => first,
                };
                let until = now + lasts;
                let entry = Entry::Failure {
                    why,
                    cd,
                    until,
                    lasts,
                };
                Some((key, entry))
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
pub(super) fn seconds(ttl: u32) -> Duration {
    if ttl & 0x8000_0000 != 0 {
        Duration::ZERO
    } else {
        Duration::from_secs(u64::from(ttl))
    }
}

/// The octets of `set`, as the cache counts them against
/// [`Limits::max_bytes`]: every record and RRSIG as a message carries it,
/// its owner written out without compression. A record that cannot be
/// written counts its owner and its fixed fields (RFC 1035 §4.1.3).
fn octets(set: &RecordSet) -> usize {
    /// TYPE, CLASS, TTL, and RDLENGTH.
    const FIXED: usize = 10;
    set.records_without_rrsigs()
        .chain(set.rrsigs())
        .map(|record| {
            record
                .to_bytes()
                .map_or(record.name.len() + FIXED, |bytes| bytes.len())
        })
        .sum()
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

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::protocols::dns::rr::rdata::A;
    use fictionet::stdlib::protocols::dns::rr::{Name, RData};

    fn limits(max_entries: usize) -> Limits {
        Limits {
            max_ttl: Duration::from_secs(100),
            max_negative_ttl: Duration::from_secs(100),
            failure_ttl: Duration::from_secs(1),
            stale: Duration::from_secs(100),
            max_entries,
            max_bytes: usize::MAX,
        }
    }

    fn at(seconds: u64) -> Instant {
        Instant::from_since_start(Duration::from_secs(seconds))
    }

    /// An A RRset at `owner` with one address, its TTL `ttl`.
    fn address(owner: &str, ttl: u32) -> Offer {
        let name = Name::from_ascii(owner).unwrap();
        let mut set = RecordSet::with_ttl(name.clone(), RecordType::A, ttl);
        set.insert(
            Record::from_rdata(name, ttl, RData::A(A::new(192, 0, 2, 1))),
            0,
        );
        Offer::Positive {
            set,
            rank: Rank::AuthAnswer,
            validation: Validation::NotPerformed,
            proof: Vec::new(),
            truncated: false,
        }
    }

    /// An NSEC RRset at `owner` with one record.
    fn nsec(owner: &str) -> RecordSet {
        use fictionet::stdlib::protocols::dns::dnssec::rdata::{DNSSECRData, NSEC};
        let name = Name::from_ascii(owner).unwrap();
        let next = Name::from_ascii(format!("next.{owner}")).unwrap();
        let rdata = RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(next, [RecordType::A])));
        let mut set = RecordSet::with_ttl(name.clone(), RecordType::NSEC, 100);
        set.insert(Record::from_rdata(name, 100, rdata), 0);
        set
    }

    #[test]
    fn expired_entries_are_reclaimed_though_the_cache_stops_growing() {
        let mut cache = Cache::new(limits(usize::MAX));
        for index in 0..10 {
            cache.insert(at(0), address(&format!("host{index}.example."), 1));
        }
        // One more entry long after the first ten expired and left the
        // stale window: they are gone, though the cache did not grow.
        cache.insert(at(200), address("late.example.", 50));
        assert_eq!(cache.entries.len(), 1);
        assert_eq!(cache.drops.len(), 1);
        // Time alone reclaims the last one.
        cache.expire(at(400));
        assert!(cache.entries.is_empty());
        assert!(cache.drops.is_empty());
        assert_eq!(cache.bytes, 0);
    }

    #[test]
    fn expired_denial_proofs_are_reclaimed_by_any_insert() {
        let mut cache = Cache::new(limits(usize::MAX));
        let soa = RecordSet::with_ttl(Name::from_ascii("example.").unwrap(), RecordType::SOA, 100);
        cache.add_secure_nsec(&soa, Some(at(1)), &[(nsec("a.example."), None)], at(0));
        assert!(!cache.nsec.is_empty());
        cache.insert(at(2), address("host.example.", 50));
        assert!(cache.nsec.is_empty());
        assert_eq!(cache.drops.len(), 1);
    }

    #[test]
    fn nsec_records_count_against_the_entry_limit_and_the_longest_lived_stay() {
        let mut cache = Cache::new(limits(4));
        let soa = RecordSet::with_ttl(Name::from_ascii("example.").unwrap(), RecordType::SOA, 100);
        let owners: Vec<String> = (0..10).map(|index| format!("n{index}.example.")).collect();
        let records: Vec<(RecordSet, Option<Instant>)> = owners
            .iter()
            .enumerate()
            .map(|(index, owner)| (nsec(owner), Some(at(10 + index as u64))))
            .collect();
        cache.add_secure_nsec(&soa, Some(at(90)), &records, at(0));
        assert!(cache.drops.len() <= 4);
        let zone = &cache.nsec[&LowerName::new(soa.name())];
        let kept: Vec<&LowerName> = zone.sets.keys().collect();
        assert_eq!(kept.len(), 3);
        for owner in &owners[7..] {
            assert!(kept.contains(&&LowerName::new(&Name::from_ascii(owner).unwrap())));
        }
        // An entry counts against the same limit.
        cache.insert(at(0), address("host.example.", 50));
        assert!(cache.drops.len() <= 4);
        assert!(
            cache
                .get(
                    &Key::new(
                        LowerName::new(&Name::from_ascii("host.example.").unwrap()),
                        RecordType::A,
                        DNSClass::IN,
                    ),
                    at(0),
                )
                .is_some()
        );
    }

    #[test]
    fn expiry_reclaims_expired_denial_proofs_and_preserves_live_ones() {
        let mut cache = Cache::new(limits(usize::MAX));
        let set =
            |owner: &str, rtype| RecordSet::with_ttl(Name::from_ascii(owner).unwrap(), rtype, 100);
        for (zone, soa_until, proof_until) in [
            ("soa-expired.example.", at(1), at(3)),
            ("proof-expired.example.", at(3), at(1)),
            ("live.example.", at(3), at(3)),
        ] {
            cache.add_secure_nsec(
                &set(zone, RecordType::SOA),
                Some(soa_until),
                &[
                    (set(zone, RecordType::NSEC), Some(proof_until)),
                    (set(&format!("old.{zone}"), RecordType::NSEC), Some(at(1))),
                ],
                at(0),
            );
        }
        let before = cache.nsec.len();
        cache.expire(at(2));
        assert!(cache.nsec.len() < before);
        assert!(!cache.nsec.is_empty());
        for zone in cache.nsec.values() {
            assert!(zone.soa_expires > at(2));
            assert!(!zone.sets.is_empty());
            assert!(zone.sets.values().all(|nsec| nsec.expires > at(2)));
        }
        let live = LowerName::new(&Name::from_ascii("live.example.").unwrap());
        assert!(cache.secure_nsec(&live, at(2)).is_some());
        cache.expire(at(3));
        assert!(cache.nsec.is_empty());
        assert!(cache.secure_nsec(&live, at(3)).is_none());
    }
}
