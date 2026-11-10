//! What a resolver remembers between questions: RRsets, negative answers,
//! and failures, each until its TTL runs out.

use std::borrow::Borrow;
use std::ops::Bound;
use std::time::Duration;

use fictionet::stdlib::layer::{BoundedMap, Budget, Charge};
use fictionet::stdlib::protocols::dns::EdeCode;
use fictionet::stdlib::protocols::dns::dnssec::Validation;
use fictionet::stdlib::protocols::dns::rr::{
    DNSClass, LowerName, Name, Record, RecordSet, RecordType,
};
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

    /// The heap the entry holds past its own struct, by [`rrset_heap`].
    fn heap(&self) -> usize {
        match self {
            Entry::Positive { set, proof, .. } => rrset_heap(set) + rrsets_heap(proof),
            Entry::Negative { soa, denial, .. } => rrset_heap(soa) + rrsets_heap(denial),
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
/// [`Config`](super::Config). The memory it holds is bounded by the
/// [`Budget`] it is made with ([`Cache::new`]).
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
    /// each NSEC RRset count one. The budget pays for the room to hold
    /// them all when the cache is made ([`Cache::storage`]).
    pub max_entries: usize,
}

/// The longest a failure that persists is kept (RFC 9520 §3.2: up to 5
/// minutes), unless [`Limits::failure_ttl`] is longer.
const MAX_FAILURE_TTL: Duration = Duration::from_secs(300);

/// The SOA RRset of a zone whose validated NSEC records the cache holds.
#[derive(Debug)]
struct Zone {
    soa: RecordSet,
    soa_expires: Instant,
    /// Pays for its heap, by [`Cache::add_secure_nsec`].
    _charge: Charge,
}

/// A validated NSEC RRset and when it stops proving anything.
#[derive(Debug)]
pub(super) struct Nsec {
    set: RecordSet,
    expires: Instant,
    /// Pays for its heap, by [`Cache::add_secure_nsec`].
    _charge: Charge,
}

impl Borrow<RecordSet> for Nsec {
    fn borrow(&self) -> &RecordSet {
        &self.set
    }
}

/// The validated NSEC RRsets, by their zone's apex and their owner.
type Nsecs = BoundedMap<(LowerName, LowerName), Box<Nsec>>;

/// The NSEC RRsets `nsecs` holds for the zone at `apex`, by owner in
/// canonical order.
fn zone_records<'a>(
    nsecs: &'a Nsecs,
    apex: &'a LowerName,
) -> impl Iterator<Item = (&'a (LowerName, LowerName), &'a Nsec)> + Clone + use<'a> {
    // The root sorts before every name.
    let first = (apex.clone(), LowerName::new(&Name::root()));
    nsecs
        .range((Bound::Included(first), Bound::Unbounded))
        .take_while(move |((zone, _), _)| zone == apex)
        .map(|(key, nsec)| (key, &**nsec))
}

/// The validated NSEC records of the zone [`Cache::secure_nsec`] found,
/// borrowed from the cache. Nothing is copied until an answer picks the
/// records it carries.
pub(super) struct ZoneNsecs<'a> {
    /// The zone's apex.
    pub(super) zone: &'a LowerName,
    soa: &'a Zone,
    nsecs: &'a Nsecs,
    now: Instant,
}

impl<'a> ZoneNsecs<'a> {
    /// The zone's SOA RRset, and the TTL it has left.
    pub(super) fn soa(&self) -> (&'a RecordSet, u32) {
        (&self.soa.soa, ttl_left(self.soa.soa_expires, self.now))
    }

    /// The NSEC RRsets still live, by owner in canonical order.
    pub(super) fn live(&self) -> impl Iterator<Item = &'a Nsec> + Clone + use<'a> {
        let now = self.now;
        zone_records(self.nsecs, self.zone)
            .map(|(_, nsec)| nsec)
            .filter(move |nsec| now < nsec.expires)
    }

    /// The TTL `nsec`, one of [`live`](ZoneNsecs::live), has left.
    pub(super) fn ttl_left(&self, nsec: &Nsec) -> u32 {
        ttl_left(nsec.expires, self.now)
    }
}

/// A stored entry, with what it was laid over.
#[derive(Debug)]
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
    /// Pays for its heap, by [`Cache::put`].
    _charge: Charge,
}

impl Stored {
    /// When it is past any use, by [`useless_at`].
    fn useless_at(&self, stale: Duration) -> Instant {
        useless_at(
            &self.entry,
            [self.under.as_ref(), self.glue.as_ref()],
            stale,
        )
    }
}

/// When `entry`, stored over `laid_over`, is past any use at all:
/// expired, past the stale window, and for a failure, past the time a
/// failure after it would count as persisting, and the same for what it
/// was laid over.
fn useless_at(entry: &Entry, laid_over: [Option<&Entry>; 2], stale: Duration) -> Instant {
    let persists = match entry {
        Entry::Failure { until, lasts, .. } => *until + *lasts,
        _ => entry.expires(),
    };
    let last = laid_over
        .into_iter()
        .flatten()
        .map(Entry::expires)
        .fold(persists, Instant::max);
    last + stale
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

impl Slot {
    /// The heap of the names a thing is held under, by estimate: each
    /// name's octets, once in its store's key and once in its place in
    /// [`Cache::drops`].
    fn heap(&self) -> usize {
        let names = match self {
            Slot::Entry(key) => key.name.len(),
            Slot::Zone(apex) => apex.len(),
            Slot::Nsec(apex, owner) => apex.len() + owner.len(),
        };
        2 * names
    }
}

/// A place in [`Cache::drops`]: when a thing is past any use, and which.
type Place = (Instant, Slot);

/// Puts `value` under `key` in `store`, and `place` in `drops`, which has
/// a place free: [`Cache::room`] made one, or taking the value out freed
/// it. A store holds no more than `drops` does, so it has a place too;
/// were either full, neither would keep the value.
fn hold<K: Ord + Clone, V>(
    store: &mut BoundedMap<K, V>,
    drops: &mut BoundedMap<Place, ()>,
    key: K,
    value: V,
    place: Place,
) {
    if store.insert(key.clone(), value).is_ok() && drops.insert(place, ()).is_err() {
        store.remove(&key);
    }
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
/// It holds at most [`Limits::max_entries`] things, and its memory is
/// charged to its [`Budget`]: the room for that many things when it is
/// made ([`storage`](Cache::storage)), and the heap of each thing, by
/// estimate, before it is stored. When either has no room, what is
/// soonest of no use goes first: data past any use, then live data that
/// expires first. Something that would itself go first is not stored.
/// Data past any use is dropped as time passes, whether or not anything
/// new arrives ([`expire`](Cache::expire)).
#[derive(Debug)]
pub struct Cache {
    limits: Limits,
    /// What its memory is charged to.
    budget: Budget,
    entries: BoundedMap<Key, Box<Stored>>,
    /// The SOA RRsets of the zones with validated NSEC records, by apex,
    /// for synthesizing negative answers (RFC 8198).
    zones: BoundedMap<LowerName, Box<Zone>>,
    /// The validated NSEC RRsets of those zones.
    nsecs: Nsecs,
    /// Everything held, each entry, NSEC zone, and NSEC RRset once, by
    /// when it is past any use, soonest first.
    drops: BoundedMap<Place, ()>,
}

impl Cache {
    /// The bytes a cache of at most `max_entries` things charges when it
    /// is made: the room to hold that many entries, NSEC zones, NSEC
    /// RRsets, and places in its index of what goes first, since any one
    /// kind may take them all. `None` if that overflows.
    pub fn storage(max_entries: usize) -> Option<usize> {
        [
            BoundedMap::<Key, Box<Stored>>::storage(max_entries)?,
            BoundedMap::<LowerName, Box<Zone>>::storage(max_entries)?,
            Nsecs::storage(max_entries)?,
            BoundedMap::<Place, ()>::storage(max_entries)?,
        ]
        .into_iter()
        .try_fold(0usize, usize::checked_add)
    }

    /// An empty cache, its memory charged to `budget`. `None` if the
    /// budget has no room for [`storage`](Cache::storage).
    pub fn new(limits: Limits, budget: &Budget) -> Option<Cache> {
        let max = limits.max_entries;
        Some(Cache {
            limits,
            budget: budget.clone(),
            entries: BoundedMap::new(budget, max)?,
            zones: BoundedMap::new(budget, max)?,
            nsecs: BoundedMap::new(budget, max)?,
            drops: BoundedMap::new(budget, max)?,
        })
    }

    /// The budget its memory is charged to.
    pub fn budget(&self) -> &Budget {
        &self.budget
    }

    /// Forgets everything, as a resolver does when its session changes:
    /// nothing learned before is served again.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.zones.clear();
        self.nsecs.clear();
        self.drops.clear();
    }

    /// Drops everything past any use at `now`: entries expired, past the
    /// stale window, and for a failure, past the time a failure after it
    /// would count as persisting; NSEC records expired, and NSEC zones
    /// whose SOA expired or that hold no live records. Nothing dropped
    /// could serve a read at `now` or later.
    pub fn expire(&mut self, now: Instant) {
        while self
            .drops
            .first_key_value()
            .is_some_and(|((at, _), ())| *at <= now)
        {
            self.drop_first();
        }
    }

    /// Makes room for one more thing, held at `place` with `bytes` of
    /// heap: drops what is sooner of no use until the index has a place
    /// free and the budget has the bytes, and charges them. `None` when
    /// dropping everything sooner of no use leaves too little room: the
    /// thing would go first itself, so it is not stored.
    fn room(&mut self, place: &Place, bytes: usize) -> Option<Charge> {
        loop {
            if self.drops.len() < self.drops.limit()
                && let Some(charge) = self.budget.charge(bytes)
            {
                return Some(charge);
            }
            let sooner = self
                .drops
                .first_key_value()
                .is_some_and(|(first, ())| first < place);
            if !sooner || !self.drop_first() {
                return None;
            }
        }
    }

    /// Drops what is soonest of no use, or returns false when nothing is
    /// held. Its place in [`drops`](Cache::drops) goes first, so every
    /// call takes one place off and the loops over it end, whatever the
    /// stores behind it hold.
    fn drop_first(&mut self) -> bool {
        let Some(((_, slot), ())) = self.drops.pop_first() else {
            return false;
        };
        match slot {
            Slot::Entry(key) => {
                self.take(&key);
            }
            Slot::Zone(zone) => self.drop_zone(&zone),
            Slot::Nsec(zone, owner) => self.drop_nsec(&zone, &owner),
        }
        true
    }

    /// Stores `entry` at `key`, laid over `under` and `glue`, in place of
    /// what was there, if [`room`](Cache::room) can be made for it. Its
    /// charge covers the box it is stored in, the heap of all three
    /// entries ([`rrset_heap`]), and the names it is held under.
    fn put(&mut self, key: Key, entry: Entry, under: Option<Entry>, glue: Option<Entry>) {
        self.take(&key);
        let place = (
            useless_at(&entry, [under.as_ref(), glue.as_ref()], self.limits.stale),
            Slot::Entry(key.clone()),
        );
        let bytes = size_of::<Stored>()
            + [Some(&entry), under.as_ref(), glue.as_ref()]
                .into_iter()
                .flatten()
                .map(Entry::heap)
                .sum::<usize>()
            + place.1.heap();
        let Some(charge) = self.room(&place, bytes) else {
            return;
        };
        let stored = Box::new(Stored {
            entry,
            under,
            glue,
            _charge: charge,
        });
        hold(&mut self.entries, &mut self.drops, key, stored, place);
    }

    /// Removes what is stored at `key`.
    fn take(&mut self, key: &Key) -> Option<Box<Stored>> {
        let stored = self.entries.remove(key)?;
        self.drops.remove(&(
            stored.useless_at(self.limits.stale),
            Slot::Entry(key.clone()),
        ));
        Some(stored)
    }

    /// Removes the SOA RRset of the NSEC zone at `apex`, leaving its
    /// RRsets.
    fn take_zone(&mut self, apex: &LowerName) -> Option<Box<Zone>> {
        let zone = self.zones.remove(apex)?;
        self.drops
            .remove(&(zone.soa_expires, Slot::Zone(apex.clone())));
        Some(zone)
    }

    /// Removes the NSEC RRset at `key`, its zone's apex and its owner,
    /// leaving the zone.
    fn take_nsec(&mut self, key: &(LowerName, LowerName)) -> Option<Box<Nsec>> {
        let nsec = self.nsecs.remove(key)?;
        let (apex, owner) = key.clone();
        self.drops.remove(&(nsec.expires, Slot::Nsec(apex, owner)));
        Some(nsec)
    }

    /// Removes the NSEC zone at `apex`, with every RRset it holds.
    fn drop_zone(&mut self, apex: &LowerName) {
        self.take_zone(apex);
        loop {
            let first = zone_records(&self.nsecs, apex).next();
            let Some(key) = first.map(|(key, _)| key.clone()) else {
                return;
            };
            self.take_nsec(&key);
        }
    }

    /// Removes the NSEC RRset at `owner` in the zone at `apex`, and the
    /// zone when that leaves it no records.
    fn drop_nsec(&mut self, apex: &LowerName, owner: &LowerName) {
        if self.take_nsec(&(apex.clone(), owner.clone())).is_some()
            && zone_records(&self.nsecs, apex).next().is_none()
        {
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
            let glue = glue(self, &asked);
            self.put(asked, entry.clone(), None, glue);
        }
        let glue = glue(self, &key);
        self.put(key, entry, under, glue);
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
        self.entries.get(key).map(|stored| &**stored)
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
        // Taken out and put back with its charge, in the place taking it
        // out freed, so that a shorter life is indexed.
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
        let place = (
            stored.useless_at(self.limits.stale),
            Slot::Entry(key.clone()),
        );
        hold(
            &mut self.entries,
            &mut self.drops,
            key.clone(),
            stored,
            place,
        );
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
        let apex = LowerName::new(soa.name());
        let soa = normalized(soa);
        let capped =
            |expires: Instant, until: Option<Instant>| until.map_or(expires, |u| expires.min(u));
        let soa_expires = capped(
            at + seconds(soa.ttl()).min(self.limits.max_negative_ttl),
            soa_until,
        );
        // The zone's old SOA leaves while its records go in, so making
        // room for them never drops the zone for holding none. The new
        // SOA goes in after them, in a place of its own.
        self.take_zone(&apex);
        for (set, until) in nsec {
            let set = normalized(set);
            let expires = capped(
                at + seconds(set.ttl()).min(self.limits.max_negative_ttl),
                *until,
            );
            let key = (apex.clone(), LowerName::new(set.name()));
            self.take_nsec(&key);
            let place = (expires, Slot::Nsec(key.0.clone(), key.1.clone()));
            let bytes = size_of::<Nsec>() + rrset_heap(&set) + place.1.heap();
            let Some(charge) = self.room(&place, bytes) else {
                continue;
            };
            let nsec = Box::new(Nsec {
                set,
                expires,
                _charge: charge,
            });
            hold(&mut self.nsecs, &mut self.drops, key, nsec, place);
        }
        // The records prove nothing without the SOA, so they go when it
        // finds no room, or when room for it took them all.
        let held = |cache: &Cache| zone_records(&cache.nsecs, &apex).next().is_some();
        let place = (soa_expires, Slot::Zone(apex.clone()));
        let bytes = size_of::<Zone>() + rrset_heap(&soa) + place.1.heap();
        if held(self)
            && let Some(charge) = self.room(&place, bytes)
            && held(self)
        {
            let zone = Box::new(Zone {
                soa,
                soa_expires,
                _charge: charge,
            });
            hold(&mut self.zones, &mut self.drops, apex, zone, place);
        } else {
            self.drop_zone(&apex);
        }
    }

    /// The deepest zone holding `name` with validated NSEC records live at
    /// `now`, with its SOA RRset, borrowed.
    pub(super) fn secure_nsec(&self, name: &LowerName, now: Instant) -> Option<ZoneNsecs<'_>> {
        let mut at = name.clone();
        loop {
            if let Some((zone, soa)) = self.zones.get_key_value(&at)
                && now < soa.soa_expires
            {
                let found = ZoneNsecs {
                    zone,
                    soa,
                    nsecs: &self.nsecs,
                    now,
                };
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

/// The heap `set` holds past its own struct, as the cache charges it to
/// its budget, by estimate: its owner's octets and, for every record and
/// RRSIG, its place in the set's vectors and its octets as a message
/// carries it, owner written out without compression, which covers the
/// owner's and the data's heap. A record that cannot be written counts
/// its owner and its fixed fields (RFC 1035 §4.1.3). Spare capacity in
/// the vectors and the allocator's rounding are not counted.
fn rrset_heap(set: &RecordSet) -> usize {
    /// TYPE, CLASS, TTL, and RDLENGTH.
    const FIXED: usize = 10;
    let records: usize = set
        .records_without_rrsigs()
        .chain(set.rrsigs())
        .map(|record| {
            size_of::<Record>()
                + record
                    .to_bytes()
                    .map_or(record.name.len() + FIXED, |bytes| bytes.len())
        })
        .sum();
    set.name().len() + records
}

/// The heap `sets` holds, by estimate: the vector's places, and each
/// set's heap by [`rrset_heap`].
fn rrsets_heap(sets: &Vec<RecordSet>) -> usize {
    sets.capacity() * size_of::<RecordSet>() + sets.iter().map(rrset_heap).sum::<usize>()
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
    use fictionet::stdlib::protocols::dns::rr::RData;
    use fictionet::stdlib::protocols::dns::rr::rdata::A;
    use fictionet::{Entropy, Seed, SeededEntropy};

    fn limits(max_entries: usize) -> Limits {
        Limits {
            max_ttl: Duration::from_secs(100),
            max_negative_ttl: Duration::from_secs(100),
            failure_ttl: Duration::from_secs(1),
            stale: Duration::from_secs(100),
            max_entries,
        }
    }

    /// A cache of at most `max_entries` things, on a budget with room for
    /// its index and `room` bytes more.
    fn cache_with_room(max_entries: usize, room: usize) -> Cache {
        let budget = Budget::new(Cache::storage(max_entries).unwrap() + room);
        Cache::new(limits(max_entries), &budget).unwrap()
    }

    /// A cache that only its count of things limits.
    fn cache(max_entries: usize) -> Cache {
        Cache::new(limits(max_entries), &Budget::unlimited()).unwrap()
    }

    fn at(seconds: u64) -> Instant {
        Instant::from_since_start(Duration::from_secs(seconds))
    }

    fn name(text: &str) -> Name {
        Name::from_ascii(text).unwrap()
    }

    /// The key of the A RRset at `owner`.
    fn key_a(owner: &str) -> Key {
        Key::new(LowerName::new(&name(owner)), RecordType::A, DNSClass::IN)
    }

    /// An A RRset at `owner` with `count` addresses, its TTL `ttl`.
    fn addresses(owner: &str, ttl: u32, count: u8) -> Offer {
        let owner = name(owner);
        let mut set = RecordSet::with_ttl(owner.clone(), RecordType::A, ttl);
        for index in 0..count {
            let data = RData::A(A::new(192, 0, 2, index));
            set.insert(Record::from_rdata(owner.clone(), ttl, data), 0);
        }
        Offer::Positive {
            set,
            rank: Rank::AuthAnswer,
            validation: Validation::NotPerformed,
            proof: Vec::new(),
            truncated: false,
        }
    }

    /// An A RRset at `owner` with one address, its TTL `ttl`.
    fn address(owner: &str, ttl: u32) -> Offer {
        addresses(owner, ttl, 1)
    }

    /// An NSEC RRset at `owner` with one record.
    fn nsec(owner: &str) -> RecordSet {
        use fictionet::stdlib::protocols::dns::dnssec::rdata::{DNSSECRData, NSEC};
        let next = name(&format!("next.{owner}"));
        let rdata = RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(next, [RecordType::A])));
        let mut set = RecordSet::with_ttl(name(owner), RecordType::NSEC, 100);
        set.insert(Record::from_rdata(name(owner), 100, rdata), 0);
        set
    }

    /// An SOA RRset at `zone` with no records, its TTL `ttl`.
    fn soa(zone: &str, ttl: u32) -> RecordSet {
        RecordSet::with_ttl(name(zone), RecordType::SOA, ttl)
    }

    /// The records and RRSIGs in every RRset `entry` holds.
    fn records_of(entry: &Entry) -> usize {
        let sets: Vec<&RecordSet> = match entry {
            Entry::Positive { set, proof, .. } => std::iter::once(set).chain(proof).collect(),
            Entry::Negative { soa, denial, .. } => std::iter::once(soa).chain(denial).collect(),
            Entry::Failure { .. } => Vec::new(),
        };
        sets.iter()
            .map(|set| set.records_without_rrsigs().count() + set.rrsigs().len())
            .sum()
    }

    /// What the budget must hold for what `cache` holds now: the room
    /// for its index, and the heap of each thing by the estimate it is
    /// charged.
    fn charged_for(cache: &Cache) -> usize {
        let entries = cache.entries.iter().map(|(key, stored)| {
            size_of::<Stored>()
                + [
                    Some(&stored.entry),
                    stored.under.as_ref(),
                    stored.glue.as_ref(),
                ]
                .into_iter()
                .flatten()
                .map(Entry::heap)
                .sum::<usize>()
                + Slot::Entry(key.clone()).heap()
        });
        let zones = cache.zones.iter().map(|(apex, zone)| {
            size_of::<Zone>() + rrset_heap(&zone.soa) + Slot::Zone(apex.clone()).heap()
        });
        let nsecs = cache.nsecs.iter().map(|((apex, owner), nsec)| {
            size_of::<Nsec>()
                + rrset_heap(&nsec.set)
                + Slot::Nsec(apex.clone(), owner.clone()).heap()
        });
        Cache::storage(cache.limits.max_entries).unwrap()
            + entries.sum::<usize>()
            + zones.sum::<usize>()
            + nsecs.sum::<usize>()
    }

    /// What holds after every call:
    ///
    /// - Sum: the budget's count is within its limit.
    /// - Cover and Return: the budget holds the index's room and each
    ///   thing's heap for exactly what the cache holds, nothing for what
    ///   it dropped.
    /// - The heap is counted, not the octets a message carries: each
    ///   entry is charged at least its box and its records' places.
    /// - Each thing held has one place in the index, at the time it is
    ///   of no use, and the index holds no more than the limit.
    /// - Each NSEC zone holds records, and each record has its zone.
    fn check(cache: &Cache) {
        let budget = cache.budget();
        assert!(budget.used() <= budget.limit());
        assert_eq!(budget.used(), charged_for(cache));
        let storage = Cache::storage(cache.limits.max_entries).unwrap();
        let floor: usize = cache
            .entries
            .iter()
            .map(|(_, stored)| {
                let records: usize = [
                    Some(&stored.entry),
                    stored.under.as_ref(),
                    stored.glue.as_ref(),
                ]
                .into_iter()
                .flatten()
                .map(records_of)
                .sum();
                size_of::<Stored>() + records * size_of::<Record>()
            })
            .sum();
        assert!(budget.used() - storage >= floor);
        let held = cache.entries.len() + cache.zones.len() + cache.nsecs.len();
        assert_eq!(cache.drops.len(), held);
        assert!(held <= cache.limits.max_entries);
        for ((at, slot), ()) in cache.drops.iter() {
            let useless = match slot {
                Slot::Entry(key) => cache
                    .entries
                    .get(key)
                    .map(|stored| stored.useless_at(cache.limits.stale)),
                Slot::Zone(apex) => cache.zones.get(apex).map(|zone| zone.soa_expires),
                Slot::Nsec(apex, owner) => cache
                    .nsecs
                    .get(&(apex.clone(), owner.clone()))
                    .map(|nsec| nsec.expires),
            };
            assert_eq!(useless, Some(*at), "{slot:?}");
        }
        for (apex, _) in cache.zones.iter() {
            assert!(zone_records(&cache.nsecs, apex).next().is_some());
        }
        for ((apex, _), _) in cache.nsecs.iter() {
            assert!(cache.zones.get(apex).is_some());
        }
    }

    /// Random calls on caches with little room, checked after each, and
    /// every byte given back when the cache goes.
    #[test]
    fn the_budget_pays_for_the_index_and_every_thing_held() {
        for seed in 0..64 {
            let rng = SeededEntropy::new(Seed::from_u64(seed));
            let below = |n: usize| rng.random_below(n as u64) as usize;
            let max_entries = 4 + below(28);
            let mut cache = cache_with_room(max_entries, 2_000 + below(30_000));
            let budget = cache.budget().clone();
            let mut now = 0;
            for _ in 0..300 {
                let zone = format!("z{}.example.", below(3));
                let owner = format!("h{}.{zone}", below(6));
                let ttl = 1 + below(60) as u32;
                let until = |most: usize| Some(at(now + below(most) as u64));
                match below(10) {
                    0..=3 => cache.insert(at(now), addresses(&owner, ttl, 1 + below(4) as u8)),
                    4 => cache.insert(
                        at(now),
                        Offer::Failure {
                            key: key_a(&owner),
                            why: FailureKind::Unknown,
                            cd: false,
                            follows: None,
                        },
                    ),
                    5 => cache.insert(
                        at(now),
                        Offer::Negative {
                            key: key_a(&owner),
                            kind: [Negative::NxDomain, Negative::NoData][below(2)],
                            soa: Some(soa(&zone, ttl)),
                            rank: Rank::AuthAnswer,
                            denial: Vec::new(),
                            validation: Validation::NotPerformed,
                            truncated: false,
                        },
                    ),
                    6 => {
                        let records: Vec<(RecordSet, Option<Instant>)> = (0..1 + below(4))
                            .map(|_| (nsec(&format!("n{}.{zone}", below(8))), until(60)))
                            .collect();
                        cache.add_secure_nsec(&soa(&zone, 100), until(80), &records, at(now));
                    }
                    7 => {
                        let key = key_a(&owner);
                        if let Some(Entry::Positive { set, .. }) = cache.get(&key, at(now)) {
                            let checked = Checked::Rrset(set.clone());
                            let result = Validation::Secure;
                            cache.validated(&key, &checked, result, until(30), at(now));
                        }
                    }
                    8 => {
                        now += below(40) as u64;
                        cache.expire(at(now));
                    }
                    _ => {
                        if below(8) == 0 {
                            cache.clear();
                        }
                    }
                }
                check(&cache);
            }
            drop(cache);
            assert_eq!(budget.used(), 0, "seed {seed}");
        }
    }

    #[test]
    fn with_no_room_what_is_soonest_of_no_use_goes_first() {
        // One entry's charge, on a cache with room to spare. Every owner
        // below has as many octets.
        let mut roomy = cache(8);
        let empty = roomy.budget().used();
        roomy.insert(at(0), address("host0.example.", 10));
        let one = roomy.budget().used() - empty;
        // Room for three entries, not four.
        let mut cache = cache_with_room(8, 3 * one + one / 2);
        for (index, ttl) in [(0, 10), (1, 20), (2, 30)] {
            cache.insert(at(0), address(&format!("host{index}.example."), ttl));
        }
        let held = |cache: &Cache, index: usize| {
            let key = key_a(&format!("host{index}.example."));
            cache.get(&key, at(0)).is_some()
        };
        assert!((0..3).all(|index| held(&cache, index)));
        let full = cache.budget().used();
        // An entry that would go first itself is not stored, and nothing
        // goes for it.
        cache.insert(at(0), address("host3.example.", 5));
        assert!(!held(&cache, 3));
        assert!((0..3).all(|index| held(&cache, index)));
        assert_eq!(cache.budget().used(), full);
        // One that lasts longer takes the room of the one that expires
        // first.
        cache.insert(at(0), address("host4.example.", 50));
        assert!(held(&cache, 4));
        assert!(!held(&cache, 0));
        assert!(held(&cache, 1) && held(&cache, 2));
        check(&cache);
    }

    #[test]
    fn an_entry_is_charged_for_the_heap_of_its_records() {
        let mut cache = cache(8);
        let empty = cache.budget().used();
        cache.insert(at(0), addresses("one.example.", 10, 1));
        let one = cache.budget().used() - empty;
        assert!(one >= size_of::<Stored>() + size_of::<Record>());
        cache.insert(at(0), addresses("all.example.", 10, 4));
        let four = cache.budget().used() - empty - one;
        assert!(four >= one + 3 * size_of::<Record>());
        check(&cache);
        cache.expire(at(1000));
        assert_eq!(cache.budget().used(), empty);
    }

    #[test]
    fn a_cache_is_made_only_with_room_for_its_index() {
        let storage = Cache::storage(16).unwrap();
        assert!(storage > 0);
        assert!(Cache::storage(usize::MAX).is_none());
        let short = Budget::new(storage - 1);
        assert!(Cache::new(limits(16), &short).is_none());
        assert_eq!(short.used(), 0, "a cache not made holds nothing");
        let exact = Budget::new(storage);
        let mut cache = Cache::new(limits(16), &exact).unwrap();
        assert_eq!(exact.used(), storage);
        // Nothing more fits, so nothing is stored.
        cache.insert(at(0), address("host.example.", 10));
        assert!(cache.get(&key_a("host.example."), at(0)).is_none());
        check(&cache);
        drop(cache);
        assert_eq!(exact.used(), 0);
    }

    #[test]
    fn expired_entries_are_reclaimed_though_the_cache_stops_growing() {
        let mut cache = cache(64);
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
        assert_eq!(cache.budget().used(), Cache::storage(64).unwrap());
    }

    /// Dropping takes a place off the index before what it names, so a
    /// place whose entry is gone, or an index that runs out while the
    /// budget is still short, cannot keep `expire` or `room` turning.
    #[test]
    fn dropping_ends_when_the_index_and_the_stores_disagree() {
        let mut cache = cache(64);
        cache.insert(at(0), address("host.example.", 50));
        let key = cache
            .entries
            .iter()
            .next()
            .map(|(key, _)| key.clone())
            .unwrap();
        cache.entries.remove(&key);
        cache.expire(at(400));
        assert!(cache.drops.is_empty());

        let mut roomy = self::cache(8);
        let empty = roomy.budget().used();
        roomy.insert(at(0), address("host.example.", 50));
        let one = roomy.budget().used() - empty;
        let mut cache = cache_with_room(8, one);
        cache.insert(at(0), address("host.example.", 50));
        cache.drops.clear();
        cache.insert(at(0), address("other.example.", 100));
        assert!(cache.get(&key_a("other.example."), at(0)).is_none());
        assert!(cache.budget().used() <= cache.budget().limit());
    }

    #[test]
    fn expired_denial_proofs_are_reclaimed_by_any_insert() {
        let mut cache = cache(64);
        let soa = soa("example.", 100);
        cache.add_secure_nsec(&soa, Some(at(1)), &[(nsec("a.example."), None)], at(0));
        assert!(!cache.zones.is_empty());
        cache.insert(at(2), address("host.example.", 50));
        assert!(cache.zones.is_empty());
        assert!(cache.nsecs.is_empty());
        assert_eq!(cache.drops.len(), 1);
        check(&cache);
    }

    #[test]
    fn nsec_records_count_against_the_entry_limit_and_the_longest_lived_stay() {
        let mut cache = cache(4);
        let soa = soa("example.", 100);
        let owners: Vec<String> = (0..10).map(|index| format!("n{index}.example.")).collect();
        let records: Vec<(RecordSet, Option<Instant>)> = owners
            .iter()
            .enumerate()
            .map(|(index, owner)| (nsec(owner), Some(at(10 + index as u64))))
            .collect();
        cache.add_secure_nsec(&soa, Some(at(90)), &records, at(0));
        assert!(cache.drops.len() <= 4);
        let apex = LowerName::new(soa.name());
        let kept: Vec<&LowerName> = zone_records(&cache.nsecs, &apex)
            .map(|((_, owner), _)| owner)
            .collect();
        assert_eq!(kept.len(), 3);
        for owner in &owners[7..] {
            assert!(kept.contains(&&LowerName::new(&name(owner))));
        }
        check(&cache);
        // An entry counts against the same limit.
        cache.insert(at(0), address("host.example.", 50));
        assert!(cache.drops.len() <= 4);
        assert!(cache.get(&key_a("host.example."), at(0)).is_some());
        check(&cache);
    }

    #[test]
    fn expiry_reclaims_expired_denial_proofs_and_preserves_live_ones() {
        let mut cache = cache(64);
        let set = |owner: &str, rtype| RecordSet::with_ttl(name(owner), rtype, 100);
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
        let before = cache.zones.len();
        cache.expire(at(2));
        assert!(cache.zones.len() < before);
        assert!(!cache.zones.is_empty());
        for (apex, zone) in cache.zones.iter() {
            assert!(zone.soa_expires > at(2));
            assert!(zone_records(&cache.nsecs, apex).next().is_some());
            assert!(zone_records(&cache.nsecs, apex).all(|(_, nsec)| nsec.expires > at(2)));
        }
        check(&cache);
        let live = LowerName::new(&name("live.example."));
        assert!(cache.secure_nsec(&live, at(2)).is_some());
        cache.expire(at(3));
        assert!(cache.zones.is_empty());
        assert!(cache.nsecs.is_empty());
        assert!(cache.secure_nsec(&live, at(3)).is_none());
    }
}
