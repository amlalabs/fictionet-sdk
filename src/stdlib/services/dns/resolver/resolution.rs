//! One resolution: the iteration of RFC 1034 §5.3.3 with the rules that
//! came after it (RFC 9156 QNAME minimisation, RFC 8109 priming, RFC 5452
//! matching, RFC 7766 TCP after truncation, RFC 9520 failures), and the
//! gathering of the DS and DNSKEY sets a validation needs.
//!
//! Work is a graph. A *lookup* finds what the servers say about one
//! question and offers it to the cache. A lookup may need other lookups
//! first: the priming of the root, or the addresses of name servers that
//! came without glue. A *check* validates one RRset or one negative
//! answer and needs the lookups of the DS and DNSKEY sets from a trust
//! anchor down. Client queries need lookups for the names their aliases
//! lead to, and checks for what they found. Every edge is explicit, so a
//! lookup that would need itself, such as a name server whose address
//! only the zone it serves can give, fails that edge instead of waiting
//! forever. Lookups and checks for the same question are shared, and one
//! whose last dependent is gone is cancelled.
//!
//! The queries a client question costs, over everything it needs, are
//! counted against [`Work`](super::Work): the question is its own *tree*,
//! and lookups and checks it starts belong to it. A lookup another tree
//! started and this one joins stays charged to that tree until its bound
//! runs out, and then goes on charged to another tree it does work for,
//! directly or through the lookups and checks that wait on it.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{IpAddr, SocketAddr};

use fictionet::Entropy;
use fictionet::stdlib::protocols::dns::dnssec::rdata::DNSSECRData;
use fictionet::stdlib::protocols::dns::dnssec::{
    Anchors, Chain, Fetched, Insecure, Link, Validation, Verified, Verify, proof, validate_denial,
    validate_rrset,
};
use fictionet::stdlib::protocols::dns::op::{
    Edns, Message, MessageType, OpCode, Query, ResponseCode,
};
use fictionet::stdlib::protocols::dns::rr::domain::Label;
use fictionet::stdlib::protocols::dns::rr::{
    DNSClass, LowerName, Name, RData, RecordSet, RecordType, SerialNumber,
};
use fictionet::stdlib::protocols::dns::{Parsed, Request, Response, dname_substitute, label_count};
use fictionet::stdlib::services::serve::Transport;
use fictionet::time::Instant;

use super::super::event::{Event, Unmatched, UpstreamOutcome};
use super::super::exchange::{
    Action, ExchangeFailure, Sent, Token, Transmit, ignored, matching, outstanding,
};
use super::super::records::{expanded_from, rrsets, signatures};
use super::super::zone::dname_target;
use super::Resolver;
use super::cache::{
    Checked, Entry, FailureKind, Key, Negative, Offer, Rank, normalized, same_rrset, same_rrsets,
    seconds, ttl_left,
};

/// How many times one resolution sends a query to one server address over
/// one transport before it gives up on that address (RFC 9520 §3.1: at
/// most three).
const TRIES: u8 = 3;

/// The smallest EDNS payload a priming query offers, so the root's NS
/// RRset and its glue fit in one reply, whatever payload the resolver
/// advertises to its clients (RFC 8109 §3: 1024 octets or more).
const PRIMING_PAYLOAD: u16 = 1232;

/// A client query the resolver is answering.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct AskerId(u64);

/// A lookup: one question being resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct LookupId(u64);

/// A check: one validation being made.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct CheckId(u64);

/// The work one client question costs, over everything it needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct TreeId(u64);

impl TreeId {
    /// The tree of `asker`: a client question is its own tree.
    pub(super) fn of(asker: AskerId) -> TreeId {
        TreeId(asker.0)
    }
}

/// Something that waits in the graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) enum Node {
    /// A client query.
    Asker(AskerId),
    /// A lookup.
    Lookup(LookupId),
    /// A check.
    Check(CheckId),
    /// A lookup kept going after its client was answered with stale data,
    /// so that the cache is refreshed (RFC 8767 §5).
    Refresh,
}

/// What a lookup found for one question.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum Outcome {
    /// RRsets at the name: one of the type asked for, or every RRset the
    /// server sent for QTYPE ANY.
    Data {
        sets: Vec<RecordSet>,
        /// The DNAME a CNAME asked for was synthesized from, if it was,
        /// and the NSEC or NSEC3 records that show a wildcard answer had no
        /// closer match.
        proof: Vec<RecordSet>,
        /// The zone whose server answered.
        zone: Name,
    },
    /// A CNAME at the name, for any type but CNAME and ANY.
    Alias {
        cname: RecordSet,
        target: Name,
        /// The DNAME the CNAME was synthesized from, if it was, and the
        /// NSEC or NSEC3 records that show a wildcard CNAME had no closer
        /// match.
        proof: Vec<RecordSet>,
        zone: Name,
    },
    /// A DNAME above the name whose substitution would pass 255 octets:
    /// the server answered YXDOMAIN with it (RFC 6672 §2.2).
    TooLong { dname: RecordSet, zone: Name },
    /// A negative answer.
    Negative {
        kind: Negative,
        /// The name the negative is about.
        name: Name,
        qtype: RecordType,
        soa: Option<RecordSet>,
        denial: Vec<RecordSet>,
        zone: Name,
    },
    /// The lookup failed.
    Failure(FailureKind),
}

impl Outcome {
    /// The RRsets an answer from this outcome carries, with the TTLs they
    /// had when found.
    pub(super) fn records(&self) -> Vec<&RecordSet> {
        match self {
            Outcome::Data { sets, proof, .. } => sets.iter().chain(proof).collect(),
            Outcome::Alias { cname, proof, .. } => std::iter::once(cname).chain(proof).collect(),
            Outcome::Negative { soa, denial, .. } => soa.iter().chain(denial).collect(),
            Outcome::TooLong { dname, .. } => vec![dname],
            Outcome::Failure(_) => Vec::new(),
        }
    }
}

/// One thing a check validates.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) enum Subject {
    /// The RRset at a key.
    Rrset(Key),
    /// A negative answer for a key.
    Denial(Key, Negative),
}

/// The subjects `outcome` holds, in the order a client sees them.
pub(super) fn subjects(outcome: &Outcome) -> Vec<Subject> {
    let key = |set: &RecordSet| {
        Key::new(
            LowerName::new(set.name()),
            set.record_type(),
            set.dns_class(),
        )
    };
    match outcome {
        // RRSIG records are not signed themselves (RFC 4035 §2.2), so an
        // answer of them has nothing to validate.
        Outcome::Data { sets, .. } => sets
            .iter()
            .filter(|set| set.record_type() != RecordType::RRSIG)
            .map(|set| Subject::Rrset(key(set)))
            .collect(),
        Outcome::Alias { cname, .. } => vec![Subject::Rrset(key(cname))],
        Outcome::TooLong { dname, .. } => vec![Subject::Rrset(key(dname))],
        Outcome::Negative {
            kind, name, qtype, ..
        } => {
            let rtype = match kind {
                Negative::NxDomain => RecordType::ANY,
                Negative::NoData => *qtype,
            };
            let key = Key::new(LowerName::new(name), rtype, DNSClass::IN);
            vec![Subject::Denial(key, *kind)]
        }
        Outcome::Failure(_) => Vec::new(),
    }
}

/// An outcome with what is known of its validation.
#[derive(Clone, Debug)]
pub(super) struct Found {
    pub(super) outcome: Outcome,
    pub(super) checks: Vec<(Subject, Validation)>,
    pub(super) cached: bool,
    /// When `outcome` is an alias from a server's reply, what the same
    /// reply said about each alias target after it, in turn.
    pub(super) rest: Vec<Outcome>,
}

/// A zone cut a local zone refers a question to.
pub(super) struct LocalCut {
    cut: LowerName,
    /// The cut's NS targets.
    targets: Vec<Name>,
    /// The addresses the zone holds for its targets, as glue.
    glue: BTreeMap<LowerName, Vec<IpAddr>>,
}

impl Found {
    fn fresh(outcome: Outcome) -> Found {
        let checks = subjects(&outcome)
            .into_iter()
            .map(|subject| (subject, Validation::NotPerformed))
            .collect();
        Found {
            outcome,
            checks,
            cached: false,
            rest: Vec::new(),
        }
    }
}

/// What asking for a question's outcome gave.
pub(super) enum Dep {
    /// The cache had it.
    Ready(Box<Found>),
    /// This lookup is finding it.
    Waiting(LookupId),
    /// It cannot be had: the lookup would wait on itself.
    Cycle,
    /// It cannot be had by this tree: the dependency is deeper than the
    /// work bound allows.
    TooDeep,
}

/// What starting a check gave.
pub(super) enum CheckStart {
    Done(Verdict),
    Waiting(CheckId),
}

/// What a check established: the result, and the RRSIGs that verified the
/// RRsets a Secure result rests on, which alone bound how long it lasts
/// (RFC 4035 §5.3.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Verdict {
    pub(super) validation: Validation,
    pub(super) verified: Vec<Verified>,
}

impl From<Validation> for Verdict {
    fn from(validation: Validation) -> Verdict {
        Verdict {
            validation,
            verified: Vec::new(),
        }
    }
}

/// Something that became ready for a node waiting on it.
pub(super) enum Ready {
    Looked {
        to: Node,
        lookup: LookupId,
        key: Key,
        found: Box<Found>,
        /// Whether the work bound stopped the lookup.
        bounded: bool,
    },
    Checked {
        to: Node,
        check: CheckId,
        subject: Subject,
        verdict: Verdict,
    },
}

/// The resolver's work in progress.
#[derive(Default)]
pub(super) struct Graph {
    next: u64,
    lookups: BTreeMap<LookupId, Lookup>,
    /// The lookup under way for each key, and whether it relays a client's
    /// CD bit.
    by_key: BTreeMap<(Key, bool), LookupId>,
    checks: BTreeMap<CheckId, Check>,
    /// The checks under way for each subject, each over its own data.
    by_subject: BTreeMap<Subject, Vec<CheckId>>,
    exchanges: BTreeMap<Token, Exchange>,
    trees: BTreeMap<TreeId, Tree>,
    pub(super) ready: VecDeque<Ready>,
}

/// The work one client question has cost, and how many nodes still hold
/// it.
struct Tree {
    sent: u16,
    holders: usize,
    /// Whether any server sent a matching reply to a query of this tree.
    replied: bool,
}

/// One question being resolved.
struct Lookup {
    key: Key,
    /// Whether its queries carry CD because a client's did, as a
    /// forwarder that does not validate sends them.
    relay_cd: bool,
    tree: TreeId,
    depth: u8,
    dependents: Vec<Node>,
    /// Server addresses given up on over each transport: they failed, or
    /// timed out [`TRIES`] times.
    tried: Vec<(SocketAddr, Transport)>,
    /// How many queries to each server address over each transport timed
    /// out.
    timeouts: Vec<(SocketAddr, Transport, u8)>,
    /// Whether a server sent a reply the lookup could not use.
    errors: bool,
    minimise: Minimising,
    /// Addresses of name servers that lookups this one waited on found,
    /// or that a local zone holds as glue for its cut.
    learned: BTreeMap<LowerName, Vec<IpAddr>>,
    /// Name servers whose addresses this lookup asked for.
    asked: BTreeSet<LowerName>,
    /// The last referral this lookup followed, or a local zone's cut it
    /// started from: the cut and its NS
    /// targets. Data with TTL 0 is not cached but serves the resolution in
    /// progress (RFC 1035 §7.4), so the referral moves the lookup down
    /// even when the cache kept nothing of it.
    delegation: Option<(LowerName, Vec<Name>)>,
    /// Whether the work bound stopped this lookup, or a lookup it waited
    /// on. Its failure then says how far one client question's budget
    /// went, not what the servers did, so it is not cached for other
    /// clients (RFC 9520 §3.2).
    bounded: bool,
    /// How long the cached failure of its key lasted, when the lookup
    /// began while that failure persisted
    /// ([`Cache::persisting`](super::cache::Cache::persisting)).
    follows: Option<std::time::Duration>,
    wait: LookupWait,
}

#[derive(Default)]
struct Minimising {
    /// Minimised questions answered so far. A question asked again after
    /// a timeout or an unusable reply is the same step (RFC 9156 §2.3).
    steps: u8,
    /// The deepest name below the current zone cut known not to be a cut.
    through: Option<LowerName>,
    /// Whether minimisation stopped, after a minimised query got NXDOMAIN
    /// from an authority that does not follow RFC 8020.
    off: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum LookupWait {
    Nothing,
    Exchange(Token),
    Lookups(BTreeSet<LookupId>),
}

/// One query a lookup is about to send: what it asks, of which server,
/// and how.
struct Asking {
    /// The zone the server is asked as an authority for.
    zone: LowerName,
    to: SocketAddr,
    transport: Transport,
    /// The question. Its case is randomised when it is sent, with
    /// [`case_randomise`](super::Config::case_randomise).
    question: Query,
    /// Whether the question is a minimised one.
    minimised: bool,
    /// Whether it asks with RD set, as to a forwarder.
    forwarded: bool,
}

/// One query sent to a server.
struct Exchange {
    lookup: LookupId,
    to: SocketAddr,
    transport: Transport,
    id: u16,
    /// The question, in the case it was sent with.
    question: Query,
    /// The zone the server was asked as an authority for.
    zone: LowerName,
    /// Whether the question is a minimised one.
    minimised: bool,
    /// Whether it asked with RD set, as to a forwarder.
    forwarded: bool,
    /// When the query went out, to time the server's round trip.
    sent: Instant,
    deadline: Instant,
}

/// One validation being made.
struct Check {
    subject: Subject,
    /// The data at the subject's key the result is for.
    checked: Checked,
    material: Material,
    /// When the TTLs in `material` were current: when it arrived, or when
    /// it was read from the cache with its TTLs counted down.
    at: Instant,
    tree: TreeId,
    depth: u8,
    /// The trust anchor the chain starts at.
    anchor: Name,
    /// The zone the material came from, as far as the resolution knew.
    zone: Name,
    /// What the chain has gathered, per zone.
    links: BTreeMap<LowerName, (Name, Option<Fetched>, Option<Fetched>)>,
    /// The lookups the check waits for, with the zone and the part each
    /// fetches.
    wait: BTreeMap<LookupId, (LowerName, Part)>,
    /// Whether the check looked for zone cuts between `zone` and an
    /// unsigned RRset's owner.
    probed: bool,
    /// Whether the work bound stopped a lookup the check needed. Its
    /// result then says how far one client question's budget went, so it
    /// is not cached for other clients (RFC 9520 §3.2).
    bounded: bool,
    dependents: Vec<Node>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Part {
    Ds,
    Dnskey,
    /// The DS RRset at a name between the zone and the owner of an
    /// unsigned RRset, asked to find a zone cut the resolution never saw.
    Cut,
}

/// The records one check validates.
#[derive(Clone)]
enum Material {
    Rrset {
        set: RecordSet,
        authority: Vec<RecordSet>,
    },
    Denial {
        query: Query,
        rcode: ResponseCode,
        authority: Vec<RecordSet>,
    },
}

impl Material {
    /// Whether `other` is the same records, whatever the TTLs and the
    /// case of the owners.
    fn same(&self, other: &Material) -> bool {
        match (self, other) {
            (
                Material::Rrset { set, authority },
                Material::Rrset {
                    set: other_set,
                    authority: other_authority,
                },
            ) => same_rrset(set, other_set) && same_rrsets(authority, other_authority),
            (
                Material::Denial {
                    query,
                    rcode,
                    authority,
                },
                Material::Denial {
                    query: other_query,
                    rcode: other_rcode,
                    authority: other_authority,
                },
            ) => {
                LowerName::new(query.name()) == LowerName::new(other_query.name())
                    && query.query_type() == other_query.query_type()
                    && rcode == other_rcode
                    && same_rrsets(authority, other_authority)
            }
            _ => false,
        }
    }
}

impl Graph {
    /// A number no node has had.
    fn issue(&mut self) -> u64 {
        self.next += 1;
        self.next
    }

    /// Takes check `id` off the checks under way for `subject`.
    fn unlist(&mut self, subject: &Subject, id: CheckId) {
        if let Some(ids) = self.by_subject.get_mut(subject) {
            ids.retain(|other| *other != id);
            if ids.is_empty() {
                self.by_subject.remove(subject);
            }
        }
    }

    /// A name for a new client query.
    pub(super) fn asker(&mut self) -> AskerId {
        AskerId(self.issue())
    }

    fn lookup_id(&mut self) -> LookupId {
        LookupId(self.issue())
    }

    fn check_id(&mut self) -> CheckId {
        CheckId(self.issue())
    }

    /// Notes one more node of `tree`.
    pub(super) fn hold(&mut self, tree: TreeId) {
        self.trees
            .entry(tree)
            .or_insert(Tree {
                sent: 0,
                holders: 0,
                replied: false,
            })
            .holders += 1;
    }

    /// Notes one node fewer of `tree`, forgetting it after the last.
    pub(super) fn release(&mut self, tree: TreeId) {
        if let Some(entry) = self.trees.get_mut(&tree) {
            entry.holders -= 1;
            if entry.holders == 0 {
                self.trees.remove(&tree);
            }
        }
    }

    /// Whether `tree` has sent fewer than `limit` queries.
    fn within(&self, tree: TreeId, limit: u16) -> bool {
        self.trees
            .get(&tree)
            .is_some_and(|entry| entry.sent < limit)
    }

    /// The tree `node` belongs to. A refresh belongs to none.
    fn tree_of(&self, node: Node) -> Option<TreeId> {
        match node {
            Node::Asker(asker) => Some(TreeId::of(asker)),
            Node::Lookup(id) => self.lookups.get(&id).map(|lookup| lookup.tree),
            Node::Check(id) => self.checks.get(&id).map(|check| check.tree),
            Node::Refresh => None,
        }
    }

    /// The trees whose work `node` does: its own, and those of every node
    /// that waits on it, directly or through others. A refresh does
    /// none's.
    fn served(&self, node: Node) -> BTreeSet<TreeId> {
        let mut trees = BTreeSet::new();
        let mut seen = BTreeSet::new();
        let mut todo = vec![node];
        while let Some(node) = todo.pop() {
            if !seen.insert(node) {
                continue;
            }
            trees.extend(self.tree_of(node));
            let dependents = match node {
                Node::Lookup(id) => self.lookups.get(&id).map(|l| &l.dependents),
                Node::Check(id) => self.checks.get(&id).map(|c| &c.dependents),
                Node::Asker(_) | Node::Refresh => None,
            };
            todo.extend(dependents.into_iter().flatten().copied());
        }
        trees
    }

    /// Counts one query against `tree`. Whether the tree may send it.
    fn charge(&mut self, tree: TreeId, limit: u16) -> bool {
        match self.trees.get_mut(&tree) {
            Some(entry) => {
                entry.sent = entry.sent.saturating_add(1);
                entry.sent <= limit
            }
            None => false,
        }
    }

    /// The question lookup `id` resolves, if it is running.
    pub(super) fn lookup_key(&self, id: LookupId) -> Option<Key> {
        self.lookups.get(&id).map(|lookup| lookup.key.clone())
    }

    /// Keeps lookup `id` going for the cache once `node` no longer waits
    /// on it.
    pub(super) fn refresh(&mut self, id: LookupId, node: Node) {
        if let Some(lookup) = self.lookups.get_mut(&id) {
            lookup.dependents.retain(|dependent| *dependent != node);
            if !lookup.dependents.contains(&Node::Refresh) {
                lookup.dependents.push(Node::Refresh);
            }
        }
    }

    /// When the next exchange times out.
    pub(super) fn next_deadline(&self) -> Option<Instant> {
        self.exchanges
            .values()
            .map(|exchange| exchange.deadline)
            .min()
    }

    /// Forgets every lookup, check, and tree, and returns the tokens of the
    /// exchanges that were outstanding.
    pub(super) fn clear(&mut self) -> Vec<Token> {
        let tokens = self.exchanges.keys().copied().collect();
        let next = self.next;
        *self = Graph::default();
        self.next = next;
        tokens
    }

    /// Whether `target` is `from` or a node that waits on `from`, directly
    /// or through others: whether `from` waiting on `target` would close a
    /// cycle.
    fn reaches(&self, from: Node, target: Node) -> bool {
        let mut seen = BTreeSet::new();
        let mut todo = vec![from];
        while let Some(node) = todo.pop() {
            if node == target {
                return true;
            }
            if !seen.insert(node) {
                continue;
            }
            let dependents = match node {
                Node::Lookup(id) => self.lookups.get(&id).map(|l| &l.dependents),
                Node::Check(id) => self.checks.get(&id).map(|c| &c.dependents),
                Node::Asker(_) | Node::Refresh => None,
            };
            todo.extend(dependents.into_iter().flatten().copied());
        }
        false
    }
}

impl<V: Verify> Resolver<V> {
    /// What the cache answers for `key` now, with TTLs counted down: an
    /// NXDOMAIN at the name or a Secure one above it (RFC 8020), what
    /// validated NSEC records prove (RFC 8198), the RRset, the negative or
    /// failure, or a CNAME at the name when the question
    /// [follows](follows_alias) it. Data below [`Rank::NonAuthAnswer`]
    /// never answers (RFC 2181 §5.4.1), and QTYPE ANY is always asked
    /// again.
    pub(super) fn cached(&self, key: &Key) -> Option<Found> {
        let now = self.now;
        if key.rtype == RecordType::ANY {
            return None;
        }
        if let Some((at, entry)) = self.cache.nxdomain_above(&key.name, key.class, now) {
            let found = self.found_negative(key, at, entry);
            if found.is_some() {
                return found;
            }
        }
        match self.cache.get(key, now) {
            Some(entry @ Entry::Positive { rank, .. }) if *rank >= Rank::NonAuthAnswer => {
                return Some(self.found_positive(entry, key.rtype, false));
            }
            Some(entry @ Entry::Negative { .. }) => {
                return self.found_negative(key, &key.name, entry);
            }
            Some(Entry::Failure { why, .. }) => {
                return Some(Found {
                    outcome: Outcome::Failure(*why),
                    checks: Vec::new(),
                    cached: true,
                    rest: Vec::new(),
                });
            }
            _ => {}
        }
        if follows_alias(key.rtype) {
            let alias = Key::new(key.name.clone(), RecordType::CNAME, key.class);
            if let Some(entry @ Entry::Positive { rank, .. }) = self.cache.get(&alias, now)
                && *rank >= Rank::NonAuthAnswer
            {
                return Some(self.found_positive(entry, key.rtype, false));
            }
        }
        self.aggressive(key)
    }

    /// [`cached`](Resolver::cached), less, for a lookup that relays a
    /// client's CD bit, a cached failure of servers that replied with
    /// errors to queries without CD: a server that validates may have
    /// failed only those (RFC 4035 §3.2.2). Any other failure holds for
    /// it too, so no query goes out until it expires (RFC 9520 §3.2).
    fn cached_for(&self, key: &Key, relay_cd: bool) -> Option<Found> {
        let without_cd = || {
            matches!(
                self.cache.get(key, self.now),
                Some(Entry::Failure {
                    why: FailureKind::Unknown,
                    cd: false,
                    ..
                })
            )
        };
        self.cached(key).filter(|found| {
            !(relay_cd && matches!(found.outcome, Outcome::Failure(_)) && without_cd())
        })
    }

    /// What the local zones give for `request`'s question, as the
    /// outcomes of an answer: the aliases its chain follows inside the
    /// zone that answers, then the data or the negative the chain ends
    /// in, or nothing more when the chain leaves the zone, where the
    /// answer goes on at the last alias's target (RFC 1034 §4.3.2 step 1
    /// and 3a). `None` when no local zone knows the answer, or the zone
    /// refers the name to a cut, whose servers the resolution then asks
    /// ([`local_cut`](Resolver::local_cut)).
    pub(super) fn local_outcomes(&mut self, request: &Request) -> Option<Vec<Outcome>> {
        let local = self.local_answer(request)?;
        let message = local.response.message;
        if !message.metadata.authoritative {
            return None;
        }
        let zone = local.zone;
        let sname = request.question.name().to_lowercase();
        let stype = request.question.query_type();
        let rcode = message.metadata.response_code;
        let answers: Vec<RecordSet> = match stype {
            RecordType::RRSIG => signatures(&message.answers),
            _ => rrsets(&message.answers),
        }
        .iter()
        .map(normalized)
        .collect();
        let authority: Vec<RecordSet> = rrsets(&message.authorities)
            .iter()
            .map(normalized)
            .collect();
        let denial: Vec<RecordSet> = authority
            .iter()
            .filter(|set| matches!(set.record_type(), RecordType::NSEC | RecordType::NSEC3))
            .cloned()
            .collect();
        let soa = authority
            .iter()
            .find(|set| set.record_type() == RecordType::SOA)
            .cloned();
        if rcode == ResponseCode::YXDomain {
            let (first, rest) = self.too_long(&answers, &sname, stype, None, &denial, &zone)?;
            return Some(std::iter::once(first).chain(rest).collect());
        }
        if !answers.is_empty() {
            // Nothing is offered to the cache: local data is the
            // resolver's own, and is asked of the zone each time.
            let (first, rest) =
                self.store_chain(&answers, &sname, stype, None, &denial, rcode, &soa, &zone)?;
            return Some(std::iter::once(first).chain(rest).collect());
        }
        let kind = match rcode {
            ResponseCode::NXDomain => Negative::NxDomain,
            ResponseCode::NoError => Negative::NoData,
            _ => return None,
        };
        Some(vec![Outcome::Negative {
            kind,
            name: sname,
            qtype: stype,
            soa,
            denial,
            zone,
        }])
    }

    /// A local zone's answer to `request`, when it is a referral to a cut
    /// below the zone (RFC 1034 §4.3.2 step 3b).
    pub(super) fn local_referral(&self, request: &Request) -> Option<Response> {
        let response = self.local_answer(request)?.response;
        let message = &response.message;
        let metadata = &message.metadata;
        let referral = !metadata.authoritative
            && metadata.response_code == ResponseCode::NoError
            && message.answers.is_empty();
        referral.then_some(response)
    }

    /// The zone cut a local zone refers `request`'s question to, when its
    /// answer is a referral. The name servers local data names are the
    /// best to ask for a name below the cut (RFC 1034 §5.3.3 step 2), so
    /// a resolution of it starts there, not at the root.
    pub(super) fn local_cut(&self, request: &Request) -> Option<LocalCut> {
        let message = self.local_referral(request)?.message;
        let mut cut = None;
        let mut targets = Vec::new();
        for record in &message.authorities {
            if let RData::NS(ns) = &record.data {
                cut = Some(LowerName::new(&record.name));
                targets.push(ns.0.to_lowercase());
            }
        }
        let mut glue: BTreeMap<LowerName, Vec<IpAddr>> = BTreeMap::new();
        for record in &message.additionals {
            if let Some(address) = record.data.ip_addr() {
                glue.entry(LowerName::new(&record.name))
                    .or_default()
                    .push(address);
            }
        }
        Some(LocalCut {
            cut: cut?,
            targets,
            glue,
        })
    }

    /// Expired data for `key`, for serving stale (RFC 8767 §4): the RRset
    /// or the negative, or else a CNAME at the name the question
    /// follows, as [`cached`](Resolver::cached) finds them.
    pub(super) fn stale_found(&self, key: &Key) -> Option<Found> {
        let found = match self.cache.stale(key, self.now) {
            Some(entry @ Entry::Positive { rank, .. }) if *rank >= Rank::NonAuthAnswer => {
                return Some(self.found_positive(entry, key.rtype, true));
            }
            Some(entry @ Entry::Negative { .. }) => self.found_negative(key, &key.name, entry),
            _ => None,
        };
        if found.is_some() || key.rtype == RecordType::ANY || !follows_alias(key.rtype) {
            return found;
        }
        let alias = Key::new(key.name.clone(), RecordType::CNAME, key.class);
        match self.cache.stale(&alias, self.now)? {
            entry @ Entry::Positive { rank, .. } if *rank >= Rank::NonAuthAnswer => {
                Some(self.found_positive(entry, key.rtype, true))
            }
            _ => None,
        }
    }

    /// A cached RRset as the outcome for a question of type `asked`, its
    /// TTL counted down to now, or set to zero for `stale` data, whose TTL
    /// the front sets.
    fn found_positive(&self, entry: &Entry, asked: RecordType, stale: bool) -> Found {
        let Entry::Positive {
            set,
            validation,
            proof,
            expires,
            ..
        } = entry
        else {
            unreachable!("found_positive takes a positive entry")
        };
        let remaining = if stale {
            0
        } else {
            ttl_left(*expires, self.now)
        };
        let set = with_ttl(set, remaining);
        let zone = self.zone_of(&set);
        let proof = proof.iter().map(|p| with_ttl(p, remaining)).collect();
        // A CNAME is the answer to a question for CNAME itself, and an
        // alias to follow for any other type (RFC 1034 §4.3.2 step 3a).
        let outcome = match (set.record_type(), cname_target(&set)) {
            (RecordType::CNAME, Some(target)) if asked != RecordType::CNAME => Outcome::Alias {
                target,
                proof,
                cname: set,
                zone,
            },
            _ => Outcome::Data {
                sets: vec![set],
                proof,
                zone,
            },
        };
        let checks = subjects(&outcome)
            .into_iter()
            .map(|subject| {
                let validation = self.recheck(&subject, &outcome, *validation);
                (subject, validation)
            })
            .collect();
        Found {
            outcome,
            checks,
            cached: true,
            rest: Vec::new(),
        }
    }

    /// A cached negative as the outcome for `key`. `at` is where the
    /// negative is cached, which for NXDOMAIN may be a name above the
    /// key's (RFC 8020): the NSEC records that deny `at` deny every name
    /// below it, so the outcome is checked again for the key's own name.
    fn found_negative(&self, key: &Key, at: &LowerName, entry: &Entry) -> Option<Found> {
        let Entry::Negative {
            kind,
            soa,
            denial,
            expires,
            validation,
            ..
        } = entry
        else {
            return None;
        };
        let remaining = ttl_left(*expires, self.now);
        let soa = with_ttl(soa, remaining);
        let zone = soa.name().clone();
        let outcome = Outcome::Negative {
            kind: *kind,
            name: Name::from(&key.name),
            qtype: key.rtype,
            soa: Some(soa),
            denial: denial.iter().map(|set| with_ttl(set, remaining)).collect(),
            zone,
        };
        let own = *at == key.name;
        let checks = subjects(&outcome)
            .into_iter()
            .map(|subject| {
                let validation = if own {
                    self.recheck(&subject, &outcome, *validation)
                } else {
                    Validation::NotPerformed
                };
                (subject, validation)
            })
            .collect();
        Some(Found {
            outcome,
            checks,
            cached: true,
            rest: Vec::new(),
        })
    }

    /// `stored`, the result the cache holds for `subject` of `outcome`, or
    /// `NotPerformed`, so that the subject is checked again, when the
    /// negative trust anchors changed under it since. A result validated
    /// before a negative trust anchor came to cover the subject counts for
    /// nothing below the anchor, where nothing is validated (RFC 7646 §2).
    /// An entry cached under a negative trust anchor counts as removed
    /// with the anchor (RFC 7646 §4). A result is Insecure for want of an
    /// anchor only below a negative trust anchor or where no trust anchor
    /// covers the zone.
    fn recheck(&self, subject: &Subject, outcome: &Outcome, stored: Validation) -> Validation {
        let no_anchor = Validation::Insecure(Insecure::NoAnchor);
        if self.negative_anchor(subject) {
            return if stored == no_anchor {
                stored
            } else {
                Validation::NotPerformed
            };
        }
        if stored != no_anchor {
            return stored;
        }
        let anchored = material(subject, outcome).is_some_and(|(_, zone)| {
            self.config
                .anchors
                .as_ref()
                .is_some_and(|anchors| anchors.closest(&zone, false).is_some())
        });
        if anchored {
            Validation::NotPerformed
        } else {
            stored
        }
    }

    /// The negative answer validated NSEC records prove for `key`, when
    /// the configuration uses them that way (RFC 8198 §5.1, §5.2).
    fn aggressive(&self, key: &Key) -> Option<Found> {
        if !self.config.aggressive_nsec {
            return None;
        }
        let (zone, soa, cached) = self.cache.secure_nsec(&key.name, self.now)?;
        let name = Name::from(&key.name);
        let zone_name = Name::from(zone);
        // The answer carries the records that prove it, and lives as long
        // as they do (RFC 8198 §5.4).
        let (kind, records) = match proof::nxdomain_nsecs(&name, &zone_name, &cached) {
            Some(records) => (Negative::NxDomain, records),
            None => (
                Negative::NoData,
                proof::nodata_nsecs(&name, key.rtype, &zone_name, &cached)?,
            ),
        };
        let ttl = records
            .iter()
            .map(RecordSet::ttl)
            .chain(std::iter::once(soa.ttl()))
            .min()
            .unwrap_or(0);
        let outcome = Outcome::Negative {
            kind,
            name,
            qtype: key.rtype,
            soa: Some(with_ttl(&soa, ttl)),
            denial: records.iter().map(|set| with_ttl(set, ttl)).collect(),
            zone: zone_name,
        };
        let subjects = subjects(&outcome);
        // Below a negative trust anchor nothing is validated (RFC 7646
        // §2), so validated NSEC records prove nothing there.
        if subjects.iter().any(|subject| self.negative_anchor(subject)) {
            return None;
        }
        let checks = subjects
            .into_iter()
            .map(|subject| (subject, Validation::Secure))
            .collect();
        Some(Found {
            outcome,
            checks,
            cached: true,
            rest: Vec::new(),
        })
    }

    /// The zone that holds `set`, for cached data: the signer of its
    /// RRSIGs, or else the deepest zone cut the cache knows above it
    /// (strictly above for DS, which the parent holds).
    fn zone_of(&self, set: &RecordSet) -> Name {
        if let Some(signer) = signer(set) {
            return signer;
        }
        let owner = LowerName::new(set.name());
        let strictly = set.record_type() == RecordType::DS;
        Name::from(
            &self
                .cut(&owner, strictly)
                .unwrap_or_else(|| LowerName::from(Name::root())),
        )
    }

    /// The deepest name at or above `name` (strictly above when
    /// `strictly`) with a live NS RRset in the cache.
    fn cut(&self, name: &LowerName, strictly: bool) -> Option<LowerName> {
        let mut at = name.clone();
        if strictly {
            if at.is_root() {
                return None;
            }
            at = at.base_name();
        }
        loop {
            let key = Key::new(at.clone(), RecordType::NS, DNSClass::IN);
            if matches!(
                self.cache.data(&key, self.now),
                Some(Entry::Positive { .. })
            ) {
                return Some(at);
            }
            if at.is_root() {
                return None;
            }
            at = at.base_name();
        }
    }

    /// The NS targets of the zone cut at `zone` in the cache.
    fn targets(&self, zone: &LowerName) -> Vec<Name> {
        let key = Key::new(zone.clone(), RecordType::NS, DNSClass::IN);
        match self.cache.data(&key, self.now) {
            Some(Entry::Positive { set, .. }) => set
                .records_without_rrsigs()
                .filter_map(|record| match &record.data {
                    RData::NS(ns) => Some(ns.0.to_lowercase()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    /// The cached addresses of `target`, at any rank.
    fn addresses(&self, target: &Name) -> Vec<IpAddr> {
        let mut out = Vec::new();
        for rtype in [RecordType::A, RecordType::AAAA] {
            let key = Key::new(LowerName::new(target), rtype, DNSClass::IN);
            if let Some(Entry::Positive { set, .. }) = self.cache.data(&key, self.now) {
                out.extend(
                    set.records_without_rrsigs()
                        .filter_map(|record| record.data.ip_addr()),
                );
            }
        }
        out
    }

    /// Makes `from` wait on the lookup of `key`, starting it when none
    /// runs, unless a local zone or the cache answers at once. Local data
    /// comes first for every name the resolver looks up, a name server's
    /// address or a DS or DNSKEY RRset as much as a client's question
    /// (RFC 1034 §5.3.3 step 2), so a name a local zone holds never
    /// leaves the resolver, such as the special-use names of RFC 6761
    /// §6.4 and RFC 7686 §2.
    ///
    /// With `relay_cd`, the lookup forwards a client's CD bit, as a
    /// forwarder that does not validate relays the client's header: it
    /// shares no lookup with questions asked without CD, and caches
    /// nothing it learns but its failure. A cached failure of servers that
    /// replied with errors to the question without CD does not answer it,
    /// since a server that validates may have failed only that question
    /// ([`cached_for`](Resolver::cached_for)).
    pub(super) fn depend(
        &mut self,
        from: Node,
        key: Key,
        relay_cd: bool,
        tree: TreeId,
        depth: u8,
        entropy: &dyn Entropy,
    ) -> Dep {
        let local = question_of(&key).and_then(|asked| self.local_outcomes(&asked));
        if let Some((outcome, rest)) = local.and_then(split) {
            // Local data is never validated.
            return Dep::Ready(Box::new(Found {
                outcome,
                checks: Vec::new(),
                cached: false,
                rest,
            }));
        }
        if let Some(found) = self.cached_for(&key, relay_cd) {
            return Dep::Ready(Box::new(found));
        }
        let shared = (key.clone(), relay_cd);
        if let Some(&id) = self.graph.by_key.get(&shared) {
            if self.graph.reaches(from, Node::Lookup(id)) {
                return Dep::Cycle;
            }
            if let Some(lookup) = self.graph.lookups.get_mut(&id) {
                lookup.dependents.push(from);
            }
            return Dep::Waiting(id);
        }
        if depth > self.config.work.depth {
            return Dep::TooDeep;
        }
        // A name below a local zone's cut is resolved from the servers the
        // cut names, as from a referral.
        let (delegation, learned) = match question_of(&key).and_then(|asked| self.local_cut(&asked))
        {
            Some(LocalCut { cut, targets, glue }) => (Some((cut, targets)), glue),
            None => (None, BTreeMap::new()),
        };
        let follows = self.cache.persisting(&key, self.now);
        let id = self.graph.lookup_id();
        self.graph.hold(tree);
        self.graph.by_key.insert(shared, id);
        self.graph.lookups.insert(
            id,
            Lookup {
                key,
                relay_cd,
                tree,
                depth,
                dependents: vec![from],
                tried: Vec::new(),
                timeouts: Vec::new(),
                errors: false,
                minimise: Minimising::default(),
                learned,
                asked: BTreeSet::new(),
                delegation,
                bounded: false,
                follows,
                wait: LookupWait::Nothing,
            },
        );
        self.plan(id, entropy);
        Dep::Waiting(id)
    }

    /// Decides lookup `id`'s next step from what the cache holds now: an
    /// answer, a query to a server of the deepest zone cut it knows, the
    /// lookups that step needs first, or failure.
    fn plan(&mut self, id: LookupId, entropy: &dyn Entropy) {
        let Some(lookup) = self.graph.lookups.get(&id) else {
            return;
        };
        let key = lookup.key.clone();
        if let Some(found) = self.cached_for(&key, lookup.relay_cd) {
            return self.finish(id, found);
        }
        if let Some((zone, servers)) = self.forward_for(&key) {
            let mut servers = servers.to_vec();
            servers.retain(|server| !lookup.tried.contains(&(*server, Transport::Udp)));
            if servers.is_empty() {
                return self.fail(id);
            }
            return self.ask_one(id, zone, servers, true, entropy);
        }
        // With no hints the resolver iterates only from a cut a local zone
        // names (RFC 1034 §5.3.3 step 2).
        if self.config.hints.is_empty() && lookup.delegation.is_none() {
            return self.fail(id);
        }
        let root = LowerName::from(Name::root());
        let priming = Key::new(root.clone(), RecordType::NS, DNSClass::IN);
        // Root NS with TTL 0 are not cached but serve the lookup they were
        // primed for, as its delegation (RFC 1035 §7.4).
        let primed = self.cut(&root, false).is_some() || lookup.delegation.is_some();
        if !primed {
            if key == priming {
                let mut hints = self.hint_servers();
                hints.retain(|server| !lookup.tried.contains(&(*server, Transport::Udp)));
                if hints.is_empty() {
                    return self.fail(id);
                }
                return self.ask_one(id, root, hints, false, entropy);
            }
            let (tree, depth) = (lookup.tree, lookup.depth);
            return match self.depend(Node::Lookup(id), priming, false, tree, depth + 1, entropy) {
                Dep::Waiting(prime) => self.wait_lookups(id, [prime].into()),
                Dep::Ready(found) => self.primed(id, found.outcome, entropy),
                Dep::Cycle => self.fail(id),
                Dep::TooDeep => {
                    self.bound(id);
                    self.fail(id)
                }
            };
        }

        // The parent holds a DS RRset, so it is asked of the cut above the
        // name. The root has no parent: its own servers answer `. DS`.
        let strictly = key.rtype == RecordType::DS && !key.name.is_root();
        let cached = self.cut(&key.name, strictly);
        let deeper = |cut: &LowerName| {
            cached
                .as_ref()
                .is_none_or(|cached| label_count(cut) > label_count(cached))
        };
        let (zone, targets) = match (&lookup.delegation, cached.clone()) {
            (Some((cut, targets)), _)
                if deeper(cut) && cut.zone_of(&key.name) && !(strictly && *cut == key.name) =>
            {
                (cut.clone(), targets.clone())
            }
            (_, Some(cached)) => {
                let targets = self.targets(&cached);
                (cached, targets)
            }
            // The lookup's delegation does not hold the name, and the cache
            // holds no other.
            (_, None) => return self.fail(id),
        };
        // A cut from the cache none of whose servers can be reached without
        // the cut itself is of no use: each name server lies under it with
        // no address known. The cut above it gives a fresh referral, with
        // glue (RFC 1034 §5.3.3, as Unbound's `iter_dp_is_useless`). A cut
        // this lookup was just referred to is used as it is: the cut above
        // gave it, and asking there again gives it again.
        let (zone, targets) = match &lookup.delegation {
            Some((cut, _)) if *cut == zone => (zone, targets),
            _ => self.usable_cut(&lookup.learned, zone, targets),
        };
        let mut servers: Vec<SocketAddr> = Vec::new();
        for target in &targets {
            let lower = LowerName::new(target);
            let learned = lookup.learned.get(&lower).into_iter().flatten().copied();
            for address in self.addresses(target).into_iter().chain(learned) {
                let server = SocketAddr::new(address, 53);
                if !servers.contains(&server) {
                    servers.push(server);
                }
            }
        }
        // After priming, the root's servers are the ones the priming
        // response gave, and the hints serve only when it gave none an
        // address (RFC 8109 §2).
        if zone.is_root() && servers.is_empty() {
            servers = self.hint_servers();
        }
        servers.retain(|server| !lookup.tried.contains(&(*server, Transport::Udp)));
        if !servers.is_empty() {
            return self.ask_one(id, zone, servers, false, entropy);
        }

        // No server of the cut is left to ask: look up the addresses of a
        // name server that came without glue.
        let (tree, depth) = (lookup.tree, lookup.depth);
        let glueless: Vec<Name> = targets
            .iter()
            .filter(|target| !lookup.asked.contains(&LowerName::new(target)))
            .filter(|target| !lookup.learned.contains_key(&LowerName::new(target)))
            .filter(|target| self.addresses(target).is_empty())
            .cloned()
            .collect();
        for target in glueless {
            let lower = LowerName::new(&target);
            if let Some(lookup) = self.graph.lookups.get_mut(&id) {
                lookup.asked.insert(lower.clone());
            }
            let mut waiting = BTreeSet::new();
            for rtype in [RecordType::A, RecordType::AAAA] {
                let key = Key::new(lower.clone(), rtype, DNSClass::IN);
                match self.depend(Node::Lookup(id), key, false, tree, depth + 1, entropy) {
                    Dep::Waiting(dep) => {
                        waiting.insert(dep);
                    }
                    Dep::Ready(found) => self.learn(id, &lower, &found.outcome),
                    Dep::Cycle => {}
                    Dep::TooDeep => self.bound(id),
                }
            }
            if !waiting.is_empty() {
                return self.wait_lookups(id, waiting);
            }
            if self
                .graph
                .lookups
                .get(&id)
                .is_some_and(|lookup| lookup.learned.contains_key(&lower))
            {
                return self.plan(id, entropy);
            }
        }
        self.fail(id)
    }

    /// `zone` and its name server `targets`, or the nearest cut above it
    /// the cache holds when no target has an address, cached or `learned`,
    /// and the cache would ask `zone` itself for every target's address.
    fn usable_cut(
        &self,
        learned: &BTreeMap<LowerName, Vec<IpAddr>>,
        mut zone: LowerName,
        mut targets: Vec<Name>,
    ) -> (LowerName, Vec<Name>) {
        loop {
            let useless = targets.iter().all(|target| {
                let lower = LowerName::new(target);
                !learned.contains_key(&lower)
                    && self.addresses(target).is_empty()
                    && self.cut(&lower, false).as_ref() == Some(&zone)
            });
            let parent = if useless && !targets.is_empty() {
                self.cut(&zone, true)
            } else {
                None
            };
            let Some(parent) = parent else {
                return (zone, targets);
            };
            targets = self.targets(&parent);
            zone = parent;
        }
    }

    fn hint_servers(&self) -> Vec<SocketAddr> {
        self.config
            .hints
            .iter()
            .map(|(_, address)| SocketAddr::new(*address, 53))
            .collect()
    }

    fn wait_lookups(&mut self, id: LookupId, waiting: BTreeSet<LookupId>) {
        if let Some(lookup) = self.graph.lookups.get_mut(&id) {
            lookup.wait = LookupWait::Lookups(waiting);
        }
    }

    /// Notes the addresses `outcome` holds for name server `target`.
    fn learn(&mut self, id: LookupId, target: &LowerName, outcome: &Outcome) {
        let Outcome::Data { sets, .. } = outcome else {
            return;
        };
        let addresses: Vec<IpAddr> = sets
            .iter()
            .flat_map(|set| {
                set.records_without_rrsigs()
                    .filter_map(|record| record.data.ip_addr())
            })
            .collect();
        if addresses.is_empty() {
            return;
        }
        if let Some(lookup) = self.graph.lookups.get_mut(&id) {
            lookup
                .learned
                .entry(target.clone())
                .or_default()
                .extend(addresses);
        }
    }

    /// What a lookup that lookup `id` waited for found, and whether the
    /// work bound stopped it.
    pub(super) fn lookup_looked(
        &mut self,
        id: LookupId,
        dep: LookupId,
        key: &Key,
        found: Found,
        bounded: bool,
        entropy: &dyn Entropy,
    ) {
        let Some(lookup) = self.graph.lookups.get_mut(&id) else {
            return;
        };
        let LookupWait::Lookups(waiting) = &mut lookup.wait else {
            return;
        };
        if !waiting.remove(&dep) {
            return;
        }
        lookup.bounded |= bounded;
        let done = waiting.is_empty();
        let priming = key.rtype == RecordType::NS && key.name.is_root();
        if !priming {
            self.learn(id, &key.name, &found.outcome);
        }
        if done {
            if let Some(lookup) = self.graph.lookups.get_mut(&id) {
                lookup.wait = LookupWait::Nothing;
            }
            if priming {
                return self.primed(id, found.outcome, entropy);
            }
            self.plan(id, entropy);
        }
    }

    /// Goes on with lookup `id` from what priming the root found. Root NS
    /// that the cache did not keep, such as with TTL 0, become the
    /// lookup's delegation, which serves it alone (RFC 1035 §7.4). A
    /// failure, or no NS RRset, ends the lookup.
    fn primed(&mut self, id: LookupId, outcome: Outcome, entropy: &dyn Entropy) {
        let sets = match outcome {
            Outcome::Failure(why) => return self.finish(id, Found::fresh(Outcome::Failure(why))),
            Outcome::Data { sets, .. } => sets,
            _ => return self.fail(id),
        };
        let root = LowerName::from(Name::root());
        if self.cut(&root, false).is_none() {
            let targets: Vec<Name> = sets
                .iter()
                .flat_map(|set| set.records_without_rrsigs())
                .filter_map(|record| match &record.data {
                    RData::NS(ns) => Some(ns.0.to_lowercase()),
                    _ => None,
                })
                .collect();
            if targets.is_empty() {
                return self.fail(id);
            }
            if let Some(lookup) = self.graph.lookups.get_mut(&id) {
                lookup.delegation = Some((root, targets));
            }
        }
        self.plan(id, entropy);
    }

    /// Ends lookup `id` with no server left to ask, caching the failure
    /// (RFC 9520 §3.2) unless the work bound caused it.
    fn fail(&mut self, id: LookupId) {
        let Some(lookup) = self.graph.lookups.get(&id) else {
            return;
        };
        let why = if lookup.bounded {
            self.bound_failure(lookup.tree)
        } else if lookup.errors {
            FailureKind::Unknown
        } else {
            FailureKind::NoReachableAuthority
        };
        if !lookup.bounded {
            let offer = Offer::Failure {
                key: lookup.key.clone(),
                why,
                cd: self.sends_cd(lookup.relay_cd),
                follows: lookup.follows,
            };
            self.cache.insert(self.now, offer);
        }
        self.finish(id, Found::fresh(Outcome::Failure(why)));
    }

    /// Whether a lookup's queries set CD. RFC 6840 §5.9: a validating
    /// resolver sets it, so it gets the data even where the server would
    /// find it bogus, and judges it itself. A forwarder that does not
    /// validate sets it as the client did, `relay_cd` (RFC 4035 §3.2.2).
    fn sends_cd(&self, relay_cd: bool) -> bool {
        self.config.anchors.is_some() || relay_cd
    }

    /// Why a question of `tree` failed when the work bound stopped it
    /// (RFC 1034 §5.3.3): the bound, unless no server replied to any of
    /// the question's queries, when every server failed (RFC 8914
    /// §4.23).
    fn bound_failure(&self, tree: TreeId) -> FailureKind {
        if self.graph.trees.get(&tree).is_some_and(|tree| tree.replied) {
            FailureKind::WorkExceeded
        } else {
            FailureKind::NoReachableAuthority
        }
    }

    /// Hands lookup `id`, whose tree `spent` has used up the work bound,
    /// to another tree it does work for that has not, and returns that
    /// tree. The bound is per client question (RFC 1034 §5.3.3), so a
    /// question that joined a lookup another one started pays for the
    /// rest of it from its own bound, and so for the lookups and checks
    /// that lookup waits on, however deep. The nodes waiting on `id` that
    /// do work for `spent` alone stop waiting, with the failure the bound
    /// makes. `None` when no other tree it does work for has queries left.
    fn take_over(&mut self, id: LookupId, spent: TreeId) -> Option<TreeId> {
        let limit = self.config.work.queries;
        let lookup = self.graph.lookups.get(&id)?;
        let served: Vec<(Node, BTreeSet<TreeId>)> = lookup
            .dependents
            .iter()
            .map(|node| (*node, self.graph.served(*node)))
            .collect();
        let next = served
            .iter()
            .flat_map(|(_, trees)| trees)
            .copied()
            .find(|tree| *tree != spent && self.graph.within(*tree, limit))?;
        let (gone, kept): (Vec<_>, Vec<_>) = served
            .into_iter()
            .partition(|(_, trees)| !trees.is_empty() && trees.iter().all(|tree| *tree == spent));
        let gone: Vec<Node> = gone.into_iter().map(|(node, _)| node).collect();
        let kept: Vec<Node> = kept.into_iter().map(|(node, _)| node).collect();
        let key = lookup.key.clone();
        let failure = Found::fresh(Outcome::Failure(self.bound_failure(spent)));
        self.graph.hold(next);
        self.graph.release(spent);
        if let Some(lookup) = self.graph.lookups.get_mut(&id) {
            lookup.tree = next;
            lookup.dependents = kept;
        }
        for to in gone {
            self.graph.ready.push_back(Ready::Looked {
                to,
                lookup: id,
                key: key.clone(),
                found: Box::new(failure.clone()),
                bounded: true,
            });
        }
        Some(next)
    }

    /// Notes that the work bound stopped lookup `id` or something it
    /// needed.
    fn bound(&mut self, id: LookupId) {
        if let Some(lookup) = self.graph.lookups.get_mut(&id) {
            lookup.bounded = true;
        }
    }

    /// Ends lookup `id` with `found`, for every node that waited on it.
    fn finish(&mut self, id: LookupId, found: Found) {
        let Some(lookup) = self.graph.lookups.remove(&id) else {
            return;
        };
        self.graph
            .by_key
            .remove(&(lookup.key.clone(), lookup.relay_cd));
        self.graph.release(lookup.tree);
        if let LookupWait::Exchange(token) = lookup.wait {
            self.graph.exchanges.remove(&token);
        }
        for to in lookup.dependents {
            self.graph.ready.push_back(Ready::Looked {
                to,
                lookup: id,
                key: lookup.key.clone(),
                found: Box::new(found.clone()),
                bounded: lookup.bounded,
            });
        }
    }

    /// The deepest forward zone ([`Config::forward`](super::Config::forward))
    /// that holds `name`, with its servers. At equal depth, the zone given
    /// last.
    fn forward_zone(&self, name: &LowerName) -> Option<(LowerName, &[SocketAddr])> {
        self.config
            .forward
            .iter()
            .map(|(zone, servers)| (LowerName::new(zone), servers))
            .filter(|(zone, _)| zone.zone_of(name))
            .max_by_key(|(zone, _)| label_count(zone))
            .map(|(zone, servers)| (zone, servers.as_slice()))
    }

    /// The forward zone whose servers `key` is asked of. A DS RRset is
    /// the parent's data (RFC 4035 §2.4), so the DS at a forward zone's
    /// apex is asked where the parent's data is: of the forward zone that
    /// holds the parent, or by iteration. The root has no parent.
    pub(super) fn forward_for(&self, key: &Key) -> Option<(LowerName, &[SocketAddr])> {
        if key.rtype == RecordType::DS && !key.name.is_root() {
            self.forward_zone(&key.name.base_name())
        } else {
            self.forward_zone(&key.name)
        }
    }

    /// Sends lookup `id`'s next question to one of `servers`, chosen at
    /// random: to a server that resolves it, with RD set, when
    /// `forwarded`, and otherwise to an authority for `zone`.
    fn ask_one(
        &mut self,
        id: LookupId,
        zone: LowerName,
        servers: Vec<SocketAddr>,
        forwarded: bool,
        entropy: &dyn Entropy,
    ) {
        let servers = self.servers.band(&servers, self.now);
        let index = entropy.random_below(servers.len() as u64) as usize;
        let to = servers[index];
        let Some((name, rtype, minimised)) = self.next_question(id, &zone, forwarded) else {
            return;
        };
        let asking = Asking {
            zone,
            to,
            transport: Transport::Udp,
            question: Query::query(name, rtype),
            minimised,
            forwarded,
        };
        self.send(id, asking, entropy);
    }

    /// The question lookup `id` asks a server of `zone` next: the whole
    /// question, or with QNAME minimisation the name a few labels past
    /// what is known, with QTYPE A (RFC 9156 §2.3).
    fn next_question(
        &self,
        id: LookupId,
        zone: &LowerName,
        forwarded: bool,
    ) -> Option<(Name, RecordType, bool)> {
        let lookup = self.graph.lookups.get(&id)?;
        let qname = Name::from(&lookup.key.name);
        let whole = (qname.clone(), lookup.key.rtype, false);
        let Some(bounds) = self.config.minimise else {
            return Some(whole);
        };
        let priming = lookup.key.name.is_root();
        if forwarded || priming || lookup.minimise.off {
            return Some(whole);
        }
        let mut known = label_count(zone);
        if let Some(through) = &lookup.minimise.through
            && zone.zone_of(through)
            && through.zone_of(&lookup.key.name)
        {
            known = known.max(label_count(through));
        }
        let total = label_count(&qname);
        let steps = lookup.minimise.steps;
        if known + 1 >= total || steps >= bounds.max_queries {
            return Some(whole);
        }
        // The labels not yet shown are divided over the queries left, and
        // the remainder goes to the last ones (RFC 9156 §2.3): rounding
        // down here leaves it for the queries after this one.
        let add = if steps < bounds.one_label {
            1
        } else {
            let left = usize::from(bounds.max_queries - steps);
            ((total - known) / left).max(1)
        };
        let labels = known + add;
        if labels >= total {
            return Some(whole);
        }
        Some((qname.trim_to(labels), RecordType::A, true))
    }

    /// Sends one query for lookup `id` and waits for it.
    fn send(&mut self, id: LookupId, asking: Asking, entropy: &dyn Entropy) {
        let Asking {
            zone,
            to,
            transport,
            question,
            minimised,
            forwarded,
        } = asking;
        let Some(lookup) = self.graph.lookups.get(&id) else {
            return;
        };
        let (mut tree, relay_cd) = (lookup.tree, lookup.relay_cd);
        while !self.graph.charge(tree, self.config.work.queries) {
            match self.take_over(id, tree) {
                Some(next) => tree = next,
                None => {
                    // Past the bound, the question fails. The bound is one
                    // tree's, so the failure is not cached.
                    let why = self.bound_failure(tree);
                    self.bound(id);
                    return self.finish(id, Found::fresh(Outcome::Failure(why)));
                }
            }
        }
        let mut name = question.name().clone();
        if self.config.case_randomise {
            name = randomise_case(&name, entropy);
        }
        let mut bytes = [0u8; 2];
        entropy.fill_random(&mut bytes);
        let message_id = u16::from_be_bytes(bytes);
        let question = Query::query(name, question.query_type());
        let mut message = Message::new(message_id, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = forwarded;
        message.metadata.checking_disabled = self.sends_cd(relay_cd);
        message.add_query(question.clone());
        let priming = question.name().is_root() && question.query_type() == RecordType::NS;
        let payload = if priming {
            self.config.payload.max(PRIMING_PAYLOAD)
        } else {
            self.config.payload.max(512)
        };
        let mut edns = Edns::new();
        edns.set_max_payload(payload).set_dnssec_ok(true);
        message.set_edns(edns);
        let bytes = message
            .to_vec()
            .expect("a query with one question and an OPT record writes");
        let token = self.tokens.issue();
        // A query over TCP waits one round trip more, for the handshake.
        let wait = match transport {
            Transport::Udp => self.servers.timeout(to.ip(), self.now),
            Transport::Tcp => self.servers.timeout(to.ip(), self.now) * 2,
        };
        self.graph.exchanges.insert(
            token,
            Exchange {
                lookup: id,
                to,
                transport,
                id: message_id,
                question,
                zone,
                minimised,
                forwarded,
                sent: self.now,
                deadline: self.now + wait,
            },
        );
        if let Some(lookup) = self.graph.lookups.get_mut(&id) {
            lookup.wait = LookupWait::Exchange(token);
        }
        self.queue.push_back(Action::Send(Transmit {
            token,
            to,
            transport,
            bytes,
        }));
    }

    /// The exchange `token` names, if it is outstanding in the current
    /// generation.
    fn outstanding(&self, token: Token) -> Result<&Exchange, Unmatched> {
        outstanding(&self.tokens, &self.graph.exchanges, token)
    }

    /// The reply `bytes`, if it answers `token`'s exchange: from the
    /// address and over the transport the query went to, with its ID and
    /// question, the QNAME in the exact case sent when the case was
    /// randomised (RFC 5452 §9.1).
    fn matching(
        &self,
        token: Token,
        from: SocketAddr,
        transport: Transport,
        bytes: &[u8],
    ) -> Result<Message, Unmatched> {
        let exchange = self.outstanding(token)?;
        let sent = Sent {
            to: exchange.to,
            transport: exchange.transport,
            asked: Some((exchange.id, &exchange.question)),
            exact_case: self.config.case_randomise,
        };
        matching(&sent, from, transport, bytes)
    }

    fn ignore(&mut self, token: Token, from: Option<SocketAddr>, why: Unmatched) {
        self.queue.push_back(ignored(self.now, token, from, why));
    }

    fn upstream(&mut self, token: Token, exchange: &Exchange, outcome: UpstreamOutcome) {
        self.queue.push_back(Action::Event(Event::Upstream {
            at: self.now,
            token,
            to: exchange.to,
            transport: exchange.transport,
            question: exchange.question.clone(),
            outcome,
        }));
    }

    /// Takes a reply for an exchange.
    pub(super) fn reply(
        &mut self,
        token: Token,
        from: SocketAddr,
        transport: Transport,
        bytes: &[u8],
        entropy: &dyn Entropy,
    ) {
        let message = match self.matching(token, from, transport, bytes) {
            Ok(message) => message,
            Err(why) => return self.ignore(token, Some(from), why),
        };
        let exchange = self
            .graph
            .exchanges
            .remove(&token)
            .expect("a matching reply's exchange is outstanding");
        let size = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
        let outcome = UpstreamOutcome::Reply {
            rcode: message.metadata.response_code,
            truncated: message.metadata.truncation,
            size,
        };
        self.upstream(token, &exchange, outcome);
        self.servers
            .replied(exchange.to.ip(), rtt(exchange.sent, self.now), self.now);
        if let Some(lookup) = self.graph.lookups.get_mut(&exchange.lookup) {
            lookup.wait = LookupWait::Nothing;
            if let Some(tree) = self.graph.trees.get_mut(&lookup.tree) {
                tree.replied = true;
            }
        }
        self.answered(exchange, message, entropy);
    }

    /// Takes an exchange that ended without a reply.
    pub(super) fn failed(&mut self, token: Token, failure: ExchangeFailure, entropy: &dyn Entropy) {
        if let Err(why) = self.outstanding(token) {
            return self.ignore(token, None, why);
        }
        let exchange = self
            .graph
            .exchanges
            .remove(&token)
            .expect("the exchange is outstanding");
        self.upstream(token, &exchange, UpstreamOutcome::Failed(failure));
        self.give_up(exchange, false, entropy);
    }

    /// Takes what a lookup gave. A resolver starts no lookups, so `token`
    /// names none of its own and the input changes nothing.
    pub(super) fn looked(&mut self, token: Token) {
        let why = match self.outstanding(token) {
            Err(Unmatched::OldGeneration) => Unmatched::OldGeneration,
            Ok(_) | Err(_) => Unmatched::NotOutstanding,
        };
        self.ignore(token, None, why);
    }

    /// Times out every exchange whose deadline has passed.
    pub(super) fn expire(&mut self, entropy: &dyn Entropy) {
        let expired: Vec<Token> = self
            .graph
            .exchanges
            .iter()
            .filter(|(_, exchange)| exchange.deadline <= self.now)
            .map(|(token, _)| *token)
            .collect();
        for token in expired {
            let Some(exchange) = self.graph.exchanges.remove(&token) else {
                continue;
            };
            self.queue.push_back(Action::Abandon(token));
            self.upstream(token, &exchange, UpstreamOutcome::Timeout);
            self.timed_out(exchange, entropy);
        }
    }

    /// Asks `exchange`'s question again after it timed out: over TCP of
    /// the same server, which already sent a truncated reply, and over UDP
    /// of whichever server the lookup picks next. A server address that
    /// timed out [`TRIES`] times over a transport is given up on.
    fn timed_out(&mut self, exchange: Exchange, entropy: &dyn Entropy) {
        self.servers.lost(exchange.to.ip(), self.now);
        let Some(lookup) = self.graph.lookups.get_mut(&exchange.lookup) else {
            return;
        };
        let index = lookup
            .timeouts
            .iter()
            .position(|(to, transport, _)| (*to, *transport) == (exchange.to, exchange.transport))
            .unwrap_or_else(|| {
                lookup.timeouts.push((exchange.to, exchange.transport, 0));
                lookup.timeouts.len() - 1
            });
        let timeouts = &mut lookup.timeouts[index].2;
        *timeouts += 1;
        if *timeouts >= TRIES {
            return self.give_up(exchange, false, entropy);
        }
        lookup.wait = LookupWait::Nothing;
        match exchange.transport {
            Transport::Tcp => {
                let Exchange {
                    lookup,
                    zone,
                    to,
                    question,
                    minimised,
                    forwarded,
                    ..
                } = exchange;
                let asking = Asking {
                    zone,
                    to,
                    transport: Transport::Tcp,
                    question,
                    minimised,
                    forwarded,
                };
                self.send(lookup, asking, entropy);
            }
            Transport::Udp => self.plan(exchange.lookup, entropy),
        }
    }

    /// Notes that `exchange`'s server failed over its transport, and over
    /// UDP too when it failed over TCP after a truncated reply, then lets
    /// the lookup try another. `errors` says the server replied with
    /// something unusable.
    fn give_up(&mut self, exchange: Exchange, errors: bool, entropy: &dyn Entropy) {
        let Some(lookup) = self.graph.lookups.get_mut(&exchange.lookup) else {
            return;
        };
        lookup.tried.push((exchange.to, exchange.transport));
        if exchange.transport == Transport::Tcp {
            lookup.tried.push((exchange.to, Transport::Udp));
        }
        lookup.errors |= errors;
        lookup.wait = LookupWait::Nothing;
        self.plan(exchange.lookup, entropy);
    }

    /// Acts on a matching reply to `exchange`.
    fn answered(&mut self, exchange: Exchange, message: Message, entropy: &dyn Entropy) {
        let id = exchange.lookup;
        let Some(lookup) = self.graph.lookups.get(&id) else {
            return;
        };
        let key = lookup.key.clone();
        let truncated = message.metadata.truncation;
        if truncated {
            // RFC 7766 §5: a truncated reply over UDP is asked again over
            // TCP, of the same server. Over TCP it is a broken server.
            return match exchange.transport {
                Transport::Udp => {
                    let Exchange {
                        zone,
                        to,
                        question,
                        minimised,
                        forwarded,
                        ..
                    } = exchange;
                    let asking = Asking {
                        zone,
                        to,
                        transport: Transport::Tcp,
                        question,
                        minimised,
                        forwarded,
                    };
                    self.send(id, asking, entropy)
                }
                Transport::Tcp => self.give_up(exchange, true, entropy),
            };
        }
        let rcode = message.metadata.response_code;
        if !matches!(
            rcode,
            ResponseCode::NoError | ResponseCode::NXDomain | ResponseCode::YXDomain
        ) {
            return self.give_up(exchange, true, entropy);
        }

        let zone = Name::from(&exchange.zone);
        let sname = exchange.question.name().to_lowercase();
        let stype = exchange.question.query_type();
        let authoritative = message.metadata.authoritative || exchange.forwarded;
        // A question for RRSIG gets the signatures themselves as its
        // answer; for any other type they go with the RRsets they cover.
        let answers = match stype {
            RecordType::RRSIG => signatures(&message.answers),
            _ => rrsets(&message.answers),
        };
        let authority = rrsets(&message.authorities);
        // A forwarder answers the whole question (RFC 1034 §4.3.1), so
        // its reply carries what the zone that holds the name sends with
        // the answer, even when that zone's apex lies above the forward
        // zone: the SOA and denial records of a negative (RFC 2308 §2.1),
        // the denial records that show a wildcard had no closer match
        // (RFC 4035 §3.1.3.3), and the DNAME a CNAME was synthesized from
        // (RFC 6672 §3.1). Such a reply is bounded by that zone, which
        // the SOA's owner, the signer of the answer, or the DNAME's owner
        // shows.
        let bound = if exchange.forwarded {
            let soa = authority
                .iter()
                .filter(|set| set.record_type() == RecordType::SOA)
                .map(|set| set.name().to_lowercase());
            let signers = answers.iter().filter_map(signer);
            let dname = answers
                .iter()
                .filter(|set| is_dname(set))
                .map(|set| set.name().to_lowercase());
            soa.chain(signers)
                .chain(dname)
                .filter(|apex| apex.zone_of(&sname) && apex.zone_of(&zone))
                .min_by_key(Name::num_labels)
                .unwrap_or_else(|| zone.clone())
        } else {
            zone.clone()
        };
        let answers: Vec<RecordSet> = answers
            .iter()
            .filter(|set| bound.zone_of(set.name()))
            .map(normalized)
            .collect();
        let authority: Vec<RecordSet> = authority
            .iter()
            .filter(|set| bound.zone_of(set.name()))
            .map(normalized)
            .collect();
        let additional: Vec<RecordSet> = rrsets(&message.additionals)
            .iter()
            .map(normalized)
            .collect();
        let denial: Vec<RecordSet> = authority
            .iter()
            .filter(|set| matches!(set.record_type(), RecordType::NSEC | RecordType::NSEC3))
            .cloned()
            .collect();
        let soa = authority
            .iter()
            .find(|set| set.record_type() == RecordType::SOA && set.name().zone_of(&sname))
            .cloned();
        let rank = if exchange.forwarded {
            Rank::NonAuthAnswer
        } else {
            Rank::AuthAnswer
        };
        // What a lookup that relays a client's CD bit learns may be data a
        // validating upstream fails for every client without CD (RFC 4035
        // §3.2.2), so it serves that lookup alone and is never cached.
        let rank = (!lookup.relay_cd).then_some(rank);

        if rcode == ResponseCode::YXDomain {
            // RFC 6672 §2.2: the DNAME above the name the chain reached
            // would make it longer than a name may be. With the chain and
            // the DNAME, that is the answer.
            let too_long = authoritative
                .then(|| self.too_long(&answers, &sname, stype, rank, &denial, &zone))
                .flatten();
            return match too_long {
                Some((outcome, rest)) => self.finish(
                    id,
                    Found {
                        rest,
                        ..Found::fresh(outcome)
                    },
                ),
                None => self.give_up(exchange, true, entropy),
            };
        }

        if !answers.is_empty() {
            if !authoritative {
                return self.give_up(exchange, true, entropy);
            }
            let Some((outcome, rest)) =
                self.store_chain(&answers, &sname, stype, rank, &denial, rcode, &soa, &zone)
            else {
                return self.give_up(exchange, true, entropy);
            };
            if rank.is_some() {
                self.store_glue(&answers, &additional, &zone);
            }
            if exchange.minimised {
                return self.through(id, &sname, entropy);
            }
            return self.finish(
                id,
                Found {
                    rest,
                    ..Found::fresh(outcome)
                },
            );
        }

        if rcode == ResponseCode::NXDomain {
            if !authoritative {
                return self.give_up(exchange, true, entropy);
            }
            if exchange.minimised {
                // RFC 9156 §2.3: an NXDOMAIN for a minimised name may come
                // from an authority that does not know RFC 8020, so the
                // whole question is asked instead.
                if let Some(lookup) = self.graph.lookups.get_mut(&id) {
                    lookup.minimise.off = true;
                }
                return self.plan(id, entropy);
            }
            return self.negative(id, &key, Negative::NxDomain, rank, soa, denial, zone);
        }

        let referral = authority
            .iter()
            .find(|set| set.record_type() == RecordType::NS && *set.name() != zone);
        if soa.is_none()
            && let Some(ns) = referral
        {
            let cut = ns.name().to_lowercase();
            // RFC 1034 §5.3.3: a referral moves strictly closer to the
            // name. Anything else is a broken server. DS is the parent's
            // data (RFC 4035 §2.4), so it is asked of the zone above the
            // name, and a referral to the name itself leads back there. A
            // forwarder was asked to recurse (RFC 1034 §4.3.1), so a
            // referral from it is no step closer: it does not recurse.
            let to_ds_owner = stype == RecordType::DS && cut == sname;
            if exchange.forwarded || !cut.zone_of(&sname) || to_ds_owner {
                return self.give_up(exchange, true, entropy);
            }
            self.cache.insert(
                self.now,
                Offer::Positive {
                    set: ns.clone(),
                    rank: Rank::NonAuthAuthority,
                    validation: Validation::NotPerformed,
                    proof: Vec::new(),
                    truncated,
                },
            );
            let glue = self.store_glue(std::slice::from_ref(ns), &additional, &zone);
            let targets: Vec<Name> = ns
                .records_without_rrsigs()
                .filter_map(|record| match &record.data {
                    RData::NS(ns) => Some(ns.0.to_lowercase()),
                    _ => None,
                })
                .collect();
            if let Some(lookup) = self.graph.lookups.get_mut(&id) {
                lookup.minimise.steps += u8::from(exchange.minimised);
                lookup.delegation = Some((LowerName::new(&cut), targets));
                for set in glue {
                    let addresses = set
                        .records_without_rrsigs()
                        .filter_map(|record| record.data.ip_addr());
                    lookup
                        .learned
                        .entry(LowerName::new(set.name()))
                        .or_default()
                        .extend(addresses);
                }
            }
            return self.plan(id, entropy);
        }

        if !authoritative {
            return self.give_up(exchange, true, entropy);
        }
        if exchange.minimised {
            return self.through(id, &sname, entropy);
        }
        self.negative(id, &key, Negative::NoData, rank, soa, denial, zone)
    }

    /// Notes that `name`, a minimised question's name, is no zone cut, and
    /// goes on one step deeper.
    fn through(&mut self, id: LookupId, name: &Name, entropy: &dyn Entropy) {
        if let Some(lookup) = self.graph.lookups.get_mut(&id) {
            lookup.minimise.through = Some(LowerName::new(name));
            lookup.minimise.steps += 1;
        }
        self.plan(id, entropy);
    }

    /// Ends lookup `id` with a negative answer, offered to the cache at
    /// `rank`, or to nothing when `rank` is `None`.
    #[allow(clippy::too_many_arguments)]
    fn negative(
        &mut self,
        id: LookupId,
        key: &Key,
        kind: Negative,
        rank: Option<Rank>,
        soa: Option<RecordSet>,
        denial: Vec<RecordSet>,
        zone: Name,
    ) {
        if let Some(rank) = rank {
            self.cache.insert(
                self.now,
                Offer::Negative {
                    key: key.clone(),
                    kind,
                    soa: soa.clone(),
                    rank,
                    denial: denial.clone(),
                    validation: Validation::NotPerformed,
                    truncated: false,
                },
            );
        }
        let zone = soa.as_ref().map_or(zone, |soa| soa.name().to_lowercase());
        // The client sees the SOA at the negative TTL, as from the cache.
        let soa = soa.map(|soa| {
            let ttl = self.cache.negative_ttl(&soa, &denial).as_secs();
            with_ttl(&soa, u32::try_from(ttl).unwrap_or(u32::MAX))
        });
        let outcome = Outcome::Negative {
            kind,
            name: Name::from(&key.name),
            qtype: key.rtype,
            soa,
            denial,
            zone,
        };
        self.finish(id, Found::fresh(outcome));
    }

    /// Offers the answer section's chain for `sname` and `stype` to the
    /// cache at `rank`, or to nothing when `rank` is `None`: the RRsets of
    /// the asked type at the name, or the CNAMEs from it and what they lead
    /// to inside the zone. When the chain ends in the zone without data,
    /// the reply's RCODE and SOA are the last name's (RFC 6604 §2), and
    /// that negative is offered too. Returns what the answer says about
    /// `sname` itself, or `None` when it holds nothing for it, and then
    /// what it says about each alias target in turn, which serves this
    /// resolution whether or not the cache keeps it (RFC 1035 §7.4).
    #[allow(clippy::too_many_arguments)]
    fn store_chain(
        &mut self,
        answers: &[RecordSet],
        sname: &Name,
        stype: RecordType,
        rank: Option<Rank>,
        denial: &[RecordSet],
        rcode: ResponseCode,
        soa: &Option<RecordSet>,
        zone: &Name,
    ) -> Option<(Outcome, Vec<Outcome>)> {
        let mut chain = Vec::new();
        let mut at = sname.clone();
        let mut seen = Vec::new();
        loop {
            if seen.contains(&at) {
                return split(chain);
            }
            seen.push(at.clone());
            // A CNAME synthesized from a DNAME has no RRSIG of its own;
            // the DNAME above it vouches for it (RFC 6672 §3.4), whether
            // the CNAME is followed or is itself the data asked for. One
            // expanded from a wildcard needs the denial records that show
            // no closer name matched (RFC 4035 §5.3.4), and any other
            // RRset none: the denial records of the reply belong to the
            // negative its chain ends in (RFC 4035 §3.1.3).
            let dname: Vec<RecordSet> = answers
                .iter()
                .filter(|set| is_dname(set))
                .filter(|set| set.name().zone_of(&at) && *set.name() != at)
                .cloned()
                .collect();
            let proof_for = |sets: &[&RecordSet]| -> Vec<RecordSet> {
                let mut proof = dname.clone();
                for set in sets {
                    for record in expansion_proof(set, zone, denial) {
                        if !proof.contains(&record) {
                            proof.push(record);
                        }
                    }
                }
                proof
            };
            let here: Vec<RecordSet> = answers
                .iter()
                .filter(|set| *set.name() == at)
                .filter(|set| stype == RecordType::ANY || set.record_type() == stype)
                .cloned()
                .collect();
            if !here.is_empty() {
                for set in &dname {
                    self.offer(set, rank, Vec::new());
                }
                for set in &here {
                    self.offer(set, rank, proof_for(&[set]));
                }
                chain.push(Outcome::Data {
                    proof: proof_for(&here.iter().collect::<Vec<_>>()),
                    sets: here,
                    zone: zone.clone(),
                });
                return split(chain);
            }
            let Some(cname) = answers
                .iter()
                .find(|set| *set.name() == at && set.record_type() == RecordType::CNAME)
            else {
                break;
            };
            let target = cname_target(cname)?;
            for set in &dname {
                self.offer(set, rank, Vec::new());
            }
            let proof = proof_for(&[cname]);
            self.offer(cname, rank, proof.clone());
            chain.push(Outcome::Alias {
                cname: cname.clone(),
                target: target.clone(),
                proof,
                zone: zone.clone(),
            });
            if !zone.zone_of(&target) {
                return split(chain);
            }
            at = target;
        }
        // The chain ended inside the zone without data for the type.
        if let (false, Some(soa)) = (chain.is_empty(), soa) {
            let kind = match rcode {
                ResponseCode::NXDomain => Negative::NxDomain,
                _ => Negative::NoData,
            };
            // The negative is the SOA's zone's, and only that zone's
            // denial records prove it (RFC 4035 §5.4). The proofs of the
            // chain's wildcard aliases may come from other zones.
            let denial: Vec<RecordSet> = denial
                .iter()
                .filter(|set| proof::of_zone(set, soa.name()))
                .cloned()
                .collect();
            let denial = denial.as_slice();
            if let Some(rank) = rank {
                self.cache.insert(
                    self.now,
                    Offer::Negative {
                        key: Key::new(LowerName::new(&at), stype, DNSClass::IN),
                        kind,
                        soa: Some(soa.clone()),
                        rank,
                        denial: denial.to_vec(),
                        validation: Validation::NotPerformed,
                        truncated: false,
                    },
                );
            }
            // The client sees the SOA at the negative TTL, as from the
            // cache.
            let ttl = self.cache.negative_ttl(soa, denial).as_secs();
            chain.push(Outcome::Negative {
                kind,
                name: at,
                qtype: stype,
                soa: Some(with_ttl(soa, u32::try_from(ttl).unwrap_or(u32::MAX))),
                denial: denial.to_vec(),
                zone: soa.name().to_lowercase(),
            });
        }
        split(chain)
    }

    /// The outcomes of a YXDOMAIN answer to `sname` from `zone`, offered
    /// to the cache at `rank` as [`store_chain`](Resolver::store_chain)
    /// does: the aliases its CNAME chain follows inside the zone, then the
    /// DNAME above the name the chain reached, whose new name would pass
    /// 255 octets (RFC 6672 §2.2). The RCODE is the last name's
    /// (RFC 6604 §2). `None` when the answer holds no such DNAME.
    fn too_long(
        &mut self,
        answers: &[RecordSet],
        sname: &Name,
        stype: RecordType,
        rank: Option<Rank>,
        denial: &[RecordSet],
        zone: &Name,
    ) -> Option<(Outcome, Vec<Outcome>)> {
        let mut reached = sname.clone();
        let mut seen = vec![reached.clone()];
        while let Some(target) = answers
            .iter()
            .find(|set| *set.name() == reached && set.record_type() == RecordType::CNAME)
            .and_then(cname_target)
            .filter(|target| zone.zone_of(target) && !seen.contains(target))
        {
            seen.push(target.clone());
            reached = target;
        }
        let dname = answers
            .iter()
            .find(|set| is_dname(set) && set.name().zone_of(&reached) && *set.name() != reached)
            .cloned()?;
        let mut outcomes = Vec::new();
        if reached != *sname {
            let (first, rest) = self.store_chain(
                answers,
                sname,
                stype,
                rank,
                denial,
                ResponseCode::YXDomain,
                &None,
                zone,
            )?;
            outcomes.push(first);
            outcomes.extend(rest);
        }
        self.offer(&dname, rank, Vec::new());
        outcomes.push(Outcome::TooLong {
            dname,
            zone: zone.clone(),
        });
        split(outcomes)
    }

    /// Offers `set` to the cache at `rank`, or nothing when `rank` is
    /// `None`.
    fn offer(&mut self, set: &RecordSet, rank: Option<Rank>, proof: Vec<RecordSet>) {
        let Some(rank) = rank else {
            return;
        };
        self.cache.insert(
            self.now,
            Offer::Positive {
                set: set.clone(),
                rank,
                validation: Validation::NotPerformed,
                proof,
                truncated: false,
            },
        );
    }

    /// Offers, at glue rank, the addresses in `additional` of the NS
    /// targets in `sets` that lie inside `zone`, the zone whose server
    /// sent them, and returns them. Addresses outside it could be anything
    /// (RFC 2181 §5.4.1).
    fn store_glue(
        &mut self,
        sets: &[RecordSet],
        additional: &[RecordSet],
        zone: &Name,
    ) -> Vec<RecordSet> {
        let mut kept = Vec::new();
        let targets: Vec<Name> = sets
            .iter()
            .filter(|set| set.record_type() == RecordType::NS)
            .flat_map(|set| set.records_without_rrsigs())
            .filter_map(|record| match &record.data {
                RData::NS(ns) => Some(ns.0.clone()),
                _ => None,
            })
            .collect();
        for set in additional {
            let glue = matches!(set.record_type(), RecordType::A | RecordType::AAAA)
                && zone.zone_of(set.name())
                && targets.contains(set.name());
            if glue {
                self.cache.insert(
                    self.now,
                    Offer::Positive {
                        set: set.clone(),
                        rank: Rank::Glue,
                        validation: Validation::NotPerformed,
                        proof: Vec::new(),
                        truncated: false,
                    },
                );
                kept.push(set.clone());
            }
        }
        kept
    }

    /// Validates `subject` of `outcome`, whose TTLs were current at `at`,
    /// for `from`: at once when nothing needs fetching, or with a check
    /// that gathers the chain.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn check(
        &mut self,
        from: Node,
        subject: Subject,
        outcome: &Outcome,
        at: Instant,
        tree: TreeId,
        depth: u8,
        entropy: &dyn Entropy,
    ) -> CheckStart {
        if self.config.anchors.is_none() {
            return CheckStart::Done(Validation::NotPerformed.into());
        }
        let (Some((material, zone)), Some(checked)) =
            (material(&subject, outcome), checked(&subject, outcome))
        else {
            return CheckStart::Done(Validation::Indeterminate.into());
        };
        if self.negative_anchor(&subject) {
            // RFC 7646 §1.1: below a negative trust anchor nothing is
            // validated, as though no trust anchor covered the name, until
            // a trust anchor further down.
            let verdict = Verdict::from(Validation::Insecure(Insecure::NoAnchor));
            self.validated(&subject, &checked, &material, &verdict, at);
            return CheckStart::Done(verdict);
        }
        // A check under way for the same subject is joined only when it
        // validates the same data: the same key may hold other records by
        // now, and the result of one says nothing of the other.
        let joined = self.graph.by_subject.get(&subject).and_then(|ids| {
            ids.iter().copied().find(|id| {
                self.graph.checks.get(id).is_some_and(|check| {
                    check.checked.same(&checked) && check.material.same(&material)
                })
            })
        });
        if let Some(id) = joined {
            if let Some(check) = self.graph.checks.get_mut(&id) {
                check.dependents.push(from);
            }
            return CheckStart::Waiting(id);
        }
        let anchor = {
            let anchors = self.config.anchors.as_ref().expect("anchors are set");
            anchors
                .closest(&zone, false)
                .map(|anchor| anchor.owner.clone())
        };
        let Some(anchor) = anchor else {
            let verdict = self.validate(&material, &Chain::default());
            self.validated(&subject, &checked, &material, &verdict, at);
            return CheckStart::Done(verdict);
        };
        let id = self.graph.check_id();
        self.graph.hold(tree);
        self.graph
            .by_subject
            .entry(subject.clone())
            .or_default()
            .push(id);
        self.graph.checks.insert(
            id,
            Check {
                subject,
                checked,
                material,
                at,
                tree,
                depth,
                anchor,
                zone: zone.clone(),
                links: BTreeMap::new(),
                wait: BTreeMap::new(),
                probed: false,
                bounded: false,
                dependents: vec![from],
            },
        );
        self.link(id, zone, entropy);
        match self.graph.checks.get(&id) {
            Some(check) if check.wait.is_empty() => match self.conclude(id, entropy) {
                Some(verdict) => CheckStart::Done(verdict),
                None => CheckStart::Waiting(id),
            },
            Some(_) => CheckStart::Waiting(id),
            None => CheckStart::Done(Validation::Indeterminate.into()),
        }
    }

    /// Whether a negative trust anchor covers `subject`: its name or a
    /// name above it is one, with no trust anchor between them. A trust
    /// anchor at the negative one or below it starts validation again
    /// (RFC 7646 §1.1), as Unbound's trust anchors override its
    /// `domain-insecure`. A DS RRset belongs to the parent's side of its
    /// name, so for DS the names from the parent up count.
    fn negative_anchor(&self, subject: &Subject) -> bool {
        let Some(negative) = &self.config.negative_anchors else {
            return false;
        };
        let anchored = |name: &LowerName| {
            self.config
                .anchors
                .iter()
                .flat_map(Anchors::iter)
                .any(|anchor| !anchor.ds.is_empty() && LowerName::new(&anchor.owner) == *name)
        };
        let key = match subject {
            Subject::Rrset(key) | Subject::Denial(key, _) => key,
        };
        let mut name = key.name.clone();
        if key.rtype == RecordType::DS {
            if name.is_root() {
                return false;
            }
            name = name.base_name();
        }
        loop {
            if anchored(&name) {
                return false;
            }
            if negative(&name) {
                return true;
            }
            if name.is_root() {
                return false;
            }
            name = name.base_name();
        }
    }

    /// Adds the zone at `zone` to check `id`'s chain: its DNSKEY RRset,
    /// and its DS RRset unless it is the anchor's zone.
    fn link(&mut self, id: CheckId, zone: Name, entropy: &dyn Entropy) {
        let Some(check) = self.graph.checks.get_mut(&id) else {
            return;
        };
        let lower = LowerName::new(&zone);
        if check.links.contains_key(&lower) {
            return;
        }
        check
            .links
            .insert(lower.clone(), (zone.clone(), None, None));
        let mut parts = vec![Part::Dnskey];
        if zone != check.anchor {
            parts.push(Part::Ds);
        }
        for part in parts {
            self.fetch(id, lower.clone(), part, entropy);
        }
    }

    /// Starts the lookup of `part` at `name` for check `id`, or takes what
    /// the cache has for it at once.
    fn fetch(&mut self, id: CheckId, name: LowerName, part: Part, entropy: &dyn Entropy) {
        let Some(check) = self.graph.checks.get(&id) else {
            return;
        };
        let (tree, depth) = (check.tree, check.depth);
        let rtype = match part {
            Part::Ds | Part::Cut => RecordType::DS,
            Part::Dnskey => RecordType::DNSKEY,
        };
        let key = Key::new(name.clone(), rtype, DNSClass::IN);
        let outcome = match self.depend(Node::Check(id), key, false, tree, depth + 1, entropy) {
            Dep::Ready(found) => found.outcome,
            Dep::Waiting(lookup) => {
                if let Some(check) = self.graph.checks.get_mut(&id) {
                    check.wait.insert(lookup, (name, part));
                }
                return;
            }
            Dep::Cycle => Outcome::Failure(FailureKind::WorkExceeded),
            Dep::TooDeep => {
                if let Some(check) = self.graph.checks.get_mut(&id) {
                    check.bounded = true;
                }
                Outcome::Failure(FailureKind::WorkExceeded)
            }
        };
        self.fetched(id, &name, part, &outcome, entropy);
    }

    /// Looks for the zone cuts between check `id`'s zone and the owner of
    /// its unsigned RRset, which the resolution may never have seen: a
    /// server that hosts a zone and its unsigned child answers for the
    /// child itself, without a referral. The DS RRset of each name on the
    /// way is asked of the parent's side, as Unbound does, and a name the
    /// parent proves to be a delegation without DS joins the chain, so the
    /// RRset is Insecure there (RFC 4035 §4.3, §5.2).
    fn probe(&mut self, id: CheckId, entropy: &dyn Entropy) {
        let Some(check) = self.graph.checks.get_mut(&id) else {
            return;
        };
        check.probed = true;
        let Material::Rrset { set, .. } = &check.material else {
            return;
        };
        let owner = set.name().to_lowercase();
        let zone = check.zone.clone();
        // A DS RRset belongs to the parent's side of its own name.
        let last = if set.record_type() == RecordType::DS {
            owner.base_name()
        } else {
            owner
        };
        let mut names = Vec::new();
        let mut name = last;
        while label_count(&name) > label_count(&zone) && zone.zone_of(&name) {
            names.push(LowerName::new(&name));
            name = name.base_name();
        }
        for name in names.into_iter().rev() {
            self.fetch(id, name, Part::Cut, entropy);
        }
    }

    /// Records what the DS lookup at `name` that check `id`'s probe made
    /// found. A DS RRset makes `name` a signed cut, and the chain takes in
    /// its keys. A NODATA whose records the parent signs to show a
    /// delegation without DS makes it an unsigned cut. Anything else says
    /// `name` is no cut.
    fn cut_found(
        &mut self,
        id: CheckId,
        name: &LowerName,
        outcome: &Outcome,
        entropy: &dyn Entropy,
    ) {
        let max = self.config.policy.max_nsec3_iterations;
        match outcome {
            Outcome::Data { .. } => self.link(id, Name::from(name), entropy),
            Outcome::Negative {
                kind: Negative::NoData,
                soa,
                denial,
                zone,
                ..
            } => {
                let parent = soa.as_ref().map_or(zone.clone(), |soa| soa.name().clone());
                let proof = proof::no_ds(&Name::from(name), &parent, denial, max);
                if proof == proof::Proof::Unproven {
                    return;
                }
                let Some(check) = self.graph.checks.get_mut(&id) else {
                    return;
                };
                check
                    .links
                    .entry(name.clone())
                    .or_insert_with(|| (Name::from(name), None, None));
                self.fetched(id, name, Part::Ds, outcome, entropy);
            }
            _ => {}
        }
    }

    /// Records what a lookup for check `id`'s chain found for `part` of the
    /// zone at `zone`. A DS RRset or its denial names the parent zone, by
    /// the signer of its RRSIGs or the owner of its SOA, and the chain goes
    /// on up to it. What a probe for a cut found goes to
    /// [`cut_found`](Resolver::cut_found).
    fn fetched(
        &mut self,
        id: CheckId,
        zone: &LowerName,
        part: Part,
        outcome: &Outcome,
        entropy: &dyn Entropy,
    ) {
        if part == Part::Cut {
            return self.cut_found(id, zone, outcome, entropy);
        }
        let (fetched, parent) = match outcome {
            Outcome::Data { sets, zone, .. } => {
                let set = sets[0].clone();
                let parent = signer(&set).unwrap_or_else(|| zone.clone());
                (Fetched::Answer(set), Some(parent))
            }
            Outcome::Negative {
                soa, denial, zone, ..
            } => {
                let parent = soa.as_ref().map_or(zone.clone(), |soa| soa.name().clone());
                let records = soa.iter().cloned().chain(denial.iter().cloned()).collect();
                (Fetched::Denied(records), Some(parent))
            }
            // Without a DS answer or denial to name the parent, the chain
            // goes on up from the zone cut the cache knows above the name,
            // so a validation can still reach an insecure delegation
            // higher up, below which the DS was never needed
            // (RFC 4035 §4.3).
            Outcome::Alias { .. } | Outcome::TooLong { .. } => (
                Fetched::Denied(Vec::new()),
                self.cut(zone, true).map(|cut| Name::from(&cut)),
            ),
            Outcome::Failure(_) => (
                Fetched::Failed,
                self.cut(zone, true).map(|cut| Name::from(&cut)),
            ),
        };
        let Some(check) = self.graph.checks.get_mut(&id) else {
            return;
        };
        let anchor = check.anchor.clone();
        if let Some(link) = check.links.get_mut(zone) {
            match part {
                Part::Ds => link.1 = Some(fetched),
                Part::Dnskey => link.2 = Some(fetched),
                Part::Cut => {}
            }
        }
        if part == Part::Ds
            && let Some(parent) = parent
        {
            let parent = parent.to_lowercase();
            let above =
                label_count(&parent) < label_count(zone) && parent.zone_of(&Name::from(zone));
            if above && anchor.zone_of(&parent) {
                self.link(id, parent, entropy);
            }
        }
    }

    /// What a lookup that check `id` waited for found, and whether the
    /// work bound stopped it.
    pub(super) fn check_looked(
        &mut self,
        id: CheckId,
        lookup: LookupId,
        found: Found,
        bounded: bool,
        entropy: &dyn Entropy,
    ) {
        let Some(check) = self.graph.checks.get_mut(&id) else {
            return;
        };
        let Some((zone, part)) = check.wait.remove(&lookup) else {
            return;
        };
        check.bounded |= bounded;
        self.fetched(id, &zone, part, &found.outcome, entropy);
        if self
            .graph
            .checks
            .get(&id)
            .is_some_and(|check| check.wait.is_empty())
        {
            self.conclude(id, entropy);
        }
    }

    /// Validates check `id`'s material with the chain it gathered, records
    /// the result in the cache unless the work bound stopped a lookup the
    /// check needed, and hands it to every node that waited.
    ///
    /// An unsigned RRset that is Bogus with the chain so far may sit below
    /// a cut the resolution never saw, so the check first probes for one,
    /// once. `None` while the probe waits.
    fn conclude(&mut self, id: CheckId, entropy: &dyn Entropy) -> Option<Verdict> {
        let check = self.graph.checks.get(&id)?;
        let links = check
            .links
            .values()
            .map(|(zone, ds, dnskey)| Link {
                zone: zone.clone(),
                ds: ds.clone().unwrap_or(Fetched::Failed),
                dnskey: dnskey.clone().unwrap_or(Fetched::Failed),
            })
            .collect();
        let chain = Chain { links };
        let verdict = self.validate(&check.material, &chain);
        let unsigned = match &check.material {
            Material::Rrset { set, .. } => set.rrsigs().is_empty(),
            Material::Denial { .. } => false,
        };
        if unsigned && !check.probed && matches!(verdict.validation, Validation::Bogus(_)) {
            self.probe(id, entropy);
            let waiting = self
                .graph
                .checks
                .get(&id)
                .is_some_and(|check| !check.wait.is_empty());
            return if waiting {
                None
            } else {
                self.conclude(id, entropy)
            };
        }
        let check = self.graph.checks.remove(&id)?;
        self.graph.unlist(&check.subject, id);
        self.graph.release(check.tree);
        if !check.bounded {
            self.validated(
                &check.subject,
                &check.checked,
                &check.material,
                &verdict,
                check.at,
            );
        }
        for to in check.dependents {
            self.graph.ready.push_back(Ready::Checked {
                to,
                check: id,
                subject: check.subject.clone(),
                verdict: verdict.clone(),
            });
        }
        Some(verdict)
    }

    /// What `material` validates to with `chain`.
    ///
    /// A negative answer is Secure only when every NSEC and NSEC3 RRset
    /// in it verifies, as Unbound fails a reply with any authority RRset
    /// that does not: a record that did not verify would otherwise reach
    /// the client beside AD (RFC 4035 §3.2.3), and be kept to deny other
    /// names (RFC 8198 §5.1).
    fn validate(&self, material: &Material, chain: &Chain) -> Verdict {
        let anchors = self.config.anchors.as_ref().expect("anchors are set");
        let at = self.clock.at(self.now);
        let policy = &self.config.policy;
        match material {
            Material::Rrset { set, authority } => {
                let rrset =
                    validate_rrset(set, authority, chain, anchors, policy, at, &self.verify);
                Verdict {
                    validation: rrset.validation,
                    verified: rrset.verified,
                }
            }
            Material::Denial {
                query,
                rcode,
                authority,
            } => {
                let denial = validate_denial(
                    query,
                    *rcode,
                    authority,
                    chain,
                    anchors,
                    policy,
                    at,
                    &self.verify,
                );
                match (denial.validation, denial.unverified) {
                    (Validation::Secure, Some(code)) => Validation::Bogus(code).into(),
                    (validation, _) => Verdict {
                        validation,
                        verified: denial.verified,
                    },
                }
            }
        }
    }

    /// Records `verdict` on `subject`, made over `checked` with
    /// `material`, whose TTLs were current at `at`, in the cache, where the
    /// subject's entry still holds `checked`. A Secure RRset lives no
    /// longer than the RRSIG that verified it allows (RFC 4035 §5.3.3),
    /// and a Secure negative answer no longer than the RRSIGs that
    /// verified its SOA and denial records. The NSEC records of a Secure
    /// negative answer, every one of which verified, are kept for
    /// synthesizing answers while they and their SOA are Secure
    /// (RFC 8198 §5.4).
    fn validated(
        &mut self,
        subject: &Subject,
        checked: &Checked,
        material: &Material,
        verdict: &Verdict,
        at: Instant,
    ) {
        let now = self.now;
        let validation = verdict.validation;
        let key = match (subject, material) {
            (Subject::Rrset(key), Material::Rrset { .. })
            | (Subject::Denial(key, _), Material::Denial { .. }) => key,
            _ => return,
        };
        // The RRSIGs that proved the result: the RRset's, or those of a
        // negative answer's SOA and NSEC or NSEC3 records, which together
        // last only as long as each of them (RFC 8198 §5.4).
        let secure_until = verdict
            .verified
            .iter()
            .map(|verified| {
                self.signature_expires(verified)
                    .min(at + seconds(verified.ttl_bound()))
            })
            .min();
        self.cache
            .validated(key, checked, validation, secure_until, now);
        if let (Validation::Secure, Material::Denial { authority, .. }) = (validation, material)
            && self.config.aggressive_nsec
        {
            let soa = authority
                .iter()
                .find(|set| set.record_type() == RecordType::SOA);
            let nsec: Vec<(RecordSet, Option<Instant>)> = authority
                .iter()
                .filter(|set| set.record_type() == RecordType::NSEC)
                .map(|set| (set.clone(), self.secure_until(set, at, &verdict.verified)))
                .collect();
            if let Some(soa) = soa
                && !nsec.is_empty()
            {
                let soa_until = self.secure_until(soa, at, &verdict.verified);
                self.cache.add_secure_nsec(soa, soa_until, &nsec, at);
            }
        }
    }

    /// When `set`, Secure and current at `at`, may be served no longer:
    /// when the RRSIG among `verified` that verified it expires, or its
    /// own TTL or Original TTL past `at`, whichever comes first
    /// (RFC 4035 §5.3.3).
    /// `None` when no RRSIG verified `set`: RRSIGs that did not prove it
    /// bound nothing.
    pub(super) fn secure_until(
        &self,
        set: &RecordSet,
        at: Instant,
        verified: &[Verified],
    ) -> Option<Instant> {
        verified
            .iter()
            .filter(|verified| verified.signs(set))
            .map(|verified| {
                let ttl = at + seconds(verified.ttl_bound());
                self.signature_expires(verified).min(ttl)
            })
            .min()
    }

    /// When the RRSIG that made `verified` expires, on the run's clock: it
    /// is valid through its last second (RFC 4034 §3.1.5), or now when
    /// that has passed.
    fn signature_expires(&self, verified: &Verified) -> Instant {
        use std::cmp::Ordering::{Equal, Less};
        let now = self.serial_now();
        if !matches!(now.partial_cmp(&verified.expiration), Some(Less | Equal)) {
            return self.now;
        }
        // An RRSIG still current expires within 2^31 seconds (RFC 1982).
        let ahead = verified.expiration.get().wrapping_sub(now.get());
        self.now + std::time::Duration::from_secs(u64::from(ahead) + 1)
    }

    /// The run's clock as an RRSIG time field: seconds since 1970 modulo
    /// 2^32 (RFC 4034 §3.1.5).
    fn serial_now(&self) -> SerialNumber {
        let date = self.clock.at(self.now);
        let seconds = date
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        SerialNumber::new(seconds as u32)
    }

    /// Drops `node` from everything it waits on, and cancels what then
    /// has no dependent left.
    pub(super) fn forget(&mut self, node: Node) {
        let mut todo = vec![node];
        while let Some(node) = todo.pop() {
            for (id, lookup) in &mut self.graph.lookups {
                lookup.dependents.retain(|dependent| *dependent != node);
                if lookup.dependents.is_empty() {
                    todo.push(Node::Lookup(*id));
                }
            }
            for (id, check) in &mut self.graph.checks {
                check.dependents.retain(|dependent| *dependent != node);
                if check.dependents.is_empty() {
                    todo.push(Node::Check(*id));
                }
            }
            match node {
                Node::Lookup(id) => {
                    if let Some(lookup) = self.graph.lookups.remove(&id) {
                        self.graph
                            .by_key
                            .remove(&(lookup.key.clone(), lookup.relay_cd));
                        self.graph.release(lookup.tree);
                        if let LookupWait::Exchange(token) = lookup.wait {
                            self.graph.exchanges.remove(&token);
                            self.queue.push_back(Action::Abandon(token));
                        }
                    }
                }
                Node::Check(id) => {
                    if let Some(check) = self.graph.checks.remove(&id) {
                        self.graph.unlist(&check.subject, id);
                        self.graph.release(check.tree);
                    }
                }
                Node::Asker(_) | Node::Refresh => {}
            }
        }
    }
}

/// `key`'s question as a client's request, as the local zones are asked
/// it. `None` for a type no request may ask for.
fn question_of(key: &Key) -> Option<Request> {
    let mut message = Message::new(0, MessageType::Query, OpCode::Query);
    message.add_query(Query::query(Name::from(&key.name), key.rtype));
    match Request::parse(&message.to_vec().ok()?, Transport::Tcp) {
        Parsed::Request(request) => Some(request),
        Parsed::Reject(_) | Parsed::Silent => None,
    }
}

/// The data at `subject`'s key in `outcome` that a check's result is for.
fn checked(subject: &Subject, outcome: &Outcome) -> Option<Checked> {
    match (subject, outcome) {
        (Subject::Rrset(key), Outcome::Data { sets, .. }) => sets
            .iter()
            .find(|set| set.record_type() == key.rtype)
            .map(|set| Checked::Rrset(set.clone())),
        (Subject::Rrset(_), Outcome::Alias { cname, .. }) => Some(Checked::Rrset(cname.clone())),
        (Subject::Rrset(_), Outcome::TooLong { dname, .. }) => Some(Checked::Rrset(dname.clone())),
        (Subject::Denial(..), Outcome::Negative { soa, denial, .. }) => Some(Checked::Denial {
            soa: soa.clone(),
            denial: denial.clone(),
        }),
        _ => None,
    }
}

/// What a check of `subject` validates, and the zone that holds it.
fn material(subject: &Subject, outcome: &Outcome) -> Option<(Material, Name)> {
    match (subject, outcome) {
        (Subject::Rrset(key), Outcome::Data { sets, proof, zone }) => {
            let set = sets.iter().find(|set| set.record_type() == key.rtype)?;
            Some(vouched(set, proof, zone))
        }
        (
            Subject::Rrset(_),
            Outcome::Alias {
                cname, proof, zone, ..
            },
        ) => Some(vouched(cname, proof, zone)),
        (Subject::Rrset(_), Outcome::TooLong { dname, zone }) => {
            let zone = signer(dname).unwrap_or_else(|| zone.clone());
            Some((
                Material::Rrset {
                    set: dname.clone(),
                    authority: Vec::new(),
                },
                zone,
            ))
        }
        (
            Subject::Denial(..),
            Outcome::Negative {
                kind,
                name,
                qtype,
                soa,
                denial,
                zone,
            },
        ) => {
            let rcode = match kind {
                Negative::NxDomain => ResponseCode::NXDomain,
                Negative::NoData => ResponseCode::NoError,
            };
            let authority = soa.iter().cloned().chain(denial.iter().cloned()).collect();
            let zone = soa.as_ref().map_or(zone.clone(), |soa| soa.name().clone());
            let query = Query::query(name.clone(), *qtype);
            Some((
                Material::Denial {
                    query,
                    rcode,
                    authority,
                },
                zone,
            ))
        }
        _ => None,
    }
}

/// The material that validates `set`, found in `zone` with `proof`, and
/// the zone that holds it. A CNAME synthesized from a DNAME in `proof` is
/// as good as that DNAME, so the DNAME is validated in its place
/// (RFC 6672 §3.4).
fn vouched(set: &RecordSet, proof: &[RecordSet], zone: &Name) -> (Material, Name) {
    let dname = proof.iter().find(|set| is_dname(set));
    let set = match (signer(set), dname) {
        (None, Some(dname)) if dname_matches(dname, set) => dname.clone(),
        _ => set.clone(),
    };
    let zone = signer(&set).unwrap_or_else(|| zone.clone());
    let authority = proof.iter().filter(|set| !is_dname(set)).cloned().collect();
    (Material::Rrset { set, authority }, zone)
}

/// The NSEC or NSEC3 RRsets among `denial`, those of a reply from `zone`,
/// that show no closer name matched when a wildcard made `set`
/// (RFC 4035 §3.1.3.3, RFC 5155 §7.2.6): all of them when they hold no
/// such proof, so that validation finds it missing, and none when no
/// wildcard made `set`. The proof comes from the zone that signed
/// `set`, which holds the wildcard: a server that serves a zone below
/// `zone` too may answer from both in one reply (RFC 1034 §4.3.2).
fn expansion_proof(set: &RecordSet, zone: &Name, denial: &[RecordSet]) -> Vec<RecordSet> {
    let Some(labels) = expanded_from(set) else {
        return Vec::new();
    };
    let closest_encloser = set.name().trim_to(labels);
    let claim = proof::Claim::Wildcard {
        name: set.name(),
        closest_encloser: &closest_encloser,
    };
    let zone = signer(set).unwrap_or_else(|| zone.clone());
    proof::proof_of(claim, &zone, denial).unwrap_or_else(|| denial.to_vec())
}

/// Whether `cname` is what `dname` synthesizes for its owner (RFC 6672
/// §2.2).
fn dname_matches(dname: &RecordSet, cname: &RecordSet) -> bool {
    let Some(target) = dname
        .records_without_rrsigs()
        .find_map(|r| dname_target(&r.data))
    else {
        return false;
    };
    let Some(alias) = cname_target(cname) else {
        return false;
    };
    dname_substitute(cname.name(), dname.name(), &target).is_some_and(|expected| expected == alias)
}

/// Whether a cached CNAME answers a question of type `rtype` at its
/// owner. A question for the CNAME itself, or for the RRSIG and NSEC
/// records that may sit beside it (RFC 4035 §2.5, RFC 2181 §10.1), is
/// about the alias's own records, which the alias's server answers.
fn follows_alias(rtype: RecordType) -> bool {
    !matches!(
        rtype,
        RecordType::CNAME | RecordType::RRSIG | RecordType::NSEC
    )
}

/// Whether `set` is a DNAME RRset (RFC 6672).
pub(super) fn is_dname(set: &RecordSet) -> bool {
    set.record_type() == RecordType::DNAME
}

/// The signer named in `set`'s RRSIGs.
fn signer(set: &RecordSet) -> Option<Name> {
    set.rrsigs().iter().find_map(|record| match &record.data {
        RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => Some(rrsig.input().signer_name.to_lowercase()),
        _ => None,
    })
}

fn cname_target(set: &RecordSet) -> Option<Name> {
    set.records_without_rrsigs()
        .find_map(|record| match &record.data {
            RData::CNAME(cname) => Some(cname.0.to_lowercase()),
            _ => None,
        })
}

/// The time from `sent` to `now`.
fn rtt(sent: Instant, now: Instant) -> std::time::Duration {
    now.since_start().saturating_sub(sent.since_start())
}

/// The first outcome of `chain` and the rest, or `None` when it is empty.
fn split(mut chain: Vec<Outcome>) -> Option<(Outcome, Vec<Outcome>)> {
    if chain.is_empty() {
        return None;
    }
    let first = chain.remove(0);
    Some((first, chain))
}

/// `set` with its TTL, and every record's and RRSIG's, set to `ttl`.
pub(super) fn with_ttl(set: &RecordSet, ttl: u32) -> RecordSet {
    let mut out = set.clone();
    out.set_ttl(ttl);
    let records = set
        .records_without_rrsigs()
        .map(|record| {
            let mut record = record.clone();
            record.ttl = ttl;
            record
        })
        .collect();
    out.set_records(records);
    let rrsigs = set
        .rrsigs()
        .iter()
        .map(|record| {
            let mut record = record.clone();
            record.ttl = ttl;
            record
        })
        .collect();
    out.set_rrsigs(rrsigs);
    out
}

/// `name` with each ASCII letter's case drawn from `entropy`
/// (draft-vixie-dnsext-dns0x20).
fn randomise_case(name: &Name, entropy: &dyn Entropy) -> Name {
    let letters = name
        .iter()
        .flat_map(|label| label.iter())
        .filter(|byte| byte.is_ascii_alphabetic())
        .count();
    let mut bits = vec![0u8; letters.div_ceil(8)];
    entropy.fill_random(&mut bits);
    let mut next = 0usize;
    let labels: Vec<Label> = name
        .iter()
        .map(|label| {
            let bytes: Vec<u8> = label
                .iter()
                .map(|byte| {
                    if !byte.is_ascii_alphabetic() {
                        return *byte;
                    }
                    let upper = bits[next / 8] >> (next % 8) & 1 == 1;
                    next += 1;
                    if upper {
                        byte.to_ascii_uppercase()
                    } else {
                        byte.to_ascii_lowercase()
                    }
                })
                .collect();
            Label::from_raw_bytes(&bytes).expect("a label keeps its length when its case changes")
        })
        .collect();
    let mut out = Name::from_labels(labels).expect("a name keeps its length when its case changes");
    out.set_fqdn(true);
    out
}
