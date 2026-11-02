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
//! started and this one joins stays charged to its own tree.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{IpAddr, SocketAddr};

use fictionet::Entropy;
use fictionet::stdlib::protocols::dns::dnssec::rdata::DNSSECRData;
use fictionet::stdlib::protocols::dns::dnssec::{
    Chain, Fetched, Link, Validation, Verify, proof, validate_denial, validate_rrset,
};
use fictionet::stdlib::protocols::dns::op::{
    Edns, Message, MessageType, OpCode, Query, ResponseCode,
};
use fictionet::stdlib::protocols::dns::rr::domain::Label;
use fictionet::stdlib::protocols::dns::rr::{
    DNSClass, LowerName, Name, RData, Record, RecordSet, RecordType,
};
use fictionet::stdlib::services::serve::Transport;
use fictionet::time::Instant;

use super::super::event::{Event, Unmatched, UpstreamOutcome};
use super::super::exchange::{Action, ExchangeFailure, Token, Transmit};
use super::super::zone::dname_target;
use super::Resolver;
use super::cache::{Entry, FailureKind, Key, Negative, Offer, Rank, normalized, ttl_left};

/// Something that waits in the graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) enum Node {
    /// A client query.
    Asker(u64),
    /// A lookup.
    Lookup(u64),
    /// A check.
    Check(u64),
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
        /// The NSEC or NSEC3 records that show a wildcard answer had no
        /// closer match.
        proof: Vec<RecordSet>,
        /// The zone whose server answered.
        zone: Name,
    },
    /// A CNAME at the name, for any type but CNAME and ANY.
    Alias {
        cname: RecordSet,
        target: Name,
        /// The DNAME the CNAME was synthesized from, if it was.
        proof: Vec<RecordSet>,
        zone: Name,
    },
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

/// One thing a check validates.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) enum Subject {
    /// The RRset at a key.
    Rrset(Key),
    /// A negative answer for a key.
    Denial(Key, NegativeKind),
}

/// [`Negative`] with an order, for keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) enum NegativeKind {
    NxDomain,
    NoData,
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
        Outcome::Data { sets, .. } => sets.iter().map(|set| Subject::Rrset(key(set))).collect(),
        Outcome::Alias { cname, .. } => vec![Subject::Rrset(key(cname))],
        Outcome::Negative {
            kind, name, qtype, ..
        } => {
            let (rtype, kind) = match kind {
                Negative::NxDomain => (RecordType::ANY, NegativeKind::NxDomain),
                Negative::NoData => (*qtype, NegativeKind::NoData),
            };
            let key = Key::new(LowerName::new(name), rtype, DNSClass::IN);
            vec![Subject::Denial(key, kind)]
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
        }
    }
}

/// What asking for a question's outcome gave.
pub(super) enum Dep {
    /// The cache had it.
    Ready(Box<Found>),
    /// This lookup is finding it.
    Waiting(u64),
    /// It cannot be had: the lookup would wait on itself, or the
    /// dependency is deeper than the work bound allows.
    Refused,
}

/// What starting a check gave.
pub(super) enum CheckStart {
    Done(Validation),
    Waiting(u64),
}

/// Something that became ready for a node waiting on it.
pub(super) enum Ready {
    Looked {
        to: Node,
        lookup: u64,
        key: Key,
        found: Box<Found>,
    },
    Checked {
        to: Node,
        check: u64,
        subject: Subject,
        validation: Validation,
    },
}

/// The resolver's work in progress.
#[derive(Default)]
pub(super) struct Graph {
    next: u64,
    lookups: BTreeMap<u64, Lookup>,
    by_key: BTreeMap<Key, u64>,
    checks: BTreeMap<u64, Check>,
    by_subject: BTreeMap<Subject, u64>,
    exchanges: BTreeMap<Token, Exchange>,
    trees: BTreeMap<u64, Tree>,
    pub(super) ready: VecDeque<Ready>,
}

/// The work one client question has cost, and how many nodes still hold
/// it.
struct Tree {
    sent: u16,
    holders: usize,
}

/// One question being resolved.
struct Lookup {
    key: Key,
    tree: u64,
    depth: u8,
    dependents: Vec<Node>,
    /// Server addresses that failed over each transport. Each is asked at
    /// most once per transport in one resolution (RFC 9520 §3.1).
    tried: Vec<(SocketAddr, Transport)>,
    /// Whether any server sent a matching reply.
    replied: bool,
    /// Whether a server sent a reply the lookup could not use.
    errors: bool,
    minimise: Minimising,
    /// Addresses of name servers that lookups this one waited on found.
    learned: BTreeMap<LowerName, Vec<IpAddr>>,
    /// Name servers whose addresses this lookup asked for.
    asked: BTreeSet<LowerName>,
    wait: LookupWait,
}

#[derive(Default)]
struct Minimising {
    /// Minimised queries sent so far.
    sent: u8,
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
    Lookups(BTreeSet<u64>),
}

/// One query sent to a server.
struct Exchange {
    lookup: u64,
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
    deadline: Instant,
}

/// One validation being made.
struct Check {
    subject: Subject,
    material: Material,
    tree: u64,
    depth: u8,
    /// The trust anchor the chain starts at.
    anchor: Name,
    /// What the chain has gathered, per zone.
    links: BTreeMap<LowerName, (Name, Option<Fetched>, Option<Fetched>)>,
    /// The lookups the check waits for, with the zone and the part each
    /// fetches.
    wait: BTreeMap<u64, (LowerName, Part)>,
    dependents: Vec<Node>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Part {
    Ds,
    Dnskey,
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

impl Graph {
    /// A number no node has had.
    pub(super) fn issue(&mut self) -> u64 {
        self.next += 1;
        self.next
    }

    /// Notes one more node of `tree`.
    pub(super) fn hold(&mut self, tree: u64) {
        self.trees
            .entry(tree)
            .or_insert(Tree {
                sent: 0,
                holders: 0,
            })
            .holders += 1;
    }

    /// Notes one node fewer of `tree`, forgetting it after the last.
    pub(super) fn release(&mut self, tree: u64) {
        if let Some(entry) = self.trees.get_mut(&tree) {
            entry.holders -= 1;
            if entry.holders == 0 {
                self.trees.remove(&tree);
            }
        }
    }

    /// Counts one query against `tree`. Whether the tree may send it.
    fn charge(&mut self, tree: u64, limit: u16) -> bool {
        match self.trees.get_mut(&tree) {
            Some(entry) => {
                entry.sent = entry.sent.saturating_add(1);
                entry.sent <= limit
            }
            None => false,
        }
    }

    /// The question lookup `id` resolves, if it is running.
    pub(super) fn lookup_key(&self, id: u64) -> Option<Key> {
        self.lookups.get(&id).map(|lookup| lookup.key.clone())
    }

    /// Keeps lookup `id` going for the cache once `node` no longer waits
    /// on it.
    pub(super) fn refresh(&mut self, id: u64, node: Node) {
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
    /// NXDOMAIN at or above the name (RFC 8020), what validated NSEC
    /// records prove (RFC 8198), the RRset, the negative or failure, or a
    /// CNAME at the name. Data below [`Rank::NonAuthAnswer`] never
    /// answers (RFC 2181 §5.4.1), and QTYPE ANY is always asked again.
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
                return Some(self.found_positive(entry, false));
            }
            Some(entry @ Entry::Negative { .. }) => {
                return self.found_negative(key, &key.name, entry);
            }
            Some(Entry::Failure { why, .. }) => {
                return Some(Found {
                    outcome: Outcome::Failure(*why),
                    checks: Vec::new(),
                    cached: true,
                });
            }
            _ => {}
        }
        if key.rtype != RecordType::CNAME {
            let alias = Key::new(key.name.clone(), RecordType::CNAME, key.class);
            if let Some(entry @ Entry::Positive { rank, .. }) = self.cache.get(&alias, now)
                && *rank >= Rank::NonAuthAnswer
            {
                return Some(self.found_positive(entry, false));
            }
        }
        self.aggressive(key)
    }

    /// Expired data for `key`, for serving stale (RFC 8767 §4).
    pub(super) fn stale_found(&self, key: &Key) -> Option<Found> {
        match self.cache.stale(key, self.now)? {
            entry @ Entry::Positive { rank, .. } if *rank >= Rank::NonAuthAnswer => {
                Some(self.found_positive(entry, true))
            }
            entry @ Entry::Negative { .. } => self.found_negative(key, &key.name, entry),
            _ => None,
        }
    }

    /// A cached RRset as an outcome, its TTL counted down to now, or set to
    /// zero for `stale` data, whose TTL the front sets.
    fn found_positive(&self, entry: &Entry, stale: bool) -> Found {
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
        let key = Key::new(
            LowerName::new(set.name()),
            set.record_type(),
            set.dns_class(),
        );
        let outcome = match (set.record_type(), cname_target(&set)) {
            (RecordType::CNAME, Some(target)) => Outcome::Alias {
                target,
                proof: proof.iter().map(|p| with_ttl(p, remaining)).collect(),
                cname: set,
                zone,
            },
            _ => Outcome::Data {
                sets: vec![set],
                proof: proof.clone(),
                zone,
            },
        };
        Found {
            outcome,
            checks: vec![(Subject::Rrset(key), *validation)],
            cached: true,
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
                    *validation
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
        })
    }

    /// The negative answer validated NSEC records prove for `key`, when
    /// the configuration uses them that way (RFC 8198 §5.1, §5.2).
    fn aggressive(&self, key: &Key) -> Option<Found> {
        if !self.config.aggressive_nsec {
            return None;
        }
        let (zone, soa, records) = self.cache.secure_nsec(&key.name, self.now)?;
        let name = Name::from(&key.name);
        let zone_name = Name::from(zone);
        let max = self.config.policy.max_nsec3_iterations;
        let kind = if proof::nxdomain(&name, &zone_name, &records, max) == proof::Proof::Proven {
            Negative::NxDomain
        } else if proof::nodata(&name, key.rtype, &zone_name, &records, max) == proof::Proof::Proven
        {
            Negative::NoData
        } else {
            return None;
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
        let checks = subjects(&outcome)
            .into_iter()
            .map(|subject| (subject, Validation::Secure))
            .collect();
        Some(Found {
            outcome,
            checks,
            cached: true,
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
            if matches!(self.cache.get(&key, self.now), Some(Entry::Positive { .. })) {
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
        match self.cache.get(&key, self.now) {
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
            if let Some(Entry::Positive { set, .. }) = self.cache.get(&key, self.now) {
                out.extend(set.records_without_rrsigs().filter_map(address));
            }
        }
        out
    }

    /// Makes `from` wait on the lookup of `key`, starting it when none
    /// runs, unless the cache answers at once.
    pub(super) fn depend(
        &mut self,
        from: Node,
        key: Key,
        tree: u64,
        depth: u8,
        entropy: &dyn Entropy,
    ) -> Dep {
        if let Some(found) = self.cached(&key) {
            return Dep::Ready(Box::new(found));
        }
        if let Some(&id) = self.graph.by_key.get(&key) {
            if self.graph.reaches(from, Node::Lookup(id)) {
                return Dep::Refused;
            }
            if let Some(lookup) = self.graph.lookups.get_mut(&id) {
                lookup.dependents.push(from);
            }
            return Dep::Waiting(id);
        }
        if depth > self.config.work.depth {
            return Dep::Refused;
        }
        let id = self.graph.issue();
        self.graph.hold(tree);
        self.graph.by_key.insert(key.clone(), id);
        self.graph.lookups.insert(
            id,
            Lookup {
                key,
                tree,
                depth,
                dependents: vec![from],
                tried: Vec::new(),
                replied: false,
                errors: false,
                minimise: Minimising::default(),
                learned: BTreeMap::new(),
                asked: BTreeSet::new(),
                wait: LookupWait::Nothing,
            },
        );
        self.plan(id, entropy);
        Dep::Waiting(id)
    }

    /// Decides lookup `id`'s next step from what the cache holds now: an
    /// answer, a query to a server of the deepest zone cut it knows, the
    /// lookups that step needs first, or failure.
    fn plan(&mut self, id: u64, entropy: &dyn Entropy) {
        let Some(lookup) = self.graph.lookups.get(&id) else {
            return;
        };
        let key = lookup.key.clone();
        if let Some(found) = self.cached(&key) {
            return self.finish(id, found);
        }
        if !self.config.forward.is_empty() {
            let mut servers = self.config.forward.clone();
            servers.retain(|server| !lookup.tried.contains(&(*server, Transport::Udp)));
            if servers.is_empty() {
                return self.fail(id);
            }
            return self.ask_one(id, LowerName::from(Name::root()), servers, entropy);
        }
        if self.config.hints.is_empty() {
            return self.fail(id);
        }
        let root = LowerName::from(Name::root());
        let priming = Key::new(root.clone(), RecordType::NS, DNSClass::IN);
        if self.cut(&root, false).is_none() {
            if key == priming {
                let hints = self.hint_servers();
                return self.ask_one(id, root, hints, entropy);
            }
            let (tree, depth) = (lookup.tree, lookup.depth);
            return match self.depend(Node::Lookup(id), priming, tree, depth + 1, entropy) {
                Dep::Waiting(prime) => self.wait_lookups(id, [prime].into()),
                Dep::Ready(found) if let Outcome::Failure(why) = found.outcome => {
                    self.finish(id, Found::fresh(Outcome::Failure(why)))
                }
                // Root NS that the cache did not keep, such as with TTL 0,
                // cannot be iterated from.
                Dep::Ready(_) | Dep::Refused => self.fail(id),
            };
        }

        let strictly = key.rtype == RecordType::DS;
        let zone = self
            .cut(&key.name, strictly)
            .expect("the root's NS RRset is cached");
        let targets = self.targets(&zone);
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
        if zone.is_root() {
            for server in self.hint_servers() {
                if !servers.contains(&server) {
                    servers.push(server);
                }
            }
        }
        servers.retain(|server| !lookup.tried.contains(&(*server, Transport::Udp)));
        if !servers.is_empty() {
            return self.ask_one(id, zone, servers, entropy);
        }

        // No server of the cut is left to ask: look up the addresses of a
        // name server that came without glue.
        let (tree, depth) = (lookup.tree, lookup.depth);
        let glueless: Vec<Name> = targets
            .iter()
            .filter(|target| !lookup.asked.contains(&LowerName::new(target)))
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
                match self.depend(Node::Lookup(id), key, tree, depth + 1, entropy) {
                    Dep::Waiting(dep) => {
                        waiting.insert(dep);
                    }
                    Dep::Ready(found) => self.learn(id, &lower, &found.outcome),
                    Dep::Refused => {}
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

    fn hint_servers(&self) -> Vec<SocketAddr> {
        self.config
            .hints
            .iter()
            .map(|(_, address)| SocketAddr::new(*address, 53))
            .collect()
    }

    fn wait_lookups(&mut self, id: u64, waiting: BTreeSet<u64>) {
        if let Some(lookup) = self.graph.lookups.get_mut(&id) {
            lookup.wait = LookupWait::Lookups(waiting);
        }
    }

    /// Notes the addresses `outcome` holds for name server `target`.
    fn learn(&mut self, id: u64, target: &LowerName, outcome: &Outcome) {
        let Outcome::Data { sets, .. } = outcome else {
            return;
        };
        let addresses: Vec<IpAddr> = sets
            .iter()
            .flat_map(|set| set.records_without_rrsigs().filter_map(address))
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

    /// What a lookup that lookup `id` waited for found.
    pub(super) fn lookup_looked(
        &mut self,
        id: u64,
        dep: u64,
        key: &Key,
        found: Found,
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
        let done = waiting.is_empty();
        if key.rtype == RecordType::NS && key.name.is_root() {
            if let Outcome::Failure(why) = found.outcome {
                return self.finish(id, Found::fresh(Outcome::Failure(why)));
            }
        } else {
            self.learn(id, &key.name, &found.outcome);
        }
        if done {
            if let Some(lookup) = self.graph.lookups.get_mut(&id) {
                lookup.wait = LookupWait::Nothing;
            }
            self.plan(id, entropy);
        }
    }

    /// Ends lookup `id` with no server left to ask, caching the failure
    /// (RFC 9520 §3.2).
    fn fail(&mut self, id: u64) {
        let Some(lookup) = self.graph.lookups.get(&id) else {
            return;
        };
        let why = if lookup.errors {
            FailureKind::Unknown
        } else {
            FailureKind::NoReachableAuthority
        };
        let key = lookup.key.clone();
        self.cache.insert(self.now, Offer::Failure { key, why });
        self.finish(id, Found::fresh(Outcome::Failure(why)));
    }

    /// Ends lookup `id` with `found`, for every node that waited on it.
    fn finish(&mut self, id: u64, found: Found) {
        let Some(lookup) = self.graph.lookups.remove(&id) else {
            return;
        };
        self.graph.by_key.remove(&lookup.key);
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
            });
        }
    }

    /// Sends lookup `id`'s next question to one of `servers`, chosen at
    /// random, as an authority for `zone`.
    fn ask_one(
        &mut self,
        id: u64,
        zone: LowerName,
        servers: Vec<SocketAddr>,
        entropy: &dyn Entropy,
    ) {
        let index = entropy.random_below(servers.len() as u64) as usize;
        let to = servers[index];
        let forwarded = !self.config.forward.is_empty();
        let Some((name, rtype, minimised)) = self.next_question(id, &zone, forwarded) else {
            return;
        };
        self.send(
            id,
            zone,
            to,
            Transport::Udp,
            name,
            rtype,
            minimised,
            forwarded,
            entropy,
        );
    }

    /// The question lookup `id` asks a server of `zone` next: the whole
    /// question, or with QNAME minimisation the name a few labels past
    /// what is known, with QTYPE A (RFC 9156 §2.3).
    fn next_question(
        &mut self,
        id: u64,
        zone: &LowerName,
        forwarded: bool,
    ) -> Option<(Name, RecordType, bool)> {
        let lookup = self.graph.lookups.get_mut(&id)?;
        let qname = Name::from(&lookup.key.name);
        let whole = (qname.clone(), lookup.key.rtype, false);
        let Some(bounds) = self.config.minimise else {
            return Some(whole);
        };
        let priming = lookup.key.name.is_root();
        if forwarded || priming || lookup.minimise.off {
            return Some(whole);
        }
        let mut known = zone.num_labels();
        if let Some(through) = &lookup.minimise.through
            && zone.zone_of(through)
            && through.zone_of(&lookup.key.name)
        {
            known = known.max(through.num_labels());
        }
        let total = qname.num_labels();
        if known + 1 >= total || lookup.minimise.sent >= bounds.max_queries {
            return Some(whole);
        }
        let sent = lookup.minimise.sent;
        let add = if sent < bounds.one_label {
            1
        } else {
            let left = bounds.max_queries - sent;
            (total - known).div_ceil(left).max(1)
        };
        let labels = known + add;
        if labels >= total {
            return Some(whole);
        }
        lookup.minimise.sent += 1;
        Some((qname.trim_to(usize::from(labels)), RecordType::A, true))
    }

    /// Sends one query for lookup `id` and waits for it.
    #[allow(clippy::too_many_arguments)]
    fn send(
        &mut self,
        id: u64,
        zone: LowerName,
        to: SocketAddr,
        transport: Transport,
        name: Name,
        rtype: RecordType,
        minimised: bool,
        forwarded: bool,
        entropy: &dyn Entropy,
    ) {
        let Some(lookup) = self.graph.lookups.get(&id) else {
            return;
        };
        let (tree, replied, key) = (lookup.tree, lookup.replied, lookup.key.clone());
        if !self.graph.charge(tree, self.config.work.queries) {
            // RFC 1034 §5.3.3: past the bound, the question fails. When no
            // server ever replied, every server failed (RFC 8914 §4.23).
            let why = if replied {
                FailureKind::WorkExceeded
            } else {
                FailureKind::NoReachableAuthority
            };
            self.cache.insert(self.now, Offer::Failure { key, why });
            return self.finish(id, Found::fresh(Outcome::Failure(why)));
        }
        let mut name = name;
        if self.config.case_randomise {
            name = randomise_case(&name, entropy);
        }
        let mut bytes = [0u8; 2];
        entropy.fill_random(&mut bytes);
        let message_id = u16::from_be_bytes(bytes);
        let question = Query::query(name, rtype);
        let mut message = Message::new(message_id, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = forwarded;
        // RFC 6840 §5.9: a validating resolver sets CD, so it gets the
        // data even where the server would find it bogus, and judges it
        // itself.
        message.metadata.checking_disabled = self.config.anchors.is_some();
        message.add_query(question.clone());
        let mut edns = Edns::new();
        edns.set_max_payload(self.config.payload.max(512))
            .set_dnssec_ok(true);
        message.set_edns(edns);
        let bytes = message
            .to_vec()
            .expect("a query with one question and an OPT record writes");
        let token = self.tokens.issue();
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
                deadline: self.now + self.config.retransmit,
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
        if token.generation() < self.tokens.generation() {
            return Err(Unmatched::OldGeneration);
        }
        self.graph
            .exchanges
            .get(&token)
            .ok_or(Unmatched::NotOutstanding)
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
        if from != exchange.to || transport != exchange.transport {
            return Err(Unmatched::WrongPeer);
        }
        let reply = Message::from_vec(bytes).map_err(|_| Unmatched::Malformed)?;
        if reply.metadata.message_type != MessageType::Response {
            return Err(Unmatched::Malformed);
        }
        if reply.metadata.id != exchange.id {
            return Err(Unmatched::WrongId);
        }
        let asked = &exchange.question;
        let same = |got: &Query| {
            let name = if self.config.case_randomise {
                got.name().eq_case(asked.name())
            } else {
                got.name() == asked.name()
            };
            name && got.query_type() == asked.query_type()
                && got.query_class() == asked.query_class()
        };
        match reply.queries.as_slice() {
            [got] if same(got) => Ok(reply),
            _ => Err(Unmatched::WrongQuestion),
        }
    }

    fn ignore(&mut self, token: Token, from: Option<SocketAddr>, why: Unmatched) {
        self.queue.push_back(Action::Event(Event::Ignored {
            at: self.now,
            token,
            from,
            why,
        }));
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
        if let Some(lookup) = self.graph.lookups.get_mut(&exchange.lookup) {
            lookup.replied = true;
            lookup.wait = LookupWait::Nothing;
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
            self.give_up(exchange, false, entropy);
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
                    let name = exchange.question.name().clone();
                    let rtype = exchange.question.query_type();
                    let Exchange {
                        zone,
                        to,
                        minimised,
                        forwarded,
                        ..
                    } = exchange;
                    self.send(
                        id,
                        zone,
                        to,
                        Transport::Tcp,
                        name,
                        rtype,
                        minimised,
                        forwarded,
                        entropy,
                    )
                }
                Transport::Tcp => self.give_up(exchange, true, entropy),
            };
        }
        let rcode = message.metadata.response_code;
        if !matches!(rcode, ResponseCode::NoError | ResponseCode::NXDomain) {
            return self.give_up(exchange, true, entropy);
        }

        let zone = Name::from(&exchange.zone);
        let inside = |name: &Name| zone.zone_of(name);
        let sname = exchange.question.name().to_lowercase();
        let stype = exchange.question.query_type();
        let authoritative = message.metadata.authoritative || exchange.forwarded;
        let answers: Vec<RecordSet> = rrsets(&message.answers)
            .into_iter()
            .filter(|set| inside(set.name()))
            .collect();
        let authority: Vec<RecordSet> = rrsets(&message.authorities)
            .into_iter()
            .filter(|set| inside(set.name()))
            .collect();
        let additional = rrsets(&message.additionals);
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

        if !answers.is_empty() {
            if !authoritative {
                return self.give_up(exchange, true, entropy);
            }
            let Some(outcome) =
                self.store_chain(&answers, &sname, stype, rank, &denial, rcode, &soa, &zone)
            else {
                return self.give_up(exchange, true, entropy);
            };
            self.store_glue(&answers, &additional, &zone);
            if exchange.minimised {
                return self.through(id, &sname, entropy);
            }
            return self.finish(id, Found::fresh(outcome));
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
            return self.negative(id, &key, Negative::NxDomain, soa, denial, zone);
        }

        let referral = authority
            .iter()
            .find(|set| set.record_type() == RecordType::NS && *set.name() != zone);
        if soa.is_none()
            && let Some(ns) = referral
        {
            let cut = ns.name().to_lowercase();
            // RFC 1034 §5.3.3: a referral moves strictly closer to the
            // name. Anything else is a broken server.
            if !cut.zone_of(&sname) {
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
            self.store_glue(std::slice::from_ref(ns), &additional, &zone);
            return self.plan(id, entropy);
        }

        if !authoritative {
            return self.give_up(exchange, true, entropy);
        }
        if exchange.minimised {
            return self.through(id, &sname, entropy);
        }
        self.negative(id, &key, Negative::NoData, soa, denial, zone)
    }

    /// Notes that `name`, a minimised question's name, is no zone cut, and
    /// goes on one step deeper.
    fn through(&mut self, id: u64, name: &Name, entropy: &dyn Entropy) {
        if let Some(lookup) = self.graph.lookups.get_mut(&id) {
            lookup.minimise.through = Some(LowerName::new(name));
        }
        self.plan(id, entropy);
    }

    /// Ends lookup `id` with a negative answer, offered to the cache.
    fn negative(
        &mut self,
        id: u64,
        key: &Key,
        kind: Negative,
        soa: Option<RecordSet>,
        denial: Vec<RecordSet>,
        zone: Name,
    ) {
        self.cache.insert(
            self.now,
            Offer::Negative {
                key: key.clone(),
                kind,
                soa: soa.clone(),
                denial: denial.clone(),
                validation: Validation::NotPerformed,
                truncated: false,
            },
        );
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
    /// cache: the RRsets of the asked type at the name, or the CNAMEs from
    /// it and what they lead to inside the zone. When the chain ends in the
    /// zone without data, the reply's RCODE and SOA are the last name's
    /// (RFC 6604 §2), and that negative is offered too. Returns what the
    /// answer says about `sname` itself, or `None` when it holds nothing
    /// for it.
    #[allow(clippy::too_many_arguments)]
    fn store_chain(
        &mut self,
        answers: &[RecordSet],
        sname: &Name,
        stype: RecordType,
        rank: Rank,
        denial: &[RecordSet],
        rcode: ResponseCode,
        soa: &Option<RecordSet>,
        zone: &Name,
    ) -> Option<Outcome> {
        let mut first = None;
        let mut at = sname.clone();
        let mut seen = Vec::new();
        loop {
            if seen.contains(&at) {
                break;
            }
            seen.push(at.clone());
            let here: Vec<RecordSet> = answers
                .iter()
                .filter(|set| *set.name() == at)
                .filter(|set| stype == RecordType::ANY || set.record_type() == stype)
                .cloned()
                .collect();
            if !here.is_empty() {
                for set in &here {
                    self.offer(set, rank, denial.to_vec());
                }
                return Some(first.unwrap_or(Outcome::Data {
                    sets: here,
                    proof: denial.to_vec(),
                    zone: zone.clone(),
                }));
            }
            let Some(cname) = answers
                .iter()
                .find(|set| *set.name() == at && set.record_type() == RecordType::CNAME)
            else {
                break;
            };
            let target = cname_target(cname)?;
            // A CNAME synthesized from a DNAME has no RRSIG of its own;
            // the DNAME above it vouches for it (RFC 6672 §3.4).
            let dname: Vec<RecordSet> = answers
                .iter()
                .filter(|set| set.record_type() == RecordType::Unknown(39))
                .filter(|set| set.name().zone_of(&at) && *set.name() != at)
                .cloned()
                .collect();
            for set in &dname {
                self.offer(set, rank, Vec::new());
            }
            self.offer(cname, rank, dname.clone());
            first.get_or_insert(Outcome::Alias {
                cname: cname.clone(),
                target: target.clone(),
                proof: dname,
                zone: zone.clone(),
            });
            if !zone.zone_of(&target) {
                return first;
            }
            at = target;
        }
        // The chain ended inside the zone without data for the type.
        if first.is_some() && soa.is_some() {
            let kind = match rcode {
                ResponseCode::NXDomain => Negative::NxDomain,
                _ => Negative::NoData,
            };
            self.cache.insert(
                self.now,
                Offer::Negative {
                    key: Key::new(LowerName::new(&at), stype, DNSClass::IN),
                    kind,
                    soa: soa.clone(),
                    denial: denial.to_vec(),
                    validation: Validation::NotPerformed,
                    truncated: false,
                },
            );
        }
        first
    }

    fn offer(&mut self, set: &RecordSet, rank: Rank, proof: Vec<RecordSet>) {
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
    /// sent them. Addresses outside it could be anything (RFC 2181 §5.4.1).
    fn store_glue(&mut self, sets: &[RecordSet], additional: &[RecordSet], zone: &Name) {
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
            }
        }
    }

    /// Validates `subject` of `outcome` for `from`: at once when nothing
    /// needs fetching, or with a check that gathers the chain.
    pub(super) fn check(
        &mut self,
        from: Node,
        subject: Subject,
        outcome: &Outcome,
        tree: u64,
        depth: u8,
        entropy: &dyn Entropy,
    ) -> CheckStart {
        if self.config.anchors.is_none() {
            return CheckStart::Done(Validation::NotPerformed);
        }
        if let Some(&id) = self.graph.by_subject.get(&subject) {
            if let Some(check) = self.graph.checks.get_mut(&id) {
                check.dependents.push(from);
            }
            return CheckStart::Waiting(id);
        }
        let Some((material, zone)) = material(&subject, outcome) else {
            return CheckStart::Done(Validation::Indeterminate);
        };
        let anchor = {
            let anchors = self.config.anchors.as_ref().expect("anchors are set");
            anchors
                .closest(&zone, false)
                .map(|anchor| anchor.owner.clone())
        };
        let Some(anchor) = anchor else {
            let validation = self.validate(&material, &Chain::default());
            self.validated(&subject, &material, validation);
            return CheckStart::Done(validation);
        };
        let id = self.graph.issue();
        self.graph.hold(tree);
        self.graph.by_subject.insert(subject.clone(), id);
        self.graph.checks.insert(
            id,
            Check {
                subject,
                material,
                tree,
                depth,
                anchor,
                links: BTreeMap::new(),
                wait: BTreeMap::new(),
                dependents: vec![from],
            },
        );
        self.link(id, zone, entropy);
        match self.graph.checks.get(&id) {
            Some(check) if check.wait.is_empty() => {
                let validation = self.conclude(id);
                CheckStart::Done(validation)
            }
            Some(_) => CheckStart::Waiting(id),
            None => CheckStart::Done(Validation::Indeterminate),
        }
    }

    /// Adds the zone at `zone` to check `id`'s chain: its DNSKEY RRset,
    /// and its DS RRset unless it is the anchor's zone.
    fn link(&mut self, id: u64, zone: Name, entropy: &dyn Entropy) {
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
        let (tree, depth) = (check.tree, check.depth);
        for part in parts {
            let rtype = match part {
                Part::Ds => RecordType::DS,
                Part::Dnskey => RecordType::DNSKEY,
            };
            let key = Key::new(lower.clone(), rtype, DNSClass::IN);
            match self.depend(Node::Check(id), key, tree, depth + 1, entropy) {
                Dep::Ready(found) => self.fetched(id, &lower, part, &found.outcome, entropy),
                Dep::Waiting(lookup) => {
                    if let Some(check) = self.graph.checks.get_mut(&id) {
                        check.wait.insert(lookup, (lower.clone(), part));
                    }
                }
                Dep::Refused => self.fetched(
                    id,
                    &lower,
                    part,
                    &Outcome::Failure(FailureKind::WorkExceeded),
                    entropy,
                ),
            }
        }
    }

    /// Records what a lookup for check `id`'s chain found for `part` of the
    /// zone at `zone`. A DS RRset or its denial names the parent zone, by
    /// the signer of its RRSIGs or the owner of its SOA, and the chain goes
    /// on up to it.
    fn fetched(
        &mut self,
        id: u64,
        zone: &LowerName,
        part: Part,
        outcome: &Outcome,
        entropy: &dyn Entropy,
    ) {
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
            Outcome::Alias { .. } => (Fetched::Denied(Vec::new()), None),
            Outcome::Failure(_) => (Fetched::Failed, None),
        };
        let Some(check) = self.graph.checks.get_mut(&id) else {
            return;
        };
        let anchor = check.anchor.clone();
        if let Some(link) = check.links.get_mut(zone) {
            match part {
                Part::Ds => link.1 = Some(fetched),
                Part::Dnskey => link.2 = Some(fetched),
            }
        }
        if part == Part::Ds
            && let Some(parent) = parent
        {
            let parent = parent.to_lowercase();
            let above =
                parent.num_labels() < zone.num_labels() && parent.zone_of(&Name::from(zone));
            if above && anchor.zone_of(&parent) {
                self.link(id, parent, entropy);
            }
        }
    }

    /// What a lookup that check `id` waited for found.
    pub(super) fn check_looked(
        &mut self,
        id: u64,
        lookup: u64,
        found: Found,
        entropy: &dyn Entropy,
    ) {
        let Some(check) = self.graph.checks.get_mut(&id) else {
            return;
        };
        let Some((zone, part)) = check.wait.remove(&lookup) else {
            return;
        };
        self.fetched(id, &zone, part, &found.outcome, entropy);
        if self
            .graph
            .checks
            .get(&id)
            .is_some_and(|check| check.wait.is_empty())
        {
            self.conclude(id);
        }
    }

    /// Validates check `id`'s material with the chain it gathered, records
    /// the result in the cache, and hands it to every node that waited.
    fn conclude(&mut self, id: u64) -> Validation {
        let Some(check) = self.graph.checks.remove(&id) else {
            return Validation::Indeterminate;
        };
        self.graph.by_subject.remove(&check.subject);
        self.graph.release(check.tree);
        let links = check
            .links
            .into_values()
            .map(|(zone, ds, dnskey)| Link {
                zone,
                ds: ds.unwrap_or(Fetched::Failed),
                dnskey: dnskey.unwrap_or(Fetched::Failed),
            })
            .collect();
        let chain = Chain { links };
        let validation = self.validate(&check.material, &chain);
        self.validated(&check.subject, &check.material, validation);
        for to in check.dependents {
            self.graph.ready.push_back(Ready::Checked {
                to,
                check: id,
                subject: check.subject.clone(),
                validation,
            });
        }
        validation
    }

    fn validate(&self, material: &Material, chain: &Chain) -> Validation {
        let anchors = self.config.anchors.as_ref().expect("anchors are set");
        let at = self.clock.at(self.now);
        let policy = &self.config.policy;
        match material {
            Material::Rrset { set, authority } => {
                validate_rrset(set, authority, chain, anchors, policy, at, &self.verify)
            }
            Material::Denial {
                query,
                rcode,
                authority,
            } => validate_denial(
                query,
                *rcode,
                authority,
                chain,
                anchors,
                policy,
                at,
                &self.verify,
            ),
        }
    }

    /// Records `validation` of `subject` in the cache. A Secure RRset
    /// lives no longer than the first of its RRSIGs to expire
    /// (RFC 4035 §5.3.3), and validated NSEC records are kept for
    /// synthesizing answers (RFC 8198).
    fn validated(&mut self, subject: &Subject, material: &Material, validation: Validation) {
        let now = self.now;
        let (key, set) = match (subject, material) {
            (Subject::Rrset(key), Material::Rrset { set, .. }) => (key, Some(set)),
            (Subject::Denial(key, _), _) => (key, None),
            _ => return,
        };
        let expires = set.and_then(|set| self.signatures_expire(set));
        self.cache.validated(key, validation, expires, now);
        if let (Validation::Secure, Material::Denial { authority, .. }) = (validation, material)
            && self.config.aggressive_nsec
        {
            let soa = authority
                .iter()
                .find(|set| set.record_type() == RecordType::SOA);
            let nsec: Vec<RecordSet> = authority
                .iter()
                .filter(|set| set.record_type() == RecordType::NSEC)
                .cloned()
                .collect();
            if let Some(soa) = soa
                && !nsec.is_empty()
            {
                self.cache.add_secure_nsec(soa, &nsec, now);
            }
        }
    }

    /// The first time one of `set`'s RRSIGs expires, on the run's clock.
    fn signatures_expire(&self, set: &RecordSet) -> Option<Instant> {
        let date = self.clock.at(self.now);
        let today = date.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
        set.rrsigs()
            .iter()
            .filter_map(|record| match &record.data {
                RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => {
                    Some(u64::from(rrsig.input().sig_expiration.get()))
                }
                _ => None,
            })
            .map(|expiration| {
                // Serial arithmetic (RFC 1982): the expiration is within
                // 2^31 seconds of today.
                let today32 = today as u32;
                let ahead = (expiration as u32).wrapping_sub(today32);
                if ahead < 0x8000_0000 {
                    self.now + std::time::Duration::from_secs(u64::from(ahead) + 1)
                } else {
                    self.now
                }
            })
            .min()
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
                        self.graph.by_key.remove(&lookup.key);
                        self.graph.release(lookup.tree);
                        if let LookupWait::Exchange(token) = lookup.wait {
                            self.graph.exchanges.remove(&token);
                            self.queue.push_back(Action::Abandon(token));
                        }
                    }
                }
                Node::Check(id) => {
                    if let Some(check) = self.graph.checks.remove(&id) {
                        self.graph.by_subject.remove(&check.subject);
                        self.graph.release(check.tree);
                    }
                }
                Node::Asker(_) | Node::Refresh => {}
            }
        }
    }
}

/// What a check of `subject` validates, and the zone that holds it.
fn material(subject: &Subject, outcome: &Outcome) -> Option<(Material, Name)> {
    match (subject, outcome) {
        (Subject::Rrset(key), Outcome::Data { sets, proof, zone }) => {
            let set = sets
                .iter()
                .find(|set| set.record_type() == key.rtype)?
                .clone();
            let zone = signer(&set).unwrap_or_else(|| zone.clone());
            let authority = proof.clone();
            Some((Material::Rrset { set, authority }, zone))
        }
        (
            Subject::Rrset(_),
            Outcome::Alias {
                cname, proof, zone, ..
            },
        ) => {
            // A synthesized CNAME is as good as the DNAME it came from.
            let set = match (signer(cname), proof.first()) {
                (None, Some(dname)) if dname_matches(dname, cname) => dname.clone(),
                _ => cname.clone(),
            };
            let zone = signer(&set).unwrap_or_else(|| zone.clone());
            Some((
                Material::Rrset {
                    set,
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
    let owner = cname.name();
    let keep = usize::from(owner.num_labels() - dname.name().num_labels());
    let prefix: Vec<&[u8]> = owner.iter().take(keep).collect();
    Name::from_labels(prefix)
        .and_then(|prefix| prefix.append_domain(&target))
        .is_ok_and(|expected| expected == alias)
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

fn address(record: &Record) -> Option<IpAddr> {
    match &record.data {
        RData::A(a) => Some(IpAddr::V4(a.0)),
        RData::AAAA(aaaa) => Some(IpAddr::V6(aaaa.0)),
        _ => None,
    }
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

/// `records` gathered into RRsets in order of first appearance, each
/// RRSIG with the RRset it covers, normalized as the cache keeps them.
fn rrsets(records: &[Record]) -> Vec<RecordSet> {
    let mut sets: Vec<RecordSet> = Vec::new();
    for record in records {
        let covered = match &record.data {
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => Some(rrsig.input().type_covered),
            _ => None,
        };
        let rtype = covered.unwrap_or(record.record_type());
        if rtype == RecordType::OPT {
            continue;
        }
        let index = sets.iter().position(|set| {
            set.name() == &record.name
                && set.record_type() == rtype
                && set.dns_class() == record.dns_class
        });
        let index = index.unwrap_or_else(|| {
            let mut set = RecordSet::with_ttl(record.name.clone(), rtype, record.ttl);
            set.set_dns_class(record.dns_class);
            sets.push(set);
            sets.len() - 1
        });
        let set = &mut sets[index];
        match covered {
            Some(_) => set.insert_rrsig(record.clone()),
            None => {
                let ttl = set.ttl().min(record.ttl);
                let mut record = record.clone();
                record.name = set.name().clone();
                set.insert(record, 0);
                set.set_ttl(ttl);
            }
        }
    }
    sets.iter().map(normalized).collect()
}
