//! The recursive resolver: answers clients from its local zones, its
//! cache, and the authoritative servers it asks, and validates what it
//! learns.
//!
//! [`Resolver`] is an [`Engine`]: a driver hands it client queries,
//! replies, and ticks, and carries out the exchanges it asks for. How the
//! queries travel is the driver's business, so the same engine resolves
//! through zones in memory ([`memory`](super::memory)), through packets in
//! a world's network, or through recorded exchanges.
//!
//! For each client query the resolver:
//!
//! 1. Parses it with [`Request::parse`] and queues [`Event::Query`].
//! 2. Answers a CHAOS-class question from its
//!    [`identity`](Config::identity).
//! 3. Asks its local zones that hold QNAME, deepest first and at equal
//!    depth the one added last. The first that knows the answer gives it;
//!    a zone that does not know passes the question on. When RD is set,
//!    a local chain that leaves its zone goes on from its target as any
//!    alias does, and a local referral is followed. When RD is clear,
//!    the chain goes on through the local zones, and through the cache
//!    with [`rd0_from_cache`](Config::rd0_from_cache), and a name a
//!    local zone refers to a cut gets that zone's referral.
//! 4. Answers from its cache, or starts or joins a resolution: the
//!    iteration of RFC 1034 §5.3.3 from the root servers down, or from
//!    the servers a local zone's cut names, following aliases, each
//!    target asked of the local zones first as in step 3, looking up
//!    name servers that came without glue, and fetching the DS and
//!    DNSKEY sets that validation needs.
//! 5. Renders the answer for this client: its ID, flags, EDNS, question
//!    case, and TTLs counted down.
//!
//! The standards it follows:
//!
//! | RFC | What it sets here |
//! | --- | --- |
//! | RFC 1034 §5.3.3 | Iteration, and a bound on the work one question costs |
//! | RFC 1035 §7.4, RFC 2181 §5, §8, §9 | What is cached, at which TTL, and never from truncated replies |
//! | RFC 2181 §5.4.1 | Ranks; glue and referral data never answer a client |
//! | RFC 2308 | Negative answers cached with their SOA, TTLs counted down |
//! | RFC 4035 §3.2, §4, §5; RFC 6840 §5 | Validation, DO and CD upstream, AD and CD toward clients |
//! | RFC 5452 §9 | Random IDs; replies accepted only from the address asked with the ID and question sent |
//! | RFC 6891 | EDNS toward servers and clients |
//! | RFC 7766 | TCP after a truncated reply |
//! | RFC 8020 | Nothing exists below a cached Secure NXDOMAIN |
//! | RFC 8109 | Priming from root hints |
//! | RFC 8198 | Negative answers synthesized from validated NSEC records |
//! | RFC 8767 | Serving stale data |
//! | RFC 8914 | Extended DNS Errors |
//! | RFC 9156 | QNAME minimisation |
//! | RFC 9520 | Failures cached apart from negatives, for longer each time they persist; each server asked at most three times per transport |

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use fictionet::Entropy;
use fictionet::stdlib::protocols::dns::dnssec::{Ring, Validation, Verified, Verify};
use fictionet::stdlib::protocols::dns::op::ResponseCode;
use fictionet::stdlib::protocols::dns::rr::{DNSClass, LowerName, Name, RecordType};
use fictionet::stdlib::protocols::dns::{Parsed, Request, Response, label_count};
use fictionet::time::Instant;

use super::authority::{ServerConfig, bare_reply};
use super::clock::WallClock;
use super::event::{Event, QueryFlags};
use super::exchange::{Action, Client, ClientQuery, Engine, Generation, Input, Session, Tokens};
use super::zone::{Answered, answer_onward};

mod cache;
mod config;
mod front;
mod resolution;
mod servers;

pub use cache::{Cache, Checked, Entry, FailureKind, Key, Limits, Negative, Offer, Rank};
pub use config::{
    Config, LocalZone, Minimise, NameServer, NegativeAnchors, ROOT_SERVERS, Stale, Work, root_hints,
};

use resolution::{AskerId, CheckId, Graph, LookupId, Outcome, Subject, TreeId};
use servers::Servers;

/// A recursive resolver, as an engine.
///
/// It keeps the contract of [`Engine`]. Every exchange it starts has a
/// fresh token, a random ID, and, with
/// [`case_randomise`](Config::case_randomise), a random case in its
/// QNAME; a reply counts only from the address and over the transport the
/// query went to, with that ID and question. Client queries that need the
/// same lookups wait on them together, and [`Input::Gone`] drops only
/// what no remaining client needs. [`Engine::advance`] abandons every
/// exchange, empties the cache, restarts the queries still waiting, and
/// checks signatures against the new session's clock from then on.
///
/// `V` checks signatures; [`Ring`] checks them with the algorithms ring
/// implements.
pub struct Resolver<V: Verify = Ring> {
    config: Config,
    /// The front's view of `config`, for the header and EDNS rules
    /// authoritative servers and resolvers share.
    server: ServerConfig,
    verify: V,
    clock: WallClock,
    tokens: Tokens,
    cache: Cache,
    /// The round trips of the servers it asked.
    servers: Servers,
    graph: Graph,
    askers: BTreeMap<AskerId, Asker>,
    /// Client queries a new session restarts, on the next input.
    restart: Vec<AskerId>,
    queue: VecDeque<Action>,
    now: Instant,
}

/// One client query being answered.
struct Asker {
    client: Client,
    request: Request,
    /// Whether answers must be validated: anchors are set and the client
    /// did not set CD.
    validate: bool,
    /// Whether the answer may come only from the cache: RD was clear.
    cache_only: bool,
    /// What the answer is made of so far: aliases, then the data, negative,
    /// or failure they lead to.
    pieces: Vec<Piece>,
    /// What the query waits for.
    wait: AskerWait,
    /// When the query arrived, for serving stale data to a slow
    /// resolution.
    since: Instant,
    /// Whether stale data was already looked for after the client timeout.
    stale_tried: bool,
}

impl Asker {
    /// The client's request with the name the answer asks for next: QNAME,
    /// then the target of each alias it follows. `None` once the answer
    /// holds what its chain ends in.
    fn next_question(&self) -> Option<Request> {
        let name = match self.pieces.last() {
            None => self.request.question.name().to_lowercase(),
            Some(Piece {
                outcome: Outcome::Alias { target, .. },
                ..
            }) => target.clone(),
            Some(_) => return None,
        };
        let mut asked = self.request.clone();
        asked.question.set_name(name);
        Some(asked)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AskerWait {
    Nothing,
    Lookup(LookupId),
    Checks(BTreeSet<CheckId>),
}

/// One step of an answer: an alias, or what the question finally found.
#[derive(Clone, Debug)]
struct Piece {
    outcome: Outcome,
    /// What validation established, per RRset or denial the piece holds.
    checks: Vec<(Subject, Validation)>,
    /// The RRSIGs that verified its RRsets for Secure results of its
    /// checks, which bound how long the client may keep them (RFC 4035
    /// §5.3.3). Empty for data from the cache, whose TTL the cache already
    /// bounded when it stored the result.
    verified: Vec<Verified>,
    /// Whether it came from the cache.
    cached: bool,
    /// Whether it is expired data served under RFC 8767.
    stale: bool,
    /// Whether it came from a local zone, or from the servers a local
    /// zone's cut names, which rests on that zone's data. Local data is
    /// never validated.
    local: bool,
    /// When the TTLs in `outcome` were current.
    at: Instant,
}

impl Piece {
    /// What validation established for the whole piece: its worst result,
    /// or `NotPerformed` for local data.
    fn validation(&self) -> Validation {
        if self.local {
            return Validation::NotPerformed;
        }
        self.checks
            .iter()
            .map(|(_, validation)| *validation)
            .fold(Validation::Secure, worse)
    }
}

/// The delegation a client query with RD clear is referred to, when its
/// chain stops at a name the resolver cannot answer.
enum Delegation {
    /// A local zone's referral to a cut below it, with its NS RRset and
    /// glue as the zone gives them.
    Local(Response),
    /// The closest delegation the cache holds for the name, as a server
    /// answering from its cache gives it.
    Cached(LowerName),
}

/// What a local zone answered a question with.
struct Local {
    /// The answer, before the front renders it.
    response: Response,
    /// The apex of the zone that answered.
    zone: Name,
    /// Whether the answer keeps the AA bit the zone gives it.
    keep_aa: bool,
    /// Whether its CNAME and DNAME chain went past the zone, out of it or
    /// to a referral ([`answer_onward`]).
    onward: bool,
}

impl Local {
    /// Whether the answer settles the question: the zone answered with
    /// authority, and its chain stayed inside the zone. A referral, or a
    /// chain that goes past the zone, leaves the rest to resolve.
    fn settles(&self) -> bool {
        self.response.message.metadata.authoritative && !self.onward
    }
}

/// The worse of two validation results, for an answer made of several
/// RRsets: Bogus, then Indeterminate, then not performed, then Insecure,
/// then Secure.
fn worse(a: Validation, b: Validation) -> Validation {
    fn badness(v: &Validation) -> u8 {
        match v {
            Validation::Secure => 0,
            Validation::Insecure(_) => 1,
            Validation::NotPerformed => 2,
            Validation::Indeterminate => 3,
            Validation::Bogus(_) => 4,
        }
    }
    if badness(&b) > badness(&a) { b } else { a }
}

impl<V: Verify> Resolver<V> {
    /// A resolver behaving as `config`, checking signatures with `verify`
    /// against dates from `clock`, in generation 0.
    pub fn new(config: Config, verify: V, clock: WallClock) -> Resolver<V> {
        let server = ServerConfig {
            identity: config.identity.clone(),
            payload: config.payload,
            ede: config.ede,
            any: config.any,
            ask_timeout: config.retransmit,
            recursion_available: true,
        };
        let servers = Servers::new(&config);
        let limits = Limits {
            max_ttl: config.max_ttl,
            max_negative_ttl: config.max_negative_ttl,
            failure_ttl: config.failure_ttl,
            stale: config
                .serve_stale
                .map_or(std::time::Duration::ZERO, |stale| stale.max_stale),
        };
        Resolver {
            config,
            server,
            verify,
            clock,
            tokens: Tokens::new(),
            cache: Cache::new(limits),
            servers,
            graph: Graph::default(),
            askers: BTreeMap::new(),
            restart: Vec::new(),
            queue: VecDeque::new(),
            now: Instant::ZERO,
        }
    }

    /// The cache, to look at what the resolver has learned.
    pub fn cache(&self) -> &Cache {
        &self.cache
    }

    fn query(&mut self, query: ClientQuery, entropy: &dyn Entropy) {
        let ClientQuery { client, bytes } = query;
        let request = match Request::parse(&bytes, client.transport) {
            Parsed::Silent => return,
            Parsed::Reject(reject) => {
                let bytes = self.server.render_reject(reject, client.transport);
                return self.send_answer(client, bytes, Validation::NotPerformed, false);
            }
            Parsed::Request(request) => request,
        };
        self.queue.push_back(Action::Event(Event::Query {
            at: self.now,
            server: client.local,
            client: client.clone(),
            question: request.question.clone(),
            flags: QueryFlags {
                rd: request.rd,
                cd: request.cd,
                ad: request.ad,
            },
            edns: request.edns,
        }));

        let qtype = request.question.query_type();
        match request.question.query_class() {
            DNSClass::CH => {
                let bytes = self.server.render_chaos(&request);
                return self.send_answer(client, bytes, Validation::NotPerformed, false);
            }
            DNSClass::IN if !matches!(qtype, RecordType::AXFR | RecordType::IXFR) => {}
            _ => {
                let refused = bare_reply(&request, ResponseCode::Refused, None);
                let bytes = self.render_response(&request, refused);
                return self.send_answer(client, bytes, Validation::NotPerformed, false);
            }
        }

        // When the client asked for recursion, a local answer that does
        // not settle the question is resolved on, as every name the
        // resolution reaches is (RFC 1034 §4.3.2 step 1, §5.3.3): a local
        // chain that leaves its zone goes on from its target, and a local
        // referral is followed to the servers it names. With RD clear, a
        // local chain that goes past its zone goes on through the local
        // zones, and through the cache of a resolver that answers from
        // it, as step 3a goes back to step 1, and a local referral goes
        // out as it is (step 3b).
        let local = self.local_answer(&request);
        if let Some(local) = &local
            && (local.settles() || (!request.rd && !local.onward))
        {
            let bytes = self.render_local(&request, local.response.clone(), local.keep_aa);
            return self.send_answer(client, bytes, Validation::NotPerformed, false);
        }
        if !request.rd && !self.config.rd0_from_cache && local.is_none() {
            let refused = bare_reply(&request, ResponseCode::Refused, None);
            let bytes = self.render_response(&request, refused);
            return self.send_answer(client, bytes, Validation::NotPerformed, false);
        }

        let id = self.graph.asker();
        let asker = Asker {
            validate: self.config.anchors.is_some() && !request.cd,
            cache_only: !request.rd,
            client,
            request,
            pieces: Vec::new(),
            wait: AskerWait::Nothing,
            since: self.now,
            stale_tried: false,
        };
        self.askers.insert(id, asker);
        self.graph.hold(TreeId::of(id));
        self.step_asker(id, entropy);
    }

    /// The answer of the local zones that hold QNAME, if one knows it:
    /// deepest zone first, and at equal depth the zone added last.
    fn local_answer(&self, request: &Request) -> Option<Local> {
        let qname = LowerName::new(request.question.name());
        let mut zones: Vec<(usize, &LocalZone)> = self
            .config
            .local
            .iter()
            .enumerate()
            .filter(|(_, zone)| zone.data.apex().zone_of(&qname))
            .collect();
        zones.sort_by_key(|(index, zone)| {
            std::cmp::Reverse((label_count(zone.data.apex()), *index))
        });
        let hosted: Vec<LowerName> = self
            .config
            .local
            .iter()
            .map(|zone| zone.data.apex().clone())
            .collect();
        zones.into_iter().find_map(|(_, zone)| {
            let view = zone.data.view(&request.question);
            match answer_onward(&*view, request, self.config.any, &hosted) {
                (Answered::Response(response), onward) => Some(Local {
                    response,
                    zone: Name::from(zone.data.apex()),
                    keep_aa: zone.keep_aa,
                    onward: onward.is_some(),
                }),
                (Answered::Unknown { .. }, _) => None,
            }
        })
    }

    /// Adds `outcomes`, a local zone's answer ([`Resolver::local_outcomes`]),
    /// to the answer of client query `id`. Local data is never validated,
    /// so it holds no checks.
    fn push_local(&mut self, id: AskerId, outcomes: Vec<Outcome>) {
        let Some(asker) = self.askers.get_mut(&id) else {
            return;
        };
        asker
            .pieces
            .extend(outcomes.into_iter().map(|outcome| Piece {
                outcome,
                checks: Vec::new(),
                verified: Vec::new(),
                cached: false,
                stale: false,
                local: true,
                at: self.now,
            }));
    }

    /// Moves the client query `id` on as far as it can go now: along its
    /// aliases, then through validation, then to its answer.
    fn step_asker(&mut self, id: AskerId, entropy: &dyn Entropy) {
        loop {
            let Some(asker) = self.askers.get(&id) else {
                return;
            };
            if asker.wait != AskerWait::Nothing {
                return;
            }
            let Some(asked) = asker.next_question() else {
                break;
            };
            let name = asked.question.name().clone();
            let qtype = asker.request.question.query_type();
            let aliases = u8::try_from(asker.pieces.len()).unwrap_or(u8::MAX);
            let looped = asker.pieces.iter().any(|piece| match &piece.outcome {
                Outcome::Alias { cname, .. } => *cname.name() == name,
                _ => false,
            });
            let key = Key::new(LowerName::new(&name), qtype, DNSClass::IN);
            if looped || aliases > self.config.work.depth {
                // An alias chain that comes back to a name it passed, or
                // runs past the work bound, fails (RFC 1034 §5.3.3).
                self.push_piece(id, Outcome::Failure(FailureKind::WorkExceeded), false);
                break;
            }
            // Local data is the first source for every name the chain
            // reaches, as for QNAME (RFC 1034 §4.3.2 step 1, §5.3.3), so
            // a name a local zone holds never leaves the resolver, but
            // for the servers a local cut names.
            if let Some(outcomes) = self.local_outcomes(&asked) {
                self.push_local(id, outcomes);
                continue;
            }
            let Some(asker) = self.askers.get(&id) else {
                return;
            };
            if asker.cache_only {
                // A name a local zone refers to a cut gets that referral,
                // as QNAME does (RFC 1034 §4.3.2 step 3b).
                if let Some(referral) = self.local_referral(&asked) {
                    return self.answer_referral(id, Delegation::Local(referral));
                }
                // A resolver that answers no question with RD clear from
                // its cache ends a local chain where it leaves the local
                // zones, as step 4 of RFC 1034 §4.3.2 then finds nothing.
                if !self.config.rd0_from_cache {
                    break;
                }
                // A query with RD clear may not start the lookups a
                // validation needs, so data no check has validated is
                // answered as if the cache did not hold it.
                let validate = asker.validate;
                match self.cached(&key) {
                    Some(found) if !unchecked(validate, &found) => self.push_found(id, found),
                    _ => return self.answer_referral(id, Delegation::Cached(key.name)),
                }
                continue;
            }
            // A forwarder that does not validate passes the client's CD
            // bit on, as it relays the rest of the client's header.
            let relay_cd = asker.request.cd
                && self.config.anchors.is_none()
                && self.forward_for(&key).is_some();
            // The aliases followed are counted above, apart from how
            // deeply this name's own lookups nest.
            match self.depend(
                resolution::Node::Asker(id),
                key,
                relay_cd,
                TreeId::of(id),
                0,
                entropy,
            ) {
                resolution::Dep::Ready(found) => self.push_found(id, *found),
                resolution::Dep::Waiting(lookup) => {
                    if let Some(asker) = self.askers.get_mut(&id) {
                        asker.wait = AskerWait::Lookup(lookup);
                    }
                    return;
                }
                resolution::Dep::Cycle | resolution::Dep::TooDeep => {
                    self.push_piece(id, Outcome::Failure(FailureKind::WorkExceeded), false);
                }
            }
        }
        self.serve_stale_on_failure(id);
        self.validate_asker(id, entropy);
    }

    fn push_found(&mut self, id: AskerId, found: resolution::Found) {
        let depth = usize::from(self.config.work.depth);
        let Some(asker) = self.askers.get(&id) else {
            return;
        };
        // What the servers a local zone's cut names answered rests on that
        // zone's data, and is not validated, as the zone's own is not.
        let asked = asker.next_question();
        let local = asked
            .as_ref()
            .is_some_and(|asked| self.local_cut(asked).is_some());
        let Some(asker) = self.askers.get_mut(&id) else {
            return;
        };
        asker.pieces.push(Piece {
            checks: if local { Vec::new() } else { found.checks },
            verified: Vec::new(),
            outcome: found.outcome,
            cached: found.cached,
            stale: false,
            local,
            at: self.now,
        });
        // The rest of a chain the same reply carried answers its targets,
        // before any lookup of them, so the data that came for this
        // question serves it even when the cache did not keep it
        // (RFC 1035 §7.4). It stops where following the chain one name at
        // a time would stop: at a name the chain passed, past the work
        // bound, which the next step then fails on, or at a name a local
        // zone answers for, since local data comes first for every name
        // the chain reaches (RFC 1034 §4.3.2 step 1).
        for outcome in found.rest {
            let Some(asker) = self.askers.get(&id) else {
                return;
            };
            let Some(Piece {
                outcome: Outcome::Alias { target, .. },
                ..
            }) = asker.pieces.last()
            else {
                break;
            };
            let looped = asker.pieces.iter().any(|piece| match &piece.outcome {
                Outcome::Alias { cname, .. } => cname.name() == target,
                _ => false,
            });
            if looped || asker.pieces.len() > depth {
                break;
            }
            if asker
                .next_question()
                .is_some_and(|asked| self.local_answer(&asked).is_some())
            {
                break;
            }
            let checks = resolution::subjects(&outcome)
                .into_iter()
                .map(|subject| (subject, Validation::NotPerformed))
                .collect();
            let Some(asker) = self.askers.get_mut(&id) else {
                return;
            };
            asker.pieces.push(Piece {
                checks,
                verified: Vec::new(),
                outcome,
                cached: false,
                stale: false,
                local: false,
                at: self.now,
            });
        }
    }

    fn push_piece(&mut self, id: AskerId, outcome: Outcome, cached: bool) {
        let checks = resolution::subjects(&outcome)
            .into_iter()
            .map(|subject| (subject, Validation::NotPerformed))
            .collect();
        self.push_found(
            id,
            resolution::Found {
                outcome,
                checks,
                cached,
                rest: Vec::new(),
            },
        );
    }

    /// Replaces a failed last piece with expired data for its question,
    /// or the expired aliases at its name and the data they lead to, when
    /// the configuration serves stale data and the cache still holds
    /// some (RFC 8767 §4). Stale data is served only as fresh data would
    /// be: data no check has validated never reaches a client that asked
    /// for validation.
    fn serve_stale_on_failure(&mut self, id: AskerId) {
        if self.config.serve_stale.is_none() {
            return;
        }
        let Some(asker) = self.askers.get(&id) else {
            return;
        };
        if !matches!(
            asker.pieces.last(),
            Some(Piece {
                outcome: Outcome::Failure(_),
                ..
            })
        ) {
            return;
        }
        let name = match asker.pieces.iter().rev().nth(1) {
            Some(Piece {
                outcome: Outcome::Alias { target, .. },
                ..
            }) => target.clone(),
            _ => asker.request.question.name().to_lowercase(),
        };
        let key = Key::new(
            LowerName::new(&name),
            asker.request.question.query_type(),
            DNSClass::IN,
        );
        if let Some(chain) = self.stale_chain(id, key)
            && let Some(asker) = self.askers.get_mut(&id)
        {
            asker.pieces.pop();
            asker.pieces.extend(chain);
        }
    }

    /// Expired data for `key`, the next name client query `id` asks
    /// about, as the pieces of its answer: the data, or the aliases at
    /// `key`'s name and after it that lead to the data (RFC 8767 §4).
    /// `None` when the chain does not reach data the cache still holds,
    /// comes back to a name, runs past the work bound, or holds data no
    /// check has validated for a client that asked for validation.
    fn stale_chain(&self, id: AskerId, mut key: Key) -> Option<Vec<Piece>> {
        let asker = self.askers.get(&id)?;
        let mut seen: Vec<Name> = asker
            .pieces
            .iter()
            .filter_map(|piece| match &piece.outcome {
                Outcome::Alias { cname, .. } => Some(cname.name().to_lowercase()),
                _ => None,
            })
            .collect();
        let mut aliases = seen.len();
        let mut chain = Vec::new();
        loop {
            let found = self
                .stale_found(&key)
                .filter(|found| !unchecked(asker.validate, found))?;
            let target = match &found.outcome {
                Outcome::Alias { target, cname, .. } => {
                    seen.push(cname.name().to_lowercase());
                    Some(target.clone())
                }
                _ => None,
            };
            chain.push(Piece {
                checks: found.checks,
                verified: Vec::new(),
                outcome: found.outcome,
                cached: true,
                stale: true,
                local: false,
                at: self.now,
            });
            let Some(target) = target else {
                return Some(chain);
            };
            aliases += 1;
            if seen.contains(&target) || aliases > usize::from(self.config.work.depth) {
                return None;
            }
            key = Key::new(LowerName::new(&target), key.rtype, key.class);
        }
    }

    /// Starts the validations the answer of client query `id` still needs,
    /// and answers it once there are none.
    fn validate_asker(&mut self, id: AskerId, entropy: &dyn Entropy) {
        let Some(asker) = self.askers.get(&id) else {
            return;
        };
        let mut waiting = BTreeSet::new();
        if asker.validate && !asker.cache_only {
            let needed: Vec<(usize, usize, Subject, Outcome, Instant)> = asker
                .pieces
                .iter()
                .enumerate()
                .filter(|(_, piece)| !piece.stale)
                .flat_map(|(index, piece)| {
                    piece
                        .checks
                        .iter()
                        .enumerate()
                        .filter(|(_, (_, validation))| *validation == Validation::NotPerformed)
                        .map(move |(at, (subject, _))| {
                            (index, at, subject.clone(), piece.outcome.clone(), piece.at)
                        })
                })
                .collect();
            for (index, at, subject, outcome, current) in needed {
                // Like a piece's lookup, its check's lookups nest from 0,
                // whatever number of aliases led to it.
                match self.check(
                    resolution::Node::Asker(id),
                    subject,
                    &outcome,
                    current,
                    TreeId::of(id),
                    0,
                    entropy,
                ) {
                    resolution::CheckStart::Done(verdict) => {
                        if let Some(asker) = self.askers.get_mut(&id) {
                            let piece = &mut asker.pieces[index];
                            piece.checks[at].1 = verdict.validation;
                            piece.verified.extend(verdict.verified);
                        }
                    }
                    resolution::CheckStart::Waiting(check) => {
                        waiting.insert(check);
                    }
                }
            }
        }
        if waiting.is_empty() {
            self.answer_asker(id, entropy);
        } else if let Some(asker) = self.askers.get_mut(&id) {
            asker.wait = AskerWait::Checks(waiting);
        }
    }

    /// What a lookup the client query `id` waited for found.
    fn asker_looked(
        &mut self,
        id: AskerId,
        lookup: LookupId,
        found: resolution::Found,
        entropy: &dyn Entropy,
    ) {
        let Some(asker) = self.askers.get_mut(&id) else {
            return;
        };
        if asker.wait != AskerWait::Lookup(lookup) {
            return;
        }
        asker.wait = AskerWait::Nothing;
        self.push_found(id, found);
        self.step_asker(id, entropy);
    }

    /// What a validation the client query `id` waited for established.
    fn asker_checked(
        &mut self,
        id: AskerId,
        check: CheckId,
        subject: &Subject,
        verdict: resolution::Verdict,
        entropy: &dyn Entropy,
    ) {
        let Some(asker) = self.askers.get_mut(&id) else {
            return;
        };
        let AskerWait::Checks(waiting) = &mut asker.wait else {
            return;
        };
        if !waiting.remove(&check) {
            return;
        }
        for piece in &mut asker.pieces {
            let mut took = false;
            for (have, result) in &mut piece.checks {
                if have == subject && *result == Validation::NotPerformed {
                    *result = verdict.validation;
                    took = true;
                }
            }
            if took {
                piece.verified.extend(verdict.verified.iter().cloned());
            }
        }
        if waiting.is_empty() {
            asker.wait = AskerWait::Nothing;
            self.answer_asker(id, entropy);
        }
    }

    /// Answers client query `id` from its pieces, unless a record the
    /// cache gave them ran out while the rest was resolved, such as a
    /// cached CNAME whose TTL ended while its target was chased. The chain
    /// is then followed again from the question, as the cache has it now.
    /// The work spent so far stays counted against the question.
    fn answer_asker(&mut self, id: AskerId, entropy: &dyn Entropy) {
        if self.ran_out(id) {
            if let Some(asker) = self.askers.get_mut(&id) {
                asker.pieces.clear();
                asker.wait = AskerWait::Nothing;
            }
            return self.step_asker(id, entropy);
        }
        self.send_pieces(id);
    }

    /// Whether a fresh piece of client query `id` that came from the cache
    /// holds a record whose TTL has ended by now. Data that arrived while
    /// the question was resolved serves the answer it came for, with the
    /// TTL it has left, even 0 (RFC 1035 §7.4), so a following again could
    /// only fetch it again. Cached data that shows TTL 0 has less than a
    /// second left and serves the answer the same way. Stale data is
    /// served past its TTL on purpose (RFC 8767).
    fn ran_out(&self, id: AskerId) -> bool {
        let Some(asker) = self.askers.get(&id) else {
            return false;
        };
        let max_ttl = self.config.max_ttl;
        asker
            .pieces
            .iter()
            .filter(|piece| piece.cached && !piece.stale)
            .any(|piece| {
                piece.outcome.records().iter().any(|set| {
                    let ttl = std::time::Duration::from_secs(u64::from(set.ttl())).min(max_ttl);
                    !ttl.is_zero() && piece.at + ttl <= self.now
                })
            })
    }

    /// Answers client query `id` from its pieces as they are, and forgets
    /// it.
    fn send_pieces(&mut self, id: AskerId) {
        let Some(asker) = self.askers.remove(&id) else {
            return;
        };
        self.graph.release(TreeId::of(id));
        let (bytes, validation, cached) = self.render_pieces(&asker);
        self.send_answer(asker.client, bytes, validation, cached);
    }

    /// Answers client query `id`, whose RD was clear and whose chain
    /// stopped at a name it cannot answer, with the aliases it followed to
    /// that name and `delegation`.
    fn answer_referral(&mut self, id: AskerId, delegation: Delegation) {
        let Some(asker) = self.askers.remove(&id) else {
            return;
        };
        self.graph.release(TreeId::of(id));
        let cached = matches!(delegation, Delegation::Cached(_));
        let bytes = self.render_referral(&asker.request, &asker.pieces, delegation);
        self.send_answer(asker.client, bytes, Validation::NotPerformed, cached);
    }

    /// Serves stale data to client queries that waited longer than the
    /// client timeout of RFC 8767 §5, and lets their resolutions go on.
    /// As on failure, data no check has validated is not served to a
    /// client that asked for validation: stale data must already be
    /// validated, and the aliases the query followed to it are validated
    /// before the answer goes out.
    fn stale_timeouts(&mut self, entropy: &dyn Entropy) {
        let Some(stale) = self.config.serve_stale else {
            return;
        };
        let due: Vec<(AskerId, LookupId)> = self
            .askers
            .iter()
            .filter(|(_, asker)| {
                !asker.stale_tried && asker.since + stale.client_timeout <= self.now
            })
            .filter_map(|(id, asker)| match asker.wait {
                AskerWait::Lookup(lookup) => Some((*id, lookup)),
                _ => None,
            })
            .collect();
        for (id, lookup) in due {
            let Some(asker) = self.askers.get_mut(&id) else {
                continue;
            };
            asker.stale_tried = true;
            let Some(key) = self.graph.lookup_key(lookup) else {
                continue;
            };
            let Some(chain) = self.stale_chain(id, key) else {
                continue;
            };
            self.graph.refresh(lookup, resolution::Node::Asker(id));
            if let Some(asker) = self.askers.get_mut(&id) {
                asker.wait = AskerWait::Nothing;
                asker.pieces.extend(chain);
            }
            self.validate_asker(id, entropy);
        }
    }

    /// Drops the client queries of `client` and what only they needed.
    fn gone(&mut self, client: &Client) {
        let ids: Vec<AskerId> = self
            .askers
            .iter()
            .filter(|(_, asker)| asker.client == *client)
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            self.askers.remove(&id);
            self.graph.release(TreeId::of(id));
            self.forget(resolution::Node::Asker(id));
        }
    }

    /// Queues [`Event::Reply`] and the answer `bytes` for `client`.
    fn send_answer(
        &mut self,
        client: Client,
        bytes: Vec<u8>,
        validation: Validation,
        cached: bool,
    ) {
        let event = front::reply_event(self.now, client.clone(), &bytes, validation, cached);
        self.queue.push_back(Action::Event(event));
        self.queue
            .push_back(Action::Answer(super::exchange::Answer { client, bytes }));
    }

    /// Takes what became ready and hands it on, until nothing is left.
    fn run(&mut self, entropy: &dyn Entropy) {
        while let Some(ready) = self.graph.ready.pop_front() {
            match ready {
                resolution::Ready::Looked {
                    to,
                    lookup,
                    key,
                    found,
                    bounded,
                } => match to {
                    resolution::Node::Asker(id) => self.asker_looked(id, lookup, *found, entropy),
                    resolution::Node::Lookup(id) => {
                        self.lookup_looked(id, lookup, &key, *found, bounded, entropy)
                    }
                    resolution::Node::Check(id) => {
                        self.check_looked(id, lookup, *found, bounded, entropy)
                    }
                    resolution::Node::Refresh => {}
                },
                resolution::Ready::Checked {
                    to,
                    check,
                    subject,
                    verdict,
                } => {
                    if let resolution::Node::Asker(id) = to {
                        self.asker_checked(id, check, &subject, verdict, entropy);
                    }
                }
            }
        }
    }
}

impl<V: Verify> Engine for Resolver<V> {
    fn handle(&mut self, input: Input, now: Instant, entropy: &dyn Entropy) {
        self.now = now;
        for id in std::mem::take(&mut self.restart) {
            self.graph.hold(TreeId::of(id));
            self.step_asker(id, entropy);
        }
        match input {
            Input::Query(query) => self.query(query, entropy),
            Input::Reply {
                token,
                from,
                transport,
                bytes,
            } => self.reply(token, from, transport, &bytes, entropy),
            Input::Failed { token, failure } => self.failed(token, failure, entropy),
            Input::Looked { token, .. } => self.looked(token),
            Input::Gone(client) => self.gone(&client),
            Input::Tick => {
                self.expire(entropy);
                self.stale_timeouts(entropy);
            }
        }
        self.run(entropy);
    }

    fn poll(&mut self) -> Option<Action> {
        self.queue.pop_front()
    }

    fn next_deadline(&self) -> Option<Instant> {
        let exchanges = self.graph.next_deadline();
        let stale = self.config.serve_stale.and_then(|stale| {
            self.askers
                .values()
                .filter(|asker| !asker.stale_tried && matches!(asker.wait, AskerWait::Lookup(_)))
                .map(|asker| asker.since + stale.client_timeout)
                .min()
        });
        let restart = (!self.restart.is_empty()).then_some(self.now);
        [exchanges, stale, restart].into_iter().flatten().min()
    }

    /// Abandons every outstanding exchange, empties the cache, and starts
    /// every client query still waiting again from the beginning, so it is
    /// answered from the new session. Signatures are checked against the
    /// session's clock from then on. The work of the restarted queries is
    /// counted afresh. Starting them draws IDs from entropy, which
    /// `advance` has none of, so they start on the next input, and
    /// [`next_deadline`](Engine::next_deadline) asks for one at once.
    fn advance(&mut self, session: Session) {
        if !self.tokens.advance(session.generation) {
            return;
        }
        self.clock = session.clock;
        for token in self.graph.clear() {
            self.queue.push_back(Action::Abandon(token));
        }
        self.cache.advance(session.generation);
        self.servers.clear();
        let ids: Vec<AskerId> = self.askers.keys().copied().collect();
        for id in &ids {
            if let Some(asker) = self.askers.get_mut(id) {
                asker.pieces.clear();
                asker.wait = AskerWait::Nothing;
                asker.stale_tried = false;
                asker.since = self.now;
            }
        }
        self.restart = ids;
    }

    fn generation(&self) -> Generation {
        self.tokens.generation()
    }
}

/// Whether `found` holds data no check has validated, for a client that
/// asked for validation when `validate`. Such data is never handed to that
/// client without a check (RFC 4035 §4.7), so where an answer cannot start
/// one, as from the cache alone or from stale data, it is not used.
fn unchecked(validate: bool, found: &resolution::Found) -> bool {
    validate
        && found
            .checks
            .iter()
            .any(|(_, validation)| *validation == Validation::NotPerformed)
}
