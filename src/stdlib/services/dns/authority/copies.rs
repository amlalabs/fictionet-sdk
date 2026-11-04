//! Learned copies of real zones, each served at its real servers'
//! addresses.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use fictionet::stdlib::protocols::dns::op::{Message, Query, ResponseCode};
use fictionet::stdlib::protocols::dns::rr::{DNSClass, LowerName, Name, RecordSet, RecordType};
use fictionet::stdlib::protocols::dns::{Request, Response, label_count};
use fictionet::sync::Mutex;

use super::super::exchange::{Client, Generation};
use super::super::lookup::{Looked, Lookup};
use super::super::zone::{Denied, Fact, Filing, Learned, Node, Revision, View, ZoneData};
use super::{Authority, ServerConfig, Step, bare_reply, refuse_transfer, respond_from};

/// The [learned](Learned) copies of real zones, one per apex, shared by
/// every address that serves the zone, and the zones each address serves.
///
/// At each address it answers as [`Zones`](super::Zones) over the copies
/// of the zones the address serves, looking up what they lack at the
/// address itself. A copy's view that does not know a fact the reply
/// needs never gives a negative: the copy looks the client's question up
/// ([`Step::Need`]). When the real server answered that lookup with an
/// error RCODE that gives no facts, such as FORMERR or SERVFAIL, the reply
/// is that RCODE ([`Learned::failed`]). A server that answers as RFC 1034
/// and RFC 6672 say carries the whole CNAME and DNAME chain in its
/// response. When the response to the client's question was filed and
/// the answer still stops at a name the chain led to in the zone, as when
/// a server stops a chain early, the copy looks that name up with QTYPE
/// instead, as the walk starts again there (RFC 1034 §4.3.2 step 3a,
/// RFC 6672 §3.2). A server that answers NSEC at an alias with NODATA,
/// where its own denial records show the CNAME, is asked for the CNAME,
/// and the copy follows it ([`Learned::stops_at_alias`]).
///
/// A world notes which address serves which zone with
/// [`serves`](Copies::serves), such as at the addresses a referral's glue
/// gives. An address noted for a zone may not serve it, as the servers of
/// a lame delegation do not, so it answers from the zone's copy only once
/// a lookup there showed that its real server serves the zone
/// ([`Learned::shows`]). Until then a question in the zone is looked up
/// at the address and answered from the copy, as long as the reply holds
/// only records the response to it held: other addresses' data is not
/// this one's until it shows it serves the zone. Otherwise, or for a
/// question it was not asked, such as a name a chain led to, the address
/// is asked for the zone's SOA RRset at the apex, which the zone's server
/// answers and any other refuses. The answer does not depend on what was
/// asked before, at the address or at others.
///
/// A real server that does not serve a zone refuses questions in it
/// (RFC 8906 §3.1.1), or answers them without authority: from a zone
/// above it, with a referral to that zone's cut or above
/// (RFC 1034 §4.3.1). A server of the zone that holds a cut answers DS at
/// the cut from that zone, where a server that serves only the zone below
/// answers from the zone below (RFC 4035 §3.1.4.1). When a lookup's
/// response shows any of that, the address answers for the rest of the
/// session as though it had never been noted for the zone: from the
/// other zones it serves, or REFUSED when none holds the name.
///
/// A real server may also serve a zone below one it was noted for, as the
/// root servers serve `arpa`, and `root-servers.net` below `net`: it
/// answers for the child's names from the child's data, never with a
/// referral to it. When a lookup's response shows the child's apex
/// ([`Learned::child_answering`]), the address is noted as serving the
/// child, and the response is filed into the child's copy. So is a
/// referral to a cut below a cut the copy holds, which only a server of
/// the zone at that cut, or one below it, gives. A DS question at the
/// child's apex that the address answered from the child is answered from
/// the child there after. An authoritative answer that shows no apex,
/// below a cut the copy holds ([`Learned::below_cut`]) or from an address
/// that turned out not to serve the zone, may come from such a child all
/// the same, so the address is asked for the SOA RRset at the name, whose
/// response shows the child's apex (RFC 2308 §3), before the name is
/// answered, whether the client asked for it or a chain led there. A name
/// that is an alias answers that with the alias alone, so the address is
/// then asked at each name above it in turn, up to the cut, or up to the
/// apex when it does not serve the zone.
///
/// Servers of one zone differ only in the other zones they serve, so each
/// address answers from its copies as its own real server does
/// ([`Learned::at`]). An answer RRset that a response did not show to be
/// the zone's, at a name below no cut the copy holds, may come from a
/// child that only its server serves, so it stands for that address
/// alone, and every other address looks the name up itself. A referral
/// shows only that its own server holds no zone below the cut, so the cut
/// refers the name at that address alone.
#[derive(Default)]
pub struct Copies {
    /// Each zone's copy, by apex.
    zones: Mutex<HashMap<LowerName, Arc<Learned>>>,
    /// The zones each address serves.
    served: Mutex<HashMap<IpAddr, Vec<LowerName>>>,
    /// What lookups showed this session about the zones addresses serve.
    seen: Mutex<Seen>,
}

/// What the lookups of one session showed about the zones addresses
/// serve.
struct Seen {
    generation: Generation,
    /// The zones addresses were noted for and showed they serve.
    serving: HashSet<(IpAddr, LowerName)>,
    /// The zones addresses were noted for and turned out not to serve.
    lame: HashSet<(IpAddr, LowerName)>,
    /// The names each address was asked about in a lookup.
    asked: HashSet<(IpAddr, LowerName)>,
    /// The lookups that brought a response.
    looked: HashSet<Lookup>,
    /// The lookups whose response did not show whether the address
    /// serves the zone, nor come from a zone below, each with the owner
    /// and type of every record of its answer and authority sections.
    answered: HashMap<Lookup, HashSet<(LowerName, RecordType)>>,
    /// The apexes at which an address answered DS from the zone at the
    /// apex, not from a zone above it.
    ds_below: HashSet<(IpAddr, LowerName)>,
    /// The names each address answered with authority from a zone whose
    /// apex its response did not show.
    unplaced: HashMap<(IpAddr, LowerName), Unplaced>,
    /// The names each address answered with authority in a zone, without
    /// showing the zone, that are placed only if it turns out not to
    /// serve the zone: the answer then came from a zone below.
    deferred: HashMap<(IpAddr, LowerName), Unplaced>,
}

/// A name an address answered with authority from a zone whose apex no
/// response has shown yet.
struct Unplaced {
    /// The zone of the lookup that showed it.
    zone: LowerName,
    /// The name whose SOA RRset the address is asked for next: the name
    /// itself, then each name above it in turn. An SOA question at an
    /// alias is answered with the alias, which shows no apex
    /// (RFC 1034 §3.6.2), and the apex answers it with the zone's SOA.
    at: LowerName,
}

impl Default for Seen {
    fn default() -> Seen {
        Seen::new(Generation(0))
    }
}

impl Seen {
    fn new(generation: Generation) -> Seen {
        Seen {
            generation,
            serving: HashSet::new(),
            lame: HashSet::new(),
            asked: HashSet::new(),
            looked: HashSet::new(),
            answered: HashMap::new(),
            ds_below: HashSet::new(),
            unplaced: HashMap::new(),
            deferred: HashMap::new(),
        }
    }

    /// Starts session `generation`, if it is newer than the one held,
    /// forgetting what the older one showed. Whether `generation` is the
    /// session held now.
    fn at(&mut self, generation: Generation) -> bool {
        if generation > self.generation {
            *self = Seen::new(generation);
        }
        generation == self.generation
    }

    /// Notes that `addr` does not serve the zone at `zone`, so the names
    /// it answered there with authority without showing the zone are
    /// placed in the zones below it serves.
    fn lame(&mut self, addr: IpAddr, zone: &LowerName) {
        self.lame.insert((addr, zone.clone()));
        let deferred = std::mem::take(&mut self.deferred);
        for (key, walk) in deferred {
            if key.0 == addr && walk.zone == *zone {
                self.unplaced.entry(key).or_insert(walk);
            } else {
                self.deferred.insert(key, walk);
            }
        }
    }
}

impl Copies {
    /// Copies of no zone, served nowhere.
    pub fn new() -> Copies {
        Copies::default()
    }

    /// Notes that `addr` serves the zone at `zone`.
    pub fn serves(&self, addr: IpAddr, zone: &LowerName) {
        let mut served = self.served.lock();
        let zones = served.entry(addr).or_default();
        if !zones.contains(zone) {
            zones.push(zone.clone());
        }
    }

    /// The copy of the zone at `apex`, made empty the first time.
    fn copy(&self, apex: &LowerName) -> Arc<Learned> {
        self.zones
            .lock()
            .entry(apex.clone())
            .or_insert_with(|| Arc::new(Learned::new(&Name::from(apex))))
            .clone()
    }

    /// Files what `lookup`, made in session `generation`, gave, as
    /// [`Authority::file`] does, and returns what the copy it went into
    /// kept: into the copy of the zone the lookup names, or of the child
    /// zone the response comes from. What the response shows about the
    /// zones the address serves is noted, as the type's documentation
    /// says. `None` when the lookup brought no response.
    pub fn keep(&self, lookup: &Lookup, looked: &Looked, generation: Generation) -> Option<Filing> {
        let Looked::Response(response) = looked else {
            return None;
        };
        let addr = lookup.server.ip();
        let zone = &lookup.zone;
        let question = &lookup.question;
        let qname = LowerName::new(question.name());
        let mut learned = self.copy(zone);
        let child = learned.child_answering(question, response);
        let shows = child.is_none() && learned.shows(question, response);
        let disowned = disowns(zone, response);
        {
            let mut seen = self.seen.lock();
            if seen.at(generation) {
                seen.asked.insert((addr, qname.clone()));
                seen.looked.insert(lookup.clone());
                if child.is_none() && !shows && !disowned && !response.metadata.truncation {
                    seen.answered.insert(lookup.clone(), records(response));
                }
                if let Some(child) = &child {
                    seen.serving.insert((addr, child.clone()));
                    seen.unplaced
                        .retain(|(at, name), _| *at != addr || !child.zone_of(name));
                    // A server of the zone that holds the cut answers DS
                    // there from that zone (RFC 4035 §3.1.4.1).
                    if question.query_type() == RecordType::DS && *child == qname {
                        match learned.holds_cut(&qname) {
                            true => seen.lame(addr, zone),
                            false => {
                                seen.ds_below.insert((addr, qname.clone()));
                            }
                        }
                    }
                }
                if shows {
                    seen.serving.insert((addr, zone.clone()));
                }
                // Below a cut the zone holds, what shows the zone comes
                // from where a chain led, not from the question's name.
                let placed = child.is_some() || (shows && !learned.below_cut(question));
                place(&mut seen, &learned, lookup, response, placed);
                if disowned {
                    seen.lame(addr, zone);
                } else if qname == *zone && question.query_type() == RecordType::SOA {
                    // The zone's server answers the SOA question at its
                    // apex, and any other server refuses it.
                    seen.serving.insert((addr, zone.clone()));
                }
            }
        }
        if let Some(child) = child {
            self.serves(addr, &child);
            learned = self.copy(&child);
        }
        Some(learned.file(generation, addr, question, response))
    }

    /// The step that looks `question` up at `local` for `req`, as a
    /// question in the zone at `zone`: the lookup, or the reply with the
    /// error RCODE the real server already answered that lookup with
    /// this session ([`Learned::failed`]), which a server sends rather
    /// than no reply (RFC 8906 §3.1.1).
    fn look_up(&self, req: &Request, local: SocketAddr, zone: LowerName, question: &Query) -> Step {
        match self.copy(&zone).failed(local.ip(), question) {
            Some(rcode) => Step::Reply(bare_reply(req, rcode, None)),
            None => Step::Need(Lookup::new(local, zone, question)),
        }
    }

    /// The lookup of the SOA RRset that places `name`, which the address
    /// at `local` answered from a zone whose apex no response showed yet,
    /// if it did.
    fn placing(&self, req: &Request, local: SocketAddr, name: &LowerName) -> Option<Step> {
        let (zone, at) = self
            .seen
            .lock()
            .unplaced
            .get(&(local.ip(), name.clone()))
            .map(|unplaced| (unplaced.zone.clone(), unplaced.at.clone()))?;
        let soa = Query::query(Name::from(at), RecordType::SOA);
        Some(self.look_up(req, local, zone, &soa))
    }

    /// The lookup of the SOA RRset at `apex` at `local`, which settles
    /// whether the address serves the zone there: its server answers it,
    /// and any other refuses.
    fn settle(&self, req: &Request, local: SocketAddr, apex: &LowerName) -> Step {
        let soa = Query::query(Name::from(apex), RecordType::SOA);
        self.look_up(req, local, apex.clone(), &soa)
    }

    /// The zone `addr` was noted for and does not serve, the deepest that
    /// holds `qname`, when none of `zones`, the zones it may serve, holds
    /// `qname` and `addr` was never asked about `qname` this session.
    fn lame_holding(
        &self,
        addr: IpAddr,
        qname: &LowerName,
        zones: &[Arc<dyn ZoneData>],
    ) -> Option<LowerName> {
        if zones.iter().any(|zone| zone.apex().zone_of(qname)) {
            return None;
        }
        let seen = self.seen.lock();
        if seen.asked.contains(&(addr, qname.clone())) {
            return None;
        }
        seen.lame
            .iter()
            .filter(|(at, apex)| *at == addr && apex.zone_of(qname))
            .map(|(_, apex)| apex)
            .max_by_key(|apex| label_count(apex))
            .cloned()
    }

    /// The zones the address at `local` may serve, for `question`: the
    /// copies of those it [answers from](Seen::answers_from), and an
    /// [`Unsettled`] zone for each other one it was noted for and not
    /// found lame in. A DS question at an apex the address answered DS
    /// from the zone there gets no zone above it.
    fn zones_at(&self, local: SocketAddr, question: &Query) -> Vec<Arc<dyn ZoneData>> {
        let addr = local.ip();
        let apexes = self.served.lock().get(&addr).cloned().unwrap_or_default();
        let qname = LowerName::new(question.name());
        let seen = self.seen.lock();
        let ds_below = question.query_type() == RecordType::DS
            && seen.ds_below.contains(&(addr, qname.clone()));
        apexes
            .iter()
            .filter(|apex| !seen.lame.contains(&(addr, (*apex).clone())))
            .filter(|apex| !ds_below || !apex.zone_of(&qname) || **apex == qname)
            .map(|apex| match seen.answers_from(local, apex, question) {
                true => self.copy(apex).at(addr),
                false => Arc::new(Unsettled::new(apex)) as Arc<dyn ZoneData>,
            })
            .collect()
    }
}

impl Seen {
    /// Whether the address at `local` answers `question` from the copy
    /// of the zone at `apex`: once it showed it serves the zone, and
    /// before, for a question it answered without showing whether it
    /// does, as far as [`unsettled`](Seen::unsettled) allows.
    fn answers_from(&self, local: SocketAddr, apex: &LowerName, question: &Query) -> bool {
        self.serving.contains(&(local.ip(), apex.clone()))
            || self
                .answered
                .contains_key(&Lookup::new(local, apex.clone(), question))
    }

    /// The apex of one of `zones` that the address at `local` has not
    /// shown it serves, when `reply` to `question` holds a record in that
    /// zone, and in none of `zones` below it, that its response to
    /// `question` there did not hold.
    fn unsettled(
        &self,
        local: SocketAddr,
        zones: &[Arc<dyn ZoneData>],
        question: &Query,
        reply: &Response,
    ) -> Option<LowerName> {
        let held = records(&reply.message);
        zones.iter().map(|zone| zone.apex()).find_map(|apex| {
            if self.serving.contains(&(local.ip(), apex.clone())) {
                return None;
            }
            let sent = self
                .answered
                .get(&Lookup::new(local, apex.clone(), question))?;
            let below = |owner: &LowerName| {
                zones
                    .iter()
                    .map(|zone| zone.apex())
                    .any(|other| other != apex && apex.zone_of(other) && other.zone_of(owner))
            };
            held.iter()
                .any(|key| apex.zone_of(&key.0) && !below(&key.0) && !sent.contains(key))
                .then(|| apex.clone())
        })
    }
}

/// The owner and type of every record of `message`'s answer and
/// authority sections.
fn records(message: &Message) -> HashSet<(LowerName, RecordType)> {
    message
        .answers
        .iter()
        .chain(&message.authorities)
        .map(|record| (LowerName::new(&record.name), record.record_type()))
        .collect()
}

/// Whether `response` is an authoritative answer: AA set, NOERROR,
/// NXDOMAIN, or YXDOMAIN, and not truncated, since a truncated response's
/// sections may be incomplete (RFC 2181 §9).
fn answers(response: &Message) -> bool {
    let metadata = &response.metadata;
    metadata.authoritative
        && !metadata.truncation
        && matches!(
            metadata.response_code,
            ResponseCode::NoError | ResponseCode::NXDomain | ResponseCode::YXDomain
        )
}

/// Notes what `response`, the response to `lookup`, shows about where
/// the names its address answered are placed: `placed` says it showed the
/// zone it came from. The walk that asked SOA at its question's name ends
/// when it shows a zone or that the address does not serve the zone, and
/// goes on above the name when it is an authoritative answer that shows
/// none. A new walk starts at an authoritative answer that shows no zone,
/// below a cut the copy holds or from an address that does not serve the
/// zone, and is kept for when the address turns out not to serve it
/// otherwise.
fn place(seen: &mut Seen, learned: &Learned, lookup: &Lookup, response: &Message, placed: bool) {
    let addr = lookup.server.ip();
    let zone = &lookup.zone;
    let question = &lookup.question;
    let qname = LowerName::new(question.name());
    let answered = answers(response);
    let disowned = disowns(zone, response);
    let lame = seen.lame.contains(&(addr, zone.clone()));
    // The next name up the walk from `name`: up to the cut, or for an
    // address that does not serve the zone, up to the apex.
    let above = |name: &LowerName, to_apex: bool| {
        let up = (name != zone).then(|| name.base_name())?;
        let soa = Query::query(Name::from(&up), RecordType::SOA);
        (to_apex || learned.below_cut(&soa)).then_some(up)
    };
    let soa = question.query_type() == RecordType::SOA;
    if soa {
        seen.unplaced.retain(|(at, _), unplaced| {
            if *at != addr || unplaced.zone != *zone || unplaced.at != qname {
                return true;
            }
            if placed || disowned {
                return false;
            }
            if !answered {
                return true;
            }
            match above(&qname, lame) {
                Some(up) => {
                    unplaced.at = up;
                    true
                }
                None => false,
            }
        });
    }
    if placed || !answered {
        return;
    }
    let now = lame || learned.below_cut(question);
    let at = if soa {
        above(&qname, lame || !now)
    } else {
        Some(qname.clone())
    };
    let Some(at) = at else {
        return;
    };
    let walks = match now {
        true => &mut seen.unplaced,
        false => &mut seen.deferred,
    };
    walks.entry((addr, qname)).or_insert(Unplaced {
        zone: zone.clone(),
        at,
    });
}

/// Whether `response`, a real server's to a question in the zone at
/// `zone`, shows that the server does not serve the zone: it refused the
/// question (RFC 8906 §3.1.1), or answered NOERROR or NXDOMAIN without
/// authority other than with a referral to a cut below the zone's apex
/// (RFC 1034 §4.3.1). A truncated response, whose sections may be
/// incomplete (RFC 2181 §9), and any other RCODE show nothing.
fn disowns(zone: &LowerName, response: &Message) -> bool {
    let metadata = &response.metadata;
    if metadata.truncation {
        return false;
    }
    match metadata.response_code {
        ResponseCode::Refused => true,
        ResponseCode::NoError | ResponseCode::NXDomain if !metadata.authoritative => {
            let refers_below = metadata.response_code == ResponseCode::NoError
                && response.answers.is_empty()
                && response.authorities.iter().any(|record| {
                    let owner = LowerName::new(&record.name);
                    record.record_type() == RecordType::NS
                        && record.dns_class == DNSClass::IN
                        && owner != *zone
                        && zone.zone_of(&owner)
                });
            !refers_below
        }
        _ => false,
    }
}

/// A zone an address was noted for, before a lookup showed whether its
/// real server serves it. Nothing is known there, so every question in
/// it is looked up at the address.
struct Unsettled {
    apex: LowerName,
    /// An empty SOA RRset, which no answer reads: every fact is unknown.
    soa: RecordSet,
}

impl Unsettled {
    fn new(apex: &LowerName) -> Unsettled {
        Unsettled {
            apex: apex.clone(),
            soa: RecordSet::new(Name::from(apex), RecordType::SOA, 0),
        }
    }
}

impl ZoneData for Unsettled {
    fn apex(&self) -> &LowerName {
        &self.apex
    }

    fn view(&self, _question: &Query) -> Arc<dyn View + Send + Sync> {
        Arc::new(Unsettled::new(&self.apex))
    }
}

impl View for Unsettled {
    fn apex(&self) -> &LowerName {
        &self.apex
    }

    fn revision(&self) -> Revision {
        Revision(0)
    }

    fn soa(&self) -> &RecordSet {
        &self.soa
    }

    fn node(&self, _name: &LowerName) -> Fact<&Node> {
        Fact::Unknown
    }

    fn denial(&self, _name: &LowerName, _kind: Denied) -> Fact<Vec<RecordSet>> {
        Fact::Unknown
    }
}

impl Authority for Copies {
    fn respond(
        &self,
        req: &Request,
        local: SocketAddr,
        server: &ServerConfig,
        _client: &Client,
    ) -> Step {
        if let Some(refused) = refuse_transfer(req) {
            return refused;
        }
        let addr = local.ip();
        let qname = LowerName::new(req.question.name());
        let zones = self.zones_at(local, &req.question);
        // A question of another class is answered without data
        // (`respond_from`), so it needs no lookup.
        if req.question.query_class() == DNSClass::IN {
            if let Some(step) = self.placing(req, local, &qname) {
                return step;
            }
            if let Some(lame) = self.lame_holding(addr, &qname, &zones) {
                return self.look_up(req, local, lame, &req.question);
            }
        }
        let step = respond_from(&zones, req, server, &|zone, asked, reached| {
            // A name a chain led to, answered from a zone not placed yet.
            if let Some(step) = self.placing(req, local, &reached) {
                return step;
            }
            let apex = zone.apex();
            let learned = self.copy(apex);
            let (copied, asked_before) = {
                let seen = self.seen.lock();
                let lookup = Lookup::new(local, apex.clone(), asked);
                (
                    seen.answers_from(local, apex, &req.question),
                    seen.looked.contains(&lookup),
                )
            };
            if !copied {
                // The question itself first, then the apex's SOA, which
                // settles whether the address serves the zone.
                if asked_before {
                    return self.settle(req, local, apex);
                }
                return self.look_up(req, local, apex.clone(), asked);
            }
            // A question the real server answered with an error RCODE gets
            // that RCODE, wherever the copy's answer stops.
            let mut question = asked.clone();
            if LowerName::new(question.name()) != reached
                && learned.answered(asked)
                && learned.failed(addr, asked).is_none()
            {
                question.set_name(Name::from(reached));
            }
            // A server that stopped at an alias for NSEC is asked for the
            // CNAME, which the answer then follows.
            if learned.stops_at_alias(&question) {
                question.set_query_type(RecordType::CNAME);
            }
            self.look_up(req, local, apex.clone(), &question)
        });
        // A reply from a zone the address has not shown it serves holds
        // only what its own response to the question held.
        if let Step::Reply(reply) = &step {
            let unsettled = self
                .seen
                .lock()
                .unsettled(local, &zones, &req.question, reply);
            if let Some(apex) = unsettled {
                return self.settle(req, local, &apex);
            }
        }
        step
    }

    fn file(&self, lookup: &Lookup, looked: &Looked, generation: Generation) {
        self.keep(lookup, looked, generation);
    }

    fn advance(&self, generation: Generation) {
        self.seen.lock().at(generation);
        let zones: Vec<Arc<Learned>> = self.zones.lock().values().cloned().collect();
        for learned in zones {
            learned.advance(generation);
        }
    }
}
