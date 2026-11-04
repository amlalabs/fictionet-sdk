//! Learned copies of real zones, each served at its real servers'
//! addresses.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use fictionet::stdlib::protocols::dns::op::{Message, Query, ResponseCode};
use fictionet::stdlib::protocols::dns::rr::{DNSClass, LowerName, Name, RecordType};
use fictionet::stdlib::protocols::dns::{Request, label_count};
use fictionet::sync::Mutex;

use super::super::exchange::{Client, Generation};
use super::super::lookup::{Looked, Lookup};
use super::super::zone::{Filing, Learned, ZoneData};
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
/// and RFC 6672 say
/// carries the whole
/// CNAME and DNAME chain in its response. When the response to the
/// client's question was filed and the answer still stops at a name the
/// chain led to in the zone, as when a server stops a chain early, the
/// copy looks that name up with QTYPE instead, as the walk starts again
/// there (RFC 1034 §4.3.2 step 3a, RFC 6672 §3.2). A server that answers
/// NSEC at an alias with NODATA, where its own denial records show the
/// CNAME, is asked for the CNAME, and the copy follows it
/// ([`Learned::stops_at_alias`]).
///
/// A world notes which address serves which zone with
/// [`serves`](Copies::serves), such as at the addresses a referral's glue
/// gives.
///
/// A real server may also serve a zone below one it was noted for, as the
/// root servers serve `arpa`, and `root-servers.net` below `net`: it
/// answers for the child's names from the child's data, never with a
/// referral to it. When a lookup's response shows the child's apex
/// ([`Learned::child_answering`]), the address is noted as serving the
/// child, and the response is filed into the child's copy. So is a
/// referral to a cut below a cut the copy holds, which only a server of
/// the zone at that cut, or one below it, gives. An
/// authoritative answer below a cut the copy holds that shows no apex
/// ([`Learned::below_cut`]) comes from such a child all the same, so the
/// address is asked for the SOA RRset at the name, whose response shows
/// the child's apex (RFC 2308 §3), before the question is answered. A
/// name that is an alias answers that with the alias alone, so the
/// address is then asked at each name above it in turn, up to the cut.
///
/// Servers of one zone differ only in the other zones they serve, so each
/// address answers from its copies as its own real server does
/// ([`Learned::at`]). An authoritative answer that shows no zone, at a
/// name below no cut the copy holds, may come from a child that only its
/// server serves, so its answer RRsets stand for that address alone, and
/// every other address looks the name up itself. A referral shows only
/// that its own server holds no zone below the cut, so the cut refers
/// the name at that address alone.
///
/// An address noted for a zone may not serve it, as the servers of a lame
/// delegation do not. A real server that does not serve a zone refuses
/// questions in it (RFC 8906 §3.1.1), or answers them without authority:
/// from a zone above it, with a referral to that zone's cut or above
/// (RFC 1034 §4.3.1). A server that serves only a zone below answers DS
/// at that zone's apex from it, where a server of a zone above answers
/// from the zone above (RFC 4035 §3.1.4.1). When a lookup's response
/// shows any of that, the address answers for the rest of the session as
/// though it had never been noted for the zone: from the other zones it
/// serves, or REFUSED when none holds the name. The server may still
/// serve a zone below the one it does not, so a name in that zone the
/// address was never asked about is looked up there all the same, and
/// answered from the child zone its response shows, or REFUSED when it
/// shows none. The answer does not depend on what was asked before.
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
    /// The zones addresses were noted for and turned out not to serve.
    lame: HashSet<(IpAddr, LowerName)>,
    /// The names each address was asked about in a lookup.
    asked: HashSet<(IpAddr, LowerName)>,
    /// The names each address answered with authority from a zone below
    /// a cut whose apex its response did not show.
    unplaced: HashMap<(IpAddr, LowerName), Unplaced>,
}

/// A name an address answered with authority from a zone below a cut,
/// whose apex no response has shown yet.
struct Unplaced {
    /// The zone of the lookup that showed it.
    zone: LowerName,
    /// The name whose SOA RRset the address is asked for next: the name
    /// itself, then each name above it up to the cut. An SOA question at
    /// an alias is answered with the alias, which shows no apex
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
            lame: HashSet::new(),
            asked: HashSet::new(),
            unplaced: HashMap::new(),
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
    /// zone the response comes from. A response that shows the address
    /// does not serve the zone the lookup names gives nothing, and the
    /// address stops answering for that zone this session. `None` when the
    /// lookup brought no response.
    pub fn keep(&self, lookup: &Lookup, looked: &Looked, generation: Generation) -> Option<Filing> {
        let Looked::Response(response) = looked else {
            return None;
        };
        let addr = lookup.server.ip();
        let qname = LowerName::new(lookup.question.name());
        let mut learned = self.copy(&lookup.zone);
        let child = learned.child_answering(&lookup.question, response);
        {
            let mut seen = self.seen.lock();
            if seen.at(generation) {
                seen.asked.insert((addr, qname.clone()));
                // A server of a zone above a child answers DS at the
                // child's apex from the zone above (RFC 4035 §3.1.4.1), so
                // one that answers it from the child serves no zone above.
                let child_ds = lookup.question.query_type() == RecordType::DS
                    && child.as_ref() == Some(&qname);
                match &child {
                    Some(child) => seen
                        .unplaced
                        .retain(|(at, name), _| *at != addr || !child.zone_of(name)),
                    None if response.metadata.authoritative
                        && learned.below_cut(&lookup.question) =>
                    {
                        // The name above `name` up to the cut, if any.
                        let above = |name: &LowerName| {
                            let up = name.base_name();
                            let soa = Query::query(Name::from(&up), RecordType::SOA);
                            learned.below_cut(&soa).then_some(up)
                        };
                        let soa = lookup.question.query_type() == RecordType::SOA;
                        if soa {
                            seen.unplaced.retain(|(at, _), unplaced| {
                                if *at != addr
                                    || unplaced.zone != lookup.zone
                                    || unplaced.at != qname
                                {
                                    return true;
                                }
                                match above(&qname) {
                                    Some(up) => {
                                        unplaced.at = up;
                                        true
                                    }
                                    None => false,
                                }
                            });
                        }
                        let at = if soa {
                            above(&qname)
                        } else {
                            Some(qname.clone())
                        };
                        if let Some(at) = at {
                            seen.unplaced
                                .entry((addr, qname.clone()))
                                .or_insert(Unplaced {
                                    zone: lookup.zone.clone(),
                                    at,
                                });
                        }
                    }
                    None => {}
                }
                if disowns(&lookup.zone, response) || child_ds {
                    seen.lame.insert((addr, lookup.zone.clone()));
                    // The address answers as though never noted for the
                    // zone, so nothing is placed in it there.
                    seen.unplaced
                        .retain(|(at, _), unplaced| *at != addr || unplaced.zone != lookup.zone);
                }
            }
        }
        if let Some(child) = child {
            self.serves(addr, &child);
            learned = self.copy(&child);
        }
        Some(learned.file(generation, addr, &lookup.question, response))
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

    /// The zone `addr` was noted for and does not serve, the deepest that
    /// holds `qname`, when none of `zones`, the zones it serves, holds
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

    /// The copies of the zones `addr` serves.
    fn zones_at(&self, addr: IpAddr) -> Vec<Arc<dyn ZoneData>> {
        let apexes = self.served.lock().get(&addr).cloned().unwrap_or_default();
        let seen = self.seen.lock();
        apexes
            .iter()
            .filter(|apex| !seen.lame.contains(&(addr, (*apex).clone())))
            .map(|apex| self.copy(apex).at(addr))
            .collect()
    }
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
        let qname = LowerName::new(req.question.name());
        let zones = self.zones_at(local.ip());
        // A question of another class is answered without data
        // (`respond_from`), so it needs no lookup.
        if req.question.query_class() == DNSClass::IN {
            let unplaced = self
                .seen
                .lock()
                .unplaced
                .get(&(local.ip(), qname.clone()))
                .map(|unplaced| (unplaced.zone.clone(), unplaced.at.clone()));
            if let Some((zone, at)) = unplaced {
                let soa = Query::query(Name::from(at), RecordType::SOA);
                return self.look_up(req, local, zone, &soa);
            }
            if let Some(lame) = self.lame_holding(local.ip(), &qname, &zones) {
                return self.look_up(req, local, lame, &req.question);
            }
        }
        respond_from(&zones, req, server, &|zone, asked, reached| {
            let apex = zone.apex();
            let learned = self.copy(apex);
            // A question the real server answered with an error RCODE gets
            // that RCODE, wherever the copy's answer stops.
            let mut question = asked.clone();
            if LowerName::new(question.name()) != reached
                && learned.answered(asked)
                && learned.failed(local.ip(), asked).is_none()
            {
                question.set_name(Name::from(reached));
            }
            // A server that stopped at an alias for NSEC is asked for the
            // CNAME, which the answer then follows.
            if learned.stops_at_alias(&question) {
                question.set_query_type(RecordType::CNAME);
            }
            self.look_up(req, local, apex.clone(), &question)
        })
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
