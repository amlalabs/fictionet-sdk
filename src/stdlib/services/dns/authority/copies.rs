//! Learned copies of real zones, each served at its real servers'
//! addresses.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use fictionet::stdlib::protocols::dns::Request;
use fictionet::stdlib::protocols::dns::op::{Message, Query, ResponseCode};
use fictionet::stdlib::protocols::dns::rr::{DNSClass, LowerName, Name, RecordType};
use fictionet::sync::Mutex;

use super::super::exchange::{Client, Generation};
use super::super::lookup::{Looked, Lookup};
use super::super::zone::{Filing, Learned, ZoneData};
use super::{Authority, ServerConfig, Step, refuse_transfer, respond_from};

/// The [learned](Learned) copies of real zones, one per apex, shared by
/// every address that serves the zone, and the zones each address serves.
///
/// At each address it answers as [`Zones`](super::Zones) over the copies
/// of the zones the address serves, looking up what they lack at the
/// address itself. A copy's view that does not know a fact the reply
/// needs never gives a negative: the copy looks the client's question up
/// ([`Step::Need`]). A server that answers as RFC 1034 and RFC 6672 say
/// carries the whole
/// CNAME and DNAME chain in its response. When the response to the
/// client's question was filed and the answer still stops at a name the
/// chain led to in the zone, as when a server stops a chain early, the
/// copy looks that name up with QTYPE instead, as the walk starts again
/// there (RFC 1034 §4.3.2 step 3a, RFC 6672 §3.2).
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
/// child, and the response is filed into the child's copy. An
/// authoritative answer below a cut the copy holds that shows no apex
/// ([`Learned::below_cut`]) comes from such a child all the same, so the
/// address is asked for the SOA RRset at the name, whose response shows
/// the child's apex (RFC 2308 §3), before the question is answered.
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
/// serves, or REFUSED when none holds the name.
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
    /// The names each address answered with authority from a zone below
    /// a cut whose apex its response did not show, with the zone of the
    /// lookup that showed it.
    unplaced: HashMap<(IpAddr, LowerName), LowerName>,
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
                // A server of a zone above a child answers DS at the
                // child's apex from the zone above (RFC 4035 §3.1.4.1), so
                // one that answers it from the child serves no zone above.
                let child_ds = lookup.question.query_type() == RecordType::DS
                    && child.as_ref() == Some(&qname);
                if disowns(&lookup.zone, response) || child_ds {
                    seen.lame.insert((addr, lookup.zone.clone()));
                }
                match &child {
                    Some(child) => seen
                        .unplaced
                        .retain(|(at, name), _| *at != addr || !child.zone_of(name)),
                    None if response.metadata.authoritative
                        && learned.below_cut(&lookup.question) =>
                    {
                        seen.unplaced
                            .insert((addr, qname.clone()), lookup.zone.clone());
                    }
                    None => {}
                }
            }
        }
        if let Some(child) = child {
            self.serves(addr, &child);
            learned = self.copy(&child);
        }
        Some(learned.file(generation, addr, &lookup.question, response))
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
        let unplaced = self
            .seen
            .lock()
            .unplaced
            .get(&(local.ip(), qname.clone()))
            .cloned();
        if let Some(zone) = unplaced {
            let soa = Query::query(Name::from(qname), RecordType::SOA);
            return Step::Need(Lookup::new(local, zone, &soa));
        }
        let zones = self.zones_at(local.ip());
        respond_from(&zones, req, server, &|zone, reached| {
            let apex = zone.apex();
            let mut question = req.question.clone();
            if LowerName::new(question.name()) != reached && self.copy(apex).answered(&req.question)
            {
                question.set_name(Name::from(reached));
            }
            Step::Need(Lookup::new(local, apex.clone(), &question))
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
