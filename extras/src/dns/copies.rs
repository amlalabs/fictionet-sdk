//! Learned copies of real zones, each address answering from its own.

use std::cell::Cell;
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use fictionet::stdlib::protocols::dns::dnssec::rdata::DNSSECRData;
use fictionet::stdlib::protocols::dns::op::{Message, Query, ResponseCode};
use fictionet::stdlib::protocols::dns::rr::{
    DNSClass, LowerName, Name, RData, Record, RecordSet, RecordType,
};
use fictionet::stdlib::protocols::dns::{Request, label_count};
use fictionet::stdlib::services::dns::authority::{
    Authority, ServerConfig, Step, bare_reply, refuse_transfer, respond_from_zones,
};
use fictionet::stdlib::services::dns::zone::{Denied, Fact, Node, Revision, View, ZoneData};
use fictionet::stdlib::services::dns::{Client, Generation, Looked, Lookup};
use fictionet::sync::Mutex;

use super::learned::{Declined, Filing, Learned};

/// Learned copies of real zones, kept per address: each address holds
/// its own [learned](Learned) copy of each zone it serves, filled only
/// from the responses of the real server at that address. Nothing is
/// shared between addresses, so each address answers as its own real
/// server does, whatever was asked at the others.
///
/// At each address it answers as
/// [`Zones`](fictionet::stdlib::services::dns::authority::Zones) over that
/// address's copies, looking up what they lack at the address itself. A
/// copy's view that does not know a fact the reply needs never gives a
/// negative: the copy looks the client's question up ([`Step::Need`]).
/// When the real server answered that lookup with an error RCODE that
/// gives no facts, such as FORMERR or SERVFAIL, the reply is that RCODE
/// ([`Learned::failed`]). A server that answers as RFC 1034 and RFC 6672
/// say carries the whole CNAME and DNAME chain in its response. When the
/// response to the client's question was filed and the answer still stops
/// at a name the chain led to in the zone, as when a server stops a chain
/// early, the copy looks that name up with QTYPE instead, as the walk
/// starts again there (RFC 1034 §4.3.2 step 3a, RFC 6672 §3.2). A server
/// that answers NSEC at an alias with NODATA, where its own denial
/// records show the CNAME, is asked for the CNAME, and the copy follows it
/// ([`Learned::stops_at_alias`]).
///
/// A world notes which zones an address serves with
/// [`serves`](Copies::serves), such as at the addresses a referral's glue
/// gives. Each response then goes into one zone of the address that sent
/// it, the zone it shows it came from ([`file`](Authority::file)), which
/// adds a zone to the address when the response shows one it did not
/// hold, such as `arpa` at a root letter. A question the real server
/// answered from another zone than the one it was asked in, or refused
/// (RFC 8906 §3.1.1), or answered without authority (RFC 1034 §4.3.1),
/// is [declined](Learned::decline) in that zone: the address answers it
/// from its other zones, and with REFUSED when none holds the name, so it
/// answers as its real server did and is never silent.
///
/// Real servers depart from the RFCs in ways a copy cannot always tell
/// apart, so each case is normalized where it is handled, on a best-effort
/// basis. A real server's departure that cannot be normalized is copied
/// as the server sent it. So an address whose real server referred a
/// question upward, to a cut at or above the zone asked, from a zone the
/// address does not hold, answers it with REFUSED, as a server that does
/// not serve the name does (RFC 8906 §3.1.1).
#[derive(Default)]
pub struct Copies {
    /// Each address's copies.
    servers: Mutex<HashMap<IpAddr, Arc<Server>>>,
}

/// The copies one address answers from, by apex.
#[derive(Default)]
struct Server {
    zones: Mutex<BTreeMap<LowerName, Arc<Learned>>>,
}

impl Server {
    /// The copy of the zone at `apex`, made empty the first time.
    fn zone(&self, apex: &LowerName) -> Arc<Learned> {
        self.zones
            .lock()
            .entry(apex.clone())
            .or_insert_with(|| Arc::new(Learned::new(&Name::from(apex))))
            .clone()
    }

    /// Every copy the address holds.
    fn zones(&self) -> Vec<Arc<Learned>> {
        self.zones.lock().values().cloned().collect()
    }
}

impl Copies {
    /// Copies of no zone, served nowhere.
    pub fn new() -> Copies {
        Copies::default()
    }

    /// The copies of the address `addr`, none the first time.
    fn server(&self, addr: IpAddr) -> Arc<Server> {
        self.servers.lock().entry(addr).or_default().clone()
    }

    /// Notes that `addr` serves the zone at `zone`.
    pub fn serves(&self, addr: IpAddr, zone: &LowerName) {
        self.server(addr).zone(zone);
    }

    /// Files what `lookup`, made in session `generation`, gave, as
    /// [`Authority::file`] does, and returns what the copy it went into
    /// kept. `None` when the lookup brought no response.
    ///
    /// A response goes into the zone of the lookup's address that it
    /// [comes from](zone_of), and a question whose response went into
    /// another zone is [declined](Declined::Elsewhere) in the zone asked.
    /// So is one the server answered with a referral to a cut at or above
    /// the apex of the zone asked, from a zone above it, which files
    /// nothing. A REFUSED and a response without AA that is no referral
    /// file nothing, and the question is [declined](Declined::Refused) in
    /// the zone asked: the server does not serve the zone
    /// (RFC 8906 §3.1.1, RFC 1034 §4.3.1). Any other error RCODE goes into
    /// the zone asked ([`Learned::failed`]), and a truncated response,
    /// whose sections may be incomplete (RFC 2181 §9), files nothing.
    pub fn keep(&self, lookup: &Lookup, looked: &Looked, generation: Generation) -> Option<Filing> {
        let Looked::Response(response) = looked else {
            return None;
        };
        let server = self.server(lookup.server.ip());
        let asked = server.zone(&lookup.zone);
        let question = &lookup.question;
        let metadata = &response.metadata;
        let nothing = Filing {
            zone: lookup.zone.clone(),
            sets: Vec::new(),
        };
        let declined = match metadata.response_code {
            _ if metadata.truncation => return Some(nothing),
            ResponseCode::Refused => Some(Declined::Refused),
            ResponseCode::NoError | ResponseCode::NXDomain | ResponseCode::YXDomain => {
                match (metadata.authoritative, referral(question, response)) {
                    (true, _) => None,
                    (false, Some(cut)) if cut != lookup.zone && lookup.zone.zone_of(&cut) => None,
                    (false, Some(_)) => Some(Declined::Elsewhere),
                    (false, None) => Some(Declined::Refused),
                }
            }
            _ => return Some(asked.file(generation, question, response)),
        };
        if let Some(why) = declined {
            asked.decline(generation, question, why);
            return Some(nothing);
        }
        let apex = zone_of(&server, lookup, response);
        if apex != lookup.zone {
            asked.decline(generation, question, Declined::Elsewhere);
        }
        Some(server.zone(&apex).file(generation, question, response))
    }
}

/// The cut `response` refers `question` to, when it is a referral:
/// NOERROR, no answer, and an NS RRset in its authority section owned at
/// or above the question's name, the deepest when it holds more than one.
fn referral(question: &Query, response: &Message) -> Option<LowerName> {
    let qname = LowerName::new(question.name());
    if response.metadata.response_code != ResponseCode::NoError || !response.answers.is_empty() {
        return None;
    }
    response
        .authorities
        .iter()
        .filter(|record| record.record_type() == RecordType::NS && record.dns_class == DNSClass::IN)
        .map(|record| LowerName::new(&record.name))
        .filter(|owner| owner.zone_of(&qname))
        .max_by_key(|owner| label_count(owner))
}

/// The apex of the zone of `server` that `response`, an authoritative
/// answer or a referral to `lookup`, comes from, by the first rule that
/// applies, each zone holding the question's name:
///
/// 1. the zone that signed its answer RRsets at or above the question's
///    name, or else its NSEC, NSEC3, or DS RRsets (RFC 4034 §3.1.7);
/// 2. for an answer, the owner of the SOA RRset in its authority section,
///    which a negative carries for its zone (RFC 2308 §3);
/// 3. for an answer, the owner of an NS RRset in its authority section,
///    which an answer carries only for its zone's apex;
/// 4. for an answer, the question's name, when the answer section holds
///    an SOA or NS RRset there, which an answer holds only at an apex;
/// 5. for a referral, the deepest zone of `server` strictly above the
///    cut;
/// 6. otherwise, the deepest zone of `server`.
///
/// Rules 5 and 6 pass over a zone that declined the question. A zone
/// they give may hold a cut that the response's data lies below, which
/// only a zone below the cut holds (RFC 1034 §4.2.1): the server also
/// serves a zone there, which a minimal answer does not show
/// (RFC 2181 §6.1). As a best-effort normalization the response then goes
/// into a zone of `server` at the deepest such cut, which answers what
/// such responses gave and declines the rest. A zone shown by rules 1 to
/// 4 that `server` did not hold is added to it.
fn zone_of(server: &Server, lookup: &Lookup, response: &Message) -> LowerName {
    let question = &lookup.question;
    let qname = LowerName::new(question.name());
    let holds = |apex: &LowerName| apex.zone_of(&qname);
    if let Some(signer) = signer(response, &qname).filter(holds) {
        return signer;
    }
    let authoritative = response.metadata.authoritative;
    let owners = |records: &[Record], rtype: RecordType| {
        records
            .iter()
            .filter(move |record| record.record_type() == rtype && record.dns_class == DNSClass::IN)
            .map(|record| LowerName::new(&record.name))
            .collect::<Vec<_>>()
    };
    let deepest = |owners: Vec<LowerName>| {
        owners
            .into_iter()
            .filter(holds)
            .max_by_key(|owner| label_count(owner))
    };
    if authoritative {
        let shown = deepest(owners(&response.authorities, RecordType::SOA))
            .or_else(|| deepest(owners(&response.authorities, RecordType::NS)))
            .or_else(|| {
                let at_apex = [RecordType::SOA, RecordType::NS]
                    .into_iter()
                    .any(|rtype| owners(&response.answers, rtype).contains(&qname));
                at_apex.then(|| qname.clone())
            });
        if let Some(apex) = shown {
            return apex;
        }
    }
    // The name whose data the response holds, and the type of that data:
    // a referral's cut, whose parent holds it as DS does, or the
    // question's name.
    let (name, rtype) = match authoritative {
        false => {
            let cut = referral(question, response).unwrap_or_else(|| qname.clone());
            (cut, RecordType::DS)
        }
        true => (qname.clone(), question.query_type()),
    };
    let zones = server.zones();
    let mut apex = zones
        .iter()
        .filter(|zone| {
            let apex = zone.apex();
            apex.zone_of(&name)
                && (authoritative || *apex != name)
                && zone.declined(question).is_none()
        })
        .map(|zone| zone.apex().clone())
        .max_by_key(|name| label_count(name))
        .unwrap_or_else(|| lookup.zone.clone());
    while let Some(cut) = server.zone(&apex).cut_over(&name, rtype) {
        apex = cut;
    }
    apex
}

/// The deepest zone that signed the RRsets of `response`'s answer section
/// at or above `qname`, or else its NSEC, NSEC3, or DS RRsets
/// (RFC 4034 §3.1.7).
fn signer(response: &Message, qname: &LowerName) -> Option<LowerName> {
    let signers = |records: &[Record], covers: &dyn Fn(&LowerName, RecordType) -> bool| {
        records
            .iter()
            .filter_map(|record| match &record.data {
                RData::DNSSEC(DNSSECRData::RRSIG(rrsig))
                    if record.dns_class == DNSClass::IN
                        && covers(&LowerName::new(&record.name), rrsig.input().type_covered) =>
                {
                    Some(LowerName::new(&rrsig.input().signer_name))
                }
                _ => None,
            })
            .max_by_key(|name| label_count(name))
    };
    signers(&response.answers, &|owner, _| owner.zone_of(qname)).or_else(|| {
        signers(&response.authorities, &|_, covered| {
            matches!(
                covered,
                RecordType::NSEC | RecordType::NSEC3 | RecordType::DS
            )
        })
    })
}

/// Where the answer at one address goes around a question one of its
/// zones declined.
#[derive(Clone, Debug, PartialEq)]
enum Around {
    /// The address answers the reply from its zones but this one.
    Zone(LowerName),
    /// A chain stops at this name, which the real server answers from
    /// none of its zones: the reply ends with the chain up to it.
    Name(LowerName),
}

/// A name a chain stops at ([`Around::Name`]), as a zone at the name that
/// knows nothing, so the answer of the zone above it stops there
/// (RFC 1034 §4.3.2 step 3a).
struct Stop {
    apex: LowerName,
    /// An empty SOA RRset, which no answer reads: every fact is unknown.
    soa: RecordSet,
}

impl Stop {
    fn new(apex: &LowerName) -> Stop {
        Stop {
            apex: apex.clone(),
            soa: RecordSet::new(Name::from(apex), RecordType::SOA, 0),
        }
    }
}

impl ZoneData for Stop {
    fn apex(&self) -> &LowerName {
        &self.apex
    }

    fn view(&self, _question: &Query) -> Arc<dyn View + Send + Sync> {
        Arc::new(Stop::new(&self.apex))
    }
}

impl View for Stop {
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
    /// Answers `req` at `local` from that address's copies, as the type's
    /// documentation says. A zone that declined a question the reply
    /// needs is gone around: a chain from another name that reaches a
    /// declined name stops there, as the real server's chain stops at a
    /// name in none of its zones, and any other reply is answered from
    /// the address's other zones.
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
        let copies = self.server(local.ip()).zones();
        let mut around: Vec<Around> = Vec::new();
        loop {
            let copies: Vec<&Arc<Learned>> = copies
                .iter()
                .filter(|learned| !around.contains(&Around::Zone(learned.apex().clone())))
                .collect();
            let stops = around.iter().filter_map(|around| match around {
                Around::Name(name) => Some(Arc::new(Stop::new(name)) as Arc<dyn ZoneData>),
                Around::Zone(_) => None,
            });
            let zones: Vec<Arc<dyn ZoneData>> = copies
                .iter()
                .map(|learned| (*learned).clone() as Arc<dyn ZoneData>)
                .chain(stops)
                .collect();
            let next = Cell::new(None);
            let step = respond_from_zones(&zones, req, server, &|zone, asked, reached| {
                let apex = zone.apex();
                let Some(learned) = copies.iter().find(|learned| learned.apex() == apex) else {
                    // The chain reached a stop: the rest of the reply is
                    // empty, and the reply holds the chain alone.
                    return Step::Reply(bare_reply(req, ResponseCode::NoError, None));
                };
                // A question the real server answered with an error RCODE
                // gets that RCODE, wherever the copy's answer stops.
                let mut question = asked.clone();
                if LowerName::new(question.name()) != reached
                    && learned.answered(asked)
                    && learned.failed(asked).is_none()
                {
                    question.set_name(Name::from(reached));
                }
                // A server that stopped at an alias for NSEC is asked for
                // the CNAME, which the answer then follows.
                if learned.stops_at_alias(&question) {
                    question.set_query_type(RecordType::CNAME);
                }
                if let Some(why) = learned.declined(&question) {
                    // A name the server holds in no zone ends a chain that
                    // reached it. A stop at a name at or above the
                    // question's, or at the apex of a copy, would answer
                    // for more than that name.
                    let name = LowerName::new(question.name());
                    let stop = Around::Name(name.clone());
                    if around.contains(&stop) {
                        // Asked of a zone above the stop, as DS at its
                        // apex is: the zone refers it on to the stop.
                        return Step::Reply(bare_reply(req, ResponseCode::NoError, None));
                    }
                    let whole = why == Declined::Elsewhere
                        || name.zone_of(&qname)
                        || copies.iter().any(|learned| *learned.apex() == name);
                    next.set(Some(match whole {
                        true => Around::Zone(apex.clone()),
                        false => stop,
                    }));
                    return Step::Silent;
                }
                match learned.failed(&question) {
                    // A server sends that RCODE rather than no reply
                    // (RFC 8906 §3.1.1).
                    Some(rcode) => Step::Reply(bare_reply(req, rcode, None)),
                    None => Step::Need(Lookup::new(local, apex.clone(), &question)),
                }
            });
            match next.take() {
                Some(next) => around.push(next),
                None => return step,
            }
        }
    }

    fn file(&self, lookup: &Lookup, looked: &Looked, generation: Generation) {
        self.keep(lookup, looked, generation);
    }

    fn advance(&self, generation: Generation) {
        let servers: Vec<Arc<Server>> = self.servers.lock().values().cloned().collect();
        for server in servers {
            for learned in server.zones() {
                learned.advance(generation);
            }
        }
    }
}
