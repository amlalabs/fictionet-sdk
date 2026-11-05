//! An authority for tests of the engine's lookups: it knows nothing until
//! a lookup tells it, so every question it has not looked up yet gives
//! [`Step::Need`].

use std::collections::HashMap;
use std::net::SocketAddr;

use fictionet::stdlib::protocols::dns::Request;
use fictionet::stdlib::protocols::dns::op::{Message, ResponseCode};
use fictionet::stdlib::protocols::dns::rr::{DNSClass, LowerName, Name, Record, RecordType};
use fictionet::stdlib::services::dns::authority::{
    Authority, ServerConfig, Step, bare_reply, refuse_transfer, respond_from_zones,
};
use fictionet::stdlib::services::dns::{Client, Generation, Looked, Lookup};
use fictionet::sync::Mutex;

/// The server of one zone at any address, which answers each question
/// from the records a lookup of that question filed, and looks up every
/// question it holds no records for at its own address.
///
/// A filed response gives the reply's RCODE and AA bit, its answer
/// section's records at the question's name of the type asked or CNAME,
/// in the client's case, and its authority and additional sections.
/// Without DO the reply leaves out RRSIG, NSEC, and NSEC3 records
/// (RFC 4035 §3.1). A lookup that brought no response files nothing, so
/// the question is looked up again. What a session filed is dropped when
/// a newer one starts. A zone transfer is refused, a class other than IN
/// is answered as [`Zones`](fictionet::stdlib::services::dns::authority::Zones)
/// answers it, and a name outside the zone is REFUSED.
pub struct LookupAuthority {
    zone: LowerName,
    filed: Mutex<Filed>,
}

/// The responses of one session, by the question each answered.
struct Filed {
    generation: Generation,
    responses: HashMap<(LowerName, RecordType), Message>,
}

impl Filed {
    /// Nothing filed, in session 0.
    fn new() -> Filed {
        Filed {
            generation: Generation(0),
            responses: HashMap::new(),
        }
    }

    /// Starts session `generation` if it is newer than the one held, and
    /// whether `generation` is the session held now.
    fn at(&mut self, generation: Generation) -> bool {
        if generation > self.generation {
            *self = Filed {
                generation,
                responses: HashMap::new(),
            };
        }
        generation == self.generation
    }
}

impl LookupAuthority {
    /// The server of the zone at `apex`, holding nothing yet.
    pub fn new(apex: &str) -> LookupAuthority {
        let apex = Name::from_ascii(apex).expect("a valid apex");
        LookupAuthority {
            zone: LowerName::new(&apex),
            filed: Mutex::new(Filed::new()),
        }
    }
}

/// The key of the question `name` and `rtype`.
fn key(name: &Name, rtype: RecordType) -> (LowerName, RecordType) {
    (LowerName::new(name), rtype)
}

/// Whether `record` is a DNSSEC record a reply carries only with DO.
fn dnssec(record: &Record) -> bool {
    matches!(
        record.record_type(),
        RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3
    )
}

impl Authority for LookupAuthority {
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
        if req.question.query_class() != DNSClass::IN {
            // No zone holds another class, so no fact is ever unknown.
            return respond_from_zones(&[], req, server, &|_, _, _| {
                unreachable!("no zone is asked")
            });
        }
        let qname = req.question.name();
        if !self.zone.zone_of(&LowerName::new(qname)) {
            let refused = bare_reply(req, ResponseCode::Refused, None);
            return Step::Reply(refused);
        }
        let qtype = req.question.query_type();
        let filed = self.filed.lock();
        let Some(response) = filed.responses.get(&key(qname, qtype)) else {
            return Step::Need(Lookup::new(local, self.zone.clone(), &req.question));
        };
        let dnssec_ok = req.edns.is_some_and(|edns| edns.dnssec_ok);
        let shown = |record: &&Record| dnssec_ok || !dnssec(record);
        let mut reply = bare_reply(req, response.metadata.response_code, None);
        let message = &mut reply.message;
        message.metadata.authoritative = response.metadata.authoritative;
        // The answer section's records at the question's name of the type
        // asked, or a CNAME there, with their RRSIGs.
        for record in response.answers.iter().filter(shown) {
            let at_qname = LowerName::new(&record.name) == LowerName::new(qname);
            let asked = match record.record_type() {
                RecordType::RRSIG | RecordType::CNAME => true,
                rtype => rtype == qtype,
            };
            if at_qname && asked {
                let mut record = record.clone();
                record.name = qname.clone();
                message.add_answer(record);
            }
        }
        for record in response.authorities.iter().filter(shown) {
            message.add_authority(record.clone());
        }
        for record in response.additionals.iter().filter(shown) {
            message.add_additional(record.clone());
        }
        Step::Reply(reply)
    }

    fn file(&self, lookup: &Lookup, looked: &Looked, generation: Generation) {
        let Looked::Response(response) = looked else {
            return;
        };
        let mut filed = self.filed.lock();
        if filed.at(generation) {
            let question = &lookup.question;
            let key = key(question.name(), question.query_type());
            filed.responses.insert(key, response.clone());
        }
    }

    fn advance(&self, generation: Generation) {
        self.filed.lock().at(generation);
    }
}
