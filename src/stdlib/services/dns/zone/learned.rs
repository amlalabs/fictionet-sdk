//! A zone whose data is copied from the responses of its real servers, as
//! a world's server needs it.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use std::ops::Bound;
use std::sync::Arc;

use fictionet::stdlib::protocols::dns::dname_substitute;
use fictionet::stdlib::protocols::dns::dnssec::proof::{self, Claim, Proof, proof_of};
use fictionet::stdlib::protocols::dns::dnssec::rdata::DNSSECRData;
use fictionet::stdlib::protocols::dns::op::{Message, Query, ResponseCode};
use fictionet::stdlib::protocols::dns::rr::{
    DNSClass, LowerName, Name, RData, Record, RecordSet, RecordType,
};
use fictionet::sync::Mutex;

use super::super::exchange::Generation;
use super::super::records::{expanded_from, rrsets};
use super::data::{Denied, Fact, Revision, View, ZoneData};
use super::zone::{Node, dname_target, targets, wildcard};

/// Zone data copied from what one zone's real servers answered, one
/// session at a time.
///
/// A world's server never passes a real server's message on. It answers
/// from this data with [`answer`](super::answer), and when a reply needs a
/// fact the data does not hold, [`Copies`](super::super::authority::Copies)
/// looks the client's question up at a real server of the zone, or the
/// name its chain reached when that response did not settle it, and
/// [files](Learned::file) the response here.
/// Every fact the data holds was filed from such a response:
///
/// - An authoritative answer (AA set, NOERROR, NXDOMAIN, or YXDOMAIN)
///   gives the RRsets of its answer section that are in the zone and not
///   below a cut it holds, each with its RRSIGs; the zone's apex NS RRset
///   from its authority section; and the A and AAAA RRsets of its
///   additional section, which never replace an RRset an answer section
///   gave or stand against a filed NODATA, and which are served only as
///   additional data, never as an answer (RFC 2181 §5.4.1): such an RRset
///   may be glue below a cut the zone does not hold yet, or sent without
///   its RRSIGs. A DNAME is kept, and the CNAME synthesized from it is not
///   (RFC 6672 §3.4); a YXDOMAIN gives the DNAME whose new name would pass
///   255 octets (RFC 6672 §2.2). An RRset of the answer section whose
///   RRSIGs show a wildcard expansion (a Labels field below the owner's
///   label count, RFC 4035 §5.3.4) is kept at the wildcard that made it,
///   the name one label below the wildcard's parent toward the owner is
///   kept as absent, and the authority section's NSEC and NSEC3 records
///   that prove the expansion are kept as its proof (RFC 4035 §3.1.3.3,
///   RFC 5155 §7.2.6). An answer to ANY or RRSIG expanded from a wildcard
///   is kept the same way.
/// - A NODATA for NSEC whose denial records show a CNAME at the name, or
///   at the wildcard that answers for it, is no negative: the server
///   stopped at an alias that RFC 1034 §4.3.2 step 3a follows for NSEC
///   when no NSEC RRset sits beside it ([`stops_at_alias`](Learned::stops_at_alias)).
/// - Where the answer's CNAME and DNAME chain ends inside the zone
///   without an RRset of the type asked, the answer is negative there. A
///   DNAME moves the chain on whatever the type asked (RFC 6672 §3.2); a
///   CNAME does unless the question asks for CNAME, ANY, or RRSIG. A
///   CNAME the chain passes for an NSEC question shows that its owner, or
///   the wildcard that made it, has no NSEC RRset, which may sit beside a
///   CNAME (RFC 4035 §2.5). With the zone's SOA in its authority section
///   (RFC 2308 §5), NXDOMAIN keeps
///   the name as absent, and so the names below it (RFC 8020), and the
///   wildcard at its parent, which would have matched it; NOERROR keeps
///   the type as absent at the name. The authority section's NSEC and
///   NSEC3 records that prove the negative, with their RRSIGs, are kept as
///   its proof, and an unsigned zone's proof is empty, as the server sent
///   it. When the records sent do not prove the negative, all of them are
///   kept as its proof, as the server sent them. A negative without the
///   SOA is not kept. A chain that ends below a cut of the zone ends in a
///   referral, with the cut's NS RRset in the authority section and no
///   SOA (RFC 1034 §4.3.2 step 3b), which gives the cut as a referral
///   does.
/// - A referral (AA clear, NOERROR, an NS RRset below the apex at or
///   above the question's name) gives a zone cut: the NS RRset, the glue
///   for its targets at or below the cut (RFC 9471 §3.1), and the DS
///   RRset, or else the NSEC and NSEC3 records sent beside it that prove
///   the cut has none, which the copy's referrals carry
///   (RFC 4035 §3.1.4). It shows that the server holds no zone at the
///   name it referred or above it, below the cut. A referral for an NSEC
///   question at the cut shows that the parent holds no NSEC RRset there.
/// - An error RCODE other than REFUSED, such as FORMERR for a meta-type,
///   gives no records, only that the server answers the question with
///   that RCODE ([`failed`](Learned::failed)): a server may answer so,
///   and must answer (RFC 8906 §3.1). An authoritative SERVFAIL whose
///   answer is a CNAME loop, which RFC 1034 §3.6.2 has signalled as an
///   error, gives its CNAME RRsets too, as an answer does.
/// - Any other response, such as REFUSED, an answer without AA, or a
///   truncated response (TC set), whose sections may be incomplete
///   (RFC 2181 §9), gives nothing.
///
/// TTLs are kept as sent, since an authoritative TTL does not count down,
/// and RRSIGs as they came: copied records are never signed again, so a
/// validator checks the real zone's signatures and proofs.
///
/// A view holds one revision of the data, and every filing makes a new
/// one. Through a view, a name the answer may end at (the question's
/// name, a target of the CNAME and DNAME chain from it, or a wildcard
/// that could answer for one) is present with its RRsets only when the
/// data holds the fact the question's type needs there: an RRset of that
/// type from an answer or authority section, a CNAME from one unless the
/// question asks for NSEC and the name is not known to lack it, or the
/// type known absent. A wildcard's absent type answers only a question
/// for the wildcard itself: a name the wildcard answers for needs the
/// proof that came for it (RFC 5155 §7.2.5), not the proof for the
/// wildcard's own name. Such a name the data holds, or holds names below,
/// is otherwise an empty node that answers nothing
/// ([`View::answers_empty`] is false), so the answer ends unknown there
/// and the server looks the question up. Any other name the data holds
/// is present as it is, since the answer only passes it on the way down
/// or reads optional addresses there. A name is absent only where a
/// filed negative said so, and [`View::denial`] gives only the proof that
/// came with it. Questions for ANY and for RRSIG are answered from the
/// response to that same question alone, since a server may answer ANY
/// with a subset or a made-up HINFO (RFC 8482 §4).
///
/// The zone's real servers hold the same data, but each may also hold
/// zones below cuts of this one, as the root servers hold
/// `root-servers.net` below `net`, and a real server answers from the
/// deepest zone it holds (RFC 1034 §4.3.2). So the data is viewed as one
/// server answers it ([`at`](Learned::at)). A cut refers a name on the
/// chain at or below it only when a referral from that server to that
/// cut was filed for that name or a name below it. A referral for one
/// name says nothing of other cuts, of the zones its server holds under
/// the cut at other names, or of the zones other servers hold. A
/// referral to a cut below a cut the data holds comes from a zone below
/// that cut, which its server also serves. An authoritative answer shows the
/// zone it comes from with the zone's SOA or apex NS RRset in its
/// authority section, with the zone's signature on its answer
/// (RFC 4034 §3.1.7), or by being for the apex or a name the zone holds
/// data at; one that shows none, such as a minimal response, may come
/// from a zone below a cut the data does not hold yet. Its answer RRsets
/// are then the answers of the server that sent them alone, and the
/// names they are at are unknown to the other servers until a response
/// shows the zone there. A DS or NSEC question at
/// the cut is answered from the parent's side (RFC 4035 §2.6, §3.1.4.1):
/// from a filed RRset of the type, a filed NODATA for DS, or a referral
/// filed for NSEC there. A referral carries no SOA, and may come from a
/// zone below this one that the server also serves, so it never makes a
/// DS NODATA. An unknown fact never becomes NXDOMAIN or NODATA.
///
/// A real server that also serves a zone below this one answers for that
/// zone's names from the child's data. [`child_answering`](Learned::child_answering)
/// tells such a response apart, so that it is filed into the child's copy
/// instead, and [`below_cut`](Learned::below_cut) tells an authoritative
/// answer from a zone whose apex it does not show
/// ([`Copies`](super::super::authority::Copies) does both).
///
/// Facts belong to a session ([`Generation`]): [`advance`](Learned::advance)
/// to a newer one drops them all, and a response to a lookup made in an
/// older session is not filed.
pub struct Learned {
    apex: LowerName,
    held: Mutex<Held>,
}

/// What one response gave a [`Learned`] zone: the RRsets it kept, each as
/// the real server sent it, owned by the name the response gave it even
/// when a wildcard made it. A world learns from these which names and
/// addresses its copies hold, such as where the name servers a referral
/// names are.
#[derive(Clone, Debug, PartialEq)]
pub struct Filing {
    /// The apex of the zone the RRsets were filed into.
    pub zone: LowerName,
    /// The RRsets kept, each with the section it came from, in the order
    /// they were filed: for an answer, the apex NS RRset, the answers,
    /// then additional data; for a referral, its NS RRset, its glue, and
    /// its DS RRset.
    pub sets: Vec<(Section, RecordSet)>,
}

/// The session a [`Learned`] zone's facts belong to, and the facts.
struct Held {
    generation: Generation,
    facts: Arc<Facts>,
}

/// What a [`Learned`] zone holds at one revision.
#[derive(Clone)]
struct Facts {
    revision: Revision,
    names: BTreeMap<LowerName, Known>,
    /// Names a filed NXDOMAIN or wildcard expansion showed do not exist.
    /// Nothing exists below them either (RFC 8020).
    absent: BTreeSet<LowerName>,
    /// The names below a cut a filed referral was for, the question's
    /// name or the name its chain ended at, each with the servers that
    /// sent such a referral and the cut each referred it to.
    referred: BTreeMap<LowerName, BTreeSet<(IpAddr, LowerName)>>,
    /// The names whose answer RRsets came only from responses that did
    /// not show which zone they were answered from, each with the servers
    /// that sent them.
    scoped: BTreeMap<LowerName, BTreeSet<IpAddr>>,
    /// The questions a whole response was filed for, by name and type.
    answered: HashSet<(LowerName, RecordType)>,
    /// The questions a server answered with an error RCODE that gives no
    /// facts, by server, name, and type, with that RCODE.
    failed: HashMap<(IpAddr, LowerName, RecordType), ResponseCode>,
    /// The denial records that came with each negative, by what they prove.
    proofs: HashMap<(LowerName, Denied), Vec<RecordSet>>,
    /// The answers to ANY and RRSIG questions, by name and type.
    whole: BTreeMap<(LowerName, RecordType), Node>,
    /// The names whose NSEC question a server answered with a NODATA
    /// whose own denial records show a CNAME there, where it stopped at
    /// an alias that RFC 1034 §4.3.2 step 3a follows.
    stops_at_alias: BTreeSet<LowerName>,
    /// The SOA RRset a negative answer carried, with its TTL already the
    /// negative TTL (RFC 2308 §3).
    negative_soa: Option<RecordSet>,
}

/// What a [`Learned`] zone holds at one name.
#[derive(Clone)]
struct Known {
    /// RRsets, each with the section it was filed from.
    sets: BTreeMap<RecordType, (Section, RecordSet)>,
    /// Types a NODATA answer showed the name lacks; NSEC at a CNAME the
    /// answer to an NSEC question followed; and NSEC at a cut a referral
    /// answered an NSEC question for.
    absent: BTreeSet<RecordType>,
    /// A zone cut's NS RRset and glue. Its DS RRset is in `sets`.
    cut: Option<(RecordSet, Vec<RecordSet>)>,
    /// The node `sets` and `cut` make, for views.
    node: Node,
}

impl Default for Known {
    fn default() -> Known {
        Known {
            sets: BTreeMap::new(),
            absent: BTreeSet::new(),
            cut: None,
            node: Node::Data(BTreeMap::new()),
        }
    }
}

/// Which section of a response an RRset came from: an answer outranks
/// the authority section, which outranks additional data
/// (RFC 2181 §5.4.1). A referral's NS and DS RRsets come from its
/// authority section, and its glue from additional data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Section {
    /// The additional section: glue, or the addresses of names the
    /// answer or authority section names.
    Additional,
    /// The authority section: the zone's NS RRset, or a referral's NS and
    /// DS RRsets.
    Authority,
    /// The answer section.
    Answer,
}

impl Learned {
    /// A zone at `apex` that holds nothing yet, in session 0.
    pub fn new(apex: &Name) -> Learned {
        Learned {
            apex: LowerName::new(apex),
            held: Mutex::new(Held {
                generation: Generation(0),
                facts: Arc::new(Facts::new()),
            }),
        }
    }

    /// Files `response`, the response of `server`, a real server of the
    /// zone, to `question`, asked in session `generation`, as the type's
    /// documentation says, and returns what it kept. A response from a
    /// session before the current one is dropped; one from a newer
    /// session starts it first.
    pub fn file(
        &self,
        generation: Generation,
        server: IpAddr,
        question: &Query,
        response: &Message,
    ) -> Filing {
        let mut filing = Filing {
            zone: self.apex.clone(),
            sets: Vec::new(),
        };
        let mut held = self.held.lock();
        if generation < held.generation {
            return filing;
        }
        if generation > held.generation {
            *held = Held {
                generation,
                facts: Arc::new(Facts::new()),
            };
        }
        let facts = Arc::make_mut(&mut held.facts);
        if facts.file(&self.apex, server, question, response, &mut filing.sets) {
            facts.revision = Revision(facts.revision.0 + 1);
        }
        filing
    }

    /// The apex of the zone strictly below this one that `response`, a
    /// real server of the zone's response to `question`, answers from,
    /// when it is authoritative and shows one: an SOA RRset in its
    /// authority section, which a negative answer carries for the zone it
    /// comes from (RFC 2308 §3), or else an NS RRset there, which an
    /// authoritative answer carries only at its zone's apex, owned
    /// strictly below this zone's apex and at or above the question's
    /// name; or the SOA RRset that answers an SOA question at the
    /// question's name, which is then that zone's apex; or the signer of
    /// the RRSIGs over the answer RRsets at or above the question's name,
    /// which is the zone that holds them (RFC 4034 §3.1.7). A server that
    /// also serves a child zone answers that way for the child's names,
    /// and never with a referral to it.
    ///
    /// For a referral (AA clear, NOERROR, no answer), the deepest cut this
    /// zone holds strictly above the cut it refers to: only a zone below
    /// that cut holds the deeper cut's NS RRset (RFC 1034 §4.2.1), so the
    /// server serves one there, and refers from it (RFC 1034 §4.3.2
    /// step 3b).
    pub fn child_answering(&self, question: &Query, response: &Message) -> Option<LowerName> {
        let qname = LowerName::new(question.name());
        if !response.metadata.authoritative {
            return self.child_referring(&qname, response);
        }
        let below = |owner: &LowerName| *owner != self.apex && self.apex.zone_of(owner);
        let owner = |rtype: RecordType| {
            response.authorities.iter().find_map(|record| {
                let owner = LowerName::new(&record.name);
                (record.record_type() == rtype
                    && record.dns_class == DNSClass::IN
                    && below(&owner)
                    && owner.zone_of(&qname))
                .then_some(owner)
            })
        };
        let apex_soa = question.query_type() == RecordType::SOA
            && below(&qname)
            && response.answers.iter().any(|record| {
                record.record_type() == RecordType::SOA
                    && record.dns_class == DNSClass::IN
                    && LowerName::new(&record.name) == qname
            });
        let signer = signer(&response.answers, &qname)
            .filter(|signer| below(signer) && signer.zone_of(&qname));
        owner(RecordType::SOA)
            .or_else(|| owner(RecordType::NS))
            .or_else(|| apex_soa.then_some(qname))
            .or(signer)
    }

    /// The deepest cut this zone holds strictly above the cut `response`,
    /// a referral for `qname`, refers to, as
    /// [`child_answering`](Learned::child_answering) says.
    fn child_referring(&self, qname: &LowerName, response: &Message) -> Option<LowerName> {
        let metadata = &response.metadata;
        if metadata.response_code != ResponseCode::NoError
            || metadata.truncation
            || !response.answers.is_empty()
        {
            return None;
        }
        let referred = response.authorities.iter().find_map(|record| {
            let owner = LowerName::new(&record.name);
            (record.record_type() == RecordType::NS
                && record.dns_class == DNSClass::IN
                && owner != self.apex
                && self.apex.zone_of(&owner)
                && owner.zone_of(qname))
            .then_some(owner)
        })?;
        let held = self.held.lock();
        let mut at = referred;
        while at != self.apex {
            at = at.base_name();
            if held
                .facts
                .names
                .get(&at)
                .is_some_and(|known| known.cut.is_some())
            {
                return Some(at);
            }
        }
        None
    }

    /// Whether a whole response to `question` was filed this session,
    /// whatever it gave.
    pub fn answered(&self, question: &Query) -> bool {
        let qname = LowerName::new(question.name());
        self.held
            .lock()
            .facts
            .answered
            .contains(&(qname, question.query_type()))
    }

    /// The error RCODE `server` answered `question` with this session,
    /// when it answered with one that gives no facts.
    pub fn failed(&self, server: IpAddr, question: &Query) -> Option<ResponseCode> {
        let key = (
            server,
            LowerName::new(question.name()),
            question.query_type(),
        );
        self.held.lock().facts.failed.get(&key).copied()
    }

    /// Whether `question` asks for NSEC at a name where a server answered
    /// it with a NODATA whose own denial records show a CNAME: the server
    /// stopped at an alias, whose CNAME is looked up next, so the answer
    /// follows it (RFC 1034 §4.3.2 step 3a).
    pub fn stops_at_alias(&self, question: &Query) -> bool {
        question.query_type() == RecordType::NSEC
            && self
                .held
                .lock()
                .facts
                .stops_at_alias
                .contains(&LowerName::new(question.name()))
    }

    /// Whether the answer to `question` lies below a cut the zone holds,
    /// where only the child zone has data (RFC 4035 §2.4): an
    /// authoritative answer to it comes from a zone below the cut that
    /// the server also serves.
    pub fn below_cut(&self, question: &Query) -> bool {
        let qname = LowerName::new(question.name());
        self.held
            .lock()
            .facts
            .below_cut(&qname, question.query_type())
    }

    /// Starts session `generation`, if it is newer than the current one,
    /// dropping every fact filed before.
    pub fn advance(&self, generation: Generation) {
        let mut held = self.held.lock();
        if generation > held.generation {
            *held = Held {
                generation,
                facts: Arc::new(Facts::new()),
            };
        }
    }
}

impl Learned {
    /// The zone as `server`, one of its real servers, answers it: the
    /// facts every server's responses gave, the answers `server` gave
    /// that showed no zone, and the referrals `server` gave, as zone data
    /// for a world's server at that address.
    pub fn at(self: &Arc<Learned>, server: IpAddr) -> Arc<dyn ZoneData> {
        Arc::new(Served {
            learned: self.clone(),
            server,
        })
    }

    /// The view of the zone as `server`, one of its real servers, answers
    /// it ([`at`](Learned::at)), for `question`.
    pub fn view_at(&self, server: IpAddr, question: &Query) -> Arc<dyn View + Send + Sync> {
        let facts = self.held.lock().facts.clone();
        let soa = facts
            .names
            .get(&self.apex)
            .and_then(|known| known.sets.get(&RecordType::SOA))
            .map(|(_, set)| set.clone())
            .or_else(|| facts.negative_soa.clone())
            // Every negative the view gives rests on a filed NXDOMAIN or
            // NODATA, which came with the SOA, and no positive answer
            // reads it.
            .unwrap_or_else(|| RecordSet::new(Name::from(&self.apex), RecordType::SOA, 0));
        let qname = LowerName::new(question.name());
        let (chain, answering) = answering(&self.apex, &facts, server, qname.clone());
        Arc::new(LearnedView {
            apex: self.apex.clone(),
            server,
            qname,
            chain,
            answering,
            qtype: question.query_type(),
            soa,
            facts,
        })
    }
}

/// A [`Learned`] zone as one of its real servers answers it.
struct Served {
    learned: Arc<Learned>,
    server: IpAddr,
}

impl ZoneData for Served {
    fn apex(&self) -> &LowerName {
        &self.learned.apex
    }

    fn view(&self, question: &Query) -> Arc<dyn View + Send + Sync> {
        self.learned.view_at(self.server, question)
    }
}

impl Facts {
    fn new() -> Facts {
        Facts {
            revision: Revision(0),
            names: BTreeMap::new(),
            absent: BTreeSet::new(),
            referred: BTreeMap::new(),
            scoped: BTreeMap::new(),
            answered: HashSet::new(),
            failed: HashMap::new(),
            proofs: HashMap::new(),
            whole: BTreeMap::new(),
            stops_at_alias: BTreeSet::new(),
            negative_soa: None,
        }
    }

    /// Files `response` to `question` for the zone at `apex`, adding the
    /// RRsets it keeps to `kept` as they came. Whether it gave anything.
    fn file(
        &mut self,
        apex: &LowerName,
        server: IpAddr,
        question: &Query,
        response: &Message,
        kept: &mut Vec<(Section, RecordSet)>,
    ) -> bool {
        let qname = LowerName::new(question.name());
        if !apex.zone_of(&qname)
            || question.query_class() != DNSClass::IN
            || response.metadata.truncation
        {
            return false;
        }
        self.answered.insert((qname.clone(), question.query_type()));
        let in_class = |records: &[Record]| -> Vec<RecordSet> {
            rrsets(records)
                .into_iter()
                .filter(|set| set.dns_class() == DNSClass::IN)
                .collect()
        };
        let answer = in_class(&response.answers);
        let authority = in_class(&response.authorities);
        let additional = in_class(&response.additionals);
        let denial: Vec<RecordSet> = authority
            .iter()
            .filter(|set| matches!(set.record_type(), RecordType::NSEC | RecordType::NSEC3))
            .filter(|set| apex.zone_of(&LowerName::new(set.name())))
            .cloned()
            .collect();
        let metadata = &response.metadata;
        match (metadata.authoritative, metadata.response_code) {
            (
                true,
                rcode @ (ResponseCode::NoError | ResponseCode::NXDomain | ResponseCode::YXDomain),
            ) => {
                let filed = Filed {
                    apex,
                    server,
                    qname: &qname,
                    qtype: question.query_type(),
                    rcode,
                    denial: &denial,
                };
                self.file_answer(&filed, &answer, &authority, &additional, kept);
                true
            }
            // A CNAME loop is signalled as an error (RFC 1034 §3.6.2),
            // and its CNAME RRsets are the zone's data, from which the
            // copy answers the loop as the server does.
            (true, ResponseCode::ServFail) if loops(&qname, question.query_type(), &answer) => {
                self.failed.insert(
                    (server, qname.clone(), question.query_type()),
                    ResponseCode::ServFail,
                );
                let filed = Filed {
                    apex,
                    server,
                    qname: &qname,
                    qtype: question.query_type(),
                    rcode: ResponseCode::ServFail,
                    denial: &denial,
                };
                self.file_answer(&filed, &answer, &authority, &additional, kept);
                true
            }
            (false, ResponseCode::NoError) if answer.is_empty() => {
                let referral = Referral {
                    apex,
                    server,
                    name: &qname,
                    qtype: question.query_type(),
                    authority: &authority,
                    additional: &additional,
                    denial: &denial,
                };
                self.file_cut(&referral, kept)
            }
            (_, rcode)
                if !matches!(
                    rcode,
                    ResponseCode::NoError
                        | ResponseCode::NXDomain
                        | ResponseCode::YXDomain
                        | ResponseCode::Refused
                ) =>
            {
                self.failed
                    .insert((server, qname, question.query_type()), rcode);
                false
            }
            _ => false,
        }
    }

    /// Files an authoritative answer, adding the RRsets it keeps to
    /// `kept`.
    fn file_answer(
        &mut self,
        filed: &Filed<'_>,
        answer: &[RecordSet],
        authority: &[RecordSet],
        additional: &[RecordSet],
        kept: &mut Vec<(Section, RecordSet)>,
    ) {
        let apex = filed.apex;
        let soa = authority
            .iter()
            .find(|set| set.record_type() == RecordType::SOA && LowerName::new(set.name()) == *apex)
            .cloned();
        // The name whose zone answers the question: its own, or for DS the
        // parent's side, which holds DS (RFC 4035 §2.4).
        let placing = if filed.qtype == RecordType::DS && filed.qname != apex {
            filed.qname.base_name()
        } else {
            filed.qname.clone()
        };
        // A response shows that this zone answered it with the zone's SOA
        // or apex NS RRset in its authority section, with the zone's
        // signature on its answer (RFC 4034 §3.1.7), or by answering for
        // the apex or a name the zone holds data at. Otherwise the server
        // may also serve a zone below a cut the zone does not know yet,
        // and have answered from that zone (RFC 1034 §4.3.2), so the
        // answer RRsets stand only for the server that sent them.
        let shown = soa.is_some()
            || authority.iter().any(|set| {
                set.record_type() == RecordType::NS && LowerName::new(set.name()) == *apex
            })
            || signer(answer.iter().flat_map(|set| set.rrsigs()), filed.qname).as_ref()
                == Some(apex)
            || placing == *apex
            || self.placed(&placing);
        let scope = (!shown).then_some(filed.server);
        for set in authority {
            if set.record_type() == RecordType::NS
                && LowerName::new(set.name()) == *apex
                && self.put(apex, set.clone(), Section::Authority)
            {
                kept.push((Section::Authority, set.clone()));
            }
        }
        let whole = matches!(filed.qtype, RecordType::ANY | RecordType::RRSIG);
        let dnames: Vec<&RecordSet> = answer
            .iter()
            .filter(|set| set.record_type() == RecordType::DNAME)
            .collect();
        let end = chain_end(apex, filed.qname, filed.qtype, answer, &dnames);
        // A CNAME made from a DNAME above its owner.
        let synthesized = |set: &RecordSet| {
            let owner = LowerName::new(set.name());
            set.record_type() == RecordType::CNAME
                && dnames.iter().any(|dname| {
                    let dname = LowerName::new(dname.name());
                    dname.zone_of(&owner) && dname != owner
                })
        };
        for set in answer {
            let owner = LowerName::new(set.name());
            if !apex.zone_of(&owner)
                || (whole && end.as_ref() == Some(&owner))
                || synthesized(set)
                || self.below_cut(&owner, set.record_type())
            {
                continue;
            }
            let scope = scope.filter(|_| !self.placed(&owner));
            if self.put_expanded(apex, set, Section::Answer, filed.denial) {
                kept.push((Section::Answer, set.clone()));
            }
            self.scope(&owner, scope);
        }
        // An NSEC RRset may sit beside a CNAME (RFC 4035 §2.5), so each
        // CNAME the answer to an NSEC question followed shows that the
        // name it is kept at, its owner or the wildcard that made it, has
        // none.
        if filed.qtype == RecordType::NSEC {
            for set in answer {
                let owner = LowerName::new(set.name());
                let nsec_beside = answer.iter().any(|other| {
                    other.record_type() == RecordType::NSEC && LowerName::new(other.name()) == owner
                });
                let at = match expanded_from(set) {
                    Some(labels) => wildcard(&LowerName::new(&set.name().trim_to(labels))),
                    None => owner,
                };
                if set.record_type() == RecordType::CNAME
                    && !nsec_beside
                    && !synthesized(set)
                    && let Some(known) = self.names.get_mut(&at)
                    && known.sets.contains_key(&RecordType::CNAME)
                {
                    known.absent.insert(RecordType::NSEC);
                }
            }
        }
        for set in additional {
            let owner = LowerName::new(set.name());
            if matches!(set.record_type(), RecordType::A | RecordType::AAAA)
                && apex.zone_of(&owner)
                && !self.below_cut(&owner, set.record_type())
                // At its owner even when a wildcard made it: the answer's
                // proofs are not the proof for it.
                && self.put(apex, set.clone(), Section::Additional)
            {
                kept.push((Section::Additional, set.clone()));
            }
        }

        let Some(end) = end else {
            return;
        };
        let at_end: Vec<&RecordSet> = answer
            .iter()
            .filter(|set| LowerName::new(set.name()) == end)
            .collect();
        if whole && filed.rcode == ResponseCode::NoError && !at_end.is_empty() {
            let scope = scope.filter(|_| !self.placed(&end));
            if self.put_whole(apex, &end, filed, &at_end) {
                kept.extend(at_end.into_iter().map(|set| (Section::Answer, set.clone())));
            }
            self.scope(&end, scope);
            return;
        }
        if at_end.iter().any(|set| set.record_type() == filed.qtype) {
            return;
        }
        // A chain that ends below a cut ends in a referral, which carries
        // no SOA (RFC 1034 §4.3.2 step 3b, RFC 6672 §3.2).
        let referral = Referral {
            apex,
            server: filed.server,
            name: &end,
            qtype: filed.qtype,
            authority,
            additional,
            denial: filed.denial,
        };
        let referred =
            filed.rcode == ResponseCode::NoError && soa.is_none() && self.file_cut(&referral, kept);
        if referred || self.below_cut(&end, filed.qtype) {
            return;
        }
        // A negative needs the zone's SOA to be kept (RFC 2308 §5).
        let Some(soa) = soa else {
            return;
        };
        self.negative_soa = Some(soa);
        match filed.rcode {
            // An NSEC RRset may sit beside a CNAME (RFC 4035 §2.5), and
            // without one the CNAME is followed, so such a NODATA is no
            // negative of the zone's.
            ResponseCode::NoError
                if filed.qtype == RecordType::NSEC && at_alias(apex, &end, filed.denial) =>
            {
                self.stops_at_alias.insert(end);
            }
            ResponseCode::NXDomain if end != *apex => {
                self.mark_absent(&end);
                self.mark_absent(&wildcard(&end.base_name()));
                self.proofs.insert(
                    (end.clone(), Denied::Name),
                    proof(apex, Claim::Nxdomain(&Name::from(&end)), filed.denial),
                );
            }
            ResponseCode::NoError => {
                self.unabsent(apex, &end);
                self.scope(&end, None);
                if whole {
                    self.whole
                        .insert((end.clone(), filed.qtype), Node::Data(BTreeMap::new()));
                } else {
                    let known = self.names.entry(end.clone()).or_default();
                    known.absent.insert(filed.qtype);
                    // Such as additional data filed before.
                    known.sets.remove(&filed.qtype);
                    self.rebuild(&end);
                }
                self.proofs.insert(
                    (end.clone(), Denied::Type(filed.qtype)),
                    proof(
                        apex,
                        Claim::Nodata(&Name::from(&end), filed.qtype),
                        filed.denial,
                    ),
                );
            }
            _ => {}
        }
    }

    /// Files `referral`, to a cut below its apex at or above its name,
    /// adding the NS, glue, and DS RRsets it keeps to `kept`. Whether it
    /// was one.
    fn file_cut(&mut self, referral: &Referral<'_>, kept: &mut Vec<(Section, RecordSet)>) -> bool {
        let Referral {
            apex,
            server,
            name,
            qtype,
            authority,
            additional,
            denial,
        } = *referral;
        let ns = authority.iter().find(|set| {
            let owner = LowerName::new(set.name());
            set.record_type() == RecordType::NS
                && apex.zone_of(&owner)
                && owner != *apex
                && owner.zone_of(name)
        });
        let Some(ns) = ns else {
            return false;
        };
        let cut = LowerName::new(ns.name());
        // A cut strictly below a cut the zone holds is the child zone's.
        if self.below_cut(&cut.base_name(), RecordType::NS) {
            return false;
        }
        let names = targets(ns);
        let glue: Vec<RecordSet> = additional
            .iter()
            .filter(|set| {
                let owner = LowerName::new(set.name());
                matches!(set.record_type(), RecordType::A | RecordType::AAAA)
                    && names.contains(&owner)
                    && cut.zone_of(&owner)
            })
            .cloned()
            .collect();
        let ds = authority
            .iter()
            .find(|set| set.record_type() == RecordType::DS && LowerName::new(set.name()) == cut)
            .cloned();
        self.unabsent(apex, &cut);
        self.referred
            .entry(name.clone())
            .or_default()
            .insert((server, cut.clone()));
        kept.push((Section::Authority, ns.clone()));
        kept.extend(glue.iter().map(|set| (Section::Additional, set.clone())));
        kept.extend(ds.iter().map(|set| (Section::Authority, set.clone())));
        let known = self.names.entry(cut.clone()).or_default();
        known.cut = Some((ns.clone(), glue));
        // The parent's side answers NSEC at the cut when it holds one
        // (RFC 4035 §2.6), so a referral shows it holds none.
        if qtype == RecordType::NSEC && cut == *name {
            known.absent.insert(RecordType::NSEC);
        }
        match ds {
            Some(ds) => {
                known.sets.insert(RecordType::DS, (Section::Authority, ds));
            }
            None => {
                self.proofs.insert(
                    (cut.clone(), Denied::Type(RecordType::DS)),
                    proof(
                        apex,
                        Claim::Nodata(&Name::from(&cut), RecordType::DS),
                        denial,
                    ),
                );
            }
        }
        self.rebuild(&cut);
        true
    }

    /// Files `set` from an authoritative response's `rank` section: at
    /// its owner, or at the wildcard that made it, with `denial` as the
    /// proof for the expansion. Whether it was kept.
    fn put_expanded(
        &mut self,
        apex: &LowerName,
        set: &RecordSet,
        rank: Section,
        denial: &[RecordSet],
    ) -> bool {
        let Some(labels) = expanded_from(set) else {
            return self.put(apex, set.clone(), rank);
        };
        let owner = LowerName::new(set.name());
        let Some(at) = self.expansion(apex, &owner, labels, denial) else {
            return false;
        };
        self.put(apex, renamed(set, &Name::from(&at)), rank)
    }

    /// Files `at_end`, the RRsets of an answer to ANY or RRSIG at `end`,
    /// as that question's answer: at `end`, or at the wildcard that made
    /// them, with the authority section's proof for the expansion. Whether
    /// they were kept.
    fn put_whole(
        &mut self,
        apex: &LowerName,
        end: &LowerName,
        filed: &Filed<'_>,
        at_end: &[&RecordSet],
    ) -> bool {
        let (at, owner) = match at_end.iter().find_map(|set| expanded_from(set)) {
            None => (end.clone(), Name::from(end)),
            Some(labels) => {
                let Some(at) = self.expansion(apex, end, labels, filed.denial) else {
                    return false;
                };
                let owner = Name::from(&at);
                (at, owner)
            }
        };
        let sets = at_end
            .iter()
            .map(|set| (set.record_type(), renamed(set, &owner)))
            .collect();
        self.whole.insert((at, filed.qtype), Node::Data(sets));
        true
    }

    /// Notes that `owner` was answered by expanding the wildcard whose
    /// parent has `labels` labels: the next closer name is absent, and the
    /// records of `denial` that prove the expansion are its proof
    /// (RFC 4035 §3.1.3.3, RFC 5155 §7.2.6). The wildcard, or `None` when
    /// its parent is outside the zone.
    fn expansion(
        &mut self,
        apex: &LowerName,
        owner: &LowerName,
        labels: usize,
        denial: &[RecordSet],
    ) -> Option<LowerName> {
        let name = Name::from(owner);
        let encloser_name = name.trim_to(labels);
        let encloser = LowerName::new(&encloser_name);
        let next_closer = LowerName::new(&name.trim_to(labels + 1));
        if !apex.zone_of(&encloser) {
            return None;
        }
        let at = wildcard(&encloser);
        self.mark_absent(&next_closer);
        let claim = Claim::Wildcard {
            name: &name,
            closest_encloser: &encloser_name,
        };
        self.proofs.insert(
            (
                owner.clone(),
                Denied::Wildcard {
                    closest_encloser: encloser,
                },
            ),
            proof(apex, claim, denial),
        );
        Some(at)
    }

    /// Keeps `set` at its owner, unless an RRset of the same type is held
    /// from a section that outranks `rank`, or `rank` is the additional
    /// section's and a filed NODATA says the owner has no such RRset.
    /// Whether it was kept.
    fn put(&mut self, apex: &LowerName, set: RecordSet, rank: Section) -> bool {
        let owner = LowerName::new(set.name());
        self.unabsent(apex, &owner);
        let known = self.names.entry(owner.clone()).or_default();
        let rtype = set.record_type();
        let replaces = known.sets.get(&rtype).is_none_or(|(held, _)| *held <= rank);
        let denied = rank == Section::Additional && known.absent.contains(&rtype);
        let keeps = replaces && !denied;
        if keeps {
            known.sets.insert(rtype, (rank, set));
            known.absent.remove(&rtype);
        }
        self.rebuild(&owner);
        keeps
    }

    /// Keeps `name` as absent, with nothing below it.
    fn mark_absent(&mut self, name: &LowerName) {
        self.names.retain(|held, _| !name.zone_of(held));
        self.whole.retain(|(held, _), _| !name.zone_of(held));
        self.referred.retain(|held, _| !name.zone_of(held));
        self.scoped.retain(|held, _| !name.zone_of(held));
        self.absent.insert(name.clone());
    }

    /// Whether a referral from `server` to the cut at `cut` was filed for
    /// `name` or a name below it, which shows that the server holds no
    /// zone at `name`, nor between it and that cut. Another server may
    /// hold one there, and a referral to another cut says nothing of this
    /// one: a server that serves a zone below `cut` refers from there.
    fn refers(&self, name: &LowerName, server: IpAddr, cut: &LowerName) -> bool {
        // Names below `name` follow it directly in canonical order.
        let referral = (server, cut.clone());
        self.referred
            .range(name.clone()..)
            .take_while(|(held, _)| name.zone_of(held))
            .any(|(_, referrals)| referrals.contains(&referral))
    }

    /// Notes that the answer RRsets at `name` stand only for `scope`'s
    /// server, or with `None`, for every server of the zone.
    fn scope(&mut self, name: &LowerName, scope: Option<IpAddr>) {
        match scope {
            Some(server) => {
                self.scoped.entry(name.clone()).or_default().insert(server);
            }
            None => {
                self.scoped.remove(name);
            }
        }
    }

    /// Whether `server` answers with the facts held at `name`: every
    /// server does, but for answer RRsets only some servers gave.
    fn visible(&self, name: &LowerName, server: IpAddr) -> bool {
        self.scoped
            .get(name)
            .is_none_or(|servers| servers.contains(&server))
    }

    /// Whether the zone holds facts at `name`, which is no cut, from a
    /// response that showed the zone: an RRset from an answer or
    /// authority section, or a type known absent. Every server of the
    /// zone then answers for `name` from the zone.
    fn placed(&self, name: &LowerName) -> bool {
        !self.scoped.contains_key(name)
            && self.names.get(name).is_some_and(|known| {
                known.cut.is_none()
                    && (!known.absent.is_empty()
                        || known
                            .sets
                            .values()
                            .any(|(rank, _)| *rank > Section::Additional))
            })
    }

    /// Forgets that `name` or a name above it is absent, as a response
    /// gave data there.
    fn unabsent(&mut self, apex: &LowerName, name: &LowerName) {
        let mut at = name.clone();
        while apex.zone_of(&at) && at != *apex {
            self.absent.remove(&at);
            at = at.base_name();
        }
    }

    /// Whether data of `rtype` at `owner` is below a cut the zone holds,
    /// where only the child zone has data: strictly below it, or at it for
    /// anything but the DS and NSEC RRsets the parent holds there
    /// (RFC 4035 §2.4, §2.6).
    fn below_cut(&self, owner: &LowerName, rtype: RecordType) -> bool {
        let mut at = owner.clone();
        loop {
            if let Some(known) = self.names.get(&at)
                && known.cut.is_some()
            {
                return at != *owner || !matches!(rtype, RecordType::DS | RecordType::NSEC);
            }
            if at.is_root() {
                return false;
            }
            at = at.base_name();
        }
    }

    /// Makes the node at `name` again from what it holds.
    fn rebuild(&mut self, name: &LowerName) {
        let Some(known) = self.names.get_mut(name) else {
            return;
        };
        let mut sets: BTreeMap<RecordType, RecordSet> = known
            .sets
            .iter()
            .map(|(rtype, (_, set))| (*rtype, set.clone()))
            .collect();
        known.node = match &known.cut {
            Some((ns, glue)) => Node::Cut {
                ns: ns.clone(),
                ds: sets.remove(&RecordType::DS),
                glue: glue.clone(),
            },
            None => match sets.remove(&RecordType::DNAME) {
                Some(dname) => Node::Dname(dname, sets),
                None => Node::Data(sets),
            },
        };
    }

    /// Whether `name`, below `apex`, or a name above it is absent.
    fn is_absent(&self, apex: &LowerName, name: &LowerName) -> bool {
        let mut at = name.clone();
        while apex.zone_of(&at) && at != *apex {
            if self.absent.contains(&at) {
                return true;
            }
            at = at.base_name();
        }
        false
    }

    /// Whether the zone holds a fact at a name strictly below `name`.
    fn holds_below(&self, name: &LowerName) -> bool {
        let after = (Bound::Excluded(name.clone()), Bound::Unbounded);
        // Names below `name` follow it directly in canonical order.
        let names = self
            .names
            .range(after.clone())
            .next()
            .is_some_and(|(held, _)| name.zone_of(held));
        let absent = self
            .absent
            .range(after)
            .next()
            .is_some_and(|held| name.zone_of(held));
        let whole = self
            .whole
            .keys()
            .any(|(held, _)| name.zone_of(held) && held != name);
        names || absent || whole
    }
}

/// What one authoritative answer was for.
struct Filed<'a> {
    apex: &'a LowerName,
    /// The real server that sent the response.
    server: IpAddr,
    qname: &'a LowerName,
    qtype: RecordType,
    rcode: ResponseCode,
    /// The NSEC and NSEC3 RRsets of its authority section.
    denial: &'a [RecordSet],
}

/// What a referral may be in: a response's sections, the question's type,
/// and the name it refers, the question's name or where the answer's
/// chain ended.
#[derive(Clone, Copy)]
struct Referral<'a> {
    apex: &'a LowerName,
    /// The real server that sent the response.
    server: IpAddr,
    name: &'a LowerName,
    qtype: RecordType,
    authority: &'a [RecordSet],
    additional: &'a [RecordSet],
    /// The NSEC and NSEC3 RRsets of the authority section.
    denial: &'a [RecordSet],
}

/// Whether the CNAME chain of `answer`, an answer to `qname` and `qtype`,
/// comes back to a name it passed: a loop. A question for CNAME, ANY, or
/// RRSIG follows no CNAME.
fn loops(qname: &LowerName, qtype: RecordType, answer: &[RecordSet]) -> bool {
    if matches!(
        qtype,
        RecordType::CNAME | RecordType::ANY | RecordType::RRSIG
    ) {
        return false;
    }
    let mut name = qname.clone();
    let mut seen = vec![name.clone()];
    loop {
        let target = answer
            .iter()
            .filter(|set| {
                set.record_type() == RecordType::CNAME && LowerName::new(set.name()) == name
            })
            .flat_map(|set| set.records_without_rrsigs())
            .find_map(|record| match &record.data {
                RData::CNAME(target) => Some(LowerName::new(&target.0)),
                _ => None,
            });
        let Some(target) = target else {
            return false;
        };
        if seen.contains(&target) {
            return true;
        }
        seen.push(target.clone());
        name = target;
    }
}

/// Where the CNAME and DNAME chain of `answer`, an answer to `qname` and
/// `qtype` from the zone at `apex`, ends: the name whose RRset of `qtype`
/// the answer has, or whose negative it is. A DNAME above a name moves the
/// chain on whatever the type asked, as the walk of the answer does
/// (RFC 6672 §3.2), and a CNAME at a name moves it on unless the question
/// asks for CNAME (RFC 1034 §4.3.2 step 3a), or for ANY or RRSIG, which
/// the answer gives at the name itself. `None` when the chain leaves
/// the zone, loops, or substitutes a name past 255 octets (YXDOMAIN,
/// RFC 6672 §2.2), which leaves nothing negative to keep.
fn chain_end(
    apex: &LowerName,
    qname: &LowerName,
    qtype: RecordType,
    answer: &[RecordSet],
    dnames: &[&RecordSet],
) -> Option<LowerName> {
    let mut name = qname.clone();
    let mut seen = Vec::new();
    loop {
        if !apex.zone_of(&name) {
            return None;
        }
        let dname = dnames.iter().find(|dname| {
            let owner = LowerName::new(dname.name());
            owner.zone_of(&name) && owner != name
        });
        let target = match dname {
            Some(dname) => {
                let target = dname
                    .records_without_rrsigs()
                    .find_map(|record| dname_target(&record.data))?;
                dname_substitute(&Name::from(&name), dname.name(), &target)?
            }
            None => {
                let at = |rtype: RecordType| {
                    answer.iter().find(|set| {
                        set.record_type() == rtype && LowerName::new(set.name()) == name
                    })
                };
                let stops = matches!(
                    qtype,
                    RecordType::CNAME | RecordType::ANY | RecordType::RRSIG
                );
                if stops || at(qtype).is_some() {
                    return Some(name);
                }
                let cname = at(RecordType::CNAME).and_then(|set| {
                    set.records_without_rrsigs()
                        .find_map(|record| match &record.data {
                            RData::CNAME(target) => Some(target.0.clone()),
                            _ => None,
                        })
                });
                let Some(target) = cname else {
                    return Some(name);
                };
                target
            }
        };
        let target = LowerName::new(&target);
        if target == name || seen.contains(&target) {
            return None;
        }
        seen.push(std::mem::replace(&mut name, target));
    }
}

/// The zone that signed the RRsets of an answer at or above `qname`: the
/// signer of the RRSIGs among `records` that cover them (RFC 4034
/// §3.1.7).
fn signer<'a>(
    records: impl IntoIterator<Item = &'a Record>,
    qname: &LowerName,
) -> Option<LowerName> {
    records.into_iter().find_map(|record| match &record.data {
        RData::DNSSEC(DNSSECRData::RRSIG(rrsig))
            if record.dns_class == DNSClass::IN && LowerName::new(&record.name).zone_of(qname) =>
        {
            Some(LowerName::new(&rrsig.input().signer_name))
        }
        _ => None,
    })
}

/// The records of `denial`, the NSEC and NSEC3 RRsets of one response
/// from the zone at `apex`, that prove `claim` (RFC 4035 §3.1.3,
/// RFC 5155 §7.2): a reply for that claim alone carries them, as a real
/// server's reply to a question that needs only it does. All of them when
/// they hold no proof of it, as the server sent them; none from an
/// unsigned zone.
fn proof(apex: &LowerName, claim: Claim<'_>, denial: &[RecordSet]) -> Vec<RecordSet> {
    proof_of(claim, &Name::from(apex), denial).unwrap_or_else(|| denial.to_vec())
}

/// Whether `denial`, the records a NODATA for NSEC at `name` in the zone
/// at `apex` came with, show a CNAME at the name, or at the wildcard that
/// answers for it ([`proof::alias`]).
fn at_alias(apex: &LowerName, name: &LowerName, denial: &[RecordSet]) -> bool {
    let (zone, name) = (Name::from(apex), Name::from(name));
    proof::alias(&name, &zone, denial, u16::MAX) == Proof::Proven
}

/// `set` with `owner` as the owner of every record and RRSIG.
fn renamed(set: &RecordSet, owner: &Name) -> RecordSet {
    let rename = |record: &Record| {
        let mut record = record.clone();
        record.name = owner.clone();
        record
    };
    let mut renamed = RecordSet::with_ttl(owner.clone(), set.record_type(), set.ttl());
    renamed.set_dns_class(set.dns_class());
    renamed.set_records(set.records_without_rrsigs().map(rename).collect());
    renamed.set_rrsigs(set.rrsigs().iter().map(rename).collect());
    renamed
}

/// The names in the zone at `apex` where an answer to `qname` may end,
/// by what `facts` hold for `server`: the chain, which is `qname` and the
/// targets of the CNAME and DNAME records the chain from it passes, and
/// every name that answers, which adds the wildcards that could answer
/// for one of them (RFC 4592 §3.3). Every other name the answer reads it
/// only passes on the way down, or reads optional addresses at.
fn answering(
    apex: &LowerName,
    facts: &Facts,
    server: IpAddr,
    qname: LowerName,
) -> (BTreeSet<LowerName>, BTreeSet<LowerName>) {
    let mut chain = BTreeSet::new();
    let mut answering = BTreeSet::new();
    // Each name, and whether the chain reaches it.
    let mut pending = vec![(qname, true)];
    while let Some((name, on_chain)) = pending.pop() {
        if !apex.zone_of(&name) {
            continue;
        }
        let newly_on_chain = on_chain && chain.insert(name.clone());
        if !answering.insert(name.clone()) && !newly_on_chain {
            continue;
        }
        let cname = facts
            .names
            .get(&name)
            .filter(|_| facts.visible(&name, server))
            .and_then(|known| known.sets.get(&RecordType::CNAME))
            .and_then(|(_, set)| {
                set.records_without_rrsigs()
                    .find_map(|record| match &record.data {
                        RData::CNAME(target) => Some(LowerName::new(&target.0)),
                        _ => None,
                    })
            });
        // A wildcard's CNAME is followed for the names it answers.
        pending.extend(cname.map(|target| (target, true)));
        let mut above = name.clone();
        while above != *apex {
            above = above.base_name();
            pending.push((wildcard(&above), false));
            let dname = facts
                .names
                .get(&above)
                .filter(|_| facts.visible(&above, server))
                .and_then(|known| known.sets.get(&RecordType::DNAME))
                .and_then(|(_, set)| {
                    set.records_without_rrsigs()
                        .find_map(|record| dname_target(&record.data))
                });
            if let Some(target) = dname
                && let Some(next) =
                    dname_substitute(&Name::from(&name), &Name::from(&above), &target)
            {
                pending.push((LowerName::new(&next), on_chain));
            }
        }
    }
    (chain, answering)
}

/// The view of a [`Learned`] zone for one question, at one revision, as
/// one of its real servers answers it.
struct LearnedView {
    apex: LowerName,
    /// The real server whose answers the view gives.
    server: IpAddr,
    /// The question's name.
    qname: LowerName,
    /// The names the question's chain reaches ([`answering`]).
    chain: BTreeSet<LowerName>,
    /// The names the answer may end at ([`answering`]).
    answering: BTreeSet<LowerName>,
    qtype: RecordType,
    soa: RecordSet,
    facts: Arc<Facts>,
}

/// The node of a name the zone holds facts at or below, but none the
/// question's type needs.
static EMPTY: Node = Node::Empty;

impl LearnedView {
    /// Whether `known` holds the fact an answer of the view's type reads
    /// at `name`: an RRset of that type from an answer or authority
    /// section; a CNAME from one, which answers every type
    /// (RFC 1034 §3.6.2) but NSEC, whose RRset may sit beside it
    /// (RFC 4035 §2.5), unless the name is known to have none or a server
    /// stopped there for the question's name; or the type known absent
    /// where the chain reaches `name`. A wildcard's
    /// absent type is the proof for the wildcard's own name, which a name
    /// it answers for cannot use (RFC 5155 §7.2.5). Additional data never
    /// answers (RFC 2181 §5.4.1). ANY and RRSIG are answered from their
    /// own responses instead.
    fn knows(&self, name: &LowerName, known: &Known) -> bool {
        let qtype = self.qtype;
        let answers = |rtype: RecordType| {
            known
                .sets
                .get(&rtype)
                .is_some_and(|(rank, _)| *rank > Section::Additional)
        };
        let alias = answers(RecordType::CNAME)
            && (qtype != RecordType::NSEC
                || known.absent.contains(&RecordType::NSEC)
                || self.facts.stops_at_alias.contains(&self.qname));
        let absent = self.chain.contains(name) && known.absent.contains(&qtype);
        !matches!(qtype, RecordType::ANY | RecordType::RRSIG) && (answers(qtype) || alias || absent)
    }

    /// What the view gives for the cut `known` holds at `name`. DS and
    /// NSEC at the cut are the parent's data (RFC 4035 §2.6, §3.1.4.1),
    /// so a question for them there stands once the zone holds an RRset
    /// of the type or knows there is none. A name of the chain at or
    /// below the cut is referred only when the view's server's referral
    /// to this cut was filed for it or a name below it
    /// ([`Facts::refers`]).
    fn cut<'a>(&self, name: &LowerName, known: &'a Known) -> Fact<&'a Node> {
        let parents = matches!(self.qtype, RecordType::DS | RecordType::NSEC);
        if parents && self.chain.contains(name) {
            let settled =
                known.sets.contains_key(&self.qtype) || known.absent.contains(&self.qtype);
            return if settled {
                Fact::Present(&known.node)
            } else {
                Fact::Unknown
            };
        }
        let unreferred = self
            .chain
            .iter()
            .any(|reached| name.zone_of(reached) && !self.facts.refers(reached, self.server, name));
        if unreferred {
            Fact::Unknown
        } else {
            Fact::Present(&known.node)
        }
    }
}

impl View for LearnedView {
    fn apex(&self) -> &LowerName {
        &self.apex
    }

    fn revision(&self) -> Revision {
        self.facts.revision
    }

    fn soa(&self) -> &RecordSet {
        &self.soa
    }

    fn node(&self, name: &LowerName) -> Fact<&Node> {
        let facts = &self.facts;
        if !self.apex.zone_of(name) || facts.is_absent(&self.apex, name) {
            return Fact::Absent;
        }
        let visible = facts.visible(name, self.server);
        if let Some(known) = facts.names.get(name) {
            match &known.node {
                Node::Cut { .. } => return self.cut(name, known),
                // Answers another server gave without showing their zone
                // are not this server's.
                _ if !visible => {}
                // A name the answer only passes, or reads addresses at,
                // never ends it.
                _ if !self.answering.contains(name) || self.knows(name, known) => {
                    return Fact::Present(&known.node);
                }
                _ => {}
            }
        }
        if visible && let Some(node) = facts.whole.get(&(name.clone(), self.qtype)) {
            return Fact::Present(node);
        }
        if facts.names.contains_key(name) || facts.holds_below(name) {
            return Fact::Present(&EMPTY);
        }
        Fact::Unknown
    }

    fn denial(&self, name: &LowerName, kind: Denied) -> Fact<Vec<RecordSet>> {
        // The NSEC RRset an answer gave at `name`, which a cut's node does
        // not hold.
        let nsec = self
            .facts
            .names
            .get(name)
            .and_then(|known| known.sets.get(&RecordType::NSEC))
            .filter(|(rank, _)| *rank > Section::Additional);
        if kind == Denied::Type(RecordType::NSEC)
            && let Some((_, set)) = nsec
        {
            return Fact::Present(vec![set.clone()]);
        }
        match self.facts.proofs.get(&(name.clone(), kind)) {
            Some(sets) => Fact::Present(sets.clone()),
            None => Fact::Unknown,
        }
    }

    fn answers_empty(&self) -> bool {
        false
    }
}
