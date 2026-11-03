//! A zone whose data is copied from the responses of its real servers, as
//! a world's server needs it.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::Bound;
use std::sync::Arc;

use fictionet::stdlib::protocols::dns::dname_substitute;
use fictionet::stdlib::protocols::dns::dnssec::rdata::DNSSECRData;
use fictionet::stdlib::protocols::dns::op::{Message, Query, ResponseCode};
use fictionet::stdlib::protocols::dns::rr::{
    DNSClass, LowerName, Name, RData, Record, RecordSet, RecordType,
};
use fictionet::sync::Mutex;

use super::super::exchange::Generation;
use super::super::records::rrsets;
use super::data::{Denied, Fact, Revision, View, ZoneData};
use super::zone::{Node, dname_target, targets, wildcard};

/// Zone data copied from what one zone's real servers answered, one
/// session at a time.
///
/// A world's server never passes a real server's message on. It answers
/// from this data with [`answer`](super::answer), and when a reply needs a
/// fact the data does not hold, [`Zones`](super::super::authority::Zones)
/// looks the client's question up at a real server of the zone and
/// [files](Learned::file) the response here. Every fact the data holds was
/// filed from such a response:
///
/// - An authoritative answer (AA set) gives the RRsets of its answer
///   section that are in the zone and not below a cut it holds, each with
///   its RRSIGs; the zone's apex NS RRset from its authority section; and
///   the A and AAAA RRsets of its additional section, which never replace
///   an RRset an answer section gave or stand against a filed NODATA, and
///   which are served only as additional data, never as an answer
///   (RFC 2181 §5.4.1): such an RRset may be glue below a cut the zone
///   does not hold yet, or sent without its RRSIGs. A DNAME is kept,
///   and the CNAME synthesized from it is not (RFC 6672 §3.4). An RRset
///   of the answer section whose RRSIGs show a wildcard expansion (a
///   Labels field below the owner's label count, RFC 4035 §5.3.4) is kept
///   at the wildcard that made it, the name one label below the wildcard's parent toward the
///   owner is kept as absent, and the NSEC and NSEC3 records of the
///   authority section are kept as the proof for the expansion
///   (RFC 4035 §3.1.3.3, RFC 5155 §7.2.6). An answer to ANY or RRSIG
///   expanded from a wildcard is kept the same way.
/// - Where the answer's CNAME and DNAME chain ends inside the zone
///   without an RRset of the type asked, the answer is negative there.
///   With the zone's SOA in its authority section (RFC 2308 §5), NXDOMAIN
///   keeps the name as absent, and so the names below it (RFC 8020), and
///   the wildcard at its parent, which would have matched it; NOERROR
///   keeps the type as absent at the name. The authority section's NSEC
///   and NSEC3 records, with their RRSIGs, are kept as the proof, and an
///   unsigned zone's proof is empty, as the server sent it. A negative
///   without the SOA is not kept.
/// - A referral (AA clear, NOERROR, an NS RRset below the apex at or
///   above the question's name) gives a zone cut: the NS RRset, the glue
///   for its targets at or below the cut (RFC 9471 §3.1), and the DS
///   RRset, or else the NSEC and NSEC3 records sent beside it as the proof
///   that the cut has none, which the copy's referrals carry
///   (RFC 4035 §3.1.4).
/// - Any other response, such as REFUSED, SERVFAIL, an answer without
///   AA, or a truncated response (TC set), whose sections may be
///   incomplete (RFC 2181 §9), gives nothing.
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
/// type or a CNAME from an answer or authority section, or the type known
/// absent. Such a name the data holds, or holds names below, is
/// otherwise an empty node that answers nothing
/// ([`View::answers_empty`] is false), so the answer ends unknown there
/// and the server looks the question up. Any other name the data holds
/// is present as it is, since the answer only passes it on the way down
/// or reads optional addresses there. A name is absent only where a
/// filed negative said so, and [`View::denial`] gives only the proof that
/// came with it. Questions for ANY and for RRSIG are answered from the
/// response to that same question alone, since a server may answer ANY
/// with a subset or a made-up HINFO (RFC 8482 §4). A DS question at a cut
/// a referral showed without DS is answered NODATA only from a filed
/// NODATA for it: a referral carries no SOA, and may come from a zone
/// below this one that the server also serves. An unknown fact never
/// becomes NXDOMAIN or NODATA.
///
/// A real server that also serves a zone below this one answers for that
/// zone's names from the child's data. [`child_answering`](Learned::child_answering)
/// tells such a response apart, so that it is filed into the child's copy
/// instead ([`Copies`](super::super::authority::Copies) does).
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
    /// The denial records that came with each negative, by what they prove.
    proofs: HashMap<(LowerName, Denied), Vec<RecordSet>>,
    /// The answers to ANY and RRSIG questions, by name and type.
    whole: BTreeMap<(LowerName, RecordType), Node>,
    /// The SOA RRset a negative answer carried, with its TTL already the
    /// negative TTL (RFC 2308 §3).
    negative_soa: Option<RecordSet>,
}

/// What a [`Learned`] zone holds at one name.
#[derive(Clone)]
struct Known {
    /// RRsets, each with the section it was filed from.
    sets: BTreeMap<RecordType, (Section, RecordSet)>,
    /// Types a NODATA answer showed the name lacks.
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

    /// Files `response`, a real server of the zone's response to
    /// `question`, asked in session `generation`, as the type's
    /// documentation says, and returns what it kept. A response from a
    /// session before the current one is dropped; one from a newer
    /// session starts it first.
    pub fn file(&self, generation: Generation, question: &Query, response: &Message) -> Filing {
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
        if facts.file(&self.apex, question, response, &mut filing.sets) {
            facts.revision = Revision(facts.revision.0 + 1);
        }
        filing
    }

    /// The apex of the zone strictly below this one that `response`, a
    /// real server of the zone's response to `question`, answers from,
    /// when it is authoritative and its authority section shows one: an
    /// SOA RRset, which a negative answer carries for the zone it comes
    /// from (RFC 2308 §3), or else an NS RRset, which an authoritative
    /// answer carries only at its zone's apex, owned strictly below this
    /// zone's apex and at or above the question's name. A server that
    /// also serves a child zone answers that way for the child's names,
    /// and never with a referral to it.
    pub fn child_answering(&self, question: &Query, response: &Message) -> Option<LowerName> {
        if !response.metadata.authoritative {
            return None;
        }
        let qname = LowerName::new(question.name());
        let owner = |rtype: RecordType| {
            response.authorities.iter().find_map(|record| {
                let owner = LowerName::new(&record.name);
                (record.record_type() == rtype
                    && record.dns_class == DNSClass::IN
                    && owner != self.apex
                    && self.apex.zone_of(&owner)
                    && owner.zone_of(&qname))
                .then_some(owner)
            })
        };
        owner(RecordType::SOA).or_else(|| owner(RecordType::NS))
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

impl ZoneData for Learned {
    fn apex(&self) -> &LowerName {
        &self.apex
    }

    fn view(&self, question: &Query) -> Arc<dyn View + Send + Sync> {
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
        Arc::new(LearnedView {
            apex: self.apex.clone(),
            answering: answering(&self.apex, &facts, LowerName::new(question.name())),
            qtype: question.query_type(),
            soa,
            facts,
        })
    }

    fn learned(&self) -> Option<&Learned> {
        Some(self)
    }
}

impl Facts {
    fn new() -> Facts {
        Facts {
            revision: Revision(0),
            names: BTreeMap::new(),
            absent: BTreeSet::new(),
            proofs: HashMap::new(),
            whole: BTreeMap::new(),
            negative_soa: None,
        }
    }

    /// Files `response` to `question` for the zone at `apex`, adding the
    /// RRsets it keeps to `kept` as they came. Whether it gave anything.
    fn file(
        &mut self,
        apex: &LowerName,
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
            (true, rcode @ (ResponseCode::NoError | ResponseCode::NXDomain)) => {
                let filed = Filed {
                    apex,
                    qname: &qname,
                    qtype: question.query_type(),
                    rcode,
                    denial: &denial,
                };
                self.file_answer(&filed, &answer, &authority, &additional, kept);
                true
            }
            (false, ResponseCode::NoError) if answer.is_empty() => {
                self.file_referral(apex, &qname, &authority, &additional, &denial, kept)
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
        for set in answer {
            let owner = LowerName::new(set.name());
            let synthesized = set.record_type() == RecordType::CNAME
                && dnames.iter().any(|dname| {
                    let dname = LowerName::new(dname.name());
                    dname.zone_of(&owner) && dname != owner
                });
            if !apex.zone_of(&owner)
                || (whole && owner == *filed.qname)
                || synthesized
                || self.below_cut(&owner, set.record_type())
            {
                continue;
            }
            if self.put_expanded(apex, set, Section::Answer, filed.denial) {
                kept.push((Section::Answer, set.clone()));
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

        let end = if whole {
            Some(filed.qname.clone())
        } else {
            chain_end(apex, filed.qname, filed.qtype, answer, &dnames)
        };
        let Some(end) = end else {
            return;
        };
        let at_end: Vec<&RecordSet> = answer
            .iter()
            .filter(|set| LowerName::new(set.name()) == end)
            .collect();
        if whole && filed.rcode == ResponseCode::NoError && !at_end.is_empty() {
            if self.put_whole(apex, &end, filed, &at_end) {
                kept.extend(at_end.into_iter().map(|set| (Section::Answer, set.clone())));
            }
            return;
        }
        let positive = at_end.iter().any(|set| set.record_type() == filed.qtype);
        if positive || self.below_cut(&end, filed.qtype) {
            return;
        }
        // A negative needs the zone's SOA to be kept (RFC 2308 §5).
        let Some(soa) = soa else {
            return;
        };
        self.negative_soa = Some(soa);
        match filed.rcode {
            ResponseCode::NXDomain if end != *apex => {
                self.mark_absent(&end);
                self.mark_absent(&wildcard(&end.base_name()));
                self.proofs
                    .insert((end, Denied::Name), filed.denial.to_vec());
            }
            ResponseCode::NoError => {
                self.unabsent(apex, &end);
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
                self.proofs
                    .insert((end, Denied::Type(filed.qtype)), filed.denial.to_vec());
            }
            _ => {}
        }
    }

    /// Files a referral to a cut below `apex` at or above `qname`, adding
    /// the NS, glue, and DS RRsets it keeps to `kept`. Whether it was one.
    fn file_referral(
        &mut self,
        apex: &LowerName,
        qname: &LowerName,
        authority: &[RecordSet],
        additional: &[RecordSet],
        denial: &[RecordSet],
        kept: &mut Vec<(Section, RecordSet)>,
    ) -> bool {
        let ns = authority.iter().find(|set| {
            let owner = LowerName::new(set.name());
            set.record_type() == RecordType::NS
                && apex.zone_of(&owner)
                && owner != *apex
                && owner.zone_of(qname)
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
        kept.push((Section::Authority, ns.clone()));
        kept.extend(glue.iter().map(|set| (Section::Additional, set.clone())));
        kept.extend(ds.iter().map(|set| (Section::Authority, set.clone())));
        let known = self.names.entry(cut.clone()).or_default();
        known.cut = Some((ns.clone(), glue));
        match ds {
            Some(ds) => {
                known.sets.insert(RecordType::DS, (Section::Authority, ds));
            }
            None => {
                self.proofs
                    .insert((cut.clone(), Denied::Type(RecordType::DS)), denial.to_vec());
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
    /// parent has `labels` labels: the next closer name is absent, and
    /// `denial` is the proof for the expansion (RFC 4035 §3.1.3.3, RFC 5155
    /// §7.2.6). The wildcard, or `None` when its parent is outside the zone.
    fn expansion(
        &mut self,
        apex: &LowerName,
        owner: &LowerName,
        labels: usize,
        denial: &[RecordSet],
    ) -> Option<LowerName> {
        let name = Name::from(owner);
        let encloser = LowerName::new(&name.trim_to(labels));
        let next_closer = LowerName::new(&name.trim_to(labels + 1));
        if !apex.zone_of(&encloser) {
            return None;
        }
        let at = wildcard(&encloser);
        self.mark_absent(&next_closer);
        self.proofs.insert(
            (
                owner.clone(),
                Denied::Wildcard {
                    closest_encloser: encloser,
                },
            ),
            denial.to_vec(),
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
        self.absent.insert(name.clone());
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
    qname: &'a LowerName,
    qtype: RecordType,
    rcode: ResponseCode,
    /// The NSEC and NSEC3 RRsets of its authority section.
    denial: &'a [RecordSet],
}

/// Where the CNAME and DNAME chain of `answer`, an answer to `qname` and
/// `qtype` from the zone at `apex`, ends: the name whose RRset of `qtype`
/// the answer has, or whose negative it is. `None` when the chain leaves
/// the zone or loops, which leaves nothing negative to keep.
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
        let at = |rtype: RecordType| {
            answer
                .iter()
                .find(|set| set.record_type() == rtype && LowerName::new(set.name()) == name)
        };
        if qtype == RecordType::CNAME || at(qtype).is_some() {
            return Some(name);
        }
        let cname = at(RecordType::CNAME).and_then(|set| {
            set.records_without_rrsigs()
                .find_map(|record| match &record.data {
                    RData::CNAME(target) => Some(target.0.clone()),
                    _ => None,
                })
        });
        let target = cname.or_else(|| {
            dnames.iter().find_map(|dname| {
                let owner = dname.name();
                let target = dname
                    .records_without_rrsigs()
                    .find_map(|record| dname_target(&record.data))?;
                dname_substitute(&Name::from(&name), owner, &target)
            })
        });
        let Some(target) = target else {
            return Some(name);
        };
        let target = LowerName::new(&target);
        if target == name || seen.contains(&target) {
            return None;
        }
        seen.push(std::mem::replace(&mut name, target));
    }
}

/// The label count of the wildcard's parent when `set`'s RRSIGs show a
/// wildcard expansion: a Labels field below the owner's label count, a
/// leading `*` not counted (RFC 4034 §3.1.3, RFC 4035 §5.3.4).
fn expanded_from(set: &RecordSet) -> Option<usize> {
    let owner = usize::from(set.name().num_labels());
    set.rrsigs().iter().find_map(|record| match &record.data {
        RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => {
            let labels = usize::from(rrsig.input().num_labels);
            (labels < owner).then_some(labels)
        }
        _ => None,
    })
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
/// by what `facts` hold: `qname`, the targets of the CNAME and DNAME
/// records the chain from it passes, and the wildcards that could answer
/// for any of them (RFC 4592 §3.3). Every other name the answer reads it
/// only passes on the way down, or reads optional addresses at.
fn answering(apex: &LowerName, facts: &Facts, qname: LowerName) -> BTreeSet<LowerName> {
    let mut answering = BTreeSet::new();
    let mut pending = vec![qname];
    while let Some(name) = pending.pop() {
        if !apex.zone_of(&name) || !answering.insert(name.clone()) {
            continue;
        }
        let cname = facts
            .names
            .get(&name)
            .and_then(|known| known.sets.get(&RecordType::CNAME))
            .and_then(|(_, set)| {
                set.records_without_rrsigs()
                    .find_map(|record| match &record.data {
                        RData::CNAME(target) => Some(LowerName::new(&target.0)),
                        _ => None,
                    })
            });
        pending.extend(cname);
        let mut above = name.clone();
        while above != *apex {
            above = above.base_name();
            pending.push(wildcard(&above));
            let dname = facts
                .names
                .get(&above)
                .and_then(|known| known.sets.get(&RecordType::DNAME))
                .and_then(|(_, set)| {
                    set.records_without_rrsigs()
                        .find_map(|record| dname_target(&record.data))
                });
            if let Some(target) = dname
                && let Some(next) =
                    dname_substitute(&Name::from(&name), &Name::from(&above), &target)
            {
                pending.push(LowerName::new(&next));
            }
        }
    }
    answering
}

/// The view of a [`Learned`] zone for one question, at one revision.
struct LearnedView {
    apex: LowerName,
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
    /// at its name: an RRset of that type, or a CNAME, which answers every
    /// type (RFC 1034 §3.6.2), from an answer or authority section, or
    /// the type known absent. Additional data never answers
    /// (RFC 2181 §5.4.1). ANY and RRSIG are answered from their own
    /// responses instead.
    fn knows(&self, known: &Known) -> bool {
        let qtype = self.qtype;
        let answers = |rtype: RecordType| {
            known
                .sets
                .get(&rtype)
                .is_some_and(|(rank, _)| *rank > Section::Additional)
        };
        !matches!(qtype, RecordType::ANY | RecordType::RRSIG)
            && (answers(qtype) || answers(RecordType::CNAME) || known.absent.contains(&qtype))
    }

    /// Whether the zone knows whether the cut `known` holds has a DS
    /// RRset: it holds one, or a filed NODATA shows there is none.
    fn ds_settled(known: &Known) -> bool {
        known.sets.contains_key(&RecordType::DS) || known.absent.contains(&RecordType::DS)
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
        if let Some(known) = facts.names.get(name) {
            let answers = self.answering.contains(name);
            match &known.node {
                // A cut without DS answers NODATA to DS at the cut, so for
                // a DS question there it stands only once its DS is
                // settled.
                Node::Cut { .. }
                    if answers && self.qtype == RecordType::DS && !Self::ds_settled(known) =>
                {
                    return Fact::Unknown;
                }
                // A cut refers every other question below it.
                Node::Cut { .. } => return Fact::Present(&known.node),
                // A name the answer only passes, or reads addresses at,
                // never ends it.
                _ if !answers || self.knows(known) => return Fact::Present(&known.node),
                _ => {}
            }
        }
        if let Some(node) = facts.whole.get(&(name.clone(), self.qtype)) {
            return Fact::Present(node);
        }
        if facts.names.contains_key(name) || facts.holds_below(name) {
            return Fact::Present(&EMPTY);
        }
        Fact::Unknown
    }

    fn denial(&self, name: &LowerName, kind: Denied) -> Fact<Vec<RecordSet>> {
        match self.facts.proofs.get(&(name.clone(), kind)) {
            Some(sets) => Fact::Present(sets.clone()),
            None => Fact::Unknown,
        }
    }

    fn answers_empty(&self) -> bool {
        false
    }
}
