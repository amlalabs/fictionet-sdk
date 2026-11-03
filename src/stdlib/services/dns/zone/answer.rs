//! The authoritative answer of RFC 1034 §4.3.2, over one view of a zone.

use fictionet::stdlib::protocols::dns::op::{Message, ResponseCode};
use fictionet::stdlib::protocols::dns::rr::rdata::{CNAME, HINFO};
use fictionet::stdlib::protocols::dns::rr::{
    LowerName, Name, RData, Record, RecordSet, RecordType,
};
use fictionet::stdlib::protocols::dns::{Request, Response, dname_substitute};

use super::cover::negative_ttl;
use super::data::{Denied, Fact, View};
use super::zone::{Node, dname_target, targets, unique, wildcard};

/// What [`answer`] found.
#[derive(Clone, Debug, PartialEq)]
pub enum Answered {
    /// The reply, before a server front adds its header details and EDNS.
    Response(Response),
    /// The view does not know a fact the reply rests on: the node at
    /// `name`, or the denial records for it. A server answers SERVFAIL; a
    /// resolver looks elsewhere. It is never a negative answer.
    Unknown {
        /// The name whose fact is unknown.
        name: LowerName,
    },
}

/// What a server sends for QTYPE ANY (RFC 8482 §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AnyResponse {
    /// One synthesized HINFO record with CPU "RFC8482" and an empty OS, as
    /// Cloudflare's servers send (RFC 8482 §4.2), with the smallest TTL
    /// among the name's RRsets, which leaves the TTL to the responder.
    /// With DO, a signed zone
    /// signs it as Cloudflare's online signer does; a zone signed once,
    /// whose keys the view does not hold, sends one RRset of the name
    /// instead. A name with a CNAME gets the CNAME.
    Hinfo,
    /// One RRset of the name, as BIND's `minimal-any` does (RFC 8482 §4.1):
    /// the RRset of this type, or the name's first RRset in type order when
    /// it has none of this type.
    OneRrset(RecordType),
    /// Every RRset of the name, as servers did before RFC 8482, with the
    /// NSEC RRset and the RRSIGs even without DO: such servers count ANY as
    /// asking for them (RFC 4035 §3.2.1).
    All,
}

/// RFC 1034 §4.3.2 over one view. Pure: the reply depends only on the
/// view's facts and the request.
///
/// In order:
///
/// 1. The walk goes from the apex down toward QNAME, reading each name's
///    node from the view. An unknown node ends the answer with
///    [`Answered::Unknown`].
/// 2. A zone cut strictly below the apex and at or above QNAME gives a
///    referral with AA clear: the NS RRset in the authority section; with
///    DO, the DS RRset or the proof that there is none (RFC 4035 §3.1.4);
///    the glue for NS targets at or below the cut as required additional
///    data, then the addresses this zone holds for the other targets, as
///    its own data or as glue under other cuts, as optional additional
///    data (RFC 1034 §4.3.2 step 3b, RFC 9471 §3 and §3.2). QTYPE DS
///    at the cut is answered from the parent's side (RFC 4035 §3.1.4.1),
///    and so is QTYPE NSEC when the zone holds an NSEC there (RFC 4035
///    §2.6).
/// 3. A DNAME above QNAME: the DNAME and a CNAME synthesized with the
///    DNAME's TTL, and the walk goes on at the new name inside the zone;
///    YXDOMAIN when the new name would pass 255 octets (RFC 6672 §2.2,
///    §3.1).
/// 4. A node at QNAME: its RRset with AA set. A CNAME starts the walk
///    again at its target, inside this zone only, and the chain stops at
///    the first name it has seen before (RFC 1034 §4.3.2 step 3a). QTYPE
///    NSEC gets the NSEC the zone holds at the name, in its node or not.
///    No RRset of QTYPE, or an empty non-terminal: NODATA with the SOA.
/// 5. No node at QNAME: the wildcard at the closest encloser, unless a
///    closer name exists, which stops it (RFC 4592 §2.2.2). A wildcard's
///    answer has QNAME as its owner and the wildcard's TTL, follows a
///    wildcard CNAME, and is NODATA when the wildcard has no RRset of
///    QTYPE (RFC 4592 §3.3, §4.3). With no wildcard, NXDOMAIN with the
///    SOA. A `*` label anywhere but first is an ordinary label.
/// 6. A negative answer's SOA has the TTL min(SOA TTL, MINIMUM)
///    (RFC 2308 §3). After a chain, the RCODE is the last name's
///    (RFC 6604 §2). QTYPE ANY follows `any` (RFC 8482 §4). The addresses
///    of NS, MX, and SRV targets in the zone go in the additional section.
/// 7. With DO, every RRset brings its RRSIGs, and every negative and
///    wildcard answer brings the view's denial records for its case
///    (RFC 4035 §3.1.3). Without DO, RRSIG, NSEC, and NSEC3 records are
///    left out unless the question asks for their type, or asks ANY of a
///    server that answers with every RRset (RFC 4035 §3.2.1).
///
/// The reply's header has the request's ID, opcode, RD, and CD, AA and
/// the RCODE; its question is the request's. Owners in the answer section
/// are QNAME in lowercase; the server front gives them the question's case
/// (RFC 4343 §4.1). A QNAME outside the zone gets REFUSED.
pub fn answer(view: &dyn View, req: &Request, any: AnyResponse) -> Answered {
    let qname = LowerName::new(req.question.name());
    let qtype = req.question.query_type();
    let dnssec_ok = req.edns.is_some_and(|edns| edns.dnssec_ok);
    match resolve(view, &qname, qtype, dnssec_ok, any) {
        Ok(found) => Answered::Response(found.response(req, dnssec_ok)),
        Err(name) => Answered::Unknown { name },
    }
}

/// The sections of an answer, before they become a message.
pub(super) struct Found {
    rcode: ResponseCode,
    aa: bool,
    answer: Vec<RecordSet>,
    authority: Vec<RecordSet>,
    additional: Vec<RecordSet>,
    required: usize,
}

impl Found {
    /// A reply with `rcode` and AA as given, and empty sections.
    fn new(rcode: ResponseCode, aa: bool) -> Found {
        Found {
            rcode,
            aa,
            answer: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
            required: 0,
        }
    }

    fn response(self, req: &Request, dnssec_ok: bool) -> Response {
        let query = &req.message.metadata;
        let mut message = Message::response(query.id, query.op_code);
        message.metadata.authoritative = self.aa;
        message.metadata.response_code = self.rcode;
        message.metadata.recursion_desired = req.rd;
        message.metadata.checking_disabled = req.cd;
        message.add_query(req.question.clone());
        let records = |sets: &[RecordSet]| -> Vec<Record> {
            sets.iter()
                .flat_map(|set| set.records(dnssec_ok))
                .cloned()
                .collect()
        };
        message.answers = records(&self.answer);
        message.authorities = records(&self.authority);
        message.additionals = records(&self.additional);
        Response {
            message,
            required_additional: self.required,
        }
    }
}

/// The answer's sections, or the name whose fact the view does not know.
/// `Lazy` runs this to learn which names an answer reads.
pub(super) fn resolve(
    view: &dyn View,
    qname: &LowerName,
    qtype: RecordType,
    dnssec_ok: bool,
    any: AnyResponse,
) -> Result<Found, LowerName> {
    let walk = Walk {
        view,
        qtype,
        dnssec_ok,
        any,
    };
    walk.chase(qname.clone())
}

/// Where the walk from the apex toward a name stops.
enum Loc<'v> {
    /// The name is outside the zone.
    Outside,
    /// The walk reached the name, which has this node.
    Node(&'v Node),
    /// A cut strictly below the apex and at or above the name.
    Cut {
        name: LowerName,
        ns: &'v RecordSet,
        ds: Option<&'v RecordSet>,
        glue: &'v [RecordSet],
    },
    /// A DNAME at this name, strictly above the name.
    Dname(LowerName, &'v RecordSet),
    /// Nothing at the name or below it. The name is the closest encloser.
    Absent(LowerName),
}

/// One step's outcome.
enum Out {
    /// A finished reply.
    Done(Found),
    /// A CNAME, written or synthesized, and the name to go on at. `proof`
    /// holds the denial records a wildcard CNAME needs.
    Restart {
        answer: Vec<RecordSet>,
        target: LowerName,
        proof: Vec<RecordSet>,
    },
}

struct Walk<'v> {
    view: &'v dyn View,
    qtype: RecordType,
    dnssec_ok: bool,
    any: AnyResponse,
}

impl<'v> Walk<'v> {
    /// The node at `name`: `None` when known absent, or the end of the
    /// answer when unknown.
    fn get(&self, name: &LowerName) -> Result<Option<&'v Node>, LowerName> {
        match self.view.node(name) {
            Fact::Present(node) => Ok(Some(node)),
            Fact::Absent => Ok(None),
            Fact::Unknown => Err(name.clone()),
        }
    }

    /// The denial records for `kind` at `name`, when the query set DO.
    fn denial(&self, name: &LowerName, kind: Denied) -> Result<Vec<RecordSet>, LowerName> {
        if !self.dnssec_ok {
            return Ok(Vec::new());
        }
        match self.view.denial(name, kind) {
            Fact::Present(sets) => Ok(sets),
            Fact::Absent | Fact::Unknown => Err(name.clone()),
        }
    }

    /// The NSEC RRset the zone holds at `owner`, an existing name whose
    /// node does not hold it, with its RRSIGs: the NSEC a zone signed once
    /// keeps beside a cut, or the one a zone signed as it is asked makes
    /// for `owner` (RFC 4470 §3). The view's denial records for type NSEC
    /// at `owner` carry it. `None` when the zone holds none there (an
    /// unsigned zone, NSEC3, or an empty non-terminal of a zone signed
    /// once) or the view cannot say.
    fn nsec_at(&self, owner: &LowerName) -> Option<RecordSet> {
        match self.view.denial(owner, Denied::Type(RecordType::NSEC)) {
            Fact::Present(sets) => sets.into_iter().find(|set| {
                set.record_type() == RecordType::NSEC && LowerName::new(set.name()) == *owner
            }),
            Fact::Absent | Fact::Unknown => None,
        }
    }

    /// Walks from the apex down to `name` (steps 1 to 5 without the
    /// wildcard).
    fn locate(&self, name: &LowerName) -> Result<Loc<'v>, LowerName> {
        let apex = self.view.apex();
        if !apex.zone_of(name) {
            return Ok(Loc::Outside);
        }
        // The names from the apex down to `name`.
        let mut path = vec![name.clone()];
        while path.last() != Some(apex) {
            let parent = path.last().expect("not empty").base_name();
            path.push(parent);
        }
        path.reverse();

        let mut names = path.into_iter();
        let mut at = names.next().expect("the apex");
        let Some(mut node) = self.get(&at)? else {
            return Ok(Loc::Absent(at));
        };
        for next in names {
            if let Node::Dname(dname, _) = node {
                return Ok(Loc::Dname(at, dname));
            }
            match self.get(&next)? {
                None => return Ok(Loc::Absent(at)),
                Some(Node::Cut { ns, ds, glue }) => {
                    return Ok(Loc::Cut {
                        name: next,
                        ns,
                        ds: ds.as_ref(),
                        glue,
                    });
                }
                Some(child) => {
                    at = next;
                    node = child;
                }
            }
        }
        Ok(Loc::Node(node))
    }

    /// Follows CNAMEs inside the zone, stopping at the first repeated
    /// name or at a target outside the zone (RFC 1034 §4.3.2 step 3a).
    /// The RCODE is the last name's (RFC 6604 §2). An RRset the chain
    /// reaches twice, such as a DNAME it passes again, goes out once
    /// (RFC 2181 §5).
    fn chase(&self, mut name: LowerName) -> Result<Found, LowerName> {
        let mut seen = Vec::new();
        let mut answer = Vec::new();
        let mut proofs = Vec::new();
        loop {
            match self.step(&name)? {
                Out::Done(mut found) => {
                    found.aa |= !answer.is_empty();
                    answer.append(&mut found.answer);
                    found.answer = unique(answer.into_iter());
                    found.authority = unique(found.authority.into_iter().chain(proofs));
                    return Ok(found);
                }
                Out::Restart {
                    answer: mut more,
                    target,
                    proof,
                } => {
                    answer.append(&mut more);
                    proofs.extend(proof);
                    let looped = target == name || seen.contains(&target);
                    if looped || !self.view.apex().zone_of(&target) {
                        return Ok(Found {
                            answer: unique(answer.into_iter()),
                            authority: unique(proofs.into_iter()),
                            ..Found::new(ResponseCode::NoError, true)
                        });
                    }
                    seen.push(std::mem::replace(&mut name, target));
                }
            }
        }
    }

    /// One pass of steps 1 to 5 for `name`.
    fn step(&self, name: &LowerName) -> Result<Out, LowerName> {
        match self.locate(name)? {
            Loc::Outside => Ok(Out::Done(Found::new(ResponseCode::Refused, false))),
            Loc::Cut {
                name: cut,
                ns,
                ds,
                glue,
            } => {
                if cut == *name && self.qtype == RecordType::DS {
                    // The parent's side answers DS at the cut
                    // (RFC 4035 §3.1.4.1).
                    return match ds {
                        Some(ds) => Ok(Out::Done(positive(vec![ds.clone()], Vec::new()))),
                        None => self.nodata(name, None),
                    };
                }
                if cut == *name && self.qtype == RecordType::NSEC {
                    // So does the NSEC at the cut, which is the parent's
                    // data (RFC 4035 §2.6, §4.2).
                    if let Some(nsec) = self.nsec_at(&cut) {
                        return Ok(Out::Done(positive(vec![nsec], Vec::new())));
                    }
                }
                self.referral(&cut, ns, ds, glue)
            }
            Loc::Dname(owner, dname) => self.substitute(name, &owner, dname),
            Loc::Node(Node::Empty) if !self.view.answers_empty() => Err(name.clone()),
            Loc::Node(node) => self.exact(name, &node.rrsets(), None),
            Loc::Absent(encloser) => {
                let wild = wildcard(&encloser);
                match self.get(&wild)? {
                    None => {
                        let mut authority = vec![self.negative_soa()];
                        authority.extend(self.denial(name, Denied::Name)?);
                        Ok(Out::Done(Found {
                            authority,
                            ..Found::new(ResponseCode::NXDomain, true)
                        }))
                    }
                    Some(Node::Cut { ns, ds, glue }) => self.referral(&wild, ns, ds.as_ref(), glue),
                    Some(Node::Empty) if !self.view.answers_empty() => Err(wild),
                    Some(node) => self.exact(name, &node.rrsets(), Some(&encloser)),
                }
            }
        }
    }

    /// A referral to the cut at `cut` (step 2).
    fn referral(
        &self,
        cut: &LowerName,
        ns: &RecordSet,
        ds: Option<&RecordSet>,
        glue: &[RecordSet],
    ) -> Result<Out, LowerName> {
        let targets = targets(ns);
        let in_domain: Vec<RecordSet> = glue
            .iter()
            .filter(|set| {
                let owner = LowerName::new(set.name());
                is_address(set) && targets.contains(&owner) && cut.zone_of(&owner)
            })
            .cloned()
            .collect();
        let mut additional = in_domain.clone();
        for target in &targets {
            if !cut.zone_of(target) {
                additional.extend(self.addresses_of(target));
            }
        }
        let mut authority = vec![ns.clone()];
        if self.dnssec_ok {
            match ds {
                Some(ds) => authority.push(ds.clone()),
                None => authority.extend(self.denial(cut, Denied::Type(RecordType::DS))?),
            }
        }
        Ok(Out::Done(Found {
            authority,
            required: in_domain.len(),
            additional: unique(additional.into_iter()),
            ..Found::new(ResponseCode::NoError, false)
        }))
    }

    /// The address RRsets of a target in this zone: at its own node, or
    /// held as glue under a cut. They are optional additional data
    /// (RFC 2181 §5.4.1, RFC 9471 §3.2), so a reply never rests on them:
    /// a target the view does not know has none.
    fn addresses_of(&self, target: &LowerName) -> Vec<RecordSet> {
        if !self.view.apex().zone_of(target) {
            return Vec::new();
        }
        match self.locate(target) {
            Ok(Loc::Node(node)) => node
                .rrsets()
                .into_iter()
                .filter(|set| is_address(set))
                .cloned()
                .collect(),
            Ok(Loc::Cut { glue, .. }) => glue_for(glue, target),
            _ => Vec::new(),
        }
    }

    /// A DNAME at `owner` above `name` (step 3).
    fn substitute(
        &self,
        name: &LowerName,
        owner: &LowerName,
        dname: &RecordSet,
    ) -> Result<Out, LowerName> {
        let target = dname
            .records_without_rrsigs()
            .next()
            .and_then(|record| dname_target(&record.data));
        let Some(target) = target else {
            return Ok(Out::Done(positive(vec![dname.clone()], Vec::new())));
        };
        // `owner` is strictly above `name`, so only a new name past 255
        // octets has none.
        let Some(synthesized) = dname_substitute(name, owner, &target) else {
            return Ok(Out::Done(Found {
                answer: vec![dname.clone()],
                ..Found::new(ResponseCode::YXDomain, true)
            }));
        };
        let owner_name = Name::from(name);
        let mut cname = RecordSet::with_ttl(owner_name.clone(), RecordType::CNAME, dname.ttl());
        cname.set_records(vec![Record::from_rdata(
            owner_name,
            dname.ttl(),
            RData::CNAME(CNAME(synthesized.clone())),
        )]);
        Ok(Out::Restart {
            answer: vec![dname.clone(), cname],
            target: LowerName::new(&synthesized),
            proof: Vec::new(),
        })
    }

    /// The answer from the RRsets matched at `name`, its own node's or,
    /// with `encloser`, the wildcard's there (steps 4 and 5).
    fn exact(
        &self,
        name: &LowerName,
        sets: &[&RecordSet],
        encloser: Option<&LowerName>,
    ) -> Result<Out, LowerName> {
        let owner = Name::from(name);
        let proof = match encloser {
            Some(encloser) => self.denial(
                name,
                Denied::Wildcard {
                    closest_encloser: encloser.clone(),
                },
            )?,
            None => Vec::new(),
        };

        if self.qtype == RecordType::ANY {
            // Without DO, only `All` sends the DNSSEC RRsets.
            let sets: Vec<&RecordSet> = sets
                .iter()
                .copied()
                .filter(|set| {
                    self.dnssec_ok || self.any == AnyResponse::All || !is_dnssec(set.record_type())
                })
                .collect();
            let Some(first) = sets.first() else {
                return self.nodata(name, encloser);
            };
            let cname = sets
                .iter()
                .find(|set| set.record_type() == RecordType::CNAME);
            let answer = match (self.any, cname) {
                // No HINFO is made up at a CNAME (RFC 8482 §4.2), which
                // leaves room for no other data (RFC 1034 §3.6.2).
                (AnyResponse::Hinfo, Some(cname)) => vec![owned(cname, &owner)],
                (AnyResponse::Hinfo, None) => vec![
                    self.hinfo(&owner, smallest_ttl(&sets))
                        .unwrap_or_else(|| owned(first, &owner)),
                ],
                (AnyResponse::OneRrset(rtype), _) => {
                    let set = sets.iter().find(|set| set.record_type() == rtype);
                    vec![owned(set.unwrap_or(first), &owner)]
                }
                (AnyResponse::All, _) => {
                    let mut answer: Vec<RecordSet> =
                        sets.iter().map(|set| owned(set, &owner)).collect();
                    // With DO the RRSIGs go out inside their RRsets.
                    if !self.dnssec_ok {
                        answer.extend(rrsigs_of(&sets, &owner));
                    }
                    answer
                }
            };
            return Ok(Out::Done(positive(answer, proof)));
        }

        if self.qtype == RecordType::RRSIG {
            // RRSIGs travel inside the RRsets they cover, so an RRSIG
            // question gathers them.
            return Ok(Out::Done(match rrsigs_of(sets, &owner) {
                Some(set) => positive(vec![set], proof),
                None => return self.nodata(name, encloser),
            }));
        }

        if let Some(set) = sets.iter().find(|set| set.record_type() == self.qtype) {
            let mut additional = Vec::new();
            for target in targets(set) {
                additional.extend(self.addresses_of(&target));
            }
            let mut found = positive(vec![owned(set, &owner)], proof);
            found.additional = unique(additional.into_iter());
            return Ok(Out::Done(found));
        }

        if self.qtype == RecordType::NSEC {
            // A zone signed as it is asked keeps its NSEC records out of
            // its nodes, and serves the one it makes for the name
            // (RFC 4470 §3). A NODATA here would carry that NSEC as its
            // proof, though it lists NSEC.
            let matched = encloser.map_or_else(|| name.clone(), wildcard);
            if let Some(nsec) = self.nsec_at(&matched) {
                return Ok(Out::Done(positive(vec![owned(&nsec, &owner)], proof)));
            }
        }

        if let Some(cname) = sets
            .iter()
            .find(|set| set.record_type() == RecordType::CNAME)
        {
            let target = cname
                .records_without_rrsigs()
                .find_map(|record| match &record.data {
                    RData::CNAME(target) => Some(LowerName::new(&target.0)),
                    _ => None,
                });
            return Ok(match target {
                Some(target) => Out::Restart {
                    answer: vec![owned(cname, &owner)],
                    target,
                    proof,
                },
                None => Out::Done(positive(vec![owned(cname, &owner)], proof)),
            });
        }

        self.nodata(name, encloser)
    }

    /// NODATA at `name`, matched at its own node or, with `encloser`, at
    /// the wildcard there (RFC 2308 §2.2, RFC 4035 §3.1.3.1 and §3.1.3.4).
    fn nodata(&self, name: &LowerName, encloser: Option<&LowerName>) -> Result<Out, LowerName> {
        let mut authority = vec![self.negative_soa()];
        match encloser {
            None => authority.extend(self.denial(name, Denied::Type(self.qtype))?),
            Some(encloser) => {
                let kind = Denied::Wildcard {
                    closest_encloser: encloser.clone(),
                };
                authority.extend(self.denial(name, kind)?);
                authority.extend(self.denial(&wildcard(encloser), Denied::Type(self.qtype))?);
            }
        }
        Ok(Out::Done(Found {
            authority: unique(authority.into_iter()),
            ..Found::new(ResponseCode::NoError, true)
        }))
    }

    /// The synthesized HINFO answer to QTYPE ANY at `owner` (RFC 8482
    /// §4.2). With DO, in a signed zone, it is signed, since a validator
    /// rejects an unsigned RRset there. A view that cannot sign gives
    /// `None`, and the answer is one RRset of the name with its RRSIGs
    /// instead (RFC 8482 §4.1). Without DO no RRSIG goes out, so the
    /// HINFO goes out as it is.
    fn hinfo(&self, owner: &Name, ttl: u32) -> Option<RecordSet> {
        let rdata = RData::HINFO(HINFO::new("RFC8482".to_string(), String::new()));
        let mut set = RecordSet::with_ttl(owner.clone(), RecordType::HINFO, ttl);
        set.set_records(vec![Record::from_rdata(owner.clone(), ttl, rdata)]);
        if !self.dnssec_ok || self.view.soa().rrsigs().is_empty() {
            return Some(set);
        }
        self.view.sign(&set)
    }

    /// The SOA RRset for a negative answer, with TTL min(SOA TTL, MINIMUM)
    /// (RFC 2308 §3). Its RRSIGs take the same TTL.
    fn negative_soa(&self) -> RecordSet {
        let soa = self.view.soa();
        let ttl = negative_ttl(soa);
        let retimed = |records: &mut dyn Iterator<Item = &Record>| -> Vec<Record> {
            records
                .map(|record| {
                    let mut record = record.clone();
                    record.ttl = ttl;
                    record
                })
                .collect()
        };
        let mut set = soa.clone();
        set.set_ttl(ttl);
        set.set_records(retimed(&mut soa.records_without_rrsigs()));
        set.set_rrsigs(retimed(&mut soa.rrsigs().iter()));
        set
    }
}

/// A positive answer with AA set.
fn positive(answer: Vec<RecordSet>, authority: Vec<RecordSet>) -> Found {
    Found {
        answer,
        authority,
        ..Found::new(ResponseCode::NoError, true)
    }
}

/// The smallest TTL among `sets`, or 0 when there are none.
fn smallest_ttl(sets: &[&RecordSet]) -> u32 {
    sets.iter().map(|set| set.ttl()).min().unwrap_or(0)
}

/// `set` with `owner` as the owner of every record and RRSIG.
fn owned(set: &RecordSet, owner: &Name) -> RecordSet {
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

/// The RRSIGs of `sets` as one RRSIG RRset owned by `owner`, or `None`
/// when none of them is signed.
fn rrsigs_of(sets: &[&RecordSet], owner: &Name) -> Option<RecordSet> {
    let rrsigs: Vec<Record> = sets.iter().flat_map(|set| set.rrsigs()).cloned().collect();
    let ttl = rrsigs.first()?.ttl;
    let mut set = RecordSet::with_ttl(owner.clone(), RecordType::RRSIG, ttl);
    set.set_records(rrsigs);
    Some(owned(&set, owner))
}

/// The address RRsets of `target` among a cut's glue.
fn glue_for(glue: &[RecordSet], target: &LowerName) -> Vec<RecordSet> {
    glue.iter()
        .filter(|set| is_address(set) && LowerName::new(set.name()) == *target)
        .cloned()
        .collect()
}

fn is_address(set: &RecordSet) -> bool {
    matches!(set.record_type(), RecordType::A | RecordType::AAAA)
}

/// The types RFC 4035 §3.2.1 keeps out of replies without DO.
fn is_dnssec(rtype: RecordType) -> bool {
    matches!(
        rtype,
        RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3
    )
}
