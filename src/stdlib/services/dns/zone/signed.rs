//! Signed zones: a complete zone signed once, the way `dnssec-signzone`
//! signs a master file, and any zone data signed as it is asked.
//!
//! Both add the zone's DNSKEY RRset at the apex and an RRSIG for every
//! RRset the zone is authoritative for: everything but the NS RRsets at
//! zone cuts and glue (RFC 4035 §2.2). With a key-signing key and a
//! zone-signing key, as the real root has, the key-signing keys sign the
//! DNSKEY, CDS, and CDNSKEY RRsets and the zone-signing keys sign the
//! rest; with keys of one kind only, every key signs every RRset.
//!
//! [`Zone::signed`] also adds a complete NSEC or NSEC3 chain. [`Signed`]
//! cannot: its data may grow, and a chain made now would deny names added
//! later to any resolver that reuses denials (RFC 8198). It makes denial
//! records for each negative answer with [`cover`] instead.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::sync::Arc;

use fictionet::stdlib::protocols::dns::ProtoError;
use fictionet::stdlib::protocols::dns::dnssec::rdata::{DNSKEY, DNSSECRData, NSEC3PARAM};
use fictionet::stdlib::protocols::dns::dnssec::{
    KeyFlags, KeySet, Nsec3HashAlgorithm, PublicKey, Sign, Window, sign,
};
use fictionet::stdlib::protocols::dns::op::Query;
use fictionet::stdlib::protocols::dns::rr::{
    LowerName, Name, RData, Record, RecordSet, RecordType,
};
use fictionet::sync::Mutex;

use super::answer::{AnyResponse, resolve};
use super::cover::{Nsec3Params, cover, negative_ttl, node_types, nsec_set, nsec3_hash, nsec3_set};
use super::data::{Denied, Fact, Revision, View, ZoneData};
use super::zone::{Node, Zone, ZoneBuilder};

/// How a signed zone proves that names and types do not exist.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Denial {
    /// NSEC records (RFC 4034 §4).
    Nsec,
    /// NSEC3 records with SHA-1 and zero iterations (RFC 5155,
    /// RFC 9276 §3.1), and an NSEC3PARAM record at the apex.
    Nsec3 {
        /// Whether unsigned delegations are left out of the chain, so the
        /// records spanning them say that an unsigned delegation may be
        /// there (RFC 5155 §6).
        opt_out: bool,
        /// The salt every hash is taken with. RFC 9276 §3.1 recommends
        /// none.
        salt: Vec<u8>,
    },
}

impl Zone {
    /// This zone signed with `keys` for `window`, with a complete chain of
    /// denial records, as `dnssec-signzone` signs a master file.
    ///
    /// The signed zone holds the DNSKEY RRset of `keys` at the apex, with
    /// the SOA RRset's TTL, an RRSIG for every authoritative RRset, and
    /// the chain `denial` asks for: an NSEC at every name that holds data
    /// or a zone cut, or an NSEC3 at the hash of every name, empty
    /// non-terminals included, leaving out unsigned delegations when
    /// opt-out is set (RFC 5155 §7.1). Empty non-terminals that lead only
    /// to unsigned delegations keep their NSEC3, as RFC 7129 §5.1
    /// recommends. Denial records take the negative TTL of RFC 9077.
    ///
    /// DNSSEC records the zone held before (DNSKEY and NSEC3PARAM at the
    /// apex, NSEC, NSEC3, and RRSIGs) are replaced, so signing a signed
    /// zone again signs it afresh. The signed zone is a new zone, at
    /// revision 0 as every built zone is.
    ///
    /// The error is hickory's, for a record whose data does not encode, so
    /// it could not be signed or served.
    pub fn signed(
        &self,
        keys: &KeySet,
        window: Window,
        denial: Denial,
    ) -> Result<Zone, ProtoError> {
        let signing = Signing::new(self.apex(), keys.clone(), window, denial);
        let soa = View::soa(self);
        let mut nodes = BTreeMap::new();
        for (name, node) in self.nodes() {
            let node = signing.node(name, node, soa, &mut |set| signing.sign(set))?;
            nodes.insert(name.clone(), node);
        }
        let ttl = negative_ttl(soa);
        let chain = match &signing.denial {
            Denial::Nsec => nsec_chain(&signing.apex, &nodes, ttl),
            Denial::Nsec3 { opt_out, salt } => {
                let params = Nsec3Params {
                    opt_out: *opt_out,
                    salt,
                    ttl,
                };
                nsec3_chain(&signing.apex, &nodes, &params)
            }
        };

        let signed_soa = match nodes.get(self.apex()) {
            Some(Node::Data(sets)) => sets.get(&RecordType::SOA).cloned(),
            _ => None,
        };
        let signed_soa = signed_soa.expect("a zone's apex holds its SOA RRset");
        let mut builder = ZoneBuilder::with_soa(signing.apex.clone(), signed_soa);
        for (name, node) in nodes {
            builder = match node {
                Node::Data(sets) => sets
                    .into_iter()
                    .filter(|(rtype, _)| !(*rtype == RecordType::SOA && name == *self.apex()))
                    .fold(builder, |builder, (_, set)| builder.rrset(set)),
                Node::Dname(dname, sets) => std::iter::once(dname)
                    .chain(sets.into_values())
                    .fold(builder, ZoneBuilder::rrset),
                Node::Cut { ns, ds, glue } => builder.delegate(Name::from(&name), ns, glue, ds),
                Node::Empty => builder,
            };
        }
        for set in chain {
            builder = builder.rrset(signing.sign(&set)?);
        }
        Ok(builder
            .build()
            .expect("signing a zone keeps every rule it was built under"))
    }
}

/// The NSEC chain over `nodes`: one NSEC at each name that holds data or
/// a zone cut, in canonical order, the last pointing back at the apex
/// (RFC 4035 §2.3). Empty non-terminals have none.
fn nsec_chain(apex: &Name, nodes: &BTreeMap<LowerName, Node>, ttl: u32) -> Vec<RecordSet> {
    let owners: Vec<(&LowerName, &Node)> = nodes
        .iter()
        .filter(|(_, node)| !matches!(node, Node::Empty))
        .collect();
    owners
        .iter()
        .enumerate()
        .map(|(index, (owner, node))| {
            let next = match owners.get(index + 1) {
                Some((next, _)) => Name::from(*next),
                None => apex.clone(),
            };
            nsec_set(&Name::from(*owner), next, &node_types(node).0, ttl)
        })
        .collect()
}

/// The NSEC3 chain over `nodes`: one NSEC3 at the hash of each name,
/// empty non-terminals included and unsigned delegations left out under
/// opt-out, in hash order, the last pointing back at the first
/// (RFC 5155 §7.1).
fn nsec3_chain(
    apex: &Name,
    nodes: &BTreeMap<LowerName, Node>,
    params: &Nsec3Params<'_>,
) -> Vec<RecordSet> {
    let mut hashed: Vec<(Vec<u8>, &Node)> = nodes
        .iter()
        .filter(|(_, node)| !(params.opt_out && matches!(node, Node::Cut { ds: None, .. })))
        .map(|(name, node)| (nsec3_hash(&Name::from(name), params.salt), node))
        .collect();
    hashed.sort_by(|a, b| a.0.cmp(&b.0));
    hashed
        .iter()
        .enumerate()
        .map(|(index, (hash, node))| {
            let next = hashed[(index + 1) % hashed.len()].0.clone();
            let (types, signed) = node_types(node);
            nsec3_set(apex, hash, next, &types, signed, params)
        })
        .collect()
}

/// Zone data signed as it is asked: every RRset a view serves is signed,
/// and every denial is made for its question with [`cover`].
///
/// Signatures are kept for each RRset, key, and window, so an RRset asked
/// again is not signed again. The data is trusted world code; nothing it
/// returns reaches a validator except through the records served.
///
/// A view holds the facts its question reads from the data's view, each
/// node signed, with the DNSKEY RRset (and with NSEC3, the NSEC3PARAM
/// RRset) at the apex. Other names read as unknown. An RRset whose data
/// does not encode is served without RRSIGs, which a validator rejects.
pub struct Signed<D: ZoneData> {
    data: D,
    signing: Arc<Signing>,
}

impl<D: ZoneData> Signed<D> {
    /// `data` signed with `keys` for `window`, denying with `denial`.
    pub fn new(data: D, keys: KeySet, window: Window, denial: Denial) -> Signed<D> {
        let remembered = KeySet {
            keys: keys
                .keys
                .into_iter()
                .map(|key| {
                    Arc::new(Remembered {
                        key,
                        signatures: Mutex::new(BTreeMap::new()),
                    }) as Arc<dyn Sign>
                })
                .collect(),
        };
        let signing = Signing::new(data.apex(), remembered, window, denial);
        Signed {
            data,
            signing: Arc::new(signing),
        }
    }
}

impl<D: ZoneData> ZoneData for Signed<D> {
    fn apex(&self) -> &LowerName {
        self.data.apex()
    }

    fn view(&self, question: &Query) -> Arc<dyn View + Send + Sync> {
        let inner = self.data.view(question);
        // The names the answer reads. They do not depend on DO, on how ANY
        // is answered, or on the DNSSEC records signing adds.
        let reads = Reads {
            view: &*inner,
            names: RefCell::new(BTreeSet::new()),
        };
        let qname = LowerName::new(question.name());
        let _ = resolve(
            &reads,
            &qname,
            question.query_type(),
            false,
            AnyResponse::All,
        );

        let signing = &self.signing;
        let soa = inner.soa();
        let mut sign =
            |set: &RecordSet| -> Result<RecordSet, Infallible> { Ok(signing.sign_or_leave(set)) };
        let facts = reads
            .names
            .into_inner()
            .into_iter()
            .map(|name| {
                let fact = match inner.node(&name) {
                    Fact::Present(node) => {
                        let Ok(node) = signing.node(&name, node, soa, &mut sign);
                        Fact::Present(node)
                    }
                    Fact::Absent => Fact::Absent,
                    Fact::Unknown => Fact::Unknown,
                };
                (name, fact)
            })
            .collect();
        Arc::new(SignedView {
            apex: self.data.apex().clone(),
            revision: inner.revision(),
            soa: signing.sign_or_leave(soa),
            facts,
            signing: self.signing.clone(),
        })
    }
}

/// A key whose signatures are kept by the bytes signed. Those bytes hold
/// the RRset in canonical form and the RRSIG's fields, the window among
/// them, so each signature is kept per RRset, key, and window.
struct Remembered {
    key: Arc<dyn Sign>,
    signatures: Mutex<BTreeMap<Vec<u8>, Vec<u8>>>,
}

impl Sign for Remembered {
    fn dnskey(&self) -> DNSKEY {
        self.key.dnskey()
    }

    fn sign(&self, tbs: &[u8]) -> Vec<u8> {
        if let Some(signature) = self.signatures.lock().get(tbs) {
            return signature.clone();
        }
        let signature = self.key.sign(tbs);
        self.signatures
            .lock()
            .insert(tbs.to_vec(), signature.clone());
        signature
    }
}

/// What signing one zone needs: its keys, split by what they sign, the
/// window, and how it denies.
struct Signing {
    apex: Name,
    lower_apex: LowerName,
    keys: KeySet,
    /// The keys that sign the DNSKEY, CDS, and CDNSKEY RRsets.
    entry: Vec<Arc<dyn Sign>>,
    /// The keys that sign every other RRset.
    data: Vec<Arc<dyn Sign>>,
    window: Window,
    denial: Denial,
}

impl Signing {
    /// The keys are split per algorithm, since every RRset needs an RRSIG
    /// from a key of each algorithm in the DNSKEY RRset (RFC 4035 §2.2).
    /// Within one algorithm, keys with the Secure Entry Point flag sign
    /// the DNSKEY, CDS, and CDNSKEY RRsets and the others sign the rest;
    /// when all of its keys or none have the flag, they all sign
    /// everything.
    fn new(apex: &LowerName, keys: KeySet, window: Window, denial: Denial) -> Signing {
        let algorithm = |key: &Arc<dyn Sign>| u8::from(key.dnskey().public_key().algorithm());
        let mut algorithms: Vec<u8> = Vec::new();
        for key in &keys.keys {
            if !algorithms.contains(&algorithm(key)) {
                algorithms.push(algorithm(key));
            }
        }
        let (mut entry, mut data) = (Vec::new(), Vec::new());
        for each in algorithms {
            let (sep, other): (Vec<_>, Vec<_>) = keys
                .keys
                .iter()
                .filter(|key| algorithm(key) == each)
                .cloned()
                .partition(|key| KeyFlags(key.dnskey().flags()).secure_entry_point());
            if sep.is_empty() || other.is_empty() {
                let all: Vec<_> = sep.into_iter().chain(other).collect();
                entry.extend(all.iter().cloned());
                data.extend(all);
            } else {
                entry.extend(sep);
                data.extend(other);
            }
        }
        Signing {
            apex: Name::from(apex),
            lower_apex: apex.clone(),
            keys,
            entry,
            data,
            window,
            denial,
        }
    }

    /// `set` with its old RRSIGs replaced by one from each key that signs
    /// its type.
    fn sign(&self, set: &RecordSet) -> Result<RecordSet, ProtoError> {
        let keys = match set.record_type() {
            RecordType::DNSKEY | RecordType::CDS | RecordType::CDNSKEY => &self.entry,
            _ => &self.data,
        };
        let mut signed = bare(set);
        for key in keys {
            signed.insert_rrsig(sign(key.as_ref(), &signed, &self.apex, self.window)?);
        }
        Ok(signed)
    }

    /// `set` signed, or without RRSIGs when its data does not encode.
    fn sign_or_leave(&self, set: &RecordSet) -> RecordSet {
        self.sign(set).unwrap_or_else(|_| bare(set))
    }

    /// `node` at `name` as the signed zone holds it, its RRsets passed
    /// through `sign`. DNSSEC records the node held are dropped; the apex
    /// gets the DNSKEY RRset, with `soa`'s TTL, and with NSEC3 the
    /// NSEC3PARAM RRset.
    fn node<E>(
        &self,
        name: &LowerName,
        node: &Node,
        soa: &RecordSet,
        sign: &mut dyn FnMut(&RecordSet) -> Result<RecordSet, E>,
    ) -> Result<Node, E> {
        let apex = *name == self.lower_apex;
        let mut signed_sets = |sets: &BTreeMap<RecordType, RecordSet>| {
            let mut kept: BTreeMap<RecordType, RecordSet> = sets
                .iter()
                .filter(|(rtype, _)| {
                    !matches!(
                        **rtype,
                        RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3
                    ) && !(apex && matches!(**rtype, RecordType::DNSKEY | RecordType::NSEC3PARAM))
                })
                .map(|(rtype, set)| (*rtype, set.clone()))
                .collect();
            if apex {
                kept.insert(
                    RecordType::DNSKEY,
                    self.keys.dnskey_rrset(&self.apex, soa.ttl()),
                );
                if let Some(param) = self.nsec3param(soa) {
                    kept.insert(RecordType::NSEC3PARAM, param);
                }
            }
            kept.into_iter()
                .map(|(rtype, set)| Ok((rtype, sign(&set)?)))
                .collect::<Result<BTreeMap<_, _>, E>>()
        };
        Ok(match node {
            Node::Data(sets) => Node::Data(signed_sets(sets)?),
            Node::Dname(dname, sets) => {
                let sets = signed_sets(sets)?;
                Node::Dname(sign(dname)?, sets)
            }
            Node::Cut { ns, ds, glue } => Node::Cut {
                ns: bare(ns),
                ds: ds.as_ref().map(&mut *sign).transpose()?,
                glue: glue.iter().map(bare).collect(),
            },
            Node::Empty => Node::Empty,
        })
    }

    /// The NSEC3PARAM RRset for an NSEC3 denial, with the denial records'
    /// TTL. Its flags are zero (RFC 5155 §4.1.2).
    fn nsec3param(&self, soa: &RecordSet) -> Option<RecordSet> {
        let Denial::Nsec3 { salt, .. } = &self.denial else {
            return None;
        };
        let rdata = NSEC3PARAM::new(Nsec3HashAlgorithm::SHA1, false, 0, salt.clone());
        let ttl = negative_ttl(soa);
        let mut set = RecordSet::with_ttl(self.apex.clone(), RecordType::NSEC3PARAM, ttl);
        set.set_records(vec![Record::from_rdata(
            self.apex.clone(),
            ttl,
            RData::DNSSEC(DNSSECRData::NSEC3PARAM(rdata)),
        )]);
        Some(set)
    }
}

/// `set` without its RRSIGs.
fn bare(set: &RecordSet) -> RecordSet {
    let mut set = set.clone();
    set.clear_rrsigs();
    set
}

/// A view that notes every name read from it.
struct Reads<'v> {
    view: &'v dyn View,
    names: RefCell<BTreeSet<LowerName>>,
}

impl View for Reads<'_> {
    fn apex(&self) -> &LowerName {
        self.view.apex()
    }

    fn revision(&self) -> Revision {
        self.view.revision()
    }

    fn soa(&self) -> &RecordSet {
        self.view.soa()
    }

    fn node(&self, name: &LowerName) -> Fact<&Node> {
        self.names.borrow_mut().insert(name.clone());
        self.view.node(name)
    }

    /// The answer runs without DO, so it never asks.
    fn denial(&self, _name: &LowerName, _kind: Denied) -> Fact<Vec<RecordSet>> {
        Fact::Present(Vec::new())
    }
}

/// The signed facts one question reads, at the data's revision.
struct SignedView {
    apex: LowerName,
    revision: Revision,
    soa: RecordSet,
    facts: BTreeMap<LowerName, Fact<Node>>,
    signing: Arc<Signing>,
}

impl View for SignedView {
    fn apex(&self) -> &LowerName {
        &self.apex
    }

    fn revision(&self) -> Revision {
        self.revision
    }

    fn soa(&self) -> &RecordSet {
        &self.soa
    }

    fn node(&self, name: &LowerName) -> Fact<&Node> {
        if !self.apex.zone_of(name) {
            return Fact::Absent;
        }
        match self.facts.get(name) {
            Some(Fact::Present(node)) => Fact::Present(node),
            Some(Fact::Absent) => Fact::Absent,
            Some(Fact::Unknown) | None => Fact::Unknown,
        }
    }

    fn denial(&self, name: &LowerName, kind: Denied) -> Fact<Vec<RecordSet>> {
        cover(self, name, kind, &self.signing.denial).map(|sets| {
            sets.iter()
                .map(|set| self.signing.sign_or_leave(set))
                .collect()
        })
    }

    fn sign(&self, set: &RecordSet) -> Option<RecordSet> {
        self.signing.sign(set).ok()
    }
}

#[cfg(test)]
pub(super) mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::stdlib::protocols::dns::dnssec::{
        Algorithm, AlgorithmPolicy, Anchors, Chain, DigestType, Fetched, Insecure, Link, Ring,
        Validation, ZoneKey, validate_denial, validate_rrset,
    };
    use crate::stdlib::protocols::dns::op::{Edns, Message, MessageType, OpCode, ResponseCode};
    use crate::stdlib::protocols::dns::rr::rdata::{A, NS, SOA};
    use crate::stdlib::protocols::dns::{Parsed, Request};
    use crate::stdlib::services::dns::zone::{Answered, answer};
    use crate::stdlib::services::serve::Transport;
    use fictionet::{Seed, SeededEntropy};

    /// A fully qualified name from text, where `\DDD` is the octet DDD
    /// (RFC 1035 §5.1).
    pub(in super::super) fn name(text: &str) -> Name {
        let labels = text
            .split('.')
            .filter(|label| !label.is_empty())
            .map(|label| {
                let mut octets = Vec::new();
                let mut rest = label.as_bytes();
                while let Some((&first, tail)) = rest.split_first() {
                    if first == b'\\' {
                        let digits = std::str::from_utf8(&tail[..3]).unwrap();
                        octets.push(digits.parse::<u8>().unwrap());
                        rest = &tail[3..];
                    } else {
                        octets.push(first);
                        rest = tail;
                    }
                }
                octets
            });
        Name::from_labels(labels).unwrap()
    }

    pub(in super::super) fn lower(text: &str) -> LowerName {
        LowerName::new(&name(text))
    }

    pub(in super::super) fn ns(text: &str) -> RData {
        RData::NS(NS(name(text)))
    }

    pub(in super::super) fn rrset(owner: &str, data: Vec<RData>) -> RecordSet {
        let owner = name(owner);
        let mut set = RecordSet::with_ttl(owner.clone(), data[0].record_type(), 3600);
        set.set_records(
            data.into_iter()
                .map(|data| Record::from_rdata(owner.clone(), 3600, data))
                .collect(),
        );
        set
    }

    pub(in super::super) fn a(last: u8) -> RData {
        RData::A(A::new(192, 0, 2, last))
    }

    /// A builder for `apex` with its NS RRset and the address of its name
    /// server.
    pub(in super::super) fn builder(apex: &str) -> ZoneBuilder {
        let server = format!("ns1.{apex}");
        let soa = SOA::new(
            name(&server),
            name(&format!("hostmaster.{apex}")),
            1,
            7200,
            3600,
            1209600,
            300,
        );
        Zone::builder(name(apex), soa, 3600)
            .rrset(rrset(apex, vec![ns(&server)]))
            .rrset(rrset(&server, vec![a(1)]))
    }

    pub(in super::super) fn time(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    /// A time inside [`window`].
    pub(in super::super) const NOW: u64 = 1_750_000_000;

    pub(in super::super) fn window() -> Window {
        Window {
            inception: time(1_700_000_000),
            expiration: time(1_800_000_000),
        }
    }

    pub(in super::super) fn key(seed: u64, algorithm: Algorithm, flags: KeyFlags) -> Arc<dyn Sign> {
        let entropy = SeededEntropy::new(Seed::from_u64(seed));
        Arc::new(ZoneKey::generate(&entropy, algorithm, flags))
    }

    /// A key-signing and a zone-signing key of one algorithm, Ed25519,
    /// drawn from `seed`.
    pub(in super::super) fn keys(seed: u64) -> KeySet {
        KeySet {
            keys: vec![
                key(seed, Algorithm::Ed25519, KeyFlags::KSK),
                key(seed + 1, Algorithm::Ed25519, KeyFlags::ZSK),
            ],
        }
    }

    /// The reply `data` gives to `qname` `qtype` with DO set.
    pub(in super::super) fn ask(data: &dyn ZoneData, qname: &str, qtype: RecordType) -> Message {
        let mut message = Message::new(7, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(name(qname), qtype));
        let mut edns = Edns::new();
        edns.set_max_payload(1232).set_dnssec_ok(true);
        message.set_edns(edns);
        let request = match Request::parse(&message.to_vec().unwrap(), Transport::Udp) {
            Parsed::Request(request) => request,
            other => panic!("not a request: {other:?}"),
        };
        let view = data.view(&request.question);
        match answer(&*view, &request, AnyResponse::All) {
            Answered::Response(response) => response.message,
            Answered::Unknown { name } => panic!("{qname} {qtype}: unknown at {name}"),
        }
    }

    /// Records gathered back into RRsets, each RRSIG with the RRset it
    /// covers.
    pub(in super::super) fn sets(records: &[Record]) -> Vec<RecordSet> {
        crate::stdlib::services::dns::records::rrsets(records)
    }

    /// What the validator needs besides the records.
    pub(in super::super) struct Validator {
        pub anchors: Anchors,
        pub chain: Chain,
    }

    impl Validator {
        /// A validator anchored at `apex` with `keys`, its chain starting
        /// with the DNSKEY RRset `data` serves.
        pub(in super::super) fn new(data: &dyn ZoneData, apex: &str, keys: &KeySet) -> Validator {
            let reply = ask(data, apex, RecordType::DNSKEY);
            let dnskey = sets(&reply.answers).remove(0);
            Validator {
                anchors: Anchors::of(vec![keys.anchor(&name(apex))]),
                chain: Chain {
                    links: vec![Link {
                        zone: name(apex),
                        ds: Fetched::Failed,
                        dnskey: Fetched::Answer(dnskey),
                    }],
                },
            }
        }

        pub(in super::super) fn rrset(
            &self,
            set: &RecordSet,
            authority: &[RecordSet],
        ) -> Validation {
            let policy = AlgorithmPolicy::iana();
            validate_rrset(
                set,
                authority,
                &self.chain,
                &self.anchors,
                &policy,
                time(NOW),
                &Ring,
            )
        }

        pub(in super::super) fn denial(
            &self,
            qname: &str,
            qtype: RecordType,
            reply: &Message,
        ) -> Validation {
            let policy = AlgorithmPolicy::iana();
            let query = Query::query(name(qname), qtype);
            validate_denial(
                &query,
                reply.metadata.response_code,
                &sets(&reply.authorities),
                &self.chain,
                &self.anchors,
                &policy,
                time(NOW),
                &Ring,
            )
            .validation
        }
    }

    /// The signed child `secure.example.`, with its keys.
    pub(in super::super) fn secure_child() -> (Zone, KeySet) {
        let keys = keys(20);
        let zone = builder("secure.example.")
            .rrset(rrset("www.secure.example.", vec![a(30)]))
            .build()
            .unwrap()
            .signed(&keys, window(), Denial::Nsec)
            .unwrap();
        (zone, keys)
    }

    /// `example.`: a name with data, an empty non-terminal, a wildcard, a
    /// signed delegation, and an unsigned one.
    pub(in super::super) fn parent() -> Zone {
        parent_with_ds_for(&keys(20))
    }

    /// `example.` with a DS RRset for `child_keys` at `secure.example.`.
    pub(in super::super) fn parent_with_ds_for(child_keys: &KeySet) -> Zone {
        let ds = child_keys
            .ds(
                &name("secure.example."),
                3600,
                DigestType::Sha256,
                &AlgorithmPolicy::iana(),
            )
            .unwrap();
        builder("example.")
            .rrset(rrset("www.example.", vec![a(10)]))
            .rrset(rrset("a.b.example.", vec![a(11)]))
            .rrset(rrset("*.wild.example.", vec![a(12)]))
            .delegate(
                name("secure.example."),
                rrset("secure.example.", vec![ns("ns1.secure.example.")]),
                vec![rrset("ns1.secure.example.", vec![a(1)])],
                Some(ds),
            )
            .delegate(
                name("plain.example."),
                rrset("plain.example.", vec![ns("ns1.plain.example.")]),
                vec![rrset("ns1.plain.example.", vec![a(2)])],
                None,
            )
            .build()
            .unwrap()
    }

    /// What one way of signing `example.` should validate as, where opt-out
    /// changes it.
    struct Expected {
        nxdomain: Validation,
        wildcard: Validation,
        plain_ds: Validation,
        plain: Validation,
    }

    const PROVEN: Expected = Expected {
        nxdomain: Validation::Secure,
        wildcard: Validation::Secure,
        plain_ds: Validation::Secure,
        plain: Validation::Insecure(Insecure::ProvenNoDs),
    };

    const OPT_OUT: Validation = Validation::Insecure(Insecure::OptOutCovered);

    /// Asks `data`, `example.` signed with `keys(10)`, every kind of
    /// question and validates each reply under the zone's own anchor.
    fn every_answer_validates(data: &dyn ZoneData, expected: Expected) {
        let validator = Validator::new(data, "example.", &keys(10));
        let only = |reply: &Message| sets(&reply.answers).remove(0);

        let dnskey = ask(data, "example.", RecordType::DNSKEY);
        assert_eq!(validator.rrset(&only(&dnskey), &[]), Validation::Secure);

        let www = ask(data, "www.example.", RecordType::A);
        assert_eq!(
            validator.rrset(&only(&www), &sets(&www.authorities)),
            Validation::Secure
        );

        for (qname, qtype) in [
            ("www.example.", RecordType::TXT),
            ("b.example.", RecordType::A),
            ("example.", RecordType::TXT),
        ] {
            let reply = ask(data, qname, qtype);
            assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
            assert!(reply.answers.is_empty(), "{qname} {qtype}");
            assert_eq!(
                validator.denial(qname, qtype, &reply),
                Validation::Secure,
                "{qname} {qtype}"
            );
        }

        for qname in ["nope.example.", "deep.er.nope.example.", "\\000.example."] {
            let reply = ask(data, qname, RecordType::A);
            assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
            assert_eq!(
                validator.denial(qname, RecordType::A, &reply),
                expected.nxdomain,
                "{qname}"
            );
            // Every denial record is needed: without any one of them the
            // proof fails.
            let authority = sets(&reply.authorities);
            for left_out in authority
                .iter()
                .filter(|set| matches!(set.record_type(), RecordType::NSEC | RecordType::NSEC3))
            {
                let mut short = reply.clone();
                short.authorities = authority
                    .iter()
                    .filter(|set| *set != left_out)
                    .flat_map(|set| set.records_with_rrsigs().cloned())
                    .collect();
                assert!(
                    matches!(
                        validator.denial(qname, RecordType::A, &short),
                        Validation::Bogus(_)
                    ),
                    "{qname} without {}",
                    left_out.name()
                );
            }
        }

        let wild = ask(data, "host.wild.example.", RecordType::A);
        assert_eq!(
            validator.rrset(&only(&wild), &sets(&wild.authorities)),
            expected.wildcard
        );
        let wild_nodata = ask(data, "host.wild.example.", RecordType::TXT);
        assert!(wild_nodata.answers.is_empty());
        assert_eq!(
            validator.denial("host.wild.example.", RecordType::TXT, &wild_nodata),
            expected.wildcard
        );

        // A referral with DS: the DS validates, and through it the child.
        let (child, child_keys) = secure_child();
        let referral = ask(data, "www.secure.example.", RecordType::A);
        assert!(!referral.metadata.authoritative);
        let authority = sets(&referral.authorities);
        let ds = authority
            .iter()
            .find(|set| set.record_type() == RecordType::DS)
            .expect("a DS RRset in the referral")
            .clone();
        assert_eq!(validator.rrset(&ds, &[]), Validation::Secure);
        let child_dnskey = only(&ask(&child, "secure.example.", RecordType::DNSKEY));
        let mut chain = validator.chain.clone();
        chain.links.push(Link {
            zone: name("secure.example."),
            ds: Fetched::Answer(ds),
            dnskey: Fetched::Answer(child_dnskey),
        });
        let through = Validator {
            anchors: Anchors::of(vec![keys(10).anchor(&name("example."))]),
            chain,
        };
        let child_www = ask(&child, "www.secure.example.", RecordType::A);
        assert_eq!(through.rrset(&only(&child_www), &[]), Validation::Secure);
        assert_ne!(
            child_keys.anchor(&name("secure.example.")),
            keys(10).anchor(&name("example."))
        );

        // A referral without DS: the parent proves there is none, and the
        // unsigned child is Insecure.
        let referral = ask(data, "www.plain.example.", RecordType::A);
        assert!(!referral.metadata.authoritative);
        assert!(
            sets(&referral.authorities)
                .iter()
                .all(|set| set.record_type() != RecordType::DS)
        );
        assert_eq!(
            validator.denial("plain.example.", RecordType::DS, &referral),
            expected.plain_ds
        );
        let plain = builder("plain.example.")
            .rrset(rrset("www.plain.example.", vec![a(40)]))
            .build()
            .unwrap();
        let mut chain = validator.chain.clone();
        chain.links.push(Link {
            zone: name("plain.example."),
            ds: Fetched::Denied(sets(&referral.authorities)),
            dnskey: Fetched::Failed,
        });
        let through = Validator {
            anchors: Anchors::of(vec![keys(10).anchor(&name("example."))]),
            chain,
        };
        let plain_www = ask(&plain, "www.plain.example.", RecordType::A);
        assert_eq!(through.rrset(&only(&plain_www), &[]), expected.plain);
    }

    fn nsec3(opt_out: bool) -> Denial {
        Denial::Nsec3 {
            opt_out,
            salt: vec![0xab, 0xcd],
        }
    }

    #[test]
    fn a_zone_signed_with_nsec_validates() {
        let zone = parent().signed(&keys(10), window(), Denial::Nsec).unwrap();
        every_answer_validates(&zone, PROVEN);
    }

    #[test]
    fn a_zone_signed_with_nsec3_validates() {
        let zone = parent().signed(&keys(10), window(), nsec3(false)).unwrap();
        every_answer_validates(&zone, PROVEN);
    }

    #[test]
    fn a_zone_signed_with_nsec3_opt_out_validates() {
        let zone = parent().signed(&keys(10), window(), nsec3(true)).unwrap();
        every_answer_validates(
            &zone,
            Expected {
                nxdomain: OPT_OUT,
                wildcard: OPT_OUT,
                plain_ds: OPT_OUT,
                plain: OPT_OUT,
            },
        );
    }

    #[test]
    fn online_signing_with_minimally_covering_nsec_validates() {
        let signed = Signed::new(parent(), keys(10), window(), Denial::Nsec);
        every_answer_validates(&signed, PROVEN);
    }

    #[test]
    fn online_signing_with_nsec3_white_lies_validates() {
        let signed = Signed::new(parent(), keys(10), window(), nsec3(false));
        every_answer_validates(&signed, PROVEN);
    }

    #[test]
    fn online_white_lies_with_opt_out_still_prove_unsigned_delegations() {
        // Each white lie matches the cut itself, so the opt-out flag
        // weakens only the spans that cover a name.
        let signed = Signed::new(parent(), keys(10), window(), nsec3(true));
        every_answer_validates(
            &signed,
            Expected {
                nxdomain: OPT_OUT,
                wildcard: OPT_OUT,
                ..PROVEN
            },
        );
    }

    #[test]
    fn the_key_signing_key_signs_only_the_dnskey_rrset() {
        let keys = keys(10);
        let ksk = key_tag_of(&keys.keys[0]);
        let zsk = key_tag_of(&keys.keys[1]);
        let zone = parent().signed(&keys, window(), Denial::Nsec).unwrap();
        let signers = |reply: &Message| -> Vec<u16> {
            reply
                .answers
                .iter()
                .filter_map(|record| match &record.data {
                    RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => Some(rrsig.input().key_tag),
                    _ => None,
                })
                .collect()
        };
        assert_eq!(
            signers(&ask(&zone, "example.", RecordType::DNSKEY)),
            vec![ksk]
        );
        assert_eq!(
            signers(&ask(&zone, "www.example.", RecordType::A)),
            vec![zsk]
        );

        // Keys of one kind each sign everything.
        let both = KeySet {
            keys: vec![keys.keys[1].clone()],
        };
        let zone = parent().signed(&both, window(), Denial::Nsec).unwrap();
        assert_eq!(
            signers(&ask(&zone, "example.", RecordType::DNSKEY)),
            vec![zsk]
        );
    }

    fn key_tag_of(key: &Arc<dyn Sign>) -> u16 {
        crate::stdlib::protocols::dns::dnssec::key_tag(&key.dnskey())
    }

    #[test]
    fn signing_a_signed_zone_again_gives_the_same_zone() {
        for denial in [Denial::Nsec, nsec3(false), nsec3(true)] {
            let once = parent()
                .signed(&keys(10), window(), denial.clone())
                .unwrap();
            let twice = once.signed(&keys(10), window(), denial.clone()).unwrap();
            assert!(once.nodes().eq(twice.nodes()), "{denial:?}");
            for qname in ["nope.example.", "www.example.", "b.example."] {
                assert_eq!(
                    ask(&once, qname, RecordType::TXT),
                    ask(&twice, qname, RecordType::TXT),
                    "{denial:?} {qname}"
                );
            }
        }
    }

    #[test]
    fn nsec3_zones_carry_their_parameters_at_the_apex() {
        let zone = parent().signed(&keys(10), window(), nsec3(false)).unwrap();
        let reply = ask(&zone, "example.", RecordType::NSEC3PARAM);
        let RData::DNSSEC(DNSSECRData::NSEC3PARAM(param)) = &reply.answers[0].data else {
            panic!("an NSEC3PARAM record");
        };
        assert_eq!((param.iterations(), param.salt()), (0, &[0xab, 0xcd][..]));
        assert_eq!(param.flags(), 0);
    }

    /// A key that counts its signatures.
    struct Counting {
        key: Arc<dyn Sign>,
        count: Arc<AtomicUsize>,
    }

    impl Sign for Counting {
        fn dnskey(&self) -> DNSKEY {
            self.key.dnskey()
        }

        fn sign(&self, tbs: &[u8]) -> Vec<u8> {
            self.count.fetch_add(1, Ordering::SeqCst);
            self.key.sign(tbs)
        }
    }

    #[test]
    fn online_signatures_are_made_once_per_rrset_and_key() {
        let count = Arc::new(AtomicUsize::new(0));
        let counted = |key: Arc<dyn Sign>| -> Arc<dyn Sign> {
            Arc::new(Counting {
                key,
                count: count.clone(),
            })
        };
        let keys = KeySet {
            keys: keys(10).keys.into_iter().map(counted).collect(),
        };
        let signed = Signed::new(parent(), keys, window(), Denial::Nsec);
        let first = ask(&signed, "www.example.", RecordType::A);
        let after_first = count.load(Ordering::SeqCst);
        assert!(after_first > 0);
        assert_eq!(ask(&signed, "www.example.", RecordType::A), first);
        assert_eq!(count.load(Ordering::SeqCst), after_first);

        // A new question signs only what it adds: the SOA and the apex are
        // kept, and the NSEC at www is new, signed by the zone-signing key.
        ask(&signed, "www.example.", RecordType::TXT);
        assert_eq!(count.load(Ordering::SeqCst), after_first + 1);
    }
}
