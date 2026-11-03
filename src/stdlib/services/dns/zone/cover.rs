//! Denial records made for one question: minimally covering NSEC records
//! (RFC 4470) and NSEC3 white lies (RFC 7129 Appendix B).
//!
//! A zone that grows as names are asked cannot hold a chain of NSEC or
//! NSEC3 records: a chain made now would let a resolver that reuses denials
//! (RFC 8198) deny a name the zone gains later. Instead each negative
//! answer gets records made for it, which deny only what the question needs
//! denied.
//!
//! A covering record narrows what a proof denies; it never supplies
//! knowledge. [`cover`] reads the facts a denial rests on from the view,
//! and when one of them is unknown the result is unknown, so the answer is
//! SERVFAIL rather than a signed negative.

use fictionet::stdlib::protocols::dns::dnssec::Nsec3HashAlgorithm;
use fictionet::stdlib::protocols::dns::dnssec::proof::base32hex_encode;
use fictionet::stdlib::protocols::dns::dnssec::rdata::{DNSSECRData, NSEC, NSEC3};
use fictionet::stdlib::protocols::dns::label_count;
use fictionet::stdlib::protocols::dns::rr::{
    LowerName, Name, RData, Record, RecordSet, RecordType,
};

use super::data::{Denied, Fact, View};
use super::signed::Denial;
use super::zone::{Node, unique, wildcard};

/// A name takes at most 255 octets on the wire (RFC 1035 §2.3.4).
const MAX_NAME: usize = 255;
/// A label takes at most 63 octets (RFC 1035 §2.3.4).
const MAX_LABEL: usize = 63;

/// The NSEC or NSEC3 records, without RRSIGs, that prove `kind` at `name`
/// in the zone `view` shows, made for this one denial.
///
/// With [`Denial::Nsec`] the records are minimally covering NSEC records
/// (RFC 4470 §3). A name that does not exist is denied by an NSEC whose
/// owner is the name just before its next closer name in canonical order
/// and whose next name is the first name after everything at or below the
/// next closer name, so the record covers that name and its descendants
/// and nothing else. The wildcard at the closest encloser is denied the
/// same way. A name that exists gets an NSEC at its own name, with its own
/// types and `\000.<name>` as the next name.
///
/// With [`Denial::Nsec3`] the records are NSEC3 white lies (RFC 7129
/// Appendix B), with zero iterations (RFC 9276 §3.1): a name is matched by
/// an NSEC3 at its hash whose next hash is one more, and covered by an
/// NSEC3 from one less than its hash to one more, so each covers a single
/// hash. Each record has the opt-out flag the denial asks for.
///
/// `Unknown` when a fact the denial rests on is unknown: the node at the
/// name or at a name on the way to it from the apex, or the wildcard at
/// the closest encloser. `Absent` when no records can prove `kind` here:
/// the name exists and `kind` says it does not, it has the type `kind`
/// denies, the wildcard `kind` relies on is missing, or the name lies
/// outside the zone or below a zone cut or a DNAME.
///
/// The type bitmaps come from the view's nodes, so a view of a signed zone
/// gives bitmaps with DNSKEY at the apex. Every record has the negative TTL
/// of RFC 9077: the lesser of the SOA's TTL and its MINIMUM field.
pub fn cover(
    view: &dyn View,
    name: &LowerName,
    kind: Denied,
    denial: &Denial,
) -> Fact<Vec<RecordSet>> {
    let apex = Name::from(view.apex());
    let ttl = negative_ttl(view.soa());
    let spans = Spans { apex: &apex, ttl };
    let sets = match kind {
        Denied::Name => {
            let (encloser, encloser_node, next_closer) = match place(view, name) {
                Fact::Present(Place::Absent {
                    encloser,
                    encloser_node,
                    next_closer,
                }) => (encloser, encloser_node, next_closer),
                Fact::Present(Place::Node(_)) | Fact::Absent => return Fact::Absent,
                Fact::Unknown => return Fact::Unknown,
            };
            let wild = wildcard(&encloser);
            match view.node(&wild) {
                Fact::Absent => {}
                Fact::Present(_) => return Fact::Absent,
                Fact::Unknown => return Fact::Unknown,
            }
            match denial {
                Denial::Nsec => vec![
                    spans.covering(&next_closer, &encloser, encloser_node),
                    spans.covering(&wild, &encloser, encloser_node),
                ],
                Denial::Nsec3 { opt_out, salt } => {
                    let lies = WhiteLies::new(&apex, ttl, *opt_out, salt);
                    vec![
                        lies.matching(&encloser, encloser_node),
                        lies.covering(&next_closer),
                        lies.covering(&wild),
                    ]
                }
            }
        }
        Denied::Type(rtype) => {
            let node = match place(view, name) {
                Fact::Present(Place::Node(node)) => node,
                Fact::Present(Place::Absent { .. }) | Fact::Absent => return Fact::Absent,
                Fact::Unknown => return Fact::Unknown,
            };
            if !lacks(node, rtype) {
                return Fact::Absent;
            }
            match denial {
                Denial::Nsec => vec![spans.matching(name, node)],
                Denial::Nsec3 { opt_out, salt } => {
                    let lies = WhiteLies::new(&apex, ttl, *opt_out, salt);
                    let mut sets = vec![lies.matching(name, node)];
                    // A wildcard's NODATA also needs its closest encloser
                    // matched (RFC 5155 §7.2.5).
                    if name.is_wildcard() {
                        let encloser = name.base_name();
                        match place(view, &encloser) {
                            Fact::Present(Place::Node(node)) => {
                                sets.push(lies.matching(&encloser, node));
                            }
                            Fact::Present(Place::Absent { .. }) | Fact::Absent => {
                                return Fact::Absent;
                            }
                            Fact::Unknown => return Fact::Unknown,
                        }
                    }
                    sets
                }
            }
        }
        Denied::Wildcard { closest_encloser } => {
            let (encloser, encloser_node, next_closer) = match place(view, name) {
                Fact::Present(Place::Absent {
                    encloser,
                    encloser_node,
                    next_closer,
                }) if encloser == closest_encloser => (encloser, encloser_node, next_closer),
                Fact::Present(_) | Fact::Absent => return Fact::Absent,
                Fact::Unknown => return Fact::Unknown,
            };
            match view.node(&wildcard(&encloser)) {
                Fact::Present(_) => {}
                Fact::Absent => return Fact::Absent,
                Fact::Unknown => return Fact::Unknown,
            }
            match denial {
                Denial::Nsec => vec![spans.covering(&next_closer, &encloser, encloser_node)],
                Denial::Nsec3 { opt_out, salt } => {
                    vec![WhiteLies::new(&apex, ttl, *opt_out, salt).covering(&next_closer)]
                }
            }
        }
    };
    Fact::Present(unique(sets.into_iter()))
}

/// Where the walk from the apex toward a name ends.
enum Place<'v> {
    /// The name exists, with this node.
    Node(&'v Node),
    /// The name does not exist. `encloser` is its closest encloser and
    /// `next_closer` the absent name one label below it on the way to the
    /// name (RFC 5155 §1.3), which is the name itself or an ancestor.
    Absent {
        encloser: LowerName,
        encloser_node: &'v Node,
        next_closer: LowerName,
    },
}

/// Walks from the apex down to `name`, reading each node, as the answer
/// does. `Absent` when the name is outside the zone or below a zone cut or
/// a DNAME, where this zone denies nothing.
fn place<'v>(view: &'v dyn View, name: &LowerName) -> Fact<Place<'v>> {
    let apex = view.apex();
    if !apex.zone_of(name) {
        return Fact::Absent;
    }
    let mut path = vec![name.clone()];
    while path.last() != Some(apex) {
        let parent = path.last().expect("not empty").base_name();
        path.push(parent);
    }
    path.reverse();

    let mut names = path.into_iter();
    let mut at = names.next().expect("the apex");
    let mut node = match view.node(&at) {
        Fact::Present(node) => node,
        Fact::Absent => return Fact::Absent,
        Fact::Unknown => return Fact::Unknown,
    };
    for next in names {
        if matches!(node, Node::Cut { .. } | Node::Dname(..)) {
            return Fact::Absent;
        }
        match view.node(&next) {
            Fact::Present(child) => {
                at = next;
                node = child;
            }
            Fact::Absent => {
                return Fact::Present(Place::Absent {
                    encloser: at,
                    encloser_node: node,
                    next_closer: next,
                });
            }
            Fact::Unknown => return Fact::Unknown,
        }
    }
    Fact::Present(Place::Node(node))
}

/// Whether `node` has no RRset of `rtype` that a denial could deny. At a
/// zone cut only the parent's side can be denied: DS (RFC 6840 §4.1), and
/// NSEC, which no node holds (RFC 4035 §2.6).
fn lacks(node: &Node, rtype: RecordType) -> bool {
    match node {
        Node::Data(sets) => !sets.contains_key(&rtype),
        Node::Dname(_, sets) => rtype != RecordType::DNAME && !sets.contains_key(&rtype),
        Node::Cut { ds, .. } => {
            rtype == RecordType::NSEC || (rtype == RecordType::DS && ds.is_none())
        }
        Node::Empty => true,
    }
}

/// The types at `node` that its NSEC or NSEC3 bitmap lists, leaving out
/// the denial and signature types, and whether the node holds RRsets a
/// signed zone signs: every RRset of a data node, and a cut's DS.
pub(super) fn node_types(node: &Node) -> (Vec<RecordType>, bool) {
    let denial = |rtype: &RecordType| {
        !matches!(
            *rtype,
            RecordType::NSEC | RecordType::NSEC3 | RecordType::RRSIG
        )
    };
    match node {
        Node::Data(sets) => {
            let types: Vec<RecordType> = sets.keys().copied().filter(denial).collect();
            let signed = !types.is_empty();
            (types, signed)
        }
        Node::Dname(_, sets) => {
            let types = std::iter::once(RecordType::DNAME)
                .chain(sets.keys().copied().filter(denial))
                .collect();
            (types, true)
        }
        Node::Cut { ds, .. } => {
            let mut types = vec![RecordType::NS];
            types.extend(ds.as_ref().map(|_| RecordType::DS));
            (types, ds.is_some())
        }
        Node::Empty => (Vec::new(), false),
    }
}

/// The TTL of denial records: the lesser of the SOA RRset's TTL and its
/// MINIMUM field (RFC 9077 §3, updating RFC 4035 §2.3 and RFC 5155 §3).
pub(crate) fn negative_ttl(soa: &RecordSet) -> u32 {
    let minimum = soa
        .records_without_rrsigs()
        .find_map(|record| match &record.data {
            RData::SOA(soa) => Some(soa.minimum),
            _ => None,
        });
    minimum.map_or(soa.ttl(), |minimum| soa.ttl().min(minimum))
}

/// Makes minimally covering NSEC records for one zone (RFC 4470 §3).
struct Spans<'a> {
    apex: &'a Name,
    ttl: u32,
}

impl Spans<'_> {
    /// An NSEC at the existing `name`, with its own types and the next name
    /// just after it.
    fn matching(&self, name: &LowerName, node: &Node) -> RecordSet {
        let name = Name::from(name);
        let next = successor(&name, self.apex);
        nsec_set(&name, next, &node_types(node).0, self.ttl)
    }

    /// An NSEC covering exactly `next_closer`, which does not exist, and
    /// the names below it. Its owner is the name just before
    /// `next_closer`; when that is the closest `encloser`, an existing
    /// name, the record lists the encloser's own types.
    fn covering(
        &self,
        next_closer: &LowerName,
        encloser: &LowerName,
        encloser_node: &Node,
    ) -> RecordSet {
        let next_closer = Name::from(next_closer);
        let encloser = Name::from(encloser);
        let owner = predecessor(&next_closer, &encloser);
        let next = after_subtree(&next_closer, self.apex);
        // RFC 4470 §3: a made-up owner lists only NSEC and RRSIG.
        let types = if owner == encloser {
            node_types(encloser_node).0
        } else {
            Vec::new()
        };
        nsec_set(&owner, next, &types, self.ttl)
    }
}

/// Makes NSEC3 white lies for one zone (RFC 7129 Appendix B).
struct WhiteLies<'a> {
    apex: &'a Name,
    ttl: u32,
    opt_out: bool,
    salt: &'a [u8],
}

impl<'a> WhiteLies<'a> {
    fn new(apex: &'a Name, ttl: u32, opt_out: bool, salt: &'a [u8]) -> WhiteLies<'a> {
        WhiteLies {
            apex,
            ttl,
            opt_out,
            salt,
        }
    }

    /// An NSEC3 matching the existing `name`, with its own types, whose
    /// next hash is one more than the name's.
    fn matching(&self, name: &LowerName, node: &Node) -> RecordSet {
        let hash = nsec3_hash(&Name::from(name), self.salt);
        let (types, signed) = node_types(node);
        self.nsec3(&hash, step(&hash, true), &types, signed)
    }

    /// An NSEC3 covering only the hash of `name`: from one less to one
    /// more. Its bitmap is empty.
    fn covering(&self, name: &LowerName) -> RecordSet {
        let hash = nsec3_hash(&Name::from(name), self.salt);
        self.nsec3(&step(&hash, false), step(&hash, true), &[], false)
    }

    fn nsec3(&self, owner: &[u8], next: Vec<u8>, types: &[RecordType], signed: bool) -> RecordSet {
        let params = Nsec3Params {
            opt_out: self.opt_out,
            salt: self.salt,
            ttl: self.ttl,
        };
        nsec3_set(self.apex, owner, next, types, signed, &params)
    }
}

/// What every NSEC3 record of one zone shares.
pub(super) struct Nsec3Params<'a> {
    /// Whether the opt-out flag is set (RFC 5155 §3.1.2.1).
    pub opt_out: bool,
    /// The salt (RFC 5155 §3.1.5).
    pub salt: &'a [u8],
    /// The records' TTL.
    pub ttl: u32,
}

/// An NSEC RRset at `owner` pointing at `next`, listing `types` and the
/// NSEC and RRSIG types that every NSEC's owner holds (RFC 4034 §4.1.2).
pub(super) fn nsec_set(owner: &Name, next: Name, types: &[RecordType], ttl: u32) -> RecordSet {
    let rdata = NSEC::new_cover_self(next, types.iter().copied());
    one_record(owner, RData::DNSSEC(DNSSECRData::NSEC(rdata)), ttl)
}

/// An NSEC3 RRset for the hash `owner` under `apex` pointing at the hash
/// `next`, listing `types`, and RRSIG when the original owner holds
/// signed RRsets (RFC 5155 §3.2.1). Iterations are always 0
/// (RFC 9276 §3.1).
pub(super) fn nsec3_set(
    apex: &Name,
    owner: &[u8],
    next: Vec<u8>,
    types: &[RecordType],
    signed: bool,
    params: &Nsec3Params<'_>,
) -> RecordSet {
    let types = types
        .iter()
        .copied()
        .chain(signed.then_some(RecordType::RRSIG));
    let rdata = NSEC3::new(
        Nsec3HashAlgorithm::SHA1,
        params.opt_out,
        0,
        params.salt.to_vec(),
        next,
        types,
    );
    let owner = hashed_owner(owner, apex);
    one_record(&owner, RData::DNSSEC(DNSSECRData::NSEC3(rdata)), params.ttl)
}

/// The owner of the NSEC3 record for `hash` in the zone at `apex`: the
/// hash in base32hex as one label under the apex (RFC 5155 §3.3).
pub(super) fn hashed_owner(hash: &[u8], apex: &Name) -> Name {
    Name::from_labels([base32hex_encode(hash).as_bytes()])
        .and_then(|label| label.append_domain(apex))
        .expect("a hash label fits under the apex")
}

/// The NSEC3 hash of `name` with `salt` and zero iterations (RFC 5155 §5,
/// RFC 9276 §3.1).
pub(super) fn nsec3_hash(name: &Name, salt: &[u8]) -> Vec<u8> {
    Nsec3HashAlgorithm::SHA1
        .hash(salt, name, 0)
        .expect("a name always encodes")
        .as_ref()
        .to_vec()
}

fn one_record(owner: &Name, rdata: RData, ttl: u32) -> RecordSet {
    let mut set = RecordSet::with_ttl(owner.clone(), rdata.record_type(), ttl);
    set.set_records(vec![Record::from_rdata(owner.clone(), ttl, rdata)]);
    set
}

/// `hash` plus or minus one, as a number of its length, wrapping around.
fn step(hash: &[u8], up: bool) -> Vec<u8> {
    let mut out = hash.to_vec();
    for byte in out.iter_mut().rev() {
        let (value, carry) = if up {
            byte.overflowing_add(1)
        } else {
            byte.overflowing_sub(1)
        };
        *byte = value;
        if !carry {
            break;
        }
    }
    out
}

/// The octets `name` takes on the wire, uncompressed.
fn wire_len(name: &Name) -> usize {
    name.iter().map(|label| label.len() + 1).sum::<usize>() + 1
}

/// The leftmost label of `name` in lowercase.
fn first_label(name: &Name) -> Vec<u8> {
    name.iter()
        .next()
        .expect("a name below the apex has a label")
        .to_ascii_lowercase()
}

fn below(parent: &Name, label: &[u8]) -> Name {
    parent
        .prepend_label(label)
        .expect("the label fits the name's length")
}

/// The first name after `name` in canonical order (RFC 4034 §6.1):
/// `\000.<name>`, or when that would be too long, and so nothing can be
/// below `name`, the first name after `name`'s subtree.
fn successor(name: &Name, apex: &Name) -> Name {
    if wire_len(name) + 2 <= MAX_NAME {
        below(name, &[0])
    } else {
        after_subtree(name, apex)
    }
}

/// The first name after every name at or below `name`, in canonical order:
/// the next label at the same depth, or at a shallower one when `name`'s
/// label has no successor. Past the zone's last name it wraps to the apex,
/// as the last NSEC of a chain does (RFC 4034 §4.1.1).
fn after_subtree(name: &Name, apex: &Name) -> Name {
    let mut name = name.clone();
    while label_count(&name) > label_count(apex) {
        let parent = name.base_name();
        let room = (MAX_NAME - wire_len(&parent) - 1).min(MAX_LABEL);
        if let Some(next) = next_label(&first_label(&name), room) {
            return below(&parent, &next);
        }
        name = parent;
    }
    apex.clone()
}

/// The first label after `label` in canonical order among labels of at
/// most `max` octets: `label` with a zero octet added, or with its trailing
/// 0xff octets dropped and its last octet raised by one. `None` when every
/// octet is 0xff. Octets compare as lowercase, so a raised octet skips the
/// uppercase letters, which sort as their lowercase forms.
fn next_label(label: &[u8], max: usize) -> Option<Vec<u8>> {
    let mut next = label.to_vec();
    if next.len() < max {
        next.push(0);
        return Some(next);
    }
    while next.last() == Some(&0xff) {
        next.pop();
    }
    let last = next.last_mut()?;
    *last += 1;
    if last.is_ascii_uppercase() {
        *last = b'Z' + 1;
    }
    Some(next)
}

/// The name just before `next_closer`, a child of `encloser`, in canonical
/// order. Every name between the two would be `next_closer`'s earlier
/// sibling or below it, so this is the last name at or below the label
/// just before `next_closer`'s: its last octet lowered by one and padded
/// with 0xff octets to the longest label, then 0xff labels down to the
/// longest name (RFC 4470 §4). A label ending in a zero octet has the same
/// label without it just before it; for the label `\000` alone, that is
/// `encloser` itself.
fn predecessor(next_closer: &Name, encloser: &Name) -> Name {
    let mut label = first_label(next_closer);
    let room = (MAX_NAME - wire_len(encloser) - 1).min(MAX_LABEL);
    if label.last() == Some(&0) {
        label.pop();
        if label.is_empty() {
            return encloser.clone();
        }
    } else {
        let last = label.last_mut().expect("labels are not empty");
        *last -= 1;
        if last.is_ascii_uppercase() {
            *last = b'A' - 1;
        }
        label.resize(room, 0xff);
    }
    last_below(below(encloser, &label))
}

/// The last name at or below `name` in canonical order: `name` with the
/// longest 0xff labels added until no more fit.
fn last_below(mut name: Name) -> Name {
    loop {
        let room = MAX_NAME - wire_len(&name);
        if room < 2 {
            return name;
        }
        let length = (room - 1).min(MAX_LABEL);
        name = below(&name, &vec![0xff; length]);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::stdlib::protocols::dns::dnssec::Validation;
    use crate::stdlib::protocols::dns::dnssec::proof::{self, Proof};
    use crate::stdlib::protocols::dns::op::ResponseCode;
    use crate::stdlib::protocols::dns::rr::rdata::SOA;
    use crate::stdlib::services::dns::zone::signed::tests::{
        Validator, a, ask, keys, lower, name, ns, parent, rrset, sets, window,
    };
    use crate::stdlib::services::dns::zone::{Lazy, Revision, Signed, Zone};

    fn nsec3() -> Denial {
        Denial::Nsec3 {
            opt_out: false,
            salt: Vec::new(),
        }
    }

    #[test]
    fn a_white_lie_never_covers_a_name_the_zone_holds_later() {
        for denial in [Denial::Nsec, nsec3()] {
            let held: Arc<Mutex<BTreeMap<LowerName, Vec<RecordSet>>>> = Arc::default();
            let provider = {
                let held = held.clone();
                move |name: &LowerName| match held.lock().unwrap().get(name) {
                    Some(sets) => Fact::Present(sets.clone()),
                    None => Fact::Absent,
                }
            };
            let apex = "grow.example.";
            let soa = SOA::new(
                name("ns1.grow.example."),
                name("hostmaster.grow.example."),
                1,
                7200,
                3600,
                1209600,
                300,
            );
            let lazy = Lazy::new(
                name(apex),
                soa,
                rrset(apex, vec![ns("ns1.grow.example.")]),
                3600,
                provider,
            );
            let signed = Signed::new(lazy, keys(30), window(), denial.clone());
            let validator = Validator::new(&signed, apex, &keys(30));

            let reply = ask(&signed, "b.grow.example.", RecordType::A);
            assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
            assert_eq!(
                validator.denial("b.grow.example.", RecordType::A, &reply),
                Validation::Secure,
                "{denial:?}"
            );
            let lies = sets(&reply.authorities);

            // Names on either side of the denied one, close to it in
            // canonical order, and many others. Names below the denied one
            // are left out: its NXDOMAIN denies them too (RFC 8020).
            let mut later: Vec<String> = [
                "a",
                "c",
                "ba",
                "b\\000",
                "a\\255",
                "\\041\\255",
                "*a",
                "+",
                "x.a",
            ]
            .iter()
            .map(|label| format!("{label}.grow.example."))
            .collect();
            later.extend((0..64).map(|n| format!("n{n}.grow.example.")));
            for added in &later {
                held.lock()
                    .unwrap()
                    .insert(lower(added), vec![rrset(added, vec![a(5)])]);
                let reply = ask(&signed, added, RecordType::A);
                assert_eq!(
                    reply.answers.len(),
                    2,
                    "{added}: the A record and its RRSIG"
                );
                let added = name(added);
                let apex = name(apex);
                assert_eq!(
                    proof::nxdomain(&added, &apex, &lies, 0),
                    Proof::Unproven,
                    "{denial:?} {added}"
                );
                assert_eq!(
                    proof::nodata(&added, RecordType::A, &apex, &lies, 0),
                    Proof::Unproven,
                    "{denial:?} {added}"
                );
            }
        }
    }

    /// A zone's view with one name's fact unknown.
    struct Hiding {
        zone: Zone,
        hidden: LowerName,
    }

    impl View for Hiding {
        fn apex(&self) -> &LowerName {
            View::apex(&self.zone)
        }

        fn revision(&self) -> Revision {
            View::revision(&self.zone)
        }

        fn soa(&self) -> &RecordSet {
            self.zone.soa()
        }

        fn node(&self, name: &LowerName) -> Fact<&Node> {
            if *name == self.hidden {
                return Fact::Unknown;
            }
            View::node(&self.zone, name)
        }

        fn denial(&self, name: &LowerName, kind: Denied) -> Fact<Vec<RecordSet>> {
            self.zone.denial(name, kind)
        }
    }

    #[test]
    fn an_unknown_fact_gives_an_unknown_cover() {
        let wildcard = |encloser: &str| Denied::Wildcard {
            closest_encloser: lower(encloser),
        };
        let cases = [
            // The wildcard at the closest encloser.
            ("*.example.", "nope.example.", Denied::Name),
            // The next closer name.
            ("nope.example.", "deep.nope.example.", Denied::Name),
            // An empty non-terminal on the way.
            ("b.example.", "x.b.example.", Denied::Name),
            // The name itself.
            (
                "www.example.",
                "www.example.",
                Denied::Type(RecordType::TXT),
            ),
            // The wildcard that answered, and its closest encloser.
            (
                "*.wild.example.",
                "host.wild.example.",
                wildcard("wild.example."),
            ),
            (
                "wild.example.",
                "host.wild.example.",
                wildcard("wild.example."),
            ),
            (
                "wild.example.",
                "*.wild.example.",
                Denied::Type(RecordType::TXT),
            ),
        ];
        for denial in [Denial::Nsec, nsec3()] {
            for (hidden, qname, kind) in cases.clone() {
                let zone = parent();
                let known = cover(&zone, &lower(qname), kind.clone(), &denial);
                assert!(
                    matches!(&known, Fact::Present(sets) if !sets.is_empty()),
                    "{denial:?} {qname} {kind:?}: {known:?}"
                );
                let hiding = Hiding {
                    zone,
                    hidden: lower(hidden),
                };
                assert_eq!(
                    cover(&hiding, &lower(qname), kind.clone(), &denial),
                    Fact::Unknown,
                    "{denial:?} {qname} {kind:?} with {hidden} unknown"
                );
            }
        }
    }

    #[test]
    fn a_claim_the_zone_contradicts_has_no_cover() {
        let zone = parent();
        for denial in [Denial::Nsec, nsec3()] {
            let cases = [
                ("www.example.", Denied::Type(RecordType::A)),
                ("www.example.", Denied::Name),
                ("nope.example.", Denied::Type(RecordType::A)),
                // No wildcard at the apex answers.
                (
                    "nope.example.",
                    Denied::Wildcard {
                        closest_encloser: lower("example."),
                    },
                ),
                // A signed delegation has its DS, and the parent denies
                // nothing else there or below.
                ("secure.example.", Denied::Type(RecordType::DS)),
                ("plain.example.", Denied::Type(RecordType::A)),
                ("x.plain.example.", Denied::Name),
                ("www.elsewhere.", Denied::Name),
            ];
            for (qname, kind) in cases {
                assert_eq!(
                    cover(&zone, &lower(qname), kind.clone(), &denial),
                    Fact::Absent,
                    "{denial:?} {qname} {kind:?}"
                );
            }
        }
    }

    #[test]
    fn neighbours_sort_just_around_the_name() {
        let apex = name("example.");
        let nc = name("b.example.");
        let before = predecessor(&nc, &apex);
        let after = after_subtree(&nc, &apex);
        assert!(before < nc && nc < after);
        assert_eq!(wire_len(&before), MAX_NAME);
        assert_eq!(after, below(&apex, b"b\0"));
        // A wildcard's neighbours too, though hickory's label count leaves
        // out its `*`.
        let wild = name("*.example.");
        assert_eq!(after_subtree(&wild, &apex), below(&apex, b"*\0"));
        assert!(predecessor(&wild, &apex) < wild);
        // Everything below the name lies inside the span; the siblings on
        // either side lie outside it.
        for inside in ["x.b.example.", "\\255.b.example."] {
            let inside = name(inside);
            assert!(before < inside && inside < after, "{inside}");
        }
        for outside in ["a.example.", "c.example.", "ba.example.", "a\\255.example."] {
            let outside = name(outside);
            assert!(!(before < outside && outside < after), "{outside}");
        }
    }

    #[test]
    fn labels_ending_in_zero_and_full_labels() {
        let apex = name("example.");
        assert_eq!(predecessor(&below(&apex, &[0]), &apex), apex);
        let before = predecessor(&below(&apex, b"a\0"), &apex);
        assert!(name("a.example.").zone_of(&before));

        let full = below(&apex, &[0xff; 63]);
        assert_eq!(after_subtree(&full, &apex), apex);
        let almost = below(&apex, &[b'a'; 63]);
        assert_eq!(
            after_subtree(&almost, &apex),
            below(&apex, &[[b'a'; 62].as_slice(), b"b"].concat())
        );
        // Raising '@' would give 'A', which sorts as 'a'; '[' comes next.
        assert_eq!(next_label(b"@", 1), Some(b"[".to_vec()));
        assert_eq!(step(&[0, 0xff], true), vec![1, 0]);
        assert_eq!(step(&[0, 0], false), vec![0xff, 0xff]);
    }
}
