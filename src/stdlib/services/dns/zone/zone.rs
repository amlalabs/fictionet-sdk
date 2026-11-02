//! Complete zones: every fact present or known absent, checked against
//! the rules of the DNS standards when they are built.

// A zone error names the owners it is about. It comes once per build,
// never on a path that answers questions, so its size costs nothing.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use fictionet::stdlib::protocols::dns::dnssec::Nsec3HashAlgorithm;
use fictionet::stdlib::protocols::dns::dnssec::rdata::DNSSECRData;
use fictionet::stdlib::protocols::dns::op::Query;
use fictionet::stdlib::protocols::dns::rr::rdata::{NULL, SOA};
use fictionet::stdlib::protocols::dns::rr::{
    LowerName, Name, RData, Record, RecordSet, RecordType,
};
use fictionet::stdlib::protocols::dns::serialize::binary::{BinDecodable, BinDecoder};

use super::cover::hashed_owner;
use super::data::{Denied, Fact, Revision, View, ZoneData};
use super::master::MasterError;

/// A zone whose data is all known: what it holds is present, and
/// everything else under its apex is known absent.
///
/// A `Zone` is an immutable value, cheap to clone. [`with`](Zone::with)
/// and [`with_delegation`](Zone::with_delegation) return a new zone at the
/// next revision and leave this one as it was. Every way of making a zone
/// checks the same rules, the ones [`ZoneError`] lists.
///
/// NS RRsets below the apex are zone cuts. A and AAAA RRsets at or below a
/// cut are its glue, and a DS RRset at a cut is the cut's, all as in a master
/// file (RFC 1034 §4.2.1). NSEC and NSEC3 RRsets, with the RRSIGs in each
/// RRset, are what [`View::denial`] reads in a signed zone.
#[derive(Clone, Debug)]
pub struct Zone {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    apex: LowerName,
    soa: RecordSet,
    nodes: BTreeMap<LowerName, Node>,
    /// NSEC RRsets by owner, including those at zone cuts, which hold no
    /// data node of their own.
    nsec: BTreeMap<LowerName, RecordSet>,
    /// NSEC3 RRsets by their hashed owner. Hashed owners are not nodes.
    nsec3: BTreeMap<LowerName, RecordSet>,
    revision: Revision,
}

/// What a zone holds at one name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    /// Authoritative RRsets, one per type.
    Data(BTreeMap<RecordType, RecordSet>),
    /// A zone cut: the child's NS RRset, its DS RRset if the child is
    /// signed, and the address RRsets the parent holds at or below the cut
    /// as glue.
    Cut {
        /// The NS RRset at the cut.
        ns: RecordSet,
        /// The DS RRset at the cut, which the parent serves.
        ds: Option<RecordSet>,
        /// A and AAAA RRsets at or below the cut.
        glue: Vec<RecordSet>,
    },
    /// A DNAME (RFC 6672) and the other RRsets at its owner.
    Dname(RecordSet, BTreeMap<RecordType, RecordSet>),
    /// An empty non-terminal: nothing here, but names below (RFC 8020).
    Empty,
}

impl Node {
    /// The RRsets an answer at this node reads: a DNAME first, then the
    /// rest in type order. A cut gives its NS and DS RRsets.
    pub fn rrsets(&self) -> Vec<&RecordSet> {
        match self {
            Node::Data(sets) => sets.values().collect(),
            Node::Dname(dname, sets) => std::iter::once(dname).chain(sets.values()).collect(),
            Node::Cut { ns, ds, .. } => std::iter::once(ns).chain(ds).collect(),
            Node::Empty => Vec::new(),
        }
    }
}

/// Collects RRsets and delegations, then checks them into a [`Zone`].
#[derive(Clone, Debug)]
pub struct ZoneBuilder {
    apex: Name,
    soa: RecordSet,
    sets: Vec<RecordSet>,
    delegations: Vec<Delegation>,
}

#[derive(Clone, Debug)]
struct Delegation {
    child: Name,
    ns: RecordSet,
    glue: Vec<RecordSet>,
    ds: Option<RecordSet>,
}

/// Why a zone could not be built. Each rule comes from the standard named
/// on its variant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZoneError {
    /// An RRset whose owner is not at or below the apex, or a delegation
    /// that is not strictly below it (RFC 1034 §4.2).
    OutOfZone {
        /// The owner, or the delegated child.
        owner: LowerName,
    },
    /// A CNAME beside other data at its owner, or more than one CNAME
    /// record there (RFC 1034 §3.6.2, RFC 2181 §10.1). NSEC and RRSIG
    /// records may share its owner (RFC 4035 §2.5).
    CnameWithOtherData {
        /// The CNAME's owner.
        owner: LowerName,
    },
    /// A CNAME at the apex, where the SOA and NS RRsets must be
    /// (RFC 1912 §2.4).
    CnameAtApex,
    /// Data or a delegation below a DNAME's owner (RFC 6672 §2.4).
    DataBelowDname {
        /// The owner below the DNAME.
        owner: LowerName,
    },
    /// Data other than glue at or below a zone cut, or a cut below another
    /// cut. Only the child zone holds data there (RFC 1034 §4.2.1).
    DataBelowCut {
        /// The owner, or the deeper cut.
        owner: LowerName,
        /// The cut it is below.
        cut: LowerName,
    },
    /// An NS target at or below its own cut with no address in the glue,
    /// so the delegation cannot be followed (RFC 9471 §3.1).
    MissingInDomainGlue {
        /// The delegated child.
        child: LowerName,
        /// The NS target without glue.
        ns: LowerName,
    },
    /// An NS, MX, or SRV target that is a CNAME's owner (RFC 2181 §10.3).
    TargetIsAlias {
        /// The owner of the record that names the target.
        owner: LowerName,
        /// The target.
        target: LowerName,
    },
    /// Records of one RRset with different TTLs (RFC 2181 §5.2).
    RrsetTtlsDiffer {
        /// The RRset's owner.
        owner: LowerName,
        /// The RRset's type.
        rtype: RecordType,
    },
    /// A TTL of 2^31 seconds or more (RFC 2181 §8).
    TtlTooLarge {
        /// The record's owner.
        owner: LowerName,
        /// The TTL.
        ttl: u32,
    },
    /// No NS RRset at the apex (RFC 1034 §4.2.1).
    MissingApexNs,
    /// A master file that does not read (RFC 1035 §5).
    Master {
        /// The line the fault is on, counted from 1.
        line: usize,
        /// The fault.
        error: MasterError,
    },
}

impl fmt::Display for ZoneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZoneError::OutOfZone { owner } => write!(f, "{owner} is outside the zone"),
            ZoneError::CnameWithOtherData { owner } => {
                write!(f, "the CNAME at {owner} is not alone")
            }
            ZoneError::CnameAtApex => f.write_str("a CNAME is at the apex"),
            ZoneError::DataBelowDname { owner } => write!(f, "{owner} is below a DNAME"),
            ZoneError::DataBelowCut { owner, cut } => {
                write!(f, "{owner} is below the zone cut at {cut}")
            }
            ZoneError::MissingInDomainGlue { child, ns } => {
                write!(f, "the delegation of {child} has no glue for {ns}")
            }
            ZoneError::TargetIsAlias { owner, target } => {
                write!(f, "{owner} names {target}, which is a CNAME")
            }
            ZoneError::RrsetTtlsDiffer { owner, rtype } => {
                write!(f, "the {rtype} records at {owner} have different TTLs")
            }
            ZoneError::TtlTooLarge { owner, ttl } => {
                write!(f, "the TTL {ttl} at {owner} is 2^31 or more")
            }
            ZoneError::MissingApexNs => f.write_str("the apex has no NS RRset"),
            ZoneError::Master { line, error } => write!(f, "line {line}: {error}"),
        }
    }
}

impl std::error::Error for ZoneError {}

/// TTLs must stay below 2^31 seconds (RFC 2181 §8).
const MAX_TTL: u32 = 1 << 31;

impl Zone {
    /// A builder for a zone at `apex` whose SOA record has `soa` and
    /// `ttl`.
    pub fn builder(apex: Name, soa: SOA, ttl: u32) -> ZoneBuilder {
        let mut set = RecordSet::with_ttl(apex.clone(), RecordType::SOA, ttl);
        set.set_records(vec![Record::from_rdata(apex.clone(), ttl, RData::SOA(soa))]);
        ZoneBuilder::with_soa(apex, set)
    }

    /// The zone's apex.
    pub fn apex(&self) -> &LowerName {
        &self.inner.apex
    }

    /// The zone's revision. A built zone is at revision 0, and each
    /// [`with`](Zone::with) or [`with_delegation`](Zone::with_delegation)
    /// adds one.
    pub fn revision(&self) -> Revision {
        self.inner.revision
    }

    /// The node at exactly `name`, empty non-terminals included.
    pub fn node(&self, name: &LowerName) -> Option<&Node> {
        self.inner.nodes.get(name)
    }

    /// Every node, in canonical order (RFC 4034 §6.1).
    pub fn nodes(&self) -> impl Iterator<Item = (&LowerName, &Node)> {
        self.inner.nodes.iter()
    }

    /// A new revision with `set` added. Records already in the zone's
    /// RRset of the same owner and type are kept once (RFC 2181 §5).
    pub fn with(&self, set: RecordSet) -> Result<Zone, ZoneError> {
        self.unbuilt().rrset(set).finish(self.next_revision())
    }

    /// A new revision with a zone cut at `child`: its NS RRset, its glue,
    /// and its DS RRset if the child is signed.
    pub fn with_delegation(
        &self,
        child: Name,
        ns: RecordSet,
        glue: Vec<RecordSet>,
        ds: Option<RecordSet>,
    ) -> Result<Zone, ZoneError> {
        self.unbuilt()
            .delegate(child, ns, glue, ds)
            .finish(self.next_revision())
    }

    fn next_revision(&self) -> Revision {
        Revision(self.inner.revision.0 + 1)
    }

    /// The builder that makes this zone again.
    fn unbuilt(&self) -> ZoneBuilder {
        let inner = &self.inner;
        let mut builder = ZoneBuilder::with_soa(Name::from(&inner.apex), inner.soa.clone());
        for (name, node) in &inner.nodes {
            match node {
                Node::Data(sets) | Node::Dname(_, sets) => {
                    let sets = sets.values().filter(|set| {
                        // The apex SOA is the builder's, and NSEC RRsets
                        // come back from the NSEC index below.
                        !(set.record_type() == RecordType::SOA && *name == inner.apex)
                            && set.record_type() != RecordType::NSEC
                    });
                    builder.sets.extend(sets.cloned());
                    if let Node::Dname(dname, _) = node {
                        builder.sets.push(dname.clone());
                    }
                }
                Node::Cut { ns, ds, glue } => builder.delegations.push(Delegation {
                    child: Name::from(name),
                    ns: ns.clone(),
                    glue: glue.clone(),
                    ds: ds.clone(),
                }),
                Node::Empty => {}
            }
        }
        builder.sets.extend(inner.nsec.values().cloned());
        builder.sets.extend(inner.nsec3.values().cloned());
        builder
    }
}

impl ZoneBuilder {
    pub(super) fn with_soa(mut apex: Name, soa: RecordSet) -> ZoneBuilder {
        apex.set_fqdn(true);
        ZoneBuilder {
            apex,
            soa,
            sets: Vec::new(),
            delegations: Vec::new(),
        }
    }

    /// Adds an RRset. An NS RRset below the apex makes a zone cut, an
    /// address RRset at or below a cut is that cut's glue, and a DS RRset
    /// at a cut is the cut's DS. An SOA RRset at the apex replaces the
    /// zone's SOA. Duplicate records collapse to one (RFC 2181 §5).
    pub fn rrset(mut self, set: RecordSet) -> ZoneBuilder {
        self.sets.push(set);
        self
    }

    /// Adds a zone cut at `child`: its NS RRset, the glue for it, and its
    /// DS RRset if the child is signed.
    pub fn delegate(
        mut self,
        child: Name,
        ns: RecordSet,
        glue: Vec<RecordSet>,
        ds: Option<RecordSet>,
    ) -> ZoneBuilder {
        self.delegations.push(Delegation {
            child,
            ns,
            glue,
            ds,
        });
        self
    }

    /// Checks every rule of [`ZoneError`], in the order it lists them
    /// except that a CNAME at the apex is reported before a CNAME beside
    /// other data, and makes the zone.
    pub fn build(self) -> Result<Zone, ZoneError> {
        self.finish(Revision(0))
    }

    fn finish(self, revision: Revision) -> Result<Zone, ZoneError> {
        Ok(Parts::sort(self).check()?.assemble(revision))
    }
}

/// A builder's RRsets sorted into what a zone holds, before the rules are
/// checked.
struct Parts {
    apex: LowerName,
    soa: RecordSet,
    /// Data RRsets by owner and type, merged.
    sets: BTreeMap<(LowerName, RecordType), RecordSet>,
    cuts: BTreeMap<LowerName, Cut>,
    /// NSEC RRsets at cuts, where no data node holds them.
    cut_nsec: BTreeMap<LowerName, RecordSet>,
    nsec3: BTreeMap<LowerName, RecordSet>,
    /// The first RRset found whose records have different TTLs.
    ttls_differ: Option<(LowerName, RecordType)>,
    /// The first delegation outside the zone. Its RRsets are left out.
    outside_cut: Option<LowerName>,
}

struct Cut {
    ns: RecordSet,
    ds: Option<RecordSet>,
    glue: BTreeMap<(LowerName, RecordType), RecordSet>,
}

impl Parts {
    fn sort(builder: ZoneBuilder) -> Parts {
        let apex = LowerName::new(&builder.apex);
        let mut parts = Parts {
            apex,
            soa: RecordSet::new(builder.apex.clone(), RecordType::SOA, 0),
            sets: BTreeMap::new(),
            cuts: BTreeMap::new(),
            cut_nsec: BTreeMap::new(),
            nsec3: BTreeMap::new(),
            ttls_differ: None,
            outside_cut: None,
        };
        parts.soa = parts.normal(&builder.soa);

        let mut rest = Vec::new();
        for delegation in builder.delegations {
            parts.cut(delegation);
        }
        for set in builder.sets {
            let owner = LowerName::new(set.name());
            match set.record_type() {
                _ if set.is_empty() => {}
                RecordType::SOA if owner == parts.apex => parts.soa = parts.normal(&set),
                RecordType::NS if owner != parts.apex => parts.cut(Delegation {
                    child: set.name().clone(),
                    ns: set,
                    glue: Vec::new(),
                    ds: None,
                }),
                _ => rest.push(set),
            }
        }
        for set in rest {
            let owner = LowerName::new(set.name());
            let rtype = set.record_type();
            let cut = parts.cut_above(&owner);
            match (cut, rtype) {
                (Some(cut), RecordType::A | RecordType::AAAA) => {
                    let set = parts.normal(&set);
                    let glue = &mut parts.cuts.get_mut(&cut).expect("a cut above").glue;
                    merge_into(glue, (owner, rtype), set, &mut parts.ttls_differ);
                }
                (Some(cut), RecordType::DS) if cut == owner => {
                    let set = parts.normal(&set);
                    let entry = &mut parts.cuts.get_mut(&cut).expect("a cut").ds;
                    *entry = Some(match entry.take() {
                        Some(ds) => union(ds, set, &mut parts.ttls_differ),
                        None => set,
                    });
                }
                (Some(cut), RecordType::NSEC) if cut == owner => {
                    let set = parts.normal(&set);
                    merge_into(&mut parts.cut_nsec, owner, set, &mut parts.ttls_differ);
                }
                (_, RecordType::NSEC3) => {
                    let set = parts.normal(&set);
                    merge_into(&mut parts.nsec3, owner, set, &mut parts.ttls_differ);
                }
                _ => {
                    let set = parts.normal(&set);
                    merge_into(&mut parts.sets, (owner, rtype), set, &mut parts.ttls_differ);
                }
            }
        }
        parts
    }

    /// Adds a delegation, merging it with one already at the same child.
    fn cut(&mut self, delegation: Delegation) {
        let child = LowerName::new(&delegation.child);
        if !(self.apex.zone_of(&child) && child != self.apex) {
            self.outside_cut.get_or_insert(child);
            return;
        }
        let ns = self.normal(&delegation.ns);
        let ds = delegation.ds.map(|ds| self.normal(&ds));
        let glue: Vec<RecordSet> = delegation.glue.iter().map(|set| self.normal(set)).collect();
        let cut = match self.cuts.remove(&child) {
            Some(mut cut) => {
                cut.ns = union(cut.ns, ns, &mut self.ttls_differ);
                cut.ds = match (cut.ds, ds) {
                    (Some(old), Some(new)) => Some(union(old, new, &mut self.ttls_differ)),
                    (old, new) => old.or(new),
                };
                cut
            }
            None => Cut {
                ns,
                ds,
                glue: BTreeMap::new(),
            },
        };
        self.cuts.insert(child.clone(), cut);
        let cut = self.cuts.get_mut(&child).expect("just inserted");
        for set in glue.into_iter().filter(|set| !set.is_empty()) {
            let key = (LowerName::new(set.name()), set.record_type());
            merge_into(&mut cut.glue, key, set, &mut self.ttls_differ);
        }
    }

    /// The cut at or above `owner`, if any.
    fn cut_above(&self, owner: &LowerName) -> Option<LowerName> {
        let mut name = owner.clone();
        while self.apex.zone_of(&name) && name != self.apex {
            if self.cuts.contains_key(&name) {
                return Some(name);
            }
            name = name.base_name();
        }
        None
    }

    /// `set` with duplicate records dropped, noting different TTLs.
    fn normal(&mut self, set: &RecordSet) -> RecordSet {
        let mut empty = RecordSet::with_ttl(set.name().clone(), set.record_type(), set.ttl());
        empty.set_dns_class(set.dns_class());
        union(empty, set.clone(), &mut self.ttls_differ)
    }

    /// Checks the rules in order and gives the first broken one.
    fn check(self) -> Result<Parts, ZoneError> {
        let apex = &self.apex;
        let data_owners = || self.sets.keys().map(|(owner, _)| owner);
        let all_sets = || {
            self.sets
                .values()
                .chain(self.cut_nsec.values())
                .chain(self.nsec3.values())
        };

        // Out of the zone (RFC 1034 §4.2).
        if let Some(set) = all_sets().find(|set| !apex.zone_of(&LowerName::new(set.name()))) {
            return Err(ZoneError::OutOfZone {
                owner: LowerName::new(set.name()),
            });
        }
        if let Some(child) = &self.outside_cut {
            return Err(ZoneError::OutOfZone {
                owner: child.clone(),
            });
        }

        // CNAME at the apex (RFC 1912 §2.4), then beside other data
        // (RFC 1034 §3.6.2, RFC 2181 §10.1).
        if self.sets.contains_key(&(apex.clone(), RecordType::CNAME)) {
            return Err(ZoneError::CnameAtApex);
        }
        for ((owner, rtype), set) in &self.sets {
            if *rtype != RecordType::CNAME {
                continue;
            }
            let others = self
                .sets
                .range((owner.clone(), RecordType::from(0))..)
                .take_while(|((other, _), _)| other == owner)
                .any(|((_, other), _)| !matches!(*other, RecordType::CNAME | RecordType::NSEC));
            if others || set.records_count() > 1 {
                return Err(ZoneError::CnameWithOtherData {
                    owner: owner.clone(),
                });
            }
        }

        // Below a DNAME (RFC 6672 §2.4).
        let dnames: BTreeSet<&LowerName> = self
            .sets
            .keys()
            .filter(|(_, rtype)| *rtype == RecordType::DNAME)
            .map(|(owner, _)| owner)
            .collect();
        let below_dname = |name: &LowerName| {
            dnames
                .iter()
                .any(|dname| dname.zone_of(name) && name != *dname)
        };
        if let Some(owner) = data_owners()
            .chain(self.cuts.keys())
            .find(|owner| below_dname(owner))
        {
            return Err(ZoneError::DataBelowDname {
                owner: owner.clone(),
            });
        }

        // Below a cut: data, or another cut (RFC 1034 §4.2.1).
        for child in self.cuts.keys() {
            if let Some(owner) = data_owners().find(|owner| child.zone_of(owner)) {
                return Err(ZoneError::DataBelowCut {
                    owner: owner.clone(),
                    cut: child.clone(),
                });
            }
            let deeper = self
                .cuts
                .range(child.clone()..)
                .map(|(other, _)| other)
                .take_while(|other| child.zone_of(other))
                .find(|other| *other != child);
            if let Some(deeper) = deeper {
                return Err(ZoneError::DataBelowCut {
                    owner: deeper.clone(),
                    cut: child.clone(),
                });
            }
        }

        // In-domain glue (RFC 9471 §3.1).
        for (child, cut) in &self.cuts {
            for target in targets(&cut.ns) {
                let glued = [RecordType::A, RecordType::AAAA]
                    .iter()
                    .any(|rtype| cut.glue.contains_key(&(target.clone(), *rtype)));
                if child.zone_of(&target) && !glued {
                    return Err(ZoneError::MissingInDomainGlue {
                        child: child.clone(),
                        ns: target,
                    });
                }
            }
        }

        // Targets that are aliases (RFC 2181 §10.3).
        let alias =
            |target: &LowerName| self.sets.contains_key(&(target.clone(), RecordType::CNAME));
        let named = self
            .sets
            .values()
            .chain(self.cuts.values().map(|cut| &cut.ns));
        for set in named {
            if let Some(target) = targets(set).into_iter().find(|target| alias(target)) {
                return Err(ZoneError::TargetIsAlias {
                    owner: LowerName::new(set.name()),
                    target,
                });
            }
        }

        // TTLs within an RRset (RFC 2181 §5.2).
        if let Some((owner, rtype)) = &self.ttls_differ {
            return Err(ZoneError::RrsetTtlsDiffer {
                owner: owner.clone(),
                rtype: *rtype,
            });
        }

        // TTLs below 2^31 (RFC 2181 §8).
        let cut_sets = self.cuts.values().flat_map(|cut| {
            std::iter::once(&cut.ns)
                .chain(&cut.ds)
                .chain(cut.glue.values())
        });
        let too_large = std::iter::once(&self.soa)
            .chain(all_sets())
            .chain(cut_sets)
            .flat_map(|set| set.records_with_rrsigs())
            .find(|record| record.ttl >= MAX_TTL);
        if let Some(record) = too_large {
            return Err(ZoneError::TtlTooLarge {
                owner: LowerName::new(&record.name),
                ttl: record.ttl,
            });
        }

        // An NS RRset at the apex (RFC 1034 §4.2.1).
        if !self.sets.contains_key(&(apex.clone(), RecordType::NS)) {
            return Err(ZoneError::MissingApexNs);
        }
        Ok(self)
    }

    fn assemble(self, revision: Revision) -> Zone {
        let mut grouped: BTreeMap<LowerName, BTreeMap<RecordType, RecordSet>> = BTreeMap::new();
        grouped
            .entry(self.apex.clone())
            .or_default()
            .insert(RecordType::SOA, self.soa.clone());
        let mut nsec = self.cut_nsec;
        for ((owner, rtype), set) in self.sets {
            if rtype == RecordType::NSEC {
                nsec.insert(owner.clone(), set.clone());
            }
            grouped.entry(owner).or_default().insert(rtype, set);
        }

        let mut nodes = BTreeMap::new();
        for (owner, mut sets) in grouped {
            let node = match sets.remove(&RecordType::DNAME) {
                Some(dname) => Node::Dname(dname, sets),
                None => Node::Data(sets),
            };
            nodes.insert(owner, node);
        }
        for (child, cut) in self.cuts {
            let node = Node::Cut {
                ns: cut.ns,
                ds: cut.ds,
                glue: cut.glue.into_values().collect(),
            };
            nodes.insert(child, node);
        }

        // Every name between the apex and a node is an empty non-terminal
        // unless it holds a node itself.
        let owners: Vec<LowerName> = nodes.keys().cloned().collect();
        for owner in owners {
            let mut name = owner;
            while name != self.apex && self.apex.zone_of(&name) {
                name = name.base_name();
                nodes.entry(name.clone()).or_insert(Node::Empty);
            }
        }

        Zone {
            inner: Arc::new(Inner {
                apex: self.apex,
                soa: self.soa,
                nodes,
                nsec,
                nsec3: self.nsec3,
                revision,
            }),
        }
    }
}

/// Merges `set` into the RRset under `key`.
fn merge_into<K: Ord>(
    map: &mut BTreeMap<K, RecordSet>,
    key: K,
    set: RecordSet,
    ttls_differ: &mut Option<(LowerName, RecordType)>,
) {
    let merged = match map.remove(&key) {
        Some(old) => union(old, set, ttls_differ),
        None => set,
    };
    map.insert(key, merged);
}

/// The records and RRSIGs of both RRsets, each record once (RFC 2181 §5).
/// Records of one RRset with different TTLs are noted in `ttls_differ`.
pub(super) fn union(
    mut into: RecordSet,
    from: RecordSet,
    ttls_differ: &mut Option<(LowerName, RecordType)>,
) -> RecordSet {
    let mut records: Vec<Record> = into.records_without_rrsigs().cloned().collect();
    let mut rrsigs: Vec<Record> = into.rrsigs().to_vec();
    for record in from.records_without_rrsigs() {
        if records.iter().all(|kept| kept.data != record.data) {
            records.push(record.clone());
        }
    }
    for rrsig in from.rrsigs() {
        if !rrsigs.contains(rrsig) {
            rrsigs.push(rrsig.clone());
        }
    }
    let ttl = records.first().map(|record| record.ttl);
    let differ = records.iter().any(|record| Some(record.ttl) != ttl);
    if differ && ttls_differ.is_none() {
        *ttls_differ = Some((LowerName::new(into.name()), into.record_type()));
    }
    if let Some(ttl) = ttl {
        into.set_ttl(ttl);
    }
    into.set_records(records);
    into.set_rrsigs(rrsigs);
    into
}

/// The names an NS, MX, or SRV RRset points at, whose addresses go in the
/// additional section (RFC 1034 §4.3.2 step 6).
pub(super) fn targets(set: &RecordSet) -> Vec<LowerName> {
    set.records_without_rrsigs()
        .filter_map(|record| match &record.data {
            RData::NS(ns) => Some(LowerName::new(&ns.0)),
            RData::MX(mx) => Some(LowerName::new(&mx.exchange)),
            RData::SRV(srv) => Some(LowerName::new(&srv.target)),
            _ => None,
        })
        .collect()
}

/// DNAME RDATA pointing at `target` (RFC 6672 §2.1). hickory carries DNAME
/// as unknown RDATA, so the target is written out uncompressed, as
/// RFC 6672 §2.5 requires on the wire.
pub fn dname(target: &Name) -> RData {
    let mut bytes = Vec::new();
    for label in target.iter() {
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label);
    }
    bytes.push(0);
    RData::Unknown {
        code: RecordType::DNAME,
        rdata: NULL::with(bytes),
    }
}

/// The target of DNAME RDATA, read from its uncompressed name
/// (RFC 6672 §2.5). `None` for other RDATA, or a target that does not
/// read.
pub fn dname_target(rdata: &RData) -> Option<Name> {
    let RData::Unknown { code, rdata } = rdata else {
        return None;
    };
    if *code != RecordType::DNAME {
        return None;
    }
    let mut decoder = BinDecoder::new(&rdata.anything);
    let name = Name::read(&mut decoder).ok()?;
    decoder.is_empty().then_some(name)
}

impl View for Zone {
    fn apex(&self) -> &LowerName {
        &self.inner.apex
    }

    fn revision(&self) -> Revision {
        self.inner.revision
    }

    fn soa(&self) -> &RecordSet {
        &self.inner.soa
    }

    fn node(&self, name: &LowerName) -> Fact<&Node> {
        match self.inner.nodes.get(name) {
            Some(node) => Fact::Present(node),
            None => Fact::Absent,
        }
    }

    fn denial(&self, name: &LowerName, kind: Denied) -> Fact<Vec<RecordSet>> {
        let inner = &self.inner;
        let proof = if !inner.nsec.is_empty() {
            inner.nsec_proof(name, kind)
        } else if !inner.nsec3.is_empty() {
            inner.nsec3_proof(name, kind)
        } else {
            Vec::new()
        };
        Fact::Present(proof)
    }
}

impl ZoneData for Zone {
    fn apex(&self) -> &LowerName {
        &self.inner.apex
    }

    fn view(&self, _question: &Query) -> Arc<dyn View + Send + Sync> {
        Arc::new(self.clone())
    }
}

impl Inner {
    /// The deepest name at or above `name` that the zone holds a node at,
    /// or the apex.
    fn closest_encloser(&self, name: &LowerName) -> LowerName {
        let mut name = name.clone();
        while name != self.apex && !self.nodes.contains_key(&name) {
            name = name.base_name();
        }
        name
    }

    /// NSEC records proving `kind` at `name` (RFC 4035 §3.1.3).
    fn nsec_proof(&self, name: &LowerName, kind: Denied) -> Vec<RecordSet> {
        // The NSEC whose owner is the last at or before `name` in canonical
        // order. The chain wraps, but the apex comes first, so there is
        // always one in a complete chain.
        let covering = |name: &LowerName| {
            self.nsec
                .range(..=name.clone())
                .next_back()
                .or_else(|| self.nsec.iter().next_back())
                .map(|(_, set)| set.clone())
        };
        let proof = match kind {
            Denied::Name => {
                let wildcard = wildcard(&self.closest_encloser(name));
                vec![covering(name), covering(&wildcard)]
            }
            // The NSEC at the name, or for an empty non-terminal or a name a
            // wildcard answered, the one that covers it.
            Denied::Type(_) | Denied::Wildcard { .. } => vec![covering(name)],
        };
        unique(proof.into_iter().flatten())
    }

    /// NSEC3 records proving `kind` at `name` (RFC 5155 §7.2).
    fn nsec3_proof(&self, name: &LowerName, kind: Denied) -> Vec<RecordSet> {
        let Some(params) = self.nsec3_params() else {
            return Vec::new();
        };
        let matching = |name: &LowerName| self.nsec3.get(&self.hashed(name, &params)).cloned();
        let covering = |name: &LowerName| {
            let hashed = self.hashed(name, &params);
            self.nsec3
                .range(..hashed)
                .next_back()
                .or_else(|| self.nsec3.iter().next_back())
                .map(|(_, set)| set.clone())
        };
        let proof = match kind {
            Denied::Name => {
                let encloser = self.closest_encloser(name);
                vec![
                    matching(&encloser),
                    covering(&next_closer(name, &encloser)),
                    covering(&wildcard(&encloser)),
                ]
            }
            Denied::Type(_) => match matching(name) {
                // A wildcard's NODATA also needs its closest encloser
                // matched (RFC 5155 §7.2.5).
                Some(set) if name.is_wildcard() => vec![Some(set), matching(&name.base_name())],
                Some(set) => vec![Some(set)],
                None => {
                    // No NSEC3 at the name: an opt-out cut, proven by its
                    // closest provable encloser (RFC 5155 §7.2.4).
                    let mut encloser = name.base_name();
                    while encloser != self.apex && matching(&encloser).is_none() {
                        encloser = encloser.base_name();
                    }
                    vec![matching(&encloser), covering(&next_closer(name, &encloser))]
                }
            },
            Denied::Wildcard { closest_encloser } => {
                vec![covering(&next_closer(name, &closest_encloser))]
            }
        };
        unique(proof.into_iter().flatten())
    }

    /// How every NSEC3 record of the zone hashes names (RFC 5155 §7.1).
    fn nsec3_params(&self) -> Option<Hashing> {
        let record = self
            .nsec3
            .values()
            .next()?
            .records_without_rrsigs()
            .next()?;
        match &record.data {
            RData::DNSSEC(DNSSECRData::NSEC3(nsec3)) => Some(Hashing {
                algorithm: nsec3.hash_algorithm(),
                salt: nsec3.salt().to_vec(),
                iterations: nsec3.iterations(),
            }),
            _ => None,
        }
    }

    /// `name`'s hashed owner: its NSEC3 hash in base32hex, under the apex
    /// (RFC 5155 §3.3).
    fn hashed(&self, name: &LowerName, hashing: &Hashing) -> LowerName {
        let hash = hashing
            .algorithm
            .hash(&hashing.salt, &Name::from(name), hashing.iterations)
            .expect("a name always encodes");
        LowerName::new(&hashed_owner(hash.as_ref(), &Name::from(&self.apex)))
    }
}

/// The parameters every NSEC3 record of one zone hashes names with
/// (RFC 5155 §5).
struct Hashing {
    algorithm: Nsec3HashAlgorithm,
    salt: Vec<u8>,
    iterations: u16,
}

/// The wildcard at `encloser`: `*.<encloser>` (RFC 4592 §2.1.1).
pub(super) fn wildcard(encloser: &LowerName) -> LowerName {
    let name = Name::from(encloser)
        .prepend_label("*")
        .expect("a wildcard label fits");
    LowerName::new(&name)
}

/// The ancestor of `name` one label below `encloser`, or `name` itself
/// (RFC 5155 §1.3).
fn next_closer(name: &LowerName, encloser: &LowerName) -> LowerName {
    let mut name = name.clone();
    while name.base_name() != *encloser && encloser.zone_of(&name) && name != *encloser {
        name = name.base_name();
    }
    name
}

/// RRsets with each owner and type once, in their first place.
pub(super) fn unique(sets: impl Iterator<Item = RecordSet>) -> Vec<RecordSet> {
    let mut seen = BTreeSet::new();
    sets.filter(|set| seen.insert((LowerName::new(set.name()), set.record_type())))
        .collect()
}
