//! A zone that grows from a [`Provider`] as names are asked.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use fictionet::stdlib::protocols::dns::op::Query;
use fictionet::stdlib::protocols::dns::rr::rdata::SOA;
use fictionet::stdlib::protocols::dns::rr::{
    LowerName, Name, RData, Record, RecordSet, RecordType,
};
use fictionet::sync::Mutex;

use super::answer::{AnyResponse, resolve};
use super::data::{Denied, Fact, Provider, Revision, View, ZoneData};
use super::zone::{Node, targets, union};

/// A zone whose names come from a [`Provider`], asked the first time a
/// question needs them.
///
/// The zone holds its apex (the SOA and NS RRsets) from the start. Each
/// view asks the provider about the names its question needs that the
/// zone does not hold yet: every name on the path from the apex to the
/// question's name, then whatever else the answer reads, such as the
/// wildcard where the name is absent, CNAME and DNAME targets inside the
/// zone, and the NS, MX, and SRV targets whose addresses the answer adds.
/// `Present` RRsets are kept, each name a new revision.
/// `Absent` and `Unknown` are not kept, so the provider is asked again
/// next time, and a world whose names come into being as it runs needs
/// nothing more.
///
/// A view takes the zone's lock once, asks the provider under it, and
/// copies out the facts its question read, so it is one revision. The
/// provider runs under this lock only.
///
/// RRsets with NS below the apex make a zone cut. The provider is then
/// asked about the cut's NS targets at or below it, and their address
/// RRsets become the cut's glue; while one of those targets is unknown,
/// so is the cut. RRsets with a DNAME make a DNAME node. Names the
/// provider gives RRsets to make the ancestors it calls absent empty
/// non-terminals, so a question for such a parent gets NODATA. An
/// ancestor it does not know stays unknown, and so do the names below
/// it.
pub struct Lazy<P: Provider> {
    apex: LowerName,
    soa: RecordSet,
    provider: P,
    held: Mutex<Held>,
}

/// The names a [`Lazy`] zone holds.
struct Held {
    nodes: BTreeMap<LowerName, Node>,
    revision: Revision,
}

impl<P: Provider> Lazy<P> {
    /// A zone at `apex` with an SOA record of `soa` and `ttl` and the apex
    /// NS RRset `ns`, whose other names come from `provider`.
    pub fn new(apex: Name, soa: SOA, ns: RecordSet, ttl: u32, provider: P) -> Lazy<P> {
        let mut soa_set = RecordSet::with_ttl(apex.clone(), RecordType::SOA, ttl);
        soa_set.set_records(vec![Record::from_rdata(apex.clone(), ttl, RData::SOA(soa))]);
        let apex = LowerName::new(&apex);
        let sets = BTreeMap::from([(RecordType::SOA, soa_set.clone()), (RecordType::NS, ns)]);
        Lazy {
            held: Mutex::new(Held {
                nodes: BTreeMap::from([(apex.clone(), Node::Data(sets))]),
                revision: Revision(0),
            }),
            apex,
            soa: soa_set,
            provider,
        }
    }

    /// Asks the provider about `name` and keeps what is present. A zone
    /// cut whose glue for an NS target at or below it is unknown is not
    /// kept: it stays unknown until the provider knows the glue.
    fn ask(&self, held: &mut Held, said: &mut BTreeMap<LowerName, Fact<()>>, name: LowerName) {
        let node = match self.provider.lookup(&name) {
            Fact::Present(sets) => self.node_of(&name, sets),
            Fact::Absent => Fact::Absent,
            Fact::Unknown => Fact::Unknown,
        };
        match node {
            Fact::Present(node) => {
                held.nodes.insert(name, node);
                held.revision = Revision(held.revision.0 + 1);
            }
            Fact::Absent => {
                said.insert(name, Fact::Absent);
            }
            Fact::Unknown => {
                said.insert(name, Fact::Unknown);
            }
        }
    }

    /// The node the provider's RRsets for `name` make, or `Unknown` for a
    /// zone cut whose glue the provider does not know: a referral without
    /// the glue for an NS target at or below the cut cannot be followed
    /// (RFC 9471 §3.1).
    fn node_of(&self, name: &LowerName, sets: Vec<RecordSet>) -> Fact<Node> {
        let mut by_type: BTreeMap<RecordType, RecordSet> = BTreeMap::new();
        for set in sets.into_iter().filter(|set| !set.is_empty()) {
            // The provider is trusted, so records of one RRset with
            // different TTLs are kept as they are.
            let kept = by_type.remove(&set.record_type()).unwrap_or_else(|| {
                RecordSet::with_ttl(set.name().clone(), set.record_type(), set.ttl())
            });
            let set = union(kept, set, &mut None);
            by_type.insert(set.record_type(), set);
        }
        if let Some(ns) = by_type.remove(&RecordType::NS) {
            let ds = by_type.remove(&RecordType::DS);
            let mut glue = Vec::new();
            for target in targets(&ns).into_iter().filter(|t| name.zone_of(t)) {
                match self.provider.lookup(&target) {
                    Fact::Present(sets) => glue.extend(sets.into_iter().filter(|set| {
                        matches!(set.record_type(), RecordType::A | RecordType::AAAA)
                    })),
                    Fact::Absent => {}
                    Fact::Unknown => return Fact::Unknown,
                }
            }
            return Fact::Present(Node::Cut { ns, ds, glue });
        }
        Fact::Present(match by_type.remove(&RecordType::DNAME) {
            Some(dname) => Node::Dname(dname, by_type),
            None => Node::Data(by_type),
        })
    }
}

impl<P: Provider> ZoneData for Lazy<P> {
    fn apex(&self) -> &LowerName {
        &self.apex
    }

    fn view(&self, question: &Query) -> Arc<dyn View + Send + Sync> {
        let qname = LowerName::new(question.name());
        let qtype = question.query_type();
        let mut held = self.held.lock();
        // What the provider said this time about names it did not give
        // RRsets to.
        let mut said = BTreeMap::new();
        // Every name from the apex down to the question's name first, so a
        // name the provider gives RRsets to is found even when it calls
        // its ancestors absent; they become empty non-terminals.
        let mut path = Vec::new();
        let mut name = qname.clone();
        while self.apex.zone_of(&name) && name != self.apex {
            path.push(name.clone());
            name = name.base_name();
        }
        for name in path.into_iter().rev() {
            if !held.nodes.contains_key(&name) {
                self.ask(&mut held, &mut said, name);
            }
        }
        loop {
            let probe = Probe {
                lazy: self,
                held: &held,
                said: &said,
                read: RefCell::new(BTreeSet::new()),
                wanted: RefCell::new(BTreeSet::new()),
            };
            // The names an answer reads do not depend on DO or on how ANY
            // is answered, so one run finds them for every request.
            let _ = resolve(&probe, &qname, qtype, false, AnyResponse::All);
            let wanted = probe.wanted.take();
            if wanted.is_empty() {
                return Arc::new(probe.snapshot());
            }
            for name in wanted {
                self.ask(&mut held, &mut said, name);
            }
        }
    }
}

/// A view over the zone as it is while a view is being made. Names it has
/// not asked the provider about read as unknown and are noted, so they
/// can be asked before the answer runs again.
struct Probe<'a, P: Provider> {
    lazy: &'a Lazy<P>,
    held: &'a Held,
    said: &'a BTreeMap<LowerName, Fact<()>>,
    read: RefCell<BTreeSet<LowerName>>,
    wanted: RefCell<BTreeSet<LowerName>>,
}

/// The node of a name with nothing of its own and names below it.
static EMPTY: Node = Node::Empty;

impl<P: Provider> Probe<'_, P> {
    /// The view of exactly the facts this run read.
    fn snapshot(&self) -> Snapshot {
        let facts = self
            .read
            .borrow()
            .iter()
            .map(|name| (name.clone(), self.fact(name).map(Node::clone)))
            .collect();
        Snapshot {
            apex: self.lazy.apex.clone(),
            soa: self.lazy.soa.clone(),
            revision: self.held.revision,
            facts,
        }
    }

    fn fact(&self, name: &LowerName) -> Fact<&Node> {
        if let Some(node) = self.held.nodes.get(name) {
            return Fact::Present(node);
        }
        // What the provider said comes first: a name it does not know
        // stays unknown whatever is below it.
        match self.said.get(name) {
            Some(Fact::Absent) => {
                // Names below `name` follow it directly in canonical order.
                let below = self
                    .held
                    .nodes
                    .range(name.clone()..)
                    .next()
                    .is_some_and(|(other, _)| name.zone_of(other));
                if below {
                    Fact::Present(&EMPTY)
                } else {
                    Fact::Absent
                }
            }
            Some(_) => Fact::Unknown,
            None => {
                self.wanted.borrow_mut().insert(name.clone());
                Fact::Unknown
            }
        }
    }
}

impl<P: Provider> View for Probe<'_, P> {
    fn apex(&self) -> &LowerName {
        &self.lazy.apex
    }

    fn revision(&self) -> Revision {
        self.held.revision
    }

    fn soa(&self) -> &RecordSet {
        &self.lazy.soa
    }

    fn node(&self, name: &LowerName) -> Fact<&Node> {
        if !self.lazy.apex.zone_of(name) {
            return Fact::Absent;
        }
        self.read.borrow_mut().insert(name.clone());
        self.fact(name)
    }

    fn denial(&self, _name: &LowerName, _kind: Denied) -> Fact<Vec<RecordSet>> {
        Fact::Present(Vec::new())
    }
}

/// The facts one question read from a [`Lazy`] zone, at one revision.
/// Every other name is unknown.
struct Snapshot {
    apex: LowerName,
    soa: RecordSet,
    revision: Revision,
    facts: BTreeMap<LowerName, Fact<Node>>,
}

impl View for Snapshot {
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

    /// A lazy zone is unsigned.
    fn denial(&self, _name: &LowerName, _kind: Denied) -> Fact<Vec<RecordSet>> {
        Fact::Present(Vec::new())
    }
}
