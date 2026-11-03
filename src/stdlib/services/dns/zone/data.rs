//! What a zone knows: facts that are present, known absent, or unknown,
//! and views that hold the facts one question needs at one revision.

use std::collections::BTreeMap;
use std::sync::Arc;

use fictionet::stdlib::protocols::dns::op::Query;
use fictionet::stdlib::protocols::dns::rr::{LowerName, Name, RecordSet, RecordType};

use super::apex::EmptyApex;
use super::zone::{Node, ZoneError};

/// What a zone knows about one fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Fact<T> {
    /// The fact holds, with this value.
    Present(T),
    /// The zone knows there is nothing here.
    Absent,
    /// The zone does not know. [`answer`](super::answer) never turns an
    /// unknown fact into NXDOMAIN or NODATA.
    Unknown,
}

impl<T> Fact<T> {
    /// The fact with its value changed by `f`.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Fact<U> {
        match self {
            Fact::Present(value) => Fact::Present(f(value)),
            Fact::Absent => Fact::Absent,
            Fact::Unknown => Fact::Unknown,
        }
    }
}

/// A zone's data at one moment. Revisions only grow: each change to a
/// zone's data makes a new one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Revision(pub u64);

/// The negative a set of denial records proves.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Denied {
    /// Nothing exists at the name, and no wildcard could make it exist
    /// (RFC 4035 §3.1.3.2, RFC 5155 §7.2.2).
    Name,
    /// The name exists without an RRset of this type (RFC 4035 §3.1.3.1,
    /// RFC 5155 §7.2.3 and §7.2.4). At a zone cut with
    /// [`RecordType::DS`], it proves the child is unsigned.
    Type(RecordType),
    /// The name does not exist, so the wildcard at `closest_encloser`
    /// answered for it (RFC 4035 §3.1.3.3, RFC 5155 §7.2.6).
    Wildcard {
        /// The deepest existing ancestor of the name.
        closest_encloser: LowerName,
    },
}

/// An immutable view of a zone at one revision, holding every fact one
/// question needs that the data can know.
///
/// [`answer`](super::answer) reads a view and nothing else, so a view
/// that reports facts from one revision gives an answer from one
/// revision, however the data behind it changes meanwhile.
pub trait View {
    /// The zone's apex.
    fn apex(&self) -> &LowerName;
    /// The revision every fact of this view comes from.
    fn revision(&self) -> Revision;
    /// The zone's SOA RRset.
    fn soa(&self) -> &RecordSet;
    /// What is at `name`. `Absent` means no node at `name` and nothing
    /// below it (RFC 8020). A name with nothing of its own but names
    /// below it is `Present(Node::Empty)`.
    fn node(&self, name: &LowerName) -> Fact<&Node>;
    /// The denial records that prove `kind` at `name` (NSEC or NSEC3, each
    /// with its RRSIGs), which a reply carries when the query set DO. An
    /// unsigned zone returns `Present(vec![])`. In a zone that denies with
    /// NSEC, `Type(NSEC)` at a name gives the NSEC at that name, which
    /// lists the name's types, and which the answer to QTYPE NSEC sends
    /// when no node holds it.
    fn denial(&self, name: &LowerName, kind: Denied) -> Fact<Vec<RecordSet>>;
    /// Whether a name with nothing of its own but names below it answers
    /// NODATA when the answer ends there, rather than being unknown. Such
    /// a name on the way down to another one is a step all the same.
    fn answers_empty(&self) -> bool {
        true
    }
    /// `set`, an RRset the answer makes up rather than reads, such as the
    /// HINFO of RFC 8482 §4.2, with RRSIGs from the zone's keys. `None`
    /// when the view cannot sign: the zone is unsigned, or was signed once
    /// with keys it does not hold.
    fn sign(&self, set: &RecordSet) -> Option<RecordSet> {
        let _ = set;
        None
    }
}

/// Zone data: something that makes views.
pub trait ZoneData: Send + Sync + 'static {
    /// The zone's apex.
    fn apex(&self) -> &LowerName;
    /// A view with every fact `question` needs that this data can know,
    /// all at one revision.
    fn view(&self, question: &Query) -> Arc<dyn View + Send + Sync>;
}

/// Decides names as they are asked. World code: trusted, called
/// synchronously while the zone holds its lock, so it must return
/// quickly.
pub trait Provider: Send + Sync + 'static {
    /// What exists at `name`: its RRsets, nothing at or below it, or not
    /// known.
    ///
    /// `Absent` promises that nothing exists below `name` either. RRsets
    /// whose owner is not `name` are kept at `name` all the same.
    fn lookup(&self, name: &LowerName) -> Fact<Vec<RecordSet>>;
}

impl<F> Provider for F
where
    F: Fn(&LowerName) -> Fact<Vec<RecordSet>> + Send + Sync + 'static,
{
    fn lookup(&self, name: &LowerName) -> Fact<Vec<RecordSet>> {
        self(name)
    }
}

/// Zone data that holds some RRsets of one name and knows nothing else,
/// such as what a capture showed for a host, or the one answer a resolver
/// gives itself for a name it otherwise iterates for.
///
/// A question for the name and the type of an RRset it holds answers from
/// that RRset. So does every question at the name when it holds a CNAME,
/// which leaves no room for other data there (RFC 1034 §3.6.2), except a
/// question for RRSIGs when the CNAME carries none, and one for NSEC,
/// whose RRset may sit beside a CNAME (RFC 4035 §2.5). Every
/// other fact is unknown: a capture holding `www.example A` says nothing
/// about `www.example AAAA`, nor about the zone's SOA or NS RRsets. A
/// resolver then goes on to its next local zone or iterates, and a server
/// answers SERVFAIL.
pub struct Shown {
    apex: LowerName,
    soa: RecordSet,
    sets: BTreeMap<RecordType, RecordSet>,
}

impl Shown {
    /// The RRsets `sets` of `owner`. An RRset of another owner is
    /// [`ZoneError::OutOfZone`], and a CNAME beside other data is
    /// [`ZoneError::CnameWithOtherData`].
    // `ZoneError` is large; this returns it as `Zone::builder` does, once
    // per build and never on a path that answers questions.
    #[allow(clippy::result_large_err)]
    pub fn new(
        owner: &Name,
        sets: impl IntoIterator<Item = RecordSet>,
    ) -> Result<Shown, ZoneError> {
        let apex = LowerName::new(owner);
        let mut held = BTreeMap::new();
        for set in sets {
            if LowerName::new(set.name()) != apex {
                return Err(ZoneError::OutOfZone {
                    owner: LowerName::new(set.name()),
                });
            }
            held.insert(set.record_type(), set);
        }
        if held.contains_key(&RecordType::CNAME) && held.len() > 1 {
            return Err(ZoneError::CnameWithOtherData { owner: apex });
        }
        Ok(Shown {
            // A view needs an SOA, but every answer this data gives is a
            // positive one, which carries none.
            soa: EmptyApex::rfc6303().records(owner).0,
            apex,
            sets: held,
        })
    }
}

impl ZoneData for Shown {
    fn apex(&self) -> &LowerName {
        &self.apex
    }

    fn view(&self, question: &Query) -> Arc<dyn View + Send + Sync> {
        let cname = self.sets.get(&RecordType::CNAME);
        let asked = match question.query_type() {
            RecordType::ANY => cname,
            // RRSIGs travel inside the RRsets they cover, so a CNAME
            // answers for them only when it carries some.
            RecordType::RRSIG => cname.filter(|set| !set.rrsigs().is_empty()),
            // An NSEC RRset may sit beside a CNAME (RFC 4035 §2.5), and
            // answers an NSEC question before the CNAME does.
            RecordType::NSEC => self.sets.get(&RecordType::NSEC),
            qtype => self.sets.get(&qtype).or(cname),
        };
        Arc::new(ShownView {
            apex: self.apex.clone(),
            soa: self.soa.clone(),
            node: match asked {
                Some(set) => Fact::Present(Node::Data(BTreeMap::from([(
                    set.record_type(),
                    set.clone(),
                )]))),
                None => Fact::Unknown,
            },
        })
    }
}

/// The view of [`Shown`] for one question: the node at the apex when an
/// RRset it holds answers the question, and nothing else.
struct ShownView {
    apex: LowerName,
    soa: RecordSet,
    node: Fact<Node>,
}

impl View for ShownView {
    fn apex(&self) -> &LowerName {
        &self.apex
    }

    fn revision(&self) -> Revision {
        Revision(0)
    }

    fn soa(&self) -> &RecordSet {
        &self.soa
    }

    fn node(&self, name: &LowerName) -> Fact<&Node> {
        match &self.node {
            Fact::Present(node) if *name == self.apex => Fact::Present(node),
            _ => Fact::Unknown,
        }
    }

    fn denial(&self, _name: &LowerName, _kind: Denied) -> Fact<Vec<RecordSet>> {
        Fact::Unknown
    }
}

/// Unbound's `transparent` local zone: a name with RRsets in `D` answers
/// from them, and every other name is unknown, so a resolver goes on to
/// its next local zone or iterates for it.
///
/// A name `D` holds RRsets at, without the asked type, still answers
/// NODATA, as Unbound's transparent zones do. A name `D` says is absent,
/// and an answer that ends at a name with nothing of its own but names
/// below it, are unknown: Unbound answers from a transparent zone only
/// where it has data (`local_zones_zone_answer`). Such a name on the way
/// down to another one, such as a CNAME's target, stays as `D` has it,
/// so the answer can walk past it.
pub struct Transparent<D: ZoneData>(pub D);

impl<D: ZoneData> ZoneData for Transparent<D> {
    fn apex(&self) -> &LowerName {
        self.0.apex()
    }

    fn view(&self, question: &Query) -> Arc<dyn View + Send + Sync> {
        Arc::new(TransparentView(self.0.view(question)))
    }
}

/// Unbound's `redirect` local zone: every name below the apex answers with
/// the apex's RRsets, owned by the name asked, as Unbound serves
/// `localhost.` (`local_data_answer`). `foo.localhost. NS` gets
/// `foo.localhost. NS localhost.`.
pub struct Redirect<D: ZoneData>(pub D);

impl<D: ZoneData> ZoneData for Redirect<D> {
    fn apex(&self) -> &LowerName {
        self.0.apex()
    }

    fn view(&self, question: &Query) -> Arc<dyn View + Send + Sync> {
        let mut at_apex = question.clone();
        at_apex.set_name(Name::from(self.0.apex().clone()));
        Arc::new(RedirectView(self.0.view(&at_apex)))
    }
}

/// A view whose names below the apex read as the apex.
struct RedirectView(Arc<dyn View + Send + Sync>);

impl RedirectView {
    /// The name whose facts stand for `name`: the apex for every name
    /// below it.
    fn standing_for<'a>(&'a self, name: &'a LowerName) -> &'a LowerName {
        let apex = self.0.apex();
        if apex.zone_of(name) { apex } else { name }
    }
}

impl View for RedirectView {
    fn apex(&self) -> &LowerName {
        self.0.apex()
    }

    fn revision(&self) -> Revision {
        self.0.revision()
    }

    fn soa(&self) -> &RecordSet {
        self.0.soa()
    }

    fn node(&self, name: &LowerName) -> Fact<&Node> {
        self.0.node(self.standing_for(name))
    }

    fn denial(&self, name: &LowerName, kind: Denied) -> Fact<Vec<RecordSet>> {
        self.0.denial(self.standing_for(name), kind)
    }

    fn answers_empty(&self) -> bool {
        self.0.answers_empty()
    }

    fn sign(&self, set: &RecordSet) -> Option<RecordSet> {
        self.0.sign(set)
    }
}

/// A view whose absent nodes read as unknown, and whose empty
/// non-terminals answer nothing.
struct TransparentView(Arc<dyn View + Send + Sync>);

impl View for TransparentView {
    fn apex(&self) -> &LowerName {
        self.0.apex()
    }

    fn revision(&self) -> Revision {
        self.0.revision()
    }

    fn soa(&self) -> &RecordSet {
        self.0.soa()
    }

    fn node(&self, name: &LowerName) -> Fact<&Node> {
        match self.0.node(name) {
            Fact::Absent => Fact::Unknown,
            fact => fact,
        }
    }

    fn denial(&self, name: &LowerName, kind: Denied) -> Fact<Vec<RecordSet>> {
        self.0.denial(name, kind)
    }

    fn answers_empty(&self) -> bool {
        false
    }

    fn sign(&self, set: &RecordSet) -> Option<RecordSet> {
        self.0.sign(set)
    }
}
