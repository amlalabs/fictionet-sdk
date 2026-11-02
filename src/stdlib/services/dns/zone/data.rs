//! What a zone knows: facts that are present, known absent, or unknown,
//! and views that hold the facts one question needs at one revision.

use std::sync::Arc;

use fictionet::stdlib::protocols::dns::op::Query;
use fictionet::stdlib::protocols::dns::rr::{LowerName, RecordSet, RecordType};

use super::zone::Node;

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
    /// unsigned zone returns `Present(vec![])`.
    fn denial(&self, name: &LowerName, kind: Denied) -> Fact<Vec<RecordSet>>;
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

/// Unbound's `transparent` local zone: what `D` holds answers, and what `D`
/// says is absent is unknown, so a resolver goes on to iterate for it.
///
/// A name `D` holds without the asked type still answers NODATA, as
/// Unbound's transparent zones do. Only absence becomes unknown.
pub struct Transparent<D: ZoneData>(pub D);

impl<D: ZoneData> ZoneData for Transparent<D> {
    fn apex(&self) -> &LowerName {
        self.0.apex()
    }

    fn view(&self, question: &Query) -> Arc<dyn View + Send + Sync> {
        Arc::new(TransparentView(self.0.view(question)))
    }
}

/// A view whose absent nodes read as unknown.
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
}
