//! Zones and what they know.
//!
//! A zone's data makes [views](View): for one question, every fact the
//! answer needs, each [present, known absent, or unknown](Fact), all from
//! one [revision](Revision). [`answer`] reads one view and gives the
//! authoritative reply of RFC 1034 §4.3.2, or [`Answered::Unknown`] when a
//! fact it rests on is unknown. It never turns an unknown fact into
//! NXDOMAIN or NODATA.
//!
//! | Data | What it knows |
//! | --- | --- |
//! | [`Zone`] | Everything: a complete zone, built with [`Zone::builder`] or read with [`Zone::from_master`]. Nothing is unknown. |
//! | [`Lazy`] | The names a [`Provider`] gives when they are first asked. What the provider does not know stays unknown. |
//! | [`Transparent`] | The names with RRsets in the zone it wraps. Every other name is unknown, so a resolver goes on to iterate. |
//! | [`special`] | The zones a resolver serves itself: `localhost`, the RFC 6303 reverse zones, `home.arpa`, `resolver.arpa`, `service.arpa`, `onion`, `test`, and `invalid`. |
//!
//! A world writes its own [`ZoneData`] for anything else, such as a zone
//! that holds only what a capture showed.
//!
//! Signing is data too. [`Zone::signed`] signs a complete zone once, with
//! a complete NSEC or NSEC3 chain, as `dnssec-signzone` does. [`Signed`]
//! signs any zone data as it is asked, and makes each denial for its
//! question with [`cover`], since a chain over data that grows would deny
//! names added later. [`check_chain`] looks over a tree of signed zones for
//! the breaks a validator would find.
//!
//! | DNSSEC piece | Standard |
//! | --- | --- |
//! | [`Zone::signed`], [`Signed`] | RFC 4035 §2, RFC 5155 §7.1, RFC 9077, RFC 9276 §3.1 |
//! | [`cover`] | RFC 4470, RFC 7129 Appendix B |
//! | [`check_chain`] | RFC 4035 §5.2, RFC 4034 §3.1.5, RFC 9905 §2 |

mod answer;
mod chain;
mod cover;
mod data;
mod lazy;
mod master;
mod signed;
pub mod special;
#[allow(clippy::module_inception)]
mod zone;

pub use answer::{Answered, AnyResponse, answer};
pub use chain::{ChainProblem, check_chain};
pub use cover::cover;
pub(crate) use cover::negative_ttl;
pub use data::{Denied, Fact, Provider, Revision, Transparent, View, ZoneData};
pub use lazy::Lazy;
pub use master::MasterError;
pub use signed::{Denial, Signed};
pub use zone::{Node, Zone, ZoneBuilder, ZoneError, dname, dname_target};
