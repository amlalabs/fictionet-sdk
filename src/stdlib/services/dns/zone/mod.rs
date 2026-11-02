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
//! | [`Transparent`] | What the zone it wraps holds. Absence becomes unknown, so a resolver goes on to iterate. |
//! | [`special`] | The zones a resolver serves itself: `localhost`, the RFC 6303 reverse zones, `home.arpa`, `resolver.arpa`, `onion`, `test`, and `invalid`. |
//!
//! A world writes its own [`ZoneData`] for anything else, such as a zone
//! that holds only what a capture showed.

mod answer;
mod data;
mod lazy;
mod master;
pub mod special;
#[allow(clippy::module_inception)]
mod zone;

pub use answer::{Answered, AnyResponse, answer};
pub use data::{Denied, Fact, Provider, Revision, Transparent, View, ZoneData};
pub use lazy::Lazy;
pub use master::MasterError;
pub use zone::{Node, Zone, ZoneBuilder, ZoneError, dname, dname_target};
