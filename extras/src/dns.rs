//! The real internet's DNS servers and resolvers as a world plays them.
//!
//! [`public`] has the large public resolvers, [`doh`] what their DNS over
//! HTTPS servers answer past RFC 8484, [`place`] how the root,
//! `gtld-servers.net`, and public resolver servers look from one place,
//! and [`roots`] the `gtld-servers.net` servers' addresses and what the
//! root and `gtld-servers.net` servers' software does everywhere.
//! [`unbound`] plays Unbound's configuration, [`chaos`] the CHAOS-class
//! names servers answer about themselves and the plain and refusing looks
//! of those answers, and [`bind`] BIND's CHAOS-class zones.

pub mod bind;
pub mod chaos;
pub mod doh;
pub mod place;
pub mod public;
pub mod roots;
pub mod unbound;
