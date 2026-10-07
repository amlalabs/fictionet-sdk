//! DNS: the `hickory-proto` crate, re-exported.
//!
//! Use this module to read and answer DNS queries in a world that runs its
//! own DNS server. If the world is a set of websites,
//! [`web::Sites`](crate::stdlib::web::Sites) already runs one for you.
//!
//! Fictionet has no DNS types of its own. A DNS message is plain data: a
//! [`Message`](op::Message) with public `queries` and `answers` lists.
//! World code parses it, matches on it, and builds a reply.
//!
//! A DNS server is a loop on a UDP socket from
//! [`udp::endpoint`](crate::stdlib::udp::endpoint). Which names exist, and
//! whether answers are wrong, slow or missing, is all up to world code.
//! This server knows one name, `api.stripe.com`, and answers NXDOMAIN for
//! every other:
//!
//! ```no_run
//! use fictionet::prelude::*;
//! use fictionet::stdlib::dns::op::{Message, ResponseCode};
//! use fictionet::stdlib::dns::rr::{RData, Record, rdata::A};
//! use fictionet::{Cx, Result, stdlib::udp};
//!
//! async fn serve_dns(fcx: &Cx, socket: &mut udp::Socket) -> Result {
//!     while let Ok((bytes, from)) = socket.recv(fcx).await {
//!         let Ok(query) = Message::from_vec(&bytes) else { continue };
//!
//!         let mut reply = Message::response(query.metadata.id, query.metadata.op_code);
//!         reply.queries = query.queries.clone();
//!         for q in &query.queries {
//!             match q.name().to_ascii().as_str() {
//!                 "api.stripe.com." => {
//!                     let ip = A("104.18.32.7".parse()?);
//!                     reply.answers.push(Record::from_rdata(q.name().clone(), 300, RData::A(ip)));
//!                 }
//!                 _ => reply.metadata.response_code = ResponseCode::NXDomain,
//!             }
//!         }
//!
//!         socket.send_to(&reply.to_vec()?, from);
//!     }
//!     Ok(())
//! }
//! ```

pub use hickory_proto::*;
