//! The time server the workstation sets its clock from: Ubuntu's own
//! `ntp.ubuntu.com`, answering with the session's time.

use std::sync::Arc;

use fictionet::stdlib::codec::{Collect, Wire};
use fictionet::stdlib::protocols::ntp::{self, Packet, ServerInfo, Timestamp};
use fictionet::stdlib::services::serve::{self, Driver, Service};
use fictionet::stdlib::world::net::Host;

use crate::pages::Pages;

/// The name Ubuntu's clock asks for the time.
pub(crate) const HOST: &str = "ntp.ubuntu.com";

/// The time server, answering on UDP port 123 with the time
/// [`Pages::session_now`] gives.
pub(crate) fn host(pages: Arc<Pages>) -> Host {
    Host::new(HOST)
        .dns_name(HOST)
        .ipv4_only()
        .udp(ntp::PORT, pages, || TimeServer)
}

struct TimeServer;

impl Service for TimeServer {
    type Timer = ();
    type Decoder = Collect<Packet>;
    type State = Pages;
    type Error = core::convert::Infallible;

    fn decoder(&self) -> Collect<Packet> {
        Collect::new(ntp::MAX_PACKET)
    }

    fn on_item(
        &mut self,
        request: Packet,
        pages: &Pages,
        driver: &mut Driver<'_, Collect<Packet>, ()>,
    ) -> Result<serve::Flow, Self::Error> {
        let at = pages.session_now();
        let now = timestamp(at);
        // Answers as a stratum 2 pool server does: synced to an upstream
        // server a minute ago.
        let server = ServerInfo {
            stratum: 2,
            reference_id: [194, 58, 204, 148],
            reference: timestamp(at - std::time::Duration::from_secs(64)),
            ..ServerInfo::default()
        };
        // A packet that is not a request, such as a server's reply, gets
        // no answer, as from a real server.
        if let Ok(reply) = ntp::server_reply(&request, &server, now, now)
            && let Ok(bytes) = reply.to_bytes()
        {
            driver.reply().extend_from_slice(&bytes);
        }
        Ok(serve::Flow::Continue)
    }
}

fn timestamp(time: std::time::SystemTime) -> Timestamp {
    let since = time
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    Timestamp::from_unix(since.as_secs() as i64, since.subsec_nanos())
}
