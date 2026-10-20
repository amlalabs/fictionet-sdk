//! The admin's endpoint on the world's management subnet.
use fictionet::stdlib::network::tcp::{self, TcpConnection};
use fictionet::tokio::{Compat, ConnectionTokioExt};
use fictionet::{Cx, End};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::sync::watch;

/// The admin address on the management subnet.
pub const JUMP_ADDR: Ipv4Addr = Ipv4Addr::new(10, 10, 5, 20);

/// An admin endpoint that connects to guests across the world network.
pub struct Jump {
    fcx: Cx,
    endpoint: tcp::Endpoint,
}

impl Jump {
    /// Creates the endpoint on the supplied admin attachment.
    pub fn new(fcx: &Cx, link: End) -> Self {
        Self {
            fcx: fcx.clone(),
            endpoint: tcp::endpoint(fcx, link, JUMP_ADDR.into()),
        }
    }
    /// Waits for the guest address and connects to its port within the timeout.
    pub(super) async fn connect_addr(
        &self,
        mut guest: watch::Receiver<Option<Ipv4Addr>>,
        port: u16,
        timeout: Duration,
    ) -> io::Result<Compat<TcpConnection>> {
        tokio::time::timeout(timeout, async {
            let addr = guest
                .wait_for(Option::is_some)
                .await
                .map_err(io::Error::other)?
                .unwrap();
            let connection = self
                .endpoint
                .connect(&self.fcx, SocketAddr::from((addr, port)))
                .await?;
            Ok(connection.into_tokio(&self.fcx))
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "the guest did not answer"))?
    }
}
