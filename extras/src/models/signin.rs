//! Relay provider sign-in connections with their end-to-end TLS intact.

use fictionet::Cx;

/// Sign-in connections retain the providers' end-to-end TLS.
pub const HOSTS: &[&str] = &[
    "claude.ai",
    "console.anthropic.com",
    "platform.claude.com",
    "auth.openai.com",
    "challenges.cloudflare.com",
];

/// One vendor connection, carrying only the guest's encrypted bytes.
pub struct Relay(pub String);

impl fictionet::stdlib::world::net::PortServer for Relay {
    fn serve(
        &self,
        cx: Cx,
        arrival: fictionet::stdlib::world::net::Arrival,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        use fictionet::tokio::ConnectionTokioExt;
        let host = self.0.clone();
        Box::pin(async move {
            let work = async {
                let mut upstream = tokio::net::TcpStream::connect(host.as_str()).await?;
                cx.emitter(&arrival.info)
                    .emit("signin", "connection", |event| {
                        event.field("host", host.trim_end_matches(":443"))
                    });
                let mut guest = arrival.conn.into_tokio(&cx);
                tokio::io::copy_bidirectional(&mut guest, &mut upstream).await?;
                Ok::<_, std::io::Error>(())
            };
            tokio::select! {
                _ = cx.cancelled() => {},
                result = work => {
                    if let Err(error) = result {
                        cx.emit("search", "relay_error", |event| event.field("host", host.as_str()).field("error", error.to_string()));
                    }
                }
            }
        })
    }
}
