//! Relay provider sign-in connections with their end-to-end TLS intact.

use fictionet::Cx;

/// Sign-in connections retain the providers' end-to-end TLS.
pub const HOSTS: &[&str] = &[
    "claude.ai",
    "claude.com",
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

                let mut guest = arrival.conn.into_tokio(&cx);
                tokio::io::copy_bidirectional(&mut guest, &mut upstream).await?;
                Ok::<_, std::io::Error>(())
            };
            tokio::select! {
                _ = cx.cancelled() => {},
                _ = work => {}
            }
        })
    }
}

/// A setup window shared by sign-in hosts and the inference gateway.
/// Closing it is irreversible for this run.
#[derive(Clone, Default)]
pub struct Session(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl Session {
    /// Whether the first successful inference has closed interactive sign-in.
    pub fn closed(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Closes interactive sign-in and returns whether this changed the state.
    pub fn close(&self) -> bool {
        !self.0.swap(true, std::sync::atomic::Ordering::AcqRel)
    }

    /// The only post-login requests to a sign-in host exchange refresh tokens.
    pub fn allows(
        &self,
        host: &str,
        method: &http::Method,
        path: &str,
        body: &serde_json::Value,
    ) -> bool {
        if !HOSTS.contains(&host) {
            return false;
        }
        if !self.closed() {
            return true;
        }
        let client = match (host, path) {
            ("platform.claude.com", "/v1/oauth/token") => "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
            ("auth.openai.com", "/oauth/token") => "app_EMoamEEZ73f0CkXaXp7hrann",
            _ => return false,
        };
        method == http::Method::POST
            && body["grant_type"] == "refresh_token"
            && body["client_id"] == client
            && body["refresh_token"]
                .as_str()
                .is_some_and(|token| !token.is_empty())
            && body.as_object().is_some_and(|object| {
                object.keys().all(|key| {
                    matches!(
                        key.as_str(),
                        "grant_type" | "client_id" | "refresh_token" | "scope"
                    )
                })
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;
    use serde_json::json;

    #[test]
    fn setup_closes_to_token_refresh_only() {
        let session = Session::default();
        let other = session.clone();
        assert!(session.allows("claude.com", &Method::GET, "/oauth/authorize", &json!(null)));
        assert!(!session.allows("example.com", &Method::GET, "/", &json!(null)));
        assert!(session.close());
        assert!(!other.close());
        assert!(!other.allows("claude.com", &Method::GET, "/oauth/authorize", &json!(null)));
        for (host, path, client) in [
            (
                "platform.claude.com",
                "/v1/oauth/token",
                "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
            ),
            (
                "auth.openai.com",
                "/oauth/token",
                "app_EMoamEEZ73f0CkXaXp7hrann",
            ),
        ] {
            let body = json!({"grant_type":"refresh_token", "client_id":client, "refresh_token":"local-token"});
            assert!(other.allows(host, &Method::POST, path, &body));
            assert!(!other.allows(host, &Method::GET, path, &body));
            assert!(!other.allows(
                host,
                &Method::POST,
                &format!("{path}?redirect_uri=https://example.com"),
                &body
            ));
            for patch in [
                json!({"grant_type":"authorization_code"}),
                json!({"client_id":"another-client"}),
                json!({"redirect_uri":"https://example.com"}),
                json!({"refresh_token":""}),
            ] {
                let mut invalid = body.clone();
                invalid
                    .as_object_mut()
                    .unwrap()
                    .extend(patch.as_object().unwrap().clone());
                assert!(!other.allows(host, &Method::POST, path, &invalid));
            }
        }
    }
}
