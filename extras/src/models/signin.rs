//! Provider sign-in hosts and the setup scope shared with inference.

/// Interactive sign-in and its provider-hosted assets.
pub const HOSTS: &[&str] = &[
    "claude.ai",
    "claude.com",
    "assets-proxy.anthropic.com",
    "s-cdn.anthropic.com",
    "hcaptcha.com",
    "console.anthropic.com",
    "platform.claude.com",
    "auth.openai.com",
    "challenges.cloudflare.com",
];

/// The login's CAPTCHA assets use regional subdomains of one service.
pub fn is_host(host: &str) -> bool {
    HOSTS.contains(&host) || host.ends_with(".hcaptcha.com")
}

/// The authority under which an authentication request may leave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// An interactive sign-in request admitted before setup closed.
    SignIn,
    /// A validated refresh grant to the provider's token endpoint.
    Refresh,
}

/// A setup window shared by sign-in hosts and the inference gateway.
/// Closing it is irreversible for this run.
#[derive(Clone)]
pub struct Session {
    closed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    refresh: bool,
}
impl Default for Session {
    fn default() -> Self {
        Self {
            closed: Default::default(),
            refresh: true,
        }
    }
}

impl Session {
    /// A provisioned long-lived token needs neither sign-in nor refresh.
    pub fn inference_only() -> Self {
        Self {
            closed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            refresh: false,
        }
    }

    /// Whether interactive sign-in is closed.
    pub fn closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Closes interactive sign-in and returns whether this changed the state.
    pub fn close(&self) -> bool {
        !self.closed.swap(true, std::sync::atomic::Ordering::AcqRel)
    }

    /// The only post-login requests to a sign-in host exchange refresh tokens.
    pub fn authorize(
        &self,
        host: &str,
        method: &http::Method,
        path: &str,
        body: &serde_json::Value,
    ) -> Option<Access> {
        if !is_host(host) {
            return None;
        }
        if !self.closed() {
            return Some(Access::SignIn);
        }
        if !self.refresh {
            return None;
        }
        let client = match (host, path) {
            ("platform.claude.com", "/v1/oauth/token") => "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
            ("auth.openai.com", "/oauth/token") => "app_EMoamEEZ73f0CkXaXp7hrann",
            _ => return None,
        };
        (method == http::Method::POST
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
            }))
        .then_some(Access::Refresh)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;
    use serde_json::json;

    fn allows(
        session: &Session,
        host: &str,
        method: &Method,
        path: &str,
        body: &serde_json::Value,
    ) -> bool {
        session.authorize(host, method, path, body).is_some()
    }

    #[test]
    fn provisioned_tokens_have_no_sign_in_or_refresh_egress() {
        let session = Session::inference_only();
        assert!(session.closed());
        assert!(!session.close());
        for host in HOSTS {
            assert!(!allows(
                &session,
                host,
                &Method::GET,
                "/oauth/authorize",
                &json!(null)
            ));
        }
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
            assert!(!allows(
                &session,
                host,
                &Method::POST,
                path,
                &json!({"grant_type":"refresh_token", "client_id":client, "refresh_token":"guest-token"})
            ));
        }
    }

    #[test]
    fn setup_closes_to_token_refresh_only() {
        let session = Session::default();
        let other = session.clone();
        assert!(allows(
            &session,
            "claude.com",
            &Method::GET,
            "/oauth/authorize",
            &json!(null)
        ));
        assert!(!allows(
            &session,
            "example.com",
            &Method::GET,
            "/",
            &json!(null)
        ));
        assert!(allows(
            &session,
            "newassets.hcaptcha.com",
            &Method::GET,
            "/",
            &json!(null)
        ));
        assert!(!allows(
            &session,
            "hcaptcha.com.example.com",
            &Method::GET,
            "/",
            &json!(null)
        ));
        assert!(!allows(
            &session,
            "evilhcaptcha.com",
            &Method::GET,
            "/",
            &json!(null)
        ));
        assert!(session.close());
        assert!(!other.close());
        assert!(!allows(
            &other,
            "claude.com",
            &Method::GET,
            "/oauth/authorize",
            &json!(null)
        ));
        assert!(!allows(
            &session,
            "newassets.hcaptcha.com",
            &Method::GET,
            "/",
            &json!(null)
        ));
        for host in HOSTS {
            assert!(
                session
                    .authorize(host, &Method::GET, "/", &json!(null))
                    .is_none()
            );
        }
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
            assert!(allows(&other, host, &Method::POST, path, &body));
            assert!(!allows(&other, host, &Method::GET, path, &body));
            assert!(!allows(
                &other,
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
                assert!(!allows(&other, host, &Method::POST, path, &invalid));
            }
        }
    }
}
