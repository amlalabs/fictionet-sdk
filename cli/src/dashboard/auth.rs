use std::sync::atomic::{AtomicBool, Ordering};

use fictionet_cli::attach_proxy::auth::Token;

use super::http::Request;

pub(super) struct Auth {
    pub(super) token: Token,
    pub(super) bootstrap_used: AtomicBool,
}

impl Auth {
    pub(super) fn bootstrap(&self, req: &Request) -> bool {
        req.query.is_empty()
            && self.allows(req)
            && !self.bootstrap_used.swap(true, Ordering::SeqCst)
    }

    pub(super) fn allows(&self, req: &Request) -> bool {
        req.authorization.as_deref().is_some_and(|value| {
            value.split_once(' ').is_some_and(|(scheme, token)| {
                scheme.eq_ignore_ascii_case("Bearer") && self.token.matches(token.trim().as_bytes())
            })
        })
    }
}

#[cfg(test)]
mod auth_tests {
    use super::super::http::{host_allowed, parse_request, same_site};
    use super::*;

    fn auth() -> Auth {
        Auth {
            token: Token::new(b"secret+;/token").unwrap(),
            bootstrap_used: AtomicBool::new(false),
        }
    }

    fn request(target: &str, headers: &str) -> Request {
        parse_request(
            format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n{headers}\r\n").as_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn loopback_keylog_needs_a_token() {
        let auth = auth();
        let req = request("/api/keylog", "");
        assert!(host_allowed(
            req.host.as_deref(),
            "127.0.0.1:7878".parse().unwrap()
        ));
        assert!(same_site(&req));
        assert!(!auth.allows(&req));
        assert!(!auth.allows(&request("/api/keylog", "Authorization: Bearer wrong\r\n")));
        assert!(!auth.allows(&request("/api/keylog", "Cookie: fictionet_token=wrong\r\n")));
        assert!(auth.allows(&request(
            "/api/keylog",
            "Authorization: Bearer secret+;/token\r\n"
        )));
    }

    #[test]
    fn bootstrap_is_consumed_once_and_only_bearer_authenticates() {
        let auth = auth();
        let bearer = "Authorization: Bearer secret+;/token\r\n";
        assert!(!auth.bootstrap(&request("/api/bootstrap", "")));
        assert!(!auth.bootstrap(&request("/api/bootstrap?token=secret%2B%3B%2Ftoken", "")));
        assert!(!auth.bootstrap(&request("/api/bootstrap?extra=1", bearer)));
        let req = request("/api/bootstrap", bearer);
        assert!(auth.bootstrap(&req));
        assert!(!auth.bootstrap(&req));
        for path in [
            "/api/watch",
            "/api/packets?link=e1",
            "/api/pcap?link=e1",
            "/api/keylog",
        ] {
            assert!(auth.allows(&request(path, bearer)));
            assert!(!auth.allows(&request(
                path,
                "Cookie: fictionet_token=secret%2B%3B%2Ftoken\r\n"
            )));
        }
        assert!(!auth.allows(&request("/api/keylog?token=secret%2B%3B%2Ftoken", "")));
    }
}
