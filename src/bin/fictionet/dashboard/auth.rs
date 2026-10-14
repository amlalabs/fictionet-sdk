use std::sync::atomic::{AtomicBool, Ordering};

use fictionet::relay::proxy::auth::Token;

use super::http::{Request, unescape};

pub(super) struct Auth {
    pub(super) token: Token,
    pub(super) login_used: AtomicBool,
}

impl Auth {
    pub(super) fn login(&self, req: &Request) -> Option<String> {
        let [(key, value)] = req.query.as_slice() else {
            return None;
        };
        if key != "token"
            || !self.token.matches(value.as_bytes())
            || self.login_used.swap(true, Ordering::SeqCst)
        {
            return None;
        }
        Some(value.bytes().map(|b| format!("%{b:02X}")).collect())
    }

    pub(super) fn allows(&self, req: &Request) -> bool {
        let bearer = req.authorization.as_deref().is_some_and(|value| {
            value.split_once(' ').is_some_and(|(scheme, token)| {
                scheme.eq_ignore_ascii_case("Bearer") && self.token.matches(token.trim().as_bytes())
            })
        });
        let cookie = req.cookie.as_deref().is_some_and(|cookies| {
            cookies.split(';').any(|cookie| {
                cookie
                    .trim()
                    .strip_prefix("fictionet_token=")
                    .is_some_and(|value| self.token.matches(unescape(value).as_bytes()))
            })
        });
        bearer || cookie
    }
}

#[cfg(test)]
mod auth_tests {
    use super::super::http::{host_allowed, parse_request, same_site};
    use super::*;

    fn auth() -> Auth {
        Auth {
            token: Token::new(b"secret+;/token").unwrap(),
            login_used: AtomicBool::new(false),
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
    fn login_is_consumed_once_and_its_cookie_authenticates_streams() {
        let auth = auth();
        assert!(auth.login(&request("/login?token=wrong", "")).is_none());
        assert!(
            auth.login(&request(
                "/login?token=secret%2B%3B%2Ftoken&token=wrong",
                ""
            ))
            .is_none()
        );
        let req = request("/login?token=secret%2B%3B%2Ftoken", "");
        let cookie = auth.login(&req).unwrap();
        assert!(!cookie.contains(';'));
        assert!(auth.login(&req).is_none());
        let headers = format!("Cookie: theme=light; fictionet_token={cookie}\r\n");
        assert!(auth.allows(&request("/api/watch", &headers)));
        assert!(auth.allows(&request("/api/packets?link=e1", &headers)));
        assert!(auth.allows(&request("/api/pcap?link=e1", &headers)));
        assert!(!auth.allows(&request("/api/keylog?token=secret%2B%3B%2Ftoken", "")));
    }
}
