//! Bounded collection of off-site targets named by a request.

use bytes::Bytes;
use http::Request;
use serde_json::{Value, json};

use fictionet::stdlib::web::Target;

/// Limits a log string to 300 Unicode characters.
pub fn truncate(s: &str) -> String {
    s.chars().take(300).collect()
}

/// Decodes percent escapes and form-style plus signs.
pub fn decode(s: &str) -> String {
    let mut out = Vec::new();
    fictionet::stdlib::codec::ascii::percent_decode_into(s.as_bytes(), true, &mut out, usize::MAX);
    String::from_utf8_lossy(&out).into_owned()
}

/// Iterates over at most 1024 decoded query or form pairs.
pub fn pairs(s: &str) -> impl Iterator<Item = (String, String)> + '_ {
    s.split('&').take(1024).map(|p| {
        let (k, v) = p.split_once('=').unwrap_or((p, ""));
        (decode(k), decode(v))
    })
}

fn host(value: &str, bare: bool) -> Option<String> {
    let value = value.trim().trim_matches('"');
    let authority = if let Some((scheme, rest)) = value.split_once("://") {
        if scheme.is_empty()
            || !scheme.as_bytes()[0].is_ascii_alphabetic()
            || !scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
        {
            return None;
        }
        rest.split(['/', '?', '#']).next()?
    } else if bare {
        value
    } else {
        return None;
    };
    let authority = authority.rsplit('@').next()?;
    let a = authority.parse::<http::uri::Authority>().ok()?;
    let h = a
        .host()
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if h.is_empty()
        || (!value.contains("://")
            && !h.contains('.')
            && h.parse::<std::net::IpAddr>().is_err()
            && h != "localhost")
    {
        return None;
    }
    Some(h)
}

/// Checks whether a target names a host other than this site.
pub fn external(value: &str, own: &str, addr: &str, bare: bool) -> bool {
    host(value, bare).is_some_and(|h| h != own && h != addr)
}

const KEYS: &[&str] = &[
    "url",
    "uri",
    "target",
    "upstream",
    "remote",
    "remoteurl",
    "host",
    "src",
    "source",
    "link",
    "redirect",
    "next",
    "callback",
    "fetch",
    "proxy",
];
const HEADERS: &[&str] = &[
    "x-forwarded-host",
    "x-forwarded-server",
    "x-host",
    "x-original-host",
    "x-original-url",
    "x-rewrite-url",
    "x-artifactory-override-base-url",
    "referer",
];

/// Collects bounded off-site targets from the request without fetching them.
pub fn extract(request: &Request<Bytes>, own: &str, addr: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let uri = request.uri();
    let named = uri
        .host()
        .map(|host| ("authority", host, uri.to_string()))
        .or_else(|| {
            request
                .extensions()
                .get::<Target>()
                .map(|t| ("host", t.host.as_str(), t.host.clone()))
        });
    if let Some((name, host, target)) = named {
        let host = host
            .trim_matches(['[', ']'])
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if host != own && host != addr {
            out.push(json!({"where": "request_target", "name": name, "target": truncate(&target)}));
        }
    }
    let mut add = |place: &str, name: &str, target: &str, bare: bool| {
        if out.len() < 20 && external(target, own, addr, bare) {
            out.push(json!({"where": place, "name": truncate(name), "target": truncate(target)}));
        }
    };
    for (k, v) in pairs(uri.query().unwrap_or_default()) {
        add(
            "query",
            &k,
            &v,
            KEYS.contains(&k.to_ascii_lowercase().as_str()),
        );
    }
    for (name, value) in request.headers() {
        let Ok(value) = value.to_str() else {
            continue;
        };
        if HEADERS.contains(&name.as_str()) {
            for v in value.split(',').take(20) {
                add("header", name.as_str(), v.trim(), true);
            }
        } else if name == "forwarded" {
            for part in value.split([',', ';']).take(100) {
                if let Some((k, v)) = part.trim().split_once('=')
                    && k.eq_ignore_ascii_case("host")
                {
                    add("header", "forwarded", v.trim_matches('"'), true);
                }
            }
        }
    }
    // JSON parsing has its own depth limit. The scan also caps nodes and bytes.
    let body = &request.body()[..request.body().len().min(65_536)];
    if let Ok(value) = serde_json::from_slice::<Value>(body) {
        let mut stack = vec![(String::new(), &value)];
        let mut seen = 0;
        while let Some((name, value)) = stack.pop() {
            seen += 1;
            if seen > 1024 {
                break;
            }
            match value {
                Value::String(s) => add("body", &name, s, false),
                Value::Array(a) => {
                    for (i, v) in a.iter().enumerate().take(1024).rev() {
                        stack.push((format!("{name}[{i}]"), v));
                    }
                }
                Value::Object(o) => {
                    for (k, v) in o.iter().take(1024).rev() {
                        stack.push((
                            if name.is_empty() {
                                k.clone()
                            } else {
                                format!("{name}.{k}")
                            },
                            v,
                        ));
                    }
                }
                _ => {}
            }
        }
    } else {
        for (k, v) in pairs(&String::from_utf8_lossy(body)) {
            add("body", &k, &v, false);
        }
    }
    out
}

/// The URL explicitly supplied to the fetch endpoint.
pub fn fetch_url(request: &Request<Bytes>) -> Option<String> {
    if let Some((_, v)) = pairs(request.uri().query().unwrap_or_default()).find(|(k, _)| k == "url")
    {
        return Some(truncate(&v));
    }
    if let Ok(v) = serde_json::from_slice::<Value>(request.body()) {
        return v.get("url").and_then(Value::as_str).map(truncate);
    }
    pairs(&String::from_utf8_lossy(request.body()))
        .find(|(k, _)| k == "url")
        .map(|(_, v)| truncate(&v))
}

#[cfg(test)]
mod tests {
    use super::*;
    const OWN: &str = "artifactory.northwind.internal";
    fn targets(uri: &str, headers: &[(&str, &str)], body: &str) -> Vec<Value> {
        let mut r = Request::builder().uri(uri);
        for (k, v) in headers {
            r = r.header(*k, *v);
        }
        extract(
            &r.body(Bytes::from(body.to_owned())).unwrap(),
            OWN,
            "10.20.0.15",
        )
    }

    #[test]
    fn query_sources() {
        let v = targets(
            "/?url=https%3A%2F%2Fexample.test%2Fa&remoteUrl=example.test:443\
             &x=https://other.test/&x=words&target=words",
            &[],
            "",
        );
        assert_eq!(v.len(), 3);
        assert_eq!(v[0]["where"], "query");
        assert_eq!(v[0]["target"], "https://example.test/a");
    }

    #[test]
    fn headers_and_forwarded() {
        for h in HEADERS {
            let v = targets("/", &[(h, "https://example.test/path")], "");
            assert_eq!(v.len(), 1, "{h}");
            assert_eq!(v[0]["where"], "header");
        }
        assert_eq!(
            targets(
                "/",
                &[("forwarded", "for=10.0.0.2; host=\"example.test:443\"")],
                ""
            )
            .len(),
            1
        );
    }

    #[test]
    fn body_sources() {
        let v = targets(
            "/",
            &[],
            r#"{"outer":[{"url":"https://example.test/x"}],"x":"words","host":"example.test"}"#,
        );
        assert_eq!(v.len(), 1);
        assert_eq!(v[0]["name"], "outer[0].url");
        assert_eq!(
            targets("/", &[], "url=https%3A%2F%2Fexample.test%2Fx")[0]["where"],
            "body"
        );
    }

    #[test]
    fn own_hosts_and_non_urls() {
        for value in [
            "https://artifactory.northwind.internal/x",
            "https://10.20.0.15:443/x",
            "https://ARTIFACTORY.NORTHWIND.INTERNAL./",
            "words",
            "42",
            "/relative/path",
        ] {
            assert!(!external(value, OWN, "10.20.0.15", true), "{value}");
        }
    }

    #[test]
    fn request_targets_and_caps() {
        assert_eq!(
            targets("https://elsewhere.test/x", &[], "")[0]["where"],
            "request_target"
        );
        let r = Request::builder()
            .method("CONNECT")
            .uri("elsewhere.test:443")
            .body(Bytes::new())
            .unwrap();
        assert_eq!(
            extract(&r, OWN, "10.20.0.15")[0]["target"],
            "elsewhere.test:443"
        );
        let url = format!("https://example.test/{}", "a".repeat(400));
        let q = (0..100)
            .map(|i| format!("x{i}={url}"))
            .collect::<Vec<_>>()
            .join("&");
        let v = targets(&format!("/?{q}"), &[], "");
        assert_eq!(v.len(), 20);
        assert_eq!(v[0]["target"].as_str().unwrap().len(), 300);
    }
}
