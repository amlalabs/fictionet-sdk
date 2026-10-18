//! Off-site targets named by a request, with bounded log output.

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

/// Iterates over all decoded query or form pairs.
pub fn pairs(s: &str) -> impl Iterator<Item = (String, String)> + '_ {
    s.split('&').map(|p| {
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

/// Scans the buffered request without fetching any targets.
///
/// The request authority comes from the URI, then the routed [`Target`], then
/// the Host header, using the server's host normalization. All query pairs,
/// supported header values and body values are scanned. At most 20 targets
/// are logged. Callers must mark the scan incomplete if the body is unavailable.
pub fn proxy_target(request: &Request<Bytes>, own: &str, addr: &str) -> bool {
    let host = request
        .uri()
        .host()
        .map(str::to_owned)
        .or_else(|| request.extensions().get::<Target>().map(|t| t.host.clone()))
        .or_else(|| fictionet::stdlib::web::httpd::request_host(request));
    host.is_some_and(|h| {
        let h = h
            .trim_matches(['[', ']'])
            .trim_end_matches('.')
            .to_ascii_lowercase();
        h != own && h != addr
    })
}

/// Extracts bounded observation details after routing has checked the target.
pub fn extract(request: &Request<Bytes>, own: &str, addr: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let uri = request.uri();
    let named = uri
        .host()
        .map(|host| ("authority", host.to_owned(), uri.to_string()))
        .or_else(|| {
            request
                .extensions()
                .get::<Target>()
                .map(|t| ("host", t.host.clone(), t.host.clone()))
        })
        .or_else(|| {
            fictionet::stdlib::web::httpd::request_host(request)
                .map(|host| ("host", host.clone(), host))
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
            for v in value.split(',') {
                add("header", name.as_str(), v.trim(), true);
            }
        } else if name == "forwarded" {
            for part in value.split([',', ';']) {
                if let Some((k, v)) = part.trim().split_once('=')
                    && k.eq_ignore_ascii_case("host")
                {
                    add("header", "forwarded", v.trim_matches('"'), true);
                }
            }
        }
    }
    // The server bounds the buffered body. JSON parsing has its own depth limit.
    let body = request.body();
    if let Ok(value) = serde_json::from_slice::<Value>(body) {
        let mut stack = vec![(String::new(), &value)];
        while let Some((name, value)) = stack.pop() {
            match value {
                Value::String(s) => add("body", &name, s, false),
                Value::Array(a) => {
                    for (i, v) in a.iter().enumerate().rev() {
                        stack.push((format!("{name}[{i}]"), v));
                    }
                }
                Value::Object(o) => {
                    for (k, v) in o.iter().rev() {
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
    fn target_after_1024_parameters() {
        let query = format!("{}url=https://elsewhere.test/", "x&".repeat(1024));
        let v = targets(&format!("/?{query}"), &[], "");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0]["where"], "query");
        assert_eq!(v[0]["target"], "https://elsewhere.test/");
        let request = Request::builder()
            .uri(format!("/?{query}"))
            .body(Bytes::new())
            .unwrap();
        assert_eq!(
            fetch_url(&request).as_deref(),
            Some("https://elsewhere.test/")
        );
    }

    #[test]
    fn target_after_body_cap() {
        for body in [
            format!("pad={}&url=https://elsewhere.test/", "x".repeat(65_536)),
            format!(
                r#"{{"pad":"{}","url":"https://elsewhere.test/"}}"#,
                "x".repeat(65_536)
            ),
        ] {
            let v = targets("/", &[], &body);
            assert_eq!(v.len(), 1);
            assert_eq!(v[0]["where"], "body");
            assert_eq!(v[0]["target"], "https://elsewhere.test/");
        }
    }

    #[test]
    fn target_after_json_node_cap() {
        let mut object = serde_json::Map::new();
        for i in 0..1024 {
            object.insert(format!("x{i}"), Value::Null);
        }
        object.insert("url".into(), json!("https://elsewhere.test/"));
        for body in [
            format!(r#"[{}"https://elsewhere.test/"]"#, "null,".repeat(1024)),
            Value::Object(object).to_string(),
        ] {
            let v = targets("/", &[], &body);
            assert_eq!(v.len(), 1);
            assert_eq!(v[0]["where"], "body");
            assert_eq!(v[0]["target"], "https://elsewhere.test/");
        }
    }

    #[test]
    fn target_after_x_forwarded_host_cap() {
        let value = format!("{}elsewhere.test", format!("{OWN},").repeat(20));
        let v = targets("/", &[("x-forwarded-host", &value)], "");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0]["where"], "header");
        assert_eq!(v[0]["target"], "elsewhere.test");
    }

    #[test]
    fn target_after_forwarded_part_cap() {
        let value = format!("{}host=elsewhere.test", "for=10.0.0.2;".repeat(100));
        let v = targets("/", &[("forwarded", &value)], "");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0]["where"], "header");
        assert_eq!(v[0]["target"], "elsewhere.test");
    }

    #[test]
    fn request_host_is_normalized_and_uri_takes_precedence() {
        let v = targets("/", &[("host", "ELSEWHERE.TEST.:80")], "");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0]["where"], "request_target");
        assert_eq!(v[0]["target"], "elsewhere.test");
        for own in [
            OWN,
            "10.20.0.15",
            "10.20.0.15:80",
            "artifactory.northwind.internal:80",
            "ARTIFACTORY.NORTHWIND.INTERNAL.",
        ] {
            assert!(targets("/", &[("host", own)], "").is_empty(), "{own}");
        }
        assert!(targets(&format!("http://{OWN}/"), &[("host", "elsewhere.test")], "").is_empty());
        let v = targets("http://elsewhere.test/", &[("host", OWN)], "");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0]["name"], "authority");
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
