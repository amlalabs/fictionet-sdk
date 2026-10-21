//! Request routing: searches, the engines' redirects, and pages.

use crate::pages::text::normalize_space;
use fictionet_extras::search::Engine;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The search engines' hosts. Links to them are not mentions of pages.
pub const SEARCH_HOSTS: [&str; 8] = [
    "www.google.com",
    "google.com",
    "html.duckduckgo.com",
    "duckduckgo.com",
    "www.duckduckgo.com",
    "lite.duckduckgo.com",
    "www.bing.com",
    "bing.com",
];

/// The action requested from the world.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Route {
    /// Redirect to another URL.
    Redirect { location: String, status: u16 },
    /// Show an engine's home page.
    SearchHome { engine: Engine },
    /// Show results for a search.
    Search {
        engine: Engine,
        /// Search text with surrounding whitespace removed.
        query: String,
        /// Result offset, starting at zero.
        start: u64,
    },
    /// Fetch a page or asset.
    Page,
}

/// Normalizes search text and adds offsets of ten or more to the shared key.
pub fn query_key(query: &str, start: u64) -> String {
    let mut key = normalize_space(&query.to_lowercase());
    if start >= 10 {
        key.push_str(&format!(" (from {start})"));
    }
    key
}

/// A result offset: decimal digits after an optional `+`, saturating at
/// the largest offset. Anything else is zero.
fn number(text: &str) -> u64 {
    let text = text.trim();
    let digits = text.strip_prefix('+').unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return 0;
    }
    digits.bytes().fold(0u64, |value, b| {
        value.saturating_mul(10).saturating_add(u64::from(b - b'0'))
    })
}

/// Routes a host and request target. Pass form bytes only for a form URL
/// encoded POST; its fields take the place of the query's.
pub fn route(host: &str, target: &str, form: Option<&[u8]>) -> Route {
    let host = host.to_lowercase();
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let parse = |bytes: &[u8], blanks: bool| {
        let mut args = BTreeMap::new();
        for (name, value) in form_urlencoded::parse(bytes) {
            if blanks || !value.is_empty() {
                args.entry(name.into_owned())
                    .or_insert_with(|| value.into_owned());
            }
        }
        args
    };
    let mut args = parse(query.as_bytes(), true);
    if let Some(body) = form {
        args.extend(parse(String::from_utf8_lossy(body).as_bytes(), false));
    }
    let arg = |name: &str| args.get(name).map(String::as_str).unwrap_or("");
    let q = arg("q").trim();
    let search = |engine, start| Route::Search {
        engine,
        query: q.to_owned(),
        start,
    };
    let redirect = |location, status| Route::Redirect { location, status };
    if path == "/" && matches!(host.as_str(), "google.com" | "bing.com" | "www.bing.com") {
        return Route::SearchHome {
            engine: if host == "google.com" {
                Engine::Google
            } else {
                Engine::Bing
            },
        };
    }
    if host == "www.youtube.com" && path == "/results" && !arg("search_query").trim().is_empty() {
        return Route::Search {
            engine: Engine::YouTube,
            query: arg("search_query").trim().to_owned(),
            start: 0,
        };
    }
    if matches!(host.as_str(), "google.com" | "bing.com") {
        return redirect(format!("https://www.{host}{target}"), 301);
    }
    if host == "www.google.com" {
        if path == "/search"
            && !q.is_empty()
            && (args.contains_key("client") || args.contains_key("channel"))
        {
            let mut clean = form_urlencoded::Serializer::new(String::new());
            clean.append_pair("q", q);
            for (key, value) in form_urlencoded::parse(query.as_bytes()) {
                if !["q", "client", "channel"].contains(&key.as_ref()) {
                    clean.append_pair(&key, &value);
                }
            }
            return redirect(format!("/search?{}", clean.finish()), 302);
        }
        if path == "/search" && !q.is_empty() {
            return search(Engine::Google, number(arg("start")));
        }
        if path == "/url" && arg("q").starts_with("http") {
            return redirect(arg("q").into(), 302);
        }
        if matches!(path, "/" | "/webhp") {
            return Route::SearchHome {
                engine: Engine::Google,
            };
        }
    }
    if matches!(
        host.as_str(),
        "html.duckduckgo.com" | "duckduckgo.com" | "www.duckduckgo.com" | "lite.duckduckgo.com"
    ) {
        if path == "/l/" && arg("uddg").starts_with("http") {
            return redirect(arg("uddg").into(), 302);
        }
        if matches!(path, "/html" | "/html/" | "/lite" | "/lite/" | "/") {
            return if q.is_empty() {
                Route::SearchHome {
                    engine: Engine::DuckDuckGo,
                }
            } else {
                search(Engine::DuckDuckGo, number(arg("s")))
            };
        }
    }
    if host == "www.bing.com" && path == "/search" && !q.is_empty() {
        return search(Engine::Bing, number(arg("first")).saturating_sub(1));
    }
    Route::Page
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn browser_search_redirect_keeps_query_and_search_options() {
        assert_eq!(
            route(
                "www.google.com",
                "/search?client=firefox-b-d&channel=entpr&q=long+query+%26+details&start=10&hl=en&tbm=vid",
                None
            ),
            Route::Redirect {
                location: "/search?q=long+query+%26+details&start=10&hl=en&tbm=vid".into(),
                status: 302,
            }
        );
        assert_eq!(
            route("www.google.com", "/search?q=long+query&start=10", None),
            Route::Search {
                engine: Engine::Google,
                query: "long query".into(),
                start: 10
            }
        );
    }
    #[test]
    fn routing_branches() {
        for host in ["GOOGLE.COM", "bing.com"] {
            assert_eq!(
                route(host, "/search?q=x", None),
                Route::Redirect {
                    location: format!("https://www.{}/search?q=x", host.to_lowercase()),
                    status: 301
                }
            );
        }
        assert_eq!(
            route("www.bing.com", "/", None),
            Route::SearchHome {
                engine: Engine::Bing
            }
        );
        for path in ["/", "/webhp"] {
            assert_eq!(
                route("www.google.com", path, None),
                Route::SearchHome {
                    engine: Engine::Google
                }
            );
        }
        for host in [
            "html.duckduckgo.com",
            "duckduckgo.com",
            "lite.duckduckgo.com",
        ] {
            for path in ["/html", "/html/", "/lite", "/lite/", "/"] {
                assert_eq!(
                    route(host, path, None),
                    Route::SearchHome {
                        engine: Engine::DuckDuckGo
                    }
                );
                assert_eq!(
                    route(host, &format!("{path}?q=x&s=30"), None),
                    Route::Search {
                        engine: Engine::DuckDuckGo,
                        query: "x".into(),
                        start: 30
                    }
                );
            }
            assert_eq!(
                route(host, "/l/?uddg=https%3A%2F%2Fa.com", None),
                Route::Redirect {
                    location: "https://a.com".into(),
                    status: 302
                }
            );
            assert_eq!(route(host, "/l/?uddg=ftp://a.com", None), Route::Page);
        }
        assert_eq!(
            route("www.google.com", "/url?q=httpwhatever", None),
            Route::Redirect {
                location: "httpwhatever".into(),
                status: 302
            }
        );
        for (host, target) in [
            ("www.google.com", "/url?q=+https://a.com"),
            ("www.google.com", "/search?q="),
            ("www.bing.com", "/search"),
            ("else.com", "/search?q=x"),
            ("else.com", "/x.css"),
        ] {
            assert_eq!(route(host, target, None), Route::Page);
        }
    }
    #[test]
    fn forms_offsets_and_normalization() {
        assert_eq!(
            route(
                "html.duckduckgo.com",
                "/html/?q=url&s=2",
                Some(b"q=&q=+Form+&q=last&s=20")
            ),
            Route::Search {
                engine: Engine::DuckDuckGo,
                query: "Form".into(),
                start: 20
            }
        );
        assert_eq!(
            route("www.google.com", "/search?q=&q=second", Some(b"q=")),
            Route::Page
        );
        for (offset, want) in [
            ("-4", 0),
            ("bad", 0),
            ("1_0", 0),
            ("%2B10", 10),
            ("+20+", 20),
            ("١٢", 0),
            ("99999999999999999999999", u64::MAX),
        ] {
            assert_eq!(
                route(
                    "www.google.com",
                    &format!("/search?q=+Hi%09&start={offset}"),
                    None
                ),
                Route::Search {
                    engine: Engine::Google,
                    query: "Hi".into(),
                    start: want
                }
            );
        }
        for (first, start) in [("", 0), ("0", 0), ("1", 0), ("11", 10), ("21", 20)] {
            assert_eq!(
                route(
                    "www.bing.com",
                    &format!("/search?q=a%3Fb&first={first}"),
                    None
                ),
                Route::Search {
                    engine: Engine::Bing,
                    query: "a?b".into(),
                    start
                }
            );
        }
        assert_eq!(query_key("\tHI\u{2003}There ", 9), "hi there");
        assert_eq!(query_key("Hi", 10), "hi (from 10)");
    }
}
