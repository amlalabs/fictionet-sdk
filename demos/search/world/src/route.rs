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
