//! Embedded FakeWiki pages, with a variant chosen for each request.

pub mod diff;

mod scenario;
mod text;
mod wiki;

use scenario::*;
pub use scenario::{Variant, host_ips};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::OnceLock;
use text::*;

/// The version of a source document selected by the world.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Version {
    /// The accurate source document.
    Real,
    /// The source document carrying the false claim.
    Tampered,
}

impl Version {
    /// Selects a document version using the scenario's source policy.
    pub fn for_source(variant: Variant, source: &str) -> Self {
        if variant.stance_for(source) == "accurate" {
            Self::Real
        } else {
            Self::Tampered
        }
    }

    /// The source version served by a response, excluding mixed-source search results.
    pub fn served(variant: Variant, source: Option<&str>) -> Option<Self> {
        source
            .filter(|source| *source != "search")
            .map(|source| Self::for_source(variant, source))
    }

    /// The name used in request facts and JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Real => "real",
            Self::Tampered => "tampered",
        }
    }
}

/// A rendered response. Labels describe the full page, including for HEAD.
#[derive(Debug)]
pub struct Response {
    /// The HTTP status code.
    pub status: u16,
    /// The response bytes, empty for HEAD.
    pub body: Vec<u8>,
    /// The Content-Type header.
    pub content_type: &'static str,
    /// The full response length, including for HEAD.
    pub content_length: usize,
    /// The redirect destination, if any.
    pub location: Option<String>,
    /// The Cache-Control header, if any.
    pub cache_control: Option<&'static str>,
    /// The endpoint label used in request events.
    pub kind: &'static str,
    /// The topic label, when known.
    pub topic: Option<String>,
    /// The source label, when known.
    pub source: Option<String>,
    /// The stance detected from the body, or none when ambiguous.
    pub stance: Option<&'static str>,
}
impl Response {
    fn new(
        status: u16,
        body: impl Into<Vec<u8>>,
        content_type: &'static str,
        kind: &'static str,
    ) -> Self {
        let body = body.into();
        Self {
            status,
            content_length: body.len(),
            body,
            content_type,
            location: None,
            cache_control: Some("private, max-age=0"),
            kind,
            topic: None,
            source: None,
            stance: None,
        }
    }
    fn meta(mut self, topic: &str, source: &str) -> Self {
        self.topic = Some(topic.into());
        self.source = Some(source.into());
        self
    }
}

/// An indexable document, in the same order as the backend's index.
#[derive(Debug)]
pub struct Document {
    /// The canonical document URL.
    pub url: String,
    /// The title shown in search results.
    pub title: String,
    /// The text used for search matching and snippets.
    pub text: String,
    /// The corpus topic name.
    pub topic: &'static str,
    /// The corpus source name.
    pub source: &'static str,
    /// The corpus stance selected by the variant.
    pub stance: &'static str,
}

type Markers = HashMap<(String, String), [Vec<String>; 2]>;
struct Corpus {
    topics: Value,
    markers: Markers,
}
fn corpus() -> &'static Corpus {
    static CORPUS: OnceLock<Corpus> = OnceLock::new();
    CORPUS.get_or_init(|| {
        let mut root: Value = serde_json::from_str(include_str!("../../fixtures/corpus.json"))
            .expect("embedded corpus");
        let topics = root["topics"].take();
        let mut markers = HashMap::new();
        for (topic, t) in topics.as_object().unwrap() {
            for source in t["stances"]["accurate"].as_object().unwrap().keys() {
                let acc = strings(&t["stances"]["accurate"][source]);
                let alt = strings(&t["stances"]["altered"][source]);
                let only = |a: &[&str], b: &[&str]| {
                    let other = norm(&b.join(" "));
                    let mut found: Vec<_> = a
                        .iter()
                        .flat_map(|s| sentences(s))
                        .filter(|s| s.chars().count() >= 40)
                        .map(|s| prefix(norm(s).trim(), 60))
                        .filter(|s| !other.contains(s))
                        .collect();
                    found.sort();
                    found.dedup();
                    found
                };
                markers.insert(
                    (topic.clone(), source.clone()),
                    [only(&acc, &alt), only(&alt, &acc)],
                );
            }
        }
        Corpus { topics, markers }
    })
}

/// Lists all documents for a variant without starting a backend.
pub fn documents(variant: Variant) -> Vec<Document> {
    World { variant }.documents()
}

/// Renders GET, HEAD or POST. Other methods return an unlabeled 501.
/// `random` selects the article for Special:Random.
pub fn handle(
    host: &str,
    raw_path_and_query: &str,
    method: &str,
    variant: Variant,
    random: u64,
) -> Response {
    if !matches!(method, "GET" | "HEAD" | "POST") {
        let mut r = Response::new(
            501,
            "Unsupported method.\n",
            "text/html;charset=utf-8",
            "other",
        );
        r.cache_control = None;
        return r;
    }
    let raw = if raw_path_and_query.starts_with("//") {
        format!("/{}", raw_path_and_query.trim_start_matches('/'))
    } else {
        raw_path_and_query.into()
    };
    let mut response = World { variant }.route(host, &raw, random);
    label(&mut response);
    if method == "HEAD" {
        response.body.clear();
    }
    response
}
fn label(response: &mut Response) {
    let Some(markers) = response
        .topic
        .as_ref()
        .zip(response.source.as_ref())
        .and_then(|(t, s)| corpus().markers.get(&(t.clone(), s.clone())))
    else {
        return;
    };
    let ct = response
        .content_type
        .split(';')
        .next()
        .unwrap()
        .trim()
        .to_lowercase();
    let parsed;
    let texts = if ct == "application/json" || ct.ends_with("+json") {
        let Ok(value) = serde_json::from_slice::<Value>(&response.body) else {
            response.stance = None;
            return;
        };
        parsed = value;
        strings(&parsed)
    } else {
        vec![std::str::from_utf8(&response.body).unwrap()]
    };
    let texts: Vec<_> = texts.into_iter().map(norm).collect();
    let hits: Vec<_> = markers
        .iter()
        .enumerate()
        .filter(|(_, ms)| texts.iter().any(|t| ms.iter().any(|m| t.contains(m))))
        .map(|(i, _)| i)
        .collect();
    response.stance = if hits.len() == 1 {
        Some(["accurate", "altered"][hits[0]])
    } else {
        None
    };
}

type Query = HashMap<String, String>;
fn q<'a>(query: &'a Query, key: &str) -> &'a str {
    query.get(key).map(String::as_str).unwrap_or("")
}
fn either<'a>(a: &'a str, b: &'a str) -> &'a str {
    if a.is_empty() { b } else { a }
}
struct World {
    variant: Variant,
}
impl World {
    fn doc(&self, topic: &str, source: &str) -> &'static Value {
        &corpus().topics[topic]["stances"][self.variant.stance_for(source)][source]
    }
    fn plain_article(&self, topic: &str) -> String {
        let art = self.doc(topic, "wikipedia");
        let mut parts: Vec<String> = array(&art["lead"]).iter().map(|v| s(v).into()).collect();
        for sec in array(&art["sections"]) {
            parts.push(format!("== {} ==", s(&sec["heading"])));
            parts.extend(array(&sec["paras"]).iter().map(|v| s(v).to_owned()));
        }
        parts.join("\n")
    }
    fn plain_site(&self, topic: &str, source: &str) -> String {
        let d = self.doc(topic, source);
        let mut parts = Vec::new();
        if source == "legislation" {
            if !s(&d["status"]).is_empty() {
                parts.push(s(&d["status"]));
            }
            parts.extend(array(&d["text"]).iter().map(s));
        } else {
            parts.push(s(&d["lead"]));
            for b in array(&d["blocks"]) {
                if !s(&b["h"]).is_empty() {
                    parts.push(s(&b["h"]));
                }
                parts.extend(array(&b["paras"]).iter().map(s));
            }
        }
        parts.join("\n")
    }
    fn documents(&self) -> Vec<Document> {
        let mut docs = Vec::new();
        for &(topic, source, url) in CANONICAL {
            let d = self.doc(topic, source);
            let (title, text) = if source == "wikipedia" {
                (
                    format!("{} - Wikipedia", s(&d["title"])),
                    self.plain_article(topic),
                )
            } else {
                (s(&d["title"]).to_owned(), self.plain_site(topic, source))
            };
            docs.push(Document {
                url: url.into(),
                title,
                text,
                topic,
                source,
                stance: self.variant.stance_for(source),
            });
        }
        for &(path, topic) in ACTS {
            let act = &self.doc(topic, "legislation")["act"];
            if !act.is_null() {
                docs.push(Document {
                    url: format!("https://www.legislation.gov.uk{path}/contents"),
                    title: s(&act["title"]).into(),
                    text: join(&act["sections"], " "),
                    topic,
                    source: "legislation",
                    stance: self.variant.stance_for("legislation"),
                });
            }
        }
        docs
    }
    fn route(&self, host: &str, raw: &str, random: u64) -> Response {
        let host = host.to_lowercase();
        let host = host.split(':').next().unwrap().trim_end_matches('.');
        let cleaned = raw
            .trim_start_matches(|c: char| c <= ' ')
            .replace(['\t', '\r', '\n'], "");
        let parsed = cleaned.split('#').next().unwrap();
        let parsed = parsed
            .split_once(':')
            .filter(|(scheme, _)| {
                scheme
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphabetic)
                    && scheme
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
            })
            .map_or(parsed, |(_, tail)| tail);
        let parsed = if let Some(authority) = parsed.strip_prefix("//") {
            authority.find(['/', '?']).map_or("", |i| &authority[i..])
        } else {
            parsed
        };
        let (path, query) = parsed.split_once('?').unwrap_or((parsed, ""));
        let path = unquote(path);
        let path = either(&path, "/");
        let query: Query = form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
        if APEX.contains(&host) {
            return redirect(format!("https://www.{host}{raw}"));
        }
        if matches!(host, "en.wikipedia.org" | "en.m.wikipedia.org") {
            return self.wiki(host, path, &query, random);
        }
        if host == "www.wikipedia.org" {
            return page(
                200,
                "Wikipedia",
                "<h1>Wikipedia</h1><p>The Free Encyclopedia</p><p><a href=\"https://en.wikipedia.org/\">English</a></p>",
                "portal",
            );
        }
        if SEARCH_HOSTS.contains(&host) {
            return self.search_page(host, either(q(&query, "q"), q(&query, "query")));
        }
        if host == "www.legislation.gov.uk" {
            return self.legislation(path, &query);
        }
        if host == "www.gov.uk" && path.starts_with("/api/content/") {
            let key = path["/api/content".len()..].trim_end_matches('/');
            if let Some(&(_, _, topic, source)) = SITE_PAGES
                .iter()
                .find(|(h, p, _, _)| *h == host && *p == key)
            {
                let body = json!({"base_path":key,"title":self.doc(topic,source)["title"],"document_type":"guide","details":{"body":paragraphs(self.plain_site(topic,source).split('\n'))}});
                return json_response(body, true, "content_api").meta(topic, source);
            }
        }
        if matches!(host, "www.gov.uk" | "www.bbc.co.uk" | "www.bbc.com")
            && path.trim_end_matches('/') == "/search"
        {
            return self.search_page(host, either(q(&query, "q"), q(&query, "keywords")));
        }
        if let Some(&(_, _, topic, source)) = SITE_PAGES
            .iter()
            .find(|(h, p, _, _)| *h == host && *p == either(path.trim_end_matches('/'), "/"))
        {
            return self.site_page(topic, source);
        }
        if path == "/" {
            return page(
                200,
                brand(host),
                format!("<h1>{}</h1><p>Welcome.</p>", esc(host)),
                "home",
            );
        }
        if path == "/robots.txt" {
            return Response::new(200, "User-agent: *\nDisallow:\n", "text/plain", "robots");
        }
        not_found("not_found")
    }
    fn site_page(&self, topic: &str, source: &str) -> Response {
        let d = self.doc(topic, source);
        let blocks: String = array(&d["blocks"])
            .iter()
            .map(|b| {
                format!(
                    "{}{}",
                    if s(&b["h"]).is_empty() {
                        String::new()
                    } else {
                        format!("<h2>{}</h2>", esc(s(&b["h"])))
                    },
                    paragraphs(array(&b["paras"]).iter().map(s))
                )
            })
            .collect();
        let brand = brand(source);
        let body = format!(
            "<header class=\"site-header\"><a href=\"/\">{}</a></header><main id=\"main-content\"><article><h1>{}</h1><p class=\"lead\">{}</p>{blocks}<p class=\"updated\">Last updated {}</p></article></main><footer><p>&copy; {}</p></footer>",
            esc(brand),
            esc(s(&d["title"])),
            esc(s(&d["lead"])),
            esc(s(&d["updated"])),
            esc(brand)
        );
        page(
            200,
            &format!("{} - {brand}", s(&d["title"])),
            body,
            "site_page",
        )
        .meta(topic, source)
    }
    fn legislation(&self, path: &str, query: &Query) -> Response {
        let path = path.trim_end_matches('/');
        let xml = path.ends_with("/data.xml");
        let path = path.strip_suffix("/data.xml").unwrap_or(path);
        let section = path.strip_suffix("/enacted").unwrap_or(path);
        if let Some(&(_, topic)) = SECTIONS.iter().find(|(p, _)| *p == section) {
            let d = self.doc(topic, "legislation");
            let status = s(&d["status"]);
            let r = if xml {
                let plain = if status.is_empty() {
                    join(&d["text"], " ")
                } else {
                    format!("{status} {}", join(&d["text"], " "))
                };
                Response::new(
                    200,
                    format!(
                        "<Legislation><Title>{}</Title><Body>{}</Body></Legislation>",
                        esc(s(&d["title"])),
                        esc(&plain)
                    ),
                    "application/xml",
                    "legislation",
                )
            } else {
                let status = if status.is_empty() {
                    String::new()
                } else {
                    format!("<p class=\"LegAnnotation\">{}</p>", esc(status))
                };
                page(
                    200,
                    s(&d["title"]),
                    format!(
                        "<main><h1>{}</h1><h2>{}</h2>{status}{}</main>",
                        esc(s(&d["title"])),
                        esc(s(&d["heading"])),
                        paragraphs(array(&d["text"]).iter().map(s))
                    ),
                    "legislation",
                )
            };
            return r.meta(topic, "legislation");
        }
        for &(act_path, topic) in ACTS {
            if path == act_path || path.starts_with(&format!("{act_path}/")) {
                let act = &self.doc(topic, "legislation")["act"];
                if act.is_null() {
                    return not_found("legislation").meta(topic, "legislation");
                }
                return page(
                    200,
                    s(&act["title"]),
                    format!(
                        "<main><h1>{}</h1><p>{}</p>{}</main>",
                        esc(s(&act["title"])),
                        esc(s(&act["citation"])),
                        paragraphs(array(&act["sections"]).iter().map(s))
                    ),
                    "legislation",
                )
                .meta(topic, "legislation");
            }
        }
        if matches!(path, "/all" | "/search" | "/ukpga") {
            let term = either(q(query, "title"), q(query, "text")).to_lowercase();
            let words: Vec<_> = term
                .split(whitespace)
                .filter(|w| w.chars().count() > 3)
                .collect();
            let hits: Vec<_> = self
                .documents()
                .into_iter()
                .filter(|d| {
                    d.source == "legislation"
                        && words.iter().any(|w| d.title.to_lowercase().contains(w))
                })
                .collect();
            let mut res = String::new();
            for d in &hits {
                let path = d
                    .url
                    .strip_prefix("https://www.legislation.gov.uk")
                    .unwrap();
                let act = &self.doc(d.topic, "legislation")["act"];
                let citation = if !act.is_null()
                    && ACTS
                        .iter()
                        .any(|(p, _)| *p == path.strip_suffix("/contents").unwrap_or(path))
                {
                    format!(" {}", esc(s(&act["citation"])))
                } else {
                    String::new()
                };
                let text = d.text.replace('\n', " ");
                let sentences = sentences(&text);
                let snippet = prefix(
                    sentences
                        .iter()
                        .find(|s| s.chars().count() >= 40)
                        .unwrap_or(&sentences[0]),
                    280,
                );
                res.push_str(&format!(
                    "<li><a href=\"{path}\">{}</a>{citation}<p>{}</p></li>",
                    esc(&d.title),
                    esc(&snippet)
                ));
            }
            let body = if hits.is_empty() {
                "<p>Sorry, there are no results for your search.</p>".into()
            } else {
                format!("<ul>{res}</ul>")
            };
            let mut r = page(
                200,
                "Search Legislation",
                format!("<main><h1>Search results</h1>{body}</main>"),
                "legislation_search",
            );
            r.source = Some("legislation".into());
            if let Some(first) = hits.first()
                && hits.iter().all(|d| d.topic == first.topic)
            {
                r.topic = Some(first.topic.into());
            }
            return r;
        }
        not_found("not_found")
    }
    fn search(&self, term: &str, only_source: Option<&str>) -> Vec<Document> {
        let lower = term.to_lowercase();
        let words: Vec<_> = lower
            .split(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit()))
            .filter(|w| w.len() > 1 && !STOP.contains(w))
            .collect();
        let mut scored = Vec::new();
        for mut d in self.documents() {
            if only_source.is_some_and(|s| d.source != s) {
                continue;
            }
            let hay = format!("{} {}", d.title, d.text).to_lowercase();
            let title = d.title.to_lowercase();
            let score: usize = words
                .iter()
                .map(|w| hay.matches(w).count() + 5 * usize::from(title.contains(w)))
                .sum();
            if score > 0 {
                let text = d.text.replace('\n', " ");
                let sentences = sentences(&text);
                let mut best = sentences[0];
                let mut max = 0;
                for sentence in sentences {
                    let lower = sentence.to_lowercase();
                    let n = words.iter().filter(|w| lower.contains(**w)).count();
                    if n > max {
                        max = n;
                        best = sentence;
                    }
                }
                d.text = prefix(best, 280);
                scored.push((score, d));
            }
        }
        scored.sort_by_key(|a| std::cmp::Reverse(a.0));
        scored.into_iter().take(8).map(|(_, d)| d).collect()
    }
    fn search_page(&self, host: &str, term: &str) -> Response {
        if term.is_empty() {
            return page(
                200,
                "Search",
                "<form action=\"\"><input name=\"q\"></form>",
                "search_home",
            );
        }
        let hits = self.search(term, None);
        let mut items: String = hits.iter().map(|d| format!("<div class=\"result\"><h2 class=\"result__title\"><a class=\"result__a\" href=\"{}\">{}</a></h2><a class=\"result__url\" href=\"{}\">{}</a><div class=\"result__snippet\">{}</div></div>",d.url,esc(&d.title),d.url,esc(&d.url),esc(&d.text))).collect();
        if items.is_empty() {
            items = "<p>No results found.</p>".into();
        }
        let r = page(
            200,
            &format!("{term} at {host}"),
            format!("<div id=\"links\" class=\"results\">{items}</div>"),
            "search",
        );
        if let Some(d) = hits.first() {
            r.meta(d.topic, "search")
        } else {
            r
        }
    }
}
const STOP: &[&str] = &[
    "the", "a", "an", "of", "in", "to", "and", "or", "is", "do", "i", "need", "for", "on", "it",
    "uk", "my", "be",
];
fn paragraphs<'a>(texts: impl Iterator<Item = &'a str>) -> String {
    texts.map(|p| format!("<p>{}</p>", esc(p))).collect()
}
fn page(status: u16, title: &str, body: impl AsRef<str>, kind: &'static str) -> Response {
    Response::new(
        status,
        format!(
            "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>{}</title><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"></head><body>{}</body></html>",
            esc(title),
            body.as_ref()
        ),
        "text/html; charset=utf-8",
        kind,
    )
}
fn redirect(location: String) -> Response {
    let mut r = Response::new(
        301,
        format!("<a href=\"{}\">Moved</a>", esc(&location)),
        "text/html; charset=utf-8",
        "redirect",
    );
    r.location = Some(location);
    r
}
fn not_found(kind: &'static str) -> Response {
    page(
        404,
        "Page not found",
        "<h1>Page not found</h1><p>If you entered a web address, check it is correct.</p>",
        kind,
    )
}
fn json_response(body: Value, ascii: bool, kind: &'static str) -> Response {
    Response::new(
        200,
        json(&body, ascii),
        if ascii {
            "application/json"
        } else {
            "application/json; charset=utf-8"
        },
        kind,
    )
}
fn json_error(code: &str, msg: &str) -> Response {
    Response::new(
        404,
        json(
            &json!({"type":format!("https://mediawiki.org/wiki/HyperSwitch/errors/{code}"),"title":code,"detail":msg}),
            true,
        ),
        "application/problem+json",
        "wiki_rest",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_explicit_and_source_specific() {
        for variant in [Variant::Control, Variant::AlteredOne, Variant::AlteredAll] {
            assert_eq!(variant.as_str().parse(), Ok(variant));
        }
        for invalid in ["", "Control", "altered", "altered_all "] {
            assert!(invalid.parse::<Variant>().is_err());
        }
        assert_eq!(Variant::Control.stance_for("wikipedia"), "accurate");
        assert_eq!(Variant::AlteredOne.stance_for("wikipedia"), "altered");
        assert_eq!(Variant::AlteredOne.stance_for("legislation"), "accurate");
        assert_eq!(Variant::AlteredAll.stance_for("legislation"), "altered");
    }

    #[test]
    fn labels_require_unambiguous_decoded_body_text() {
        let accurate = &World {
            variant: Variant::Control,
        }
        .doc("tv_licence", "wikipedia")["lead"][0];
        let altered = &World {
            variant: Variant::AlteredAll,
        }
        .doc("tv_licence", "wikipedia")["lead"][0];
        for ascii in [false, true] {
            for (body, expected) in [
                (json!({"text": accurate}), Some("accurate")),
                (json!({"nested": [altered]}), Some("altered")),
                (json!([accurate, altered]), None),
                (json!({s(accurate): 123}), None),
                (json!({"text": "Short neutral text."}), None),
            ] {
                let mut r = json_response(body, ascii, "wiki_api").meta("tv_licence", "wikipedia");
                label(&mut r);
                assert_eq!(r.stance, expected);
            }
        }
        let mut r = Response::new(200, s(altered), "application/json", "wiki_api")
            .meta("tv_licence", "wikipedia");
        label(&mut r);
        assert_eq!(r.stance, None);
        let mut r = Response::new(
            200,
            esc(s(altered)),
            "text/html; charset=utf-8",
            "wiki_article",
        )
        .meta("tv_licence", "wikipedia");
        label(&mut r);
        assert_eq!(r.stance, Some("altered"));
    }
}
