//! In-process pages from the deterministic offline generator.

pub mod make;
pub mod render;
pub mod seed;
pub mod text;

pub use seed::Seed;

use crate::route::{Engine, Route, query_key, route};
use fictionet::Cx;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Mutex, OnceLock};

/// A change to the stub's generation settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum Command {
    /// Make new result lists and pages, or serve only stored ones.
    SetGeneration {
        generate: bool,
        expected_revision: u64,
    },
}

/// The settings revision after an accepted command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Applied {
    pub revision: u64,
    /// Run time when the command was applied, in milliseconds.
    pub at_ms: u64,
}

/// A command that did not change the settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum Rejected {
    /// The caller's revision differs from the current settings revision.
    Stale { current: u64 },
}

/// The current generation setting and its revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Generation {
    pub generate: bool,
    pub revision: u64,
}
impl Default for Generation {
    fn default() -> Self {
        Self {
            generate: true,
            revision: 0,
        }
    }
}

/// A backend answer before its metadata is moved to the request event.
#[derive(Clone, Debug)]
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// Media type and optional charset.
    pub content_type: String,
    /// Full page bytes, including for HEAD requests.
    pub body: Vec<u8>,
    /// Extra headers, excluding content type and content length.
    pub headers: Vec<(String, String)>,
    /// Parsed metadata for query facts and response event fields.
    pub meta: Value,
}
impl Response {
    fn html(body: impl Into<String>, meta: Value, status: u16, server: &str) -> Self {
        Self {
            status,
            content_type: "text/html; charset=utf-8".into(),
            body: body.into().into_bytes(),
            headers: vec![("Server".into(), server.into())],
            meta,
        }
    }
    fn budget(kind: &str) -> Self {
        Self::html(
            "Generation budget exhausted",
            json!({"kind":kind,"cache":"budget"}),
            503,
            "nginx",
        )
    }
}
struct StoredPage {
    host: String,
    target: String,
    url: String,
    title: String,
    description: String,
    response: Response,
}
#[derive(Default)]
struct Store {
    generation: Generation,
    pages: Vec<StoredPage>,
    mentions: Vec<((String, String), Vec<Value>)>,
    sites: Vec<(String, make::Profile)>,
    searches: Vec<(String, make::Search, u64)>,
    claims: Vec<Value>,
    generations: usize,
    cast: bool,
}
impl Store {
    fn page(&self, host: &str, target: &str) -> Option<&StoredPage> {
        self.pages
            .iter()
            .find(|p| p.host == host && p.target == target)
    }
    fn mentions(&self, host: &str, target: &str) -> &[Value] {
        self.mentions
            .iter()
            .find(|((h, t), _)| h == host && t == target)
            .map_or(&[], |(_, ms)| ms)
    }
    fn add_mention(&mut self, host: &str, target: &str, mention: Value) {
        if let Some((_, mentions)) = self
            .mentions
            .iter_mut()
            .find(|((h, t), _)| h == host && t == target)
        {
            if !mentions.contains(&mention) {
                mentions.push(mention);
            }
        } else {
            self.mentions
                .push(((host.into(), target.into()), vec![mention]));
        }
    }
    fn reserve_mention(
        &mut self,
        seed: &Seed,
        host: &str,
        target: &str,
        mut mention: Value,
    ) -> Value {
        let page = self.page(host, target).filter(|p| !p.title.is_empty());
        let metadata = page
            .map(|p| (p.title.as_str(), p.description.as_str()))
            .or_else(|| {
                seed.fixed_for(host, target)
                    .map(|p| (p.title.as_str(), p.description.as_str()))
            });
        if let Some((title, description)) = metadata {
            if !title.is_empty() {
                mention["title"] = title.into();
            }
            if !description.is_empty() {
                mention["snippet"] = description.into();
            }
        } else if let Some(title) = self
            .mentions(host, target)
            .iter()
            .filter_map(|m| m["title"].as_str())
            .find(|s| !s.is_empty())
        {
            mention["title"] = title.into();
        }
        self.add_mention(host, target, mention.clone());
        mention
    }
    fn reserve(&mut self) -> bool {
        if self.generations == 200 {
            return false;
        }
        self.generations += 1;
        true
    }
    fn begin_generation(&mut self) -> bool {
        if !self.reserve() {
            return false;
        }
        if !self.cast {
            if !self.reserve() {
                return false;
            }
            self.cast = true;
        }
        true
    }
    fn known(&self, seed: &Seed) -> Vec<make::Result> {
        let mut known: Vec<_> = seed
            .fixed
            .iter()
            .map(|f| make::Result {
                url: f.url.clone(),
                title: f.title.clone(),
                snippet: f.description.clone(),
                date: String::new(),
            })
            .collect();
        known.extend(
            self.pages[self.pages.len().saturating_sub(40)..]
                .iter()
                .filter(|p| p.response.status == 200 && !p.title.is_empty())
                .map(|p| make::Result {
                    url: p.url.clone(),
                    title: p.title.clone(),
                    snippet: p.description.clone(),
                    date: String::new(),
                }),
        );
        known
    }
    fn site_once(&mut self, host: &str) -> &make::Profile {
        let index = self
            .sites
            .iter()
            .position(|(h, _)| h == host)
            .unwrap_or_else(|| {
                let mut profile = make::site_profile(host);
                profile.style = self.sites.len();
                self.sites.push((host.into(), profile));
                self.sites.len() - 1
            });
        &self.sites[index].1
    }
    fn note_links(&mut self, url: &str, markup: &str) {
        for (host, target, anchor) in links(url, markup) {
            if self.page(&host, &target).is_none() {
                self.add_mention(
                    &host,
                    &target,
                    json!({"via":"link","from":url,"anchor":anchor}),
                );
            }
        }
    }
}

/// Returns host, target and anchor tuples under Python's link rules, in source order.
pub fn links(url: &str, markup: &str) -> Vec<(String, String, String)> {
    static LINK: OnceLock<Regex> = OnceLock::new();
    let link = LINK.get_or_init(|| {
        Regex::new(r#"(?is)<a\b[^>]*\bhref\s*=\s*["']([^"'#]+)[^"']*["'][^>]*>(.*?)</a>"#).unwrap()
    });
    link.captures_iter(markup)
        .take(80)
        .filter_map(|c| {
            let absolute = text::join(url, &text::unescape(text::strip(&c[1])))?;
            if !absolute.starts_with("http://") && !absolute.starts_with("https://") {
                return None;
            }
            let (host, target) = text::target_of(&absolute);
            if host.is_empty()
                || [
                    "www.google.com",
                    "google.com",
                    "html.duckduckgo.com",
                    "duckduckgo.com",
                    "lite.duckduckgo.com",
                    "www.bing.com",
                    "bing.com",
                ]
                .contains(&host.as_str())
            {
                return None;
            }
            let anchor = text::take(&text::text_of(&c[2]), 160);
            (!anchor.is_empty()).then_some((host, target, anchor))
        })
        .collect()
}
fn asked_mentions(mentions: &[Value]) -> Vec<Value> {
    let mut links = 0;
    mentions
        .iter()
        .filter(|m| {
            if m["via"] == "link" {
                links += 1;
                links <= 8
            } else {
                true
            }
        })
        .cloned()
        .collect()
}

/// An in-memory world with the same fresh-store behavior as the Python stub.
/// One mutex holds creation, title reservation, and outgoing link publication.
pub struct Stub {
    seed: Seed,
    store: Mutex<Store>,
}
impl Stub {
    /// Creates an empty store for the seed.
    pub fn new(seed: Seed) -> Self {
        Self {
            seed,
            store: Mutex::new(Store::default()),
        }
    }
    /// Returns the seed used by this world.
    pub fn seed(&self) -> &Seed {
        &self.seed
    }

    /// Applies a command against the current revision, without clearing pages.
    /// Only a changed setting advances the revision and emits an event.
    pub fn apply(&self, fcx: &Cx, command: Command) -> Result<Applied, Rejected> {
        let Command::SetGeneration {
            generate,
            expected_revision,
        } = command;
        let mut store = self.store.lock().unwrap();
        let generation = &mut store.generation;
        if expected_revision != generation.revision {
            return Err(Rejected::Stale {
                current: generation.revision,
            });
        }
        if generate != generation.generate {
            generation.generate = generate;
            generation.revision += 1;
            fcx.emit("adaptive", "generation", |event| {
                event
                    .summary(format_args!(
                        "generation {} at revision {}",
                        if generate { "enabled" } else { "disabled" },
                        generation.revision
                    ))
                    .field("generate", generate)
                    .field("revision", generation.revision)
            });
        }
        Ok(Applied {
            revision: generation.revision,
            at_ms: fcx.now().since_start().as_millis() as u64,
        })
    }

    /// Returns the generation setting without reading or writing files.
    pub fn generation(&self) -> Generation {
        self.store.lock().unwrap().generation
    }

    /// Answers a request without real I/O. Supply form bytes for form POSTs.
    pub fn handle(
        &self,
        cx: &Cx,
        method: &str,
        host: &str,
        target: &str,
        form: Option<&[u8]>,
    ) -> Response {
        let form = if method == "POST" {
            form.map(|f| &f[..f.len().min(1 << 20)])
        } else {
            None
        };
        let route = route(host, target, form);
        self.handle_route(cx, host, target, route)
    }
    /// Answers an already routed request and measures time on the run's clock.
    pub(crate) fn handle_route(&self, cx: &Cx, host: &str, target: &str, route: Route) -> Response {
        let started = cx.now().since_start();
        let mut response = self.answer(cx, &host.to_lowercase(), target, route);
        response.meta["serve_ms"] = json!((cx.now().since_start() - started).as_millis() as u64);
        response
    }
    fn answer(&self, cx: &Cx, host: &str, target: &str, route: Route) -> Response {
        match route {
            Route::Redirect { location, status } => {
                let body = format!(
                    "<html><head><title>{status} Moved</title></head><body><a href=\"{}\">here</a></body></html>",
                    text::escape(&location)
                );
                Response {
                    status,
                    content_type: "text/html; charset=utf-8".into(),
                    body: body.into_bytes(),
                    headers: vec![("Location".into(), location.clone())],
                    meta: json!({"kind":"redirect","location":location}),
                }
            }
            Route::SearchHome { engine } => Response::html(
                match engine {
                    Engine::Google => render::google_home(),
                    _ => render::duckduckgo_home(),
                },
                json!({"kind":"search_home"}),
                200,
                render::engine_server(engine),
            ),
            Route::Search {
                engine,
                query,
                start,
            } => self.search(cx, engine, &query, start),
            Route::Page => {
                if self.seed.fixed_for(host, target).is_none()
                    && let Some(asset) = static_asset(target.split('?').next().unwrap())
                {
                    return asset;
                }
                self.page(cx, host, target)
            }
        }
    }
    fn search(&self, cx: &Cx, engine: Engine, query: &str, start: u64) -> Response {
        let key = query_key(query, start);
        let mut store = self.store.lock().unwrap();
        let cached = store.searches.iter().position(|(k, _, _)| k == &key);
        let index = if let Some(i) = cached {
            i
        } else {
            if !store.generation.generate {
                let search = make::Search {
                    results: vec![],
                    related: vec![],
                    questions: vec![],
                    ads: vec![],
                };
                return Response::html(
                    render::search(engine, query, &search, start),
                    json!({"kind":"search","engine":engine.as_str(),"search":query,"cache":"missing","model":null,"results":0,"listed":[]}),
                    200,
                    render::engine_server(engine),
                );
            }
            if !store.begin_generation() {
                return Response::budget("search");
            }
            let started = cx.now().since_start();
            let mut search = make::search(&self.seed, query, &store.known(&self.seed));
            let ms = (cx.now().since_start() - started).as_millis() as u64;
            let mut results: Vec<make::Result> = Vec::new();
            for mut r in search.results {
                let (host, target) = text::target_of(&r.url);
                if host.is_empty() || results.iter().any(|x| x.url == r.url) {
                    continue;
                }
                let mention=store.reserve_mention(&self.seed,&host,&target,json!({"via":"search","query":query,"rank":results.len()+1,"title":r.title,"snippet":r.snippet,"date":r.date}));
                r.title = mention["title"].as_str().unwrap().into();
                r.snippet = mention["snippet"].as_str().unwrap().into();
                results.push(r);
            }
            search.results = results;
            store.searches.push((key, search, ms));
            store.searches.len() - 1
        };
        let (_, search, ms) = &store.searches[index];
        let body = render::search(engine, query, search, start);
        let listed: Vec<_> = search
            .results
            .iter()
            .enumerate()
            .map(|(i, r)| json!({"rank":i+1,"url":r.url,"title":r.title}))
            .collect();
        let mut meta = json!({"kind":"search","engine":engine.as_str(),"search":query,"cache":if cached.is_some(){"cached"}else{"generated"},"model":"stub","results":search.results.len(),"listed":listed});
        if cached.is_none() {
            meta["gen_ms"] = json!(ms);
            meta["cost"] = Value::Null;
        }
        Response::html(body, meta, 200, render::engine_server(engine))
    }
    fn page(&self, cx: &Cx, host: &str, target: &str) -> Response {
        let mut store = self.store.lock().unwrap();
        if let Some(page) = store.page(host, target) {
            let mut response = page.response.clone();
            if response.meta["cache"] != "fixed" {
                response.meta["cache"] = "cached".into();
                let meta = response.meta.as_object_mut().unwrap();
                meta.shift_remove("gen_ms");
                meta.shift_remove("cost");
            }
            return response;
        }
        if !store.generation.generate {
            let profile = store.sites.iter().find(|(h, _)| h == host).map(|(_, p)| p);
            return Response::html(
                render::not_found(host, profile, target, &self.seed.date[..4]),
                json!({"kind":"page","cache":"missing"}),
                404,
                render::server_of(profile),
            );
        }
        let (url, title, description, response) = if let Some(fixed) =
            self.seed.fixed_for(host, target)
        {
            (
                fixed.url.clone(),
                fixed.title.clone(),
                fixed.description.clone(),
                Response {
                    status: 200,
                    content_type: fixed.content_type.clone(),
                    body: fixed.body.clone(),
                    headers: vec![("Server".into(), "nginx".into())],
                    meta: json!({"kind":"page","cache":"fixed","title":fixed.title,"reason":{"via":"fixed"}}),
                },
            )
        } else {
            if !store.begin_generation() {
                return Response::budget("page");
            }
            let url = format!("https://{host}{target}");
            let mentions = asked_mentions(store.mentions(host, target));
            let host_pages = store
                .pages
                .iter()
                .filter(|p| p.host == host)
                .take(20)
                .count();
            let started = cx.now().since_start();
            let mut page = make::page(&self.seed, host, target, &mentions, host_pages);
            let ms = (cx.now().since_start() - started).as_millis() as u64;
            if let Some(title) = mentions
                .iter()
                .filter_map(|m| m["title"].as_str())
                .find(|s| !s.is_empty())
            {
                page.title = title.into();
            }
            let profile = store.site_once(host);
            let html = page.content_type.starts_with("text/html");
            let body = if html {
                render::page(host, profile, &page, &self.seed.date[..4])
            } else {
                page.body.clone()
            };
            let tells = text::tells(&if html {
                text::text_of(&page.body)
            } else {
                body.clone()
            });
            let (unsupported, unchecked) =
                text::rescore_snippets(&body, &page.content_type, &mentions);
            let first = mentions
                .first()
                .cloned()
                .unwrap_or_else(|| json!({"via":"direct"}));
            let reason: serde_json::Map<_, _> = ["via", "query", "rank", "from"]
                .into_iter()
                .filter_map(|k| first.get(k).map(|v| (k.to_owned(), v.clone())))
                .collect();
            let response = Response {
                status: page.status,
                content_type: page.content_type,
                body: body.into_bytes(),
                headers: vec![("Server".into(), render::server_of(Some(profile)).into())],
                meta: json!({"kind":"page","cache":"generated","title":page.title,"model":"stub","prefetched":false,"claims":page.claims,"mentions":mentions.len(),"unsupported_snippets":unsupported,"unchecked_snippets":unchecked,"tells":tells,"reason":reason,"gen_ms":ms,"cost":null}),
            };
            store
                .claims
                .extend(page.claims.iter().map(|c| json!({"url":url,"claim":c})));
            (url, page.title, page.description, response)
        };
        store.pages.push(StoredPage {
            host: host.into(),
            target: target.into(),
            url: url.clone(),
            title,
            description,
            response: response.clone(),
        });
        if response.content_type.starts_with("text/html") {
            store.note_links(&url, &String::from_utf8_lossy(&response.body));
        }
        response
    }
}

fn static_asset(path: &str) -> Option<Response> {
    let pixel=b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;";
    let (ctype, body): (&str, &[u8]) = if path == "/robots.txt" {
        ("text/plain; charset=utf-8", b"User-agent: *\nAllow: /\n")
    } else {
        let (base, ext) = path.rsplit_once('.')?;
        if ext.contains('/') || base.is_empty() {
            return None;
        }
        match ext.to_lowercase().as_str() {
            "css" => ("text/css", b"/* site styles */\n"),
            "js" => ("application/javascript", b"/* site scripts */\n"),
            "gif" | "png" | "jpg" | "jpeg" | "webp" | "svg" | "ico" => ("image/gif", pixel),
            "woff" => ("font/woff", b""),
            "woff2" => ("font/woff2", b""),
            _ => return None,
        }
    };
    Some(Response {
        status: 200,
        content_type: ctype.into(),
        body: body.into(),
        headers: vec![],
        meta: json!({"kind":"asset"}),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn routed_hosts_share_the_lowercase_page() {
        fictionet::block_on(fictionet::lab(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(1)),
            |cx| async move {
                let stub = Stub::new(Seed::builtin("halvard-cve").unwrap());
                let first = stub.handle_route(&cx, "UPPER.IO", "/page.json", Route::Page);
                let second = stub.handle(&cx, "GET", "upper.io", "/page.json", None);
                assert_eq!(first.body, second.body);
                assert_eq!(second.meta["cache"], "cached");
                assert_eq!(
                    serde_json::from_slice::<Value>(&first.body).unwrap()["url"],
                    "https://upper.io/page.json"
                );
                Ok(())
            },
        ))
        .unwrap();
    }
    #[test]
    fn mentions_reserve_titles_and_keep_creation_order() {
        let seed = Seed::builtin("halvard-cve").unwrap();
        let mut store = Store::default();
        store.add_mention(
            "site.com",
            "/p",
            json!({"via":"link","from":"https://source.com/","anchor":"An anchor"}),
        );
        let first = json!({"via":"search","query":"first","title":"First title","snippet":"First snippet","rank":2});
        store.reserve_mention(&seed, "site.com", "/p", first.clone());
        store.reserve_mention(&seed, "site.com", "/p", first);
        let later=store.reserve_mention(&seed,"site.com","/p",json!({"via":"search","query":"second","title":"Different title","snippet":"Second snippet","rank":1}));
        assert_eq!(later["title"], "First title");
        assert_eq!(later["snippet"], "Second snippet");
        assert_eq!(store.mentions("site.com", "/p").len(), 3);
        assert_eq!(store.mentions("site.com", "/p")[0]["via"], "link");
        let f = &seed.fixed[0];
        let reserved = store.reserve_mention(
            &seed,
            &f.host,
            &f.target,
            json!({"via":"search","title":"wrong","snippet":"wrong"}),
        );
        assert_eq!(reserved["title"], f.title);
        assert_eq!(reserved["snippet"], f.description);
    }
    #[test]
    fn links_bound_candidates_before_filtering_and_cut_characters() {
        let mut html = "<a href=\"mailto:skip@site.com\">skip</a>".repeat(79);
        html.push_str(&format!(
            "<a href=\"../é?q=1&amp;x=2#frag\"><b>{}</b></a>",
            "😀".repeat(170)
        ));
        html.push_str("<a href=\"/too-late\">late</a>");
        assert_eq!(
            links("https://site.com/a/b", &html),
            vec![("site.com".into(), "/é?q=1&x=2".into(), "😀".repeat(160))]
        );
        let html = "<a href='/empty'> <b></b> </a><a href='https://www.google.com/search?q=a'>Search</a><a href='/ok'>one &amp; two</a>";
        assert_eq!(
            links("https://site.com/", html),
            vec![("site.com".into(), "/ok".into(), "one & two".into())]
        );
        let mut mentions = Vec::new();
        for n in 0..12 {
            mentions.push(json!({"via":"link","anchor":n}));
            mentions.push(json!({"via":"search","title":n}));
        }
        let asked = asked_mentions(&mentions);
        assert_eq!(asked.len(), 20);
        assert_eq!(asked.iter().filter(|m| m["via"] == "link").count(), 8);
        assert_eq!(asked.last().unwrap()["title"], 11);
    }
    #[test]
    fn concurrent_requests_make_one_page() {
        let stub = std::sync::Arc::new(Stub::new(Seed::builtin("halvard-cve").unwrap()));
        fictionet::block_on(fictionet::lab(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(1)),
            |cx| async move {
                let replies = std::thread::scope(|scope| {
                    let tasks: Vec<_> = (0..8)
                        .map(|_| {
                            let stub = &stub;
                            let cx = &cx;
                            scope.spawn(move || {
                                stub.handle(cx, "GET", "same-page.io", "/same", None)
                            })
                        })
                        .collect();
                    tasks
                        .into_iter()
                        .map(|t| t.join().unwrap())
                        .collect::<Vec<_>>()
                });
                assert_eq!(
                    replies
                        .iter()
                        .filter(|r| r.meta["cache"] == "generated")
                        .count(),
                    1
                );
                assert!(replies.iter().all(|r| r.body == replies[0].body));
                let store = stub.store.lock().unwrap();
                assert_eq!(store.generations, 2);
                assert_eq!(store.pages.len(), 1);
                assert_eq!(store.sites.len(), 1);
                Ok(())
            },
        ))
        .unwrap();
    }
}
