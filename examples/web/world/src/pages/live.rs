//! Search on the host; replay only URLs reached by those results and their crawl.

use super::*;
use fictionet_extras::{
    capture::{self, Fetcher},
    models::{Key, Provider as ModelProvider},
    warc::{self, Archive},
};
use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio::sync::{oneshot, watch};

struct Job {
    url: String,
    navigation: Option<(String, u8)>,
    redirects: u8,
    cx: Cx,
}

#[derive(Default)]
struct State {
    archive: Archive,
    reached: HashMap<String, watch::Sender<bool>>,
    depths: HashMap<(String, String), u8>,
    queue: VecDeque<Job>,
    running: bool,
    searches: HashMap<(String, u64), search::Search>,
}

pub(super) struct Live {
    key: Key,
    engine: Key,
    endpoint: url::Url,
    path: PathBuf,
    state: Mutex<State>,
    fetcher: Mutex<Option<Fetcher>>,
}

impl Live {
    fn new(root: &Path) -> Result<Arc<Self>, String> {
        let key = Key::new(
            "GOOGLE_SEARCH_API_KEY",
            std::env::var("GOOGLE_SEARCH_API_KEY").ok(),
        )?;
        let engine = Key::new(
            "GOOGLE_SEARCH_ENGINE_ID",
            std::env::var("GOOGLE_SEARCH_ENGINE_ID").ok(),
        )?;
        std::fs::create_dir_all(root).map_err(|e| e.to_string())?;
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos();
        Ok(Arc::new(Self {
            key,
            engine,
            endpoint: url::Url::parse("https://customsearch.googleapis.com/customsearch/v1")
                .unwrap(),
            path: root.join(format!(
                "live-search-{}-{stamp}.warc.gz",
                std::process::id()
            )),
            state: Mutex::default(),
            fetcher: Mutex::default(),
        }))
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn enqueue(self: &Arc<Self>, job: Job, priority: bool) {
        let Some(url) = warc::key(&job.url) else {
            return;
        };
        let mut state = self.state();
        let newly_reached = !state.reached.contains_key(&url);
        let shallower = job.navigation.as_ref().is_some_and(|(site, depth)| {
            let entry = state
                .depths
                .entry((url.clone(), site.clone()))
                .or_insert(u8::MAX);
            if *entry <= *depth {
                false
            } else {
                *entry = *depth;
                true
            }
        });
        if !newly_reached && !shallower {
            return;
        }
        state
            .reached
            .entry(url)
            .or_insert_with(|| watch::channel(false).0);
        if priority {
            state.queue.push_front(job);
        } else {
            state.queue.push_back(job);
        }
        if !state.running {
            state.running = true;
            let live = self.clone();
            std::thread::spawn(move || live.download());
        }
    }

    fn download(self: Arc<Self>) {
        let mut transport = self.fetcher.lock().unwrap_or_else(|e| e.into_inner());
        let fetcher = match transport
            .take()
            .map(Ok)
            .unwrap_or_else(|| Fetcher::new(capture::BROWSER))
        {
            Ok(fetcher) => fetcher,
            Err(_) => {
                let mut state = self.state();
                for job in state.queue.drain(..).collect::<Vec<_>>() {
                    Self::activity(&job.cx, "download_failed", &job.url, None, 0);
                    if let Some(done) = state.reached.get(&job.url) {
                        done.send_replace(true);
                    }
                }
                state.running = false;
                return;
            }
        };
        *transport = Some(fetcher);
        let fetcher = transport.as_mut().unwrap();
        loop {
            let job = {
                let mut state = self.state();
                let Some(job) = state.queue.pop_front() else {
                    state.running = false;
                    return;
                };
                job
            };
            if job.cx.is_cancelled() {
                let mut state = self.state();
                state.queue.clear();
                for done in state.reached.values() {
                    done.send_replace(true);
                }
                state.running = false;
                return;
            }
            let started = Instant::now();
            let existing = self.state().archive.get(&job.url);
            let result = match existing {
                Ok(Some(response)) => Ok((response, false)),
                Ok(None) => fetcher.fetch(&job.url).map(|response| (response, true)),
                Err(error) => Err(error),
            };
            match result {
                Ok((response, downloaded)) => {
                    let saved = !downloaded
                        || self
                            .state()
                            .archive
                            .append(&self.path, &job.url, &response)
                            .is_ok();
                    if saved {
                        if downloaded {
                            Self::activity(
                                &job.cx,
                                "downloaded",
                                &job.url,
                                Some(response.status.as_u16()),
                                started.elapsed().as_millis() as u64,
                            );
                        }
                        if let Ok(links) = capture::links(&job.url, &response) {
                            // Dependencies get priority over the next navigation page.
                            for url in links.assets.into_iter().rev() {
                                self.enqueue(
                                    Job {
                                        url,
                                        navigation: None,
                                        redirects: 0,
                                        cx: job.cx.clone(),
                                    },
                                    true,
                                );
                            }
                            if response.status.is_redirection() && job.redirects < 10 {
                                for url in links.pages {
                                    self.enqueue(
                                        Job {
                                            url,
                                            navigation: job.navigation.clone(),
                                            redirects: job.redirects + 1,
                                            cx: job.cx.clone(),
                                        },
                                        true,
                                    );
                                }
                            } else if let Some((site, depth)) = &job.navigation
                                && *depth < 5
                            {
                                for url in links.pages.into_iter().filter(|u| {
                                    url::Url::parse(u).ok().is_some_and(|u| {
                                        u.host_str().is_some_and(|host| {
                                            host.trim_start_matches("www.")
                                                == site.trim_start_matches("www.")
                                        })
                                    })
                                }) {
                                    self.enqueue(
                                        Job {
                                            url,
                                            navigation: Some((site.clone(), depth + 1)),
                                            redirects: 0,
                                            cx: job.cx.clone(),
                                        },
                                        false,
                                    );
                                }
                            }
                        }
                    } else {
                        Self::activity(
                            &job.cx,
                            "download_failed",
                            &job.url,
                            None,
                            started.elapsed().as_millis() as u64,
                        );
                    }
                }
                Err(_) => Self::activity(&job.cx, "download_failed", &job.url, None, 0),
            }
            if let Some(done) = self.state().reached.get(&job.url) {
                done.send_replace(true);
            }
        }
    }

    fn activity(cx: &Cx, kind: &'static str, url: &str, status: Option<u16>, elapsed_ms: u64) {
        cx.emit("web", kind, |event| {
            event
                .summary(format_args!("{kind}: {url}"))
                .field("url", url)
                .field("status", status.unwrap_or(0) as u64)
                .field("elapsed_ms", elapsed_ms)
        });
    }

    async fn search(
        self: &Arc<Self>,
        cx: &Cx,
        engine: Engine,
        query: &str,
        start: u64,
    ) -> Result<search::Search, String> {
        cx.require_real_io().map_err(|e| e.to_string())?;
        if start > 90 {
            return Ok(search::Search::default());
        }
        let (send, receive) = oneshot::channel();
        let live = self.clone();
        let cx_thread = cx.clone();
        let query = query.to_owned();
        std::thread::spawn(move || {
            let result = (|| {
                let fetcher = Fetcher::new(capture::BROWSER).map_err(|e| e.to_string())?;
                let mut endpoint = live.endpoint.clone();
                let (_, key) = live.key.header(ModelProvider::Gemini);
                let (_, engine_id) = live.engine.header(ModelProvider::Gemini);
                endpoint.query_pairs_mut().extend_pairs([
                    ("key", key.as_str()),
                    ("cx", engine_id.as_str()),
                    ("q", query.as_str()),
                    ("start", &(start + 1).to_string()),
                    ("num", &(99 - start).min(10).to_string()),
                ]);
                cx_thread.emit("web", "real_search", |event| {
                    event
                        .summary(format_args!("Query sent to Google: {query}"))
                        .field("search", query.as_str())
                        .field("engine", example_common::names::name(&engine))
                        .field("start", start)
                });
                let response = fetcher
                    .api(endpoint.as_str())
                    .map_err(|_| "Google search API request failed".to_owned())?;
                if !response.status.is_success() {
                    return Err(format!("Google search API returned {}", response.status));
                }
                let value: Value =
                    serde_json::from_slice(&response.decoded().map_err(|e| e.to_string())?)
                        .map_err(|_| "Invalid Google search response")?;
                let search = parse_results(&value)?;
                live.state()
                    .searches
                    .insert((query.clone(), start), search.clone());
                for result in search.results.iter().rev() {
                    if let Ok(url) = url::Url::parse(&result.url)
                        && let Some(host) = url.host_str()
                    {
                        live.enqueue(
                            Job {
                                url: result.url.clone(),
                                navigation: Some((host.to_owned(), 0)),
                                redirects: 0,
                                cx: cx_thread.clone(),
                            },
                            true,
                        );
                    }
                }
                Ok(search)
            })();
            let _ = send.send(result);
        });
        cx.race(Some(cx.now() + Duration::from_secs(30)), receive)
            .await
            .map_err(|_| "Live search timed out or was cancelled".to_owned())?
            .map_err(|_| "Live search worker stopped".to_owned())?
    }

    async fn response(&self, cx: &Cx, url: &str) -> Option<warc::Response> {
        let url = warc::key(url)?;
        let mut waiting = {
            let mut state = self.state();
            // Browser requests can prioritize an already reached URL, never admit one.
            let waiting = state.reached.get(&url)?.subscribe();
            if let Some(index) = state.queue.iter().position(|job| job.url == url) {
                let job = state.queue.remove(index).unwrap();
                state.queue.push_front(job);
            }
            waiting
        };
        let ready = async {
            loop {
                if *waiting.borrow_and_update() {
                    break;
                }
                if waiting.changed().await.is_err() {
                    break;
                }
            }
        };
        let _ = cx
            .race(Some(cx.now() + Duration::from_secs(45)), ready)
            .await;
        let response = self.state().archive.get(&url).ok().flatten();
        if let Some(response) = &response {
            Self::activity(cx, "copy_served", &url, Some(response.status.as_u16()), 0);
        }
        response
    }
}

fn parse_results(value: &Value) -> Result<search::Search, String> {
    if value.get("error").is_some() || value.get("searchInformation").is_none() {
        return Err("Invalid Google search response".into());
    }
    let mut search = search::Search::default();
    if let Some(items) = value.get("items") {
        for item in items
            .as_array()
            .ok_or("Invalid Google search items")?
            .iter()
            .take(10)
        {
            let url = item["link"]
                .as_str()
                .and_then(warc::key)
                .ok_or("Invalid Google result URL")?;
            search.results.push(search::Result {
                url,
                title: item["title"]
                    .as_str()
                    .ok_or("Missing Google result title")?
                    .to_owned(),
                snippet: item["snippet"].as_str().unwrap_or_default().to_owned(),
                ..Default::default()
            });
        }
    }
    Ok(search)
}

impl Pages {
    /// Configure host search from environment credentials. The World menu selects it.
    pub fn with_live_search(mut self, downloads: &Path) -> Result<Self, String> {
        self.live = Some(Live::new(downloads)?);
        Ok(self)
    }

    pub(crate) fn live_only(&self) -> bool {
        self.live_active.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(crate) async fn live_url(&self, cx: &Cx, url: &str) -> Response {
        copied::replay(url, Ok(self.live.as_ref().unwrap().response(cx, url).await))
    }

    pub(super) async fn live_listing(
        &self,
        cx: &Cx,
        engine: Engine,
        query: &str,
        start: u64,
    ) -> Result<(search::Search, Cache, Option<Usage>, u64), Stop> {
        if !self.generation().generate {
            return Ok((
                self.live
                    .as_ref()
                    .unwrap()
                    .state()
                    .searches
                    .get(&(query.to_owned(), start))
                    .cloned()
                    .unwrap_or_default(),
                Cache::Cached,
                None,
                0,
            ));
        }
        self.live
            .as_ref()
            .unwrap()
            .search(cx, engine, query, start)
            .await
            .map(|search| (search, Cache::Fixed, None, 0))
            .map_err(|error| Stop::Failed { error, usage: None })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_redirects_do_not_grant_a_crawl_of_another_site() {
        use std::{
            io::{BufRead, BufReader, Write},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let origin = format!("http://127.0.0.1:{port}/");
        let landing = format!("http://localhost:{port}/landing");
        let location = landing.clone();
        let (send, receive) = oneshot::channel();
        let server = std::thread::spawn(move || {
            for _ in 0..4 {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut reader = BufReader::new(socket.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let target = line.split_whitespace().nth(1).unwrap().to_owned();
                loop {
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                }
                let (status, extra, body) = match target.as_str() {
                    "/robots.txt" => (200, String::new(), "User-agent: *\nAllow: /\n"),
                    "/" => (302, format!("Location: {location}\r\n"), ""),
                    "/landing" => (
                        200,
                        String::new(),
                        "<title>Landing</title><a href='/escape'>Another site page</a>",
                    ),
                    _ => panic!("only the result redirect and landing page are reached"),
                };
                write!(socket, "HTTP/1.1 {status} OK\r\n{extra}Content-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
            let _ = send.send(());
        });
        let path = std::env::temp_dir().join(format!(
            "fictionet-live-redirect-{}.warc.gz",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let live = Arc::new(Live {
            key: Key::new("GOOGLE_SEARCH_API_KEY", Some("private".into())).unwrap(),
            engine: Key::new("GOOGLE_SEARCH_ENGINE_ID", Some("engine".into())).unwrap(),
            endpoint: "https://customsearch.googleapis.com/customsearch/v1"
                .parse()
                .unwrap(),
            path: path.clone(),
            state: Mutex::default(),
            fetcher: Mutex::default(),
        });
        fictionet::block_on(fictionet::run(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(6)),
            |cx| async move {
                live.enqueue(
                    Job {
                        url: origin.clone(),
                        navigation: Some(("127.0.0.1".into(), 0)),
                        redirects: 0,
                        cx: cx.clone(),
                    },
                    true,
                );
                cx.race(Some(cx.now() + Duration::from_secs(10)), receive)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    live.response(&cx, &origin).await.unwrap().status.as_u16(),
                    302
                );
                assert_eq!(
                    live.response(&cx, &landing).await.unwrap().status.as_u16(),
                    200
                );
                assert!(
                    live.response(&cx, &format!("http://localhost:{port}/escape"))
                        .await
                        .is_none()
                );
                assert_eq!(live.state().archive.urls().count(), 2);
                Ok(())
            },
        ))
        .unwrap();
        server.join().unwrap();
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn every_engine_uses_the_host_api_and_logs_queries_downloads_and_replays() {
        use std::{
            io::{BufRead, BufReader, Write},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let result_url = format!("{origin}/result");
        let returned_url = result_url.clone();
        let server = std::thread::spawn(move || {
            let mut queries = 0;
            for _ in 0..6 {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut reader = BufReader::new(socket.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let target = line.split_whitespace().nth(1).unwrap().to_owned();
                loop {
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                }
                let (mime, body) = if target.starts_with("/customsearch/v1?") {
                    let url = url::Url::parse(&format!("http://localhost{target}")).unwrap();
                    let params: HashMap<_, _> = url.query_pairs().collect();
                    assert_eq!(params["key"], "host-only-key");
                    assert_eq!(params["cx"], "host-only-engine");
                    assert_eq!(params["q"], "stellar & gas");
                    assert_eq!(params["start"], "1");
                    assert_eq!(params["num"], "10");
                    queries += 1;
                    ("application/json", json!({"searchInformation":{"totalResults":"1"}, "items":[{"title":"Stellar gas", "link":returned_url, "snippet":"Stellar gas"}]}).to_string())
                } else if target == "/robots.txt" {
                    ("text/plain", "User-agent: *\nAllow: /\n".to_owned())
                } else {
                    assert_eq!(target, "/result");
                    (
                        "text/html",
                        "<title>Stellar gas</title><p>Stellar gas</p>".to_owned(),
                    )
                };
                write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
            assert_eq!(queries, 4);
        });
        let path = std::env::temp_dir().join(format!(
            "fictionet-live-engines-{}.warc.gz",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let live = Arc::new(Live {
            key: Key::new("GOOGLE_SEARCH_API_KEY", Some("host-only-key".into())).unwrap(),
            engine: Key::new("GOOGLE_SEARCH_ENGINE_ID", Some("host-only-engine".into())).unwrap(),
            endpoint: format!("{origin}/customsearch/v1").parse().unwrap(),
            path: path.clone(),
            state: Mutex::default(),
            fetcher: Mutex::default(),
        });
        let mut pages = Pages::new(Seed::builtin("web").unwrap());
        pages.live = Some(live);
        pages
            .live_active
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let pages = Arc::new(pages);
        let memory = Arc::new(fictionet_observe::Memory::default());
        fictionet::block_on(fictionet::run(fictionet::RunOptions::new(fictionet::Seed::from_u64(8)).observer(memory.clone()), |cx| async move {
            for (host, target) in [
                ("www.google.com", "/search?q=stellar+%26+gas"),
                ("www.bing.com", "/search?q=stellar+%26+gas"),
                ("html.duckduckgo.com", "/html/?q=stellar+%26+gas"),
                ("www.youtube.com", "/results?search_query=stellar+%26+gas"),
            ] {
                let response = pages.handle(&cx, "GET", host, target, None).await;
                assert_eq!(response.status, 200);
                let Meta::Search(list) = response.meta else { panic!("search response expected") };
                assert_eq!(list.listed.len(), 1);
                assert_eq!(list.listed[0].0, result_url);
                assert_eq!(list.carries, 0);
                assert_eq!(pages.live_url(&cx, &result_url).await.status, 200);
            }
            pages.apply(&cx, Command::SetNewPages { new_pages: NewPages::Off, expected_revision: 0 }).unwrap();
            let response = pages.handle(&cx, "GET", "www.google.com", "/search?q=stellar+%26+gas", None).await;
            assert!(matches!(response.meta, Meta::Search(list) if list.cache == Cache::Cached && list.listed.len() == 1));
            Ok(())
        })).unwrap();
        server.join().unwrap();
        let events = memory.checked_all().unwrap();
        for (kind, count) in [("real_search", 4), ("downloaded", 1), ("copy_served", 4)] {
            assert_eq!(
                events
                    .iter()
                    .filter(|e| e.source == "web" && e.kind == kind)
                    .count(),
                count
            );
        }
        let text = format!("{events:?}");
        assert!(!text.contains("host-only-key"));
        assert!(!text.contains("host-only-engine"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn copies_dependencies_and_same_host_links_through_five_levels() {
        use std::{
            io::{BufRead, BufReader, Write},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let external = origin.replace("127.0.0.1", "localhost");
        let (send, receive) = oneshot::channel();
        let server = std::thread::spawn(move || {
            let mut requested = Vec::new();
            for _ in 0..10 {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut reader = BufReader::new(socket.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let path = line.split_whitespace().nth(1).unwrap().to_owned();
                requested.push(path.clone());
                loop {
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                }
                let (mime, body) = match path.as_str() {
                    "/robots.txt" => ("text/plain", "User-agent: *\nDisallow: /denied\n".into()),
                    "/" => (
                        "text/html",
                        format!(
                            "<title>Sky</title><link rel='stylesheet' href='/skin.css'><img src='/star.png'><a href='/level/1'>Next</a><a href='/denied'>Denied</a><a href='{external}/outside'>External</a>"
                        ),
                    ),
                    "/skin.css" => ("text/css", "@font-face{src:url(/font.woff2)}".into()),
                    "/font.woff2" => ("font/woff2", "font bytes".into()),
                    "/star.png" => ("image/png", "image bytes".into()),
                    _ => {
                        let depth: u8 = path
                            .strip_prefix("/level/")
                            .expect("only reached paths")
                            .parse()
                            .unwrap();
                        assert!(depth <= 5);
                        (
                            "text/html",
                            format!(
                                "<title>Level {depth}</title><a href='/level/{}'>Next</a>",
                                depth + 1
                            ),
                        )
                    }
                };
                write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
            }
            let _ = send.send(requested);
        });
        let path = std::env::temp_dir().join(format!(
            "fictionet-live-crawl-{}.warc.gz",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let live = Arc::new(Live {
            key: Key::new("GOOGLE_SEARCH_API_KEY", Some("private".into())).unwrap(),
            engine: Key::new("GOOGLE_SEARCH_ENGINE_ID", Some("engine".into())).unwrap(),
            endpoint: url::Url::parse("https://customsearch.googleapis.com/customsearch/v1")
                .unwrap(),
            path: path.clone(),
            state: Mutex::default(),
            fetcher: Mutex::default(),
        });
        let copy = live.clone();
        fictionet::block_on(fictionet::run(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(7)),
            |cx| async move {
                assert!(
                    live.response(&cx, &format!("{origin}/unreached"))
                        .await
                        .is_none()
                );
                live.enqueue(
                    Job {
                        url: format!("{origin}/"),
                        navigation: Some(("127.0.0.1".into(), 0)),
                        redirects: 0,
                        cx: cx.clone(),
                    },
                    true,
                );
                let requested = cx
                    .race(Some(cx.now() + Duration::from_secs(20)), receive)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(
                    !requested
                        .iter()
                        .any(|url| url == "/denied" || url == "/level/6" || url == "/outside")
                );
                assert!(
                    live.response(&cx, &format!("{origin}/level/5"))
                        .await
                        .unwrap()
                        .status
                        .is_success()
                );
                assert!(
                    live.response(&cx, &format!("{origin}/level/6"))
                        .await
                        .is_none()
                );
                assert_eq!(
                    live.response(&cx, &format!("{origin}/star.png"))
                        .await
                        .unwrap()
                        .body,
                    "image bytes"
                );
                assert_eq!(
                    live.response(&cx, &format!("{origin}/star.png"))
                        .await
                        .unwrap()
                        .body,
                    "image bytes"
                );
                assert_eq!(live.state().archive.urls().count(), 9);
                Ok(())
            },
        ))
        .unwrap();
        server.join().unwrap();
        assert_eq!(Archive::open([path.clone()]).unwrap().urls().count(), 9);
        drop(copy);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn parses_real_result_order_and_rejects_bad_responses() {
        let value = json!({"searchInformation":{"totalResults":"2"},"items":[
            {"title":"Second star", "link":"https://sky.org/second#part", "snippet":"Fainter"},
            {"title":"First star", "link":"https://sky.org/first", "snippet":"Brighter"}
        ]});
        let search = parse_results(&value).unwrap();
        assert_eq!(
            search
                .results
                .iter()
                .map(|r| r.title.as_str())
                .collect::<Vec<_>>(),
            ["Second star", "First star"]
        );
        assert_eq!(search.results[0].url, "https://sky.org/second");
        assert!(parse_results(&json!({"error":{"code":403}})).is_err());
        assert!(parse_results(&json!({"searchInformation":{}, "items":[{"link":"file:///etc/passwd","title":"Local"}]})).is_err());
        assert!(
            parse_results(&json!({"searchInformation":{"totalResults":"0"}}))
                .unwrap()
                .results
                .is_empty()
        );
    }

    #[test]
    fn unknown_urls_do_not_fetch_and_completed_copies_survive_mode_changes() {
        let path = std::env::temp_dir().join(format!(
            "fictionet-live-copy-{}.warc.gz",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let live = Arc::new(Live {
            key: Key::new("GOOGLE_SEARCH_API_KEY", Some("private-key".into())).unwrap(),
            engine: Key::new("GOOGLE_SEARCH_ENGINE_ID", Some("private-engine".into())).unwrap(),
            endpoint: url::Url::parse("https://customsearch.googleapis.com/customsearch/v1")
                .unwrap(),
            path: path.clone(),
            state: Mutex::default(),
            fetcher: Mutex::default(),
        });
        let response = warc::Response {
            status: http::StatusCode::OK,
            headers: http::HeaderMap::from_iter([(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("text/html"),
            )]),
            body: "<title>Saved star</title><p>The original bytes</p>".into(),
        };
        live.state()
            .archive
            .append(&path, "https://sky.org/saved", &response)
            .unwrap();
        live.state()
            .reached
            .insert("https://sky.org/saved".into(), watch::channel(true).0);
        let mut pages = Pages::new(Seed::builtin("web").unwrap());
        pages.live = Some(live);
        let pages = Arc::new(pages);
        fictionet::block_on(fictionet::lab(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(9)),
            |cx| async move {
                for revision in [0, 2] {
                    pages
                        .apply(
                            &cx,
                            Command::SetNewPages {
                                new_pages: NewPages::LiveSearch,
                                expected_revision: revision,
                            },
                        )
                        .unwrap();
                    assert_eq!(pages.new_pages(), NewPages::LiveSearch);
                    assert_eq!(
                        pages
                            .handle(&cx, "GET", "sky.org", "/saved", None)
                            .await
                            .body,
                        response.body
                    );
                    assert_eq!(
                        pages
                            .handle(&cx, "GET", "sky.org", "/unreached", None)
                            .await
                            .status,
                        404
                    );
                    assert_eq!(pages.live.as_ref().unwrap().state().reached.len(), 1);
                    pages
                        .apply(
                            &cx,
                            Command::SetNewPages {
                                new_pages: NewPages::ModelWritten,
                                expected_revision: revision + 1,
                            },
                        )
                        .unwrap_err();
                    pages
                        .apply(
                            &cx,
                            Command::SetNewPages {
                                new_pages: NewPages::Off,
                                expected_revision: revision + 1,
                            },
                        )
                        .unwrap();
                }
                assert!(Pages::search_asset("www.google.com", "/search.css").is_some());
                assert!(Pages::search_asset("sky.org", "/search.css").is_none());
                Ok(())
            },
        ))
        .unwrap();
        std::fs::remove_file(path).unwrap();
    }
}
