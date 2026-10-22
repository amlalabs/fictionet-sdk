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
    endpoint: url::Url,
    path: PathBuf,
    state: Mutex<State>,
    fetcher: Mutex<Option<Fetcher>>,
}

impl Live {
    fn new(root: &Path) -> Result<Arc<Self>, String> {
        let key = Key::new("EXA_API_KEY", std::env::var("EXA_API_KEY").ok())?;
        std::fs::create_dir_all(root).map_err(|e| e.to_string())?;
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos();
        Ok(Arc::new(Self {
            key,
            endpoint: url::Url::parse("https://api.exa.ai/search").unwrap(),
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
                let (_, key) = live.key.header(ModelProvider::Anthropic);
                let request = json!({"query": query, "numResults": (start + 10).min(100), "contents": {"highlights": true}});
                cx_thread.emit("web", "real_search", |event| {
                    event
                        .summary(format_args!("Query sent to Exa: {query}"))
                        .field("search", query.as_str())
                        .field("engine", example_common::names::name(&engine))
                        .field("start", start)
                });
                let response = fetcher
                    .search(live.endpoint.as_str(), &key, &request)
                    .map_err(|_| "Exa search API request failed".to_owned())?;
                if !response.status.is_success() {
                    return Err(format!("Exa search API returned {}", response.status));
                }
                let value: Value =
                    serde_json::from_slice(&response.decoded().map_err(|e| e.to_string())?)
                        .map_err(|_| "Invalid Exa search response")?;
                let mut search = parse_results(&value)?;
                search.results = search
                    .results
                    .into_iter()
                    .skip(start as usize)
                    .take(10)
                    .collect();
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
    let items = value
        .get("results")
        .and_then(Value::as_array)
        .ok_or("Invalid Exa search response")?;
    let mut search = search::Search::default();
    for item in items {
        let url = item["url"]
            .as_str()
            .and_then(warc::key)
            .ok_or("Invalid Exa result URL")?;
        let snippet = item["highlights"]
            .as_array()
            .map(|parts| {
                parts
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .or_else(|| item["text"].as_str().map(str::to_owned))
            .unwrap_or_default();
        search.results.push(search::Result {
            url,
            title: item["title"]
                .as_str()
                .ok_or("Missing Exa result title")?
                .to_owned(),
            snippet,
            date: item["publishedDate"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
        });
    }
    Ok(search)
}

impl Pages {
    /// Whether Live mode has a configured host search credential.
    pub fn live_available(&self) -> bool {
        self.live.is_some()
    }

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
#[path = "live_tests.rs"]
mod tests;
