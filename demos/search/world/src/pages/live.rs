//! Search on the host; replay only URLs reached by those results and their crawl.

use super::*;
use fictionet_extras::{
    capture,
    models::Key,
    warc::{self, Archive},
};
use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
};
use tokio::sync::{oneshot, watch};

mod transport;
use transport::Transport;

struct Lifetime {
    stop: watch::Sender<bool>,
}
impl Default for Lifetime {
    fn default() -> Self {
        Self {
            stop: watch::channel(false).0,
        }
    }
}
impl Lifetime {
    fn cancelled(&self) -> bool {
        *self.stop.borrow()
    }
    fn cancel(&self) {
        self.stop.send_replace(true);
    }
}
impl Drop for Lifetime {
    fn drop(&mut self) {
        self.cancel();
    }
}

struct Job {
    url: String,
    navigation: Option<(String, u8)>,
    cx: Cx,
}

#[derive(Default)]
struct State {
    archive: Archive,
    lifetime: Arc<Lifetime>,
    epoch: usize,
    searches_running: usize,
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
    fetcher: Transport,
    observer: Mutex<Option<Arc<capture::Observer>>>,
}

impl Drop for Live {
    fn drop(&mut self) {
        self.state().lifetime.cancel();
    }
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
            fetcher: Transport::new()?,
            observer: Mutex::default(),
        }))
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn enqueue_in(self: &Arc<Self>, lifetime: &Arc<Lifetime>, job: Job, priority: bool) {
        let Some(url) = warc::key(&job.url) else {
            return;
        };
        let mut state = self.state();
        if lifetime.cancelled() || !Arc::ptr_eq(lifetime, &state.lifetime) {
            return;
        }
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
            let lifetime = lifetime.clone();
            self.fetcher.spawn(async move {
                live.download(lifetime).await;
            });
        }
    }

    async fn download(self: Arc<Self>, lifetime: Arc<Lifetime>) {
        loop {
            let job = {
                let mut state = self.state();
                if lifetime.cancelled() || !Arc::ptr_eq(&lifetime, &state.lifetime) {
                    return;
                }
                let Some(job) = state.queue.pop_front() else {
                    state.running = false;
                    return;
                };
                job
            };
            if job.cx.is_cancelled() || lifetime.cancelled() {
                return;
            }
            let observer = self.observer.lock().unwrap().clone();
            let existing = self.state().archive.get(&job.url);
            let result = match existing {
                Ok(Some(response)) => Ok((response, false)),
                Ok(None) => self
                    .fetcher
                    .request(&job.cx, &lifetime, observer, &job.url, None)
                    .await
                    .map(|response| (response, true))
                    .map_err(std::io::Error::other),
                Err(error) => Err(error),
            };
            if lifetime.cancelled() {
                return;
            }
            if let Ok((response, downloaded)) = result {
                let saved = {
                    let mut state = self.state();
                    if !Arc::ptr_eq(&lifetime, &state.lifetime) {
                        return;
                    }
                    let path = self.archive_path(state.epoch);
                    !downloaded || state.archive.append(&path, &job.url, &response).is_ok()
                };
                let status = response.status;
                let url = job.url.clone();
                let links = if saved {
                    self.fetcher
                        .process(&job.cx, &lifetime, move || {
                            capture::links(&url, &response).map_err(|error| error.to_string())
                        })
                        .await
                } else {
                    Err("Live capture could not be saved".into())
                };
                if let Ok(links) = links {
                    // Dependencies get priority over the next navigation page.
                    for url in links.assets.into_iter().rev() {
                        self.enqueue_in(
                            &lifetime,
                            Job {
                                url,
                                navigation: None,
                                cx: job.cx.clone(),
                            },
                            true,
                        );
                    }
                    if status.is_redirection() {
                        for url in links.pages {
                            self.enqueue_in(
                                &lifetime,
                                Job {
                                    url,
                                    navigation: job.navigation.clone(),
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
                            self.enqueue_in(
                                &lifetime,
                                Job {
                                    url,
                                    navigation: Some((site.clone(), depth + 1)),
                                    cx: job.cx.clone(),
                                },
                                false,
                            );
                        }
                    }
                }
            }
            let state = self.state();
            if !Arc::ptr_eq(&lifetime, &state.lifetime) {
                return;
            }
            if let Some(done) = state.reached.get(&job.url) {
                done.send_replace(true);
            }
        }
    }

    async fn search(
        self: &Arc<Self>,
        cx: &Cx,
        _engine: Engine,
        query: &str,
        start: u64,
    ) -> Result<search::Search, String> {
        if start > 90 {
            return Ok(search::Search::default());
        }
        let lifetime = {
            let mut state = self.state();
            if state.lifetime.cancelled() {
                return Err("Live session stopped".into());
            }
            if state.searches_running >= 2 || state.searches.len() >= 64 {
                return Err("Live search capacity reached".into());
            }
            state.searches_running += 1;
            state.lifetime.clone()
        };
        let (send, receive) = oneshot::channel();
        let live = self.clone();
        let cx_thread = cx.clone();
        let query = query.to_owned();
        self.fetcher.spawn(async move {
            let result = live
                .search_results(&cx_thread, &lifetime, &query, start)
                .await;
            let mut state = live.state();
            if Arc::ptr_eq(&lifetime, &state.lifetime) {
                state.searches_running -= 1;
            }
            drop(state);
            let _ = send.send(result);
        });
        cx.race(None, receive)
            .await
            .map_err(|_| "Live search timed out or was cancelled".to_owned())?
            .map_err(|_| "Live search worker stopped".to_owned())?
    }

    async fn search_results(
        self: &Arc<Self>,
        cx: &Cx,
        lifetime: &Arc<Lifetime>,
        query: &str,
        start: u64,
    ) -> Result<search::Search, String> {
        let observer = self.observer.lock().unwrap().clone();
        let request = json!({"query": query, "numResults": (start + 10).min(100), "contents": {"highlights": true}});
        let response = self
            .fetcher
            .request(
                cx,
                lifetime,
                observer,
                self.endpoint.as_str(),
                Some((&self.key, &request)),
            )
            .await?;
        if !response.status.is_success() {
            return Err(format!("Exa search API returned {}", response.status));
        }
        let key = self.key.clone();
        let mut search = self
            .fetcher
            .process(cx, lifetime, move || {
                let decoded = response.decoded().map_err(|error| error.to_string())?;
                let value: Value =
                    serde_json::from_slice(&decoded).map_err(|_| "Invalid Exa search response")?;
                parse_search(&value, Some(&key))
            })
            .await?;
        search.results = search
            .results
            .into_iter()
            .skip(start as usize)
            .take(10)
            .collect();
        {
            let mut state = self.state();
            if lifetime.cancelled() || !Arc::ptr_eq(lifetime, &state.lifetime) {
                return Err("Live session stopped".into());
            }
            state
                .searches
                .insert((query.to_owned(), start), search.clone());
        }
        for result in search.results.iter().rev() {
            if let Ok(url) = url::Url::parse(&result.url)
                && let Some(host) = url.host_str()
            {
                self.enqueue_in(
                    lifetime,
                    Job {
                        url: result.url.clone(),
                        navigation: Some((host.to_owned(), 0)),
                        cx: cx.clone(),
                    },
                    true,
                );
            }
        }
        Ok(search)
    }

    fn archive_path(&self, epoch: usize) -> PathBuf {
        if epoch == 0 {
            self.path.clone()
        } else {
            self.path.with_extension(format!("{epoch}.warc.gz"))
        }
    }

    pub(super) fn revoke(&self, reset: bool) {
        let mut state = self.state();
        state.lifetime.cancel();
        for done in state.reached.values() {
            done.send_replace(true);
        }
        state.queue.clear();
        state.running = false;
        if reset {
            state.lifetime = Arc::default();
            state.searches.clear();
            state.depths.clear();
            state.searches_running = 0;
            let completed: std::collections::HashSet<_> =
                state.archive.urls().map(str::to_owned).collect();
            state.reached.retain(|url, _| completed.contains(url));
        }
    }

    pub(super) fn restart(&self) {
        self.revoke(false);
        let mut state = self.state();
        let epoch = state.epoch + 1;
        let old_path = self.archive_path(state.epoch);
        *state = State {
            epoch,
            ..State::default()
        };
        drop(state);
        let _ = std::fs::remove_file(old_path);
    }

    async fn response(self: &Arc<Self>, cx: &Cx, url: &str) -> Option<warc::Response> {
        let url = warc::key(url)?;
        let lifetime = self.state().lifetime.clone();
        self.enqueue_in(
            &lifetime,
            Job {
                url: url.clone(),
                navigation: None,
                cx: cx.clone(),
            },
            true,
        );
        let (mut waiting, lifetime) = {
            let mut state = self.state();
            let waiting = state.reached.get(&url)?.subscribe();
            if let Some(index) = state.queue.iter().position(|job| job.url == url) {
                let job = state.queue.remove(index).unwrap();
                state.queue.push_front(job);
            }
            (waiting, state.lifetime.clone())
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
        let _ = cx.race(None, ready).await;

        let state = self.state();
        if !Arc::ptr_eq(&lifetime, &state.lifetime) {
            return None;
        }
        state.archive.get(&url).ok().flatten()
    }
}

fn parse_search(value: &Value, key: Option<&Key>) -> Result<search::Search, String> {
    #[derive(Deserialize)]
    struct Reply {
        results: Vec<ResultItem>,
    }
    #[derive(Deserialize)]
    struct ResultItem {
        url: String,
        title: String,
        highlights: Option<Vec<String>>,
        text: Option<String>,
        #[serde(rename = "publishedDate")]
        date: Option<String>,
    }
    let reply: Reply =
        serde_json::from_value(value.clone()).map_err(|_| "Invalid Exa search response")?;
    let mut search = search::Search::default();
    let scrub = |text: &str| key.map_or_else(|| text.to_owned(), |key| key.redact(text));
    for item in reply.results {
        let decoded = percent_encoding::percent_decode_str(&item.url).decode_utf8_lossy();
        if scrub(&decoded) != decoded {
            return Err("Exa returned a credential-bearing destination".into());
        }
        let url = warc::key(&item.url).ok_or("Invalid Exa result URL")?;
        let snippet = item
            .highlights
            .map(|parts| parts.join(" "))
            .or(item.text)
            .unwrap_or_default();
        search.results.push(search::Result {
            url,
            title: scrub(&item.title),
            snippet: scrub(&snippet),
            date: scrub(&item.date.unwrap_or_default()),
        });
    }
    Ok(search)
}

impl Pages {
    pub(crate) fn observe_live(&self, observer: Arc<capture::Observer>) {
        if let Some(live) = &self.live {
            *live.observer.lock().unwrap() = Some(observer);
        }
    }

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
        copied::replay(Ok(self.live.as_ref().unwrap().response(cx, url).await))
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
