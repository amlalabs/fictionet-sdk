//! Host search and on-demand public page copies, retained for replay.

use super::*;
use fictionet_extras::{
    capture,
    models::Key,
    warc::{self, Archive},
};
use std::path::{Path, PathBuf};
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

#[derive(Clone)]
enum CaptureState {
    Pending,
    Ready,
    Failed(String),
    Cancelled,
}

#[derive(Default)]
struct State {
    archive: Archive,
    lifetime: Arc<Lifetime>,
    epoch: usize,
    reached: HashMap<String, watch::Sender<CaptureState>>,
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

    fn capture(
        self: &Arc<Self>,
        lifetime: &Arc<Lifetime>,
        cx: &Cx,
        url: String,
    ) -> Result<watch::Receiver<CaptureState>, String> {
        let mut state = self.state();
        if lifetime.cancelled() || !Arc::ptr_eq(lifetime, &state.lifetime) {
            return Err("Live session stopped".into());
        }
        if let Some(reached) = state.reached.get(&url)
            && !matches!(*reached.borrow(), CaptureState::Failed(_))
        {
            return Ok(reached.subscribe());
        }
        let (send, receive) = watch::channel(CaptureState::Pending);
        state.reached.insert(url.clone(), send.clone());
        let live = self.clone();
        let lifetime = lifetime.clone();
        let cx = cx.clone();
        self.fetcher.spawn(async move {
            let result = live.download(&lifetime, &cx, &url).await;
            send.send_replace(match result {
                Ok(()) => CaptureState::Ready,
                Err(_) if lifetime.cancelled() || cx.is_cancelled() => CaptureState::Cancelled,
                Err(error) => CaptureState::Failed(error),
            });
        });
        Ok(receive)
    }

    async fn download(
        self: &Arc<Self>,
        lifetime: &Arc<Lifetime>,
        cx: &Cx,
        url: &str,
    ) -> Result<(), String> {
        if self.state().archive.contains(url) {
            return Ok(());
        }
        let observer = self.observer.lock().unwrap().clone();
        let response = self
            .fetcher
            .request(cx, lifetime, observer, url, None)
            .await?;
        {
            let mut state = self.state();
            if lifetime.cancelled() || !Arc::ptr_eq(lifetime, &state.lifetime) {
                return Err("Live session stopped".into());
            }
            let path = self.archive_path(state.epoch);
            state
                .archive
                .append(&path, url, &response)
                .map_err(|error| error.to_string())?;
        }
        let url = url.to_owned();
        let links = self
            .fetcher
            .process(cx, lifetime, move || {
                capture::links(&url, &response).map_err(|error| error.to_string())
            })
            .await?;
        for url in links.assets {
            let _ = self.capture(lifetime, cx, url);
        }
        Ok(())
    }

    async fn search(
        self: &Arc<Self>,
        cx: &Cx,
        _engine: Engine,
        query: &str,
        start: u64,
    ) -> Result<search::Search, String> {
        let lifetime = {
            let state = self.state();
            if state.lifetime.cancelled() {
                return Err("Live session stopped".into());
            }
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
            let _ = send.send(result);
        });
        cx.race(None, receive)
            .await
            .map_err(|_| "Live search was cancelled".to_owned())?
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
        let request =
            json!({"query": query, "numResults": start + 10, "contents": {"highlights": true}});
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
                let decoded = response
                    .decoded()
                    .map_err(|_| "Exa response has an invalid encoding")?;
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
        for result in &search.results {
            let _ = self.capture(lifetime, cx, result.url.clone());
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
            done.send_replace(CaptureState::Cancelled);
        }
        if reset {
            state.lifetime = Arc::default();
            state.searches.clear();
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

    async fn response(self: &Arc<Self>, cx: &Cx, url: &str) -> Result<warc::Response, String> {
        let url = warc::key(url).ok_or("Invalid Live URL")?;
        let lifetime = self.state().lifetime.clone();
        let mut waiting = self.capture(&lifetime, cx, url.clone())?;
        let ready = async {
            loop {
                let state = waiting.borrow_and_update().clone();
                match state {
                    CaptureState::Pending => {}
                    CaptureState::Ready => return Ok(()),
                    CaptureState::Failed(error) => return Err(error),
                    CaptureState::Cancelled => return Err("Live session stopped".into()),
                }
                waiting.changed().await.map_err(|_| "Live worker stopped")?;
            }
        };
        cx.race(None, ready)
            .await
            .map_err(|_| "Live fetch was cancelled")??;
        let state = self.state();
        if !Arc::ptr_eq(&lifetime, &state.lifetime) {
            return Err("Live session stopped".into());
        }
        state
            .archive
            .get(&url)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "Live capture is unavailable".into())
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

    /// Configure and select host search from environment credentials.
    pub fn with_live_search(mut self, downloads: &Path) -> Result<Self, String> {
        self.live = Some(Live::new(downloads)?);
        self.live_active
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.copied_active
            .store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(self)
    }

    pub(crate) fn live_only(&self) -> bool {
        self.live_active.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(crate) async fn live_url(&self, cx: &Cx, url: &str) -> Response {
        match self.live.as_ref().unwrap().response(cx, url).await {
            Ok(response) => copied::replay(Ok(Some(response))),
            Err(_) => Response::new(
                502,
                "text/plain; charset=utf-8",
                "Bad Gateway\n",
                vec![],
                Meta::Missing,
            ),
        }
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
