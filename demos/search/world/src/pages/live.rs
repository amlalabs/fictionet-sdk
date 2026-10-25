//! Host search and on-demand public page copies with their dependencies,
//! retained for replay.

use super::*;
use fictionet_extras::{
    capture,
    models::Key,
    warc::{self, Archive},
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{MutexGuard, OnceLock};
use tokio::sync::{oneshot, watch};

pub(super) mod transport;
use transport::{Ask, Transport};

pub(super) struct Lifetime {
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
        resource: capture::Resource,
        user_agent: Option<http::HeaderValue>,
        page: Option<url::Url>,
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
            let result = live
                .download(&lifetime, &cx, &url, user_agent.as_ref(), page.as_ref())
                .await;
            let response = match result {
                Ok(response) => response,
                Err(_) if lifetime.cancelled() || cx.is_cancelled() => {
                    send.send_replace(CaptureState::Cancelled);
                    return;
                }
                Err(error) => {
                    send.send_replace(CaptureState::Failed(error));
                    return;
                }
            };
            // A copied page brings what a still picture of it shows: its
            // stylesheets, CSS imports, fonts and images, including those of
            // pages already in the archive, so the host's picture of the page
            // is drawn from what the world holds. Scripts, preloads and an
            // image's other sizes come only when a client asks for them. They
            // all belong to the page the client asked for. They are under way
            // before the page is ready, so whatever shows the page can wait
            // for them (see `settled`).
            let owner = page.or_else(|| url::Url::parse(&url).ok());
            let page_url = url.clone();
            let links = live
                .fetcher
                .process(&cx, &lifetime, move || {
                    capture::shown_requisites(&page_url, &response, resource)
                        .map_err(|error| error.to_string())
                })
                .await;
            match links {
                Ok(links) => {
                    // A redirect is followed as the client asked. A page's
                    // files are asked for as a browser asks, whatever client
                    // asked for the page: a client such as curl never loads
                    // them, and sites throttle file requests that name one.
                    for (url, resource) in links {
                        let asking = match resource {
                            capture::Resource::Requisite => None,
                            capture::Resource::Document => user_agent.clone(),
                        };
                        let _ = live.capture(&lifetime, &cx, url, resource, asking, owner.clone());
                    }
                }
                Err(error) => eprintln!("Live dependency discovery failed: {error}"),
            }
            send.send_replace(CaptureState::Ready);
        });
        Ok(receive)
    }

    async fn download(
        self: &Arc<Self>,
        lifetime: &Arc<Lifetime>,
        cx: &Cx,
        url: &str,
        user_agent: Option<&http::HeaderValue>,
        page: Option<&url::Url>,
    ) -> Result<warc::Response, String> {
        if let Some(response) = self
            .state()
            .archive
            .get(url)
            .map_err(|error| error.to_string())?
        {
            return Ok(response);
        }
        // One request, as a browser makes it: a host that cannot be reached
        // fails with its real error, which the client and the log both get.
        let observer = self.observer.lock().unwrap().clone();
        let response = self
            .fetcher
            .request(cx, lifetime, observer, url, Ask::Copy { user_agent, page })
            .await
            .map_err(|error| error.to_string())?;
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
        Ok(response)
    }

    async fn search(
        self: &Arc<Self>,
        cx: &Cx,
        query: &str,
        start: u64,
        domains: &fictionet_extras::models::tools::Domains,
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
        let domains = domains.clone();
        self.fetcher.spawn(async move {
            let result = live
                .search_results(&cx_thread, &lifetime, &query, start, &domains)
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
        domains: &fictionet_extras::models::tools::Domains,
    ) -> Result<search::Search, String> {
        let observer = self.observer.lock().unwrap().clone();
        let mut request =
            json!({"query": query, "numResults": start + 10, "contents": {"highlights": true}});
        if let Some(allowed) = &domains.allowed_domains {
            if allowed.is_empty() {
                return Ok(search::Search::default());
            }
            request["includeDomains"] = json!(allowed);
        }
        if let Some(blocked) = &domains.blocked_domains {
            request["excludeDomains"] = json!(blocked);
        }
        let response = self
            .fetcher
            .request(
                cx,
                lifetime,
                observer,
                self.endpoint.as_str(),
                Ask::Search(&self.key, &request),
            )
            .await
            .map_err(|error| error.to_string())?;
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
        if lifetime.cancelled() || !Arc::ptr_eq(lifetime, &self.state().lifetime) {
            return Err("Live session stopped".into());
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
        for (url, done) in &state.reached {
            done.send_replace(if state.archive.contains(url) {
                CaptureState::Ready
            } else {
                CaptureState::Cancelled
            });
        }
        if reset {
            state.lifetime = Arc::default();
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

    /// Waits until a copy of `url` that is under way has arrived or failed.
    /// A page's files are under way once the page is ready.
    pub(super) async fn settled(&self, url: &str) {
        let Some(key) = warc::key(url) else {
            return;
        };
        let reached = self.state().reached.get(&key).map(watch::Sender::subscribe);
        if let Some(mut reached) = reached {
            let _ = reached
                .wait_for(|state| !matches!(state, CaptureState::Pending))
                .await;
        }
    }

    /// A response this session already copied, without copying anything.
    pub(super) fn held(&self, url: &str) -> Option<warc::Response> {
        self.state().archive.get(&warc::key(url)?).ok()?
    }

    async fn response(
        self: &Arc<Self>,
        cx: &Cx,
        url: &str,
        user_agent: Option<&http::HeaderValue>,
        page: Option<url::Url>,
    ) -> Result<warc::Response, String> {
        let url = warc::key(url).ok_or("Invalid Live URL")?;
        let lifetime = self.state().lifetime.clone();
        let mut waiting = self.capture(
            &lifetime,
            cx,
            url.clone(),
            capture::Resource::Document,
            user_agent.cloned(),
            page,
        )?;
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

/// Single requests from the host outside a Live session: package files
/// the copied web lacks. Its transport starts on first use.
#[derive(Default)]
pub(super) struct Fetcher {
    transport: OnceLock<Result<Arc<Transport>, String>>,
    lifetime: Arc<Lifetime>,
    observer: Mutex<Option<Arc<capture::Observer>>>,
}

impl Fetcher {
    /// The real host's response for the package file at `url`, without
    /// following redirects.
    pub(super) async fn package(&self, cx: &Cx, url: &str) -> Result<warc::Response, String> {
        let transport = self
            .transport
            .get_or_init(|| Transport::new().map(Arc::new))
            .clone()?;
        let (send, receive) = oneshot::channel();
        let lifetime = self.lifetime.clone();
        let observer = self.observer.lock().unwrap().clone();
        let (thread, url) = (cx.clone(), url.to_owned());
        transport.clone().spawn(async move {
            let response = transport
                .request(&thread, &lifetime, observer, &url, Ask::Package)
                .await
                .map_err(|error| error.to_string());
            let _ = send.send(response);
        });
        cx.race(None, receive)
            .await
            .map_err(|_| "the world stopped".to_owned())?
            .map_err(|_| "the package request stopped".to_owned())?
    }
}

impl Pages {
    /// Observes every host request: Live copies and searches, and package files.
    pub(crate) fn observe_live(&self, observer: Arc<capture::Observer>) {
        *self.fetcher.observer.lock().unwrap() = Some(observer.clone());
        if let Some(live) = &self.live {
            *live.observer.lock().unwrap() = Some(observer);
        }
    }

    /// Configure and select host search from environment credentials.
    pub fn with_live_search(mut self, downloads: &Path) -> Result<Self, String> {
        self.live = Some(Live::new(downloads)?);
        self.settings.get_mut().unwrap().source = Source::Live;
        Ok(self)
    }

    /// Answers from a Live copy of `url`, with the scenario's edits in
    /// Edited mode.
    pub(super) async fn live_url(
        &self,
        cx: &Cx,
        url: &str,
        user_agent: Option<&http::HeaderValue>,
        page: Option<url::Url>,
    ) -> Response {
        let live = self.live.as_ref().expect("a Live source");
        match live.response(cx, url, user_agent, page).await {
            Ok(response) if self.source() == Source::Edited => self.edited(cx, url, response).await,
            Ok(response) => copied::replay(Ok(Some(response))),
            Err(error) => Response::new(
                502,
                "text/plain; charset=utf-8",
                "Bad Gateway\n",
                vec![],
                Meta::Error { error },
            ),
        }
    }

    /// The real page `response` with the scenario's edits. Pages that are
    /// not HTML, not found, or not touched by the scenario are served as
    /// the site sent them.
    async fn edited(&self, cx: &Cx, url: &str, response: warc::Response) -> Response {
        let html = response.status == http::StatusCode::OK
            && response
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.to_ascii_lowercase().starts_with("text/html"));
        let editor = self.editor.as_ref().expect("Edited has an editor");
        let Some(text) = html
            .then(|| std::str::from_utf8(&response.body).ok())
            .flatten()
        else {
            return copied::replay(Ok(Some(response)));
        };
        let revision = match editor.page(cx, url, text).await {
            Ok(Some(revision)) => revision,
            Ok(None) => return copied::replay(Ok(Some(response))),
            Err(error) => {
                eprintln!("{url} was not edited: {error}");
                return copied::replay(Ok(Some(response)));
            }
        };
        let mut served = response;
        served.body = revision.served.clone().into_bytes().into();
        served
            .headers
            .insert(http::header::CONTENT_LENGTH, served.body.len().into());
        let mut answer = copied::replay(Ok(Some(served)));
        answer.edited = Some(Edited {
            edits: revision.edits.clone(),
            marked: Arc::from(revision.marked.as_str()),
        });
        answer
    }

    pub(super) async fn live_listing(
        &self,
        cx: &Cx,
        query: &str,
        start: u64,
        domains: &fictionet_extras::models::tools::Domains,
    ) -> Result<search::Search, String> {
        self.live
            .as_ref()
            .expect("a Live source")
            .search(cx, query, start, domains)
            .await
    }
}
