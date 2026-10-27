//! Host search and public page copies with their dependencies, retained
//! for replay: copied when a client asks for them (Live and Edited), or,
//! in Live-Depth, only when the address is on the allowlist that grows
//! from search results through the links of the pages the guest opens.

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
pub(super) use transport::GitRequest;
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

/// How a session reaches the real web.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Reach {
    /// Live and Edited: any page a client asks for is copied when asked.
    Asked,
    /// Live-Depth: a page is copied when asked for only if it is on the
    /// allowlist: a search result, or a link fewer than [`DEPTH`] links
    /// from one on a page the guest opened, or a file of such a page.
    Allowlist,
}

/// How many links from a search result Live-Depth allows.
const DEPTH: u8 = 5;

#[derive(Clone)]
enum CaptureState {
    Pending,
    Ready,
    /// The site answered with an error status. The copy answers only the
    /// requests waiting for it: a later request asks the site again, as
    /// a client that changed its request may now be answered.
    Unsuccessful,
    Failed(String),
    Cancelled,
}

/// Live-Depth: what a host answers for an address it has no page at, the
/// answer for an address on it the allowlist does not have.
#[derive(Clone)]
enum NotFound {
    /// The host is being asked for [`State::missing`].
    Asking,
    /// The host's own answer for `path`.
    Answer {
        path: String,
        response: warc::Response,
    },
    /// The host gave no 404 for it, or could not be asked.
    Unknown,
}

/// Why a copy of an address could not be served.
pub(super) enum Unanswered {
    /// Live-Depth's allowlist does not have it, so it was not fetched.
    Unlisted,
    /// The copy failed, or the session stopped, and why.
    Failed(String),
}

impl From<String> for Unanswered {
    fn from(error: String) -> Self {
        Self::Failed(error)
    }
}

impl From<&str> for Unanswered {
    fn from(error: &str) -> Self {
        Self::Failed(error.into())
    }
}

/// Why Live-Depth allows an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Allowed {
    /// A search result (depth 0), or a link on an allowed page one deeper
    /// than that page, at the fewest links it was reached by.
    Page { depth: u8 },
    /// A stylesheet, script, image or font an allowed page uses, or the
    /// target of a file's redirect.
    File,
}

#[derive(Default)]
struct State {
    archive: Archive,
    lifetime: Arc<Lifetime>,
    epoch: usize,
    reached: HashMap<String, watch::Sender<CaptureState>>,
    /// Live-Depth: every allowed address.
    allowed: HashMap<String, Allowed>,
    /// Live-Depth: the links of each page copied, so a page reached again
    /// closer to a search result passes its new depth on.
    links: HashMap<String, Vec<String>>,
    /// Live-Depth: how many allowed addresses each host has, which the
    /// world's DNS answers for.
    hosts: HashMap<String, usize>,
    /// Live-Depth: each host's answer for an address it has no page at.
    not_found: HashMap<String, watch::Sender<NotFound>>,
    /// Live-Depth: the one made-up path each host is asked for to learn
    /// its 404, random for the session and the same for every host, so
    /// nothing the guest asked for reaches a site.
    missing: Option<String>,
}

type Observations =
    Arc<Mutex<Option<tokio::sync::mpsc::UnboundedSender<crate::observation::Observation>>>>;

pub(super) struct Live {
    key: Key,
    endpoint: url::Url,
    path: PathBuf,
    reach: Reach,
    state: Mutex<State>,
    fetcher: Transport,
    observer: Mutex<Option<Arc<capture::Observer>>>,
    /// Where the allowlist's growth is reported.
    observations: Observations,
}

impl Drop for Live {
    fn drop(&mut self) {
        self.state().lifetime.cancel();
    }
}

impl Live {
    fn new(root: &Path, reach: Reach, observations: Observations) -> Result<Arc<Self>, String> {
        let key = Key::new("EXA_API_KEY", std::env::var("EXA_API_KEY").ok())?;
        std::fs::create_dir_all(root).map_err(|e| e.to_string())?;
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos();
        let name = match reach {
            Reach::Asked => "live-search",
            Reach::Allowlist => "live-depth",
        };
        Ok(Arc::new(Self {
            key,
            endpoint: url::Url::parse("https://api.exa.ai/search").unwrap(),
            path: root.join(format!("{name}-{}-{stamp}.warc.gz", std::process::id())),
            reach,
            state: Mutex::default(),
            fetcher: Transport::new()?,
            observer: Mutex::default(),
            observations,
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
            && !matches!(
                *reached.borrow(),
                CaptureState::Failed(_) | CaptureState::Unsuccessful
            )
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
            let unsuccessful =
                response.status.is_client_error() || response.status.is_server_error();
            if live.reach == Reach::Allowlist
                && resource == capture::Resource::Document
                && response.status.is_success()
            {
                live.learn_not_found(&lifetime, &cx, &url);
            }
            // Live-Depth allows what an allowed copy links to and uses
            // before the copy is ready, so its links resolve and answer by
            // the time the client has it.
            if live.reach == Reach::Allowlist {
                let (page_url, copy) = (url.clone(), response.clone());
                let redirect = response.status.is_redirection();
                match live
                    .fetcher
                    .process(&cx, &lifetime, move || {
                        let mut links =
                            capture::links(&page_url, &copy).map_err(|error| error.to_string())?;
                        if copy.status.is_success() && is_pdf(&copy) {
                            links.pages.extend(pdf_links(&page_url, &copy.body));
                        }
                        Ok(links)
                    })
                    .await
                {
                    Ok(links) => live.admit(&cx, &url, redirect, links),
                    Err(error) => eprintln!("Live-Depth link discovery failed: {error}"),
                }
            }
            // A copied page brings what lays a still picture of it out: its
            // stylesheets, CSS imports, fonts and icons, including those of
            // pages already in the archive, so the host's picture of the page
            // is drawn from what the world holds. Its images come as a
            // client asks for them, the way a browser loads
            // them as they come into view, so a page with hundreds of images
            // does not send hundreds of requests to its site at once.
            // Scripts, preloads and an image's other sizes come only when a
            // client asks for them. They all belong to the page the client
            // asked for. They are under way before the page is ready, so
            // whatever shows the page can wait for them (see `settled`).
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
            send.send_replace(if unsuccessful {
                CaptureState::Unsuccessful
            } else {
                CaptureState::Ready
            });
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
            && !(response.status.is_client_error() || response.status.is_server_error())
        {
            return Ok(response);
        }
        // One request, as a browser makes it: a host that cannot be reached
        // fails with its real error, which the log gets. The client's
        // connection is closed unanswered, as the real network leaves it.
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

    /// Allows what the copy of `url` leads to: a redirect's target as `url`
    /// itself is allowed; the files a page or stylesheet uses; and, for a
    /// page fewer than [`DEPTH`] links from a search result, its links one
    /// deeper.
    fn admit(&self, cx: &Cx, url: &str, redirect: bool, links: capture::Links) {
        let mut state = self.state();
        let Some(from) = state.allowed.get(url).copied() else {
            return;
        };
        if redirect {
            for target in links.pages {
                state.allow(target, from);
            }
        } else {
            for file in links.assets {
                state.allow(file, Allowed::File);
            }
            if let Allowed::Page { depth } = from {
                state.links.insert(url.to_owned(), links.pages.clone());
                if depth < DEPTH {
                    for page in links.pages {
                        state.allow(page, Allowed::Page { depth: depth + 1 });
                    }
                }
            }
        }
        let links = state.allowed.len() as u64;
        drop(state);
        self.report_allowlist(cx, links);
    }

    /// Asks the host of `url`, a page Live-Depth copied, once a session
    /// for its answer to an address it has no page at: the session's one
    /// made-up path. It is asked as the page's own copy is made, so a
    /// refusal later sends nothing and the host learns nothing new.
    fn learn_not_found(self: &Arc<Self>, lifetime: &Arc<Lifetime>, cx: &Cx, url: &str) {
        let Ok(page) = url::Url::parse(url) else {
            return;
        };
        let Some(host) = page.host_str().map(str::to_owned) else {
            return;
        };
        let mut state = self.state();
        if state.not_found.contains_key(&host) {
            return;
        }
        let path = state
            .missing
            .get_or_insert_with(|| format!("/{:016x}", cx.random_u64()))
            .clone();
        let found = watch::channel(NotFound::Asking).0;
        state.not_found.insert(host, found.clone());
        drop(state);
        let mut missing = page.clone();
        missing.set_path(&path);
        missing.set_query(None);
        missing.set_fragment(None);
        let (live, lifetime, cx) = (self.clone(), lifetime.clone(), cx.clone());
        self.fetcher.spawn(async move {
            let observer = live.observer.lock().unwrap().clone();
            let response = live
                .fetcher
                .request(
                    &cx,
                    &lifetime,
                    observer,
                    missing.as_str(),
                    Ask::Copy {
                        user_agent: None,
                        page: Some(&page),
                    },
                )
                .await;
            found.send_replace(match response {
                Ok(response) if response.status == http::StatusCode::NOT_FOUND => {
                    NotFound::Answer { path, response }
                }
                _ => NotFound::Unknown,
            });
        });
    }

    /// What Live-Depth answers for `url`, an address it does not allow,
    /// without fetching it: the host's own 404, as it answered the
    /// session's made-up path, with the guest's address in place of that
    /// path; or, before any page on the host was copied, a web server's
    /// plain 404.
    pub(super) async fn refusal(&self, cx: &Cx, url: &str) -> warc::Response {
        let parsed = url::Url::parse(url).ok();
        let host = parsed.as_ref().and_then(url::Url::host_str);
        let asking = host.and_then(|host| {
            self.state()
                .not_found
                .get(host)
                .map(watch::Sender::subscribe)
        });
        let found = match asking {
            Some(mut asking) => cx
                .race(None, async move {
                    asking
                        .wait_for(|found| !matches!(found, NotFound::Asking))
                        .await
                        .map(|found| found.clone())
                        .ok()
                })
                .await
                .ok()
                .flatten(),
            None => None,
        };
        match (found, parsed) {
            (Some(NotFound::Answer { path, mut response }), Some(parsed)) => {
                let asked = &parsed[url::Position::BeforePath..url::Position::AfterQuery];
                if let Ok(body) = std::str::from_utf8(&response.body)
                    && body.contains(&path)
                {
                    response.body = body.replace(&path, &text::escape(asked)).into();
                }
                response
                    .headers
                    .insert(http::header::CONTENT_LENGTH, response.body.len().into());
                response
            }
            _ => {
                let body = "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n\
                    <center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n\
                    </body>\r\n</html>\r\n";
                let mut headers = http::HeaderMap::new();
                headers.insert(
                    http::header::SERVER,
                    http::HeaderValue::from_static("nginx"),
                );
                headers.insert(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("text/html"),
                );
                headers.insert(http::header::CONTENT_LENGTH, body.len().into());
                warc::Response {
                    status: http::StatusCode::NOT_FOUND,
                    headers,
                    body: body.into(),
                }
            }
        }
    }

    /// Allows the results of a search at depth 0.
    fn allow_results(&self, cx: &Cx, search: &search::Search) {
        let mut state = self.state();
        for result in &search.results {
            state.allow(result.url.clone(), Allowed::Page { depth: 0 });
        }
        let links = state.allowed.len() as u64;
        drop(state);
        self.report_allowlist(cx, links);
    }

    fn report_allowlist(&self, cx: &Cx, links: u64) {
        crate::observation::report(
            &self.observations,
            cx,
            crate::observation::SearchObs::Allowlist { links },
        );
    }

    /// Why Live-Depth allows `url`, if it does.
    pub(super) fn allowed(&self, url: &str) -> Option<Allowed> {
        self.state().allowed.get(&warc::key(url)?).copied()
    }

    /// Whether an address Live-Depth allows is on `host`.
    pub(super) fn allows_host(&self, host: &str) -> bool {
        self.state().hosts.contains_key(host)
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
        // Exa's own pages (its library of weather, company and people pages)
        // would show which engine answers.
        let mut blocked = domains.blocked_domains.clone().unwrap_or_default();
        blocked.push("exa.ai".to_owned());
        request["excludeDomains"] = json!(blocked);
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
        if self.reach == Reach::Allowlist {
            self.allow_results(cx, &search);
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

    /// Stops this session's copies.
    fn revoke(&self) {
        let state = self.state();
        state.lifetime.cancel();
        for (url, done) in &state.reached {
            done.send_replace(if state.archive.contains(url) {
                CaptureState::Ready
            } else {
                CaptureState::Cancelled
            });
        }
    }

    /// Starts a new session, forgetting everything the previous one
    /// copied or allowed.
    pub(super) fn restart(&self) {
        self.revoke();
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

    /// The copy of `url`. Live and Edited make it now if it is not made
    /// yet: a document as the client by `user_agent` gets it, or a file
    /// of `page`. Live-Depth copies only what its allowlist has,
    /// and refuses anything else without fetching it.
    pub(super) async fn response(
        self: &Arc<Self>,
        cx: &Cx,
        url: &str,
        resource: capture::Resource,
        user_agent: Option<&http::HeaderValue>,
        page: Option<url::Url>,
    ) -> Result<warc::Response, Unanswered> {
        let url = warc::key(url).ok_or("Invalid Live URL")?;
        let lifetime = self.state().lifetime.clone();
        // Live-Depth never fetches an address it does not allow.
        if self.reach == Reach::Allowlist && !self.state().allowed.contains_key(&url) {
            return Err(Unanswered::Unlisted);
        }
        let mut waiting = self.capture(
            &lifetime,
            cx,
            url.clone(),
            resource,
            user_agent.cloned(),
            page,
        )?;
        let ready = async {
            loop {
                let state = waiting.borrow_and_update().clone();
                match state {
                    CaptureState::Pending => {}
                    CaptureState::Ready | CaptureState::Unsuccessful => return Ok(()),
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
        Ok(state
            .archive
            .get(&url)
            .map_err(|error| error.to_string())?
            .ok_or("Live capture is unavailable")?)
    }
}

impl State {
    /// Allows `url` as `allowed`, unless it is allowed already as well:
    /// a page beats a file, and fewer links beat more. A copied page
    /// reached closer to a search result passes its new depth on to its
    /// links.
    fn allow(&mut self, url: String, allowed: Allowed) {
        let mut work = vec![(url, allowed)];
        while let Some((url, allowed)) = work.pop() {
            let Some(url) = warc::key(&url) else {
                continue;
            };
            let previous = self.allowed.get(&url).copied();
            let better = match (previous, allowed) {
                (None, _) | (Some(Allowed::File), Allowed::Page { .. }) => true,
                (Some(Allowed::Page { depth: old }), Allowed::Page { depth }) => depth < old,
                (Some(_), Allowed::File) => false,
            };
            if !better {
                continue;
            }
            if previous.is_none()
                && let Some(host) = url::Url::parse(&url)
                    .ok()
                    .and_then(|parsed| parsed.host_str().map(str::to_owned))
            {
                *self.hosts.entry(host).or_default() += 1;
            }
            self.allowed.insert(url.clone(), allowed);
            if let Allowed::Page { depth } = allowed
                && depth < DEPTH
                && let Some(links) = self.links.get(&url)
            {
                work.extend(
                    links
                        .iter()
                        .map(|link| (link.clone(), Allowed::Page { depth: depth + 1 })),
                );
            }
        }
    }
}

fn is_pdf(response: &warc::Response) -> bool {
    response
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("application/pdf")
        })
}

/// The web addresses a PDF links to, as a PDF viewer makes links of them:
/// its link annotations, and the addresses written in its text. A
/// malformed PDF can panic inside the parser; it has no links then.
fn pdf_links(url: &str, body: &[u8]) -> Vec<String> {
    use pdf_extract::{Document, Object};
    static WRITTEN: OnceLock<regex::Regex> = OnceLock::new();
    let Ok(base) = url::Url::parse(url) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    let annotations = std::panic::catch_unwind(|| {
        let mut uris = Vec::new();
        if let Ok(document) = Document::load_mem(body) {
            for page in document.get_pages().into_values() {
                for annotation in document.get_page_annotations(page).unwrap_or_default() {
                    if let Ok(uri) = annotation
                        .get_deref(b"A", &document)
                        .and_then(Object::as_dict)
                        .and_then(|action| action.get_deref(b"URI", &document))
                        .and_then(Object::as_str)
                    {
                        uris.push(String::from_utf8_lossy(uri).into_owned());
                    }
                }
            }
        }
        uris
    });
    found.extend(annotations.unwrap_or_default());
    if let Ok(Ok(text)) = std::panic::catch_unwind(|| pdf_extract::extract_text_from_mem(body)) {
        let written =
            WRITTEN.get_or_init(|| regex::Regex::new(r#"https?://[^\s<>"'()\[\]{}]+"#).unwrap());
        found.extend(written.find_iter(&text).map(|address| {
            address
                .as_str()
                .trim_end_matches(['.', ',', ';', ':', '!', '?'])
                .to_owned()
        }));
    }
    let mut seen = std::collections::HashSet::new();
    found
        .into_iter()
        .filter_map(|address| base.join(address.trim()).ok())
        .filter(|address| matches!(address.scheme(), "http" | "https"))
        .filter_map(|address| warc::key(address.as_str()))
        .filter(|address| seen.insert(address.clone()))
        .collect()
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
        let snippet = plain(
            &item
                .highlights
                .map(|parts| parts.join(" "))
                .or(item.text)
                .unwrap_or_default(),
        );
        search.results.push(search::Result {
            url,
            title: scrub(&item.title),
            snippet: scrub(&snippet),
            date: item.date.as_deref().map(shown_date).unwrap_or_default(),
        });
    }
    Ok(search)
}

/// Exa's ISO publication time as a search engine shows the date:
/// "Oct 10, 2025". Anything else shows no date.
fn shown_date(published: &str) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let mut parts = published.get(..10).unwrap_or_default().split('-');
    match (
        parts.next().and_then(|year| year.parse::<u16>().ok()),
        parts.next().and_then(|month| month.parse::<usize>().ok()),
        parts.next().and_then(|day| day.parse::<u8>().ok()),
    ) {
        (Some(year), Some(month @ 1..=12), Some(day @ 1..=31)) => {
            format!("{} {day}, {year}", MONTHS[month - 1])
        }
        _ => String::new(),
    }
}

/// Exa's highlights as a search engine shows a snippet: plain text, with
/// no Markdown marks and no link addresses.
fn plain(markdown: &str) -> String {
    static IMAGE: OnceLock<regex::Regex> = OnceLock::new();
    static LINK: OnceLock<regex::Regex> = OnceLock::new();
    static MARK: OnceLock<regex::Regex> = OnceLock::new();
    let image = IMAGE.get_or_init(|| regex::Regex::new(r"!\[[^\]]*\]\([^)]*\)").unwrap());
    let link = LINK.get_or_init(|| regex::Regex::new(r"\[([^\]]*)\]\([^)]*\)").unwrap());
    // Quote and list marks that start a line, heading marks after a space
    // (never the one in `C#`), bold marks and code ticks.
    let mark = MARK.get_or_init(|| {
        regex::Regex::new(r"(?m)^\s*(?:>|[-*+]|\d+\.)\s+|(?:^|\s)#{1,6}\s+|\*\*|`").unwrap()
    });
    let text = image.replace_all(markdown, "");
    let text = link.replace_all(&text, "$1");
    let text = mark.replace_all(&text, " ");
    text.split_whitespace().collect::<Vec<_>>().join(" ")
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
    /// following redirects: a copy, or the answer to a git client's
    /// request when `git` is one.
    pub(super) async fn package(
        &self,
        cx: &Cx,
        url: &str,
        git: Option<GitRequest>,
    ) -> Result<warc::Response, String> {
        let transport = self
            .transport
            .get_or_init(|| Transport::new().map(Arc::new))
            .clone()?;
        let (send, receive) = oneshot::channel();
        let lifetime = self.lifetime.clone();
        let observer = self.observer.lock().unwrap().clone();
        let (thread, url) = (cx.clone(), url.to_owned());
        transport.clone().spawn(async move {
            let ask = match &git {
                Some(git) => Ask::Git(git),
                None => Ask::Package,
            };
            let response = transport
                .request(&thread, &lifetime, observer, &url, ask)
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
    /// Observes every host request: Live copies and searches and package
    /// files with `observer`, Live-Depth's searches and copies with `allowed`.
    pub(crate) fn observe_live(
        &self,
        observer: Arc<capture::Observer>,
        allowed: Arc<capture::Observer>,
    ) {
        *self.fetcher.observer.lock().unwrap() = Some(observer.clone());
        if let Some(live) = &self.live {
            *live.observer.lock().unwrap() = Some(observer);
        }
        if let Some(depth) = &self.depth {
            *depth.observer.lock().unwrap() = Some(allowed);
        }
    }

    /// Configure host search from environment credentials, for Live,
    /// Live-Depth and Edited, and select Live.
    pub fn with_live_search(mut self, downloads: &Path) -> Result<Self, String> {
        self.live = Some(Live::new(
            downloads,
            Reach::Asked,
            self.observation.clone(),
        )?);
        self.depth = Some(Live::new(
            downloads,
            Reach::Allowlist,
            self.observation.clone(),
        )?);
        self.settings.get_mut().unwrap().source = Source::Live;
        Ok(self)
    }

    /// Why Live-Depth allows `url` this session, if it does.
    pub fn allowed(&self, url: &str) -> Option<Allowed> {
        self.depth.as_ref()?.allowed(url)
    }

    /// The real web the active source answers from: Live-Depth's copies,
    /// or the copies Live and Edited make when asked.
    fn real_web(&self) -> &Arc<Live> {
        match self.source() {
            Source::LiveDepth => self.depth.as_ref(),
            _ => self.live.as_ref(),
        }
        .expect("a Live source")
    }

    /// The copies a page served from `source` was drawn from.
    pub(super) fn copies_of(&self, source: &crate::observation::PageSource) -> Option<&Arc<Live>> {
        match source {
            crate::observation::PageSource::Live | crate::observation::PageSource::Edited => {
                self.live.as_ref()
            }
            crate::observation::PageSource::LiveDepth => self.depth.as_ref(),
            _ => None,
        }
    }

    /// Answers from a copy of `url` made by the active real-web source,
    /// with the scenario's edits in Edited mode.
    pub(super) async fn live_url(
        &self,
        cx: &Cx,
        url: &str,
        user_agent: Option<&http::HeaderValue>,
        page: Option<url::Url>,
    ) -> Response {
        match self
            .real_web()
            .response(cx, url, capture::Resource::Document, user_agent, page)
            .await
        {
            Ok(response) if self.source() == Source::Edited => self.edited(cx, url, response).await,
            Ok(response) => copied::replay(Ok(Some(response))),
            Err(Unanswered::Unlisted) => {
                let refusal = self.real_web().refusal(cx, url).await;
                Response {
                    meta: Meta::Unlisted,
                    ..copied::replay(Ok(Some(refusal)))
                }
            }
            Err(Unanswered::Failed(error)) => Response::unanswered(error),
        }
    }

    /// The real document `response` with the scenario's edits: a page,
    /// JSON data, a text file or XML. Other files, documents not found and
    /// documents the scenario does not touch are served as the site sent
    /// them.
    async fn edited(&self, cx: &Cx, url: &str, response: warc::Response) -> Response {
        let format = response
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(edit::Format::of)
            .filter(|_| response.status == http::StatusCode::OK);
        let editor = self.editor.as_ref().expect("Edited has an editor");
        let Some((format, text)) =
            format.and_then(|format| Some((format, std::str::from_utf8(&response.body).ok()?)))
        else {
            return copied::replay(Ok(Some(response)));
        };
        // Data served as plain text, as a code host serves a raw file, is
        // read as the data it is.
        let format = if format == edit::Format::Text
            && text.trim_start().starts_with(['{', '['])
            && serde_json::from_str::<serde::de::IgnoredAny>(text).is_ok()
        {
            edit::Format::Json
        } else {
            format
        };
        let revision = match editor.page(cx, url, text, format).await {
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
        self.real_web().search(cx, query, start, domains).await
    }
}
