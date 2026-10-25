//! Host search and public page copies with their dependencies, retained
//! for replay: copied when a client asks for them (Live and Edited), or
//! collected ahead of time by a crawl around each search (Live-Depth).

use super::*;
use fictionet_extras::{
    capture,
    models::Key,
    warc::{self, Archive},
};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet, VecDeque};
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

/// How a session reaches the real web.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Reach {
    /// Live and Edited: any page a client asks for is copied when asked.
    Asked,
    /// Live-Depth: each search's results and their sites are crawled
    /// [`DEPTH`] links deep ahead of time, and only what the crawl reached
    /// exists.
    Crawl,
}

/// How many links from a search result Live-Depth follows on its site.
const DEPTH: u8 = 5;

#[derive(Clone)]
enum CaptureState {
    Pending,
    Ready,
    Failed(String),
    Cancelled,
}

/// Why a copy of an address could not be served.
pub(super) enum Unanswered {
    /// Live-Depth's crawl did not reach it, so it was not fetched.
    Uncollected,
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

/// Where a crawled page sits: the site of the search result the crawl
/// started from, and how many links from that result it is.
#[derive(Clone)]
struct Navigation {
    site: String,
    depth: u8,
}

/// One address the crawl fetches.
struct Job {
    url: String,
    resource: capture::Resource,
    /// A page's place in the crawl; `None` for a file.
    navigation: Option<Navigation>,
    /// The page a file belongs to.
    page: Option<url::Url>,
    /// The search whose crawl reached it first.
    search: Arc<str>,
    /// Whether this job admitted the address; a job that follows a page
    /// again from closer to a search result does not count it twice.
    fresh: bool,
    cx: Cx,
}

/// One host's crawl requests, fetched one at a time, as a polite crawler
/// fetches from a site.
#[derive(Default)]
struct Queue {
    jobs: VecDeque<Job>,
    running: bool,
}

/// What one search's crawl collected so far.
#[derive(Clone, Copy, Default)]
struct Tally {
    pages: u64,
    files: u64,
    failed: u64,
    waiting: u64,
    deepest: u8,
}

#[derive(Default)]
struct State {
    archive: Archive,
    lifetime: Arc<Lifetime>,
    epoch: usize,
    reached: HashMap<String, watch::Sender<CaptureState>>,
    /// The session's world, which the crawl runs in.
    cx: Option<Cx>,
    /// Live-Depth: the fewest links from a search result each page was
    /// reached at.
    depths: HashMap<String, u8>,
    /// Live-Depth: the hosts the crawl reached, which the world's DNS
    /// answers for.
    hosts: HashSet<String>,
    /// Live-Depth: each host's crawl requests.
    queues: HashMap<String, Queue>,
    /// Live-Depth: what each search's crawl collected.
    crawls: HashMap<Arc<str>, Tally>,
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
    /// Where the crawl's progress is reported.
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
            Reach::Crawl => "live-depth",
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
            // A copied page brings what lays a still picture of it out: its
            // stylesheets, CSS imports, fonts and icons, including those of
            // pages already in the archive, so the host's picture of the page
            // is drawn from what the world holds. Its images come as the
            // picture or a client asks for them, the way a browser loads
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

    /// Admits `job` to the crawl: an address no job reached yet, or a page
    /// reached again closer to a search result, which is followed further
    /// from there. Jobs `first` in line go before the host's others: a
    /// search's results, a page's files and redirects, and what a client
    /// is waiting for.
    fn crawl(self: &Arc<Self>, lifetime: &Arc<Lifetime>, mut job: Job, first: bool) {
        let Some(url) = warc::key(&job.url) else {
            return;
        };
        let Some(host) = url::Url::parse(&url)
            .ok()
            .and_then(|parsed| parsed.host_str().map(str::to_owned))
        else {
            return;
        };
        let mut state = self.state();
        if lifetime.cancelled() || !Arc::ptr_eq(lifetime, &state.lifetime) {
            return;
        }
        job.fresh = !state.reached.contains_key(&url);
        if job.fresh {
            state
                .reached
                .insert(url.clone(), watch::channel(CaptureState::Pending).0);
            state.crawls.entry(job.search.clone()).or_default().waiting += 1;
        } else {
            let Some(navigation) = &job.navigation else {
                return;
            };
            if state
                .depths
                .get(&url)
                .is_some_and(|depth| *depth <= navigation.depth)
            {
                return;
            }
        }
        if let Some(navigation) = &job.navigation {
            state.depths.insert(url.clone(), navigation.depth);
        }
        job.url = url;
        state.hosts.insert(host.clone());
        self.enqueue(lifetime, &mut state, host, job, first);
    }

    /// Puts `job` in `host`'s line, starting the host's fetches if none
    /// are running.
    fn enqueue(
        self: &Arc<Self>,
        lifetime: &Arc<Lifetime>,
        state: &mut State,
        host: String,
        job: Job,
        first: bool,
    ) {
        let queue = state.queues.entry(host.clone()).or_default();
        if first {
            queue.jobs.push_front(job);
        } else {
            queue.jobs.push_back(job);
        }
        if !queue.running {
            queue.running = true;
            let (live, lifetime) = (self.clone(), lifetime.clone());
            self.fetcher
                .spawn(async move { live.work(lifetime, host).await });
        }
    }

    /// Fetches `host`'s crawl requests in turn until none are left.
    async fn work(self: Arc<Self>, lifetime: Arc<Lifetime>, host: String) {
        loop {
            let job = {
                let mut state = self.state();
                if lifetime.cancelled() || !Arc::ptr_eq(&lifetime, &state.lifetime) {
                    return;
                }
                let queue = state.queues.entry(host.clone()).or_default();
                let Some(job) = queue.jobs.pop_front() else {
                    queue.running = false;
                    return;
                };
                job
            };
            self.collect(&lifetime, job).await;
        }
    }

    /// Fetches one crawl request and admits what it leads to: a redirect's
    /// target, a page's files, a stylesheet's imports and fonts, and the
    /// pages a page links to on its site, while they are fewer than
    /// [`DEPTH`] links from the search result. They are admitted before
    /// the address is ready, so the hosts a page's files live on resolve
    /// by the time a client has the page.
    async fn collect(self: &Arc<Self>, lifetime: &Arc<Lifetime>, job: Job) {
        let cx = job.cx.clone();
        let outcome = match self
            .download(lifetime, &cx, &job.url, None, job.page.as_ref())
            .await
        {
            Ok(response) => {
                let (url, resource) = (job.url.clone(), job.resource);
                let redirect = response.status.is_redirection();
                let followed = redirect
                    || resource == capture::Resource::Document
                    || response
                        .headers
                        .get(http::header::CONTENT_TYPE)
                        .is_some_and(|value| value.as_bytes().starts_with(b"text/css"));
                let links = if followed {
                    self.fetcher
                        .process(&cx, lifetime, move || {
                            capture::links(&url, &response).map_err(|error| error.to_string())
                        })
                        .await
                } else {
                    Ok(capture::Links::default())
                };
                match links {
                    Ok(links) => {
                        self.follow(lifetime, &job, redirect, links);
                        CaptureState::Ready
                    }
                    Err(_) if lifetime.cancelled() || cx.is_cancelled() => CaptureState::Cancelled,
                    Err(error) => {
                        eprintln!("Live-Depth link discovery failed: {error}");
                        CaptureState::Ready
                    }
                }
            }
            Err(_) if lifetime.cancelled() || cx.is_cancelled() => CaptureState::Cancelled,
            Err(error) => CaptureState::Failed(error),
        };
        let mut state = self.state();
        if !Arc::ptr_eq(lifetime, &state.lifetime) {
            return;
        }
        if let Some(reached) = state.reached.get(&job.url) {
            reached.send_replace(outcome.clone());
        }
        if !job.fresh {
            return;
        }
        let tally = state.crawls.entry(job.search.clone()).or_default();
        tally.waiting = tally.waiting.saturating_sub(1);
        let page = job.resource == capture::Resource::Document;
        match outcome {
            CaptureState::Ready if page => tally.pages += 1,
            CaptureState::Ready => tally.files += 1,
            CaptureState::Failed(_) => tally.failed += 1,
            CaptureState::Pending | CaptureState::Cancelled => return,
        }
        if let Some(navigation) = &job.navigation {
            tally.deepest = tally.deepest.max(navigation.depth);
        }
        // Each page collected, and the end of the crawl, reach the page.
        if page || tally.waiting == 0 {
            let tally = *tally;
            drop(state);
            crate::observation::report(
                &self.observations,
                &cx,
                crate::observation::SearchObs::Crawl {
                    search: job.search.to_string(),
                    pages: tally.pages,
                    files: tally.files,
                    failed: tally.failed,
                    waiting: tally.waiting,
                    depth: tally.deepest,
                },
            );
        }
    }

    /// Admits what the crawl request `job` led to.
    fn follow(
        self: &Arc<Self>,
        lifetime: &Arc<Lifetime>,
        job: &Job,
        redirect: bool,
        links: capture::Links,
    ) {
        let next = |url: String, resource, navigation, page| Job {
            url,
            resource,
            navigation,
            page,
            search: job.search.clone(),
            fresh: true,
            cx: job.cx.clone(),
        };
        if redirect {
            // A search result that moved puts its crawl on the site it
            // moved to; a page further in keeps the result's site.
            for url in links.pages {
                let navigation = job.navigation.as_ref().map(|navigation| Navigation {
                    site: match navigation.depth {
                        0 => site_of(&url).unwrap_or_else(|| navigation.site.clone()),
                        _ => navigation.site.clone(),
                    },
                    depth: navigation.depth,
                });
                self.crawl(
                    lifetime,
                    next(url, job.resource, navigation, job.page.clone()),
                    true,
                );
            }
            return;
        }
        let owner = job.page.clone().or_else(|| url::Url::parse(&job.url).ok());
        for url in links.assets.into_iter().rev() {
            self.crawl(
                lifetime,
                next(url, capture::Resource::Requisite, None, owner.clone()),
                true,
            );
        }
        let Some(navigation) = &job.navigation else {
            return;
        };
        // A page reached again closer to a search result is followed from
        // there.
        let depth = self
            .state()
            .depths
            .get(&job.url)
            .map_or(navigation.depth, |depth| (*depth).min(navigation.depth));
        if depth >= DEPTH {
            return;
        }
        for url in links.pages {
            if site_of(&url).as_deref() == Some(navigation.site.as_str()) {
                let navigation = Navigation {
                    site: navigation.site.clone(),
                    depth: depth + 1,
                };
                self.crawl(
                    lifetime,
                    next(url, capture::Resource::Document, Some(navigation), None),
                    false,
                );
            }
        }
    }

    /// Starts crawling each result of the search `query` on its site.
    fn crawl_results(
        self: &Arc<Self>,
        lifetime: &Arc<Lifetime>,
        cx: &Cx,
        query: &str,
        search: &search::Search,
    ) {
        let cx = self.state().cx.clone().unwrap_or_else(|| cx.clone());
        let query: Arc<str> = Arc::from(query);
        for result in search.results.iter().rev() {
            let Some(site) = site_of(&result.url) else {
                continue;
            };
            self.crawl(
                lifetime,
                Job {
                    url: result.url.clone(),
                    resource: capture::Resource::Document,
                    navigation: Some(Navigation { site, depth: 0 }),
                    page: None,
                    search: query.clone(),
                    fresh: true,
                    cx: cx.clone(),
                },
                true,
            );
        }
    }

    /// The crawl's progress on `url` for a client asking for it, moved to
    /// the front of its host's line; `None` when the crawl did not reach
    /// it. A copy that failed is fetched again.
    fn asked(
        self: &Arc<Self>,
        lifetime: &Arc<Lifetime>,
        url: &str,
    ) -> Option<watch::Receiver<CaptureState>> {
        let mut state = self.state();
        if lifetime.cancelled() || !Arc::ptr_eq(lifetime, &state.lifetime) {
            return None;
        }
        let reached = state.reached.get(url)?.subscribe();
        let failed = matches!(*reached.borrow(), CaptureState::Failed(_));
        let host = url::Url::parse(url).ok()?.host_str()?.to_owned();
        let state = &mut *state;
        let queue = state.queues.entry(host.clone()).or_default();
        if let Some(index) = queue.jobs.iter().position(|job| job.url == url) {
            let job = queue.jobs.remove(index).expect("a queued job");
            queue.jobs.push_front(job);
        } else if failed {
            let cx = state.cx.clone()?;
            let depth = state.depths.get(url).copied();
            let navigation = depth.and_then(|depth| {
                Some(Navigation {
                    site: site_of(url)?,
                    depth,
                })
            });
            state.reached.get(url)?.send_replace(CaptureState::Pending);
            let job = Job {
                url: url.to_owned(),
                resource: match navigation {
                    Some(_) => capture::Resource::Document,
                    None => capture::Resource::Requisite,
                },
                navigation,
                page: None,
                search: Arc::from(""),
                fresh: false,
                cx,
            };
            self.enqueue(lifetime, state, host, job, true);
        }
        Some(reached)
    }

    /// Whether Live-Depth's crawl reached a page or file on `host`.
    pub(super) fn reached_host(&self, host: &str) -> bool {
        self.state().hosts.contains(host)
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
        // The results are in line before the list is shown, so their
        // hosts resolve when the client follows them.
        if self.reach == Reach::Crawl {
            self.crawl_results(lifetime, cx, query, &search);
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

    /// Stops this session's copies and crawl.
    fn revoke(&self) {
        let mut state = self.state();
        state.lifetime.cancel();
        for (url, done) in &state.reached {
            done.send_replace(if state.archive.contains(url) {
                CaptureState::Ready
            } else {
                CaptureState::Cancelled
            });
        }
        state.queues.clear();
    }

    /// Starts a new session in the world `fcx`, forgetting everything the
    /// previous one copied or crawled.
    pub(super) fn restart(&self, fcx: &Cx) {
        self.revoke();
        let mut state = self.state();
        let epoch = state.epoch + 1;
        let old_path = self.archive_path(state.epoch);
        *state = State {
            epoch,
            cx: Some(fcx.clone()),
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
    /// of `page`. Live-Depth answers only from what its crawl reached,
    /// waiting for a copy still in line.
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
        let mut waiting = match self.reach {
            Reach::Asked => self.capture(
                &lifetime,
                cx,
                url.clone(),
                resource,
                user_agent.cloned(),
                page,
            )?,
            Reach::Crawl => self.asked(&lifetime, &url).ok_or(Unanswered::Uncollected)?,
        };
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
        Ok(state
            .archive
            .get(&url)
            .map_err(|error| error.to_string())?
            .ok_or("Live capture is unavailable")?)
    }
}

/// The site an address is on, for staying on it: its host without `www.`.
fn site_of(url: &str) -> Option<String> {
    let url = url::Url::parse(url).ok()?;
    Some(url.host_str()?.trim_start_matches("www.").to_owned())
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
    /// Observes every host request: Live copies and searches and package
    /// files with `observer`, Live-Depth's searches and crawl with `crawl`.
    pub(crate) fn observe_live(
        &self,
        observer: Arc<capture::Observer>,
        crawl: Arc<capture::Observer>,
    ) {
        *self.fetcher.observer.lock().unwrap() = Some(observer.clone());
        if let Some(live) = &self.live {
            *live.observer.lock().unwrap() = Some(observer);
        }
        if let Some(depth) = &self.depth {
            *depth.observer.lock().unwrap() = Some(crawl);
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
            Reach::Crawl,
            self.observation.clone(),
        )?);
        self.settings.get_mut().unwrap().source = Source::Live;
        Ok(self)
    }

    /// The real web the active source answers from: Live-Depth's crawl,
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
            Err(Unanswered::Uncollected) => Response::uncollected(),
            Err(Unanswered::Failed(error)) => Response::new(
                502,
                "text/plain; charset=utf-8",
                "Bad Gateway\n",
                vec![],
                Meta::Error { error },
            ),
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
