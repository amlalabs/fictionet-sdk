//! A bounded host cache for immutable apt objects and versioned release
//! files. Mutable indexes and release channels always go upstream, apt's with
//! its validators. Only complete responses are published.
//! The directory has one owner; other demo processes forward without caching.

use std::collections::BTreeMap;
use std::future::Future;
use std::io::{self, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use fictionet::stdlib::web::{
    self,
    httpd::{Body, Routing, Target},
};
use fictionet::{Cx, Error};
use http::{HeaderMap, Method, Request, Response, StatusCode, header};
use http_body::Frame;
use http_body_util::BodyExt;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore, mpsc};
use tower_service::Service;

const MAX_FILE: u64 = 256 << 20;
const MAX_TOTAL: u64 = 2 << 30;
const MAX_NODES: u64 = 16_384;
const MAX_HEAD: usize = 32 << 10;
const CHUNK: usize = 64 << 10;
const DEADLINE: Duration = Duration::from_secs(120);
/// How long, in all, a slow disk may hold one download back before the
/// cache gives up storing it.
const STALL: Duration = Duration::from_secs(2);
const SLOTS: usize = 16;

type Answer = Result<Response<Body>, Error>;

/// Opens the shared host cache and its upstream web proxy.
pub fn new(fcx: &Cx) -> Result<Cache<web::Proxy>, Error> {
    Ok(Cache::new(
        web::proxy(fcx, std::sync::Arc::new(fictionet_host::Client::new()))?,
        Path::new(env!("CARGO_MANIFEST_DIR")).join("downloads/cloudimage/apt-cache"),
    ))
}

#[derive(Clone)]
/// A web service that caches eligible upstream package downloads.
pub struct Cache<S> {
    upstream: S,
    state: Arc<State>,
    pub(super) addresses: Arc<arc_swap::ArcSwap<Vec<std::net::IpAddr>>>,
    pub(crate) setup: Option<Arc<Setup>>,
}

pub(crate) struct Setup {
    pending: Mutex<std::collections::HashSet<String>>,
}

impl Setup {
    pub(crate) fn new(guests: impl IntoIterator<Item = String>) -> Self {
        Self {
            pending: Mutex::new(guests.into_iter().collect()),
        }
    }

    pub(crate) fn done(&self, guest: &str) {
        self.pending.lock().unwrap().remove(guest);
    }

    fn closed(&self) -> bool {
        self.pending.lock().unwrap().is_empty()
    }
}

#[derive(Default)]
struct Stats {
    hits: AtomicU64,
    misses: AtomicU64,
    saved: AtomicU64,
    fetched: AtomicU64,
    bypassed: Mutex<BTreeMap<&'static str, u64>>,
}

struct State {
    disk: Option<Arc<Disk>>,
    keys: Mutex<BTreeMap<PathBuf, Arc<AsyncMutex<()>>>>,
    slots: Arc<Semaphore>,
    tasks: tokio_util::task::TaskTracker,
    stats: Arc<Stats>,
}

impl Stats {
    fn bypass(&self, reason: &'static str) {
        *self.bypassed.lock().unwrap().entry(reason).or_default() += 1;
    }
}

impl Drop for State {
    fn drop(&mut self) {
        let s = &self.stats;
        let reasons = s.bypassed.lock().unwrap();
        println!(
            "apt cache: {} hits, {} misses, {} bytes saved, {} bytes fetched, {} bypassed \
                {reasons:?}",
            s.hits.load(Ordering::Relaxed),
            s.misses.load(Ordering::Relaxed),
            s.saved.load(Ordering::Relaxed),
            s.fetched.load(Ordering::Relaxed),
            reasons.values().sum::<u64>()
        );
    }
}

impl<S> Cache<S> {
    /// Waits for readers and committed writes before releasing this cache owner.
    /// Call after dropping response bodies and other service clones.
    pub async fn close(self) {
        self.state.tasks.close();
        self.state.tasks.wait().await;
    }

    fn new(upstream: S, root: PathBuf) -> Self {
        let disk = match Disk::open(root) {
            Ok(disk) => Some(Arc::new(disk)),
            Err(error) => {
                eprintln!("apt cache disabled: {error}");
                None
            }
        };
        Self {
            upstream,
            addresses: Default::default(),
            setup: None,
            state: Arc::new(State {
                disk,
                keys: Mutex::new(BTreeMap::new()),
                slots: Arc::new(Semaphore::new(SLOTS)),
                tasks: tokio_util::task::TaskTracker::new(),
                stats: Arc::new(Stats::default()),
            }),
        }
    }
}

/// Hosts that publish each release under a directory named for its version,
/// and the path to those directories. A file below one never changes.
const RELEASES: [(&str, &[&str]); 2] = [
    // Claude Code's native builds and their manifests.
    ("downloads.claude.ai", &["claude-code-releases"]),
    // Codex's packages and their checksums.
    ("releases.openai.com", &["codex", "releases"]),
];

// No decoding is done on disk. Permit the encoded colon used in package
// versions, but reject encoded separators, dots, NULs and ambiguous escapes.
fn segments(path: &str) -> Option<Vec<&str>> {
    if path.len() > 2048 {
        return None;
    }
    let parts: Vec<_> = path.strip_prefix('/')?.split('/').collect();
    if parts.len() > 32
        || parts.iter().any(|p| {
            p.is_empty()
                || *p == "."
                || *p == ".."
                || p.len() > 240
                || !p
                    .replace("%3a", ":")
                    .replace("%3A", ":")
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.:+~".contains(&b))
        })
    {
        return None;
    }
    Some(parts)
}

/// A file inside a version directory of a host in [`RELEASES`].
fn release(host: &str, path: &str) -> bool {
    let Some((_, prefix)) = RELEASES.iter().find(|(name, _)| *name == host) else {
        return false;
    };
    segments(path).is_some_and(|parts| {
        parts.len() > prefix.len() + 1 && parts.starts_with(prefix) && version(parts[prefix.len()])
    })
}

/// A release version: `2.1.292`, or one with a suffix like `0.164.0-alpha.3`.
fn version(name: &str) -> bool {
    let (number, suffix) = name.split_once('-').unwrap_or((name, ""));
    let fields: Vec<_> = number.split('.').collect();
    fields.len() == 3
        && fields
            .iter()
            .all(|f| !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()))
        && suffix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.')
}

fn immutable(path: &str) -> bool {
    let Some(parts) = segments(path) else {
        return false;
    };
    if let Some(at) = parts.iter().position(|p| *p == "by-hash") {
        return parts[..at].contains(&"dists")
            && at + 3 == parts.len()
            && matches!(
                (parts[at + 1], parts[at + 2].len()),
                ("SHA256", 64) | ("SHA512", 128)
            )
            && parts[at + 2].bytes().all(|b| b.is_ascii_hexdigit());
    }
    parts.contains(&"pool") && !parts.contains(&"dists") && path.ends_with(".deb")
}

fn key(request: &Request<Body>) -> Result<PathBuf, &'static str> {
    let target = request.extensions().get::<Target>().ok_or("target")?;
    if target.routing != Routing::Exact
        || target.host.is_empty()
        || target.host.len() > 253
        || target.host.split('.').any(|p| {
            p.is_empty()
                || p.len() > 63
                || !p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err("target");
    }
    if request.method() != Method::GET || request.uri().query().is_some() {
        return Err("query or method");
    }
    if request.body().bytes().is_none_or(|b| !b.is_empty()) {
        return Err("request body");
    }
    let path = request.uri().path();
    if !immutable(path) && !release(&target.host, path) {
        return Err("not immutable");
    }
    let headers = request.headers();
    if headers.contains_key(header::AUTHORIZATION) || headers.contains_key(header::COOKIE) {
        return Err("credentials");
    }
    if headers.contains_key(header::IF_MATCH)
        || headers.contains_key(header::IF_UNMODIFIED_SINCE)
        || !supported_conditions(headers)
    {
        return Err("conditional or range");
    }
    // Request freshness directives are advisory under RFC 9111 section 5.2.1.
    // Immutable names need no refresh; Pragma carries the same preference.
    for name in [header::CACHE_CONTROL, header::PRAGMA] {
        for value in headers.get_all(&name) {
            for directive in value.to_str().map_err(|_| "request directive")?.split(',') {
                let directive = directive.trim();
                if directive.eq_ignore_ascii_case("no-cache") {
                    continue;
                }
                if name == header::CACHE_CONTROL
                    && let Some((key, value)) = directive.split_once('=')
                    && key.trim().eq_ignore_ascii_case("max-age")
                    && value.trim().parse::<u64>().is_ok()
                {
                    continue;
                }
                return Err("request directive");
            }
        }
    }
    Ok(Path::new(&target.host)
        .join(format!("{}-{}", target.scheme, target.port))
        .join(&request.uri().path()[1..]))
}

impl<S> Service<Request<Body>> for Cache<S>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Error>
        + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send,
{
    type Response = Response<Body>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Answer> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        if let Some(address) = request
            .extensions()
            .get::<fictionet::events::ConnInfo>()
            .and_then(|conn| conn.local)
            .map(|address| address.ip())
            && !self.addresses.load().contains(&address)
        {
            self.addresses.rcu(|previous| {
                let mut addresses = (**previous).clone();
                if !addresses.contains(&address) {
                    addresses.push(address);
                }
                addresses
            });
        }
        let cache = self.clone();
        // Admit before per-key waits; hold through EOF, cancellation or deadline.
        let permit = self.state.slots.clone().try_acquire_owned();
        Box::pin(async move {
            if cache.setup.as_ref().is_some_and(|setup| setup.closed()) {
                return Ok(web::httpd::text(
                    StatusCode::FORBIDDEN,
                    "Package mirror closed\n",
                ));
            }
            let Ok(permit) = permit else {
                cache.state.stats.bypass("admission");
                return Ok(web::httpd::text(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "apt mirror busy\n",
                ));
            };
            let deadline = tokio::time::Instant::now() + DEADLINE;
            let (response, fill) = tokio::time::timeout_at(deadline, cache.serve(request))
                .await
                .map_err(|_| {
                    Error::from(web::httpd::BadGateway("apt mirror timed out".into()))
                })??;
            let (parts, body) = response.into_parts();
            Ok(Response::from_parts(
                parts,
                Body::new(stream(
                    body,
                    permit,
                    deadline,
                    fill,
                    cache.state.stats.clone(),
                    cache.state.tasks.clone(),
                )),
            ))
        })
    }
}

/// Forwards to `upstream`, usually this run's [`Cache`], until `closed` is
/// set, then answers every request with 403. Clones share the flag, so a
/// demo can close the mirror once setup is done.
#[derive(Clone)]
pub struct Closable<S> {
    upstream: S,
    closed: Arc<std::sync::atomic::AtomicBool>,
}

impl<S> Closable<S> {
    /// Wraps `upstream`; setting `closed` stops forwarding.
    pub fn new(upstream: S, closed: Arc<std::sync::atomic::AtomicBool>) -> Self {
        Self { upstream, closed }
    }

    fn refusal() -> Response<Body> {
        web::httpd::text(StatusCode::FORBIDDEN, "Package mirror closed\n")
    }
}

impl<S> Service<Request<Body>> for Closable<S>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Error>
        + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send,
{
    type Response = Response<Body>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Answer> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let mut service = self.clone();
        Box::pin(async move {
            if service.closed.load(Ordering::SeqCst) {
                return Ok(Self::refusal());
            }
            std::future::poll_fn(|cx| service.upstream.poll_ready(cx)).await?;
            // The mirror can close while the upstream gets ready.
            if service.closed.load(Ordering::SeqCst) {
                return Ok(Self::refusal());
            }
            service.upstream.call(request).await
        })
    }
}

impl<S> Cache<S>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Error>
        + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send,
{
    async fn forward(&self, request: Request<Body>) -> Answer {
        let mut upstream = self.upstream.clone();
        std::future::poll_fn(|cx| upstream.poll_ready(cx)).await?;
        if self.setup.as_ref().is_some_and(|setup| setup.closed()) {
            return Ok(web::httpd::text(
                StatusCode::FORBIDDEN,
                "Package mirror closed\n",
            ));
        }
        upstream.call(request).await
    }

    async fn bypass(
        &self,
        request: Request<Body>,
        reason: &'static str,
    ) -> Result<(Response<Source>, Option<Fill>), Error> {
        self.state.stats.bypass(reason);
        Ok((self.forward(request).await?.map(Source::Upstream), None))
    }

    async fn serve(
        &self,
        mut request: Request<Body>,
    ) -> Result<(Response<Source>, Option<Fill>), Error> {
        let key = match key(&request) {
            Ok(key) => key,
            Err(reason) => return self.bypass(request, reason).await,
        };
        let Some(disk) = self.state.disk.clone() else {
            return self.bypass(request, "disabled").await;
        };
        let lock = {
            let mut keys = self.state.keys.lock().unwrap();
            keys.retain(|_, lock| Arc::strong_count(lock) > 1);
            keys.entry(key.clone()).or_default().clone()
        };
        let guard = lock.lock_owned().await;
        let path = disk.root.join(&key);
        match Entry::open(&path).await {
            Ok(entry) => {
                if let Some(mut response) = entry.response(request.headers(), disk.clone()).await? {
                    response.extensions_mut().insert(
                        fictionet::events::Fields::new().with("served_by", "host package cache"),
                    );
                    self.state.stats.hits.fetch_add(1, Ordering::Relaxed);
                    return Ok((response, None));
                }
                return self.bypass(request, "conditional or range").await;
            }
            Err(error) => {
                if path.exists() {
                    eprintln!("apt cache unreadable {}: {error}", path.display());
                }
            }
        }
        if request.headers().contains_key(header::RANGE)
            || request.headers().contains_key(header::IF_NONE_MATCH)
            || request.headers().contains_key(header::IF_MODIFIED_SINCE)
        {
            return self.bypass(request, "conditional or range").await;
        }
        // Fill with a canonical origin GET, independent of guest headers.
        let host = request.headers().get(header::HOST).cloned();
        request.headers_mut().clear();
        if let Some(host) = host {
            request.headers_mut().insert(header::HOST, host);
        }
        request
            .headers_mut()
            .insert(header::ACCEPT_ENCODING, "identity".parse()?);
        let release_file = request
            .extensions()
            .get::<Target>()
            .is_some_and(|t| release(&t.host, request.uri().path()));
        self.state.stats.misses.fetch_add(1, Ordering::Relaxed);
        let requested = SystemTime::now();
        let mut response = self.forward(request).await?.map(Source::Upstream);
        // Release servers behind Cloudflare set per-client bot-management
        // cookies on their files. A release file is the same for every
        // client, so the world passes it on, and stores it, without them.
        if release_file {
            response.headers_mut().remove(header::SET_COOKIE);
        }
        let expected = match cacheable(response.status(), response.headers()) {
            Ok(expected) => expected,
            Err(reason) => {
                self.state.stats.bypass(reason);
                return Ok((response, None));
            }
        };
        let (mut parts, body) = response.into_parts();
        // Persist receipt age and time to account for residence across runs.
        let now = SystemTime::now();
        let delay = now
            .duration_since(requested)
            .unwrap_or_default()
            .as_secs()
            .saturating_add(1);
        let age =
            current_age(&parts.headers, now).max(header_age(&parts.headers).saturating_add(delay));
        parts.headers.insert(header::AGE, age.into());
        if !parts.headers.contains_key(header::DATE) {
            parts
                .headers
                .insert(header::DATE, httpdate::fmt_http_date(now).parse()?);
        }
        let head = serde_json::to_vec(
            &parts
                .headers
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_bytes()))
                .collect::<Vec<_>>(),
        )?;
        let reservation = if head.len() > MAX_HEAD {
            Err("header budget")
        } else {
            disk.reserve(&key, expected + head.len() as u64 + 4)
                .map_err(|error| {
                    eprintln!("apt cache write: {error}");
                    "storage"
                })
                .and_then(|r| r.ok_or("full cache"))
        };
        let mut reservation = match reservation {
            Ok(reservation) => reservation,
            Err(reason) => {
                self.state.stats.bypass(reason);
                return Ok((Response::from_parts(parts, body), None));
            }
        };
        reservation._key = Some(guard);
        Ok((
            Response::from_parts(parts, body),
            Some(Fill {
                reservation,
                head,
                expected,
                received_at: now,
            }),
        ))
    }
}

// Validate the trusted host's tree and hold exclusive ownership while in use.
struct Disk {
    root: PathBuf,
    lock: std::fs::File,
    budget: Mutex<(u64, u64)>,
}

impl Drop for Disk {
    fn drop(&mut self) {
        // Release ownership even if a child inherited the open file description.
        if let Err(error) = self.lock.unlock() {
            eprintln!("apt cache unlock: {error}");
        }
    }
}

impl Disk {
    fn open(root: PathBuf) -> Result<Self, Error> {
        for ancestor in root.ancestors() {
            if ancestor.exists()
                && std::fs::symlink_metadata(ancestor)?
                    .file_type()
                    .is_symlink()
            {
                return Err(Error::msg("symlink in apt cache root"));
            }
        }
        std::fs::create_dir_all(&root)?;
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(root.join(".lock"))?;
        if !lock.metadata()?.is_file() || lock.metadata()?.nlink() != 1 {
            return Err(Error::msg("invalid apt cache lock"));
        }
        lock.try_lock()?;
        let mut budget = (0, 0);
        scan(&root, &mut budget, 0)?;
        Ok(Self {
            root,
            lock,
            budget: Mutex::new(budget),
        })
    }

    fn reserve(self: &Arc<Self>, key: &Path, size: u64) -> Result<Option<Reservation>, Error> {
        let mut budget = self.budget.lock().unwrap();
        let charge = size + 4096;
        if budget.0 + charge + key.components().count() as u64 * 4096 > MAX_TOTAL
            || budget.1 + key.components().count() as u64 > MAX_NODES
        {
            return Ok(None);
        }
        let path = self.root.join(key);
        let mut parent = self.root.clone();
        for component in key.parent().unwrap().components() {
            parent.push(component);
            match std::fs::create_dir(&parent) {
                Ok(()) => {
                    budget.0 += 4096;
                    budget.1 += 1;
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    if !std::fs::symlink_metadata(&parent)?.is_dir() {
                        return Err(Error::msg("invalid apt cache directory"));
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
        match path.symlink_metadata() {
            Ok(metadata) if metadata.is_file() && metadata.nlink() == 1 => {}
            Ok(_) => return Err(Error::msg("invalid apt cache destination")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        // Old inodes may still have readers; retain replacement charges.
        budget.0 += charge;
        budget.1 += 1;
        Ok(Some(Reservation {
            disk: self.clone(),
            path,
            charge,
            committed: false,
            _key: None,
        }))
    }
}

fn scan(path: &Path, budget: &mut (u64, u64), depth: usize) -> Result<(), Error> {
    if depth > 36 {
        return Err(Error::msg("apt cache tree too deep"));
    }
    for item in std::fs::read_dir(path)? {
        let item = item?;
        let metadata = item.path().symlink_metadata()?;
        if metadata.is_symlink()
            || (!metadata.is_dir() && (!metadata.is_file() || metadata.nlink() != 1))
        {
            return Err(Error::msg("apt cache contains a link or special file"));
        }
        if metadata.is_file()
            && item
                .file_name()
                .as_encoded_bytes()
                .starts_with(b".download-")
        {
            std::fs::remove_file(item.path())?;
            continue;
        }
        budget.0 += 4096
            + if metadata.is_file() {
                metadata.len()
            } else {
                0
            };
        budget.1 += 1;
        if budget.0 > MAX_TOTAL || budget.1 > MAX_NODES {
            return Err(Error::msg(
                "apt cache exceeds disk budget; clear it before reuse",
            ));
        }
        if metadata.is_dir() {
            scan(&item.path(), budget, depth + 1)?;
        }
    }
    Ok(())
}

struct Reservation {
    disk: Arc<Disk>,
    path: PathBuf,
    charge: u64,
    committed: bool,
    _key: Option<tokio::sync::OwnedMutexGuard<()>>,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.committed {
            let mut budget = self.disk.budget.lock().unwrap();
            budget.0 -= self.charge;
            budget.1 -= 1;
        }
    }
}

enum Source {
    Upstream(Body),
    File(tokio::io::Take<File>, Arc<Disk>),
}

impl Source {
    async fn frame(&mut self) -> Result<Option<Frame<Bytes>>, Error> {
        match self {
            Self::Upstream(body) => body.frame().await.transpose(),
            Self::File(file, _disk) => {
                if file.limit() == 0 {
                    return Ok(None);
                }
                let mut bytes = vec![0; file.limit().min(CHUNK as u64) as usize];
                file.read_exact(&mut bytes).await?;
                Ok(Some(Frame::data(bytes.into())))
            }
        }
    }
}

struct Fill {
    reservation: Reservation,
    head: Vec<u8>,
    expected: u64,
    received_at: SystemTime,
}

async fn tee(
    mut body: Source,
    tx: &mpsc::Sender<Result<Frame<Bytes>, Error>>,
    mut writer: Option<CacheWriter>,
    expected: Option<u64>,
    stats: Arc<Stats>,
) -> Result<(), Error> {
    let cached = matches!(body, Source::File(_, _));
    let result = async {
        let mut received = 0;
        while let Some(frame) = body.frame().await? {
            let data = match frame.into_data() {
                Ok(data) => data,
                Err(frame) if expected.is_none() => {
                    tx.send(Ok(frame))
                        .await
                        .map_err(|_| Error::msg("apt client disconnected"))?;
                    continue;
                }
                Err(_) => return Err(Error::msg("unexpected apt response trailers")),
            };
            received += data.len() as u64;
            if expected.is_some_and(|n| received > n) {
                return Err(Error::msg("apt response exceeds Content-Length"));
            }
            if cached || expected.is_some() {
                let counter = if cached { &stats.saved } else { &stats.fetched };
                counter.fetch_add(data.len() as u64, Ordering::Relaxed);
            }
            for chunk in data.chunks(CHUNK) {
                let chunk = Bytes::copy_from_slice(chunk);
                tx.send(Ok(Frame::data(chunk.clone())))
                    .await
                    .map_err(|_| Error::msg("apt client disconnected"))?;
                // Storage is best effort: a slow disk may hold the guest back
                // for a moment, never for long.
                if let Some(w) = writer.as_mut()
                    && !w.send(chunk).await
                {
                    stats.bypass("storage");
                    writer = None;
                }
            }
            // The last byte is queued: commit before the next await. A client
            // that stops reading at Content-Length and leaves, as curl does,
            // drops this body before its end, and a committed file still lands.
            if expected == Some(received)
                && let Some(w) = writer.as_mut()
            {
                w.commit();
            }
        }
        if expected.is_some_and(|n| received != n) {
            return Err(Error::msg("apt response does not match Content-Length"));
        }
        Ok::<_, Error>(())
    }
    .await;
    if let Some(mut writer) = writer {
        if result.is_err() {
            stats.bypass("invalid body");
            writer.task.abort();
            let _ = (&mut writer.task).await;
            return result;
        }
        // An empty body has no last byte to commit at.
        writer.commit();
        if let Err(error) = (&mut writer.task).await? {
            stats.bypass("storage");
            eprintln!("apt cache write: {error}");
        }
    }
    result
}

struct CacheWriter {
    /// The body's chunks for [`persist`]. Dropping it commits: the writer
    /// publishes the file once it has written every byte.
    write: Option<mpsc::Sender<Bytes>>,
    task: tokio::task::JoinHandle<Result<(), Error>>,
    /// What is left of [`STALL`] for this download.
    stall: Duration,
}
impl CacheWriter {
    fn new(write: mpsc::Sender<Bytes>, task: tokio::task::JoinHandle<Result<(), Error>>) -> Self {
        Self {
            write: Some(write),
            task,
            stall: STALL,
        }
    }

    /// Queues a chunk, waiting while the writer is behind for what is left
    /// of the stall budget; false once it is spent.
    async fn send(&mut self, chunk: Bytes) -> bool {
        let Some(write) = &self.write else {
            return false;
        };
        let chunk = match write.try_send(chunk) {
            Ok(()) => return true,
            Err(mpsc::error::TrySendError::Full(chunk)) => chunk,
            Err(mpsc::error::TrySendError::Closed(_)) => return false,
        };
        let started = tokio::time::Instant::now();
        let sent = tokio::time::timeout(self.stall, write.send(chunk)).await;
        self.stall = self.stall.saturating_sub(started.elapsed());
        matches!(sent, Ok(Ok(())))
    }

    /// Every byte is queued: the file lands even if this writer is dropped.
    fn commit(&mut self) {
        self.write = None;
    }
}
impl Drop for CacheWriter {
    fn drop(&mut self) {
        if self.write.is_some() {
            self.task.abort();
        }
    }
}

async fn persist(
    mut incoming: mpsc::Receiver<Bytes>,
    mut reservation: Reservation,
    head: Vec<u8>,
    expected: u64,
    received_at: SystemTime,
) -> Result<(), Error> {
    let mut random = [0; 8];
    fictionet::random_bytes(&mut random)?;
    let path = reservation
        .path
        .parent()
        .unwrap()
        .join(format!(".download-{}", u64::from_ne_bytes(random)));
    let (temp, mut file) = Temporary::create(path)?;
    file.write_u32(head.len() as u32).await?;
    file.write_all(&head).await?;
    let mut written = 0;
    while let Some(chunk) = incoming.recv().await {
        written += chunk.len() as u64;
        if written > expected {
            return Ok(());
        }
        file.write_all(&chunk).await?;
    }
    // The sender is gone. Only a commit leaves every byte written.
    if written != expected {
        return Ok(());
    }
    file.flush().await?;
    file.sync_all().await?;
    file.into_std().await.set_modified(received_at)?;
    // No await between publication and accounting, including cancellation.
    std::fs::rename(&temp.0, &reservation.path)?;
    reservation.committed = true;
    Ok(())
}

fn stream(
    body: Source,
    permit: OwnedSemaphorePermit,
    deadline: tokio::time::Instant,
    fill: Option<Fill>,
    stats: Arc<Stats>,
    tasks: tokio_util::task::TaskTracker,
) -> DownloadBody {
    let (tx, rx) = mpsc::channel(2);
    let writers = tasks.clone();
    let task = tasks.spawn(async move {
        let _permit = permit;
        let expected = fill.as_ref().map(|f| f.expected);
        let writer = fill.map(|f| {
            let (write, incoming) = mpsc::channel(32);
            let task = writers.spawn(persist(
                incoming,
                f.reservation,
                f.head,
                f.expected,
                f.received_at,
            ));
            CacheWriter::new(write, task)
        });
        let result = tokio::select! {
            _ = tx.closed() => Ok(()),
            result = tokio::time::timeout_at(deadline, tee(body, &tx, writer, expected, stats)) =>
                result.unwrap_or_else(|_| Err(Error::msg("apt response timed out"))),
        };
        drop(_permit);
        if let Err(error) = result {
            let _ = tx.send(Err(error)).await;
        }
    });
    DownloadBody { rx, task }
}

struct DownloadBody {
    rx: mpsc::Receiver<Result<Frame<Bytes>, Error>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for DownloadBody {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl http_body::Body for DownloadBody {
    type Data = Bytes;
    type Error = Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        self.rx.poll_recv(cx)
    }
}

fn length(headers: &HeaderMap) -> Option<u64> {
    if headers.get_all(header::CONTENT_LENGTH).iter().count() != 1 {
        return None;
    }
    headers
        .get(header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

fn date(headers: &HeaderMap, name: header::HeaderName) -> Option<std::time::SystemTime> {
    httpdate::parse_http_date(headers.get(name)?.to_str().ok()?).ok()
}

fn header_age(headers: &HeaderMap) -> u64 {
    headers
        .get(header::AGE)
        .and_then(|v| v.to_str().ok()?.parse().ok())
        .unwrap_or(0)
}

fn current_age(headers: &HeaderMap, now: SystemTime) -> u64 {
    header_age(headers).max(
        date(headers, header::DATE)
            .and_then(|d| now.duration_since(d).ok())
            .unwrap_or_default()
            .as_secs(),
    )
}

fn fresh(headers: &HeaderMap, age: u64) -> bool {
    let mut max_age = None;
    let mut shared_age = None;
    let mut must_revalidate = false;
    for value in headers.get_all(header::CACHE_CONTROL) {
        let Ok(value) = value.to_str() else {
            return false;
        };
        for directive in value.split(',') {
            let (name, value) = directive
                .trim()
                .split_once('=')
                .unwrap_or((directive.trim(), ""));
            match name.trim().to_ascii_lowercase().as_str() {
                "max-age" | "s-maxage" => {
                    let Ok(value) = value.trim().trim_matches('"').parse::<u64>() else {
                        return false;
                    };
                    let slot = if name.trim().eq_ignore_ascii_case("s-maxage") {
                        &mut shared_age
                    } else {
                        &mut max_age
                    };
                    if slot.replace(value).is_some() {
                        return false;
                    }
                }
                "must-revalidate" | "proxy-revalidate" => must_revalidate = true,
                _ => {}
            }
        }
    }
    if let Some(limit) = shared_age.or(max_age) {
        return age < limit;
    }
    if headers.contains_key(header::EXPIRES) {
        return date(headers, header::EXPIRES)
            .zip(date(headers, header::DATE))
            .and_then(|(expires, date)| expires.duration_since(date).ok())
            .is_some_and(|ttl| age < ttl.as_secs());
    }
    // Repository naming is the freshness contract only without an explicit
    // origin freshness requirement. apt still verifies every downloaded object.
    !must_revalidate
}

fn supported_conditions(headers: &HeaderMap) -> bool {
    // Unusual entity tags containing commas can be evaluated by the origin.
    [
        header::RANGE,
        header::IF_RANGE,
        header::IF_MODIFIED_SINCE,
        header::IF_NONE_MATCH,
    ]
    .iter()
    .all(|h| headers.get_all(h).iter().count() <= 1)
        && headers.get(header::IF_NONE_MATCH).is_none_or(|v| {
            v.to_str().is_ok_and(|s| {
                s == "*"
                    || s.split(',').all(|tag| {
                        let tag = tag.trim().strip_prefix("W/").unwrap_or(tag.trim());
                        tag.len() >= 2
                            && tag.starts_with('"')
                            && tag.ends_with('"')
                            && !tag[1..tag.len() - 1].contains('"')
                    })
            })
        })
        && (!headers.contains_key(header::IF_MODIFIED_SINCE)
            || date(headers, header::IF_MODIFIED_SINCE).is_some())
}

fn not_modified(request: &HeaderMap, stored: &HeaderMap) -> bool {
    if let Some(tags) = request
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    {
        return tags == "*"
            || stored
                .get(header::ETAG)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|etag| {
                    tags.split(',').any(|tag| {
                        let tag = tag.trim();
                        tag.strip_prefix("W/").unwrap_or(tag)
                            == etag.strip_prefix("W/").unwrap_or(etag)
                    })
                });
    }
    match (
        date(request, header::IF_MODIFIED_SINCE),
        date(stored, header::LAST_MODIFIED),
    ) {
        (Some(since), Some(modified)) => modified <= since,
        _ => false,
    }
}

fn cacheable(status: StatusCode, headers: &HeaderMap) -> Result<u64, &'static str> {
    if status != StatusCode::OK {
        return Err("response status");
    }
    let len = length(headers).ok_or("response framing")?;
    if len > MAX_FILE {
        return Err("file budget");
    }
    if [
        header::TRANSFER_ENCODING,
        header::TRAILER,
        header::CONTENT_RANGE,
    ]
    .iter()
    .any(|h| headers.contains_key(h))
    {
        return Err("response framing");
    }
    if headers.contains_key(header::SET_COOKIE)
        || !headers.get_all(header::VARY).iter().all(|v| {
            v.to_str().is_ok_and(|v| {
                v.split(',')
                    .all(|s| s.trim().eq_ignore_ascii_case("accept-encoding"))
            })
        })
        || !headers
            .get_all(header::CONTENT_ENCODING)
            .iter()
            .all(|v| v == "identity")
    {
        return Err("response variant");
    }
    for value in headers.get_all(header::CACHE_CONTROL) {
        for directive in value.to_str().map_err(|_| "response directive")?.split(',') {
            if matches!(
                directive
                    .split('=')
                    .next()
                    .unwrap()
                    .trim()
                    .to_ascii_lowercase()
                    .as_str(),
                "no-store" | "private" | "no-cache"
            ) {
                return Err("response directive");
            }
        }
    }
    Ok(len)
}

struct Temporary(PathBuf);
impl Temporary {
    fn create(path: PathBuf) -> io::Result<(Self, File)> {
        // Create synchronously so cancellation cannot leave a late-created file.
        // Only the creator owns cleanup; a name collision must preserve its file.
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        Ok((Self(path), File::from_std(file)))
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_file(&self.0)
            && error.kind() != io::ErrorKind::NotFound
        {
            eprintln!("apt cache cleanup: {error}");
        }
    }
}

struct Entry {
    file: File,
    headers: HeaderMap,
    offset: u64,
    len: u64,
}

impl Entry {
    async fn open(path: &Path) -> Result<Self, Error> {
        let mut file = File::from_std(
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path)?,
        );
        let metadata = file.metadata().await?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(Error::msg("invalid apt cache file"));
        }
        let size = file.read_u32().await? as usize;
        if size > MAX_HEAD {
            return Err(Error::msg("apt cache header too large"));
        }
        let mut head = vec![0; size];
        file.read_exact(&mut head).await?;
        let values: Vec<(String, Vec<u8>)> = serde_json::from_slice(&head)?;
        let mut headers = HeaderMap::new();
        for (name, value) in values {
            headers.append(
                http::header::HeaderName::from_bytes(name.as_bytes())?,
                value.try_into()?,
            );
        }
        let len = cacheable(StatusCode::OK, &headers).map_err(Error::msg)?;
        let offset = 4 + size as u64;
        if metadata.len() != offset + len {
            return Err(Error::msg("incomplete apt cache entry"));
        }
        let now = SystemTime::now();
        let residence = now
            .duration_since(metadata.modified()?)
            .unwrap_or_default()
            .as_secs();
        let age = current_age(&headers, now).max(header_age(&headers).saturating_add(residence));
        headers.insert(header::AGE, age.into());
        if !fresh(&headers, age) {
            return Err(Error::msg("expired apt cache entry"));
        }
        Ok(Self {
            file,
            headers,
            offset,
            len,
        })
    }

    async fn response(
        mut self,
        request: &HeaderMap,
        disk: Arc<Disk>,
    ) -> Result<Option<Response<Source>>, Error> {
        if not_modified(request, &self.headers) {
            let mut response = Response::new(Source::Upstream(Body::empty()));
            *response.status_mut() = StatusCode::NOT_MODIFIED;
            *response.headers_mut() = self.headers;
            return Ok(Some(response));
        }
        let mut start = 0;
        let mut len = self.len;
        let mut status = StatusCode::OK;
        if let Some(range) = request.get(header::RANGE) {
            if let Some(validator) = request.get(header::IF_RANGE) {
                let strong_etag = !validator.as_bytes().starts_with(b"W/")
                    && self.headers.get(header::ETAG) == Some(validator);
                if !strong_etag && self.headers.get(header::LAST_MODIFIED) != Some(validator) {
                    return Ok(None);
                }
            }
            let Some((from, count)) = range.to_str().ok().and_then(|r| byte_range(r, len)) else {
                return Ok(None);
            };
            start = from;
            len = count;
            status = StatusCode::PARTIAL_CONTENT;
            self.headers.insert(
                header::CONTENT_RANGE,
                format!("bytes {}-{}/{}", start, start + len - 1, self.len).parse()?,
            );
        }
        self.file.seek(SeekFrom::Start(self.offset + start)).await?;
        self.headers.insert(header::CONTENT_LENGTH, len.into());
        self.headers.insert(header::ACCEPT_RANGES, "bytes".parse()?);
        let mut response = Response::new(Source::File(self.file.take(len), disk));
        *response.status_mut() = status;
        *response.headers_mut() = self.headers;
        Ok(Some(response))
    }
}

// Unsupported, multiple, and unsatisfiable ranges go upstream unchanged.
fn byte_range(value: &str, len: u64) -> Option<(u64, u64)> {
    let (start, end) = value.strip_prefix("bytes=")?.split_once('-')?;
    if !start.bytes().chain(end.bytes()).all(|b| b.is_ascii_digit()) {
        return None;
    }
    if len == 0 {
        return None;
    }
    if start.is_empty() {
        let count = end.parse::<u64>().ok()?.min(len);
        return (count > 0).then_some((len - count, count));
    }
    let start: u64 = start.parse().ok()?;
    let end = if end.is_empty() {
        len - 1
    } else {
        end.parse::<u64>().ok()?.min(len - 1)
    };
    (start <= end).then(|| (start, end - start + 1))
}

#[cfg(test)]
mod tests;
