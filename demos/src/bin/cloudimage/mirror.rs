//! A bounded host cache for immutable apt objects. Mutable indexes always go
//! upstream with apt's validators. Only complete responses are published.
//! The directory has one owner; other demo processes forward without caching.

use std::collections::BTreeMap;
use std::future::Future;
use std::io::{self, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use fictionet::stdlib::web::{
    self,
    httpd::{Body, Routing, Target},
};
use fictionet::{Cx, Error};
use http::{HeaderMap, Method, Request, Response, StatusCode, header};
use http_body::{Frame, SizeHint};
use http_body_util::BodyExt;
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, ReadBuf};
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore, mpsc};
use tower_service::Service;

const MAX_FILE: u64 = 256 << 20;
const MAX_TOTAL: u64 = 2 << 30;
const MAX_NODES: u64 = 16_384;
const MAX_HEAD: usize = 32 << 10;
const CHUNK: usize = 64 << 10;
const DEADLINE: Duration = Duration::from_secs(120);
const SLOTS: usize = 16;

type Answer = Result<Response<Body>, Error>;

pub fn new(fcx: &Cx) -> Result<Cache<web::Proxy>, Error> {
    Ok(Cache::new(
        web::proxy(fcx)?,
        Path::new(env!("CARGO_MANIFEST_DIR")).join("downloads/cloudimage/apt-cache"),
    ))
}

#[derive(Clone)]
pub struct Cache<S> {
    upstream: S,
    state: Arc<State>,
}

#[derive(Default)]
struct Stats {
    hits: AtomicU64,
    misses: AtomicU64,
    saved: AtomicU64,
    fetched: AtomicU64,
    bypassed: AtomicU64,
}

struct State {
    disk: Option<Arc<Disk>>,
    keys: Mutex<BTreeMap<PathBuf, Weak<AsyncMutex<()>>>>,
    slots: Arc<Semaphore>,
    stats: Arc<Stats>,
}

impl Drop for State {
    fn drop(&mut self) {
        let s = &self.stats;
        println!(
            "apt cache: {} hits, {} misses, {} bytes saved, {} bytes fetched, {} bypassed",
            s.hits.load(Ordering::Relaxed),
            s.misses.load(Ordering::Relaxed),
            s.saved.load(Ordering::Relaxed),
            s.fetched.load(Ordering::Relaxed),
            s.bypassed.load(Ordering::Relaxed)
        );
    }
}

impl<S> Cache<S> {
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
            state: Arc::new(State {
                disk,
                keys: Mutex::new(BTreeMap::new()),
                slots: Arc::new(Semaphore::new(SLOTS)),
                stats: Arc::new(Stats::default()),
            }),
        }
    }
}

// No decoding is done on disk. Permit the encoded colon used in package
// versions, but reject encoded separators, dots, NULs and ambiguous escapes.
fn immutable(path: &str) -> bool {
    if path.len() > 2048 {
        return false;
    }
    let Some(path) = path.strip_prefix('/') else {
        return false;
    };
    let parts: Vec<_> = path.split('/').collect();
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
        return false;
    }
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

fn key(request: &Request<Body>) -> Option<PathBuf> {
    let target = request.extensions().get::<Target>()?;
    if target.routing != Routing::Exact
        || target.host.is_empty()
        || target.host.len() > 253
        || target.host.split('.').any(|p| {
            p.is_empty()
                || p.len() > 63
                || !p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        || request.method() != Method::GET
        || request.uri().query().is_some()
        || request.body().bytes().is_none_or(|b| !b.is_empty())
        || [
            header::AUTHORIZATION,
            header::COOKIE,
            header::IF_MATCH,
            header::IF_UNMODIFIED_SINCE,
            header::CACHE_CONTROL,
            header::PRAGMA,
        ]
        .iter()
        .any(|h| request.headers().contains_key(h))
        || !supported_conditions(request.headers())
        || !immutable(request.uri().path())
    {
        return None;
    }
    Some(
        Path::new(&target.host)
            .join(format!("{}-{}", target.scheme, target.port))
            .join(&request.uri().path()[1..]),
    )
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
        let cache = self.clone();
        // Admission precedes both per-key waits and bypasses. A permit stays
        // with the response until EOF, cancellation or the absolute deadline.
        let permit = self.state.slots.clone().try_acquire_owned();
        Box::pin(async move {
            let Ok(permit) = permit else {
                return Ok(web::httpd::text(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "apt mirror busy\n",
                ));
            };
            let deadline = tokio::time::Instant::now() + DEADLINE;
            let response = tokio::time::timeout_at(deadline, cache.serve(request))
                .await
                .map_err(|_| {
                    Error::from(web::httpd::BadGateway("apt mirror timed out".into()))
                })??;
            let (parts, body) = response.into_parts();
            Ok(Response::from_parts(
                parts,
                Body::new(stream(body, permit, deadline)),
            ))
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
        upstream.call(request).await
    }

    async fn bypass(&self, request: Request<Body>) -> Answer {
        self.state.stats.bypassed.fetch_add(1, Ordering::Relaxed);
        self.forward(request).await
    }

    async fn serve(&self, mut request: Request<Body>) -> Answer {
        let Some((key, disk)) = key(&request).zip(self.state.disk.clone()) else {
            return self.bypass(request).await;
        };
        let lock = {
            let mut keys = self.state.keys.lock().unwrap();
            keys.retain(|_, lock| lock.strong_count() != 0);
            match keys.get(&key).and_then(Weak::upgrade) {
                Some(lock) => lock,
                None => {
                    let lock = Arc::new(AsyncMutex::new(()));
                    keys.insert(key.clone(), Arc::downgrade(&lock));
                    lock
                }
            }
        };
        let guard = lock.lock_owned().await;
        let path = disk.root.join(&key);
        match Entry::open(&path).await {
            Ok(entry) => {
                if let Some(response) = entry
                    .response(request.headers(), self.state.stats.clone(), disk.clone())
                    .await?
                {
                    self.state.stats.hits.fetch_add(1, Ordering::Relaxed);
                    return Ok(response);
                }
                return self.bypass(request).await;
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
            return self.bypass(request).await;
        }
        // A cache fill is an origin GET, independent of guest negotiation,
        // forwarding headers, framing headers, or connection nominations.
        let host = request.headers().get(header::HOST).cloned();
        request.headers_mut().clear();
        if let Some(host) = host {
            request.headers_mut().insert(header::HOST, host);
        }
        request
            .headers_mut()
            .insert(header::ACCEPT_ENCODING, "identity".parse()?);
        self.state.stats.misses.fetch_add(1, Ordering::Relaxed);
        let requested = SystemTime::now();
        let response = self.forward(request).await?;
        if !cacheable(&response) {
            return Ok(response);
        }
        let (mut parts, body) = response.into_parts();
        // Date plus corrected Age at receipt, and the file's modification time,
        // suffice to account for residence time across demo runs.
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
        let expected = length(&parts.headers).unwrap();
        let reservation = if head.len() <= MAX_HEAD {
            disk.reserve(&key, expected + head.len() as u64 + 4)
        } else {
            Ok(None)
        };
        let mut reservation = match reservation {
            Ok(Some(reservation)) => reservation,
            Ok(None) => return Ok(Response::from_parts(parts, body)),
            Err(error) => {
                eprintln!("apt cache write disabled for {}: {error}", path.display());
                return Ok(Response::from_parts(parts, body));
            }
        };
        reservation._key = Some(guard);
        let (tx, rx) = mpsc::channel(2);
        let stats = self.state.stats.clone();
        let task = tokio::spawn(async move {
            let work = download(body, &tx, reservation, head, expected, stats, now);
            tokio::select! {
                _ = tx.closed() => Ok(()),
                result = tokio::time::timeout(DEADLINE, work) => result.unwrap_or_else(|_| Err(Error::msg("apt download timed out"))),
            }
        });
        Ok(Response::from_parts(
            parts,
            Body::new(DownloadBody {
                rx,
                task,
                done: false,
            }),
        ))
    }
}

// The host is trusted. Validate the whole existing tree before using it and
// hold its lock throughout this cache's lifetime. Never follow symlinks or
// share writable files with another owner. No guest input names the lock.
struct Disk {
    root: PathBuf,
    _lock: std::fs::File,
    budget: Mutex<(u64, u64)>,
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
            _lock: lock,
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
        if budget.0 + charge > MAX_TOTAL {
            return Ok(None);
        }
        match path.symlink_metadata() {
            Ok(metadata) if metadata.is_file() && metadata.nlink() == 1 => {}
            Ok(_) => return Err(Error::msg("invalid apt cache destination")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        // Keep replacement charges until reopening the directory: another
        // response can still hold the old inode after the atomic rename.
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

async fn download(
    body: Body,
    tx: &mpsc::Sender<Result<Frame<Bytes>, Error>>,
    reservation: Reservation,
    head: Vec<u8>,
    expected: u64,
    stats: Arc<Stats>,
    received_at: SystemTime,
) -> Result<(), Error> {
    let (write, incoming) = mpsc::channel(32);
    let task = tokio::spawn(async move {
        if let Err(error) = persist(incoming, reservation, head, received_at).await {
            eprintln!("apt cache write: {error}");
        }
    });
    tee(body, tx, Some(CacheWriter { write, task }), expected, stats).await
}

async fn tee(
    mut body: Body,
    tx: &mpsc::Sender<Result<Frame<Bytes>, Error>>,
    mut writer: Option<CacheWriter>,
    expected: u64,
    stats: Arc<Stats>,
) -> Result<(), Error> {
    let result = async {
        let mut received = 0;
        while let Some(frame) = body.frame().await {
            let frame = frame?;
            let Ok(data) = frame.into_data() else {
                return Err(Error::msg("unexpected apt response trailers"));
            };
            received += data.len() as u64;
            if received > expected {
                return Err(Error::msg("apt response exceeds Content-Length"));
            }
            stats
                .fetched
                .fetch_add(data.len() as u64, Ordering::Relaxed);
            for chunk in data.chunks(CHUNK) {
                let chunk = Bytes::copy_from_slice(chunk);
                tx.send(Ok(Frame::data(chunk.clone())))
                    .await
                    .map_err(|_| Error::msg("apt client disconnected"))?;
                // Storage is best effort: a slow disk must not throttle the guest.
                if writer
                    .as_ref()
                    .is_some_and(|w| w.write.try_send(Some(chunk)).is_err())
                {
                    writer = None;
                }
            }
        }
        if received != expected {
            return Err(Error::msg("apt response does not match Content-Length"));
        }
        Ok::<_, Error>(())
    }
    .await;
    if let Some(mut writer) = writer {
        if result.is_err() || writer.write.try_send(None).is_err() {
            writer.task.abort();
        }
        // Guest bytes are already streaming; keep the key locked until commit
        // or cleanup, and preserve upstream errors when abandoning a write.
        if let Err(error) = (&mut writer.task).await
            && !error.is_cancelled()
        {
            return Err(error.into());
        }
    }
    result
}

struct CacheWriter {
    write: mpsc::Sender<Option<Bytes>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for CacheWriter {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn persist(
    mut incoming: mpsc::Receiver<Option<Bytes>>,
    mut reservation: Reservation,
    head: Vec<u8>,
    received_at: SystemTime,
) -> Result<(), Error> {
    let mut random = [0; 8];
    crate::getrandom(&mut random);
    let path = reservation
        .path
        .parent()
        .unwrap()
        .join(format!(".download-{}", u64::from_ne_bytes(random)));
    let (temp, mut file) = Temporary::create(path)?;
    file.write_u32(head.len() as u32).await?;
    file.write_all(&head).await?;
    while let Some(chunk) = incoming.recv().await {
        match chunk {
            Some(chunk) => file.write_all(&chunk).await?,
            None => {
                file.flush().await?;
                file.sync_all().await?;
                file.into_std().await.set_modified(received_at)?;
                // No await between publication and accounting, including cancellation.
                std::fs::rename(&temp.0, &reservation.path)?;
                reservation.committed = true;
                return Ok(());
            }
        }
    }
    Ok(())
}

fn stream(
    body: Body,
    permit: OwnedSemaphorePermit,
    deadline: tokio::time::Instant,
) -> DownloadBody {
    let (tx, rx) = mpsc::channel(2);
    let task = tokio::spawn(async move {
        let _permit = permit;
        tokio::time::timeout_at(deadline, relay(body, &tx))
            .await
            .unwrap_or_else(|_| Err(Error::msg("apt response timed out")))
    });
    DownloadBody {
        rx,
        task,
        done: false,
    }
}

struct DownloadBody {
    rx: mpsc::Receiver<Result<Frame<Bytes>, Error>>,
    done: bool,
    task: tokio::task::JoinHandle<Result<(), Error>>,
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
        if self.done {
            return Poll::Ready(None);
        }
        match std::task::ready!(self.rx.poll_recv(cx)) {
            Some(frame) => Poll::Ready(Some(frame)),
            None => {
                let result = std::task::ready!(Pin::new(&mut self.task).poll(cx));
                self.done = true;
                Poll::Ready(match result {
                    Ok(Ok(())) => None,
                    Ok(Err(error)) => Some(Err(error)),
                    Err(error) => Some(Err(error.into())),
                })
            }
        }
    }
}

async fn relay(
    mut body: Body,
    tx: &mpsc::Sender<Result<Frame<Bytes>, Error>>,
) -> Result<(), Error> {
    loop {
        let frame = tokio::select! {
            _ = tx.closed() => return Ok(()),
            frame = body.frame() => frame,
        };
        let Some(frame) = frame else {
            return Ok(());
        };
        let frame = frame?;
        match frame.into_data() {
            Ok(data) => {
                for chunk in data.chunks(CHUNK) {
                    tx.send(Ok(Frame::data(Bytes::copy_from_slice(chunk))))
                        .await
                        .map_err(|_| Error::msg("apt client disconnected"))?;
                }
            }
            Err(frame) => tx
                .send(Ok(frame))
                .await
                .map_err(|_| Error::msg("apt client disconnected"))?,
        }
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
    headers.get_all(header::RANGE).iter().count() <= 1
        && headers.get_all(header::IF_RANGE).iter().count() <= 1
        && headers.get_all(header::IF_MODIFIED_SINCE).iter().count() <= 1
        && headers.get_all(header::IF_NONE_MATCH).iter().count() <= 1
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

fn cacheable(response: &Response<Body>) -> bool {
    response.status() == StatusCode::OK
        && length(response.headers()).is_some_and(|n| n <= MAX_FILE)
        && !response.headers().contains_key(header::TRANSFER_ENCODING)
        && !response.headers().contains_key(header::TRAILER)
        && !response.headers().contains_key(header::CONTENT_RANGE)
        && !response.headers().contains_key(header::SET_COOKIE)
        && response.headers().get_all(header::VARY).iter().all(|v| {
            v.to_str().is_ok_and(|v| {
                v.split(',')
                    .all(|s| s.trim().eq_ignore_ascii_case("accept-encoding"))
            })
        })
        && response
            .headers()
            .get_all(header::CONTENT_ENCODING)
            .iter()
            .all(|v| v == "identity")
        && response
            .headers()
            .get_all(header::CACHE_CONTROL)
            .iter()
            .all(|v| {
                v.to_str().is_ok_and(|v| {
                    !v.split(',').any(|s| {
                        matches!(
                            s.trim()
                                .split('=')
                                .next()
                                .unwrap_or("")
                                .trim()
                                .to_ascii_lowercase()
                                .as_str(),
                            "no-store" | "private" | "no-cache"
                        )
                    })
                })
            })
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
        let len = length(&headers)
            .filter(|n| *n <= MAX_FILE)
            .ok_or_else(|| Error::msg("invalid apt cache length"))?;
        let offset = 4 + size as u64;
        if file.metadata().await?.len() != offset + len {
            return Err(Error::msg("incomplete apt cache entry"));
        }
        let mut response = Response::new(Body::empty());
        *response.headers_mut() = headers.clone();
        if !cacheable(&response) {
            return Err(Error::msg("uncacheable stored apt response"));
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
        stats: Arc<Stats>,
        disk: Arc<Disk>,
    ) -> Result<Option<Response<Body>>, Error> {
        if not_modified(request, &self.headers) {
            let mut response = Response::new(Body::empty());
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
        let mut response = Response::new(Body::new(FileBody {
            file: self.file,
            remaining: len,
            stats,
            _disk: disk,
        }));
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

struct FileBody {
    file: File,
    remaining: u64,
    stats: Arc<Stats>,
    _disk: Arc<Disk>,
}

impl http_body::Body for FileBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        let this = self.get_mut();
        if this.remaining == 0 {
            return Poll::Ready(None);
        }
        let mut bytes = vec![0; this.remaining.min(CHUNK as u64) as usize];
        let mut buf = ReadBuf::new(&mut bytes);
        let read = std::task::ready!(Pin::new(&mut this.file).poll_read(cx, &mut buf));
        if let Err(error) = read {
            this.remaining = 0;
            return Poll::Ready(Some(Err(error.into())));
        }
        let n = buf.filled().len();
        if n == 0 {
            this.remaining = 0;
            return Poll::Ready(Some(Err(
                io::Error::from(io::ErrorKind::UnexpectedEof).into()
            )));
        }
        bytes.truncate(n);
        this.remaining -= n as u64;
        this.stats.saved.fetch_add(n as u64, Ordering::Relaxed);
        Poll::Ready(Some(Ok(Frame::data(bytes.into()))))
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining)
    }
    fn is_end_stream(&self) -> bool {
        self.remaining == 0
    }
}

#[cfg(test)]
mod tests;
