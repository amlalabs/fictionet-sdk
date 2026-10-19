//! Persistent apt responses on the host. Each entry contains a bounded HTTP
//! header block followed by the body, committed together with one rename.
//! Index validators are checked once per world; package paths never expire.

use std::collections::BTreeMap;
use std::future::Future;
use std::io::{self, SeekFrom};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use fictionet::stdlib::web::{
    self,
    httpd::{Body, Routing, Target},
};
use fictionet::{Cx, Error};
use http::{HeaderMap, Method, Request, Response, StatusCode, header};
use http_body::{Frame, SizeHint};
use http_body_util::BodyExt;
use tokio::fs::{self, File};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, ReadBuf};
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use tower_service::Service;

const MAX_FILE: u64 = 512 << 20;
const MAX_HEAD: usize = 32 << 10;
const MAX_KEYS: usize = 4096;
const CHUNK: usize = 64 << 10;
const DEADLINE: Duration = Duration::from_secs(120);

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
    revalidated: AtomicU64,
    offline: AtomicU64,
    bypassed: AtomicU64,
}

struct State {
    root: PathBuf,
    // Fixed admission limits bound both retained keys and concurrent disk work.
    keys: Mutex<BTreeMap<PathBuf, Arc<AsyncMutex<bool>>>>,
    slots: Semaphore,
    stats: Arc<Stats>,
}

impl Drop for State {
    fn drop(&mut self) {
        let s = &self.stats;
        println!(
            "apt cache: {} hits, {} misses, {} bytes saved, {} bytes fetched, {} revalidated, {} offline, {} bypassed",
            s.hits.load(Ordering::Relaxed),
            s.misses.load(Ordering::Relaxed),
            s.saved.load(Ordering::Relaxed),
            s.fetched.load(Ordering::Relaxed),
            s.revalidated.load(Ordering::Relaxed),
            s.offline.load(Ordering::Relaxed),
            s.bypassed.load(Ordering::Relaxed),
        );
    }
}

impl<S> Cache<S> {
    fn new(upstream: S, root: PathBuf) -> Self {
        Self {
            upstream,
            state: Arc::new(State {
                root,
                keys: Mutex::new(BTreeMap::new()),
                slots: Semaphore::new(16),
                stats: Arc::new(Stats::default()),
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Policy {
    Immutable,
    Index,
}

fn policy(path: &str) -> Option<Policy> {
    let parts: Vec<_> = path.strip_prefix('/')?.split('/').collect();
    if path.len() > 2048
        || parts.len() > 32
        || parts.iter().any(|p| {
            p.is_empty()
                || *p == "."
                || *p == ".."
                || p.len() > 240
                || !p
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.:+%~".contains(&b))
        })
    {
        return None;
    }
    if parts.windows(2).any(|p| p[0] == "by-hash")
        || (parts.contains(&"pool") && path.ends_with(".deb"))
    {
        Some(Policy::Immutable)
    } else if parts.windows(2).any(|p| p[0] == "dists") {
        Some(Policy::Index)
    } else {
        None
    }
}

fn key(request: &Request<Body>) -> Option<(PathBuf, Policy)> {
    let target = request.extensions().get::<Target>()?;
    if target.routing != Routing::Exact
        || !target
            .host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
        || target.host.is_empty()
        || target.host == "."
        || target.host == ".."
        || target.host.len() > 253
        || request.method() != Method::GET
        || request.uri().query().is_some()
        || request.body().bytes().is_none_or(|b| !b.is_empty())
        || [
            header::AUTHORIZATION,
            header::COOKIE,
            header::IF_MATCH,
            header::IF_UNMODIFIED_SINCE,
        ]
        .iter()
        .any(|h| request.headers().contains_key(h))
        || !supported_conditions(request.headers())
    {
        return None;
    }
    let path = request.uri().path();
    let policy = policy(path)?;
    Some((
        Path::new(&target.host)
            .join(format!("{}-{}", target.scheme, target.port))
            .join(&path[1..]),
        policy,
    ))
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
        Box::pin(async move {
            let selected = key(&request);
            tokio::time::timeout(DEADLINE, cache.serve(request, selected))
                .await
                .map_err(|_| Error::from(web::httpd::BadGateway("apt mirror timed out".into())))?
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

    async fn serve(
        &self,
        mut request: Request<Body>,
        selected: Option<(PathBuf, Policy)>,
    ) -> Answer {
        let Some((key, policy)) = selected else {
            return self.bypass(request).await;
        };
        let lock = {
            let mut keys = self.state.keys.lock().unwrap();
            if !keys.contains_key(&key) && keys.len() >= MAX_KEYS {
                None
            } else {
                Some(keys.entry(key.clone()).or_default().clone())
            }
        };
        let Some(lock) = lock else {
            return self.bypass(request).await;
        };
        let mut checked = lock.lock().await;
        let _slot = self.state.slots.acquire().await?;
        let path = self.state.root.join(key);
        let mut cached = Entry::open(&path).await.ok();
        if policy == Policy::Immutable || *checked {
            if let Some(entry) = cached.take() {
                return match entry
                    .response(request.headers(), Some(self.state.stats.clone()))
                    .await?
                {
                    Some(response) => {
                        self.state.stats.hits.fetch_add(1, Ordering::Relaxed);
                        Ok(response)
                    }
                    None => self.bypass(request).await,
                };
            }
        } else if request.headers().contains_key(header::RANGE) {
            return self.bypass(request).await;
        }
        if request.headers().contains_key(header::RANGE) {
            return self.bypass(request).await;
        }
        let conditions = request.headers().clone();
        // All stored representations are requested without content negotiation.
        request
            .headers_mut()
            .insert(header::ACCEPT_ENCODING, "identity".parse()?);
        request.headers_mut().remove(header::IF_RANGE);
        request.headers_mut().remove(header::IF_NONE_MATCH);
        request.headers_mut().remove(header::IF_MODIFIED_SINCE);
        if let Some(entry) = &cached {
            if let Some(etag) = entry.headers.get(header::ETAG) {
                request
                    .headers_mut()
                    .insert(header::IF_NONE_MATCH, etag.clone());
            } else if let Some(modified) = entry.headers.get(header::LAST_MODIFIED) {
                request
                    .headers_mut()
                    .insert(header::IF_MODIFIED_SINCE, modified.clone());
            }
        }
        self.state.stats.misses.fetch_add(1, Ordering::Relaxed);
        let result = tokio::time::timeout(Duration::from_secs(45), self.forward(request))
            .await
            .unwrap_or_else(
                |_| Err(web::httpd::BadGateway("apt upstream timed out".into()).into()),
            );
        let offline = result
            .as_ref()
            .map_or(true, |r| matches!(r.status().as_u16(), 502..=504));
        if (offline
            || result
                .as_ref()
                .is_ok_and(|r| r.status() == StatusCode::NOT_MODIFIED))
            && let Some(entry) = cached.take()
        {
            *checked = true;
            self.state.stats.hits.fetch_add(1, Ordering::Relaxed);
            if offline {
                self.state.stats.offline.fetch_add(1, Ordering::Relaxed);
            } else {
                self.state.stats.revalidated.fetch_add(1, Ordering::Relaxed);
            }
            return Ok(entry
                .response(&conditions, Some(self.state.stats.clone()))
                .await?
                .unwrap());
        }
        let mut response = result?;
        if !cacheable(&response) {
            if response.status() == StatusCode::OK && not_modified(&conditions, response.headers())
            {
                *response.status_mut() = StatusCode::NOT_MODIFIED;
                *response.body_mut() = Body::empty();
            }
            return Ok(response);
        }
        let stored = tokio::time::timeout(Duration::from_secs(60), self.store(&path, response))
            .await
            .unwrap_or_else(|_| Err(Error::msg("apt download timed out")));
        let entry = match stored {
            Ok(entry) => entry,
            Err(error) => {
                if let Some(entry) = cached {
                    *checked = true;
                    self.state.stats.hits.fetch_add(1, Ordering::Relaxed);
                    self.state.stats.offline.fetch_add(1, Ordering::Relaxed);
                    return Ok(entry
                        .response(&conditions, Some(self.state.stats.clone()))
                        .await?
                        .unwrap());
                }
                return Err(web::httpd::BadGateway(error.to_string()).into());
            }
        };
        *checked = true;
        Ok(entry.response(&conditions, None).await?.unwrap())
    }

    async fn store(&self, path: &Path, response: Response<Body>) -> Result<Entry, Error> {
        let (parts, mut body) = response.into_parts();
        let expected = length(&parts.headers).unwrap();
        let headers: Vec<_> = parts
            .headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_bytes()))
            .collect();
        let head = serde_json::to_vec(&headers)?;
        if head.len() > MAX_HEAD {
            return Err(Error::msg("apt response headers too large"));
        }
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent).await?;
        let mut random = [0; 8];
        crate::getrandom(&mut random);
        let temp = parent.join(format!(".download-{}", u64::from_ne_bytes(random)));
        let mut file = File::options()
            .write(true)
            .create_new(true)
            .open(&temp)
            .await?;
        let temp = Temporary(temp);
        file.write_u32(head.len() as u32).await?;
        file.write_all(&head).await?;
        let mut received = 0;
        while let Some(frame) = body.frame().await {
            if let Ok(data) = frame?.into_data() {
                received += data.len() as u64;
                self.state
                    .stats
                    .fetched
                    .fetch_add(data.len() as u64, Ordering::Relaxed);
                if received > expected {
                    return Err(Error::msg("apt response exceeds Content-Length"));
                }
                for chunk in data.chunks(CHUNK) {
                    file.write_all(chunk).await?;
                }
            }
        }
        if received != expected {
            return Err(Error::msg("apt response does not match Content-Length"));
        }
        file.flush().await?;
        file.sync_all().await?;
        drop(file);
        fs::rename(&temp.0, path).await?;
        Entry::open(path).await
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

fn supported_conditions(headers: &HeaderMap) -> bool {
    // Unusual entity tags containing commas can be evaluated by the origin.
    headers.get_all(header::IF_NONE_MATCH).iter().count() <= 1
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
            .get(header::CONTENT_ENCODING)
            .is_none_or(|v| v == "identity")
        && response
            .headers()
            .get_all(header::CACHE_CONTROL)
            .iter()
            .all(|v| {
                v.to_str().is_ok_and(|v| {
                    !v.split(',').any(|s| {
                        matches!(
                            s.trim().to_ascii_lowercase().as_str(),
                            "no-store" | "private"
                        )
                    })
                })
            })
}

struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
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
        let mut file = File::open(path).await?;
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
        stats: Option<Arc<Stats>>,
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
        }));
        *response.status_mut() = status;
        *response.headers_mut() = self.headers;
        Ok(Some(response))
    }
}

// Unsupported, multiple, and unsatisfiable ranges go upstream unchanged.
fn byte_range(value: &str, len: u64) -> Option<(u64, u64)> {
    let (start, end) = value.strip_prefix("bytes=")?.split_once('-')?;
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
    stats: Option<Arc<Stats>>,
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
        if let Some(stats) = &this.stats {
            stats.saved.fetch_add(n as u64, Ordering::Relaxed);
        }
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
