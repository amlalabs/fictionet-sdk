//! Immutable package files stored under their upstream host and path.

use bytes::Bytes;
use fictionet::{
    Cx, Error,
    stdlib::web::{
        self,
        httpd::{Body, Routing, Target},
    },
};
use http::{Method, Request, Response, StatusCode, header};
use http_body::{Body as HttpBody, Frame};
use http_body_util::BodyExt;
use std::{
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWriteExt};
use tower_service::Service;

type Answer = Result<Response<Body>, Error>;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// Opens the package mirror used while guests install their software.
pub fn new(fcx: &Cx) -> Result<Mirror<web::Proxy>, Error> {
    Ok(Mirror::new(
        web::proxy(fcx, Arc::new(fictionet_host::Client::new()))?,
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../downloads/cloudimage/mirror"),
    ))
}

/// A shared directory of immutable upstream files and one setup gate.
#[derive(Clone)]
pub struct Mirror<S> {
    upstream: S,
    root: PathBuf,
    pub(crate) closed: Arc<AtomicBool>,
    download: Arc<tokio::sync::Mutex<()>>,
}
impl<S> Mirror<S> {
    fn new(upstream: S, root: PathBuf) -> Self {
        Self {
            upstream,
            root,
            closed: Arc::default(),
            download: Arc::default(),
        }
    }
}

// Versioned release directories contain immutable files.
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

fn key(request: &Request<Body>) -> Option<PathBuf> {
    let target = request.extensions().get::<Target>()?;
    if target.routing != Routing::Exact
        || target.host.is_empty()
        || !target.host.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        || request.method() != Method::GET
        || request.uri().query().is_some()
        || request.body().bytes().is_none_or(|body| !body.is_empty())
        || request.headers().keys().any(|name| {
            matches!(
                name.as_str(),
                "authorization"
                    | "cookie"
                    | "range"
                    | "if-range"
                    | "if-match"
                    | "if-none-match"
                    | "if-modified-since"
                    | "if-unmodified-since"
            )
        })
        || (!immutable(request.uri().path()) && !release(&target.host, request.uri().path()))
    {
        return None;
    }
    Some(Path::new(&target.host).join(request.uri().path().strip_prefix('/')?))
}

struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

impl<S> Service<Request<Body>> for Mirror<S>
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
    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        let mut mirror = self.clone();
        Box::pin(async move {
            if mirror.closed.load(Ordering::Acquire) {
                return Ok(web::httpd::text(StatusCode::FORBIDDEN, "Forbidden\n"));
            }
            let path = key(&request).map(|key| mirror.root.join(key));
            let _download = mirror.download.lock().await;
            if mirror.closed.load(Ordering::Acquire) {
                return Ok(web::httpd::text(StatusCode::FORBIDDEN, "Forbidden\n"));
            }
            if let Some(path) = &path {
                match tokio::fs::File::open(path).await {
                    Ok(file) => return file_response(file).await,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                request.headers_mut().insert(
                    header::ACCEPT_ENCODING,
                    http::HeaderValue::from_static("identity"),
                );
            }
            std::future::poll_fn(|cx| mirror.upstream.poll_ready(cx)).await?;
            if mirror.closed.load(Ordering::Acquire) {
                return Ok(web::httpd::text(StatusCode::FORBIDDEN, "Forbidden\n"));
            }
            let response = mirror.upstream.call(request).await?;
            let Some(path) = path.filter(|_| {
                response.status() == StatusCode::OK
                    && !response.headers().contains_key(header::CONTENT_ENCODING)
            }) else {
                return Ok(response);
            };
            let expected = response
                .headers()
                .get(header::CONTENT_LENGTH)
                .map(|length| length.to_str()?.parse::<u64>().map_err(Error::from))
                .transpose()?;
            tokio::fs::create_dir_all(path.parent().expect("file parent")).await?;
            let temporary = Temporary(path.with_extension(format!(
                "part-{}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            )));
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary.0)
                .await?;
            let mut body = response.into_body();
            let mut length = 0u64;
            while let Some(frame) = body.frame().await {
                if let Ok(bytes) = frame?.into_data() {
                    file.write_all(&bytes).await?;
                    length += bytes.len() as u64;
                }
            }
            if expected.is_some_and(|expected| expected != length) {
                return Err(Error::msg("incomplete package download"));
            }
            file.flush().await?;
            drop(file);
            tokio::fs::rename(&temporary.0, &path).await?;
            file_response(tokio::fs::File::open(path).await?).await
        })
    }
}

async fn file_response(file: tokio::fs::File) -> Answer {
    let length = file.metadata().await?.len();
    Ok(Response::builder()
        .header(header::CONTENT_LENGTH, length)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::new(FileBody { file }))?)
}
struct FileBody {
    file: tokio::fs::File,
}
impl HttpBody for FileBody {
    type Data = Bytes;
    type Error = Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        let mut bytes = [0; 64 << 10];
        let mut buffer = tokio::io::ReadBuf::new(&mut bytes);
        match Pin::new(&mut self.file).poll_read(cx, &mut buffer) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Some(Err(error.into()))),
            Poll::Ready(Ok(())) if buffer.filled().is_empty() => Poll::Ready(None),
            Poll::Ready(Ok(())) => Poll::Ready(Some(Ok(Frame::data(Bytes::copy_from_slice(
                buffer.filled(),
            ))))),
        }
    }
}

#[cfg(test)]
mod tests;
