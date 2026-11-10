//! Immutable package files stored under their upstream host and path.

use fictionet::stdlib::web::httpd::{Exchange, Handler, Reply};
use fictionet::stdlib::web::{Fields, Response};
use fictionet::{
    Cx, Error,
    stdlib::web::{
        self,
        httpd::{Body, Routing},
    },
};
use http::StatusCode;
use std::{
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWriteExt};

type Answer = Result<Response, Error>;
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

fn key(request: &web::Request) -> Option<PathBuf> {
    let target = &request.site;
    if target.routing != Routing::Exact
        || target.name.is_empty()
        || !target.name.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        || request.head.method() != "GET"
        || request.head.query().is_some()
        || request.body.bytes().is_none_or(|body| !body.is_empty())
        || request.head.fields().any(|(name, _)| {
            [
                "authorization",
                "cookie",
                "range",
                "if-range",
                "if-match",
                "if-none-match",
                "if-modified-since",
                "if-unmodified-since",
            ]
            .iter()
            .any(|field| name.eq_ignore_ascii_case(field.as_bytes()))
        })
        || !immutable(request.head.path())
    {
        return None;
    }
    Some(Path::new(&*target.name).join(request.head.path().strip_prefix('/')?))
}

struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

impl<S: Handler + Clone> Handler for Mirror<S> {
    fn call(&self, request: web::Request, ex: &mut Exchange<'_>) -> Reply {
        let mirror = self.clone();
        let conn = ex.conn().clone();
        let responses = ex.responses().clone();
        Reply::Later(Box::new(move |cx| {
            Box::pin(async move {
                let mut request = request;
                if mirror.closed.load(Ordering::Acquire) {
                    return Ok(web::httpd::text(
                        &responses,
                        StatusCode::FORBIDDEN,
                        "Forbidden\n",
                    ));
                }
                let path = key(&request).map(|key| mirror.root.join(key));
                let _download = mirror.download.lock().await;
                if mirror.closed.load(Ordering::Acquire) {
                    return Ok(web::httpd::text(
                        &responses,
                        StatusCode::FORBIDDEN,
                        "Forbidden\n",
                    ));
                }
                if let Some(path) = &path {
                    match tokio::fs::File::open(path).await {
                        Ok(file) => return file_response(file).await,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error.into()),
                    }
                    request.head = web::Head::new(
                        request.head.method(),
                        request.head.target(),
                        request.head.version(),
                        request
                            .head
                            .headers()
                            .filter(|field| !field.name.eq_ignore_ascii_case("accept-encoding"))
                            .map(|field| (field.name, field.value))
                            .chain([("accept-encoding", b"identity".as_slice())]),
                    );
                }
                if mirror.closed.load(Ordering::Acquire) {
                    return Ok(web::httpd::text(
                        &responses,
                        StatusCode::FORBIDDEN,
                        "Forbidden\n",
                    ));
                }
                let reply = mirror
                    .upstream
                    .call(request, &mut Exchange::new(cx.now(), &cx, &conn, responses));
                let response = match reply {
                    Reply::Now(response) => response,
                    Reply::Later(work) => work(cx).await?,
                };
                let Some(path) = path.filter(|_| {
                    response.status == StatusCode::OK
                        && response.fields.get(b"content-encoding").is_none()
                }) else {
                    return Ok(response);
                };
                let expected = response
                    .fields
                    .get(b"content-length")
                    .map(|length| {
                        std::str::from_utf8(length)?
                            .parse::<u64>()
                            .map_err(Error::from)
                    })
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
                let mut body = response.body;
                let mut length = 0u64;
                while let Some(frame) = std::future::poll_fn(|cx| body.poll_next(cx)).await {
                    let bytes = frame?;
                    file.write_all(&bytes).await?;
                    length += bytes.len() as u64;
                }
                if expected.is_some_and(|expected| expected != length) {
                    return Err(Error::msg("incomplete package download"));
                }
                file.flush().await?;
                drop(file);
                tokio::fs::rename(&temporary.0, &path).await?;
                file_response(tokio::fs::File::open(path).await?).await
            })
        }))
    }
}

async fn file_response(file: tokio::fs::File) -> Answer {
    let length = file.metadata().await?.len();
    let mut response = Response::new(Body::Stream(Box::pin(FileBody { file })));
    response.fields = Fields::new([
        ("content-length", length.to_string().as_str()),
        ("content-type", "application/octet-stream"),
    ]);
    Ok(response)
}
struct FileBody {
    file: tokio::fs::File,
}
impl web::httpd::BodyStream for FileBody {
    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<fictionet::Chunk, Error>>> {
        let mut bytes = [0; 64 << 10];
        let mut buffer = tokio::io::ReadBuf::new(&mut bytes);
        match Pin::new(&mut self.file).poll_read(cx, &mut buffer) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Some(Err(error.into()))),
            Poll::Ready(Ok(())) if buffer.filled().is_empty() => Poll::Ready(None),
            Poll::Ready(Ok(())) => {
                Poll::Ready(Some(Ok(fictionet::Chunk::unpaid(buffer.filled().to_vec()))))
            }
        }
    }
}

#[cfg(test)]
mod tests;
