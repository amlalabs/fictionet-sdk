//! Host HTTP requests run on an owned Tokio runtime. The world drives its
//! request body, and bounded channels carry bytes in both directions.

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response};
use http_body::{Body as _, Frame, SizeHint};
use http_body_util::BodyExt;
use hyper_rustls::{HttpsConnector, MaybeHttpsStream};
use hyper_util::client::legacy::{
    Client as HttpClient,
    connect::{Connection, HttpConnector},
};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::runtime::Runtime;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::AbortHandle;
use tokio_util::sync::PollSender;
use tower_service::Service;

use fictionet::Error;
use fictionet::stdlib::web::httpd::Body;

/// An HTTP/1.1 client using host DNS, pooled sockets and verified TLS.
/// It works with any executor; its runtime only drives host I/O.
pub struct Client {
    http: HttpClient<Connector, Body>,
    slots: Arc<Semaphore>,
    runtime: Option<Runtime>,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl fictionet::stdlib::web::Upstream for Client {
    fn request(self: Arc<Self>, request: Request<Body>) -> fictionet::stdlib::web::UpstreamFuture {
        Box::pin(self.send(request))
    }
}

impl Client {
    /// Creates a client with the Mozilla root store, no redirects or host
    /// proxy settings, and no response timeout. Model calls and event
    /// streams may remain quiet for minutes.
    pub fn new() -> Self {
        Self::with_timeout(Duration::from_secs(30))
    }

    fn with_timeout(timeout: Duration) -> Self {
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring supports the default TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
        Self::with_config(tls, timeout, 64)
    }

    fn with_config(mut tls: rustls::ClientConfig, timeout: Duration, exchanges: usize) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("fictionet-upstream")
            .build()
            .expect("create the upstream runtime");
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let mut tcp = HttpConnector::new();
        tcp.enforce_http(false);
        tcp.set_nodelay(true);
        let connector = HttpsConnector::from((tcp, Arc::new(tls)));
        let http = HttpClient::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .http1_max_buf_size(400 * 1024)
            .build(Connector {
                inner: connector,
                timeout,
            });
        Self {
            http,
            slots: Arc::new(Semaphore::new(exchanges)),
            runtime: Some(runtime),
        }
    }

    async fn send(self: Arc<Self>, request: Request<Body>) -> Result<Response<Body>, Error> {
        let (mut parts, body) = request.into_parts();
        let length = body.size_hint().exact();
        if !parts.headers.contains_key(http::header::CONTENT_LENGTH)
            && let Some(length) = length
            && (length > 0
                || !matches!(
                    parts.method,
                    Method::GET
                        | Method::HEAD
                        | Method::DELETE
                        | Method::OPTIONS
                        | Method::TRACE
                        | Method::CONNECT
                ))
        {
            parts
                .headers
                .insert(http::header::CONTENT_LENGTH, length.into());
        }
        parts.version = http::Version::HTTP_11;
        let replay = if idempotent(&parts.method) {
            body.bytes()
        } else {
            None
        };
        let replay = replay.map(|bytes| Request::from_parts(parts.clone(), Body::from(bytes)));
        let (sender, receiver) = mpsc::channel(1);
        let mut upload = Upload {
            body: Some(body),
            data: Bytes::new(),
            sender: Some(PollSender::new(sender)),
            stopped: false,
        };
        let outgoing = Request::from_parts(
            parts,
            Body::new(UploadBody {
                receiver,
                remaining: length,
            }),
        );
        let permit = self.slots.clone().acquire_owned().await?;
        let (head, response) = tokio::sync::oneshot::channel();
        let (sender, receiver) = mpsc::channel(1);
        let http = self.http.clone();
        let task = self.runtime.as_ref().unwrap().spawn(async move {
            let _permit = permit;
            let mut result = http.request(outgoing).await;
            if let Some(replay) = replay
                && result.as_ref().err().is_some_and(|error| retryable(error))
            {
                result = http.request(replay).await;
            }
            let response = match result {
                Ok(response) => response,
                Err(error) => {
                    let _ = head.send(Err(failure(error)));
                    return;
                }
            };
            if response.headers().contains_key(http::header::TRANSFER_ENCODING)
                && response.headers().contains_key(http::header::CONTENT_LENGTH)
            {
                let _ = head.send(Err(Error::msg("the upstream response has both transfer encoding and content length")));
                return;
            }
            if response.status() == http::StatusCode::SWITCHING_PROTOCOLS {
                let _ = head.send(Err(Error::msg(
                    "upstream protocol upgrades are unsupported",
                )));
                return;
            }
            let remaining = response.body().size_hint().exact();
            let (parts, mut body) = response.into_parts();
            if head.send(Ok((parts, remaining))).is_err() {
                return;
            }
            loop {
                if body.is_end_stream() {
                    return;
                }
                match body.frame().await.transpose() {
                    Ok(Some(frame)) => {
                        let Ok(mut bytes) = frame.into_data() else {
                            continue;
                        };
                        while !bytes.is_empty() {
                            if sender
                                .send(Ok(bytes.split_to(bytes.len().min(8192))))
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                    }
                    Ok(None) => return,
                    Err(error) => {
                        let _ = sender.send(Err(error.into())).await;
                        return;
                    }
                }
            }
        });
        let abort = Abort(task.abort_handle());
        let mut response = Box::pin(response);
        let head = poll_fn(|cx| {
            if let Poll::Ready(result) = response.as_mut().poll(cx) {
                return Poll::Ready(result.map_err(Error::from).and_then(|head| head));
            }
            if let Err(error) = upload.poll(cx) {
                return Poll::Ready(Err(error));
            }
            Poll::Pending
        })
        .await?;
        if head.0.status.is_client_error() || head.0.status.is_server_error() {
            // A rejection ends the upload. Keep its channel alive until the
            // response ends, so an unfinished request cannot cut off the reply.
            upload.stopped = true;
            upload.body = None;
            upload.data = Bytes::new();
        }
        Ok(Response::from_parts(
            head.0,
            Body::new(Incoming {
                receiver,
                upload,
                _abort: abort,
                _client: self,
                remaining: head.1,
                done: false,
            }),
        ))
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        // The last owner may be dropped inside another runtime's task.
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

fn causes<'a>(
    error: &'a (dyn std::error::Error + 'static),
) -> impl Iterator<Item = &'a (dyn std::error::Error + 'static)> {
    std::iter::successors(Some(error), |e| e.source())
}

fn idempotent(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::PUT | Method::DELETE | Method::OPTIONS | Method::TRACE
    )
}

fn retryable(error: &(dyn std::error::Error + 'static)) -> bool {
    causes(error).any(|e| {
        e.downcast_ref::<hyper::Error>()
            .is_some_and(|e| e.is_incomplete_message())
            || e.downcast_ref::<io::Error>().is_some_and(|e| {
                matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::BrokenPipe
                        | io::ErrorKind::UnexpectedEof
                )
            })
    })
}

fn failure(error: hyper_util::client::legacy::Error) -> Error {
    if causes(&error).any(|e| e.is::<tokio::time::error::Elapsed>()) {
        return Error::msg("connecting timed out");
    }
    if causes(&error).any(|e| {
        e.downcast_ref::<hyper::Error>()
            .is_some_and(|e| e.is_parse_status())
    }) {
        return Error::msg("the upstream response is malformed: invalid HTTP start line");
    }
    Error::msg(fictionet::ErrorChain(&error).to_string())
}

type Socket = MaybeHttpsStream<TokioIo<tokio::net::TcpStream>>;
type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone)]
struct Connector {
    inner: HttpsConnector<HttpConnector>,
    timeout: Duration,
}

impl Service<http::Uri> for Connector {
    type Response = Io;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Io, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, uri: http::Uri) -> Self::Future {
        let connect = self.inner.call(uri);
        let timeout = self.timeout;
        Box::pin(async move {
            Ok(Io {
                inner: tokio::time::timeout(timeout, connect).await??,
                write_failed: false,
            })
        })
    }
}

// Let HTTP framing decide whether a TLS EOF truncated a response, and let
// a buffered response be read when a server closes during an upload.
// After a write fails, stop uploading and let the response or read error
// determine the exchange's result.
struct Io {
    inner: Socket,
    write_failed: bool,
}

impl Connection for Io {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        self.inner.connected()
    }
}

impl hyper::rt::Read for Io {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
}

impl hyper::rt::Write for Io {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_failed {
            return Poll::Pending;
        }
        match Pin::new(&mut self.inner).poll_write(cx, bytes) {
            Poll::Ready(Err(_)) => {
                self.write_failed = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            result => result,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_failed {
            return Poll::Pending;
        }
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Err(_)) => {
                self.write_failed = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            result => result,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct Abort(AbortHandle);
impl Drop for Abort {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct UploadBody {
    receiver: mpsc::Receiver<Result<Bytes, Error>>,
    remaining: Option<u64>,
}

impl http_body::Body for UploadBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        let result = std::task::ready!(self.receiver.poll_recv(cx));
        if let Some(Ok(bytes)) = &result
            && let Some(remaining) = &mut self.remaining
        {
            *remaining = remaining.saturating_sub(bytes.len() as u64);
        }
        Poll::Ready(result.map(|r| r.map(Frame::data)))
    }

    fn is_end_stream(&self) -> bool {
        self.remaining == Some(0)
    }

    fn size_hint(&self) -> SizeHint {
        self.remaining
            .map_or_else(SizeHint::default, SizeHint::with_exact)
    }
}

struct Upload {
    body: Option<Body>,
    data: Bytes,
    sender: Option<PollSender<Result<Bytes, Error>>>,
    stopped: bool,
}

impl Upload {
    fn poll(&mut self, cx: &mut Context<'_>) -> Result<(), Error> {
        if self.stopped {
            return Ok(());
        }
        loop {
            let Some(sender) = &mut self.sender else {
                return Ok(());
            };
            match sender.poll_reserve(cx) {
                Poll::Pending => return Ok(()),
                Poll::Ready(Err(_)) => {
                    self.sender = None;
                    self.body = None;
                    return Ok(());
                }
                Poll::Ready(Ok(())) => {}
            }
            if !self.data.is_empty() {
                let bytes = self.data.split_to(self.data.len().min(64 * 1024));
                if sender.send_item(Ok(bytes)).is_err() {
                    self.sender = None;
                    self.body = None;
                } else {
                    cx.waker().wake_by_ref();
                }
                return Ok(());
            }
            let Some(body) = &mut self.body else {
                self.sender = None;
                return Ok(());
            };
            match Pin::new(body).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Ok(bytes) = frame.into_data() {
                        self.data = bytes;
                    }
                }
                Poll::Ready(Some(Err(error))) => return Err(error),
                Poll::Ready(None) => self.body = None,
                Poll::Pending => return Ok(()),
            }
        }
    }
}

struct Incoming {
    receiver: mpsc::Receiver<Result<Bytes, Error>>,
    upload: Upload,
    _abort: Abort,
    _client: Arc<Client>,
    remaining: Option<u64>,
    done: bool,
}

impl http_body::Body for Incoming {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        let this = self.get_mut();
        if this.done || this.remaining == Some(0) {
            this.done = true;
            return Poll::Ready(None);
        }
        if let Err(error) = this.upload.poll(cx) {
            this.done = true;
            return Poll::Ready(Some(Err(error)));
        }
        match std::task::ready!(this.receiver.poll_recv(cx)) {
            Some(Ok(bytes)) => {
                if let Some(remaining) = &mut this.remaining {
                    *remaining = remaining.saturating_sub(bytes.len() as u64);
                }
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            result => {
                this.done = true;
                Poll::Ready(result.map(|r| r.map(Frame::data)))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done
    }

    fn size_hint(&self) -> SizeHint {
        self.remaining
            .map_or_else(SizeHint::default, SizeHint::with_exact)
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
