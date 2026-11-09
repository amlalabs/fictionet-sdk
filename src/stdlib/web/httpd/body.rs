use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use http_body::{Frame, SizeHint};

use fictionet::Error;

// ---------------------------------------------------------------------------
// Bodies

type Boxed = Pin<Box<dyn http_body::Body<Data = Bytes, Error = Error> + Send>>;

/// The body of every request a handler gets and every response it
/// returns: bytes known in full, or a stream of them.
///
/// The service reads a request's body before calling the handler. On
/// native HTTP/1, a cut-off body reaches a custom [`Handler`](super::Handler) or tower
/// service as a stream of the bytes received, followed by an error.
/// HTTP/1 upgrade requests and HTTP/2 requests with body collection errors
/// are rejected before calling any handler.
/// A response's body may stream, as a tower service's does; one whose
/// length is known goes out with `content-length`.
pub struct Body(pub(super) Inner);

pub(super) enum Inner {
    Full(Option<Bytes>),
    Stream(Boxed),
}

impl Body {
    /// No bytes.
    pub fn empty() -> Body {
        Body(Inner::Full(None))
    }

    /// Any `http_body::Body`, with its data as `Bytes`.
    pub fn new<B>(body: B) -> Body
    where
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Error>,
    {
        Body(Inner::Stream(Box::pin(IntoBytes(Box::pin(body)))))
    }

    /// Takes a stream's bytes when they are all there now, so that no work
    /// is needed to read them: one frame of data and then its end, or the
    /// end at once. A stream with more to give, or an error first, stays a
    /// stream, with what was taken from it still first.
    pub(super) fn settle(&mut self, cx: &mut Context<'_>) {
        let Inner::Stream(stream) = &mut self.0 else {
            return;
        };
        if stream.is_end_stream() {
            self.0 = Inner::Full(None);
            return;
        }
        let Poll::Ready(first) = stream.as_mut().poll_frame(cx) else {
            return;
        };
        let Some(first) = first else {
            self.0 = Inner::Full(None);
            return;
        };
        if let Ok(frame) = &first
            && let Some(data) = frame.data_ref()
            && stream.is_end_stream()
        {
            self.0 = Inner::Full((!data.is_empty()).then(|| data.clone()));
            return;
        }
        let rest = std::mem::replace(stream, Box::pin(Body::empty()));
        self.0 = Inner::Stream(Box::pin(Prefixed {
            first: Some(first),
            rest,
        }));
    }

    /// The bytes held in full: 0 for a stream.
    pub(super) fn full_len(&self) -> usize {
        match &self.0 {
            Inner::Full(b) => b.as_ref().map_or(0, Bytes::len),
            Inner::Stream(_) => 0,
        }
    }

    /// The bytes, if the body is held in full.
    pub fn bytes(&self) -> Option<Bytes> {
        match &self.0 {
            Inner::Full(b) => Some(b.clone().unwrap_or_default()),
            Inner::Stream(_) => None,
        }
    }
}

impl std::fmt::Debug for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Inner::Full(b) => write!(f, "Body({} bytes)", b.as_ref().map_or(0, Bytes::len)),
            Inner::Stream(_) => f.write_str("Body(stream)"),
        }
    }
}

impl Default for Body {
    fn default() -> Body {
        Body::empty()
    }
}

impl From<Bytes> for Body {
    fn from(b: Bytes) -> Body {
        Body(Inner::Full((!b.is_empty()).then_some(b)))
    }
}

impl From<Vec<u8>> for Body {
    fn from(b: Vec<u8>) -> Body {
        Body::from(Bytes::from(b))
    }
}

impl From<String> for Body {
    fn from(s: String) -> Body {
        Body::from(Bytes::from(s))
    }
}

impl From<&'static str> for Body {
    fn from(s: &'static str) -> Body {
        Body::from(Bytes::from_static(s.as_bytes()))
    }
}

impl http_body::Body for Body {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        match &mut self.get_mut().0 {
            Inner::Full(b) => Poll::Ready(b.take().map(|b| Ok(Frame::data(b)))),
            Inner::Stream(s) => s.as_mut().poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.0 {
            Inner::Full(b) => b.is_none(),
            Inner::Stream(s) => s.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.0 {
            Inner::Full(b) => SizeHint::with_exact(b.as_ref().map_or(0, |b| b.len() as u64)),
            Inner::Stream(s) => s.size_hint(),
        }
    }
}

/// A stream with a frame already taken from it, which comes first.
struct Prefixed {
    first: Option<Result<Frame<Bytes>, Error>>,
    rest: Boxed,
}

impl http_body::Body for Prefixed {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        let this = self.get_mut();
        if let Some(first) = this.first.take() {
            return Poll::Ready(Some(first));
        }
        this.rest.as_mut().poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.first.is_none() && self.rest.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        let mut hint = self.rest.size_hint();
        if let Some(Ok(frame)) = &self.first
            && let Some(data) = frame.data_ref()
        {
            // The upper bound moves first: each setter checks the bounds
            // against the other.
            let more = data.len() as u64;
            if let Some(upper) = hint.upper() {
                hint.set_upper(upper + more);
            }
            hint.set_lower(hint.lower() + more);
        }
        hint
    }
}

/// A body with its data as `Bytes` and its errors as [`Error`]. It passes
/// on the size hint, so a known length is sent as `content-length`.
struct IntoBytes<B>(Pin<Box<B>>);

impl<B> http_body::Body for IntoBytes<B>
where
    B: http_body::Body,
    B::Error: Into<Error>,
{
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        self.0.as_mut().poll_frame(cx).map(|f| {
            f.map(|r| {
                r.map(|f| f.map_data(|mut d| d.copy_to_bytes(d.remaining())))
                    .map_err(Into::into)
            })
        })
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.0.size_hint()
    }
}
