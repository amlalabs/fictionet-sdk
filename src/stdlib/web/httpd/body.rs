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
/// [`Router`](super::Router) rejects it. HTTP/2 and hyper's HTTP/1 upgrade path reject
/// body collection errors before calling any handler.
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
