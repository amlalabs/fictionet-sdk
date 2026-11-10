use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use http_body::{Frame, SizeHint};

use fictionet::{Budget, Chunk, Error};

// ---------------------------------------------------------------------------
// Bodies

type Boxed = Pin<Box<dyn http_body::Body<Data = Bytes, Error = Error> + Send>>;

#[derive(Debug)]
pub(super) struct BodyRefused;

impl std::fmt::Display for BodyRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the response body exceeds the connection budget")
    }
}

impl std::error::Error for BodyRefused {}

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
/// Full bodies retain their chunk and its reservation without boxing.
/// Converting opaque `Bytes` copies; polling a full body through
/// `http_body::Body` allocates a `Bytes` owner. Native delivery uses the
/// chunk directly.
pub enum Body {
    /// All bytes, retaining their backing and its reservation.
    Full(Chunk),
    /// A body polled through the allocating HTTP body interface.
    Stream(Boxed),
}

impl Body {
    /// No bytes.
    pub fn empty() -> Body {
        Body::Full(Chunk::default())
    }

    /// Any `http_body::Body`, with its data as `Bytes`.
    pub fn new<B>(body: B) -> Body
    where
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Error>,
    {
        Body::Stream(Box::pin(IntoBytes(Box::pin(body))))
    }

    /// Takes a stream's bytes when they are all there now, so that no work
    /// is needed to read them: one frame of data and then its end, or the
    /// end at once. A stream with more to give, or an error first, stays a
    /// stream, with what was taken from it still first.
    pub(super) fn settle(
        &mut self,
        cx: &mut Context<'_>,
        budget: &Budget,
    ) -> Result<(), BodyRefused> {
        let Body::Stream(stream) = self else {
            return Ok(());
        };
        if stream.is_end_stream() {
            *self = Body::Full(Chunk::default());
            return Ok(());
        }
        let Poll::Ready(first) = stream.as_mut().poll_frame(cx) else {
            return Ok(());
        };
        let Some(first) = first else {
            *self = Body::Full(Chunk::default());
            return Ok(());
        };
        if let Ok(frame) = &first
            && let Some(data) = frame.data_ref()
            && stream.is_end_stream()
        {
            *self = Body::Full(Chunk::copy_of(budget, data).ok_or(BodyRefused)?);
            return Ok(());
        }
        let rest = std::mem::replace(stream, Box::pin(Body::empty()));
        *self = Body::Stream(Box::pin(Prefixed {
            first: Some(first),
            rest,
        }));
        Ok(())
    }

    /// Moves a full body's backing reservation to the receiving budget.
    /// A stream pays for its frames when they are polled.
    pub(super) fn admit(&mut self, budget: &Budget) -> bool {
        match self {
            Self::Full(bytes) => bytes.repay(budget),
            Self::Stream(_) => true,
        }
    }

    /// The bytes held in full: 0 for a stream.
    pub(super) fn full_len(&self) -> usize {
        match self {
            Body::Full(b) => b.len(),
            Body::Stream(_) => 0,
        }
    }

    /// A shared view of the full body, without allocating or copying.
    /// The view keeps the backing's reservation until it is dropped.
    pub fn bytes(&self) -> Option<Chunk> {
        match self {
            Body::Full(b) => Some(b.clone()),
            Body::Stream(_) => None,
        }
    }
}

impl std::fmt::Debug for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Body::Full(b) => write!(f, "Body({} bytes)", b.len()),
            Body::Stream(_) => f.write_str("Body(stream)"),
        }
    }
}

impl Default for Body {
    fn default() -> Body {
        Body::empty()
    }
}

impl From<Chunk> for Body {
    fn from(bytes: Chunk) -> Self {
        Self::Full(bytes)
    }
}

impl From<Bytes> for Body {
    /// Copies opaque storage so its unexposed backing is not retained.
    fn from(b: Bytes) -> Body {
        Body::from(b.to_vec())
    }
}

impl From<Vec<u8>> for Body {
    fn from(b: Vec<u8>) -> Body {
        if b.is_empty() {
            Body::empty()
        } else {
            Body::Full(Chunk::unpaid(b))
        }
    }
}

impl From<String> for Body {
    fn from(s: String) -> Body {
        Body::from(s.into_bytes())
    }
}

impl From<&'static str> for Body {
    fn from(s: &'static str) -> Body {
        Body::from(s.as_bytes().to_vec())
    }
}

impl http_body::Body for Body {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        match self.get_mut() {
            Body::Full(b) => Poll::Ready(
                (!b.is_empty()).then(|| Ok(Frame::data(Bytes::from_owner(std::mem::take(b))))),
            ),
            Body::Stream(s) => s.as_mut().poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Body::Full(b) => b.is_empty(),
            Body::Stream(s) => s.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Body::Full(b) => SizeHint::with_exact(b.len() as u64),
            Body::Stream(s) => s.size_hint(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::{Budget, Pool};

    #[test]
    fn full_body_keeps_the_pool_block_and_its_charge() {
        let budget = Budget::new(4096);
        let pool = Pool::new(&budget, 512, 2);
        let mut block = pool.take(&budget, 64).unwrap();
        block.extend_within(b"owned body").unwrap();
        let address = block.as_ptr();
        let body = Body::from(block);
        let bytes = body.bytes().unwrap();
        assert_eq!(bytes.as_ptr(), address);
        assert_eq!(&bytes[..], b"owned body");
        drop(body);
        assert!(pool.free() == 0);
        assert!(budget.used() >= pool.slot());
        drop(bytes);
        assert!(pool.free() > 0);
    }

    #[test]
    fn settling_a_ready_frame_requires_its_whole_reservation() {
        let payload = Bytes::from_static(b"one ready frame");
        for limit in [0, payload.len() - 1, payload.len()] {
            let budget = Budget::new(limit);
            let mut body = Body::new(http_body_util::Full::new(payload.clone()));
            let mut cx = Context::from_waker(std::task::Waker::noop());
            let result = body.settle(&mut cx, &budget);
            assert_eq!(result.is_ok(), limit >= payload.len());
            if result.is_ok() {
                let held = body.bytes().unwrap();
                assert_eq!(&held[..], &payload[..]);
                drop(body);
                assert!(budget.used() >= payload.len());
                drop(held);
            }
            assert!(budget.used() == 0);
        }
    }
}
