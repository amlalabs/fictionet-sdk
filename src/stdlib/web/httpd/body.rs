use crate::stdlib::web::Fields;
use fictionet::{Budget, Chunk, Error};
use std::pin::Pin;
use std::task::{Context, Poll};

/// A native body stream. Each piece retains its storage and reservation.
pub trait BodyStream: Send {
    /// The next piece, an error, or the end. Pending must arrange a wake.
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Chunk, Error>>>;
    /// The exact number of bytes remaining, when known.
    fn remaining(&self) -> Option<u64> {
        None
    }
    /// Whether polling would return the end immediately.
    fn is_end_stream(&self) -> bool {
        false
    }
    /// Trailing fields, available after the end of the data.
    fn take_trailers(self: Pin<&mut Self>) -> Option<Fields> {
        None
    }
}

#[derive(Debug)]
pub(super) struct BodyRefused;
impl std::fmt::Display for BodyRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the response body exceeds the connection budget")
    }
}
impl std::error::Error for BodyRefused {}

/// A complete body or a stream of retained chunks.
pub enum Body {
    /// All bytes, retaining their backing and its reservation.
    Full(Chunk),
    /// Lazily produced chunks, with one box for the stream.
    Stream(Pin<Box<dyn BodyStream>>),
}
impl Body {
    /// No bytes and no allocation.
    pub fn empty() -> Self {
        Self::Full(Chunk::default())
    }
    /// A shared view of a complete body.
    pub fn bytes(&self) -> Option<Chunk> {
        match self {
            Self::Full(b) => Some(b.clone()),
            Self::Stream(_) => None,
        }
    }
    /// Poll the next native chunk.
    pub fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<Chunk, Error>>> {
        match self {
            Self::Full(b) => Poll::Ready((!b.is_empty()).then(|| Ok(std::mem::take(b)))),
            Self::Stream(s) => s.as_mut().poll_next(cx),
        }
    }
    /// The exact number of bytes remaining, when known.
    pub fn remaining(&self) -> Option<u64> {
        match self {
            Self::Full(b) => Some(b.len() as u64),
            Self::Stream(s) => s.remaining(),
        }
    }
    /// Whether the data has ended.
    pub fn is_end_stream(&self) -> bool {
        match self {
            Self::Full(b) => b.is_empty(),
            Self::Stream(s) => s.is_end_stream(),
        }
    }
    /// Trailing fields after data has ended.
    pub fn take_trailers(&mut self) -> Option<Fields> {
        match self {
            Self::Full(_) => None,
            Self::Stream(s) => s.as_mut().take_trailers(),
        }
    }
    pub(super) fn admit(&mut self, budget: &Budget) -> bool {
        match self {
            Self::Full(b) => b.repay(budget),
            Self::Stream(_) => true,
        }
    }
    pub(super) fn settle(
        &mut self,
        cx: &mut Context<'_>,
        budget: &Budget,
    ) -> Result<(), BodyRefused> {
        let Self::Stream(stream) = self else {
            return Ok(());
        };
        let Poll::Ready(first) = stream.as_mut().poll_next(cx) else {
            return Ok(());
        };
        if first.is_none() {
            let trailers = stream.as_mut().take_trailers();
            *self = if trailers.is_some() {
                Self::Stream(Box::pin(Prefixed {
                    first: None,
                    rest: Self::empty(),
                    trailers,
                }))
            } else {
                Self::empty()
            };
            return Ok(());
        }
        if stream.is_end_stream() && matches!(&first, Some(Ok(_))) {
            let Some(Ok(mut data)) = first else {
                unreachable!()
            };
            if !data.repay(budget) {
                return Err(BodyRefused);
            }
            let trailers = stream.as_mut().take_trailers();
            *self = if trailers.is_some() {
                Self::Stream(Box::pin(Prefixed {
                    first: Some(Ok(data)),
                    rest: Self::empty(),
                    trailers,
                }))
            } else {
                Self::Full(data)
            };
            return Ok(());
        }
        let rest = std::mem::replace(self, Self::empty());
        *self = Self::Stream(Box::pin(Prefixed {
            first,
            rest,
            trailers: None,
        }));
        Ok(())
    }
}
impl Default for Body {
    fn default() -> Self {
        Self::empty()
    }
}
impl std::fmt::Debug for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full(b) => write!(f, "Body({} bytes)", b.len()),
            Self::Stream(_) => f.write_str("Body(stream)"),
        }
    }
}
impl From<Chunk> for Body {
    fn from(bytes: Chunk) -> Self {
        Self::Full(bytes)
    }
}
impl From<Vec<u8>> for Body {
    fn from(bytes: Vec<u8>) -> Self {
        if bytes.is_empty() {
            Self::empty()
        } else {
            Self::Full(Chunk::unpaid(bytes))
        }
    }
}
impl From<String> for Body {
    fn from(s: String) -> Self {
        Self::from(s.into_bytes())
    }
}
impl From<&'static str> for Body {
    fn from(s: &'static str) -> Self {
        Self::from(s.as_bytes().to_vec())
    }
}
impl From<bytes::Bytes> for Body {
    fn from(b: bytes::Bytes) -> Self {
        Self::from(b.to_vec())
    }
}

struct Prefixed {
    first: Option<Result<Chunk, Error>>,
    rest: Body,
    trailers: Option<Fields>,
}
impl BodyStream for Prefixed {
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Chunk, Error>>> {
        let this = self.get_mut();
        if let Some(first) = this.first.take() {
            return Poll::Ready(Some(first));
        }
        this.rest.poll_next(cx)
    }
    fn remaining(&self) -> Option<u64> {
        self.rest.remaining()?.checked_add(
            self.first
                .as_ref()
                .and_then(|v| v.as_ref().ok())
                .map_or(0, |b| b.len() as u64),
        )
    }
    fn is_end_stream(&self) -> bool {
        self.first.is_none() && self.trailers.is_none() && self.rest.is_end_stream()
    }
    fn take_trailers(self: Pin<&mut Self>) -> Option<Fields> {
        let this = self.get_mut();
        this.trailers.take().or_else(|| this.rest.take_trailers())
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
        let payload = Chunk::unpaid(b"one ready frame".to_vec());
        struct Ready(Chunk);
        impl BodyStream for Ready {
            fn poll_next(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<Option<Result<Chunk, Error>>> {
                let data = std::mem::take(&mut self.get_mut().0);
                Poll::Ready((!data.is_empty()).then_some(Ok(data)))
            }
            fn is_end_stream(&self) -> bool {
                self.0.is_empty()
            }
        }
        for limit in [0, payload.len() - 1, payload.len()] {
            let budget = Budget::new(limit);
            let mut body = Body::Stream(Box::pin(Ready(Chunk::unpaid(payload.to_vec()))));
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
