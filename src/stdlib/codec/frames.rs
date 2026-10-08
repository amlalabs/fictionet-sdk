//! Stateless framing of owned wire values.

use core::marker::PhantomData;
use fictionet::stdlib::codec::{Decode, Step, Wire};

/// A wire value with a bounded prefix parser.
///
/// The parser borrows input and returns an owned item only after its boundary
/// is known. `None` needs more input, including at EOF. The consumed count
/// must be positive and no larger than the input length. Capacity must allow
/// the parser to return an item or refuse a frame before the buffer fills.
/// Implementations use the same limits and validation as their wire format.
///
/// `Item` is usually `Self`. It may be `Result<Self, E>` when a refused item
/// should be yielded and framing should continue. `Error` ends the stream.
pub trait Prefixed: Wire {
    /// The owned value or per-item error yielded by the decoder.
    type Item;
    /// A framing error that ends the stream.
    type Error: core::error::Error + 'static;
    /// Protocol-specific framing limits. Use `()` for fixed limits.
    type Limit;
    /// The decoder name used in diagnostics.
    const NAME: &'static str;
    /// The protocol's default limit.
    fn default_limit() -> Self::Limit;
    /// Applies the protocol's bounds to a supplied limit.
    #[inline]
    fn normalize_limit(limit: Self::Limit) -> Self::Limit {
        limit
    }
    /// Maximum unread bytes needed with this normalized limit.
    fn capacity(limit: &Self::Limit) -> usize;
    /// Reads one prefix without retaining or copying incomplete input.
    fn parse_prefix(
        input: &[u8],
        limit: &Self::Limit,
    ) -> Result<Option<(Self::Item, usize)>, Self::Error>;
}

/// A stateless decoder for a [`Prefixed`] wire value.
///
/// Limits, capacity, and error handling come from the value's implementation.
/// No input is copied or retained by this wrapper.
///
/// ```
/// use fictionet::stdlib::{codec::{Frames, Stream}, modbus};
/// let decoder = Frames::<modbus::Frame>::new();
/// assert_eq!(decoder.capacity(), modbus::MAX_FRAME);
/// let stream = Stream::new(decoder);
/// ```
pub struct Frames<T: Prefixed> {
    limit: T::Limit,
    item: PhantomData<fn() -> T>,
}

impl<T: Prefixed> Frames<T> {
    /// Creates a decoder with the protocol's default limit.
    #[inline]
    pub fn new() -> Self {
        Self::with_limit(T::default_limit())
    }

    /// Creates a decoder after applying the protocol's limit bounds.
    #[inline]
    pub fn with_limit(limit: T::Limit) -> Self {
        Self {
            limit: T::normalize_limit(limit),
            item: PhantomData,
        }
    }

    /// Returns the normalized framing limit.
    #[inline]
    pub fn limit(&self) -> T::Limit
    where
        T::Limit: Clone,
    {
        self.limit.clone()
    }

    /// Sets the framing limit between items, applying its protocol bounds.
    #[inline]
    pub fn set_limit(&mut self, limit: T::Limit) {
        self.limit = T::normalize_limit(limit);
    }

    /// Maximum unread bytes needed for one item or framing error.
    #[inline]
    pub fn capacity(&self) -> usize {
        T::capacity(&self.limit)
    }
}

impl<T: Prefixed> Default for Frames<T> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
impl<T: Prefixed> Clone for Frames<T>
where
    T::Limit: Clone,
{
    #[inline]
    fn clone(&self) -> Self {
        Self {
            limit: self.limit.clone(),
            item: PhantomData,
        }
    }
}
impl<T: Prefixed> Copy for Frames<T> where T::Limit: Copy {}
impl<T: Prefixed> core::fmt::Debug for Frames<T>
where
    T::Limit: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Frames")
            .field("limit", &self.limit)
            .finish()
    }
}
impl<T: Prefixed> PartialEq for Frames<T>
where
    T::Limit: PartialEq,
{
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.limit == other.limit
    }
}
impl<T: Prefixed> Eq for Frames<T> where T::Limit: Eq {}

impl<T: Prefixed> Decode for Frames<T> {
    type Item = T::Item;
    type Error = T::Error;
    const NAME: &'static str = T::NAME;
    #[inline]
    fn capacity(&self) -> usize {
        self.capacity()
    }
    #[inline]
    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Self::Item>, Self::Error> {
        Ok(match T::parse_prefix(input, &self.limit)? {
            Some((item, used)) => Step::Item(item, used),
            None => Step::Need,
        })
    }
}
