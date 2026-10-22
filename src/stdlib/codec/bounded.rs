extern crate alloc;

use alloc::vec::Vec;
use core::{error::Error, fmt};
use fictionet::stdlib::codec::{Buffer, Wire};

/// Why a byte-vector reservation was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReserveError {
    /// The requested total length overflowed or exceeded the supplied limit.
    TooLong {
        /// Maximum total bytes, including the existing contents.
        limit: usize,
    },
    /// The vector could not reserve storage, including an unsupported capacity.
    Allocation,
}
impl fmt::Display for ReserveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { limit } => write!(f, "reservation exceeds {limit} bytes"),
            Self::Allocation => f.write_str("reservation allocation failed"),
        }
    }
}
impl core::error::Error for ReserveError {}

/// Reserves room for `added` bytes after the current contents of `out`.
///
/// The total `out.len() + added` must fit in `usize` and be at most `limit`.
/// Either failure returns [`ReserveError::TooLong`], even if the vector
/// already has enough capacity. The caller's limit is used exactly; unlike
/// [`append_bounded`](fictionet::stdlib::codec::append_bounded), this does not
/// clamp to [`Buffer::MAX_LIMIT`](fictionet::stdlib::codec::Buffer::MAX_LIMIT).
///
/// If growth is needed, requests the larger of the total length and twice
/// the current capacity, capped at `limit`, with [`Vec::try_reserve_exact`].
/// A reservation failure returns [`ReserveError::Allocation`]. The allocator
/// may provide more capacity than requested. Existing capacity is never shrunk.
///
/// No bytes are written and the length stays unchanged, on success or failure.
/// An error also leaves capacity unchanged. A zero-byte reservation still
/// checks the existing length against the limit. Protocols, including copied
/// modules, can map these neutral errors to their own error types.
///
/// ```
/// use fictionet::stdlib::codec::{reserve_bytes, ReserveError};
/// let mut out = b"ab".to_vec();
/// reserve_bytes(&mut out, 2, 4)?;
/// assert_eq!(out, b"ab");
/// out.extend_from_slice(b"cd");
/// assert_eq!(reserve_bytes(&mut out, 1, 4), Err(ReserveError::TooLong { limit: 4 }));
/// assert_eq!(out, b"abcd");
/// # Ok::<(), ReserveError>(())
/// ```
pub fn reserve_bytes(out: &mut Vec<u8>, added: usize, limit: usize) -> Result<(), ReserveError> {
    let size = out
        .len()
        .checked_add(added)
        .filter(|size| *size <= limit)
        .ok_or(ReserveError::TooLong { limit })?;
    if size > out.capacity() {
        let target = size.max(out.capacity().saturating_mul(2)).min(limit);
        out.try_reserve_exact(target.saturating_sub(out.len()))
            .map_err(|_| ReserveError::Allocation)?;
    }
    Ok(())
}

/// Why a bounded write could not complete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RewriteError<E> {
    /// A replacement writer refused a value.
    Write(E),
    /// The resulting destination would exceed its configured byte limit.
    TooLong {
        /// Maximum total destination length, including its existing prefix.
        limit: usize,
    },
    /// Storage could not be reserved.
    Allocation,
}
impl<E: fmt::Display> fmt::Display for RewriteError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Write(_) => f.write_str("the replacement writer failed"),
            Self::TooLong { limit } => write!(f, "replacement exceeds {limit} output bytes"),
            Self::Allocation => f.write_str("replacement allocation failed"),
        }
    }
}
impl<E: Error + 'static> Error for RewriteError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Write(e) => Some(e),
            Self::TooLong { .. } | Self::Allocation => None,
        }
    }
}
impl<E> From<ReserveError> for RewriteError<E> {
    fn from(error: ReserveError) -> Self {
        match error {
            ReserveError::TooLong { limit } => Self::TooLong { limit },
            ReserveError::Allocation => Self::Allocation,
        }
    }
}

/// Writes a Wire value to a bounded replacement buffer. The temporary
/// encoding uses the Wire type's named limit. Its full length is checked
/// before copying into `out`. Errors leave the unread output unchanged.
pub fn write_bounded<T: Wire>(
    item: &T,
    out: &mut Buffer,
) -> Result<(), RewriteError<T::WriteError>> {
    let mut bytes = Vec::new();
    item.write(&mut bytes).map_err(RewriteError::Write)?;
    if bytes.len() > out.room() {
        return Err(RewriteError::TooLong { limit: out.limit() });
    }
    if out.push(&bytes) != bytes.len() {
        return Err(RewriteError::Allocation);
    }
    Ok(())
}

/// Appends exact bytes under a total destination limit, clamped to
/// [`Buffer::MAX_LIMIT`].
/// Checks multiplication and reserves before writing. Errors leave output
/// unchanged. Empty input takes constant time even for very large counts.
pub fn append_bounded<E>(
    bytes: &[u8],
    copies: usize,
    out: &mut Vec<u8>,
    limit: usize,
) -> Result<(), RewriteError<E>> {
    let limit = limit.min(Buffer::MAX_LIMIT);
    let added = bytes
        .len()
        .checked_mul(copies)
        .ok_or(RewriteError::TooLong { limit })?;
    reserve_bytes(out, added, limit)?;
    if added != 0 {
        for _ in 0..copies {
            out.extend_from_slice(bytes);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_limit_and_geometric_growth_leave_contents_unchanged() {
        let mut out = b"ab".to_vec();
        reserve_bytes(&mut out, 1, 16).unwrap();
        assert_eq!(out, b"ab");
        assert_eq!(out.capacity(), 4);
        reserve_bytes(&mut out, 4, 6).unwrap();
        assert_eq!(out, b"ab");
        assert_eq!(out.capacity(), 6);
        out.extend_from_slice(b"cdef");
        assert_eq!(
            reserve_bytes(&mut out, 1, 6),
            Err(ReserveError::TooLong { limit: 6 })
        );
        assert_eq!(out, b"abcdef");
        assert_eq!(out.capacity(), 6);
    }

    #[test]
    fn spare_capacity_does_not_bypass_the_limit() {
        let mut out = Vec::with_capacity(16);
        out.extend_from_slice(b"ab");
        let capacity = out.capacity();
        for (added, limit) in [(0, 1), (1, 2)] {
            assert_eq!(
                reserve_bytes(&mut out, added, limit),
                Err(ReserveError::TooLong { limit })
            );
            assert_eq!(out, b"ab");
            assert_eq!(out.capacity(), capacity);
        }
        reserve_bytes(&mut out, 0, 2).unwrap();
        reserve_bytes(&mut out, 2, 4).unwrap();
        assert_eq!(out, b"ab");
        assert_eq!(out.capacity(), capacity);
    }

    #[test]
    fn zero_limit_does_not_allocate() {
        let mut out = Vec::new();
        reserve_bytes(&mut out, 0, 0).unwrap();
        assert_eq!(
            reserve_bytes(&mut out, 1, 0),
            Err(ReserveError::TooLong { limit: 0 })
        );
        assert!(out.is_empty());
        assert_eq!(out.capacity(), 0);
    }

    #[test]
    fn overflow_and_allocation_refusal_leave_output_unchanged() {
        let mut out = b"ab".to_vec();
        let capacity = out.capacity();
        assert_eq!(
            reserve_bytes(&mut out, usize::MAX, usize::MAX),
            Err(ReserveError::TooLong { limit: usize::MAX })
        );
        assert_eq!(out, b"ab");
        assert_eq!(out.capacity(), capacity);
        // The total fits the caller's limit but exceeds Vec's supported
        // capacity. This refuses deterministically without a huge allocation.
        let added = usize::MAX - out.len();
        assert_eq!(
            reserve_bytes(&mut out, added, usize::MAX),
            Err(ReserveError::Allocation)
        );
        assert_eq!(out, b"ab");
        assert_eq!(out.capacity(), capacity);
    }
    #[test]
    fn bounded_append_keeps_clamp_and_rolls_back_refusals() {
        let mut out = b"ab".to_vec();
        append_bounded::<()>(b"c", 2, &mut out, 4).unwrap();
        assert_eq!(out, b"abcc");
        let capacity = out.capacity();
        for (bytes, copies, limit, expected) in [
            (b"d".as_slice(), 1, 4, 4),
            (b"xx".as_slice(), usize::MAX, usize::MAX, Buffer::MAX_LIMIT),
            (
                b"x".as_slice(),
                Buffer::MAX_LIMIT + 1,
                usize::MAX,
                Buffer::MAX_LIMIT,
            ),
        ] {
            assert_eq!(
                append_bounded::<()>(bytes, copies, &mut out, limit),
                Err(RewriteError::TooLong { limit: expected })
            );
            assert_eq!(out, b"abcc");
            assert_eq!(out.capacity(), capacity);
        }
        append_bounded::<()>(b"", usize::MAX, &mut out, 4).unwrap();
        append_bounded::<()>(b"x", 0, &mut out, 4).unwrap();
        assert_eq!(out, b"abcc");
        assert_eq!(out.capacity(), capacity);
    }
}
