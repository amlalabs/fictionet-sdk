extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

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
}
