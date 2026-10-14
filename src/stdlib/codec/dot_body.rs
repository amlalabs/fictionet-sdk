//! Dot transparency and bounded body assembly for line protocols.
//!
//! Callers frame lines and choose validation, line limits, and error classes.
//! [`Accumulator`] removes one leading dot and retains the first rejection
//! through the terminator. [`encoded_len`] and [`write()`] share the reverse
//! operation, so callers can validate and reserve before changing output.

extern crate alloc;

use alloc::vec::Vec;
use fictionet::stdlib::codec::{ReserveError, Step, reserve_bytes};

/// A dot-terminated body with an explicit unstuffed byte limit.
/// Owns accepted bytes and the first recoverable error, but no input cursor.
pub struct Accumulator<E> {
    limit: usize,
    size: usize,
    bytes: Vec<u8>,
    rejected: Option<E>,
}

impl<E> Accumulator<E> {
    /// Creates an empty body. `limit` counts unstuffed bytes with line endings,
    /// excluding the terminator. It is used exactly, without clamping.
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            size: 0,
            bytes: Vec::new(),
            rejected: None,
        }
    }

    /// Content bytes retained. Rejection clears these without shrinking capacity.
    pub fn held(&self) -> usize {
        self.bytes.len()
    }

    /// Accepts one complete framed line without its ending, or its recoverable
    /// framing error. `used` is that line's exact wire length, including its
    /// ending. Partial lines and fatal framing errors stay with the caller.
    ///
    /// A successful single-dot line completes the body without validation or
    /// charging. It returns `Item` and resets the assembly for the next body.
    /// Other lines return `Skip`. Both steps consume exactly `used` bytes;
    /// no bytes from a following line are examined.
    ///
    /// Before validation, charges `used` minus one for a successful line with
    /// a leading dot. An errored line charges all of `used`. Charging continues
    /// after rejection. Overflow or exceeding `limit` is `ReserveError::TooLong`.
    /// `reserve_error` translates this and allocation failure to a fatal error.
    ///
    /// `validate` sees unstuffed content, even after rejection. `Ok(None)` accepts
    /// it, `Ok(Some(error))` rejects the body, and `Err` ends the stream. The first
    /// rejection wins. Accepted content is stored with CRLF under the same limit.
    /// A fatal error requires discarding the accumulator.
    pub fn push<F>(
        &mut self,
        line: Result<&[u8], E>,
        used: usize,
        validate: impl FnOnce(&[u8]) -> Result<Option<E>, F>,
        reserve_error: impl Fn(ReserveError) -> F,
    ) -> Result<Step<Result<Vec<u8>, E>>, F> {
        if line.as_ref().is_ok_and(|line| *line == b".") {
            self.size = 0;
            let bytes = core::mem::take(&mut self.bytes);
            return Ok(Step::Item(
                self.rejected.take().map_or(Ok(bytes), Err),
                used,
            ));
        }
        self.size = self
            .size
            .checked_add(used)
            .and_then(|n| {
                n.checked_sub(usize::from(
                    line.as_ref().is_ok_and(|line| line.starts_with(b".")),
                ))
            })
            .filter(|&n| n <= self.limit)
            .ok_or_else(|| reserve_error(ReserveError::TooLong { limit: self.limit }))?;
        let rejection = match line {
            Ok(line) => {
                let content = line.strip_prefix(b".").unwrap_or(line);
                let rejection = validate(content)?;
                if rejection.is_none() && self.rejected.is_none() {
                    reserve_bytes(&mut self.bytes, content.len() + 2, self.limit)
                        .map_err(reserve_error)?;
                    self.bytes.extend_from_slice(content);
                    self.bytes.extend_from_slice(b"\r\n");
                }
                rejection
            }
            Err(error) => Some(error),
        };
        if let Some(error) = rejection {
            self.rejected.get_or_insert(error);
            self.bytes.clear();
        }
        Ok(Step::Skip(used))
    }
}

/// Counts stuffed bytes including the final dot line, without writing.
///
/// `body` is unstuffed and must fit `limit`. Empty bodies are allowed; every
/// other line must end in CRLF. `validate` receives each line's content without
/// CRLF and its stuffed wire length including CRLF. It chooses text rules and
/// whether the line limit counts the extra dot. Returns `None` for a refused
/// line, missing CRLF, a body over the limit, or arithmetic overflow.
pub fn encoded_len(
    body: &[u8],
    limit: usize,
    mut validate: impl FnMut(&[u8], usize) -> bool,
) -> Option<usize> {
    if body.len() > limit || (!body.is_empty() && !body.ends_with(b"\r\n")) {
        return None;
    }
    let mut size = body.len().checked_add(3)?;
    for line in body.split_inclusive(|b| *b == b'\n') {
        let content = line.strip_suffix(b"\r\n")?;
        let stuffed = usize::from(content.starts_with(b"."));
        if !validate(content, line.len().checked_add(stuffed)?) {
            return None;
        }
        size = size.checked_add(stuffed)?;
    }
    Some(size)
}

/// Appends dot-stuffed lines and the final `.` CRLF line.
/// Does no validation or fallible reservation. For transactional writes, call
/// [`encoded_len`] and reserve its result (plus any protocol prefix) before
/// writing anything. `body` must be the same bytes that passed validation.
pub fn write(body: &[u8], out: &mut Vec<u8>) {
    for line in body.split_inclusive(|b| *b == b'\n') {
        if line.starts_with(b".") {
            out.push(b'.');
        }
        out.extend_from_slice(line);
    }
    out.extend_from_slice(b".\r\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejection_retains_first_error_counts_bytes_and_resets_at_dot() {
        let mut body = Accumulator::new(10);
        assert_eq!(
            body.push(Ok(b".."), 4, |_| Ok(None), |e| e),
            Ok(Step::Skip(4))
        );
        assert_eq!(body.held(), 3);
        assert_eq!(
            body.push(Err("first"), 2, |_| panic!(), |e| e),
            Ok(Step::Skip(2))
        );
        assert_eq!(body.held(), 0);
        assert_eq!(
            body.push(
                Ok(b".x"),
                4,
                |content| {
                    assert_eq!(content, b"x");
                    Ok(Some("second"))
                },
                |e| e
            ),
            Ok(Step::Skip(4))
        );
        assert_eq!(
            body.push(Ok(b""), 2, |_| Ok(None), |e| e),
            Ok(Step::Skip(2))
        );
        assert_eq!(body.held(), 0);
        assert_eq!(
            body.push(Ok(b"."), 3, |_| panic!(), |e| e),
            Ok(Step::Item(Err("first"), 3))
        );
        assert_eq!(
            body.push(Ok(b"."), 3, |_| panic!(), |e| e),
            Ok(Step::Item(Ok(Vec::new()), 3))
        );
        body.push(Ok(b".."), 4, |_| Ok(None), |e| e).unwrap();
        assert_eq!(
            body.push(Ok(b"."), 3, |_| panic!(), |e| e),
            Ok(Step::Item(Ok(b".\r\n".to_vec()), 3))
        );
    }

    #[test]
    fn limit_precedes_validation_and_still_applies_after_rejection() {
        let mut body = Accumulator::new(5);
        body.push(Err("rejected"), 2, |_| panic!(), |_| "limit")
            .unwrap();
        assert_eq!(
            body.push(Ok(b"..x"), 5, |_| panic!(), |_| "limit"),
            Err("limit")
        );
        let mut body = Accumulator::new(usize::MAX);
        body.push(Err("rejected"), usize::MAX, |_| panic!(), |_| "limit")
            .unwrap();
        assert_eq!(
            body.push(Ok(b".."), 4, |_| panic!(), |_| "limit"),
            Err("limit")
        );
        let mut body = Accumulator::new(8);
        body.push(Err("rejected"), 2, |_| panic!(), |_| "limit")
            .unwrap();
        assert_eq!(
            body.push(Ok(b"x"), 3, |_| Err("fatal line"), |_| "limit"),
            Err("fatal line")
        );
    }

    #[test]
    fn encoding_counts_transparency_and_delegates_line_policy() {
        let body = b".\r\n\r\n..x\r\n";
        let size = encoded_len(body, body.len(), |_, _| true).unwrap();
        let mut out = Vec::with_capacity(size);
        write(body, &mut out);
        assert_eq!(out, b"..\r\n\r\n...x\r\n.\r\n");
        assert_eq!(out.len(), size);
        assert_eq!(encoded_len(body, body.len() - 1, |_, _| panic!()), None);
        assert_eq!(encoded_len(b"", 0, |_, _| panic!()), Some(3));
        for body in [b"x\n".as_slice(), b"x\r", b"x\nx\r\n"] {
            assert_eq!(encoded_len(body, 16, |_, _| true), None);
        }
        assert_eq!(
            encoded_len(b".x\r\n", 4, |content, stuffed| {
                assert_eq!(content, b".x");
                assert_eq!(stuffed, 5);
                content.len() + 2 <= 4
            }),
            Some(8)
        );
        assert_eq!(encoded_len(b".x\r\n", 4, |_, stuffed| stuffed <= 4), None);
    }
}
