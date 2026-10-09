//! Bounded input generators.

use arbitrary::{Result, Unstructured};

/// Up to `max` fuzz bytes.
#[allow(dead_code)]
pub fn bytes(u: &mut Unstructured, max: usize) -> Result<Vec<u8>> {
    let n = u.int_in_range(0..=max)?;
    Ok(u.bytes(n)?.to_vec())
}

/// Up to `max` values built by `f`.
#[allow(dead_code)]
pub fn list<T>(
    u: &mut Unstructured,
    max: usize,
    mut f: impl FnMut(&mut Unstructured) -> Result<T>,
) -> Result<Vec<T>> {
    let n = u.int_in_range(0..=max)?;
    (0..n).map(|_| f(u)).collect()
}
