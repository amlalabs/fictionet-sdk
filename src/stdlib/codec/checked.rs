extern crate alloc;

use alloc::vec::Vec;

/// Encodes `value` and appends the bytes only if `decode` reads the same value.
///
/// Use this in [`Wire::write`](fictionet::stdlib::codec::Wire::write)
/// implementations with separate encode and decode functions. Those
/// functions must enforce the type's size and field limits.
/// The temporary encoding is kept only for this call.
///
/// Returns an encoding error unchanged. Returns `unwritable` if decoding fails
/// or changes the value. Leaves `out` unchanged on either error.
pub fn write_checked<T: PartialEq, E>(
    value: &T,
    encode: impl FnOnce(&T) -> Result<Vec<u8>, E>,
    decode: impl FnOnce(&[u8]) -> Result<T, E>,
    unwritable: E,
    out: &mut Vec<u8>,
) -> Result<(), E> {
    let bytes = encode(value)?;
    if decode(&bytes).as_ref().ok() != Some(value) {
        return Err(unwritable);
    }
    out.extend_from_slice(&bytes);
    Ok(())
}
