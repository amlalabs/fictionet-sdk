use super::alloc::vec::Vec;
use core::fmt::Debug;
use fictionet::stdlib::codec::Wire;

/// Writes once into a nonempty destination and checks the result.
/// Success must preserve the prefix and parse as the original value. Failure
/// must leave the destination unchanged. Returns the bytes or the write error;
/// a parsed value is allowed to be unrepresentable by its writer.
///
/// ```
/// use fictionet::stdlib::{protocols::tpkt::Packet, test_support::assert_write};
/// let bytes = assert_write(&Packet::new(vec![1, 2, 3])).unwrap();
/// assert_eq!(bytes, [3, 0, 0, 7, 1, 2, 3]);
/// ```
pub fn assert_write<M: Wire + PartialEq + Debug>(value: &M) -> Result<Vec<u8>, M::WriteError> {
    let prefix = [0x5a, 0xc3, 0x17];
    let mut out = prefix.to_vec();
    match value.write(&mut out) {
        Err(error) => {
            assert_eq!(out, prefix, "writer changed destination on error");
            Err(error)
        }
        Ok(()) => {
            assert!(
                out.starts_with(&prefix),
                "writer changed destination prefix"
            );
            let bytes = out.split_off(prefix.len());
            let parsed = M::parse(&bytes).expect("writer output does not parse");
            assert_eq!(&parsed, value, "wire round trip changed value");
            Ok(bytes)
        }
    }
}
