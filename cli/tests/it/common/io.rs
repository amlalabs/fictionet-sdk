use std::io::Read;

#[path = "../../../../tests/common/response.rs"]
mod response;
pub use response::response;

/// Requires EOF. The caller must bound blocking reads with a socket timeout.
pub fn read_all(reader: &mut impl Read) -> Vec<u8> {
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).expect("read until EOF");
    bytes
}

/// Includes the delimiter, without consuming the next byte. Requires a read timeout.
pub fn read_until(reader: &mut impl Read, delimiter: &[u8]) -> Vec<u8> {
    assert!(!delimiter.is_empty(), "empty delimiter");
    let mut bytes = Vec::new();
    while !bytes.ends_with(delimiter) {
        let mut byte = [0];
        reader.read_exact(&mut byte).expect("read until delimiter");
        bytes.extend_from_slice(&byte);
    }
    bytes
}
