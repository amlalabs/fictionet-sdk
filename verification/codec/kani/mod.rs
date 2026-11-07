//! Kani harnesses over the codec layer's production code.
//!
//! Included from `src/stdlib/codec/mod.rs` under `cfg(kani)`, so every
//! harness calls the real functions. `verification/codec/README.md` says
//! what each one proves and the bound it proves it to.

mod base64;
mod ber;
mod bounded;
mod buffer;
mod crc;
mod dot_body;
mod frames;
mod head_body;
mod leb128;
mod reader;
mod stream;

/// A symbolic byte string of at most `N` bytes: the backing array and the
/// length in use. Harnesses slice `&bytes[..len]`.
fn bytes<const N: usize>() -> ([u8; N], usize) {
    let bytes: [u8; N] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= N);
    (bytes, len)
}
