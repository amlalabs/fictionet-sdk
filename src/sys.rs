//! What the runtime takes from the system it runs on: the clocks and
//! random bytes.
//!
//! On a host these come from `std` and the Linux `getrandom` call. In a
//! browser (wasm32-unknown-unknown), `std::time::Instant::now` and
//! `SystemTime::now` panic, so the clocks come from `web_time`, which reads
//! `performance.now()` and `Date.now()`, and random bytes come from
//! `crypto.getRandomValues` through the `getrandom` crate.

#[cfg(not(target_arch = "wasm32"))]
pub(crate) use std::time::{Instant, SystemTime, UNIX_EPOCH};
#[cfg(target_arch = "wasm32")]
pub(crate) use web_time::{Instant, SystemTime, UNIX_EPOCH};

/// Fills `buf` with random bytes from the operating system, or from the
/// browser's `crypto.getRandomValues`.
///
/// This is the secure randomness source for setup outside a run, where no
/// [`Cx`](crate::Cx) is available. Inside a run, draw randomness through
/// `Cx`. Returns the source's error if filling fails; `buf` may then be
/// partially filled.
#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "std")]
pub fn random_bytes(mut buf: &mut [u8]) -> std::io::Result<()> {
    while !buf.is_empty() {
        // SAFETY: the pointer and length describe `buf`.
        let n = unsafe { libc::getrandom(buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        buf = &mut buf[n as usize..];
    }
    Ok(())
}

/// Fills `buf` with random bytes from the operating system, or from the
/// browser's `crypto.getRandomValues`.
///
/// This is the secure randomness source for setup outside a run, where no
/// [`Cx`](crate::Cx) is available. Inside a run, draw randomness through
/// `Cx`. Returns the source's error if filling fails; `buf` may then be
/// partially filled.
#[cfg(target_arch = "wasm32")]
#[cfg(feature = "std")]
pub fn random_bytes(buf: &mut [u8]) -> std::io::Result<()> {
    getrandom::fill(buf).map_err(std::io::Error::other)
}
