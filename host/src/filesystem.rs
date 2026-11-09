//! Filesystem capacity queries for host-side storage preparation.

use std::{io, path::Path};

/// Bytes available to an unprivileged writer on the filesystem containing `path`.
pub fn available_space(path: &Path) -> io::Result<u64> {
    let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: path is terminated and stats provides aligned writable storage
    // for one statvfs. The syscall does not retain either pointer.
    if unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful statvfs initialized every field of the output.
    let stats = unsafe { stats.assume_init() };
    Ok(stats.f_bavail * stats.f_frsize)
}
