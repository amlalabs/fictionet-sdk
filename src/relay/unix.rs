use super::*;

pub(crate) fn cvt(n: libc::c_int) -> io::Result<libc::c_int> {
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n)
    }
}

/// Sets a socket's receive or send timeout. `None` waits forever.
pub fn set_timeout(fd: RawFd, option: libc::c_int, timeout: Option<Duration>) -> io::Result<()> {
    let tv = match timeout {
        Some(t) => libc::timeval {
            tv_sec: t.as_secs() as _,
            tv_usec: t.subsec_micros() as _,
        },
        None => libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
    };
    // SAFETY: setsockopt with a timeval.
    cvt(unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&raw const tv).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    })?;
    Ok(())
}

/// A `sockaddr_un` for `path`.
pub fn address(path: &std::path::Path) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: an all-zero sockaddr_un is valid.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() >= addr.sun_path.len() || bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bad Unix socket path",
        ));
    }
    for (dst, src) in addr.sun_path.iter_mut().zip(bytes) {
        *dst = *src as libc::c_char;
    }
    let len = std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1;
    Ok((addr, len as libc::socklen_t))
}

/// Raises a socket's send and receive buffers to 4 MiB, past the
/// system limit if the process has CAP_NET_ADMIN, else as far as the
/// limit allows. A seqpacket socket's default send buffer holds only
/// about a hundred full-size packets, fewer than one TCP window, so a
/// burst would lose packets. Failure is fine: the defaults still work.
pub fn raise_buffers(fd: std::os::fd::RawFd) {
    let size: libc::c_int = 4 << 20;
    for (force, plain) in [
        (libc::SO_SNDBUFFORCE, libc::SO_SNDBUF),
        (libc::SO_RCVBUFFORCE, libc::SO_RCVBUF),
    ] {
        for opt in [force, plain] {
            // SAFETY: setsockopt with an int value.
            let r = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    opt,
                    (&raw const size).cast(),
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if r == 0 {
                break;
            }
        }
    }
}

/// A new `SOCK_SEQPACKET` socket.
pub(crate) fn socket(nonblocking: bool) -> io::Result<OwnedFd> {
    let mut ty = libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC;
    if nonblocking {
        ty |= libc::SOCK_NONBLOCK;
    }
    // SAFETY: plain syscall; the fd is owned from here.
    let fd = cvt(unsafe { libc::socket(libc::AF_UNIX, ty, 0) })?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Connects to the world socket at `path`. The socket blocks.
pub fn connect(path: impl AsRef<std::path::Path>) -> io::Result<OwnedFd> {
    let fd = socket(false)?;
    let (addr, len) = address(path.as_ref())?;
    loop {
        // SAFETY: `addr` is a valid sockaddr_un of length `len`.
        let r = unsafe { libc::connect(fd.as_raw_fd(), (&raw const addr).cast(), len) };
        if r == 0 {
            return Ok(fd);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// Sets or clears `O_NONBLOCK`.
pub fn set_nonblocking(fd: RawFd, nonblocking: bool) -> io::Result<()> {
    // SAFETY: fcntl on an fd the caller owns.
    let flags = cvt(unsafe { libc::fcntl(fd, libc::F_GETFL) })?;
    let flags = if nonblocking {
        flags | libc::O_NONBLOCK
    } else {
        flags & !libc::O_NONBLOCK
    };
    cvt(unsafe { libc::fcntl(fd, libc::F_SETFL, flags) })?;
    Ok(())
}

/// Sends one message as one datagram. With `nonblocking`, a full buffer
/// is `WouldBlock` instead of a wait.
pub fn send(fd: RawFd, message: &[u8], nonblocking: bool) -> io::Result<()> {
    send_parts(fd, &[message], nonblocking)
}

/// Sends the concatenation of `parts` as one datagram.
pub fn send_parts(fd: RawFd, parts: &[&[u8]], nonblocking: bool) -> io::Result<()> {
    let iovec = |p: &&[u8]| libc::iovec {
        iov_base: p.as_ptr() as *mut libc::c_void,
        iov_len: p.len(),
    };
    // Every caller passes one or two parts (a kind byte or header, then
    // a payload), so those need no allocation.
    let mut stack = [libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    }; 2];
    let mut heap: Vec<libc::iovec>;
    let iov: &mut [libc::iovec] = if parts.len() <= stack.len() {
        for (v, p) in stack.iter_mut().zip(parts) {
            *v = iovec(p);
        }
        &mut stack[..parts.len()]
    } else {
        heap = parts.iter().map(iovec).collect();
        &mut heap
    };
    // SAFETY: an all-zero msghdr is valid; the iovecs point into `parts`.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = iov.as_mut_ptr();
    msg.msg_iovlen = iov.len() as _;
    let mut flags = libc::MSG_NOSIGNAL;
    if nonblocking {
        flags |= libc::MSG_DONTWAIT;
    }
    loop {
        // SAFETY: `msg` is valid for the call.
        let n = unsafe { libc::sendmsg(fd, &msg, flags) };
        if n >= 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// Receives one datagram into `buf`. `Ok(0)` means the other side
/// closed. A datagram longer than `buf` is cut to `buf.len()` bytes,
/// so callers pass [`MAX_MESSAGE`] + 1 bytes. A length above
/// [`MAX_MESSAGE`] marks an oversized or truncated message, which
/// [`decode`] rejects.
pub fn recv(fd: RawFd, buf: &mut [u8], nonblocking: bool) -> io::Result<usize> {
    let flags = if nonblocking { libc::MSG_DONTWAIT } else { 0 };
    loop {
        // SAFETY: `buf` is valid for writes of its length.
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), flags) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// Shuts the connection down both ways, so the other side reads its end.
pub fn shutdown(fd: RawFd) {
    // SAFETY: plain syscall on an fd the caller owns.
    unsafe { libc::shutdown(fd, libc::SHUT_RDWR) };
}
