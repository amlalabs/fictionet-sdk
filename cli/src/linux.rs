//! Linux device calls for attach: entering a network namespace, opening or
//! making `/dev/net/tun`, creating a TUN device, and looking up an interface index.

use std::fs;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;

use crate::world::{Failure, context, err};

pub(crate) fn enter_netns(path: &Path) -> io::Result<()> {
    let file = fs::File::open(path)?;
    // SAFETY: plain syscall on an fd we own.
    if unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const TUNGETIFF: libc::c_ulong = 0x8004_54d2;
const IFF_TUN: libc::c_short = 0x0001;
pub(crate) const IFF_NO_PI: libc::c_short = 0x1000;

const TUN_PATH: &str = "/dev/net/tun";

/// Opens `/dev/net/tun`. If the node is missing, as in a Kubernetes
/// container that was given no devices, attach makes it first (character
/// device 10:200). That needs `CAP_MKNOD`, and the runtime's device rules
/// must allow the device: runc's own rules do, except in runc 1.2.0 to
/// 1.2.3.
pub(crate) fn open_tun_file() -> Result<OwnedFd, Failure> {
    let open = || {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(TUN_PATH)
            .map(OwnedFd::from)
    };
    let blocked = |e: io::Error| {
        Failure::Error(format!(
            "opening {TUN_PATH}: {e}. The container runtime's device rules do not allow the tun \
             device (char 10:200). Give the container the device (docker --device /dev/net/tun), or \
             check the runtime: runc 1.2.0 to 1.2.3 leave tun out of their default rules"
        ))
    };
    match open() {
        Ok(fd) => return Ok(fd),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) if e.raw_os_error() == Some(libc::EPERM) => return Err(blocked(e)),
        Err(e) => return Err(Failure::Error(format!("opening {TUN_PATH}: {e}"))),
    }
    make_tun_node().map_err(|e| {
        Failure::Error(format!(
            "{TUN_PATH} is missing, and attach could not make it: {e}. Give attach CAP_MKNOD, \
             or give the container the device (docker --device /dev/net/tun)"
        ))
    })?;
    eprintln!("fictionet attach: made {TUN_PATH} (char 10:200)");
    open().map_err(blocked)
}

/// `mkdir -p /dev/net` and `mknod /dev/net/tun c 10 200`, mode 0666 as
/// udev makes it.
fn make_tun_node() -> io::Result<()> {
    match fs::create_dir("/dev/net") {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(context(e, "making /dev/net")),
    }
    let path = c"/dev/net/tun";
    // SAFETY: plain syscall on a valid C string.
    let r = unsafe { libc::mknod(path.as_ptr(), libc::S_IFCHR | 0o666, libc::makedev(10, 200)) };
    if r < 0 {
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::AlreadyExists {
            return Err(e);
        }
    }
    Ok(())
}

/// Creates a tun device without packet info. The kernel picks the name
/// (`tun0`, `tun1`, ...). The device is removed when the fd is closed.
pub(crate) fn open_tun() -> Result<(OwnedFd, String), Failure> {
    let fd = open_tun_file()?;
    make_tun_device(fd).map_err(err(
        "creating the tun device (does attach have CAP_NET_ADMIN?)",
    ))
}

fn make_tun_device(fd: OwnedFd) -> io::Result<(OwnedFd, String)> {
    // struct ifreq: a 16-byte name, then a union; flags are a short at 16.
    let mut ifr = [0u8; 40];
    ifr[16..18].copy_from_slice(&(IFF_TUN | IFF_NO_PI).to_ne_bytes());
    set_tun_interface(&fd, &mut ifr)?;
    if ifr[0] == 0 {
        // gVisor makes the device but does not write its name back. Ask
        // for it.
        // SAFETY: `ifr` is as large as struct ifreq.
        if unsafe { libc::ioctl(fd.as_raw_fd(), TUNGETIFF as _, ifr.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let len = ifr[..16].iter().position(|&b| b == 0).unwrap_or(16);
    if len == 0 {
        return Err(io::Error::other("the kernel gave the tun device no name"));
    }
    let name = String::from_utf8_lossy(&ifr[..len]).into_owned();
    Ok((fd, name))
}

pub(crate) fn index_of(dev: &str) -> io::Result<u32> {
    let c = std::ffi::CString::new(dev).unwrap();
    // SAFETY: `c` is a valid C string.
    let index = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if index == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(index)
    }
}

/// Sets a TUN or TAP interface using the complete Linux ifreq buffer.
pub(crate) fn set_tun_interface(fd: &OwnedFd, request: &mut [u8; 40]) -> io::Result<()> {
    // SAFETY: TUNSETIFF copies at most sizeof(ifreq) bytes to and from this
    // initialized buffer. The descriptor remains owned throughout the call.
    if unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF, request.as_mut_ptr()) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Polls exactly the supplied entries, preserving the syscall result and errno.
pub(crate) fn poll(fds: &mut [libc::pollfd], timeout: i32) -> i32 {
    // SAFETY: the mutable slice provides initialized storage for every entry;
    // poll never retains the pointer. Invalid descriptors are reported in revents.
    unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) }
}

/// Reads at most the buffer length, preserving the syscall result and errno.
pub(crate) fn read(fd: std::os::fd::RawFd, buffer: &mut [u8]) -> isize {
    // SAFETY: the buffer is writable for its entire length for this call.
    unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) }
}

/// Writes the supplied bytes, preserving the syscall result and errno.
pub(crate) fn write(fd: std::os::fd::RawFd, buffer: &[u8]) -> isize {
    // SAFETY: the buffer is readable for its entire length for this call.
    unsafe { libc::write(fd, buffer.as_ptr().cast(), buffer.len()) }
}

/// Writes a header and payload as one packet without copying their bytes.
pub(crate) fn write_packet(fd: std::os::fd::RawFd, parts: [&[u8]; 2]) -> isize {
    let iov = parts.map(|part| libc::iovec {
        iov_base: part.as_ptr() as *mut _,
        iov_len: part.len(),
    });
    // SAFETY: both iovecs borrow readable slices for the duration of writev,
    // which reads their bytes and does not retain either pointer.
    unsafe { libc::writev(fd, iov.as_ptr(), iov.len() as libc::c_int) }
}
