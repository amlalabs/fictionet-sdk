//! Direct, single-queue Linux TUN attachment without route or DNS changes.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;

use fictionet::{Cx, End, Interface, InterfaceExt, Packet};
use tokio::io::unix::AsyncFd;

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const TUNGETIFF: libc::c_ulong = 0x8004_54d2;
const TUN: i16 = 0x0001;
const NO_PI: i16 = 0x1000;
const PERSIST: i16 = 0x0800;
const EXCLUSIVE: i16 = 0x8000u16 as i16;
const MTU: i32 = 1500;

/// Whether the interface belongs to deployment provisioning or this process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Attach a persistent, single-queue TUN without changing its settings.
    Existing,
    /// Create an ephemeral TUN and bring only this interface up.
    Create,
}

/// A TUN descriptor. Closing an ephemeral device's last descriptor removes it.
pub struct Tun(AsyncFd<File>);

impl Tun {
    /// Opens the named interface in the current network namespace.
    /// Existing devices must be persistent, up, use no packet-info or virtio
    /// headers, have one queue, and have MTU 1500. Creation requires writable
    /// per-interface IPv6 sysctls and suppresses kernel address autoconfiguration
    /// before bringing the device up. It never adds routes, addresses, forwarding
    /// rules, or DNS configuration.
    pub fn open(name: &str, mode: Mode) -> io::Result<Self> {
        validate_name(name)?;
        let mut request = [0u8; 40];
        request[..name.len()].copy_from_slice(name.as_bytes());
        let control = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let exists = ioctl(control.as_raw_fd(), libc::SIOCGIFFLAGS, &mut request).is_ok();
        match (mode, exists) {
            (Mode::Create, true) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "TUN name already exists",
                ));
            }
            (Mode::Existing, false) => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "existing TUN does not exist in this network namespace",
                ));
            }
            _ => {}
        }
        if mode == Mode::Existing {
            let flags = i16::from_ne_bytes(request[16..18].try_into().unwrap());
            if flags & libc::IFF_UP as i16 == 0 {
                return Err(io::Error::other("existing TUN must already be up"));
            }
            ioctl(control.as_raw_fd(), libc::SIOCGIFMTU, &mut request)?;
            if i32::from_ne_bytes(request[16..20].try_into().unwrap()) != MTU {
                return Err(io::Error::other("existing TUN must have MTU 1500"));
            }
            let flags = std::fs::read_to_string(format!("/sys/class/net/{name}/tun_flags"))?;
            let flags = u16::from_str_radix(flags.trim().trim_start_matches("0x"), 16)
                .map_err(io::Error::other)?;
            if flags != (TUN | NO_PI | PERSIST) as u16 {
                return Err(io::Error::other(
                    "existing TUN must be persistent, single queue, and use plain IP packets",
                ));
            }
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open("/dev/net/tun")?;
        let flags = TUN | NO_PI | if mode == Mode::Create { EXCLUSIVE } else { 0 };
        request[16..18].copy_from_slice(&flags.to_ne_bytes());
        ioctl(file.as_raw_fd(), TUNSETIFF, &mut request)?;
        ioctl(file.as_raw_fd(), TUNGETIFF, &mut request)?;
        let actual = i16::from_ne_bytes(request[16..18].try_into().unwrap());
        let expected = TUN | NO_PI | if mode == Mode::Existing { PERSIST } else { 0 };
        if actual != expected {
            return Err(io::Error::other(
                "TUN configuration changed during attachment",
            ));
        }
        if mode == Mode::Create {
            // The simulated host owns the addresses. Keep the kernel from
            // assigning its own link-local address or soliciting a router on
            // this newly owned interface. IPv6 and forwarding remain available.
            let sysctl = format!("/proc/sys/net/ipv6/conf/{name}");
            std::fs::write(format!("{sysctl}/addr_gen_mode"), b"1\n")?;
            std::fs::write(format!("{sysctl}/autoconf"), b"0\n")?;
            std::fs::write(format!("{sysctl}/accept_ra"), b"0\n")?;
            request[16..20].copy_from_slice(&MTU.to_ne_bytes());
            ioctl(control.as_raw_fd(), libc::SIOCSIFMTU, &mut request)?;
            ioctl(control.as_raw_fd(), libc::SIOCGIFFLAGS, &mut request)?;
            let flags =
                i16::from_ne_bytes(request[16..18].try_into().unwrap()) | libc::IFF_UP as i16;
            request[16..18].copy_from_slice(&flags.to_ne_bytes());
            ioctl(control.as_raw_fd(), libc::SIOCSIFFLAGS, &mut request)?;
        }
        // SAFETY: this descriptor remains open and nonblocking for the registration's lifetime.
        Ok(Self(unsafe { AsyncFd::register(file)? }))
    }

    /// Relays plain IP packets in process. Backpressure leaves ingress in the
    /// kernel TUN queue; kernel queue loss is not observable through this API.
    pub async fn relay(self, fcx: Cx, mut end: End) -> fictionet::Result {
        let mut buffer = vec![0u8; 65_536];
        loop {
            let incoming = async {
                loop {
                    let mut ready = self.0.readable().await?;
                    match ready.try_io(|fd| fd.get_ref().read(&mut buffer)) {
                        Ok(result) => return result,
                        Err(_) => continue,
                    }
                }
            };
            tokio::select! {
                biased;
                _ = fcx.cancelled() => return Ok(()),
                result = end.recv(&fcx) => {
                    let packet = result?;
                    let write = async {
                        loop {
                            let mut ready = self.0.writable().await?;
                            match ready.try_io(|fd| fd.get_ref().write(&packet.0)) {
                                Ok(result) => return result,
                                Err(_) => continue,
                            }
                        }
                    };
                    let count = fcx.race(None, write).await??;
                    if count != packet.0.len() {
                        return Err(io::Error::new(io::ErrorKind::WriteZero, "partial TUN packet write").into());
                    }
                }
                result = incoming => {
                    let count = result?;
                    if count == 0 { return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "TUN closed").into()); }
                    end.send(Packet(buffer[..count].to_vec()));
                }
            }
            fcx.yield_now().await?;
        }
    }
}

fn validate_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.len() >= libc::IFNAMSIZ
        || name
            .bytes()
            .any(|b| !(b.is_ascii_alphanumeric() || b"_.-".contains(&b)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TUN name must contain one to fifteen letters, digits, dots, underscores or hyphens",
        ));
    }
    Ok(())
}

fn ioctl(fd: i32, operation: libc::c_ulong, request: &mut [u8; 40]) -> io::Result<()> {
    // SAFETY: the descriptor is live and the buffer holds a complete Linux ifreq.
    if unsafe { libc::ioctl(fd, operation, request.as_mut_ptr()) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_names_that_could_escape_device_lookup() {
        for name in ["", "../hp0", "1234567890123456", "hp\0", "hp 0"] {
            assert!(validate_name(name).is_err());
        }
        for name in ["hp0", "hp-test.0", "hp_test"] {
            assert!(validate_name(name).is_ok());
        }
    }
}
