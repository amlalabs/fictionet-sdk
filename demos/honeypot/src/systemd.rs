//! Readiness and watchdog notifications to systemd (`sd_notify(3)`).
//!
//! Under a unit with `Type=notify` and `WatchdogSec=`, systemd sets
//! `NOTIFY_SOCKET` and `WATCHDOG_USEC`. A world task sends `WATCHDOG=1` at
//! half that interval, so a world that stops making progress stops the
//! pings and systemd restarts the service. Outside systemd nothing is sent.

use std::io;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::time::Duration;

/// A state change systemd understands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notification {
    Ready,
    Watchdog,
    Stopping,
}

impl Notification {
    fn message(self) -> &'static [u8] {
        match self {
            Self::Ready => b"READY=1",
            Self::Watchdog => b"WATCHDOG=1",
            Self::Stopping => b"STOPPING=1",
        }
    }
}

/// The service manager's notification socket.
pub struct Notifier {
    socket: UnixDatagram,
    address: SocketAddr,
    watchdog: Option<Duration>,
}

impl Notifier {
    /// The notifier systemd's environment describes, or `None` when the
    /// process does not run under a notify unit.
    pub fn from_env() -> io::Result<Option<Self>> {
        let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
            return Ok(None);
        };
        let path = path.to_string_lossy().into_owned();
        let address = match path.strip_prefix('@') {
            Some(name) => SocketAddr::from_abstract_name(name.as_bytes())?,
            None => SocketAddr::from_pathname(&path)?,
        };
        let ours = std::env::var("WATCHDOG_PID")
            .ok()
            .is_none_or(|pid| pid == std::process::id().to_string());
        let watchdog = std::env::var("WATCHDOG_USEC")
            .ok()
            .and_then(|usec| usec.parse::<u64>().ok())
            .filter(|&usec| ours && usec > 0)
            .map(Duration::from_micros);
        Ok(Some(Self {
            socket: UnixDatagram::unbound()?,
            address,
            watchdog,
        }))
    }

    /// How often to send [`Notification::Watchdog`]: half the interval
    /// systemd enforces, or `None` when it enforces none.
    pub fn watchdog_period(&self) -> Option<Duration> {
        self.watchdog.map(|interval| interval / 2)
    }

    pub fn notify(&self, notification: Notification) -> io::Result<()> {
        self.socket
            .send_to_addr(notification.message(), &self.address)
            .map(drop)
    }
}
