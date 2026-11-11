//! The thread that runs an [`XdpSocket`] against a world's attachment.
//!
//! It waits in `poll(2)` on the socket and on a wake datagram. The world's
//! transmit queue wakes it through the datagram, by way of the waker it
//! registers when the queue is empty. Statistics are read once a second.
//! While a frame or flush waits on transmit completions, which `poll` does
//! not signal, it polls every millisecond instead.

use std::io;
use std::os::fd::AsFd;
use std::os::unix::net::UnixDatagram;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Waker};
use std::time::{Duration, Instant};

use fictionet::Result;

use super::{XdpSocket, XskStatistics};
use crate::raw::{DeviceStats, Driver};

const STATISTICS_PERIOD: Duration = Duration::from_secs(1);
const COMPLETION_POLL: Duration = Duration::from_millis(1);

/// Wakes the pump thread: one datagram on a nonblocking socket pair. A
/// full pair means a wake is already pending, so a failed send is fine.
pub(crate) struct Wake(UnixDatagram);

impl std::task::Wake for Wake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let _ = self.0.send(&[1]);
    }
}

/// A wake handle and the socket the pump thread polls for it.
pub(crate) fn wake_pair() -> io::Result<(Arc<Wake>, UnixDatagram)> {
    let (sender, receiver) = UnixDatagram::pair()?;
    sender.set_nonblocking(true)?;
    receiver.set_nonblocking(true)?;
    Ok((Arc::new(Wake(sender)), receiver))
}

/// What the pump shares with its owner.
pub(crate) struct Shared {
    pub stop: AtomicBool,
    pub wake: Arc<Wake>,
    pub statistics: Mutex<Option<XskStatistics>>,
    pub device: DeviceStats,
}

/// Runs until `stop`, the world's side closes, or an error. The socket is
/// dropped on return, which takes the program off the interface.
pub(crate) fn run(
    mut socket: XdpSocket,
    driver: &mut Driver,
    shared: &Shared,
    woken: &UnixDatagram,
) -> Result {
    let waker = Waker::from(shared.wake.clone());
    let mut cx = Context::from_waker(&waker);
    let mut next_read = Instant::now();
    while !shared.stop.load(Ordering::Acquire) {
        let step = socket.datapath.step(driver, &mut cx)?;
        if step.closed {
            break;
        }
        if step.kick {
            socket.kick()?;
        }
        let now = Instant::now();
        if now >= next_read {
            let statistics = socket.statistics()?;
            shared.device.record_rx_dropped(
                statistics
                    .rx_lost()
                    .saturating_add(socket.datapath.discarded()),
            );
            *shared.statistics.lock().unwrap() = Some(statistics);
            next_read = now + STATISTICS_PERIOD;
        }
        let timeout = if step.more_rx {
            Duration::ZERO
        } else if step.kick || step.awaiting_completion {
            COMPLETION_POLL
        } else {
            next_read.saturating_duration_since(now)
        };
        socket.wait(woken.as_fd(), timeout)?;
        // Drain before the next step, so a wake that lands after it stays
        // readable for the next wait.
        let mut buffer = [0u8; 16];
        while woken.recv(&mut buffer).is_ok() {}
    }
    Ok(())
}
