//! The world's socket as an [`Interface`]: the link between attach's own
//! TCP/IP stack and the world.
//!
//! `tun` moves packets between a device and the socket. A proxy type has
//! no device: the packets come from the SDK's userspace stack, which takes
//! an `Interface`. This is that interface. Each `packet` message from the
//! world is one packet out of `poll_recv`, and each packet sent goes to
//! the world as one `packet` message.
//!
//! Reading never waits on its own: when the socket has nothing, tokio is
//! asked to wake the reader once it is readable, and the readiness is
//! cleared only after a read said `WouldBlock`, so no wake-up is lost.
//! Writing never waits either: when the socket is full, packets wait in a
//! queue, in order, and a task writes them out as the world makes room.
//! Unlike `tun`, nothing is dropped on a full socket while the queue has
//! room. A dropped packet costs the stack a retransmit, which is a stall
//! of a second or more, and the queue cannot grow far: each connection
//! has at most 256 KiB in flight.

use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use fictionet::relay::{self, Message, unix};
use fictionet::{Cx, Interface, Packet, RecvError};
use tokio::io::unix::AsyncFd;
use tokio::sync::Notify;

/// Packets waiting for room in the socket may take this many bytes, each
/// counting its length plus 64, as the world's own queue does. Past it,
/// packets are dropped.
const QUEUE_BUDGET: usize = 32 << 20;

/// The world's socket, as the stack's interface.
pub(crate) struct Link {
    shared: Arc<Shared>,
    buf: Vec<u8>,
}

/// What the link, its writer task and attach's main loop share.
pub(crate) struct Shared {
    fd: AsyncFd<OwnedFd>,
    queue: Mutex<Queue>,
    /// Wakes the writer task when packets are queued.
    queued: Notify,
    /// The world closed the connection, or it failed.
    closed: AtomicBool,
    /// Why, for attach's last message.
    why: Mutex<Option<String>>,
    dropped: AtomicU64,
}

#[derive(Default)]
struct Queue {
    packets: VecDeque<Packet>,
    bytes: usize,
}

impl Link {
    /// Takes the socket after the handshake. Must be called inside the
    /// tokio runtime; starts the writer task there.
    pub(crate) fn new(sock: OwnedFd) -> io::Result<Link> {
        let shared = Arc::new(Shared {
            fd: AsyncFd::new(sock)?,
            queue: Mutex::new(Queue::default()),
            queued: Notify::new(),
            closed: AtomicBool::new(false),
            why: Mutex::new(None),
            dropped: AtomicU64::new(0),
        });
        tokio::spawn(write_queued(shared.clone()));
        Ok(Link {
            shared,
            buf: vec![0u8; relay::MAX_MESSAGE + 1],
        })
    }

    pub(crate) fn shared(&self) -> Arc<Shared> {
        self.shared.clone()
    }
}

impl Shared {
    fn close(&self, why: Option<String>) {
        if !self.closed.swap(true, Ordering::SeqCst)
            && let Some(why) = why
        {
            *self.why.lock().unwrap() = Some(why);
        }
        // Wake the writer, so it ends too.
        self.queued.notify_one();
    }

    /// Why the link closed, if it closed on an error rather than the
    /// world closing the connection.
    pub(crate) fn error(&self) -> Option<String> {
        self.why.lock().unwrap().clone()
    }

    /// Packets dropped because the queue was full.
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    fn send(&self, packet: Packet) {
        if self.closed.load(Ordering::Relaxed) {
            return;
        }
        let mut q = self.queue.lock().unwrap();
        if q.packets.is_empty() {
            match send_one(self.fd.get_ref().as_raw_fd(), &packet) {
                Ok(true) => return,
                Ok(false) => {}
                Err(e) => {
                    drop(q);
                    self.close(Some(format!("sending to the world: {e}")));
                    return;
                }
            }
        }
        let cost = packet.0.len() + 64;
        if q.bytes + cost > QUEUE_BUDGET {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        q.bytes += cost;
        q.packets.push_back(packet);
        drop(q);
        self.queued.notify_one();
    }
}

/// Sends one packet without waiting. `Ok(false)`: the socket is full.
fn send_one(fd: std::os::fd::RawFd, packet: &Packet) -> io::Result<bool> {
    match unix::send_parts(fd, &[&[relay::PACKET], &packet.0], true) {
        Ok(()) => Ok(true),
        Err(e)
            if e.kind() == io::ErrorKind::WouldBlock || e.raw_os_error() == Some(libc::ENOBUFS) =>
        {
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

/// Writes queued packets out, in order, as the socket makes room.
async fn write_queued(shared: Arc<Shared>) {
    loop {
        shared.queued.notified().await;
        loop {
            if shared.closed.load(Ordering::SeqCst) {
                return;
            }
            let mut guard = match shared.fd.writable().await {
                Ok(g) => g,
                Err(e) => {
                    shared.close(Some(format!("waiting to write to the world: {e}")));
                    return;
                }
            };
            let mut q = shared.queue.lock().unwrap();
            let mut full = false;
            while let Some(packet) = q.packets.front() {
                match send_one(shared.fd.get_ref().as_raw_fd(), packet) {
                    Ok(true) => {
                        let cost = packet.0.len() + 64;
                        q.packets.pop_front();
                        q.bytes -= cost;
                    }
                    Ok(false) => {
                        full = true;
                        break;
                    }
                    Err(e) => {
                        drop(q);
                        shared.close(Some(format!("sending to the world: {e}")));
                        return;
                    }
                }
            }
            if !full {
                break;
            }
            drop(q);
            // Wait for the next time the socket says it has room.
            guard.clear_ready();
        }
    }
}

impl Interface for Link {
    fn poll_recv(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<Packet, RecvError>> {
        if fcx.is_cancelled() {
            return Poll::Ready(Err(RecvError::Cancelled));
        }
        let shared = &self.shared;
        loop {
            if shared.closed.load(Ordering::SeqCst) {
                return Poll::Ready(Err(RecvError::Closed));
            }
            let mut guard = match shared.fd.poll_read_ready(cx) {
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => {
                    shared.close(Some(format!("waiting to read from the world: {e}")));
                    return Poll::Ready(Err(RecvError::Closed));
                }
                Poll::Pending => return Poll::Pending,
            };
            match unix::recv(shared.fd.get_ref().as_raw_fd(), &mut self.buf, true) {
                Ok(0) => {
                    shared.close(None);
                    return Poll::Ready(Err(RecvError::Closed));
                }
                Ok(n) if n > relay::MAX_MESSAGE => {
                    shared.close(Some(
                        "the world sent a message longer than 65,536 bytes".into(),
                    ));
                    return Poll::Ready(Err(RecvError::Closed));
                }
                Ok(n) => match relay::decode(&self.buf[..n]) {
                    Ok(Message::Packet(p)) => return Poll::Ready(Ok(Packet(p.to_vec()))),
                    Ok(other) => {
                        shared.close(Some(format!("the world sent {other:?} after accept")));
                        return Poll::Ready(Err(RecvError::Closed));
                    }
                    Err(e) => {
                        shared.close(Some(format!("the world sent a bad message: {e}")));
                        return Poll::Ready(Err(RecvError::Closed));
                    }
                },
                // Nothing to read: clear the readiness, and poll again so
                // tokio registers this task's waker.
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => guard.clear_ready(),
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {
                    shared.close(None);
                    return Poll::Ready(Err(RecvError::Closed));
                }
                Err(e) => {
                    shared.close(Some(format!("reading from the world: {e}")));
                    return Poll::Ready(Err(RecvError::Closed));
                }
            }
        }
    }

    fn send(&mut self, packet: Packet) {
        self.shared.send(packet);
    }
}
