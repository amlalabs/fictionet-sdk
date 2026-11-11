//! Whole Ethernet frames between a world and the thread that drives a NIC.
//!
//! This link carries Ethernet frames, not the IP packets of Fictionet's
//! `Interface`. Each direction holds at most 64 frames. When the receive
//! queue is full, the driver keeps reading and counts discarded frames.
//! [`RawAttachment::in_memory`] gives the driver's side as a [`RawWire`].
//! With the `af-xdp` feature, [`RawPump`] drives a real interface through
//! an AF_XDP socket.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use fictionet::{Cx, Error, Result};
use tokio::sync::{mpsc, oneshot};

const CAPACITY: usize = 64;
pub(crate) const MAX_FRAME: usize = 2036;

/// Complete Ethernet bytes, including the Ethernet header, without a frame checksum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EthernetFrame(pub Vec<u8>);

/// An original frame and its host receipt time before entering the queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedFrame {
    /// The unmodified frame bytes owned by the receiver.
    pub frame: EthernetFrame,
    /// Host system time, absent for untimestamped simulated traffic.
    pub received_at: Option<SystemTime>,
}

/// The world's complete Ethernet connection.
pub struct RawAttachment {
    sender: RawSender,
    receiver: RawReceiver,
    mac: [u8; 6],
    receive_stats: QueueStats,
    device_stats: Option<DeviceStats>,
}

/// Losses from one attachment queue. Device and backend losses are in
/// [`DeviceStats`], where the driver reports them.
#[derive(Clone, Default)]
pub struct QueueStats {
    queue_dropped: Arc<AtomicU64>,
}

/// Frames the driver's path lost before they reached the receive queue,
/// for drivers that can count them.
#[derive(Clone, Default)]
pub struct DeviceStats {
    rx_dropped: Arc<AtomicU64>,
}

impl DeviceStats {
    /// Received frames discarded before the attachment's queue, since the
    /// driver started. The count never goes down.
    pub fn rx_dropped(&self) -> u64 {
        self.rx_dropped.load(Ordering::Relaxed)
    }

    /// Raises the count to `total`, a running total the driver read.
    #[cfg_attr(not(all(target_os = "linux", feature = "af-xdp")), allow(dead_code))]
    pub(crate) fn record_rx_dropped(&self, total: u64) {
        self.rx_dropped.fetch_max(total, Ordering::Relaxed);
    }
}

impl QueueStats {
    /// Frames discarded because this queue was full, since
    /// attachment creation. The counter saturates rather than wrapping.
    pub fn queue_dropped(&self) -> u64 {
        self.queue_dropped.load(Ordering::Relaxed)
    }

    pub(crate) fn enqueue<T>(&self, sender: &mpsc::Sender<T>, value: T) -> Result<bool> {
        match sender.try_send(value) {
            Ok(()) => Ok(true),
            Err(mpsc::error::TrySendError::Full(_)) => {
                let _ =
                    self.queue_dropped
                        .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                            Some(count.saturating_add(1))
                        });
                Ok(false)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(Error::msg("raw Ethernet attachment closed"))
            }
        }
    }
}

/// The sending half of a raw attachment.
#[derive(Clone)]
pub struct RawSender {
    tx: mpsc::Sender<Command>,
    stats: QueueStats,
    failure: Arc<Mutex<Option<Error>>>,
}

/// The receiving half of a raw attachment.
pub struct RawReceiver {
    rx: mpsc::Receiver<ReceivedFrame>,
    failure: Arc<Mutex<Option<Error>>>,
}

pub(crate) enum Command {
    Frame(EthernetFrame),
    Flush(oneshot::Sender<()>),
}

fn check_length(frame: &EthernetFrame) -> Result {
    if (14..=MAX_FRAME).contains(&frame.0.len()) {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "Ethernet frame length is outside supported bounds",
    )
    .into())
}

fn closed(failure: &Mutex<Option<Error>>) -> Error {
    failure
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_else(|| Error::msg("raw Ethernet attachment closed"))
}

impl RawAttachment {
    /// A live view of receive queue losses, retained across [`Self::split`].
    pub fn receive_stats(&self) -> QueueStats {
        self.receive_stats.clone()
    }

    /// A live view of transmit queue losses, retained across [`Self::split`].
    pub fn transmit_stats(&self) -> QueueStats {
        self.sender.stats.clone()
    }

    /// The device's configured Ethernet address.
    pub fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    /// A live view of the driver's losses before the receive queue, or
    /// `None` when the driver cannot count them, as on an in-memory wire.
    pub fn device_stats(&self) -> Option<DeviceStats> {
        self.device_stats.clone()
    }

    /// Separates reception from transmission for independent world tasks.
    pub fn split(self) -> (RawSender, RawReceiver) {
        (self.sender, self.receiver)
    }

    /// Waits for a complete frame or cancellation.
    pub async fn recv(&mut self, fcx: &Cx) -> Result<EthernetFrame> {
        self.receiver.recv(fcx).await
    }

    /// Waits for a frame with its original backend receipt timestamp.
    pub async fn recv_with_timestamp(&mut self, fcx: &Cx) -> Result<ReceivedFrame> {
        self.receiver.recv_with_timestamp(fcx).await
    }

    /// Waits for bounded queue space. Completion means queued, not transmitted.
    pub async fn send(&self, fcx: &Cx, frame: EthernetFrame) -> Result {
        self.sender.send(fcx, frame).await
    }

    /// Waits until every earlier queued frame has completed transmission.
    pub async fn flush(&self, fcx: &Cx) -> Result {
        self.sender.flush(fcx).await
    }
}

/// The far side of an attachment made by [`RawAttachment::in_memory`]:
/// the wire, with no NIC behind it. What the world sends comes out of
/// [`recv`](RawWire::recv), and what [`send`](RawWire::send) puts on the
/// wire reaches the world, so a world's link layer runs against frames a
/// program writes and reads.
pub struct RawWire {
    incoming: mpsc::Sender<ReceivedFrame>,
    outgoing: mpsc::Receiver<Command>,
    receive_stats: QueueStats,
}

impl RawAttachment {
    /// An attachment with the Ethernet address `mac` whose frames go to
    /// and come from the returned [`RawWire`]. Each direction holds 64
    /// frames, as one to a NIC does.
    pub fn in_memory(mac: [u8; 6]) -> (RawAttachment, RawWire) {
        let (attachment, driver) = Self::driven(mac, None);
        let Driver {
            incoming,
            outgoing,
            receive_stats,
            failure: _,
        } = driver;
        (
            attachment,
            RawWire {
                incoming,
                outgoing,
                receive_stats,
            },
        )
    }

    /// An attachment and the side a driver thread holds.
    pub(crate) fn driven(mac: [u8; 6], device_stats: Option<DeviceStats>) -> (Self, Driver) {
        let (incoming, rx) = mpsc::channel(CAPACITY);
        let (tx, outgoing) = mpsc::channel(CAPACITY);
        let failure = Arc::new(Mutex::new(None));
        let receive_stats = QueueStats::default();
        (
            RawAttachment {
                sender: RawSender {
                    tx,
                    stats: QueueStats::default(),
                    failure: failure.clone(),
                },
                receiver: RawReceiver {
                    rx,
                    failure: failure.clone(),
                },
                mac,
                receive_stats: receive_stats.clone(),
                device_stats,
            },
            Driver {
                incoming,
                outgoing,
                receive_stats,
                failure,
            },
        )
    }
}

/// The driver thread's side of an attachment.
pub(crate) struct Driver {
    /// Frames to the world.
    pub incoming: mpsc::Sender<ReceivedFrame>,
    /// Frames and flushes from the world.
    pub outgoing: mpsc::Receiver<Command>,
    /// Counts frames the full queue to the world discarded.
    pub receive_stats: QueueStats,
    /// The error the world sees once the driver stops on one.
    pub failure: Arc<Mutex<Option<Error>>>,
}

impl Driver {
    /// Records why the driver stopped. The world's receive and send report
    /// it once the queues drain and this side is dropped.
    #[cfg_attr(not(all(target_os = "linux", feature = "af-xdp")), allow(dead_code))]
    pub fn fail(&self, error: Error) {
        *self.failure.lock().unwrap() = Some(error);
    }
}

impl RawWire {
    /// Puts a frame on the wire without waiting, counting a full receive
    /// queue's discarded frame just as the NIC polling thread does.
    pub fn try_send(&self, frame: EthernetFrame) -> Result<bool> {
        self.try_send_received(ReceivedFrame {
            frame,
            received_at: None,
        })
    }

    /// Queues a frame with the backend's receipt timestamp, without waiting.
    pub fn try_send_received(&self, received: ReceivedFrame) -> Result<bool> {
        check_length(&received.frame)?;
        self.receive_stats.enqueue(&self.incoming, received)
    }

    /// Puts `frame` on the wire to the world, waiting for room.
    pub async fn send(&self, fcx: &Cx, frame: EthernetFrame) -> Result {
        check_length(&frame)?;
        fcx.race(
            None,
            self.incoming.send(ReceivedFrame {
                frame,
                received_at: None,
            }),
        )
        .await?
        .map_err(|_| Error::msg("raw Ethernet attachment closed"))
    }

    /// The next frame the world sent, or `None` once the world's side is
    /// gone. A flush the world asks for completes at once: nothing is in
    /// flight on this wire.
    pub async fn recv(&mut self, fcx: &Cx) -> Result<Option<EthernetFrame>> {
        loop {
            match fcx.race(None, self.outgoing.recv()).await? {
                Some(Command::Frame(frame)) => return Ok(Some(frame)),
                Some(Command::Flush(done)) => {
                    let _ = done.send(());
                }
                None => return Ok(None),
            }
        }
    }
}

impl RawReceiver {
    /// Drains queued frames before reporting closure or a driver failure.
    pub async fn recv(&mut self, fcx: &Cx) -> Result<EthernetFrame> {
        self.recv_with_timestamp(fcx)
            .await
            .map(|received| received.frame)
    }

    /// Drains queued frames while preserving the backend's receipt timestamp.
    pub async fn recv_with_timestamp(&mut self, fcx: &Cx) -> Result<ReceivedFrame> {
        if fcx.is_cancelled() {
            return Err(fictionet::Cancelled.into());
        }
        fcx.race(None, self.rx.recv())
            .await?
            .ok_or_else(|| closed(&self.failure))
    }
}

impl RawSender {
    /// Queues a frame, waiting for space and observing world cancellation.
    /// Cancelling before queue space is available discards the supplied frame.
    pub async fn send(&self, fcx: &Cx, frame: EthernetFrame) -> Result {
        check_length(&frame)?;
        self.command(fcx, Command::Frame(frame)).await
    }

    /// Queues a frame if there is room, without waiting. Returns whether it
    /// was queued: a frame sent while the queue is full is dropped, as a
    /// host's full transmit queue drops it.
    pub fn try_send(&self, frame: EthernetFrame) -> Result<bool> {
        check_length(&frame)?;
        self.stats
            .enqueue(&self.tx, Command::Frame(frame))
            .map_err(|_| closed(&self.failure))
    }

    async fn command(&self, fcx: &Cx, command: Command) -> Result {
        if fcx.is_cancelled() {
            return Err(fictionet::Cancelled.into());
        }
        fcx.race(None, self.tx.send(command))
            .await?
            .map_err(|_| closed(&self.failure))
    }

    /// Waits for device completion of all frames queued before this call.
    pub async fn flush(&self, fcx: &Cx) -> Result {
        let (tx, rx) = oneshot::channel();
        self.command(fcx, Command::Flush(tx)).await?;
        fcx.race(None, rx).await?.map_err(|_| closed(&self.failure))
    }
}

/// Runs an [`XdpSocket`](crate::xdp::XdpSocket) on its own thread and
/// gives the world its attachment. Keep it outside `fictionet::run`.
///
/// The thread stops when the world drops its attachment, on
/// [`Self::shutdown`], or on an error, which it records in the
/// attachment's failure slot so the world's next receive or send reports
/// it. Stopping drops the socket, which takes the XDP program off the
/// interface; frames still queued are discarded.
#[cfg(all(target_os = "linux", feature = "af-xdp"))]
pub struct RawPump {
    shared: Arc<crate::xdp::pump::Shared>,
    thread: Option<std::thread::JoinHandle<Result>>,
}

#[cfg(all(target_os = "linux", feature = "af-xdp"))]
impl RawPump {
    /// Starts the pump thread and returns the world's attachment, with the
    /// interface's MAC address and the socket's loss counters.
    pub fn attach(socket: crate::xdp::XdpSocket) -> io::Result<(Self, RawAttachment)> {
        use crate::xdp::pump;
        let device = DeviceStats::default();
        let (attachment, mut driver) =
            RawAttachment::driven(socket.attached().mac, Some(device.clone()));
        let (wake, woken) = pump::wake_pair()?;
        let shared = Arc::new(pump::Shared {
            stop: Default::default(),
            wake,
            statistics: Mutex::new(None),
            device,
        });
        let thread_shared = shared.clone();
        let thread = std::thread::Builder::new()
            .name("af-xdp".into())
            .spawn(move || {
                let run = std::panic::AssertUnwindSafe(|| {
                    pump::run(socket, &mut driver, &thread_shared, &woken)
                });
                let result = std::panic::catch_unwind(run)
                    .unwrap_or_else(|_| Err(Error::msg("the AF_XDP pump thread panicked")));
                if let Err(error) = &result {
                    driver.fail(error.clone());
                }
                // Dropping the driver's side after the failure is recorded
                // lets the world's waiters see it.
                drop(driver);
                result
            })?;
        Ok((
            Self {
                shared,
                thread: Some(thread),
            },
            attachment,
        ))
    }

    /// The socket's loss counters as last read, once a second.
    pub fn statistics(&self) -> Option<crate::xdp::XskStatistics> {
        *self.shared.statistics.lock().unwrap()
    }

    /// Stops the thread, detaches the program, and reports the error that
    /// stopped the pump, if one did.
    pub fn shutdown(mut self) -> Result {
        self.stop_and_join()
    }

    fn stop_and_join(&mut self) -> Result {
        self.shared.stop.store(true, Ordering::Release);
        std::task::Wake::wake_by_ref(&self.shared.wake);
        match self.thread.take() {
            Some(thread) => thread
                .join()
                .map_err(|_| Error::msg("the AF_XDP pump thread panicked"))?,
            None => Ok(()),
        }
    }
}

#[cfg(all(target_os = "linux", feature = "af-xdp"))]
impl Drop for RawPump {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::{Future, poll_fn};
    use std::task::Poll;

    #[test]
    fn receive_queue_counts_only_full_queue_discards_and_recovers() {
        let (mut raw, wire) = RawAttachment::in_memory([2; 6]);
        let stats = raw.receive_stats();
        for byte in 0..CAPACITY {
            assert!(wire.try_send(EthernetFrame(vec![byte as u8; 14])).unwrap());
        }
        for _ in 0..3 {
            assert!(!wire.try_send(EthernetFrame(vec![0xff; 14])).unwrap());
        }
        assert!(wire.try_send(EthernetFrame(vec![0; 13])).is_err());
        assert_eq!(stats.queue_dropped(), 3);
        fictionet::block_on(fictionet::run(
            fictionet::Seed::from_u64(0),
            move |fcx| async move {
                for byte in 0..CAPACITY {
                    assert_eq!(raw.recv(&fcx).await?, EthernetFrame(vec![byte as u8; 14]));
                }
                assert!(wire.try_send(EthernetFrame(vec![0xaa; 14]))?);
                assert_eq!(raw.recv(&fcx).await?, EthernetFrame(vec![0xaa; 14]));
                drop(raw);
                assert!(wire.try_send(EthernetFrame(vec![0; 14])).is_err());
                assert_eq!(stats.queue_dropped(), 3);
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn bounded_send_waits_and_cancels_without_queueing() {
        let (tx, mut rx) = mpsc::channel(1);
        let sender = RawSender {
            tx,
            stats: QueueStats::default(),
            failure: Arc::new(Mutex::new(None)),
        };
        fictionet::block_on(fictionet::run(fictionet::Seed::from_u64(0), move |fcx| async move {
            sender.send(&fcx, EthernetFrame(vec![1; 14])).await?;
            let mut waiting = std::pin::pin!(sender.send(&fcx, EthernetFrame(vec![2; 14])));
            poll_fn(|cx| { assert!(waiting.as_mut().poll(cx).is_pending()); Poll::Ready(()) }).await;
            fcx.cancel();
            assert!(waiting.await.is_err());
            assert!(matches!(rx.try_recv(), Ok(Command::Frame(EthernetFrame(bytes))) if bytes == vec![1; 14]));
            assert!(matches!(rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)));
            Ok(())
        })).unwrap();
    }

    #[test]
    fn try_send_drops_a_frame_when_the_queue_is_full() {
        let (tx, mut rx) = mpsc::channel(1);
        let sender = RawSender {
            tx,
            stats: QueueStats::default(),
            failure: Arc::new(Mutex::new(None)),
        };
        assert!(sender.try_send(EthernetFrame(vec![1; 14])).unwrap());
        assert!(!sender.try_send(EthernetFrame(vec![2; 14])).unwrap());
        assert!(sender.try_send(EthernetFrame(vec![3; 13])).is_err());
        assert!(
            matches!(rx.try_recv(), Ok(Command::Frame(EthernetFrame(bytes))) if bytes == vec![1; 14])
        );
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        drop(rx);
        assert!(sender.try_send(EthernetFrame(vec![4; 14])).is_err());
    }

    #[test]
    fn receive_preserves_frame_and_reports_driver_failure_after_drain() {
        let (tx, rx) = mpsc::channel(1);
        let failure = Arc::new(Mutex::new(Some(Error::msg("device stopped"))));
        let mut receiver = RawReceiver { rx, failure };
        let frame = EthernetFrame(vec![0xab; 64]);
        let received_at = Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(12));
        tx.try_send(ReceivedFrame {
            frame: frame.clone(),
            received_at,
        })
        .unwrap();
        drop(tx);
        fictionet::block_on(fictionet::run(
            fictionet::Seed::from_u64(0),
            move |fcx| async move {
                let received = receiver.recv_with_timestamp(&fcx).await?;
                assert_eq!(received.frame, frame);
                assert_eq!(received.received_at, received_at);
                assert_eq!(
                    receiver.recv(&fcx).await.unwrap_err().to_string(),
                    "device stopped"
                );
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn flush_waits_for_completion_acknowledgement() {
        let (tx, mut rx) = mpsc::channel(1);
        let sender = RawSender {
            tx,
            stats: QueueStats::default(),
            failure: Arc::new(Mutex::new(None)),
        };
        fictionet::block_on(fictionet::run(
            fictionet::Seed::from_u64(0),
            move |fcx| async move {
                let mut waiting = std::pin::pin!(sender.flush(&fcx));
                poll_fn(|cx| {
                    assert!(waiting.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                let Command::Flush(done) = rx.try_recv().unwrap() else {
                    panic!("expected flush");
                };
                poll_fn(|cx| {
                    assert!(waiting.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                done.send(()).unwrap();
                waiting.await?;
                Ok(())
            },
        ))
        .unwrap();
    }
}
