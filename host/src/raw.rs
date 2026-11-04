//! Whole Ethernet frames between a world and the thread that drives a NIC.
//!
//! This link carries Ethernet frames, not the IP packets of Fictionet's
//! `Interface`. Each direction holds at most 64 frames, plus one the
//! driver thread holds. When the receive queue is full, the thread stops
//! reading, and the NIC may drop frames.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use fictionet::{Cx, Error, Result};
use tokio::sync::{mpsc, oneshot};

use crate::VirtioNet;

const CAPACITY: usize = 64;
const MAX_FRAME: usize = 2036;

/// Complete Ethernet bytes, including the Ethernet header, without a frame checksum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EthernetFrame(pub Vec<u8>);

/// The world's complete Ethernet connection.
pub struct RawAttachment {
    sender: RawSender,
    receiver: RawReceiver,
    mac: [u8; 6],
}

/// The sending half of a raw attachment.
#[derive(Clone)]
pub struct RawSender {
    tx: mpsc::Sender<Command>,
    failure: Arc<Mutex<Option<Error>>>,
}

/// The receiving half of a raw attachment.
pub struct RawReceiver {
    rx: mpsc::Receiver<EthernetFrame>,
    failure: Arc<Mutex<Option<Error>>>,
}

enum Command {
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
    /// The device's configured Ethernet address.
    pub fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    /// Separates reception from transmission for independent world tasks.
    pub fn split(self) -> (RawSender, RawReceiver) {
        (self.sender, self.receiver)
    }

    /// Waits for a complete frame or cancellation.
    pub async fn recv(&mut self, fcx: &Cx) -> Result<EthernetFrame> {
        self.receiver.recv(fcx).await
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

impl RawReceiver {
    /// Drains queued frames before reporting closure or a driver failure.
    pub async fn recv(&mut self, fcx: &Cx) -> Result<EthernetFrame> {
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
        match self.tx.try_send(Command::Frame(frame)) {
            Ok(()) => Ok(true),
            Err(mpsc::error::TrySendError::Full(_)) => Ok(false),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(closed(&self.failure)),
        }
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

/// Owns host polling and the device. Keep it outside `fictionet::run`.
///
/// Dropping this handle stops the thread and resets the device, discarding
/// queued traffic. Call the attachment's `flush` before shutdown when delivery
/// matters. An idle or backpressured driver parks between hardware polls.
pub struct RawPump {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result>>,
}

impl RawPump {
    /// Starts host polling and returns the bounded world attachment.
    pub fn attach(nic: VirtioNet) -> io::Result<(Self, RawAttachment)> {
        let mac = nic.mac_address();
        let (incoming, rx) = mpsc::channel(CAPACITY);
        let (tx, outgoing) = mpsc::channel(CAPACITY);
        let failure = Arc::new(Mutex::new(None));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let thread_failure = failure.clone();
        let thread = thread::Builder::new()
            .name("raw-ethernet".into())
            .spawn(move || {
                // Keep channels alive until the failure is published, so waiters see it.
                let mut incoming = incoming;
                let mut outgoing = outgoing;
                let result = pump(nic, &thread_stop, &mut incoming, &mut outgoing);
                if let Err(error) = &result {
                    *thread_failure.lock().unwrap() = Some(error.clone());
                }
                result
            })?;
        Ok((
            Self {
                stop,
                thread: Some(thread),
            },
            RawAttachment {
                sender: RawSender {
                    tx,
                    failure: failure.clone(),
                },
                receiver: RawReceiver { rx, failure },
                mac,
            },
        ))
    }

    /// Stops polling, resets the device, and reports any driver or thread error.
    pub fn shutdown(mut self) -> Result {
        self.stop_and_join()
    }

    fn stop_and_join(&mut self) -> Result {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.thread().unpark();
            thread
                .join()
                .map_err(|_| Error::msg("raw Ethernet host thread panicked"))??;
        }
        Ok(())
    }
}

impl Drop for RawPump {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}

fn pump(
    mut nic: VirtioNet,
    stop: &AtomicBool,
    incoming: &mut mpsc::Sender<EthernetFrame>,
    outgoing: &mut mpsc::Receiver<Command>,
) -> Result {
    let mut buffer = [0u8; MAX_FRAME];
    let mut pending_rx = None;
    let mut pending_tx = None;
    while !stop.load(Ordering::Acquire) {
        if incoming.is_closed() {
            return Ok(());
        }
        let mut progress = false;
        if pending_rx.is_none()
            && let Some(len) = nic.receive(&mut buffer)?
        {
            pending_rx = Some(EthernetFrame(buffer[..len].to_vec()));
        }
        if let Some(frame) = pending_rx.take() {
            match incoming.try_send(frame) {
                Ok(()) => progress = true,
                Err(mpsc::error::TrySendError::Full(frame)) => pending_rx = Some(frame),
                Err(mpsc::error::TrySendError::Closed(_)) => return Ok(()),
            }
        }
        if pending_tx.is_none() {
            match outgoing.try_recv() {
                Ok(command) => pending_tx = Some(command),
                Err(mpsc::error::TryRecvError::Disconnected) => return Ok(()),
                Err(mpsc::error::TryRecvError::Empty) => {}
            }
        }
        if let Some(command) = pending_tx.take() {
            match command {
                Command::Frame(frame) => {
                    if nic.transmit(&frame.0)? {
                        progress = true;
                    } else {
                        pending_tx = Some(Command::Frame(frame));
                    }
                }
                Command::Flush(done) => {
                    if nic.transmit_idle()? {
                        let _ = done.send(());
                        progress = true;
                    } else {
                        pending_tx = Some(Command::Flush(done));
                    }
                }
            }
        } else {
            nic.transmit_idle()?;
        }
        if !progress {
            thread::park_timeout(Duration::from_millis(1));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::{Future, poll_fn};
    use std::task::Poll;

    #[test]
    fn bounded_send_waits_and_cancels_without_queueing() {
        let (tx, mut rx) = mpsc::channel(1);
        let sender = RawSender {
            tx,
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
        tx.try_send(frame.clone()).unwrap();
        drop(tx);
        fictionet::block_on(fictionet::run(
            fictionet::Seed::from_u64(0),
            move |fcx| async move {
                assert_eq!(receiver.recv(&fcx).await?, frame);
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
