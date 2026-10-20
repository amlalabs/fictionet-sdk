//! A vhost-user-net backend in our process, so Cloud Hypervisor's guest
//! gets its network card from us with no tap device and no privilege beyond
//! `/dev/kvm`.
//!
//! The backend is a dumb frame transport between the guest's virtio-net
//! queues and the world's Ethernet bridge:
//!
//! - TX (guest to host): each packet is a 12-byte virtio-net header and an
//!   Ethernet frame; the header is dropped and the frame is handed to the
//!   world task over a channel.
//! - RX (host to guest): the world task leaves a frame in a shared queue and
//!   wakes the backend through an eventfd; the backend prepends a zero
//!   header and writes it into a guest receive buffer.
//!
//! The world task ([`crate::kit::bridge`]) owns the Ethernet lowering; this is
//! only the virtqueue plumbing.

use std::collections::VecDeque;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;

use tokio::sync::mpsc::Sender;
use vhost::vhost_user::message::VhostUserProtocolFeatures;
use vhost_user_backend::{VhostUserBackendMut, VhostUserDaemon, VringRwLock, VringT};
use virtio_queue::QueueT;
use vm_memory::{Bytes, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::{EFD_NONBLOCK, EventFd};

/// The guest's virtio-net header is 12 bytes under VIRTIO_F_VERSION_1.
const VNET_HDR: usize = 12;
const MAX_FRAME: usize = super::MTU as usize + 14;
pub(crate) const QUEUE_LIMIT: usize = 256;

const RX_QUEUE: u16 = 0;
const TX_QUEUE: u16 = 1;
/// The custom epoll token the world task wakes the backend with. The range
/// 0..=num_queues (here 0, 1 and the exit event 2) is reserved, so this is
/// the first free token.
const RX_NOTIFY: u16 = 3;

// Virtio feature bits.
const VIRTIO_F_VERSION_1: u64 = 1 << 32;
/// Enables the vhost-user protocol features (SET_VRING_ENABLE, GET_CONFIG).
/// Without it Cloud Hypervisor's SET_VRING_ENABLE fails as an inactive
/// feature and the net device never activates.
const VHOST_USER_F_PROTOCOL_FEATURES: u64 = 1 << 30;

type Mem = GuestMemoryAtomic<GuestMemoryMmap>;

/// Frames the world leaves for the guest, and the eventfd that wakes the
/// backend to deliver them.
#[derive(Clone)]
pub struct RxQueue {
    frames: Arc<Mutex<VecDeque<Vec<u8>>>>,
    notify: Arc<EventFd>,
}

impl RxQueue {
    /// Creates an empty receive queue and its notification event.
    pub fn new() -> std::io::Result<RxQueue> {
        Ok(RxQueue {
            frames: Arc::new(Mutex::new(VecDeque::new())),
            notify: Arc::new(EventFd::new(EFD_NONBLOCK)?),
        })
    }

    /// Hands a frame to the guest and wakes the backend.
    pub fn push(&self, frame: Vec<u8>) {
        let mut frames = self.frames.lock().unwrap();
        if frame.len() > MAX_FRAME || frames.len() >= QUEUE_LIMIT {
            return;
        }
        frames.push_back(frame);
        drop(frames);
        let _ = self.notify.write(1);
    }
}

struct NetBackend {
    mem: Option<Mem>,
    mac: [u8; 6],
    to_world: Sender<Vec<u8>>,
    rx: RxQueue,
    exit: EventFd,
}

impl VhostUserBackendMut for NetBackend {
    type Bitmap = ();
    type Vring = VringRwLock;

    fn num_queues(&self) -> usize {
        2
    }

    fn max_queue_size(&self) -> usize {
        256
    }

    fn features(&self) -> u64 {
        // No VIRTIO_NET_F_MAC: the guest picks its own MAC and the world
        // learns it from the first frame, so Cloud Hypervisor never reads
        // config over vhost-user. VHOST_USER_F_PROTOCOL_FEATURES is required
        // for SET_VRING_ENABLE.
        VIRTIO_F_VERSION_1 | VHOST_USER_F_PROTOCOL_FEATURES
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::empty()
    }

    // The features above leave out VIRTIO_RING_F_EVENT_IDX, so it stays off.
    fn set_event_idx(&mut self, _: bool) {}

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        // The virtio-net config starts with the 6-byte MAC.
        let mut config = self.mac.to_vec();
        config.resize(12, 0);
        let (start, end) = (offset as usize, offset.saturating_add(size) as usize);
        config
            .get(start..end.min(config.len()))
            .unwrap_or(&[])
            .to_vec()
    }

    fn update_memory(&mut self, mem: Mem) -> std::io::Result<()> {
        self.mem = Some(mem);
        Ok(())
    }

    fn exit_event(&self, _thread: usize) -> Option<EventFd> {
        self.exit.try_clone().ok()
    }

    fn handle_event(
        &mut self,
        device_event: u16,
        _evset: EventSet,
        vrings: &[VringRwLock],
        _thread: usize,
    ) -> std::io::Result<()> {
        match device_event {
            TX_QUEUE => self.process_tx(&vrings[TX_QUEUE as usize]),
            RX_QUEUE => self.process_rx(&vrings[RX_QUEUE as usize]),
            RX_NOTIFY => {
                // Drain the wakeups, then deliver whatever is queued.
                while self.rx.notify.read().is_ok() {}
                self.process_rx(&vrings[RX_QUEUE as usize]);
            }
            _ => {}
        }
        Ok(())
    }
}

impl NetBackend {
    /// Moves every frame the guest queued on TX to the world.
    fn process_tx(&mut self, vring: &VringRwLock) {
        let Some(atomic) = self.mem.as_ref() else {
            return;
        };
        let mem = atomic.memory();
        let mut used = false;
        {
            let mut state = vring.get_mut();
            let queue = state.get_queue_mut();
            // Drain, then re-enable kicks; loop if the guest queued more while
            // notifications were off, so the guest keeps kicking us.
            loop {
                let _ = queue.disable_notification(&*mem);
                while let Some(chain) = queue.pop_descriptor_chain(mem.clone()) {
                    let head = chain.head_index();
                    let mut frame = Vec::new();
                    let mut valid = true;
                    for desc in chain {
                        let len = desc.len() as usize;
                        if desc.is_write_only() || len > MAX_FRAME + VNET_HDR - frame.len() {
                            valid = false;
                            break;
                        }
                        let start = frame.len();
                        frame.resize(start + len, 0);
                        if mem.read_slice(&mut frame[start..], desc.addr()).is_err() {
                            valid = false;
                            break;
                        }
                    }
                    if valid && frame.len() > VNET_HDR {
                        let _ = self.to_world.try_send(frame.split_off(VNET_HDR));
                    }
                    let _ = queue.add_used(&*mem, head, 0);
                    used = true;
                }
                if !queue.enable_notification(&*mem).unwrap_or(false) {
                    break;
                }
            }
        }
        if used {
            let _ = vring.signal_used_queue();
        }
    }

    /// Delivers queued world frames into the guest's receive buffers.
    fn process_rx(&mut self, vring: &VringRwLock) {
        let Some(atomic) = self.mem.as_ref() else {
            return;
        };
        let mem = atomic.memory();
        let mut used = false;
        {
            // The guard holds the vring lock, so it must be dropped before
            // signal_used_queue, which locks the vring again.
            let mut state = vring.get_mut();
            let queue = state.get_queue_mut();
            loop {
                // Only take a frame once a receive buffer is available.
                if self.rx.frames.lock().unwrap().is_empty() {
                    break;
                }
                let Some(chain) = queue.pop_descriptor_chain(mem.clone()) else {
                    break;
                };
                let Some(eth) = self.rx.frames.lock().unwrap().pop_front() else {
                    break;
                };
                let head = chain.head_index();
                // A zero virtio-net header with one buffer, then the frame.
                let mut payload = vec![0u8; VNET_HDR];
                payload[10] = 1;
                payload.extend_from_slice(&eth);
                let mut off = 0;
                for desc in chain {
                    if !desc.is_write_only() || off >= payload.len() {
                        continue;
                    }
                    let n = (desc.len() as usize).min(payload.len() - off);
                    if mem.write_slice(&payload[off..off + n], desc.addr()).is_ok() {
                        off += n;
                    }
                }
                let _ = queue.add_used(&*mem, head, off as u32);
                used = true;
            }
        }
        if used {
            let _ = vring.signal_used_queue();
        }
    }
}

/// Starts the backend: it listens on `socket` for Cloud Hypervisor, bridges
/// the guest's net queues to `to_world`/`rx`, and runs until the VM goes.
pub fn start(
    socket: &Path,
    mac: [u8; 6],
    to_world: Sender<Vec<u8>>,
    rx: RxQueue,
) -> std::io::Result<Backend> {
    let mem: Mem = GuestMemoryAtomic::new(GuestMemoryMmap::new());
    let exit = EventFd::new(EFD_NONBLOCK)?;
    let stop = exit.try_clone()?;
    let backend = Arc::new(RwLock::new(NetBackend {
        mem: None,
        mac,
        to_world,
        rx: rx.clone(),
        exit,
    }));
    let mut daemon = VhostUserDaemon::new("fictionet-net".to_string(), backend, mem)
        .map_err(|e| std::io::Error::other(format!("vhost-user daemon: {e}")))?;
    // Wake the backend from the world task through the extra eventfd.
    for handler in daemon.get_epoll_handlers() {
        handler
            .register_listener(rx.notify.as_raw_fd(), EventSet::IN, RX_NOTIFY as u64)
            .map_err(|e| std::io::Error::other(format!("register rx listener: {e}")))?;
    }
    let listener = vhost::vhost_user::Listener::new(socket, true).map_err(std::io::Error::other)?;
    let socket = socket.to_path_buf();
    let thread = thread::Builder::new()
        .name("fictionet-net".to_string())
        .spawn(move || {
            let result = daemon.start(listener).and_then(|()| daemon.wait());
            match result {
                Ok(())
                | Err(vhost_user_backend::Error::HandleRequest(
                    vhost::vhost_user::Error::Disconnected
                    | vhost::vhost_user::Error::PartialMessage,
                )) => {}
                Err(error) => eprintln!("vhost-user-net backend stopped: {error}"),
            }
        })?;
    Ok(Backend {
        socket,
        thread: Some(thread),
        stop,
    })
}

/// Owns the listener and joins its worker when the VM disconnects.
pub struct Backend {
    socket: std::path::PathBuf,
    thread: Option<thread::JoinHandle<()>>,
    stop: EventFd,
}

impl Drop for Backend {
    fn drop(&mut self) {
        // Wake accept when boot failed before the VMM connected.
        let _ = std::os::unix::net::UnixStream::connect(&self.socket);
        let _ = self.stop.write(1);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transmit_rejects_oversized_chains_and_bounds_pending_frames() {
        use vm_memory::GuestAddress;
        for lengths in [vec![u32::MAX], vec![1000, 1000], vec![64]] {
            let mem = GuestMemoryAtomic::new(
                GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
            );
            let vring = VringRwLock::new(mem.clone(), 256).unwrap();
            vring.set_queue_info(0x1000, 0x2000, 0x3000).unwrap();
            vring.set_queue_size(256);
            vring.set_queue_ready(true);
            let (tx, mut rx) = tokio::sync::mpsc::channel(1);
            let mut backend = NetBackend {
                mem: Some(mem.clone()),
                mac: [0; 6],
                to_world: tx,
                rx: RxQueue::new().unwrap(),
                exit: EventFd::new(EFD_NONBLOCK).unwrap(),
            };
            for (index, len) in lengths.iter().enumerate() {
                let mut desc = Vec::new();
                desc.extend_from_slice(&0x4000u64.to_le_bytes());
                desc.extend_from_slice(&len.to_le_bytes());
                desc.extend_from_slice(&u16::from(index + 1 < lengths.len()).to_le_bytes());
                desc.extend_from_slice(&((index + 1) as u16).to_le_bytes());
                mem.memory()
                    .write_slice(&desc, GuestAddress(0x1000 + index as u64 * 16))
                    .unwrap();
            }
            mem.memory().write_obj(1u16, GuestAddress(0x2002)).unwrap();
            backend.process_tx(&vring);
            if lengths == [64] {
                assert_eq!(rx.len(), 1);
                mem.memory().write_obj(2u16, GuestAddress(0x2002)).unwrap();
                backend.process_tx(&vring);
                assert_eq!(rx.len(), 1);
                assert_eq!(rx.try_recv().unwrap().len(), 64 - VNET_HDR);
            } else {
                assert!(rx.try_recv().is_err());
            }
            assert_eq!(
                vring.queue_next_avail(),
                if lengths == [64] { 2 } else { 1 }
            );
        }
    }

    #[test]
    fn receive_queue_bounds_packets_and_bytes() {
        let rx = RxQueue::new().unwrap();
        rx.push(vec![0; MAX_FRAME + 1]);
        assert!(rx.frames.lock().unwrap().is_empty());
        for _ in 0..QUEUE_LIMIT + 1 {
            rx.push(vec![0; MAX_FRAME]);
        }
        assert_eq!(rx.frames.lock().unwrap().len(), QUEUE_LIMIT);
    }
}
