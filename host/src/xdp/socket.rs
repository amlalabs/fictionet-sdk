//! The AF_XDP socket, its UMEM and ring mappings, and the XDP attachment.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::ptr::NonNull;
use std::time::Duration;

use super::bpf::{Program, SocketMap, XdpLink};
use super::datapath::{Datapath, FRAME_SIZE, RING_SIZE, Rings, UMEM_LEN};
use super::interface::{self, Facts, InterfaceName, MTU};
use super::program;
use super::ring::{Consumer, Desc, Layout, Producer, Slot};
use super::{Attached, OpenError, Stage, XskStatistics};

/// The one receive queue the socket binds, and the map slot it fills.
const QUEUE: u32 = 0;

/// A shared or anonymous memory mapping, unmapped on drop.
struct Mapping {
    base: NonNull<u8>,
    len: usize,
}

// SAFETY: a mapping is plain memory with no thread affinity. Access to its
// contents goes through the ring protocol or the datapath's frame ledger.
unsafe impl Send for Mapping {}

impl Mapping {
    /// Maps `len` bytes of `fd` at page offset `offset`, or anonymous
    /// memory when `fd` is `None`.
    fn new(fd: Option<BorrowedFd<'_>>, len: usize, offset: libc::off_t) -> io::Result<Self> {
        let (flags, raw) = match fd {
            Some(fd) => (libc::MAP_SHARED | libc::MAP_POPULATE, fd.as_raw_fd()),
            None => (
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE,
                -1,
            ),
        };
        // SAFETY: a fresh mapping at an address the kernel picks; it
        // aliases no Rust object. The result is checked before use.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                flags,
                raw,
                offset,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            base: NonNull::new(base.cast()).expect("mmap does not return null on success"),
            len,
        })
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: the region came from mmap with this length and is
        // unmapped once. Every pointer into it (rings, datapath) belongs to
        // a value dropped before this one.
        unsafe { libc::munmap(self.base.as_ptr().cast(), self.len) };
    }
}

/// One interface taken over: native XDP redirecting every frame of its one
/// receive queue to an AF_XDP socket in copy mode.
///
/// Fields drop in order. The datapath goes first, then the link (the
/// program comes off the interface), then the socket (the kernel unbinds
/// it), then the ring and UMEM mappings, which nothing points into by then.
pub struct XdpSocket {
    pub(crate) datapath: Datapath,
    _link: XdpLink,
    socket: OwnedFd,
    _rings: [Mapping; 4],
    _map: SocketMap,
    _program: Program,
    _umem: Mapping,
    attached: Attached,
}

fn setsockopt<T>(socket: &OwnedFd, option: libc::c_int, value: &T) -> io::Result<()> {
    // SAFETY: `value` is a live `T` and the length passed is its size; the
    // kernel only reads it.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_XDP,
            option,
            (value as *const T).cast(),
            size_of::<T>() as libc::socklen_t,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Reads an XDP socket option that must fill all of `T`.
fn getsockopt<T: Copy>(socket: &OwnedFd, option: libc::c_int, empty: T) -> io::Result<T> {
    let mut value = empty;
    let mut len = size_of::<T>() as libc::socklen_t;
    // SAFETY: `value` is a live, exclusive `T` and `len` its size; the
    // kernel writes at most `len` bytes and reports how many.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_XDP,
            option,
            (&mut value as *mut T).cast(),
            &mut len,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != size_of::<T>() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "XDP socket option {option} returned {len} bytes, not {}",
                size_of::<T>()
            ),
        ));
    }
    Ok(value)
}

fn layout<T: Slot>(offset: &libc::xdp_ring_offset) -> Layout {
    Layout {
        producer: offset.producer as usize,
        consumer: offset.consumer as usize,
        flags: offset.flags as usize,
        desc: offset.desc as usize,
        size: RING_SIZE,
    }
}

fn step<T>(stage: Stage, result: io::Result<T>) -> Result<T, OpenError> {
    result.map_err(|source| OpenError::Io { stage, source })
}

impl XdpSocket {
    /// Checks `name`, sets its MTU to 1500 and its channels to one, and
    /// attaches the program and socket. Refuses before changing anything
    /// if the interface looks like the management path.
    pub fn open(name: &InterfaceName) -> Result<Self, OpenError> {
        let facts = step(Stage::ReadInterface, interface::read(name))?;
        let refusals = interface::management_refusals(&facts);
        if !refusals.is_empty() {
            return Err(OpenError::Refused(refusals));
        }
        if facts.mtu != MTU {
            step(Stage::SetMtu, interface::set_mtu(name, MTU))?;
        }
        if facts.channels.combined != 1 {
            step(
                Stage::SetChannels,
                interface::set_combined_channels(name, 1),
            )?;
        }
        let facts = step(Stage::ReadInterface, interface::read(name))?;
        let mut refusals = interface::management_refusals(&facts);
        refusals.extend(interface::fit_refusals(&facts));
        if !refusals.is_empty() {
            return Err(OpenError::Refused(refusals));
        }
        Self::attach(facts)
    }

    fn attach(facts: Facts) -> Result<Self, OpenError> {
        let umem = step(Stage::Umem, Mapping::new(None, UMEM_LEN, 0))?;
        // SAFETY: socket takes only scalars.
        let fd = unsafe { libc::socket(libc::AF_XDP, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(OpenError::Io {
                stage: Stage::Socket,
                source: io::Error::last_os_error(),
            });
        }
        // SAFETY: socket returned a fresh descriptor nothing else owns.
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };

        let registration = libc::xdp_umem_reg {
            addr: umem.base.as_ptr() as u64,
            len: UMEM_LEN as u64,
            chunk_size: FRAME_SIZE,
            headroom: 0,
            flags: 0,
            tx_metadata_len: 0,
        };
        step(
            Stage::Umem,
            setsockopt(&socket, libc::XDP_UMEM_REG, &registration),
        )?;
        for option in [
            libc::XDP_UMEM_FILL_RING,
            libc::XDP_UMEM_COMPLETION_RING,
            libc::XDP_RX_RING,
            libc::XDP_TX_RING,
        ] {
            step(Stage::Rings, setsockopt(&socket, option, &RING_SIZE))?;
        }
        let empty = libc::xdp_ring_offset {
            producer: 0,
            consumer: 0,
            desc: 0,
            flags: 0,
        };
        let offsets = step(
            Stage::Rings,
            getsockopt(
                &socket,
                libc::XDP_MMAP_OFFSETS,
                libc::xdp_mmap_offsets {
                    rx: empty,
                    tx: empty,
                    fr: empty,
                    cr: empty,
                },
            ),
        )?;
        let (fill, completion, rx, tx) = (
            layout::<u64>(&offsets.fr),
            layout::<u64>(&offsets.cr),
            layout::<Desc>(&offsets.rx),
            layout::<Desc>(&offsets.tx),
        );
        let map = |layout: Layout, len: usize, offset: u64| {
            step(
                Stage::Rings,
                Mapping::new(Some(socket.as_fd()), len, offset as libc::off_t),
            )
            .map(|mapping| (mapping, layout))
        };
        let (fill_map, fill) = map(fill, fill.len::<u64>(), libc::XDP_UMEM_PGOFF_FILL_RING)?;
        let (completion_map, completion) = map(
            completion,
            completion.len::<u64>(),
            libc::XDP_UMEM_PGOFF_COMPLETION_RING,
        )?;
        let (rx_map, rx) = map(rx, rx.len::<Desc>(), libc::XDP_PGOFF_RX_RING as u64)?;
        let (tx_map, tx) = map(tx, tx.len::<Desc>(), libc::XDP_PGOFF_TX_RING as u64)?;
        // SAFETY: each mapping is the kernel's ring of the layout it
        // reported, mapped for exactly `len` bytes, and lives in `XdpSocket`
        // after the datapath. The process is the only producer of the fill
        // and TX rings and the only consumer of the RX and completion rings.
        let rings = unsafe {
            Rings {
                fill: Producer::new(fill_map.base, fill),
                completion: Consumer::new(completion_map.base, completion),
                rx: Consumer::new(rx_map.base, rx),
                tx: Producer::new(tx_map.base, tx),
            }
        };
        // SAFETY: the UMEM mapping is UMEM_LEN bytes, registered with this
        // socket only, and dropped after the datapath.
        let datapath = unsafe { Datapath::new(rings, umem.base) };

        let address = libc::sockaddr_xdp {
            sxdp_family: libc::AF_XDP as u16,
            sxdp_flags: libc::XDP_COPY | libc::XDP_USE_NEED_WAKEUP,
            sxdp_ifindex: facts.ifindex,
            sxdp_queue_id: QUEUE,
            sxdp_shared_umem_fd: 0,
        };
        // SAFETY: `address` is a complete sockaddr_xdp and the length is
        // its size; bind only reads it.
        let bound = unsafe {
            libc::bind(
                socket.as_raw_fd(),
                (&address as *const libc::sockaddr_xdp).cast(),
                size_of::<libc::sockaddr_xdp>() as libc::socklen_t,
            )
        };
        if bound < 0 {
            return Err(OpenError::Io {
                stage: Stage::Bind,
                source: io::Error::last_os_error(),
            });
        }
        let options = step(
            Stage::Bind,
            getsockopt(&socket, libc::XDP_OPTIONS, libc::xdp_options { flags: 0 }),
        )?;
        if options.flags & libc::XDP_OPTIONS_ZEROCOPY != 0 {
            return Err(OpenError::Io {
                stage: Stage::Bind,
                source: io::Error::other("the socket bound in zero-copy mode, not copy mode"),
            });
        }

        let socket_map = step(Stage::Map, SocketMap::create(1))?;
        step(Stage::Map, socket_map.insert(QUEUE, socket.as_fd()))?;
        let program = Program::load(&program::redirect_to_sockets(socket_map.as_fd()))
            .map_err(OpenError::Rejected)?;
        // Last: frames reach the program only once the socket is in its slot.
        let link = XdpLink::attach_native(&program, facts.ifindex).map_err(|source| {
            if source.raw_os_error() == Some(libc::EBUSY) {
                OpenError::Occupied
            } else {
                OpenError::Io {
                    stage: Stage::Attach,
                    source,
                }
            }
        })?;
        let attached = Attached {
            interface: facts.name,
            ifindex: facts.ifindex,
            mac: facts.mac,
            driver: facts.driver,
            mtu: facts.mtu,
            queue: QUEUE,
            channels: facts.channels,
        };
        Ok(Self {
            datapath,
            _link: link,
            socket,
            _rings: [fill_map, completion_map, rx_map, tx_map],
            _map: socket_map,
            _program: program,
            _umem: umem,
            attached,
        })
    }

    /// What was attached, for the startup record.
    pub fn attached(&self) -> &Attached {
        &self.attached
    }

    /// Asks the kernel to send the TX ring. In copy mode this runs the
    /// transmit path in the calling thread. A busy device or a full
    /// completion ring is not an error: the frames stay posted and the next
    /// kick sends them.
    pub(crate) fn kick(&self) -> io::Result<()> {
        // SAFETY: a zero-length sendto with no buffer and no address; the
        // kernel reads nothing from user memory.
        let result = unsafe {
            libc::sendto(
                self.socket.as_raw_fd(),
                std::ptr::null(),
                0,
                libc::MSG_DONTWAIT,
                std::ptr::null(),
                0,
            )
        };
        if result >= 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EAGAIN | libc::EBUSY | libc::ENOBUFS | libc::ENETDOWN) => Ok(()),
            _ => Err(error),
        }
    }

    /// Waits until the RX ring has frames, `wake` is readable, or `timeout`
    /// passes.
    pub(crate) fn wait(&self, wake: BorrowedFd<'_>, timeout: Duration) -> io::Result<()> {
        let mut fds = [
            libc::pollfd {
                fd: self.socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: wake.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let millis = timeout.as_millis().min(i32::MAX as u128) as libc::c_int;
        // SAFETY: `fds` is a live array whose length is passed; the kernel
        // writes only the `revents` fields.
        let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, millis) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        if fds[0].revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err(io::Error::other("the AF_XDP socket reported an error"));
        }
        Ok(())
    }

    /// The socket's loss counters (`XDP_STATISTICS`).
    pub(crate) fn statistics(&self) -> io::Result<XskStatistics> {
        let stats = getsockopt(
            &self.socket,
            libc::XDP_STATISTICS,
            libc::xdp_statistics {
                rx_dropped: 0,
                rx_invalid_descs: 0,
                tx_invalid_descs: 0,
                rx_ring_full: 0,
                rx_fill_ring_empty_descs: 0,
                tx_ring_empty_descs: 0,
            },
        )?;
        Ok(XskStatistics {
            rx_dropped: stats.rx_dropped,
            rx_ring_full: stats.rx_ring_full,
            rx_fill_ring_empty: stats.rx_fill_ring_empty_descs,
            rx_invalid: stats.rx_invalid_descs,
            tx_invalid: stats.tx_invalid_descs,
        })
    }
}
