//! `fictionet attach --type tap`: a virtual machine's network card.
//!
//! The VM's Ethernet frames reach attach in one of two ways:
//!
//! - `--vm qemu:<path>`: QEMU's `-netdev stream` sends them over a Unix
//!   stream socket that attach listens on. No TAP device and no privileges
//!   are needed.
//! - `--vm tap:<name>`: the VM program (Firecracker, Cloud Hypervisor, or
//!   QEMU with `-netdev tap`) holds the TAP device `<name>`. A TAP device
//!   has only one file side, so attach makes a second one and has the
//!   kernel redirect every frame between the two with traffic control.
//!
//! Either way, attach answers the link-local questions itself (ARP, IPv6
//! neighbor discovery, and DHCP when the address flags are given), strips
//! the Ethernet header from the VM's IP packets on their way to the world,
//! and adds one to the world's packets on their way back.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

use fictionet::relay::{self, unix};

use crate::config::{TapArgs, VmLink};
use crate::lifecycle;
use crate::linux;
use crate::world::{self, Failure, Greeting, err};

mod device;
mod qemu;

use device::run_device;
use fictionet::stdlib::network::ethernet::stream::{self, Decoder, Outbox};
use fictionet::stdlib::network::ethernet::{FromVm, Link, RA_EVERY, Why};
use qemu::{flush, run_qemu};

/// Runs attach to the end. `Ok` means the VM's side or the world closed
/// its connection.
pub(crate) fn run(args: TapArgs) -> Result<(), Failure> {
    let mut lock = None;
    let result = match &args.vm {
        VmLink::Qemu(path) => run_qemu(&args, path, &mut lock),
        VmLink::Tap(name) => run_device(&args, name, &mut lock),
    };
    // The ready file is this attach's only once it holds the lock: an
    // attach that failed to take it leaves the running one's file alone.
    if lock.is_some()
        && let Some(path) = &args.ready_file
    {
        let _ = std::fs::remove_file(path);
    }
    // The lock is held until the process exits, which releases it. Until
    // then a new attach cannot start, so neither this cleanup nor the
    // signal handler can touch a new attach's ready file or redirect.
    std::mem::forget(lock);
    match result? {
        End::Qemu => eprintln!(
            "fictionet attach: QEMU closed the connection; {} detached",
            args.name
        ),
        End::DeviceGone(name) => eprintln!(
            "fictionet attach: {name} was removed; {} detached",
            args.name
        ),
        End::World => eprintln!("fictionet attach: the world closed the connection"),
    }
    Ok(())
}

fn greeting<'a>(args: &'a TapArgs) -> Greeting<'a> {
    Greeting {
        world: &args.world,
        world_wait: args.world_wait,
        kind: "tap",
        name: &args.name,
        mtu: args.mtu,
    }
}

/// Marks this attach as the owner of its VM link: from here on, the ready
/// file is this attach's to clear, write and remove, on exit and on a
/// signal.
fn take_ready_file(args: &TapArgs, lock: &mut Option<OwnedFd>, held: OwnedFd) {
    *lock = Some(held);
    lifecycle::clear_ready_file(args.ready_file.as_deref());
    if let Some(path) = &args.ready_file {
        lifecycle::remove_ready_on_signal(path);
    }
}

fn relay_and_report(args: &TapArgs, port: &mut Port, world: RawFd) -> Result<End, Failure> {
    let mut link = Link::new(args.v4.clone(), args.v6.clone(), args.mtu);
    let (end, stats) = relay(&mut link, port, world)?;
    stats.report();
    Ok(end)
}

/// Which side ended the relay.
enum End {
    /// QEMU closed its socket.
    Qemu,
    /// The VM's TAP device was removed.
    DeviceGone(String),
    /// The world closed its connection.
    World,
}

/// Counts of what the relay dropped.
#[derive(Default)]
struct Stats {
    /// Frames from the VM, by reason (handled link-local frames are not
    /// counted).
    from_vm: Vec<(Why, u64)>,
    /// Packets for the world that did not fit its connection's buffer.
    to_world_full: u64,
    /// Packets from the world rejected by Link::to_vm.
    from_world_bad: u64,
    /// Frames for the VM that did not fit the queue to QEMU.
    to_vm_full: u64,
}

impl Stats {
    fn drop_from_vm(&mut self, why: Why) {
        if why == Why::Handled {
            return;
        }
        match self.from_vm.iter_mut().find(|(w, _)| *w == why) {
            Some((_, n)) => *n += 1,
            None => self.from_vm.push((why, 1)),
        }
    }

    fn report(&self) {
        for (why, n) in &self.from_vm {
            let what = match why {
                Why::Malformed => "malformed",
                Why::TooBig => "over the MTU",
                Why::OtherSource => "from another MAC",
                Why::NotForUs => "for another MAC",
                Why::OtherType => "not ARP, IPv4 or IPv6",
                Why::Spoofed => "from an address attach did not hand out",
                Why::Handled => continue,
            };
            eprintln!("fictionet attach: {n} frames from the VM dropped: {what}");
        }
        if self.to_world_full > 0 {
            eprintln!(
                "fictionet attach: {} packets to the world dropped on a full buffer",
                self.to_world_full
            );
        }
        if self.to_vm_full > 0 {
            eprintln!(
                "fictionet attach: {} frames to the VM dropped on a full queue",
                self.to_vm_full
            );
        }
        if self.from_world_bad > 0 {
            eprintln!(
                "fictionet attach: {} packets from the world dropped: not IP, over the MTU, or unicast before the VM's MAC is known",
                self.from_world_bad
            );
        }
    }
}

/// At most this many messages move one way before the other way gets a
/// turn.
const BATCH: usize = 64;

/// How much may wait to be written to QEMU. A burst from the world past
/// this is dropped, as a full network card queue would drop it.
const OUTBOX: usize = 4 << 20;

/// The VM's end of the relay.
enum Port {
    /// QEMU's stream socket: frames with a length prefix, written through a
    /// queue because one frame may go out in pieces.
    Stream {
        fd: OwnedFd,
        decoder: Decoder,
        outbox: Outbox,
    },
    /// Attach's TAP device: one frame per read and per write.
    Device {
        fd: OwnedFd,
        buf: Vec<u8>,
        /// The VM's device, checked every second: when it goes, so does
        /// the VM.
        name: String,
        index: u32,
    },
}

impl Port {
    fn fd(&self) -> RawFd {
        match self {
            Port::Stream { fd, .. } | Port::Device { fd, .. } => fd.as_raw_fd(),
        }
    }

    /// Sends one frame made of `parts` to the VM. `Ok(false)` if it was
    /// dropped on a full queue.
    fn send(&mut self, parts: &[&[u8]]) -> Result<bool, Failure> {
        match self {
            Port::Stream { outbox, .. } => Ok(outbox.push(parts)),
            Port::Device { fd, .. } => {
                let mut stack = [libc::iovec {
                    iov_base: std::ptr::null_mut(),
                    iov_len: 0,
                }; 2];
                let heap: Vec<libc::iovec>;
                let iov: &[libc::iovec] = if parts.len() <= stack.len() {
                    for (v, p) in stack.iter_mut().zip(parts) {
                        *v = libc::iovec {
                            iov_base: p.as_ptr() as *mut _,
                            iov_len: p.len(),
                        };
                    }
                    &stack[..parts.len()]
                } else {
                    heap = parts
                        .iter()
                        .map(|p| libc::iovec {
                            iov_base: p.as_ptr() as *mut _,
                            iov_len: p.len(),
                        })
                        .collect();
                    &heap
                };
                // SAFETY: the iovecs point into `parts`, valid for the call.
                let n =
                    unsafe { libc::writev(fd.as_raw_fd(), iov.as_ptr(), iov.len() as libc::c_int) };
                if n >= 0 {
                    return Ok(true);
                }
                let e = io::Error::last_os_error();
                match e.raw_os_error() {
                    Some(libc::EAGAIN | libc::ENOBUFS | libc::EINTR) => Ok(false),
                    // The kernel refused this one frame.
                    Some(libc::EINVAL | libc::EMSGSIZE) => Ok(false),
                    _ => Err(err("writing to attach's TAP device")(e)),
                }
            }
        }
    }
}

/// How often attach checks that the VM's TAP device is still there.
const DEVICE_CHECK: Duration = Duration::from_secs(1);

/// Moves frames and packets both ways until the VM's side or the world
/// closes its connection.
fn relay(link: &mut Link, port: &mut Port, world: RawFd) -> Result<(End, Stats), Failure> {
    let mut stats = Stats::default();
    let mut from_world = vec![0u8; relay::MAX_MESSAGE + 1];
    let mut learned = false;
    // A first advertisement right away: a VM that kept running while attach
    // restarted asks for none.
    let mut next_ra = Instant::now();
    let mut next_check = Instant::now() + DEVICE_CHECK;
    let vm = port.fd();
    loop {
        let now = Instant::now();
        if now >= next_ra
            && let Some(ra) = link.router_advert()
        {
            if !port.send(&[&ra])? {
                stats.to_vm_full += 1;
            }
            next_ra = now + RA_EVERY;
        }
        if let Port::Device { name, index, .. } = port
            && now >= next_check
        {
            if linux::index_of(name).ok() != Some(*index) {
                return Ok((End::DeviceGone(name.clone()), stats));
            }
            next_check = now + DEVICE_CHECK;
        }
        if let Port::Stream { outbox, .. } = port
            && !outbox.is_empty()
            && !flush(vm, outbox)?
        {
            return Ok((End::Qemu, stats));
        }

        let mut wake: Option<Instant> = None;
        if link.advertises() {
            wake = Some(next_ra);
        }
        if matches!(port, Port::Device { .. }) {
            wake = Some(wake.map_or(next_check, |w| w.min(next_check)));
        }
        let timeout = match wake {
            Some(at) => at
                .saturating_duration_since(Instant::now())
                .as_millis()
                .min(i32::MAX as u128) as i32,
            None => -1,
        };
        let vm_events = match port {
            Port::Stream { outbox, .. } if !outbox.is_empty() => libc::POLLIN | libc::POLLOUT,
            _ => libc::POLLIN,
        };
        let mut fds = [
            libc::pollfd {
                fd: vm,
                events: vm_events,
                revents: 0,
            },
            libc::pollfd {
                fd: world,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: `fds` is valid for the call.
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout) } < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Failure::Error(format!("poll: {e}")));
        }

        if fds[1].revents != 0
            && !world::read_packets(world, &mut from_world, Some(BATCH), |p| {
                match link.to_vm(p) {
                    Some(h) => {
                        if !port.send(&[&h, p])? {
                            stats.to_vm_full += 1;
                        }
                    }
                    None => stats.from_world_bad += 1,
                }
                Ok(())
            })?
        {
            return Ok((End::World, stats));
        }

        if fds[0].revents & (libc::POLLERR | libc::POLLNVAL) != 0
            && matches!(port, Port::Device { .. })
        {
            return Err(Failure::Error("attach's TAP device failed".into()));
        }
        if fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            // Answers wait here until the batch is read; past OUTBOX bytes,
            // more are dropped, as the queue to the VM would drop them.
            let mut answers: Vec<Vec<u8>> = Vec::new();
            let mut answer_bytes = 0;
            for _ in 0..BATCH {
                let mut handle = |frame: &[u8],
                                  stats: &mut Stats|
                 -> Result<Option<End>, Failure> {
                    match link.frame_from_vm(frame) {
                        FromVm::World(p) => {
                            match unix::send_parts(world, &[&[relay::PACKET], p], true) {
                                Ok(()) => {}
                                Err(e)
                                    if e.kind() == io::ErrorKind::WouldBlock
                                        || e.raw_os_error() == Some(libc::ENOBUFS) =>
                                {
                                    stats.to_world_full += 1;
                                }
                                Err(e)
                                    if matches!(
                                        e.kind(),
                                        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                                    ) =>
                                {
                                    return Ok(Some(End::World));
                                }
                                Err(e) => {
                                    return Err(Failure::Error(format!(
                                        "sending to the world: {e}"
                                    )));
                                }
                            }
                        }
                        FromVm::Answer(f) => {
                            if answer_bytes + f.len() > OUTBOX {
                                stats.to_vm_full += 1;
                            } else {
                                answer_bytes += f.len();
                                answers.push(f);
                            }
                        }
                        FromVm::Drop(why) => stats.drop_from_vm(why),
                    }
                    Ok(None)
                };
                match port {
                    Port::Stream { fd, decoder, .. } => {
                        let spare = decoder.spare();
                        // SAFETY: `spare` is valid for writes of its length.
                        let n = unsafe {
                            libc::read(fd.as_raw_fd(), spare.as_mut_ptr().cast(), spare.len())
                        };
                        if n < 0 {
                            let e = io::Error::last_os_error();
                            match e.kind() {
                                io::ErrorKind::WouldBlock => break,
                                io::ErrorKind::Interrupted => continue,
                                io::ErrorKind::ConnectionReset => return Ok((End::Qemu, stats)),
                                _ => {
                                    return Err(Failure::Error(format!(
                                        "reading QEMU's socket: {e}"
                                    )));
                                }
                            }
                        }
                        if n == 0 {
                            return Ok((End::Qemu, stats));
                        }
                        decoder.filled(n as usize);
                        loop {
                            let frame = match decoder.next_frame() {
                                Ok(Some(f)) => f,
                                Ok(None) => break,
                                Err(stream::TooLong(len)) => {
                                    return Err(Failure::Error(format!(
                                        "QEMU's socket sent a frame length of {len} bytes; is it a -netdev stream socket?"
                                    )));
                                }
                            };
                            if let Some(end) = handle(frame, &mut stats)? {
                                return Ok((end, stats));
                            }
                        }
                    }
                    Port::Device { fd, buf, .. } => {
                        // SAFETY: `buf` is valid for writes of its length.
                        let n = unsafe {
                            libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len())
                        };
                        if n < 0 {
                            let e = io::Error::last_os_error();
                            match e.kind() {
                                io::ErrorKind::WouldBlock => break,
                                io::ErrorKind::Interrupted => continue,
                                _ => {
                                    return Err(Failure::Error(format!(
                                        "reading attach's TAP device: {e}"
                                    )));
                                }
                            }
                        }
                        if let Some(end) = handle(&buf[..n as usize], &mut stats)? {
                            return Ok((end, stats));
                        }
                    }
                }
            }
            for f in answers {
                if !port.send(&[&f])? {
                    stats.to_vm_full += 1;
                }
            }
            if !learned && let Some(mac) = link.vm_mac() {
                learned = true;
                let m = mac
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(":");
                eprintln!("fictionet attach: the VM's MAC is {m}");
            }
        }
    }
}
