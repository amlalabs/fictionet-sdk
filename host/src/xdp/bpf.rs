//! The `bpf(2)` calls: the socket map, the program, and the XDP link.
//!
//! Each object is a file descriptor the kernel opens close-on-exec. Nothing
//! is pinned in bpffs, so every object goes away with the last descriptor:
//! closing the link, or the process dying, takes the program off the
//! interface (`bpf_xdp_link_release` in `net/core/dev.c`).
//!
//! Attribute structs below are the leading fields of `union bpf_attr` that
//! each command reads. The kernel copies the size given and zero-fills the
//! rest of the union.

use std::ffi::CStr;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use super::program::Insn;

const BPF_MAP_CREATE: libc::c_int = 0;
const BPF_MAP_UPDATE_ELEM: libc::c_int = 2;
const BPF_PROG_LOAD: libc::c_int = 5;
const BPF_LINK_CREATE: libc::c_int = 29;
const BPF_MAP_TYPE_XSKMAP: u32 = 17;
const BPF_PROG_TYPE_XDP: u32 = 6;
/// `BPF_XDP` in `enum bpf_attach_type`.
const BPF_XDP: u32 = 37;
/// `XDP_FLAGS_DRV_MODE` from `uapi/linux/if_link.h`: native XDP in the
/// driver, never the generic hook.
const XDP_FLAGS_DRV_MODE: u32 = 1 << 2;
/// `BPF_OBJ_NAME_LEN`.
const NAME_LEN: usize = 16;

#[repr(C)]
struct MapCreate {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    inner_map_fd: u32,
    numa_node: u32,
    map_name: [u8; NAME_LEN],
}

#[repr(C)]
struct MapUpdate {
    map_fd: u32,
    _pad: u32,
    key: u64,
    value: u64,
    flags: u64,
}

#[repr(C)]
struct ProgLoad {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; NAME_LEN],
    prog_ifindex: u32,
    expected_attach_type: u32,
}

#[repr(C)]
struct LinkCreate {
    prog_fd: u32,
    target_ifindex: u32,
    attach_type: u32,
    flags: u32,
}

/// Calls `bpf(cmd, attr, sizeof attr)`.
///
/// # Safety
///
/// `attr` must be the attribute struct `cmd` reads. Every pointer field in
/// it must point to memory valid for the access the command makes (reads
/// of the stated length, or writes for an output buffer) until the call
/// returns.
unsafe fn bpf<T>(cmd: libc::c_int, attr: &mut T) -> io::Result<libc::c_long> {
    // SAFETY: `attr` is a live, exclusive `#[repr(C)]` value of exactly
    // the size passed; the kernel reads at most that many bytes. Pointer
    // fields inside are the caller's contract.
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd,
            attr as *mut T,
            size_of::<T>() as libc::c_uint,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

/// A file descriptor a `bpf(2)` command returned.
fn owned(fd: libc::c_long) -> OwnedFd {
    let fd = libc::c_int::try_from(fd).expect("file descriptors fit in c_int");
    // SAFETY: the kernel returned a fresh descriptor that nothing else owns.
    unsafe { OwnedFd::from_raw_fd(fd) }
}

fn name(name: &str) -> [u8; NAME_LEN] {
    let mut bytes = [0; NAME_LEN];
    assert!(name.len() < NAME_LEN && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
    bytes[..name.len()].copy_from_slice(name.as_bytes());
    bytes
}

/// An XSKMAP: one slot per receive queue, each holding an AF_XDP socket.
pub(crate) struct SocketMap {
    fd: OwnedFd,
}

impl SocketMap {
    /// A map with `queues` slots, all empty.
    pub fn create(queues: u32) -> io::Result<Self> {
        let mut attr = MapCreate {
            map_type: BPF_MAP_TYPE_XSKMAP,
            key_size: 4,
            value_size: 4,
            max_entries: queues,
            map_flags: 0,
            inner_map_fd: 0,
            numa_node: 0,
            map_name: name("fictionet_xsks"),
        };
        // SAFETY: the map-create attributes carry no pointers.
        let fd = unsafe { bpf(BPF_MAP_CREATE, &mut attr)? };
        Ok(Self { fd: owned(fd) })
    }

    /// Puts `socket` in the slot for receive queue `queue`.
    pub fn insert(&self, queue: u32, socket: BorrowedFd<'_>) -> io::Result<()> {
        let key = queue;
        let value: u32 = socket.as_raw_fd() as u32;
        let mut attr = MapUpdate {
            map_fd: self.fd.as_raw_fd() as u32,
            _pad: 0,
            key: &key as *const u32 as u64,
            value: &value as *const u32 as u64,
            flags: 0,
        };
        // SAFETY: `key` and `value` are live 4-byte values, the map's key
        // and value size, which the kernel only reads during the call.
        unsafe { bpf(BPF_MAP_UPDATE_ELEM, &mut attr) }.map(drop)
    }
}

impl AsFd for SocketMap {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

/// A loaded XDP program.
pub(crate) struct Program {
    fd: OwnedFd,
}

/// The verifier refused the program.
#[derive(Debug)]
pub struct Rejected {
    /// The error `BPF_PROG_LOAD` returned.
    pub error: io::Error,
    /// The verifier's log, which says why.
    pub log: String,
}

impl Program {
    /// Loads `insns` as an XDP program for the `BPF_XDP` attach type.
    pub fn load(insns: &[Insn]) -> Result<Self, Rejected> {
        const LICENSE: &CStr = c"MIT OR Apache-2.0";
        let mut log = vec![0u8; 64 * 1024];
        let mut attr = ProgLoad {
            prog_type: BPF_PROG_TYPE_XDP,
            insn_cnt: insns.len() as u32,
            insns: insns.as_ptr() as u64,
            license: LICENSE.as_ptr() as u64,
            log_level: 1,
            log_size: log.len() as u32,
            log_buf: log.as_mut_ptr() as u64,
            kern_version: 0,
            prog_flags: 0,
            prog_name: name("fictionet_xsk"),
            prog_ifindex: 0,
            expected_attach_type: BPF_XDP,
        };
        // SAFETY: `insns` holds `insn_cnt` instructions laid out as
        // `struct bpf_insn`, the license is NUL-terminated, and the log is
        // an exclusive buffer of `log_size` bytes the kernel may write. All
        // three outlive the call.
        match unsafe { bpf(BPF_PROG_LOAD, &mut attr) } {
            Ok(fd) => Ok(Self { fd: owned(fd) }),
            Err(error) => {
                let end = log.iter().position(|&b| b == 0).unwrap_or(log.len());
                Err(Rejected {
                    error,
                    log: String::from_utf8_lossy(&log[..end]).into_owned(),
                })
            }
        }
    }
}

/// The program attached to one interface in native (driver) mode. Dropping
/// it detaches the program.
pub(crate) struct XdpLink {
    _fd: OwnedFd,
}

impl XdpLink {
    /// Attaches `program` to interface `ifindex` in driver mode. Fails with
    /// `EBUSY` when the interface already has a program or link, and with
    /// the driver's error when it refuses XDP; never falls back to generic
    /// XDP.
    pub fn attach_native(program: &Program, ifindex: u32) -> io::Result<Self> {
        let mut attr = LinkCreate {
            prog_fd: program.fd.as_raw_fd() as u32,
            target_ifindex: ifindex,
            attach_type: BPF_XDP,
            flags: XDP_FLAGS_DRV_MODE,
        };
        // SAFETY: the link-create attributes carry no pointers.
        let fd = unsafe { bpf(BPF_LINK_CREATE, &mut attr)? };
        Ok(Self { _fd: owned(fd) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::offset_of;

    #[test]
    fn attribute_layouts_match_union_bpf_attr() {
        // Offsets from the field order and alignment in uapi/linux/bpf.h.
        assert_eq!(offset_of!(MapCreate, map_name), 28);
        assert_eq!(size_of::<MapCreate>(), 44);
        assert_eq!(offset_of!(MapUpdate, key), 8);
        assert_eq!(offset_of!(MapUpdate, value), 16);
        assert_eq!(offset_of!(MapUpdate, flags), 24);
        assert_eq!(offset_of!(ProgLoad, insns), 8);
        assert_eq!(offset_of!(ProgLoad, license), 16);
        assert_eq!(offset_of!(ProgLoad, log_level), 24);
        assert_eq!(offset_of!(ProgLoad, log_buf), 32);
        assert_eq!(offset_of!(ProgLoad, prog_name), 48);
        assert_eq!(offset_of!(ProgLoad, expected_attach_type), 68);
        assert_eq!(offset_of!(LinkCreate, attach_type), 8);
        assert_eq!(offset_of!(LinkCreate, flags), 12);
    }
}
