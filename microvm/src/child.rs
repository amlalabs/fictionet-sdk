//! The VM child: the program started again by [`Vm::start`](crate::Vm::start)
//! with [`ARG`] first. It reads its configuration from its arguments and
//! its links from descriptors 3 to 5, puts the kernel in memory of its own,
//! builds the VM and enters it. The VMM exits the process when the guest
//! powers off.

use std::alloc::Layout;
use std::ffi::OsString;
use std::io;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::raw::c_char;
use std::path::PathBuf;
use std::sync::OnceLock;

use msb_krun::{DiskImageFormat, VmBuilder};

use crate::{CHILD_ALIVE, CHILD_CONSOLE, CHILD_NET};

/// The first argument of a VM child. No user types it: the parent passes it.
pub(crate) const ARG: &str = "__fictionet-vm-child";

/// The alignment `msb_krun` wants for a kernel image: 64 KiB covers every
/// host page size.
const KERNEL_ALIGN: usize = 64 << 10;

/// Runs the VM child and exits, if this process is one. Call it first in
/// `main`, before any thread starts, with the kernel asset. In any other
/// process it returns at once.
pub fn run_if_child(kernel: &'static [u8]) {
    let mut args = std::env::args_os().skip(1);
    if args.next().is_none_or(|arg| arg != ARG) {
        return;
    }
    let error = match run(kernel, args.collect()) {
        Ok(never) => match never {},
        Err(error) => error,
    };
    eprintln!("fictionet VM child: {error}");
    std::process::exit(1);
}

fn run(kernel: &'static [u8], args: Vec<OsString>) -> io::Result<std::convert::Infallible> {
    let [dir, vcpus, memory] = args.as_slice() else {
        return Err(io::Error::other("expected a directory, vCPUs and memory"));
    };
    let dir = PathBuf::from(dir);
    let number = |arg: &OsString| {
        arg.to_str()
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or_else(|| io::Error::other(format!("not a number: {arg:?}")))
    };
    let vcpus = u8::try_from(number(vcpus)?).map_err(io::Error::other)?;
    let memory = number(memory)? as usize;
    watch_parent();
    load_kernel(kernel)?;

    // SAFETY: the parent put the Ethernet socket at this descriptor, and
    // nothing else here owns it.
    let net = unsafe { OwnedFd::from_raw_fd(CHILD_NET) };
    let vm = VmBuilder::new()
        .machine(|m| m.vcpus(vcpus).memory_mib(memory))
        .kernel(|k| k.init_path("/agentd"))
        .fs(|fs| fs.root(dir.join("boot")))
        .fs(|fs| {
            fs.tag(microsandbox_protocol::RUNTIME_FS_TAG)
                .path(dir.join("runtime"))
        })
        .disk(|d| {
            d.path(dir.join("rootfs.ext4"))
                .format(DiskImageFormat::Raw)
                .read_only(false)
        })
        // Offloads stay off: msb_krun gives every network card no
        // features, so each frame on the socket is whole and checksummed.
        .net(|n| n.unixstream(net))
        .console(|c| {
            c.output(dir.join("console.log")).port(
                microsandbox_protocol::AGENT_PORT_NAME,
                CHILD_CONSOLE,
                CHILD_CONSOLE,
            )
        })
        .build()
        .map_err(io::Error::other)?;
    vm.enter().map_err(io::Error::other)
}

/// Exits this process when the parent goes: the parent holds the write end
/// of the pipe at [`CHILD_ALIVE`], and the read returns when it closes,
/// however the parent ended.
fn watch_parent() {
    std::thread::spawn(|| {
        let mut byte = 0u8;
        loop {
            // SAFETY: plain read into a one-byte buffer.
            let n = unsafe { libc::read(CHILD_ALIVE, (&raw mut byte).cast(), 1) };
            if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            // SAFETY: ends the process without running anything else; the
            // VM's storage is the parent's to remove.
            unsafe { libc::_exit(1) };
        }
    });
}

/// The kernel image, in memory this process allocated and never frees.
struct Kernel {
    addr: usize,
    size: usize,
    guest: u64,
    entry: u64,
}

static KERNEL: OnceLock<Kernel> = OnceLock::new();

/// Decompresses the kernel asset into writable, 64 KiB-aligned memory
/// padded to a whole number of 64 KiB, as `msb_krun` requires of an
/// embedded kernel, and keeps it for the life of the process.
fn load_kernel(asset: &[u8]) -> io::Result<()> {
    let bytes = zstd::decode_all(asset)?;
    let (head, image) = bytes
        .split_at_checked(16)
        .ok_or_else(|| io::Error::other("the kernel asset is cut short"))?;
    let guest = u64::from_le_bytes(head[..8].try_into().unwrap());
    let entry = u64::from_le_bytes(head[8..].try_into().unwrap());
    let size = image.len().next_multiple_of(KERNEL_ALIGN);
    let layout = Layout::from_size_align(size, KERNEL_ALIGN).map_err(io::Error::other)?;
    // SAFETY: the layout has a nonzero size. The allocation is never freed,
    // because the guest maps it until the process exits.
    let addr = unsafe { std::alloc::alloc_zeroed(layout) };
    if addr.is_null() {
        return Err(io::Error::other("no memory for the kernel"));
    }
    // SAFETY: `addr` is valid for `size` bytes, which is at least the image.
    unsafe { std::ptr::copy_nonoverlapping(image.as_ptr(), addr, image.len()) };
    KERNEL
        .set(Kernel {
            addr: addr as usize,
            size,
            guest,
            entry,
        })
        .map_err(|_| io::Error::other("the kernel is already loaded"))
}

/// The kernel accessor `msb_krun`'s `static-krunfw` feature links against.
/// It serves the one embedded image, for the default path only.
///
/// # Safety
///
/// The out-parameters must be valid for writes, as `msb_krun` passes them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krunfw_get_kernel(
    path: *const c_char,
    guest_addr: *mut u64,
    entry_addr: *mut u64,
    size: *mut usize,
) -> *mut c_char {
    let Some(kernel) = KERNEL.get() else {
        return std::ptr::null_mut();
    };
    if !path.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: the caller passes valid out-parameters.
    unsafe {
        *guest_addr = kernel.guest;
        *entry_addr = kernel.entry;
        *size = kernel.size;
    }
    kernel.addr as *mut c_char
}
