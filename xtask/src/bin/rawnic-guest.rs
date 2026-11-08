//! Guest-only entry point for the isolated raw Ethernet exercise.
use std::{ffi::CString, fs, io};
#[path = "../egress.rs"]
mod egress;
#[path = "../rawnic_frames.rs"]
mod rawnic_frames;
#[path = "../rawnic_world.rs"]
mod rawnic_world;

fn mount(kind: &str, target: &str) -> io::Result<()> {
    let kind = CString::new(kind)?;
    let target = CString::new(target)?;
    if unsafe {
        libc::mount(
            kind.as_ptr(),
            target.as_ptr(),
            kind.as_ptr(),
            0,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn run(guest: &mut bool) -> Result<(), Box<dyn std::error::Error>> {
    if std::process::id() != 1 {
        return Err("guest entry point requires PID one".into());
    }
    mount("proc", "/proc")?;
    mount("sysfs", "/sys")?;
    let cmdline = fs::read_to_string("/proc/cmdline")?;
    let vendor = fs::read_to_string("/sys/class/dmi/id/sys_vendor")?;
    if !cmdline
        .split_whitespace()
        .any(|arg| arg == "fictionet.rawnic=1")
        || vendor.trim() != "QEMU"
    {
        return Err("requires explicitly marked QEMU guest".into());
    }
    *guest = true;
    mount("devtmpfs", "/dev")?;
    for index in 0.. {
        let path = format!("/modules/{index}");
        if !std::path::Path::new(&path).exists() {
            break;
        }
        let bytes = fs::read(path)?;
        if unsafe {
            libc::syscall(
                libc::SYS_init_module,
                bytes.as_ptr(),
                bytes.len(),
                c"".as_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
    }
    fs::create_dir_all("/etc")?;
    fs::write("/etc/hosts", "127.0.0.1 localhost\n")?;
    // The full host transport tests use guest-local TCP listeners.
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    let mut interface: libc::ifreq = unsafe { std::mem::zeroed() };
    interface.ifr_name[0] = b'l' as libc::c_char;
    interface.ifr_name[1] = b'o' as libc::c_char;
    use std::os::fd::AsRawFd;
    if unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFFLAGS, &mut interface) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    unsafe {
        interface.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
    }
    if unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCSIFFLAGS, &interface) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    drop(socket);
    for index in 0.. {
        let path = format!("/tests/{index}");
        if !std::path::Path::new(&path).exists() {
            break;
        }
        if !std::process::Command::new(path)
            .arg("--nocapture")
            .status()?
            .success()
        {
            return Err("guest tests failed".into());
        }
    }
    if cmdline
        .split_whitespace()
        .any(|arg| arg == "fictionet.egress=1")
    {
        return egress::run().map_err(|error| io::Error::other(error.to_string()).into());
    }
    rawnic_world::tun().map_err(|error| io::Error::other(error.to_string()))?;
    let device = "0000:00:03.0";
    let path = format!("/sys/bus/pci/devices/{device}");
    if fs::read_to_string(format!("{path}/vendor"))?.trim() != "0x1af4"
        || fs::read_to_string(format!("{path}/device"))?.trim() != "0x1041"
    {
        return Err("unexpected guest PCI device".into());
    }
    if std::path::Path::new(&format!("{path}/driver")).exists() {
        fs::write(format!("{path}/driver/unbind"), device)?;
    }
    fs::write(format!("{path}/driver_override"), "vfio-pci")?;
    fs::write("/sys/bus/pci/drivers_probe", device)?;
    let group = fs::read_link(format!("{path}/iommu_group"))?;
    println!("Guest VFIO IOMMU group: {}", group.display());
    let address: fictionet_host::PciAddress = device.parse()?;
    let nic = fictionet_host::virtio::VirtioNet::open(address)?;
    let mac = nic.mac_address();
    rawnic_world::run(nic, 6).map_err(|error| io::Error::other(error.to_string()))?;
    let reopened = fictionet_host::VirtioNet::open(address)?;
    if reopened.mac_address() != mac {
        return Err("device MAC changed after reopen".into());
    }
    rawnic_world::honeypot(reopened).map_err(|error| io::Error::other(error.to_string()))?;
    println!("Guest device reset and reopen passed");
    rawnic_world::deployed(address, mac).map_err(|error| io::Error::other(error.to_string()))?;
    println!("RAWNIC PASS");
    Ok(())
}

fn main() {
    let mut guest = false;
    let result = run(&mut guest);
    if let Err(error) = &result {
        eprintln!("RAWNIC FAIL: {error}");
    }
    if guest
        && fs::read_to_string("/proc/cmdline")
            .unwrap_or_default()
            .split_whitespace()
            .any(|arg| arg == "fictionet.egress=1")
    {
        // SAFETY: this marked QEMU guest exposes only the exit device at this port.
        unsafe {
            if libc::ioperm(0xf4, 4, 1) == 0 {
                std::arch::asm!("out dx, eax", in("dx") 0xf4u16, in("eax") 42 + u32::from(result.is_err()));
            }
        }
    }
    if guest {
        unsafe {
            libc::reboot(libc::RB_POWER_OFF);
        }
    }
    std::process::exit(1);
}
