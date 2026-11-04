//! Guest-only entry point for the isolated raw Ethernet exercise.
use std::{ffi::CString, fs, io};
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
    if !std::process::Command::new("/driver-tests")
        .args(["virtio::tests::", "--nocapture"])
        .status()?
        .success()
    {
        return Err("guest driver unit tests failed".into());
    }
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
    let nic = fictionet_host::virtio::VirtioNet::open(device)?;
    let mac = nic.mac_address();
    rawnic_world::run(nic, 6).map_err(|error| io::Error::other(error.to_string()))?;
    let reopened = fictionet_host::VirtioNet::open(device)?;
    if reopened.mac_address() != mac {
        return Err("device MAC changed after reopen".into());
    }
    drop(reopened);
    println!("Guest device reset and reopen passed");
    println!("RAWNIC PASS");
    Ok(())
}

fn main() {
    let mut guest = false;
    if let Err(error) = run(&mut guest) {
        eprintln!("RAWNIC FAIL: {error}");
    }
    if guest {
        unsafe {
            libc::reboot(libc::RB_POWER_OFF);
        }
    }
    std::process::exit(1);
}
