//! The `--vm tap:<name>` transport: the device lock, attach's own TAP device,
//! and the traffic-control redirect between it and the VM's device.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::config::TapArgs;
use crate::lifecycle;
use crate::linux;
use crate::netlink::{self, Netlink};
use crate::world::{self, Failure, context, err};

use fictionet::stdlib::network::ethernet::frame;

use super::{End, Port, greeting, relay_and_report, take_ready_file};

/// `--vm tap:<name>`: makes attach's own TAP device, redirects frames
/// between it and the VM's, then connects to the world.
pub(super) fn run_device(
    args: &TapArgs,
    name: &str,
    lock: &mut Option<OwnedFd>,
) -> Result<End, Failure> {
    // Enter the namespace first, while the process has one thread.
    if let Some(netns) = &args.netns {
        linux::enter_netns(netns).map_err(err(&format!(
            "entering the network namespace {}",
            netns.display()
        )))?;
    }
    let vm_index = linux::index_of(name).map_err(|e| {
        Failure::Error(format!(
            "no device {name} ({e}). Make the VM's TAP device first, as the VM program's user: \
             ip tuntap add dev {name} mode tap user <user>"
        ))
    })?;
    take_ready_file(args, lock, lock_device(name, vm_index)?);
    let (fd, own) = open_tap(name)?;
    let own_index = linux::index_of(&own).map_err(err(&format!("finding {own}")))?;
    let mirror = Mirror::set_up(vm_index, name, own_index, &own, args.mtu)
        .map_err(|e| Failure::Error(format!("redirecting frames between {name} and {own}: {e}")))?;
    eprintln!("fictionet attach: frames from {name} go to {own}, and back");
    let sock = world::handshake(&greeting(args))?;
    eprintln!("fictionet attach: {} attached through {name}", args.name);
    lifecycle::write_ready_file(args.ready_file.as_deref(), &args.name)?;
    let mut port = Port::Device {
        fd,
        buf: vec![0u8; 65_536 + frame::HEADER],
        name: name.to_owned(),
        index: vm_index,
    };
    let end = relay_and_report(args, &mut port, sock.as_raw_fd());
    drop(mirror);
    end
}

/// Makes attach's own TAP device, with no offloads: the kernel finishes
/// checksums and splits large frames before attach reads them. Its name is
/// the VM's device's with `-fn` added, if that fits, else the kernel picks
/// one. Closing the returned fd removes the device.
fn open_tap(vm_dev: &str) -> Result<(OwnedFd, String), Failure> {
    let fd = linux::open_tun_file()?;
    let want = format!("{vm_dev}-fn");
    let want = if want.len() <= 15 {
        want
    } else {
        "fntap%d".to_owned()
    };
    let mut ifr = [0u8; 40];
    ifr[..want.len()].copy_from_slice(want.as_bytes());
    ifr[16..18].copy_from_slice(&(IFF_TAP | linux::IFF_NO_PI).to_ne_bytes());
    // SAFETY: `ifr` is as large as struct ifreq.
    if unsafe { libc::ioctl(fd.as_raw_fd(), linux::TUNSETIFF as _, ifr.as_mut_ptr()) } < 0 {
        let e = io::Error::last_os_error();
        return Err(Failure::Error(format!(
            "creating the TAP device {want} (does attach have CAP_NET_ADMIN?): {e}"
        )));
    }
    let len = ifr[..16].iter().position(|&b| b == 0).unwrap_or(16);
    Ok((fd, String::from_utf8_lossy(&ifr[..len]).into_owned()))
}

const IFF_TAP: libc::c_short = 0x0002;

/// The redirect between the VM's TAP device and attach's: an ingress qdisc
/// on each, with a filter that sends every frame out of the other. Dropping
/// it sets the VM's device down, so the kernel drops the VM's frames
/// instead of handing them to the namespace's IP stack, then removes its
/// qdisc. Attach's device goes with its fd.
struct Mirror {
    cleanup: &'static lifecycle::NetlinkCleanup,
}

/// One step of [`Mirror::set_up`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    /// Set the VM's device down. While it is down, the kernel refuses
    /// every frame the VM program writes to it, so none reaches the
    /// namespace's IP stack before the redirect is in place.
    VmDown,
    /// No IPv6 on this device, so the namespace's own stack sends nothing
    /// on it and takes no router advertisement from the VM. It fails
    /// harmlessly where IPv6 is off.
    NoIpv6(u32),
    /// Set the MTU of attach's device and bring it up.
    OwnUp,
    /// Remove a qdisc an earlier attach left on the VM's device.
    ClearVm,
    AddIngress(u32),
    Redirect {
        from: u32,
        to: u32,
    },
    /// Bring the VM's device up, once both redirects are in place.
    VmUp,
}

/// The steps of [`Mirror::set_up`], in order. The VM's device goes down
/// first and comes up last.
fn mirror_steps(vm: u32, own: u32) -> [Step; 10] {
    [
        Step::VmDown,
        Step::NoIpv6(vm),
        Step::NoIpv6(own),
        Step::OwnUp,
        Step::ClearVm,
        Step::AddIngress(vm),
        Step::Redirect { from: vm, to: own },
        Step::AddIngress(own),
        Step::Redirect { from: own, to: vm },
        Step::VmUp,
    ]
}

impl Mirror {
    fn set_up(vm: u32, vm_name: &str, own: u32, own_name: &str, mtu: u16) -> io::Result<Mirror> {
        let nl = Netlink::open()?;
        // The cleanup is in place before anything changes: dropping the
        // guard, or SIGTERM, SIGINT and SIGHUP (whose handler does the same
        // as dropping it), set the VM's device down and remove its qdisc.
        let mirror = Mirror {
            cleanup: lifecycle::netlink_on_signal(lifecycle::NetlinkCleanup::new([
                netlink::link_down(vm),
                netlink::del_ingress(vm),
            ])),
        };
        for step in mirror_steps(vm, own) {
            match step {
                Step::VmDown => {
                    nl.call(netlink::link_down(vm))
                        .map_err(|e| context(e, "setting the VM's device down"))?;
                }
                Step::NoIpv6(index) => {
                    let name = if index == vm { vm_name } else { own_name };
                    let _ = nl.call(netlink::no_ipv6_link_local(index));
                    let _ =
                        std::fs::write(format!("/proc/sys/net/ipv6/conf/{name}/disable_ipv6"), "1");
                }
                Step::OwnUp => {
                    nl.call(netlink::link_up(own, mtu as u32))
                        .map_err(|e| context(e, "bringing up attach's device"))?;
                }
                Step::ClearVm => {
                    #[expect(
                        clippy::let_underscore_must_use,
                        reason = "AddIngress is checked next and fails if an old ingress qdisc is still there"
                    )]
                    let _ = nl.call(netlink::del_ingress(vm));
                }
                Step::AddIngress(index) => {
                    nl.call(netlink::add_ingress(index))
                        .map_err(|e| context(e, "adding an ingress qdisc"))?;
                }
                Step::Redirect { from, to } => {
                    nl.call(netlink::redirect_ingress(from, to)).map_err(|e| {
                        context(e, "adding the redirect (are the kernel modules cls_matchall and act_mirred there?)")
                    })?;
                }
                Step::VmUp => {
                    nl.call(netlink::set_up(vm))
                        .map_err(|e| context(e, "bringing up the VM's device"))?;
                }
            }
        }
        Ok(mirror)
    }
}

impl Drop for Mirror {
    fn drop(&mut self) {
        if let Ok(nl) = Netlink::open() {
            for request in self.cleanup.requests() {
                // Teardown remains best effort, including after partial setup:
                // a missing device or qdisc does not stop the remaining requests.
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "best-effort undo in Drop; each request is sent even if an earlier one failed"
                )]
                let _ = nl.call_message(request);
            }
        }
    }
}

/// Takes the lock for the VM's TAP device: a Unix socket bound to an
/// abstract name made from the device's index, in the device's network
/// namespace. One attach at a time owns a device, so a second one stops
/// here, before it touches the device, its redirect or the ready file.
/// The kernel frees the name however attach ends.
fn lock_device(name: &str, index: u32) -> Result<OwnedFd, Failure> {
    // SAFETY: plain syscall; the fd is owned from here.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(err("making the device lock")(io::Error::last_os_error()));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let id = format!("attach-tap/{index}");
    // SAFETY: an all-zero sockaddr_un is valid.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    // sun_path[0] stays 0: an abstract name, with no file.
    for (dst, src) in addr.sun_path[1..].iter_mut().zip(id.as_bytes()) {
        *dst = *src as libc::c_char;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + 1 + id.len()) as libc::socklen_t;
    // SAFETY: `addr` is a valid sockaddr_un of `len` bytes.
    if unsafe { libc::bind(fd.as_raw_fd(), (&raw const addr).cast(), len) } < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EADDRINUSE) {
            return Err(Failure::Error(format!("another attach is using {name}")));
        }
        return Err(err("taking the device lock")(e));
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_startup_keeps_vm_down_before_qdisc_removal_in_the_cleanup_plan() {
        // Index zero cannot name a device for RTM_NEWLINK. This fails the
        // first setup step without needing TAP devices or CAP_NET_ADMIN.
        let error = match Mirror::set_up(0, "", 0, "", 1500) {
            Ok(_) => panic!("setup must reject an absent VM device"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .starts_with("setting the VM's device down:")
        );
        // The guard has already dropped. The plan must have been published
        // before the failed step and must remain available until exit.
        let cleanup = lifecycle::registered_netlink_cleanup().expect("cleanup before setup");
        assert_eq!(
            cleanup.requests().collect::<Vec<_>>(),
            [
                netlink::link_down(0).finish(),
                netlink::del_ingress(0).finish()
            ]
        );
    }

    #[test]
    fn the_vm_device_stays_down_until_both_redirects_are_in_place() {
        let steps = mirror_steps(7, 8);
        assert_eq!(steps[0], Step::VmDown, "down before anything else changes");
        assert_eq!(
            steps[steps.len() - 1],
            Step::VmUp,
            "up after everything else"
        );
        let at = |s: Step| steps.iter().position(|&x| x == s).unwrap();
        assert!(at(Step::Redirect { from: 7, to: 8 }) < at(Step::VmUp));
        assert!(at(Step::Redirect { from: 8, to: 7 }) < at(Step::VmUp));
        assert!(at(Step::ClearVm) < at(Step::AddIngress(7)));
        assert!(at(Step::NoIpv6(7)) < at(Step::VmUp) && at(Step::NoIpv6(8)) < at(Step::OwnUp));
    }
}
