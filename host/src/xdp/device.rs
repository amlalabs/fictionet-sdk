//! Tests that load the program and bind the socket on a real interface.
//!
//! They are ignored by default and do nothing unless
//! `FICTIONET_XDP_TEST_INTERFACE` names the interface, and they refuse to
//! touch it if it carries the default route. They are meant for the data
//! ENA of the EC2 instance only, as root:
//!
//! ```sh
//! FICTIONET_XDP_TEST_INTERFACE=ens6 cargo test -p fictionet-host \
//!     --features af-xdp -- --ignored --test-threads=1 xdp::device
//! ```

use std::time::Duration;

use super::interface::{self, InterfaceName};
use super::{OpenError, XdpSocket};
use crate::raw::RawPump;

const VARIABLE: &str = "FICTIONET_XDP_TEST_INTERFACE";

/// The interface named by the environment, or `None` to skip. Panics,
/// before any device call, if the interface carries the default route.
fn interface() -> Option<InterfaceName> {
    let Ok(name) = std::env::var(VARIABLE) else {
        eprintln!("{VARIABLE} is not set; skipping a test that needs the EC2 data interface");
        return None;
    };
    let name: InterfaceName = name.parse().expect("an interface name");
    let routes = interface::routes().expect("reading the routing table");
    let default = routes
        .iter()
        .find(|route| route.interface == name.as_str() && route.is_default());
    assert!(
        default.is_none(),
        "refusing to test on {name}: it carries the default route"
    );
    Some(name)
}

#[test]
#[ignore = "needs the EC2 data interface; see the module docs"]
fn attach_reports_native_copy_mode_and_detaches_on_drop() {
    let Some(name) = interface() else { return };
    let socket = XdpSocket::open(&name).expect("taking the interface");
    let attached = socket.attached().clone();
    assert_eq!(attached.interface, name);
    assert_eq!(attached.mtu, interface::MTU);
    assert_eq!(attached.queue, 0);
    assert_eq!(attached.channels.combined, 1);
    assert_eq!(attached.driver.name, interface::DRIVER);
    eprintln!("attached: {attached:?}");
    drop(socket);
    // A link left behind would make this attach fail.
    let again = XdpSocket::open(&name).expect("attaching again after the drop");
    drop(again);
}

#[test]
#[ignore = "needs the EC2 data interface; see the module docs"]
fn a_second_socket_on_the_interface_is_refused() {
    let Some(name) = interface() else { return };
    let first = XdpSocket::open(&name).expect("taking the interface");
    let second = XdpSocket::open(&name);
    assert!(
        matches!(second, Err(OpenError::Occupied | OpenError::Io { .. })),
        "{:?}",
        second.err()
    );
    drop(first);
}

#[test]
#[ignore = "needs the EC2 data interface; see the module docs"]
fn the_pump_reads_statistics_and_shuts_down_cleanly() {
    let Some(name) = interface() else { return };
    let socket = XdpSocket::open(&name).expect("taking the interface");
    let (pump, attachment) = RawPump::attach(socket).expect("starting the pump");
    std::thread::sleep(Duration::from_millis(1500));
    let statistics = pump.statistics().expect("statistics after a second");
    eprintln!("statistics: {statistics:?}");
    assert_eq!(statistics.tx_invalid, 0);
    assert!(attachment.device_stats().is_some());
    pump.shutdown().expect("a clean shutdown");
    drop(attachment);
    let again = XdpSocket::open(&name).expect("attaching again after shutdown");
    drop(again);
}
