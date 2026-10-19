use std::collections::VecDeque;

use crate::iface::*;
use crate::phy::{self, Device, DeviceCapabilities};
use crate::time::Instant;
use crate::wire::*;

pub(crate) fn setup<'a>() -> (Interface, SocketSet<'a>, TestingDevice) {
    let mut device = TestingDevice::new();
    let iface = setup_with_device(&mut device);
    (iface, SocketSet::new(vec![]), device)
}

fn setup_with_device(device: &mut impl Device) -> Interface {
    let config = Config {
        random_seed: 0,
        ip_addr: IpCidr::new(IpAddress::v4(192, 168, 1, 1), 32),
    };
    Interface::new(config, device, Instant::ZERO)
}

/// A testing device.
#[derive(Debug)]
pub struct TestingDevice {
    pub(crate) tx_queue: VecDeque<Vec<u8>>,
    pub(crate) rx_queue: VecDeque<Vec<u8>>,
    max_transmission_unit: usize,
}

impl TestingDevice {
    /// Creates a testing device.
    ///
    /// Every packet transmitted through this device will be received through it
    /// in FIFO order.
    pub fn new() -> Self {
        TestingDevice {
            tx_queue: VecDeque::new(),
            rx_queue: VecDeque::new(),
            max_transmission_unit: 1500,
        }
    }
}

impl Device for TestingDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        DeviceCapabilities {
            max_transmission_unit: self.max_transmission_unit,
        }
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx_queue.pop_front().map(move |buffer| {
            let rx = RxToken { buffer };
            let tx = TxToken {
                queue: &mut self.tx_queue,
            };
            (rx, tx)
        })
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            queue: &mut self.tx_queue,
        })
    }
}

#[doc(hidden)]
pub struct RxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

#[doc(hidden)]
#[derive(Debug)]
pub struct TxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl<'a> phy::TxToken for TxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        self.queue.push_back(buffer);
        result
    }
}
