use crate::iface::{Config, Context};
use crate::time::Instant;
use crate::wire::Ipv4Address;

/// The context the tests' sockets share: host 192.168.1.1 with an MTU of
/// 1500, every connection starting at the same sequence number.
pub(crate) fn context() -> Context {
    let config = Config {
        initial_seq: Box::new(|_, _, _| crate::socket::tcp::test::LOCAL_SEQ.0 as u32),
        ip_addr: Ipv4Address::new(192, 168, 1, 1).into(),
    };
    Context::new(config, 1500, Instant::ZERO)
}
