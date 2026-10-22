//! The command's integration tests that run on any machine. The tests that
//! need user namespaces, root or a tun device are in `tests/host`.

mod common;

mod attach_bin;
mod proxy;
mod tap_bin;
