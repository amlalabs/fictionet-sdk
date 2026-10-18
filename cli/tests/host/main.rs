//! Tests of the command that need the host to provide user namespaces, root
//! or a tun device. They fail when it does not. `cargo test` and `cargo
//! nextest run` leave them out; `cargo nextest run --test host` runs them.

mod attach_bin;
