//! Differential checks of the IP, UDP and ICMP code against the executable
//! Lean reference in `verification/packet-udp/lean`. Each module reads the
//! vector files its Lean module writes, from the directory in `IP_VECTORS`.

#[path = "ip_vectors/support.rs"]
mod support;

#[path = "ip_vectors/checksum.rs"]
mod checksum;
#[path = "ip_vectors/ext6.rs"]
mod ext6;
#[path = "ip_vectors/header.rs"]
mod header;
#[path = "ip_vectors/icmp.rs"]
mod icmp;
#[path = "ip_vectors/reassembly.rs"]
mod reassembly;
#[path = "ip_vectors/udp.rs"]
mod udp;
