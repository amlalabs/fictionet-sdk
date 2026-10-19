# Fictionet's smoltcp fork

This crate contains TCP sockets and IPv4/IPv6 packet handling from smoltcp
0.14.0, under [0BSD](LICENSE-0BSD.txt). Fictionet supplies the packet device,
clock, seeded entropy, and one address per host. The crate has no features.

Ingress accepts whole IP packets with TCP directly after the IP header.
IPv4 fragments and other next-header values are dropped. Fictionet handles
fragment reassembly, IPv6 extension headers, ICMP, UDP, and routing itself.
Normal builds compute and verify IPv4 and TCP checksums. Fuzz builds retain
the checksum bypass described in [fuzz/README.md](../fuzz/README.md).

TCP retains Reno congestion control, async wakers, retransmission timers,
window scaling, MSS, SACK, timestamps, and resets. Packet options and their
encoding live in `src/wire/tcp.rs`; negotiation, sequence generation,
timestamps, hop limits, and resets live in `src/socket/tcp.rs`. Emitted IP
fields live in `src/wire/ipv4.rs` and `src/wire/ipv6.rs`. These are the places
for future per-host personality hooks; no personalities are added here.

`managed` holds owned or borrowed socket buffers. `byteorder` reads and
writes packet fields. The test-only `rand` dependency drives the assembler's
randomized test. Tests use the same capacities and sequence generator as
production. Run the workspace checks described in
[CONTRIBUTING.md](../CONTRIBUTING.md).
