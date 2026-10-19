# Fictionet's smoltcp fork

This workspace crate is a fork of smoltcp 0.14.0, licensed under
[0BSD](LICENSE-0BSD.txt). It prepares the stack for future per-host network
personalities; this change does not introduce personalities.

Fictionet uses TCP with Reno congestion control and async wakers over its own
in-memory IP device. IPv4, IPv6, ICMP packet handling, IPv6 extension parsing,
routing, and TCP buffers remain. IPv4 fragmentation is retained behind
`proto-ipv4-fragmentation` and remains disabled for the SDK, as before.
IPv6 fragmentation was not implemented for the IP medium upstream.
Automatic ICMP echo replies remain available through the default
`auto-icmp-echo-reply` feature for standalone stack use and its interface tests.
The SDK disables default features and continues handling echo replies itself.

Removed: Ethernet and ARP; IEEE 802.15.4, 6LoWPAN and RPL; neighbor discovery and
SLAAC; multicast membership, IGMP and MLD; DHCP, DNS, ICMP, raw and UDP sockets;
IPsec and unused IPv6 routing representations; host I/O and
diagnostic devices; Cubic, segmentation offload, packet IDs and paused SYN-ACKs;
log and defmt integrations; no-std feature combinations and build-time capacity
features and environment overrides. Fictionet supplies its own Ethernet, UDP,
DNS and ICMP services. The UDP wire decoder remains for IP packet formatting
and its existing tests.

The required std, IPv4, IPv6, IP-medium, TCP, Reno and async paths are
unconditional. Capacities live in [src/config.rs](src/config.rs), with the
upstream production defaults and the original unit-test fixture capacities.
The retained stack's unit tests run with the workspace checks documented in
[CONTRIBUTING.md](../CONTRIBUTING.md).
