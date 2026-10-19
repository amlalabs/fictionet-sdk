# Fictionet's smoltcp fork

This fork of smoltcp 0.14.0 provides TCP sockets over whole IPv4 and IPv6
packets under [0BSD](LICENSE-0BSD.txt). Fictionet supplies the device,
simulation clock, seeded entropy, and host address. The crate has no features
or async runtime dependency and builds for `wasm32-unknown-unknown`.

Ingress accepts TCP directly after the IP header. It drops IPv4 fragments
and other next-header values. Fictionet handles reassembly, IPv6 extension
headers, ICMP, UDP, and routing. Normal builds verify IPv4 and TCP checksums;
[fuzz builds](../fuzz/README.md) bypass those checks.

TCP retains Reno, wakers, retransmission timers, window scaling, MSS, SACK,
and timestamps. Its behavior differs from upstream in these fixes:

- Receive-window edges, scaling, overlap, and FIN handling preserve accepted data.
- ACK bounds, retransmission, and reopened windows preserve queued data and progress.
- Timestamp negotiation follows the socket state.
- RST takes precedence over SYN and FIN. LISTEN ignores it; SYN-SENT accepts it
  only with an acceptable ACK. Synchronized sockets accept it only at RCV.NXT,
  challenge it elsewhere inside the window, and drop it outside the window.
  A passive SYN-RECEIVED socket returns to LISTEN on an accepted reset.
- Closing SYN-SENT sends nothing.

Future personality hooks belong in `src/socket/tcp.rs` for negotiation,
ISNs, windows, timestamps, hop limits, and resets; in `src/wire/tcp.rs` for
option order and ECN flags; and in `src/wire/ipv4.rs` and `src/wire/ipv6.rs`
for emitted IP fields. No personalities are implemented.

`managed` supports the SDK's borrowed and owned buffers. `byteorder` keeps
packet field access concise. Test-only `rand` drives assembler tests.
Workspace checks are listed in [CONTRIBUTING.md](../CONTRIBUTING.md).
