# Raw Ethernet attachment

The `raw-ethernet` feature carries whole Ethernet frames between a Rust
world and the code that drives a network card. `RawAttachment` is the
world's side. `RawAttachment::in_memory` returns it with a `RawWire`, the
driver's side: what the world sends comes out of `RawWire::recv`, and what
`RawWire::send` puts on the wire reaches the world.

- The world awaits `RawAttachment::recv`. It never polls a device.
- Each direction holds at most 64 frames. `send` waits for room, and
  `try_send` drops the frame when there is none. A full receive queue
  counts the frames it discards. `receive_stats` and `transmit_stats`
  expose queue loss. `device_stats` exposes losses before the queue when
  the driver can count them, as the AF_XDP pump does; an in-memory
  attachment has none.
- Receive, send, and flush end when the world is cancelled.
- A frame may carry its receipt time from the host clock
  (`RawWire::try_send_received`), taken before it entered the queue.
- Frames are 14 to 2,036 bytes, without an Ethernet FCS.
- `fictionet::Interface` stays an interface for IP packets.
  `EthernetFrame` carries whole Ethernet frames.

The [honeypot](../demos/honeypot/README.md) runs its world behind this
attachment with `start_raw`. It captures each original frame before
parsing and passes IP packets on to the honeypot world. Its tests drive
`start_raw` through in-memory attachments, with no device.

## AF_XDP

The `af-xdp` feature (Linux) adds `xdp::XdpSocket` and `raw::RawPump`.
`XdpSocket::open` takes over one EC2 Elastic Network Adapter, the instance's
second one, and `RawPump::attach` runs it on a thread and returns the world's
`RawAttachment`.

- **Startup checks.** Before changing anything, `open` refuses an interface
  that carries the default route or any other route, has an address, carries
  an established TCP connection such as the SSH session, is not driven by
  `ena`, or is down. It then sets the MTU to 1500 and the channels to one
  combined channel, reads them back, and refuses unless there is one receive
  queue and the channel count is at most half the device maximum, which ENA
  needs before it accepts XDP.
- **The program.** Six eBPF instructions, built in Rust and loaded with
  `bpf(2)`: `bpf_redirect_map(&xsks, ctx->rx_queue_index, XDP_DROP)`. Every
  frame goes to the socket in its queue's slot, and a frame on a queue with no
  socket is dropped. No frame reaches the kernel's stack while it is attached.
- **Attach.** One AF_XDP socket on queue 0 in copy mode
  (`XDP_COPY | XDP_USE_NEED_WAKEUP`), put in the map before the program is
  linked to the interface in driver mode. There is no fallback to generic XDP,
  and an interface that already has a program is left alone.
- **Rings.** A UMEM of 1,024 frames of 4 KiB, half for receive and half for
  transmit, and four rings of 512 slots. A received frame is copied out,
  stamped with the host time, queued to the world, and its buffer returned to
  the fill ring at once. A world frame waits for a free transmit buffer; flush
  waits until every frame sent before it has completed. The pump thread waits
  in `poll(2)` on the socket and on a wake datagram the world's queue signals,
  and reads `XDP_STATISTICS` once a second into the attachment's
  `DeviceStats`.
- **Teardown and crashes.** Nothing is pinned. The link, map, program and
  socket are file descriptors of the process, so the program comes off the
  interface when `RawPump` stops or the process dies. An error in the pump
  thread is recorded in the attachment's failure slot, and the world's next
  receive or send returns it.

Tests on the development host cover only what needs no device: the
instruction encoding and the program's verifier-relevant shape, the
`bpf_attr` and ethtool layouts, ring wraparound, the frame ledger and the
hand-off against an in-memory kernel double, and the startup checks on
synthetic interfaces. The tests in `xdp::device` load the program and bind
the socket. They are ignored by default, do nothing unless
`FICTIONET_XDP_TEST_INTERFACE` names the interface, and refuse one that
carries the default route. Run them only on the EC2 instance, as root:

```sh
FICTIONET_XDP_TEST_INTERFACE=ens6 cargo test -p fictionet-host --no-default-features --features af-xdp -- --ignored --test-threads=1 xdp::device
```

Run the tests:

```sh
systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=8G -p MemorySwapMax=0 cargo test -p fictionet-host --features raw-ethernet
systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=8G -p MemorySwapMax=0 cargo test -p fictionet-host --no-default-features --features af-xdp
```

Do not load VFIO modules on the development host, bind host devices, run
XDP or AF_XDP binaries, attach XDP programs, or change the host's NIC
settings to test this code.
