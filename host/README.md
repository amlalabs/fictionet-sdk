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
  expose queue loss; losses inside a card or its driver remain unknown.
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

Run the tests:

```sh
systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=8G -p MemorySwapMax=0 cargo test -p fictionet-host --features raw-ethernet
```

Do not load VFIO modules on the development host, bind host devices, run
XDP or AF_XDP binaries, attach XDP programs, or change the host's NIC
settings to test this code.
