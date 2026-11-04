# Raw Ethernet in a QEMU guest

The optional `virtio-net` feature is a user-space VFIO driver for a modern
virtio-net PCI device. A driver thread, the `RawPump`, owns the device and
carries whole Ethernet frames to and from a Rust world. The guest's Linux
IP and TCP code never sees those frames. Linux still provides VFIO, the
IOMMU mappings, memory and scheduling, and QEMU still emulates the card.

The [raw world example](examples/raw_world.rs) parses a `PciAddress`, opens
`VirtioNet`, and calls `RawPump::attach` before `fictionet::run`.

- The pump polls the device on its own thread, and parks when there is
  nothing to do or the world is not keeping up.
- The world awaits `RawAttachment::recv`. It never polls the device.
- Each direction holds at most 64 frames, plus one the pump holds.
  `send` waits for room, and `try_send` drops the frame when there is
  none. When the receive queue is full, the pump stops reading, and the
  card may drop frames.
- Receive, send, and flush end when the world is cancelled.
- A driver failure closes both directions, and the world gets the error.
- Dropping the pump stops its thread and resets the device.
- `fictionet::Interface` stays an interface for IP packets.
  `EthernetFrame` carries whole Ethernet frames.

The [raw honeypot example](../demos/honeypot/examples/raw_honeypot.rs),
built with the honeypot crate's `raw-virtio` feature, uses the same
attachment. It logs each frame before reading it, and passes IP packets
on to the honeypot world.

The driver runs only in a QEMU guest. Before it opens VFIO, it checks
QEMU's DMI identity and the token `fictionet.rawnic=1` on the guest's
kernel command line. The device must already be bound to `vfio-pci`. The
library loads no modules, unbinds no drivers, and configures no network
interfaces.

`VirtioNet::receive` returns the Ethernet frame the device delivered,
without the virtio header, and `transmit` takes an Ethernet frame. The
driver turns on no checksum, segmentation, or receive coalescing offloads,
and never parses or repairs IP or TCP headers. MPTCP options are TCP
options (kind 30), so they reach the world inside those frames.

The driver supports:

- one receive queue and one transmit queue, on x86-64;
- frames of 14 to 2,036 bytes;
- the modern virtio-net PCI device ID;
- a real VFIO type 1 IOMMU, in the guest too. There is no no-IOMMU mode.

A transmit that succeeds means the frame is queued, not delivered. World
code awaits `RawAttachment::flush` before an orderly shutdown, and code
that calls the driver directly polls `transmit_idle`. Shutting the pump
down discards frames still queued. A receive buffer too short for a frame
uses up that frame and returns an error.

The frames are the virtual card's, not a capture of a physical wire.
virtio-net has no preamble, gap between frames, or Ethernet FCS. The
virtual card and the network behind it may filter traffic before the
driver sees it.

Build without opening a device:

```sh
cargo build -p fictionet-host --no-default-features --features virtio-net
```

Run the tests:

```sh
cargo xtask rawnic target/rawnic-qemu
```

The harness builds a guest initramfs, boots QEMU with an emulated Intel
IOMMU, and connects the emulated virtio-net card to a loopback socket. It
reads the local kernel and module files to build the guest. Modules load,
and the card is bound, only inside the guest. It needs no TAP device,
bridge, host device passthrough, or outside network. The output directory
holds the initramfs and `serial.log`. A failed check or a missing
prerequisite fails the command.

In the guest, with 2 GiB of RAM and its own loopback up for the HTTP
transport tests, the harness runs the host crate's and the honeypot's
tests. Among them are split queue indices that wrap, completions the
driver must refuse, and the raw attachment's backpressure, cancellation,
and flush. From the host, it then checks:

- six frames sent through a Fictionet world and back, byte for byte:
  MP_CAPABLE, DSS, a VLAN tag, malformed IPv4 and TCP, broadcast unknown
  data, and a 1,514-byte frame of an unknown EtherType;
- a last acknowledgment before the device closes and opens again;
- the real honeypot on the same attachment: an Ethernet SYN-ACK, and an
  MP_CAPABLE handshake with timestamps;
- a fragmented ping whose echo reply is too big for one frame, which the
  Ethernet adapter must drop and keep serving;
- an HTTP request under a DSS mapping, which must get the whole nginx page
  with valid TCP checksums, DSS mappings, Data ACKs, and timestamp echoes;
- in the guest, the Ethernet log, and the honeypot's log lines for the
  MPTCP SYN, its answer, and DSS.

It checks that things work, not how fast.

The harness expects an x86-64 Linux host with `qemu-system-x86_64`,
`/boot/vmlinuz-linux`, the kernel modules that match it, `modprobe` to list
module dependencies, `zstd` for compressed modules, `objcopy` to remove
debug sections from guest copies, and `ldd` for the guest binaries' libraries.
The original binaries keep their debug information. It uses QEMU's software
emulation, and needs neither KVM nor root on the host.

Driver and frame tests run only inside the QEMU guest. Do not run a driver
example on the development host. Do not load VFIO modules on the host, bind
host devices, run XDP or AF_XDP binaries, attach XDP programs, or change the
host's NIC settings to test this code.

The driver follows the modern PCI transport and split virtqueue rules of
the [virtio specification](https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html)
and the Linux [VFIO interface](https://www.kernel.org/doc/html/latest/driver-api/vfio.html).
