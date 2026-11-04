# Raw Ethernet in a QEMU guest

The optional `virtio-net` feature provides a userspace VFIO driver for a
modern virtio-net PCI device. A host-side pump owns the driver and carries
complete Ethernet frames to and from a Rust world over bounded channels.
The guest Linux IP and TCP stacks do not process those frames. Linux still
supplies VFIO, IOMMU mappings, memory and scheduling; QEMU still implements
the virtual NIC.

The [raw world example](examples/raw_world.rs) parses a typed `PciAddress`,
opens `VirtioNet`, and calls `RawPump::attach` before `fictionet::run`.
The pump polls hardware on a separate host thread and parks when idle or
backpressured. The world awaits `RawAttachment::recv`; it never polls the
device or checks a host deadline. Each direction holds at most sixty four
queued frames plus one pending host frame. Sending waits for queue space;
a full receive queue stops driver reads, so the NIC may drop traffic.
Receive, send and flush observe world cancellation. Driver failures close
the channels and propagate to the world. Dropping the pump joins its thread
and resets the device. The ordinary `fictionet::Interface` remains an
IP-packet interface; `EthernetFrame` carries complete Ethernet bytes.

The [raw honeypot example](../demos/honeypot/examples/raw_honeypot.rs), built
with the honeypot crate's `raw-virtio` feature, uses the same attachment.
It records complete ingress frames before parsing and passes supported IP
traffic to the existing honeypot world. It runs only in the opted-in guest.

This implementation is restricted to QEMU guests. It checks QEMU's DMI
identity and the guest kernel command line token `fictionet.rawnic=1`
before opening VFIO. The caller must supply an already bound virtio-net
device. The library does not load modules, unbind drivers or configure
network interfaces. The guard prevents accidental use outside the test
environment; it is not a security boundary against a privileged caller.

`VirtioNet::receive` returns the Ethernet bytes delivered by the device,
without the virtio transport header. `transmit` accepts Ethernet bytes.
Polling and bounded split queues provide backpressure. The driver does not
negotiate checksum, segmentation or receive coalescing offloads, and does
not parse or repair IP or TCP headers. MPTCP options are TCP options (kind
30), and reach the world as part of those bytes.

The current implementation supports one receive/transmit queue pair on
x86-64, frames of 14 through 2,036 bytes, and the modern PCI device ID.
It requires a real VFIO type-one IOMMU mapping, including inside the guest;
there is no unsafe no-IOMMU fallback. A successful transmit means queued,
not delivered: world code awaits `RawAttachment::flush` before orderly
teardown, while direct driver callers poll `transmit_idle`. Pump shutdown
discards any remaining queued frames. A short driver receive buffer
consumes that frame and returns an error.

Raw here means the virtual NIC's Ethernet frame, not a physical wire
capture: preamble, interpacket gap and Ethernet FCS are not supplied by
virtio-net. A virtual NIC and its upstream network may filter traffic before
the driver sees it. This does not establish that a cloud hypervisor or NAT
preserves every packet.

Build without opening a device:

```sh
cargo build -p fictionet-host --no-default-features --features virtio-net
```

Run the isolated validation:

```sh
cargo xtask rawnic target/rawnic-qemu
```

The harness builds a guest initramfs, boots QEMU with an emulated Intel
IOMMU, and connects the emulated virtio-net device to a loopback socket.
It reads the local kernel and module files to populate the guest; module
loading and PCI binding happen only inside that guest. No TAP device,
bridge, host device passthrough or external network is needed. The output
directory holds the initramfs and `serial.log`; failed assertions or missing
prerequisites fail the command.

Validation runs the host crate and honeypot tests only in the guest, including
split queue index wraparound, malformed completion rejection, and raw
attachment backpressure, cancellation and flush completion. The guest uses
2 GiB of RAM for the test image and enables its own loopback for HTTP
transport tests. The host then checks
six byte-exact round trips through a Fictionet world: MP_CAPABLE, DSS,
VLAN, malformed IPv4/TCP, broadcast unknown data, and a 1,514-byte unknown
EtherType frame. A final acknowledgment precedes device close and reopen.
The harness then runs the real honeypot through the same raw attachment,
verifies an Ethernet SYN-ACK reply, and checks complete frame capture and
MPTCP SYN, answer and DSS logs. All driver, attachment and frame test execution
stays inside QEMU. This is functional validation, not a throughput benchmark.

The current harness expects an x86-64 Linux host with
`qemu-system-x86_64`, `/boot/vmlinuz-linux`, matching installed kernel
modules, `modprobe` for read-only dependency listing, `zstd` for compressed
modules, and `ldd` for guest binary dependencies. It uses QEMU's software
emulation and does not require KVM or root on the host.

Driver and frame tests run only inside the QEMU guest. Do not run a driver
example on the development host. Do not load host VFIO modules, bind host
devices, run XDP or AF_XDP binaries, attach XDP programs, or change host NIC
settings to test this code.

The driver follows the modern PCI transport and split virtqueue rules in
the [Virtio specification](https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html)
and the Linux [VFIO interface](https://www.kernel.org/doc/html/latest/driver-api/vfio.html).

ENA and EC2 deployment are outside this implementation. ENA requires a
separate driver and separate approval; this QEMU result is not an EC2
compatibility claim.
