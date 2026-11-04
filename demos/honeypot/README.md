# MPTCP honeypot

A Fictionet world that looks like a Linux server with an MPTCP listener, and
logs everyone who tries it. It is built for CVE-2026-98432, a use-after-free
in the Linux kernel's IPv4 TCP connection setup. Anthropic showed on
2026-10-27 that the flaw gives unauthenticated root on a server with an MPTCP
listener. No exploit code is public.

Nothing in the world is a real kernel. The server is Fictionet's TCP stack
and a few lines of world code, so an attempt that would take over a vulnerable
Linux host only gets logged here.

## What the server presents

One host at a public address (`--address`) with an MPTCP listener on each
open port:

- **SSH** (`--ssh`, 22 by default): the identification line of OpenSSH 9.6p1
  on Ubuntu 24.04. It reads whatever comes back until the client leaves or
  120 seconds pass, as sshd's `LoginGraceTime` does. No keepalives: on
  Linux sshd's first comes after two hours idle, so a client sees none.
- **HTTP** (`--http`, 80 by default): nginx's default page for one request,
  then it closes. No keepalives, as nginx asks for none.

The MPTCP listener follows RFC 8684, and reads MPTCP options as Linux does:
an option Linux ignores counts for nothing, and of several that count the
last one wins.

- A SYN with MP_CAPABLE that offers HMAC-SHA256 alone gets a SYN-ACK with
  MP_CAPABLE version 1 and a fresh random key. A SYN that offers a higher
  version gets version 1 back, as Linux answers it. The SYN-ACK asks for
  checksums only when the SYN did.
- Linux ignores MP_CAPABLE of version 0, with a key, with flag B, or with any
  algorithm but HMAC-SHA256 alone, and so does the honeypot. A SYN with only
  such options is plain TCP, and so is a SYN with both MP_CAPABLE and
  MP_JOIN. On the third ACK, MP_CAPABLE counts only with version 1 and the
  Length the segment calls for: 20 on a pure ACK, 22 or 24 with data. A
  connection whose third ACK echoes no keys that count is plain TCP.
- Once the third ACK echoes the keys, every segment the server sends carries
  DSS: a mapping of its data, from its IDSN + 1, and a Data ACK of the
  client's. The client's data must come under a mapping: a DSS, or the
  MP_CAPABLE with data that a Linux client sends with its first bytes when
  it speaks first. When the client sends data that no mapping covers, the
  connection falls back to plain TCP, and the server sends no more DSS. The
  client's DATA_FIN is acknowledged at once, even on a segment with no data
  and no FIN, as Linux sends it when it closes.
- MP_JOIN is answered as by a Linux listener with its default limits. When
  the token names one of the server's open connections on the same port,
  the SYN gets a SYN-ACK with MP_JOIN, the server's HMAC and a random number.
  At the third ACK, a join with the client's right HMAC is taken, up to two
  per connection; the server sends nothing on it, reads what the client
  sends, and closes it when the connection is gone. A join with a wrong HMAC,
  past the two, or whose connection has gone gets a RST with MP_TCPRST
  "administratively prohibited", and so does a join SYN for a connection on
  another port. A third ACK with no MP_JOIN gets "MPTCP-specific error", as
  does a join SYN whose token names no open connection.
- After a SYN cookie, the server takes its key from the third ACK's echo,
  as Linux does, and drops that ACK as Linux does: when it carries both
  MP_CAPABLE and MP_JOIN, when the client's key is 0, or when the echoed
  key's token names an open connection. A join SYN that gets a SYN cookie is
  refused at once when its connection is full. Otherwise it is kept as Linux
  keeps it, in one of 1,024 slots that a later join SYN may take, and its
  third ACK is checked as any other. When its slot was taken or its
  connection has gone, that ACK is dropped with no answer.
- A RST that refuses a SYN or a third ACK has the fields Linux gives it: the
  sequence number the segment acknowledged, or else 0 and an ACK of the SYN,
  window 0, and MP_TCPRST as its only option.
- TCP options are read as Linux reads them: an option whose Length runs past
  the header ends the list, a known kind of another length is ignored, and
  the SYN is answered.

## What it logs

Every packet that crosses an attachment, both ways, goes to a pcapng file
(`--pcap`). Each packet carries a comment with the attachment's name and its
direction. The world appends to the file, one section per run, and Wireshark
reads it as it is.

The log (`--log`) has one JSON object per line. The `event` field says which
kind it is:

| `event` | When | What it holds |
| --- | --- | --- |
| `syn` | A SYN into the world | Source and destination, the initial sequence number, every TCP option in order, `options_fault` if the options did not all read, each MPTCP option decoded, the payload in hex when the SYN carried one, and `gap_us` since the same source's previous SYN when that SYN was within the burst window |
| `segment` | Any other segment in with a payload, a FIN or MPTCP options | Flags, sequence number, every TCP option in order, `options_fault`, each MPTCP option decoded, and the payload in hex |
| `answer` | A RST from the world, or the SYN-ACK that first answers a SYN | Flags, every TCP option in order, and each MPTCP option decoded, such as the key the server issued |
| `burst` | A source's SYNs, or its SYNs with MP_JOIN, reach the burst threshold | Source address, which kind, how many, and the window |
| `lost` | The log takes lines again after a file could not be written, such as while the disk was full | How many packets the capture and how many lines the log left out |

Times are `at_us`, microseconds since the Unix epoch. Keys, tokens and HMACs
are hex. Each MPTCP option is decoded with every field the codec reads, and
its bytes are in `options` too, so signatures can be run over either. An
MP_JOIN SYN says whether its token names an open connection (`token_known`).
An option of kind 30 that does not read as MPTCP is logged as `malformed`,
with the reason and its bytes. A SYN without `gap_us` is a source's first
within the burst window; the `at_us` of its lines gives longer gaps.

The world writes each packet to the capture and the log before passing it on.
The capture has each packet as it crossed. The log reads whole packets: the
attachment puts IP fragments together, as a Linux host does (at most 4 MiB
waiting, for at most 30 seconds for IPv4 and 60 for IPv6), and the world gets
the whole packet it made. A packet whose IPv4 header or TCP checksum is wrong
is in the capture only, as a host discards it unread. Every other packet in is
logged as the world sees it, whether or not the world takes it: one for an
address the internet does not reach, or whose source the network refuses, is
logged and then dropped, and its line names those addresses. Fragments for an
address the internet does not reach are in the capture only.

A SYN-ACK the server sends again while it waits for the handshake's last ACK
is in the capture, but logged only the first time.

Neither file can stop the world. When one cannot be written, such as when the
disk is full, what it could not take is lost, and once both can be written
again a `lost` line says how much. A packet or line cut short is finished
first, so both files hold whole records.

### Bursts are a heuristic

The exploit is not public. The published description says it races
connection setup on a server with an MPTCP listener, so the log flags what
such a race would look like. A burst is at least `--burst-syns` SYNs (8 by
default), or that many SYNs with MP_JOIN, from one source address within
`--burst-window-ms` (100 by default). That is a guess at the attack's shape,
not a signature of it. Every SYN is logged in full whether or not it is part of
a burst, so signatures written once the exploit is known can be run over the
log.

### Hostile input

Internet attackers send whatever they like, so every reader checks lengths.
The world keeps state for a source, and for the answer to its SYN, only while
that source has a SYN within the burst window, and an MPTCP token only while
its connection is open. A flood from spoofed addresses cannot grow either past
what one window or the open connections hold.

Spoofed SYNs cannot shut real attackers out either. Each port holds 4,096
handshakes. Past that, the server answers with SYN cookies, as Linux does, and
keeps nothing until the ACK that returns one. A handshake whose last ACK never
comes gets six SYN-ACKs, at 0, 1, 3, 7, 15 and 31 seconds, and is dropped at 63
seconds without a RST, as on Linux. A closed connection whose client never
closes its side is forgotten a minute after the client acknowledged the
server's FIN, whatever the client sends meanwhile, as on Linux.

A client cannot connect in another address's name. Each connection's initial
sequence number is a keyed hash of its addresses and ports plus a clock, as
Linux makes it (RFC 6528), so the numbers a client sees on its own
connections tell it nothing about another's. The SYN cookies have a key of
their own. So the segments of a connection whose handshake completed come
from the address they name. A SYN needs no handshake, so the source of a
`syn` or `burst` line is only what the sender wrote, and may be spoofed.

The internet reaches the server and nothing else. Its packets for any other
address are logged and dropped, and the network drops those whose source
address it has elsewhere, such as an attached sandbox's, so a spoofed packet
cannot draw answers to the sandbox. It drops those from addresses no router
forwards from, such as loopback, multicast or broadcast addresses, and the
server answers no SYN from an address that cannot be one host's, as Linux
answers none.

## Running it locally

This is the internal test: the same world, with a sandbox attached the normal
way.

Build the world and the attach command:

```sh
cargo build -p honeypot-world -p fictionet-cli
```

Start the world. It prints its address and where it logs:

```sh
target/debug/honeypot --world unix:/tmp/honeypot.sock \
    --log /tmp/honeypot.jsonl --pcap /tmp/honeypot.pcapng
```

Attach a sandbox in a new network namespace. The sandboxes' subnet is
`10.0.0.0/24`, with the gateway and DNS at `10.0.0.1`:

```sh
sudo ip netns add agent
sudo target/debug/fictionet attach tun --world unix:/tmp/honeypot.sock \
    --name agent --netns /run/netns/agent \
    --ip-addr 10.0.0.2/24 --gateway 10.0.0.1 --dns 10.0.0.1
```

Anything in that namespace now reaches the server at `203.0.113.10`, and
nothing else:

```sh
sudo ip netns exec agent nc 203.0.113.10 22
sudo ip netns exec agent curl http://203.0.113.10/
```

Run the agent under test in the same namespace. Its every packet is in
`/tmp/honeypot.pcapng`, and its SYNs, payloads and bursts are in
`/tmp/honeypot.jsonl`, named `agent`. Linux clients send MP_CAPABLE when the
program opens an MPTCP socket, or through `mptcpize run`.

## The planned public setup

These are instructions for the deployment, which has not been done. Do not
run them before the deployment is approved, and check the cloud provider's
acceptable-use policy first.

The idea: the host's own kernel only forwards packets for the honeypot's
address and never terminates them. Every packet for that address goes through
a TUN device into the world.

1. **A cloud VM with two NICs.** The first is for the operators and stays in
   the root namespace. The second carries the honeypot's traffic.
2. **A kernel patched for CVE-2026-98432**, with MPTCP off on the host:

   ```sh
   sudo sysctl -w net.mptcp.enabled=0
   ```

3. **An edge network namespace** that holds the second NIC and forwards
   between it and the world. The edge namespace must have no address of the
   honeypot's own, so its kernel never answers for it. It answers ARP for the
   address with proxy ARP instead, and routes it to the TUN device:

   ```sh
   sudo ip netns add edge
   sudo ip link set eth1 netns edge
   sudo ip netns exec edge sysctl -w net.mptcp.enabled=0
   sudo ip netns exec edge sysctl -w net.ipv4.ip_forward=1
   sudo ip netns exec edge sysctl -w net.ipv4.conf.eth1.proxy_arp=1
   sudo ip -n edge link set lo up
   sudo ip -n edge link set eth1 up
   sudo ip -n edge route add default via <provider gateway> dev eth1 onlink
   ```

   `net.mptcp.enabled` is set per namespace, so it is set again in `edge`.

4. **The world**, with `--address` set to the address packets carry when they
   reach the NIC. On a provider that maps a public address to a private one,
   that is the private one.

   ```sh
   honeypot --world unix:/run/fictionet/honeypot.sock \
       --address <honeypot address> --internet 0.0.0.0/0 \
       --log /var/log/honeypot/honeypot.jsonl \
       --pcap /var/log/honeypot/honeypot.pcapng
   ```

5. **The internet attachment**: a TUN device in `edge`, routed into the world
   as `internet` (`Net::route("internet", 0.0.0.0/0)` in the world). Then route
   the honeypot's address to it in `edge`. Attach prints the device's name:

   ```sh
   sudo fictionet attach tun --world unix:/run/fictionet/honeypot.sock \
       --name internet --netns /run/netns/edge --no-resolv-conf
   sudo ip -n edge route add <honeypot address>/32 dev tun0
   ```

The world answers from the honeypot's address, and the edge namespace sends
those packets out through its default route.

A `cargo xtask honeypot-up` is planned to do all of this from one command,
without Docker.

## Dedicated raw virtio NIC

The `raw-virtio` feature connects a dedicated virtio NIC directly to this
world through `fictionet_host::raw`. The driver and bounded host pump own
all device polling outside the run. Complete Ethernet frames cross the
attachment before any Ethernet or IP parsing. Linux does not receive IP
packets from that assigned NIC; the honeypot's existing `internet`
attachment and simulated TCP stack handle them.

Run this only inside the disposable QEMU guest described in
[`host/README.md`](../../host/README.md), with `fictionet.rawnic=1` on its
kernel command line, an IOMMU, and the dedicated NIC already bound to
`vfio-pci`. The driver requires that guest setup. Build the example on the
host, then run the resulting binary in the guest:

```sh
cargo build -p honeypot-world --features raw-virtio --example raw_honeypot
```

```sh
./raw_honeypot 0000:00:03.0 ethernet.jsonl \
  --address 203.0.113.10 --internet 0.0.0.0/0 \
  --ssh 22 --http 80 --log honeypot.jsonl --pcap honeypot.pcapng
```

The first two arguments are the assigned NIC's PCI address and the raw
Ethernet log path. The remaining flags select the existing honeypot
configuration and IP logs. This example uses the NIC attachment; the
`--world` socket setting does not create a socket listener.

`ethernet.jsonl` records each complete frame as hexadecimal `bytes`, with
`direction` (`in` or `out`), world-clock `at_us`, and `lost` (records the
writer refused since the last accepted record). It retains malformed
frames, VLAN headers, unknown EtherTypes and Ethernet padding before the
world chooses whether to interpret them. Each accepted line is flushed;
partially written records are completed before the next record. Refused
records are counted and do not stop packet handling. `honeypot.pcapng`
continues to contain IP packets, and `honeypot.jsonl` records TCP options,
MPTCP negotiation and the normal observations.

The world answers ARP for its configured IPv4 address. Untagged IPv4 and
IPv6 packets addressed to the NIC or broadcast enter the existing IP
attachment, which limits delivery to the configured honeypot address.
VLAN and unknown EtherTypes remain in the raw log. A bounded table of
1024 source IP addresses learns each reply's destination MAC from the
incoming frame; an evicted source must send again before it receives
another reply. IPv6 peers need a static neighbor entry. The adapter does
not provision addresses, configure routing, or bind PCI devices.

Embedding applications can call `honeypot_world::start_raw` with a
`RawAttachment`, the usual configuration and observation sinks, and a
`Box<dyn Write + Send>` for raw JSON lines. Create and retain the
`RawPump` outside `fictionet::run`; only the raw attachment enters the
world. All driver and raw frame tests run in the QEMU harness:

```sh
cargo xtask rawnic target/rawnic-qemu
```
