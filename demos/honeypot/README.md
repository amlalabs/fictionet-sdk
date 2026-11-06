# MPTCP honeypot

A Fictionet world that looks like a Linux server with an MPTCP listener, and
logs everyone who tries it. It is built for CVE-2026-98432, a use-after-free
in the Linux kernel's IPv4 TCP connection setup. It observes options-bearing
SYN retransmissions separately from MPTCP connections that send no data.
The honeypot contains no exploit code.

Nothing in the world is a real kernel. The server is Fictionet's TCP stack
and world code, and it never executes client commands. The deployment host
still needs a fixed kernel: disabling MPTCP does not protect ordinary IPv4
TCP listeners.

## What the server presents

One host at a public IPv4 address (`--address`), and at a public IPv6
address too when one is given (`--address-v6`). Caddy's HTTP ports accept MPTCP;
SSH uses ordinary TCP. Both addresses serve the same ports, and the log has the same
lines for both. The IPv4 address is always there, because the flaw is in
IPv4 connection setup. The IPv6 address is optional, as many servers have
none. The internet comes in by one attachment that carries both families,
from `0.0.0.0/0` and `::/0` unless `--internet` narrows one of them.

- **SSH** (`--ssh`, 22 by default): Ubuntu 24.04's OpenSSH 9.6 identification,
  encrypted authentication and a simulated bash prompt. Submitting the first
  line disconnects the entire SSH connection before any command runs. Exec
  and subsystem requests, including SFTP, disconnect immediately.
  `--ssh-auth accept` accepts any password or signed public key;
  `--ssh-auth reject` refuses credentials; `--ssh-auth password:VALUE` requires
  that password or a signed public key. The default is `accept`. `none` is
  always refused. Authentication has a 120-second deadline and six-failure
  limit. Forwarding is refused.
- **HTTP** (`--http`, 80 by default): the official Caddy 2.11.9 package's page,
  with MPTCP, persistent HTTP/1.1, a 300-second idle timeout and 15-second TCP
  keepalives. It has no request-count limit per connection. The untouched
  package site has no HTTPS listener on 443.
- **nginx comparison** (`--http-profile nginx`): Ubuntu's nginx page over
  ordinary TCP, with up to 1,000 requests, 75 seconds between requests and no
  TCP keepalives. The default profile is `--http-profile caddy`.

SSH offers implemented algorithms in OpenSSH preference order: Curve25519,
P-256 and P-384 key exchange, ChaCha20-Poly1305 and AES-GCM, and the demo's
Ed25519 host key. Core also supports RSA SHA-2 host keys and user signatures.
This is a subset of OpenSSH's full proposal: it does not offer post-quantum KEX,
finite-field DH, CTR ciphers, UMAC or compression. The reference preferences
and source citations live in `fictionet_extras::ssh::Profile`.

The line editor supports echo, backspace, Control-C, Control-D and Control-U.
Raw input and exec requests are logged before disconnecting. Empty lines,
Control-D, EOF and overlong input also disconnect. There is no command
interpreter, SFTP filesystem or guest shell.

The transport profile targets Ubuntu 24.04's Linux 6.8 kernel.
Listener backlogs match Ubuntu 24.04: 4,096 for systemd's `ssh.socket`
and Caddy, capped by the kernel's `net.core.somaxconn`; nginx uses 511.
The unmodified [Caddy page](src/caddy.html) comes from
[caddyserver/dist](https://github.com/caddyserver/dist/tree/master/welcome),
under the [Apache License 2.0](../../LICENSE-APACHE).

The MPTCP listener follows RFC 8684, and reads MPTCP options as Linux does:
an option Linux ignores counts for nothing, and of several that count the
last one wins.

Both ordinary and MPTCP SYN-ACKs carry IPv4 Record Route, Timestamp, and reversed source-route
options through the Linux echo helper in `fictionet-extras`. The core codec
and listener hook contain only protocol representation and plumbing.

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
  window 0, and MP_TCPRST as its only option. Any other RST the server
  sends on an MPTCP subflow carries MP_TCPRST too, with "unspecified error"
  unless it has a reason, as Linux sends it.
- TCP options go out in the order and with the padding Linux gives them. A
  SYN-ACK carries Maximum Segment Size, SACK-Permitted, Timestamps, a
  No-Operation and Window Scale, in that order, then any MPTCP option.
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
| `syn` | A SYN into the world | Source and destination, flags, the initial sequence number, every IPv4 and TCP option in order, `options_fault` if the options did not all read, each MPTCP option decoded, the payload in hex when the SYN carried one, and `gap_us` since the same source's previous SYN when that SYN was within the burst window |
| `segment` | Any other segment in with a payload, a FIN, a RST or MPTCP options | Flags, sequence number, every TCP option in order, `options_fault`, each MPTCP option decoded, and the payload in hex |
| `answer` | A RST from the world, or the SYN-ACK that first answers a SYN | Flags, every TCP option in order, and each MPTCP option decoded, such as the key the server issued |
| `burst` | A source's SYNs, or its SYNs with MP_JOIN, reach the burst threshold | Source address, which kind, how many, and the window |
| `ssh` | An SSH protocol or application event | Connection identity, timestamp, client version and proposal, credentials and signature validity, channel requests, terminal settings, raw input/output bytes, stderr and exit status |
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

An `ip_options_retransmit` record means a SYN with IPv4 options was followed
by the same initial sequence number on the same attachment and connection
tuple. Its typed `phase` distinguishes `offered`, `pending` and `completed`:
no answer, a matching SYN-ACK, or the matching third ACK observed. First and
previous SYN times, repeat gap, SYN-ACK time, completion time and time since
completion preserve proximity without inventing an attack threshold. Correlation
expires at the original 63-second first-SYN deadline; a close or a new initial
sequence number on that tuple ends it. An `mptcp_no_data` record independently reports an MP_CAPABLE
offer that closed or reached the existing 63 second observation timeout
without inbound payload during that observation interval. Its `completed`
field distinguishes attempts whose handshake ACK was observed. Neither
signal proves exploitation.

A burst is at least `--burst-syns` SYNs (8 by default), or that many SYNs
with MP_JOIN, from one source within `--burst-window-ms` (100 by default).
Every SYN retains its typed IPv4 and TCP options regardless of these signals;
`ipv4_options_raw` also preserves the complete IPv4 option bytes and padding.

### Hostile input

Internet attackers send whatever they like, so every reader checks lengths.
The world keeps burst state for a source only while that source has a SYN
within the burst window. It tracks unanswered SYNs and probe attempts for up
to 63 seconds, the listener's handshake timeout, and an MPTCP token only while
its connection is open. Burst, answer and probe state expires even when traffic is
quiet, so a flood from spoofed addresses leaves no permanent state.

Spoofed SYNs cannot shut real attackers out either. SSH and Caddy hold 4,096
pending handshakes each; the nginx profile holds 511. Past that, the server answers with SYN cookies and
keeps nothing until the ACK that returns one. A handshake whose last ACK never
comes gets six SYN-ACKs, at 0, 1, 3, 7, 15 and 31 seconds, and is dropped at 63
seconds without a RST, as on Linux. A closed connection whose client never
closes its side is forgotten a minute after the client acknowledged the
server's FIN, whatever the client sends meanwhile, as on Linux.

Each connection's initial sequence number is a keyed hash of its addresses
and ports plus a clock, as Linux makes it (RFC 6528). SYN cookies have a key
of their own. These mechanisms make blind spoofing harder. A matching
handshake ACK provides evidence of return-path reachability, not
authentication or proof of the sender's identity. A SYN needs no handshake,
so the source of a `syn` or `burst` line is only what the sender wrote and
may be spoofed.

The internet reaches the server and nothing else. Its packets for any other
address are logged and dropped, and the network drops those whose source
address it has elsewhere, such as an attached sandbox's, so a spoofed packet
cannot draw answers to the sandbox. It drops those from addresses no router
forwards from, such as loopback, multicast or broadcast addresses, and the
server answers no SYN from an address that cannot be one host's, as Linux
answers none.

## A NIC of its own

With the `raw-virtio` feature, the world can own a virtio network card
outright. A driver in `fictionet_host` reads whole Ethernet frames from the
card and hands them to the world. The Linux kernel on the machine never
sees the card's traffic, so it never runs its IP or TCP code on it. The
world answers in its place, through the same `internet` attachment as
above.

For now the driver runs only in a QEMU guest set up for it, as
[`host/README.md`](../../host/README.md) describes. The guest's kernel
command line has `fictionet.rawnic=1`, it has an IOMMU, and the card is
already bound to `vfio-pci`. Build the example on the host, and run it in
the guest:

```sh
cargo build -p honeypot-world --features raw-virtio --example raw_honeypot
```

```sh
./raw_honeypot 0000:00:03.0 ethernet.jsonl \
  --address 203.0.113.10 --gateway 203.0.113.1 \
  --address-v6 2001:db8:113::10 --gateway-v6 fe80::1 \
  --ssh 22 --http 80 --log honeypot.jsonl --pcap honeypot.pcapng
```

The first argument is the card's PCI address, and the second is where to
log Ethernet frames. The flags are the honeypot's usual ones. `--gateway`
sets the raw adapter's IPv4 default gateway (default `203.0.113.1`).
`--gateway-v6` sets its IPv6 default gateway, such as `fe80::1` on Hetzner.
Without it, the gateway is the first router that advertises itself, as on
AWS and Google Cloud. `--world` is not used: there is no socket to attach
to.

`ethernet.jsonl` has one line per frame, both ways, before the world reads
it: `direction` (`in` or `out`), `at_us`, the frame in hex as `bytes`,
`lost`, how many lines the file could not take since the last one it did,
`rx_queue_dropped`, frames discarded by the pump's full receive queue,
and `tx_queue_dropped`, frames refused by the full transmit queue
since the last accepted log record. Both counts survive a refused log write.
`nic_rx_dropped` is null: the driver does not expose device or backend loss
counters, so those losses cannot be inferred from the software queue count.
So it keeps frames the world ignores: VLAN tags, unknown EtherTypes,
malformed headers and Ethernet padding. `honeypot.pcapng` and
`honeypot.jsonl` are as above.

The world plays a Linux host on the link, through `fictionet`'s
`ethernet::Host`:

- It answers ARP for its IPv4 address, to the sender the request names.
- With an IPv6 address, it also has a link-local address made from the
  card's MAC. Before it uses either address, it joins their solicited-node
  groups with an MLDv2 report and checks that no other node has them
  ([duplicate address detection](https://www.rfc-editor.org/rfc/rfc4862#section-5.4)).
  Then it answers neighbor solicitations for them, and checks from other
  nodes are answered to all nodes. An address another node has is never
  used.
- Untagged IPv4 and IPv6 packets to one of its usable addresses, in frames
  sent to its MAC address, broadcast, or to a multicast group it joined, go
  on to the `internet` attachment. Every other frame is only logged.
- It broadcasts an [ARP request](https://www.rfc-editor.org/rfc/rfc826.html)
  for the IPv4 gateway at startup and asks again every second until
  answered, matching [Linux's initial ARP retransmission interval](https://github.com/torvalds/linux/blob/master/net/ipv4/arp.c).
  It finds the IPv6 gateway's MAC the same way, with
  [neighbor solicitations](https://www.rfc-editor.org/rfc/rfc4861#section-7.2).
  Without `--gateway-v6`, it first sends router solicitations, and takes the
  first router that advertises itself as its gateway for as long as the
  advertisement says. Each gateway's MAC is learned from that gateway's own
  messages. Traffic from other senders cannot replace it. Once known, it
  is checked again as RFC 4861 section 7.3 says.
- It sends every reply to the gateway of its family, whatever the
  destination IP address. It drops replies until that gateway is known,
  without queuing them. It has no other neighbors or on-link routes.
- It drops replies longer than 1,500 bytes, and does not fragment them. The
  IP capture still has them. It drops any frame, its own ARP and neighbor
  discovery included, while the card's transmit queue is full.

The world does not set up addresses or routes, or bind PCI devices.

A program that embeds the honeypot calls `honeypot_world::start_raw` with a
`RawAttachment`, the usual configuration and sinks, and a writer for the
Ethernet log. It opens the `RawPump` before `fictionet::run` and keeps it
for the run. Only the attachment goes into the world.

Every test of the driver and of raw frames runs in QEMU:

```sh
cargo xtask rawnic target/rawnic-qemu
```

## SSH through the world socket

Build the world and the stdio connector on the home volume:

```console
systemd-run --user --scope -p MemoryMax=32G env CARGO_TARGET_DIR="$PWD/target" cargo build -p honeypot-world -p xtask
./target/debug/honeypot --world unix:/tmp/honeypot.sock --ssh-auth password:ubuntu --log /tmp/honeypot.jsonl --pcap /tmp/honeypot.pcapng
```

In another terminal, connect without configuring any host network interface:

```console
ssh -o 'ProxyCommand=./target/debug/xtask ssh-connect /tmp/honeypot.sock %h %p' ubuntu@203.0.113.10
```

Use `-tt` for a terminal and `-i` for a key. An interactive session shows a
prompt and hangs up on the first submitted line; `ssh ... id` and `sftp`
hang up immediately. The connector joins the Unix relay, obtains a simulated
DHCP lease, and carries its TCP packets through the world. Its stdout is only
the SSH byte stream. Stop the world by its own process ID when finished.

Each transcript record has a wall-clock `at_us` and a nested `ssh` event with
run-relative microseconds. Byte arrays preserve commands, credentials and
streams exactly. Output records are emitted when queued bytes enter SSH
packets, so their order respects channel flow control. Input and output can be
replayed by connection and channel without inspecting encrypted packet data.
