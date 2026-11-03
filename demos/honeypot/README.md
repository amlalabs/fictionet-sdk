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
  120 seconds pass, as sshd's `LoginGraceTime` does.
- **HTTP** (`--http`, 80 by default): nginx's default page for one request,
  then it closes.

The MPTCP listener follows RFC 8684:

- A SYN with MP_CAPABLE that offers HMAC-SHA256 gets a SYN-ACK with
  MP_CAPABLE version 1 and a fresh random key. A SYN that offers a higher
  version gets version 1 back, as Linux answers it. The SYN-ACK asks for
  checksums only when the SYN did.
- Linux ignores MP_CAPABLE of version 0, with a key, with flag B, or with no
  HMAC-SHA256, and so does the honeypot: that connection is plain TCP. So is a
  SYN with both MP_CAPABLE and MP_JOIN, and a connection whose third ACK does
  not echo the keys.
- After the handshake the server speaks plain TCP, as an MPTCP host does once
  a connection has fallen back. It never takes a second subflow, but it
  answers MP_JOIN as Linux does. When the token names one of the server's open
  connections, the SYN gets a SYN-ACK with MP_JOIN, the server's HMAC and a
  random number. The join is refused at its third ACK, which carries the
  client's HMAC, with a RST that has MP_TCPRST "administratively prohibited".
  When the token names none, the SYN gets that RST at once, with
  "MPTCP-specific error".
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
| `answer` | A SYN-ACK or RST from the world | Flags, every TCP option in order, and each MPTCP option decoded, such as the key the server issued |
| `burst` | A source's SYNs, or its SYNs with MP_JOIN, reach the burst threshold | Source address, which kind, how many, and the window |

Times are `at_us`, microseconds since the Unix epoch. Keys, tokens and HMACs
are hex. Each MPTCP option is decoded with every field the codec reads, and
its bytes are in `options` too, so signatures can be run over either. An
MP_JOIN SYN says whether its token names an open connection (`token_known`).
An option of kind 30 that does not read as MPTCP is logged as `malformed`,
with the reason and its bytes. A SYN without `gap_us` is a source's first
within the burst window; the `at_us` of its lines gives longer gaps.

The world writes each packet to the capture and the log before passing it on,
so a packet the world drops is still logged. The capture has each packet as it
crossed. The log reads whole packets: IP fragments are put together first, as
the world puts them together. If either file cannot be written, the world
stops.

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
The world keeps state for a source only while that source has a SYN within the
burst window, and an MPTCP token only while its connection is open. A flood
from spoofed addresses cannot grow either past what one window or the open
connections hold.

Spoofed SYNs cannot shut real attackers out either. Each port holds 4,096
handshakes. Past that, the server answers with SYN cookies, as Linux does, and
keeps nothing until the ACK that returns one. A handshake whose last ACK never
comes gets six SYN-ACKs, at 0, 1, 3, 7, 15 and 31 seconds, and is dropped at 63
seconds without a RST, as on Linux.

The internet reaches the server and nothing else. Its packets for any other
address are logged and dropped, and the network drops those whose source
address it has elsewhere, such as an attached sandbox's, so a spoofed packet
cannot draw answers to the sandbox.

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
