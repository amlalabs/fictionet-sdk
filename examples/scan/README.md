# nmap finds a five-host range. One host is a real server.

This example is a small office subnet for a port scanner. The agent runs
`nmap` in its sandbox and scans `10.0.0.0/24`. It finds five hosts. Four
are simulated machines that the world builds from Fictionet's stdlib. The
fifth is a real server, attached to the world as a sandbox of its own and
routed into the same subnet. Compose runs it as a container with nginx
and OpenSSH. [The in-process demo](#the-in-process-demo) runs it as a VM at
the same address. From the scanner's side there is no difference between
them: every host answers pings, every closed port answers a SYN with a RST,
and every open port answers nmap's service probes.

## What is in the world

`world/src/lib.rs` builds the network with `net::Net`. The simulated machines are
`Host`s on the office subnet, the scanner is a sandbox in the `Net`'s own
subnet, and the server is wired in with `Net::route` as a trusted host
at its fixed address, so the scanner can reach it:

| Address | Host | Open TCP ports |
|---|---|---|
| 10.0.0.10 | `www`, simulated | 22 (OpenSSH banner), 80 (HTTP, Apache) |
| 10.0.0.11 | `mail`, simulated | 25 (Postfix), 110 (Dovecot POP3), 143 (Dovecot IMAP) |
| 10.0.0.12 | `files`, simulated | 21 (vsftpd), 22 (OpenSSH banner) |
| 10.0.0.13 | `printer`, simulated | 80 (HTTP, lighttpd), 631 (HTTP, CUPS) |
| 10.0.0.50 | `server`, a real server | 22 (OpenSSH), 80 (nginx) |
| 10.0.9.2 | `scanner`, the agent | |

Each simulated machine is a `Host` with a small `Service` on each open
port (`serve::Service`): one sends a banner when a client connects, the
other answers each HTTP request with a page. The banners are what the real
programs send, so `nmap -sV` names them. `Net` gives every `Host` its own
network endpoints: a `tcp::endpoint`, a `udp::endpoint` with no ports open,
and ping replies. Ports with no service need no code: the stdlib's
TCP answers a SYN to a closed port with a RST, as a kernel does, and an
address with no host gets "host unreachable".

The scanner sits in a subnet of its own, `10.0.9.0/24`. Scanning
`10.0.0.0/24` from inside that range would list the scanner itself as a
sixth host.

The world puts its parts in groups with `Cx::group` (see "Groups" in the
`fictionet::Cx` docs), so the dashboard draws "scanner", "real server" and
"simulated hosts", with one group per machine inside the last. Each
sandbox goes through a 1 or 2 ms `delay` started in its own group. The
scanner also has a passive probe tap in that group. The tasks that read the
sandboxes belong to these groups, so the sandboxes are drawn there too.

## Crate layout

`world/` is the `scan-world` crate. `world/src/lib.rs` exposes `office()`,
`start()` and `world()`. `world/src/main.rs` runs the world on a socket:

```text
cargo run -p scan-world -- /run/fictionet/world.sock
```

Integration tests live in `world/tests/`. Run all tests with `cargo test -p scan-world`.
The golden report is in `world/tests/golden.txt`.

## Attaching a real server

The attachment is named `server`, whether it comes from the Compose container
or a VM. A server VM uses a card made with
`Link::new(Family::Serve(SERVER_LEASE), Family::Off, mtu)`. Bridge its Ethernet
frames through that card to the `SERVER` attachment. `SERVER_LEASE` gives it
10.0.0.50/24, gateway 10.0.0.1 and DNS 10.0.9.1.

The scanner attaches as `scanner`. A scanner VM's card uses `Family::FromWorld`.
The world's DHCP leases it an address in `SCANNER_SUBNET` (10.0.9.0/24).
An integrator can add hosts with `.host(...)` or `.resolve(...)`, and trusted
routes with `.route(...)`, to `office()` before calling `start()`. This lets a
server reach an apt mirror and lets an admin jump host reach the server.
Other attachment names pass through unchanged.

## Port facts

The scanner's tap watches IPv4 packets and passes them through unchanged.
A probe is an office-bound TCP SYN with ACK, RST and FIN clear, a UDP
packet, or an ICMP echo request (type 8, code 0). Each host has at most one
echo row, with protocol `icmp` and port 0. A matching echo reply marks it
`open`: the host answered. Echo replies must match the latest request's
identifier and sequence number. Any ICMP destination unreachable quoting
that request marks the echo row `unreachable`.

A matching TCP SYN-ACK or UDP reply means `open`. A matching TCP
RST-ACK or ICMP port-unreachable means `closed`. Other ICMP destination
unreachable codes mean `unreachable`. Each reply must match the latest
probe's source port and, for TCP, its sequence number. Traffic outside the
office, stale replies and noninitial fragments do not update the map.

A row starts `unanswered`. Repeated probes keep the last answered state.
`scan.port` facts report new rows and state changes, with the previous state,
probe count, first and last probe times, and revision. A new row's previous
state is null. Times are whole milliseconds since the run began. A port scan
makes thousands of these facts, so each is a repeatable fact
(`Event::repeat`): the host, protocol, state and previous state identify it,
and the port, times, probe count and revision are its detail. A dashboard
keeps them in its budget for repeatable facts, so they never evict the
run's other events.

`start()` returns a shared `Ports` handle. `snapshot()` returns the office
labels and sorted rows. `changes_since(revision)` returns the latest version
of each row changed since that revision. Every tracked probe and state change
advances the map revision. Both projections include the last change time and the
untracked count. Their `MAX_JSON_BYTES` constants bound compact JSON output.

The map holds at most 16,384 rows and never evicts them. Further probes for
new keys increment `untracked`; existing rows still update. The first such
probe emits one `scan.full` fact with `max_rows`.

The tap also keeps a banner for each open TCP port: the first data the host
sent to the scanner. It reads only the first data segment of a connection,
the one that follows the SYN-ACK, and never reassembles a stream. The banner
is that segment's first line, at most 160 bytes. When the data starts with
an HTTP status line, the banner is the status line and the `Server` header's
value. Bytes outside printable ASCII show as `\xHH`, and a backslash as `\\`.
A `scan.banner` fact marks each new banner, with its host, port, text, server
value, time and revision. A new banner advances the map revision. A later
connection never replaces a kept banner. Snapshots and changes list banners
sorted by host, then port. The map keeps at most 1,024 banners and never
evicts one; further banners only increment `untracked_banners`.

## Running it

The world's optional second argument opens the observation socket with
`fictionet_observe::serve`. For a local run, use separate terminals:

```sh
cargo run -p scan-world -- /run/fictionet/world.sock /run/fictionet/observation.sock
fictionet observe --observation unix:/run/fictionet/observation.sock watch
```

`compose.yaml` passes both socket paths and runs the world and two
sandboxes. See [Fictionet Observe](../../observe/README.md) for capture
limits.

- `world` runs `scan-world`, with no network at all. Its world and
  observation sockets are on a shared volume.
- `container-attach` runs `fictionet attach --name server --type tun` for the
  real container, at 10.0.0.50. The `container` service (nginx and OpenSSH on
  Alpine) joins its network namespace, so its only interface is `tun0`.
- `scanner-attach` does the same for the agent, at 10.0.9.2, and the
  `scanner` service, with nmap, joins it. nmap needs `NET_RAW` to send SYN
  scans and pings, and the compose file grants it. The scanner does not
  see the world socket.

From this folder:

```text
$ docker compose up -d --build --wait
$ docker compose exec scanner nmap -sn -n 10.0.0.0/24
Starting Nmap 7.93 ( https://nmap.org ) at 2026-10-03 04:07 UTC
Nmap scan report for 10.0.0.10
Host is up (0.0042s latency).
Nmap scan report for 10.0.0.11
Host is up (0.0043s latency).
Nmap scan report for 10.0.0.12
Host is up (0.0042s latency).
Nmap scan report for 10.0.0.13
Host is up (0.0042s latency).
Nmap scan report for 10.0.0.50
Host is up (0.0064s latency).
Nmap done: 256 IP addresses (5 hosts up) scanned in 3.55 seconds
```

The real container answers a little later than the simulated hosts: its
packets cross `fictionet attach` and a real kernel, where the simulated
hosts answer inside the world. Then a SYN scan of the first 1,024 ports,
with service detection. `--max-rate 300` only slows the scan down, so
that it is easy to follow:

```text
$ docker compose exec scanner nmap -sS -sV -n -p 1-1024 --max-rate 300 10.0.0.0/24
Starting Nmap 7.93 ( https://nmap.org ) at 2026-10-03 03:55 UTC
Nmap scan report for 10.0.0.10
Host is up (0.0041s latency).
Not shown: 1022 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for 10.0.0.11
Host is up (0.0041s latency).
Not shown: 1021 closed tcp ports (reset)
PORT    STATE SERVICE VERSION
25/tcp  open  smtp    Postfix smtpd
110/tcp open  pop3    Dovecot pop3d
143/tcp open  imap    Dovecot imapd
Service Info: Host:  mail.corp.test

Nmap scan report for 10.0.0.12
Host is up (0.0041s latency).
Not shown: 1022 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for 10.0.0.13
Host is up (0.0041s latency).
Not shown: 1022 closed tcp ports (reset)
PORT    STATE SERVICE VERSION
80/tcp  open  http    lighttpd 1.4.69 (Linux)
631/tcp open  ipp     CUPS 2.4

Nmap scan report for 10.0.0.50
Host is up (0.0062s latency).
Not shown: 1022 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.7 (protocol 2.0)
80/tcp open  http    nginx 1.26.3

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 256 IP addresses (5 hosts up) scanned in 36.36 seconds
```

"closed tcp ports (reset)" on every host is the RST at work: nmap reports
the ports closed, not filtered. The last host is the real container, and
its versions come from the real nginx and OpenSSH.

`docker compose exec world fictionet observe --observation
unix:/run/fictionet/sock/observation.sock watch` follows the scan from a
shell. `cargo xtask demo scan` below shows the same world on its own page.

Stop it all and remove its volume with `docker compose down -v`.

## The in-process demo

`cargo xtask demo scan` runs the same world in one process with two Ubuntu
24.04 microVMs from the shared kit (see [the demos](../../demos/README.md)).
It needs KVM and Chromium. The Compose stack above is a separate way to run
the world.

- The workstation is the scanner. It runs nmap, and a script types three
  nmap steps into its terminal: host discovery, a SYN scan of ports 1 to
  1,024 with service detection, and OS detection. The agent is scripted; no
  model runs.
- The office server is the real host at 10.0.0.50, with nginx and OpenSSH.
  Its terminal follows nginx's access log and sshd's journal.

The page shows both VMs in the workspace and three panels of its own:

- **Office**: the story's steps, then the scanner and the office subnet as
  256 cells. A cell lights when the port map shows a probe to its address.
  A card appears for each machine whose address answered. When all five
  have answered, the demo emits one `scan.discovered` fact, and the page's
  header shows that moment.
- **Ports**: each answering host's 1,024 ports, filled in from the port map,
  and a view of only the ports open on any host.
- **Services**: one row per open port, with the banner the tap saw on the
  wire beside nmap's service, product and version, and nmap's OS guess for
  each host.

The standard Packets, Events, Map, Left the box, Containment, and Labels
and export panels are there too.

The port map and banners come from the tap (see Port facts above). nmap's
names and OS guesses come from its XML output, which the demo reads after
each step, and the page labels them "nmap says". The gate reads all three
through the page's API.

The command prints each step's command and nmap's findings, then the page
checks, and ends with `every required check passed`. nmap's XML reports, the
port map after each step and the screenshots go to
`demos/downloads/cloudimage/shots/`.

`cargo run -p fictionet-demo --example scan_page` serves the same page
without VMs, to work on it: an in-world scanner sends the story's probes, a
stand-in answers at 10.0.0.50, and nmap's reports are the ones recorded in a
KVM run.
