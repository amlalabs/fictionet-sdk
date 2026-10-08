# nmap finds a five-host range. One host is a real container.

This example is a small office subnet for a port scanner. The agent runs
`nmap` in its sandbox and scans `10.0.0.0/24`. It finds five hosts. Four
are simulated machines that the world builds from Fictionet's stdlib. The
fifth is a real container running nginx and OpenSSH, attached to the world
as a sandbox of its own and routed into the same subnet. From the
scanner's side there is no difference between them: every host answers
pings, every closed port answers a SYN with a RST, and every open port
answers nmap's service probes.

## What is in the world

`main.rs` builds the network with `net::Net`. The simulated machines are
`Host`s on the office subnet, the scanner is a sandbox in the `Net`'s own
subnet, and the container is wired in with `Net::route` as a trusted host
at its fixed address, so the scanner can reach it:

| Address | Host | Open TCP ports |
|---|---|---|
| 10.0.0.10 | `www`, simulated | 22 (OpenSSH banner), 80 (HTTP, Apache) |
| 10.0.0.11 | `mail`, simulated | 25 (Postfix), 110 (Dovecot POP3), 143 (Dovecot IMAP) |
| 10.0.0.12 | `files`, simulated | 21 (vsftpd), 22 (OpenSSH banner) |
| 10.0.0.13 | `printer`, simulated | 80 (HTTP, lighttpd), 631 (HTTP, CUPS) |
| 10.0.0.50 | `container`, a real container | 22 (OpenSSH), 80 (nginx) |
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
`fictionet::Cx` docs), so the dashboard draws "scanner", "real container" and
"simulated hosts", with one group per machine inside the last. Each
sandbox goes through a 1 or 2 ms `delay` started in its own group: the
delay is the task that reads the sandbox, so the sandbox is drawn in that
group too.

## Running it

`compose.yaml` runs the world, the two sandboxes and the dashboard:

- `world` runs `main.rs`, with no network at all. Its only door is the
  world socket on a shared volume.
- `container-attach` runs `fictionet attach --type tun` for the real
  container, at 10.0.0.50. The `container` service (nginx and OpenSSH on
  Alpine) joins its network namespace, so its only interface is `tun0`.
- `scanner-attach` does the same for the agent, at 10.0.9.2, and the
  `scanner` service, with nmap, joins it. nmap needs `NET_RAW` to send SYN
  scans and pings, and the compose file grants it. The scanner does not
  see the world socket.
- `dashboard` runs `fictionet dashboard` on the socket, published on
  `127.0.0.1:7880` only (`SCAN_DASHBOARD_PORT` picks another port).

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
that it is easy to follow in the dashboard:

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

Open http://127.0.0.1:7880/ while the scan runs to watch it. The scanner's
link lights up, and packets fan out from the router to the five hosts.
Double-click a host's group to open it, click the scanner's link to see
the SYNs go out and the RSTs come back, and drag any box to move it.
Closing "simulated hosts" draws its four links as one line, and that
line's packet list merges all four.

Stop it all and remove its volume with `docker compose down -v`.

## Recording the dashboard

`record.sh` builds and starts the stack, records the dashboard while nmap
runs, and removes the stack again. It needs Docker, `uv` and `ffmpeg`:

```text
$ CHROMIUM=/usr/bin/chromium examples/scan/record.sh /tmp/scan-recording
```

`record.py` drives Chromium with Playwright and records its screen. It
puts a terminal panel beside the dashboard with nmap's real output, runs
host discovery and then the port scan, and uses the dashboard while the
scan runs: it opens a group, opens the scanner's link and a RST in it,
closes a group and opens its merged packet list, and drags a box and a
group. The output folder gets `dashboard.webm` as recorded,
`dashboard.mp4` (H.264), a smaller `dashboard.gif`, and `nmap.txt` with
the two scans' output. The recording is about 67 seconds long.
