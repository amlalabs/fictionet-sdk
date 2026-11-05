# Ubuntu comparison

The current Caddy persona and benign IPv4-option comparison are in
[Caddy and IPv4 options](#caddy-and-ipv4-options). The earlier sections retain
the nginx measurements and describe the honeypot at those earlier revisions.

Measured on November 5, 2026 with `cargo xtask honeypot-diff`. The reference
guest booted `6.8.0-147-generic` and reported `linux-generic 6.8.0-147.147`,
`openssh-server 1:9.6p1-3ubuntu13.20`, and `nginx 1.24.0-2ubuntu7.19` after
installing current updates. `/proc/sys/net/mptcp/enabled` read `1`.

The probe guest used Nmap 7.94SVN. Its two isolated QEMU socket links reached
Ubuntu at `192.0.2.10` and the honeypot at `198.51.100.10`; the latter ran in
socket mode beside the guests. Probes originated only in the probe guest.
The same fixed packet construction was used for both targets, with their
respective addresses. Nmap received the same command-line arguments but adapts
its packet sequence to responses. [README.md](README.md#comparing-with-ubuntu-locally)
gives the commands. The observations from this session are retained under
`logs/honeypot-diff/`; subsequent runs write under `target/honeypot-diff/share/`.

## Baseline

The original honeypot was built from an archived copy of `698b645d3`, with a
separate Cargo target directory. Raw observations are in
`logs/honeypot-diff/before/`. The additional idle and repeated challenge
ACK observations are in `logs/honeypot-diff/timing/`. A further run against
the original binary, `logs/honeypot-diff/baseline-final/`, exercised the final
collector, including the real SSH client and nonzero-code ICMP echo. It still
reported no exact Nmap OS match.

“Same” below compares the listed fields, not byte-for-byte packets across
different hosts. Addresses, checksums, random initial sequence numbers, and
absolute timestamp values remain unmodified in the saved wire evidence.
Flags use hexadecimal. Payload lengths exclude the IP and ICMP headers.

| Probe | Ubuntu reply | Original honeypot reply | Same or different |
| --- | --- | --- | --- |
| Nmap `-O -sS -Pn -n -p22,80,81 --max-os-tries 1` | Ports 22/80 open, 81 closed; identifies “Linux 4.15 - 5.8”; distance 1 hop | Same port states/distance; “No exact OS matches”; fingerprint includes `IE(R=N)` | Different |
| SYN to SSH 22 | SYN-ACK `0x12`, TTL 64, DF, ID 0, window 65160; MSS 1460, SACK, TS, NOP, WS 7 | Same listed fields and option order | Same fields |
| SYN to HTTP 80 | Same SYN-ACK shape as SSH | Same listed fields and option order | Same fields |
| Timestamps across the two open ports | TS 278629561 then 278630313, advancing 752 ms | TS 1421725891 then 552221469 | Different |
| SYN to closed TCP 81 | RST-ACK `0x14`, sequence 0, ACK 305419897, window 0, no options, TTL 64, DF, ID 0 | Same listed fields | Same fields |
| Bare ACK to SSH 22 | RST `0x04`, sequence 2271560481, ACK 0, window 0, no options, TTL 64, DF, ID 0 | Same listed fields | Same fields |
| Bare ACK to closed TCP 81 | Same RST shape as SSH | Same listed fields | Same fields |
| ECN SYN, IP Not-ECT | SYN-ACK-ECE `0x52`, window 65160, normal option order | Same listed fields | Same fields |
| ECN SYN, IP ECT(0) | SYN-ACK `0x12`, no ECE | SYN-ACK-ECE `0x52` | Different |
| ECN SYN, IP CE | SYN-ACK `0x12`, no ECE | SYN-ACK-ECE `0x52` | Different |
| ICMP echo, 32-byte payload | Echo reply, type/code 0/0, length 60, TTL 64, DF clear, ID 15511 | Same type/code, length and TTL; DF clear; copies request ID 4660 | Different |
| ICMP echo, 1472-byte payload | Echo reply, length 1500, TTL 64, DF clear, ID 16174 | Same length and TTL; DF clear; copies request ID 4660 | Different |
| UDP to closed port 81 | ICMP 3/3, length 60, TTL 64, TOS 192, DF clear, ID 16183; includes original datagram | ICMP 3/3, length 60, TTL 64, TOS 0, DF set, ID 0; includes original datagram | Different |
| MPTCP SYN, MP_CAPABLE v1 | Ordinary SYN-ACK, window 64240, MSS 1460; no MPTCP option | SYN-ACK with MSS and MP_CAPABLE containing a server key | Different |
| In-window SYN on established HTTP connection | ACK, length 52, window 510, NOP/NOP/TS options, nonzero IP ID | ACK, length 40, window 2048, no options, ID 0 | Different |
| Repeat established SYN after 750 ms | Another ACK; IP IDs 11978 then 11979 | No second ACK within the next 750 ms | Different |
| SSH version exchange | `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20`, followed by KEXINIT with all ten name-lists | `Ubuntu-3ubuntu13.5`; no KEXINIT within the client's 5-second read deadline | Different |
| HTTP/1.1 `GET /`, then `GET /missing` on one connection | 200 with 615-byte page, then 404 with 162-byte body; both keep-alive | First 200 with the same page, `Connection: close`; EOF before second response | Different |
| HTTP response headers for `/` | Includes Last-Modified, ETag and Accept-Ranges | Those three headers absent | Different |
| Idle after a complete HTTP response | EOF after 74970 ms | EOF after 40 ms | Different |

The reference's enabled MPTCP setting did not make its default SSH listener
negotiate MP_CAPABLE. That row reports the observed reply without changing
the reference server configuration to obtain a match.

The installed nginx configuration contained no `keepalive_timeout` override.
The measured idle close was about 75 seconds, despite the requested 65-second
target. Both the configuration dump and timed observation are retained.

## After changes

The full run used the modified honeypot after the transport, service and
1,000 Hz identification-clock changes. Both targets returned one correlated
reply for every one of the fourteen fixed packet probes, plus the repeated
established-connection SYN. Unrelated packets were recorded separately.
The guest kernel configuration reported `CONFIG_HZ=1000`; its boot log reported
32,768 IP-identification buckets.

Evidence is in `logs/honeypot-diff/final/`: `reference-raw.json` and
`imitation-raw.json` contain every fixed request and response in hex;
the `*-nmap.json` files include packet traces; `*-ssh.json` holds the raw
KEXINIT and its decoded lists; `*-ssh-client.stderr.log` holds OpenSSH's trace;
`*-http.json` and `*-http-idle.json` hold the HTTP exchanges and timing.
The idle-close and backlog rows below use the later targeted checks described
below; the other rows retain the full run's observations.

| Probe | Ubuntu reply | Modified honeypot reply | Same or different |
| --- | --- | --- | --- |
| Nmap OS scan | Identifies “Linux 4.15 - 5.8”; 22/80 open, 81 closed; distance 1 hop | Same classification, port states and distance | Same classification, not identical fingerprint text |
| SYN to SSH 22 | SYN-ACK, TTL 64, DF, ID 0, window 65160; MSS 1460, SACK, TS, NOP, WS 7 | Same listed fields and option order | Same fields |
| SYN to HTTP 80 | Same SYN-ACK shape as SSH | Same listed fields and option order | Same fields |
| Timestamps across open ports | 2358196573 then 2358197324: advances 751 ms | 2362011238 then 2362011989: advances 751 ms | Same observed progression; different offsets |
| SYN to closed TCP 81 | RST-ACK, sequence 0, ACK 305419897, window 0, no options, TTL 64, DF, ID 0 | Same listed fields | Same fields |
| Bare ACK to SSH 22 | RST, sequence 2271560481, ACK 0, window 0, no options, TTL 64, DF, ID 0 | Same listed fields | Same fields |
| Bare ACK to closed TCP 81 | Same RST shape as SSH | Same listed fields | Same fields |
| ECN SYN, IP Not-ECT | SYN-ACK-ECE `0x52`, window 65160 | Same flags, window and option order | Same fields |
| ECN SYN, IP ECT(0) | SYN-ACK `0x12`, no ECE | Same flags, window and option order | Same fields |
| ECN SYN, IP CE | SYN-ACK `0x12`, no ECE | Same flags, window and option order | Same fields |
| ICMP echo, 32-byte payload | Echo 0/0, length 60, TTL 64, DF clear, payload retained, ID 43336 | Same echo fields and payload; ID 52029 | Same listed behavior; different generated ID |
| ICMP echo, 1472-byte payload | Echo 0/0, length 1500, TTL 64, DF clear, payload retained, ID 43655 | Same echo fields and payload; ID 52563 | Same listed behavior; different generated ID |
| ICMP echo with code 9 | Echo reply preserves code 9 and payload; DF clear; ID 43821 | Same echo fields and payload; ID 53086 | Same listed behavior; different generated ID |
| UDP to closed port 81 | ICMP 3/3, length 60, TTL 64, TOS 192, DF clear, ID 44171; original datagram quoted | Same error fields and quotation; ID 53230 | Same listed behavior; different generated ID |
| MPTCP SYN, MP_CAPABLE v1 | SYN-ACK, MSS only, no MP_CAPABLE, length 44 | SYN-ACK with MSS and MP_CAPABLE/server key, length 56 | Different |
| In-window SYN on established HTTP connection | ACK, length 52, NOP/NOP/TS, window 510, ID 41414 | ACK, length 52, NOP/NOP/TS, window 2048, ID 22938 | Different receive window |
| Repeat established SYN after 750 ms | Another ACK, same timestamp layout, ID 41415 | Another ACK, same timestamp layout, ID 22939 | Same response and ID progression; window still differs |
| SSH version and KEXINIT | Banner `OpenSSH_9.6p1 Ubuntu-3ubuntu13.20`; 1120-byte KEXINIT | Same banner and every KEXINIT byte except the random 16-byte cookie | Same proposal, including all ten lists/order and padding |
| Real OpenSSH client | Receives KEXINIT, selects sntrup761x25519/ssh-ed25519/chacha20-poly1305, completes key exchange, then authentication is denied | Receives KEXINIT and selects the same algorithms; waits for `SSH2_MSG_KEX_ECDH_REPLY` until the 5-second observation ends | Same initial proposal; different subsequent exchange |
| HTTP/1.1 `GET /`, then `GET /missing` on one connection | 200 with 615-byte body, then 404 with 162-byte body; keep-alive | Same statuses, byte-identical bodies and connection reuse | Same behavior |
| HTTP response headers | nginx banner, Last-Modified, ETag and Accept-Ranges on `/` | Same header names/order and formatting; wall-clock/file-age values differ | Same structure; different Date/Last-Modified/ETag values |
| Idle after HTTP response | EOF after 75005 ms | EOF after 74995 ms | Same approximately 75-second timeout; measured times differ by 10 ms |
| SSH listener backlog (guest inspection; honeypot packet test) | `ss` Send-Q 4096, owned by systemd | 4096 pending stateful handshakes; next SYN receives a cookie | Same configured limit; external saturation not compared |
| HTTP listener backlog (guest inspection; honeypot packet test) | `ss` Send-Q 511, owned by nginx | 511 pending stateful handshakes; next SYN receives a cookie | Same configured limit; external saturation not compared |

The full run's Nmap label is a classifier result, not the running kernel version;
the guest's `uname` still reported 6.8.0-147. These probes do not establish
general OS indistinguishability or validate IPv6, retransmission behavior,
receive-window growth under traffic, or HTTP ranges and malformed requests.

## Stock service defaults

The targeted rerun used `cargo xtask honeypot-diff defaults stock-defaults`
after changing the honeypot's HTTP idle timeout to 75 seconds and SSH backlog
to 4096. HTTP backlog remains 511. Its evidence is retained under
`logs/honeypot-diff/stock-defaults/`. The freshly prepared guest reported the
same kernel and package versions listed above. Only HTTP idle-close probes
and guest configuration inspection ran; unrelated network probes were not
repeated.

Both `*-http-idle.json` records report EOF without an error or extra bytes.
The nginx configuration has no keepalive-timeout or listen-backlog override;
75 seconds and 511 are nginx's built-in defaults for
[keepalive_timeout](https://nginx.org/en/docs/http/ngx_http_core_module.html#keepalive_timeout)
and Linux [listen](https://nginx.org/en/docs/http/ngx_http_core_module.html#listen).
The refreshed `listeners.txt` confirms the backlogs on both IPv4 and IPv6.
`ssh-socket.txt` records systemd's `ssh.socket`, its effective
`Backlog=2147483647`, and the guest kernel's `net.core.somaxconn=4096`, which
caps the listener backlog.

The focused honeypot packet tests passed at both backlog boundaries, including
the first cookie beyond each limit and successful cookie handshakes under a
full SSH backlog. The idle test checks closure at exactly 75 seconds, and a
request started after 74 seconds still receives its own header deadline.
These tests verify the honeypot's behavior; external backlog saturation against
Ubuntu was not measured. The established receive window, MP_CAPABLE negotiation
and SSH exchange after KEXINIT remain different in the earlier probes above.

## Caddy and IPv4 options

The November 5 rerun used `cargo xtask honeypot-diff run caddy caddy-final`
with the service changes in `98dc79a4f`. The Ubuntu reference still ran
`6.8.0-147-generic`, with `linux-generic 6.8.0-147.147` and
`openssh-server 1:9.6p1-3ubuntu13.20`. Its official Cloudsmith Caddy package
was `2.11.9`, built with Go `1.27.3`. The packaged Caddyfile was unchanged.
The harness read MPTCP enabled as `1` without writing that setting.

The earlier run `caddy-before` compared that Caddy reference with the
pre-Caddy honeypot, which still served nginx and accepted MPTCP on SSH.
`options-before` isolated the benign option probes, and `keepalive-before`
captured the reference's idle TCP traffic. These runs and `caddy-final` are
retained under `logs/honeypot-diff/`. Each full run contains fifteen fixed
packet probes, a repeated established-connection SYN, ten option sequences,
Nmap, SSH, HTTP over ordinary TCP and a real Linux MPTCP client, and idle HTTP.
Every fixed probe in the final run received a correlated reply from each
target; every option sequence received two SYN-ACKs.

The option collector runs inside the probe guest, using an unassigned source
address and userspace ARP on its QEMU socket links. This avoids automatic
kernel RSTs without changing interface or firewall settings. On each of ports
22 and 80 it sends one well-formed SYN, repeats it about 750 ms later, and
observes for 1.5 seconds. It never completes those handshakes, races CPUs,
or attempts request migration. The completed-handshake detector cases run
only in the in-memory tests. No exploit was sent.

The following baseline differences were actually observed:

| Probe | Ubuntu reply | Pre-Caddy honeypot reply | Same or different |
| --- | --- | --- | --- |
| MP_CAPABLE offer on SSH 22 | Ordinary SYN-ACK, MSS only, IP length 44 | MP_CAPABLE SYN-ACK, IP length 56 | Different |
| Two HTTP requests on one connection | Caddy 200 with 18,753-byte body, then empty 404 | nginx 200 with 615-byte body, then 162-byte 404 | Different |
| HTTP idle close in `caddy-before` | EOF after 299905 ms | EOF after 74999 ms | Different |
| Repeated SYN with IPv4 Timestamp, flags 0 or 1, both ports | Receive slot retained; send slot advances about 750 ms | Both slots frozen at their initial values | Different |

The final comparison follows. “Same” applies only to the stated fields.
Addresses, checksums, random sequence numbers, keys and clock offsets are
retained in the evidence, not rewritten to manufacture equal packets.

| Probe | Ubuntu with Caddy | Current honeypot | Same or different |
| --- | --- | --- | --- |
| Nmap `-O -sS -Pn -n -p22,80,81 --max-os-tries 1` | Linux 4.15–5.8 classification; 22/80 open, 81 closed; distance 1 | Same classification, port states and distance | Same classification; fingerprint text differs |
| Ordinary SYN to 22 or 80 | SYN-ACK `0x12`, TTL 64, DF, ID 0, window 65160; MSS 1460, SACK, TS, NOP, WS 7 | Same listed fields and order | Same fields |
| TCP timestamps across the two open ports | 3238510277 → 3238511027, +750 ms | 2607153901 → 2607154652, +751 ms | Same clock behavior; observed increments differ by 1 ms |
| SYN to closed TCP 81 | RST-ACK `0x14`, sequence 0, ACK 305419897, window 0, no options, TTL 64, DF, ID 0 | Same fields | Same fields |
| Bare ACK to 22 or closed 81 | RST `0x04`, sequence 2271560481, ACK 0, window 0, no options, TTL 64, DF, ID 0 | Same fields | Same fields |
| ECN SYN, IP Not-ECT | SYN-ACK-ECE `0x52`, window 65160, normal SYN option order | Same fields | Same fields |
| ECN SYN, IP ECT(0) or CE | SYN-ACK `0x12`, no ECE | Same fields | Same fields |
| ICMP echo, 32-byte payload | Echo 0/0, IP length 60, TTL 64, DF clear, payload retained, ID 17048 | Same fields/payload, ID 56373 | Same behavior; generated IDs differ |
| ICMP echo, 1472-byte payload | Echo 0/0, length 1500, TTL 64, DF clear, payload retained, ID 17215 | Same fields/payload, ID 56959 | Same behavior; generated IDs differ |
| ICMP echo with code 9 | Echo 0/9, length 60, TTL 64, DF clear, payload retained, ID 17513 | Same fields/payload, ID 57455 | Same behavior; generated IDs differ |
| UDP to closed 81 | ICMP 3/3, length 60, TTL 64, TOS 192, DF clear, original datagram quoted, ID 17671 | Same fields/quotation, ID 57637 | Same behavior; generated IDs differ |
| MP_CAPABLE offer `1e040101` on SSH 22 | Ordinary SYN-ACK; MSS 1460 only; window 64240, IP length 44, TTL 64, DF, ID 0 | Same fields; no MPTCP | Same fields |
| Identical MP_CAPABLE offer on HTTP 80 | SYN-ACK; MSS 1460 then `1e0c0101` and 64-bit server key; window 64240, length 56, TTL 64, DF, ID 0 | Same fields and option order, independent key | Same negotiation; random key differs |
| Linux `IPPROTO_MPTCP` HTTP client | `MPTCP_INFO`: flags 2, remote key received, negotiated, no fallback; two HTTP responses on one connection | Same status and connection reuse | Same observed negotiation |
| HTTP/1.1 `GET /`, then `GET /missing`, over TCP and MPTCP | 200 with 18,753-byte welcome page, then 404 with empty body; persistent connection | Byte-identical bodies, statuses and reuse | Same behavior |
| HTTP headers on both transports | `Server: Caddy`; welcome includes Accept-Ranges, Content-Length, Content-Type, Etag, Last-Modified, Vary, Date; 404 has Content-Length 0 | Same order and values except Date; Etag and Last-Modified exactly match the package | Same headers except wall clock |
| Idle after complete HTTP response | EOF after 299987 ms, no error or extra application bytes | EOF after 300022 ms, no error or extra application bytes | Same approximately 300-second timeout; measured times differ by 35 ms |
| TCP keepalive traffic during HTTP idle | Empty ACK probes at 15.477, 30.837, 46.198 seconds after connection attempt | Empty ACK probes at 15.002, 30.002, 45.004 seconds | Same empty-probe behavior; observed timer cadence differs |
| In-window SYN on established HTTP connection | ACK, length 52, NOP/NOP/TS, window 510, ID 16595 | ACK, same length/options, window 2048, ID 62149 | Different receive window |
| Repeated established SYN after about 750 ms | Another ACK, ID 16596 | Another ACK, ID 62150 | Same reply and sequential ID behavior; window still differs |
| SSH version exchange and KEXINIT | `OpenSSH_9.6p1 Ubuntu-3ubuntu13.20`; 1120-byte KEXINIT | Same banner and every KEXINIT byte except its random 16-byte cookie | Same proposal, all ten lists/order/padding |
| Real OpenSSH client | Selects sntrup761x25519/ssh-ed25519/chacha20-poly1305, completes key exchange, authentication denied | Selects same algorithms; waits for KEX reply until 5-second observation ends | Different after the initial proposal |
| Plain SYN and repeat in option collector, both ports | Two SYN-ACKs; MSS 1460, window 64240, TTL 64, DF, ID 0; no IPv4 options | Same IPv4/TCP fields | Same fields |
| Record Route SYN and repeat, both ports | Pointer 4 → 12; first two slots contain local address, remaining slots zero; IHL 60 bytes; repeat retains options | Same behavior with the honeypot's local address | Same option behavior |
| Timestamp-only SYN and repeat, both ports | Flags 0, pointer 5 → 13, overflow 0, IHL 60; receive slot retained; send slot advances 751 ms on each port | Same fields; send slot advances 751 ms on 22 and 750 ms on 80 | Same behavior; one measured delta differs by 1 ms |
| Timestamp-with-addresses SYN and repeat, both ports | Flags 1, pointer 5 → 21, overflow 0, IHL 56; first two slots use local address; receive timestamp retained; send advances 750 ms on 22 and 751 ms on 80 | Same behavior; send advances 750 ms on each port | Same behavior; one measured delta differs by 1 ms |
| Prespecified Timestamp SYN and repeat, both ports | Flags 3, pointer 5 → 13, overflow 0, IHL 40; local-address slot stamped, remote-address slot remains zero; repeat unchanged | Same option behavior | Same behavior |
| Ethernet envelope of option collector's plain SYN-ACK | 58-byte frame containing a 44-byte IPv4 packet | 60-byte frame containing the same-length IPv4 packet, with two padding bytes | Different link padding in this QEMU/bridge setup |

The welcome body in both transports has SHA-256
`70a45d667679109cd6b25502554597f21536ee995ada0549251167bd171533b9`.
The final option probes also produced eight typed `ip_options_retransmit`
records, all `pending`, with gaps from 750045 to 750841 microseconds. Their
SYN records retain decoded options and complete option bytes. These records
identify the observed pattern, not malicious intent or kernel request state.
The duplicate-SYN captures validate timestamp refresh; the timer-driven
refresh path is covered by the focused transport tests rather than this
1.5-second wire observation.
Keepalive frame times are userspace capture times since the connection
attempt, not hardware timestamps. The saved idle records also include the
request and idle-observation start times. The reference's roughly 15.36-second
probe spacing differs from the honeypot's roughly 15-second spacing.

Guest inspection again reported backlog 4096 for systemd's SSH socket and
4096 for Caddy. The implementation uses those limits, with packet tests at
the boundaries; external backlog saturation was not compared. Caddy's
loopback admin listener was not exposed by the imitation. There was no
reference HTTPS listener; HTTPS/TLS was not added or tested.

Remaining measured differences include SSH after KEXINIT, the established
TCP receive window, keepalive cadence and link padding. These measurements do not establish
identical TCP window growth, retransmission scheduling, IPv6 behavior, HTTP
range/conditional responses or malformed-request handling. Caddy's header,
body and write deadlines and lack of a request-count limit are source-based
settings, not additional guest-probe claims. Focused in-memory tests cover
header, body-read, idle and request-count behavior; response-write inactivity
has no dedicated test in this change.
[MPTCP-TARGET.md](MPTCP-TARGET.md) records the research and deployment kernel
requirement: disabling MPTCP does not protect the host's IPv4 TCP setup.
