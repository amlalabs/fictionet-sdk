# Ubuntu comparison

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

The final run used the modified honeypot after the transport, service and
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
| Idle after HTTP response | EOF after 74672 ms | EOF after 64998 ms | Different: approximately 75 versus 65 seconds |

The final Nmap label is a classifier result, not the running kernel version;
the guest's `uname` still reported 6.8.0-147. These probes do not establish
general OS indistinguishability or validate IPv6, retransmission behavior,
receive-window growth under traffic, or HTTP ranges and malformed requests.

Guest listener inspection (`listeners.txt` and `ssh-socket.txt`) showed nginx
backlog 511 and SSH backlog 4096 owned by systemd's socket unit. The requested
SSH backlog 128 and HTTP idle timeout 65 were retained; the reference's defaults
were not changed to make the comparison agree. External backlog saturation was
not measured. The remaining packet discrepancy is the established receive
window; MP_CAPABLE negotiation and the SSH exchange after KEXINIT also remain
different in the probes above.
