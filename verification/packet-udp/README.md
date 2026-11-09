# IP packet layer and UDP layer verification

Models and proofs of the IP layer (`src/stdlib/network/packet.rs`), the
fragment reassembly under it (`Reassembly` in `src/stdlib/network/ip.rs`)
and the UDP layer (`src/stdlib/network/udp/sockets.rs` and `wire.rs`).
TLA+ covers the state machines; Kani covers header, length and checksum
arithmetic by calling the production code. Each spec and harness file
names the source lines it follows.

This pass found three bugs. Each has a code fix and a test that fails
without it.

| Bug | Found by | Fix | Test |
|---|---|---|---|
| One IP layer fed two networks put their fragments together: the reassembly key has addresses, identification and protocol but no network, so a tunnel's first fragment and the world's last made one packet. | `Reassembly_unbound` | Each `IpLayer` serves one `Scope` (`IpLayer::host_in`); a packet of another scope is dropped with `IpReport::OtherScope`. The layer sends packets down with no scope, so it could never answer two networks anyway. | `packet::tests::inner_and_outer_fragments_with_one_key_stay_apart` |
| A fragment that arrived once its packet's time was up still completed it. The driver hands a packet in before it fires the layer's timer, and `Reassembly` only expired packets when the timer ran. | `Reassembly_lateexpiry` | `Reassembly::reassemble` expires due packets before it takes each fragment. This also covers the sandbox filter in `world/net/attachments.rs`, which shares `Reassembly`. | `ip::tests::a_late_fragment_completes_nothing_before_expire_runs`, `packet::tests::fragments_after_the_deadline_complete_nothing_before_the_timer_runs` |
| The UDP layer took any `IpPacket` sorted to UDP: an observed copy (no IPv4 header checksum check, no host policy) or a packet of another network reached a bound socket. | `UdpSockets_unchecked`, `UdpSockets_noscope` | `IpPacket::checked` is the public constructor for packets a host takes in, and `IpPacket::is_checked` tells them from observed copies. `UdpLayer` drops packets that are not checked or not of its scope. | `udp::sockets::tests::observed_copies_and_other_networks_reach_no_socket`, `packet::tests::a_checked_packet_is_what_the_ip_layer_hands_up` |

## Properties and results

The `_base`, `_keyed` and `_wide` configs must report "No error has been found". Every other
config starts with `\* expect violation: <Property>` and must fail on
exactly that property; a parse error, another property or a pass is not
its result. TLC 2.19, `-workers 4`. Every run below completed with an
empty queue, or stopped at its expected violation. A violating run stops
at its first counterexample, and with four workers its state counts vary
from run to run, so only passing runs list them.

### Reassembly (`tla/Reassembly.tla`)

Two networks send a packet each under the same key, two fragments each,
with the same place from the other network counting as other bytes. Time
is in ticks, sizes in units; the driver may hand a packet in while the
timer is due.

| Property | Meaning |
|---|---|
| `NoScopeMix` | a packet handed up is made of its own network's fragments |
| `WithinBudget` | at most `MAX_WAITING` waits after each fragment |
| `SizeAccounts` | `size` is the sum of the packets' sizes |
| `NoLateJoin` | no fragment joins a packet whose time is up |

| Config | Result | Generated | Distinct | Depth |
|---|---|---:|---:|---:|
| `Reassembly_base` | pass (all four, plus `TypeOK`) | 11,485 | 2,099 | 10 |
| `Reassembly_keyed` | pass: the other fix, scope in the key, one table | 16,876 | 6,882 | 11 |
| `Reassembly_unbound` | `NoScopeMix` violated: inner first fragment, then outer last, handed up as one | — | — | — |
| `Reassembly_lateexpiry` | `NoLateJoin` violated: first fragment, ticks past the deadline, last fragment before the timer | — | — | — |
| `Reassembly_nocap` | `WithinBudget` violated: two keys' first fragments pass the cap | — | — | — |

### Dispatch (`tla/Dispatch.tla`)

The IP layer's slots. What `take_in` makes of each packet (whole for a
transport, refused with or without an answer, a waiting fragment, a
completing one) is fixed per packet and explored over every assignment.

| Property | Meaning |
|---|---|
| `NothingLost` | every packet taken is in one place: waiting, refused, expired, the up slot, or handed up |
| `ExactlyOnce` | no packet goes up twice, and each goes to the transport it was sorted to |
| `AnswersKept` | an answer `take_in` made is never overwritten before it goes down |
| `NoSendAfterEnd` | nothing goes down after the end |
| `EndedOnce` | the end goes up once, after every packet |

| Config | Result | Generated | Distinct | Depth |
|---|---|---:|---:|---:|
| `Dispatch_base` | pass (all five, plus `TypeOK`) | 331,323 | 96,111 | 11 |
| `Dispatch_noupcheck` | `NothingLost` violated: a second packet overwrites the one waiting to go up | — | — | — |
| `Dispatch_noanswercheck` | `AnswersKept` violated: a second refusal overwrites the first answer | — | — | — |
| `Dispatch_answerafterend` | `NoSendAfterEnd` violated: a refusal after the transports' end is answered | — | — | — |

### UDP sockets (`tla/UdpSockets.tla`)

The receive side of `UdpLayer`: binds, arrivals (empty or not, checked or
observed, of the layer's network or a tunnel's), credit, the input's end,
and closes by handle and by the child's own end, with ports bound again.
Child ids are never reused (`Slots` generations, checked in
`verification/layer`).

| Property | Meaning |
|---|---|
| `NoCrossSocket` | a datagram goes up only on the child it was queued for, bound to its port, even across close and rebind |
| `NoCrossScope` | only the layer's own network reaches its sockets |
| `OnlyChecked` | an observed copy never reaches a socket |
| `Accounted` | every datagram, empty ones included, is refused, dropped with a report, queued, gone up, or discarded with its socket |
| `QueueBounded` | a socket holds at most `QUEUE / DATAGRAM_COST` datagrams, however small |
| `RetiredSilent` | a closed child hears nothing more, except one `Closed` when it closed by its own end |
| `EndedLast` | a socket's end goes up once, after its last datagram |
| `PortsMatch` | the port map names exactly the open sockets |

| Config | Result | Generated | Distinct | Depth |
|---|---|---:|---:|---:|
| `UdpSockets_base` | pass (all eight), three arrivals | 10,950,277 | 3,119,684 | 23 |
| `UdpSockets_wide` | pass (all eight), four arrivals, two units of credit; 4 min 42 s | 145,817,228 | 33,392,376 | 26 |
| `UdpSockets_noscope` | `NoCrossScope` violated (the code before this pass) | — | — | — |
| `UdpSockets_unchecked` | `OnlyChecked` violated (the code before this pass) | — | — | — |
| `UdpSockets_skipempty` | `Accounted` violated: an empty datagram skipped | — | — | — |
| `UdpSockets_freeempty` | `QueueBounded` violated: with `DATAGRAM_COST` zero, empties never fill a queue | — | — | — |
| `UdpSockets_queuebyport` | `NoCrossSocket` violated: a queue kept by port goes to the next socket bound there | — | — | — |
| `UdpSockets_lazyclose` | `RetiredSilent` violated: a socket left in its slot hands up its queue after close | — | — | — |
| `UdpSockets_earlyend` | `EndedLast` violated: the end goes up with datagrams still queued | — | — | — |
| `UdpSockets_keepport` | `PortsMatch` violated: close keeps the port | — | — | — |

The UDP layer has no timers (`Timer = ()`, no deadline), so a closed
socket has none to retire; its slot, queue, ready entry and port go with
`close`.

### Kani

Kani 0.68.0 with CBMC 6.11.0, default solver and safety checks, unwinding
assertions on. Each harness runs on its own; the files are included as
`proofs` child modules under `cfg(kani)`.

| Harness | File | What it proves | Result |
|---|---|---|---|
| `parse_reads_exactly_the_declared_length` | `kani/udp_wire.rs` | for all bytes up to 12, `Datagram::parse` takes exactly a length field in 8..=len and reads that many bytes, empty payloads included | 0 of 188 checks failed |
| `encoded_len_fits_one_ip_packet` | `kani/udp_wire.rs` | for every `usize` length, `encoded_len` refuses mixed families and accepts exactly what fits one IPv4 or IPv6 packet, so the 16-bit length never wraps | 0 of 100 failed |
| `ipv4_datagrams_roundtrip_and_one_bit_fails_the_checksum` | `kani/udp_wire.rs` | any ports, payloads of 0 to 3 bytes: `encode` then `parse` give the ports and payload back, the checksum field is nonzero and verifies, and any one flipped bit outside the length field fails it, except a flip that zeroes an IPv4 checksum field (RFC 768's "no checksum") | 0 of 454 failed, 32 s |
| `ipv6_datagrams_roundtrip_and_one_bit_fails_the_checksum` | `kani/udp_wire.rs` | the same over IPv6, where a zero field is never accepted | 0 of 454 failed, 32 s |
| `checksum_matches_rfc_1071` | `kani/ip_header.rs` | for all bytes up to 9, `ip::checksum` equals RFC 1071 written plainly | 0 of 200 failed, 58 s |
| `ipv4_reads_stay_inside_the_packet` | `kani/ip_header.rs` | for all IPv4 bytes up to 24, `parse` and `parse_truncated` give a payload from the header length to the total length (or the bytes present) | 0 of 489 failed |
| `ipv4_check_requires_the_header_checksum` | `kani/ip_header.rs` | for all 24-byte IPv4 packets, `check` takes only a verifying header checksum and agrees with `parse`; `parse_whole` takes no fragment | 0 of 845 failed |
| `ipv6_stripping_leaves_a_checked_packet` | `kani/ip_header.rs` | for all 56-byte IPv6 packets with 16 payload bytes starting with one or two 8-byte extension headers, a stripped packet is the original fixed header with the upper protocol (never an extension header) as next header, the upper bytes' length, and the upper bytes, which is what `parse_whole` reads with its upper header at 40; fragments are never stripped | 0 of 1,100 failed, 68 s |
| `checked_ipv4_packets_are_host_packets` | `kani/packet.rs` | for all 48-byte IPv4 packets with a 20-byte header and every origin, `IpPacket::checked` takes exactly whole non-fragment packets under a non-observed origin, with the header `parse_whole` reads and the sort `Sort::of` names; otherwise it hands the bytes back; an observed copy is never checked | 0 of 1,667 failed, 57 s |
| `checked_ipv6_packets_are_host_packets` | `kani/packet.rs` | the same for all 48-byte IPv6 packets, which must have no extension headers left | 0 of 1,665 failed, 126 s |

Earlier versions ran past the 12 GB memory cap: IPv4 reads over 28
symbolic bytes of any header length, IPv6 stripping with headers of any
length or with `parse_whole` called on the stripped packet, and the
checked-packet harnesses with an unwinding bound large enough for
48-byte and 16-byte comparison loops. The harnesses were narrowed as
their doc comments say: header lengths are held where noted, and bytes
and addresses are compared at a symbolic index or as integers. The Kani
harnesses have no failing controls; the TLA+ configs do.

## Executed Rust validation

`cargo test -p fictionet --lib` passed, 3,915 tests, with the fixes, and
`cargo test -p fictionet --test it -- network udp dns fragment` passed,
404 tests. The four reproduction tests in the bug table that test the old
behavior (all but `a_checked_packet_is_what_the_ip_layer_hands_up`, which
tests the new constructor) fail with the fixes taken out and pass with
them. `cargo clippy -p fictionet --lib --tests -- -D warnings` passed.

## What is left out

- Reassembly's overlap rules beyond one place per fragment (lengths that
  disagree, the "more fragments" flag on copies) are in the unit tests and
  the `ip_reassembly` fuzz target, not the model.
- The Kani harnesses do not reach `Reassembly` itself (its `HashMap`) or
  the UDP layer's state; TLA+ and the unit tests cover those.
- The UDP send side, ICMP port-unreachable answers and the `udp::endpoint`
  facade are not modeled.
- `Scope::tunnel` still draws from a process-wide counter; Astra's point
  that it must not become a replay identity is not addressed here.
- The correspondence between the specs and the code is reviewed by hand,
  not a machine-checked refinement.

## Rerunning

TLC, one config at a time, from this directory's `tla/` (the state
directory may be anywhere outside the repository):

```sh
cd verification/packet-udp/tla
java -XX:+UseParallelGC -Xmx6g -cp ~/.cache/adorably-fv/tla2tools.jar tlc2.TLC \
    -workers 4 -metadir "$CARGO_TARGET_DIR/packet-udp/Reassembly_base" \
    -config Reassembly_base.cfg Reassembly.tla
```

The specs are `Reassembly.tla`, `Dispatch.tla` and `UdpSockets.tla`; each
config's name starts with its spec's. `UdpSockets_wide` takes about five
minutes and 6 GB of heap; every other config takes under a minute.

Kani, one harness at a time, from the root of the repository:

```sh
cargo kani -p fictionet --lib --harness parse_reads_exactly_the_declared_length
```

Cap its memory (`systemd-run --user --scope -p MemoryMax=12G`), as this
pass did: wider versions of these harnesses ran past that cap. Each
harness takes under three minutes, compiling included.
