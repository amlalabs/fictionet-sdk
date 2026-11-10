# IP packet layer and UDP layer verification

Models and proofs of the IP layer (`src/stdlib/network/packet.rs`), the
fragment reassembly under it (`Reassembly` in `src/stdlib/network/ip.rs`)
and the UDP layer (`src/stdlib/network/udp/sockets.rs` and `wire.rs`).
TLA+ covers the state machines; Kani covers header, length and checksum
arithmetic by calling the production code. Each spec and harness file
names the source lines it follows.

This pass found three bugs. Each has a code fix and a test that fails
without it. Since then the IP layer takes raw packets from the input path
its endpoint owns, with no network label, hands transports a
`CheckedIpPacket`, and leaves captured copies to `ObservedIpPacket`. The
models below still have a network constant and the flags that chose
whether the code checked it; in the code that check is now
`NetworkInput`, where several networks' packets arrive together, ahead of
reassembly. The Kani harnesses in `kani/packet.rs` were rewritten for
`CheckedIpPacket`. None of these has been run since that change; the
results are those of the earlier code.

The exception is the checksum, IPv4 header and UDP wire harnesses and
their seven controls, rerun one at a time on 2026-11-10 (Kani 0.68.0, 8 GB
cap) after that change and after the source address and UDP family fixes
in `lean/README.md`; their rows below say so. Every proof passed and every
control failed on exactly its named check. At that commit the crate does
not compile under `cfg(kani)`, because the harnesses in
`verification/layer/kani` and `verification/tls/kani` no longer match
their code, so the rerun turned those two modules off in a scratch copy
of the tree. The Lean proofs in `lean/` cover the same functions for all
lengths (see its "Checksum, header and UDP" section).

| Bug | Found by | Fix | Test |
|---|---|---|---|
| One IP layer fed two networks put their fragments together: the reassembly key has addresses, identification and protocol but no network, so a tunnel's first fragment and the world's last made one packet. | `Reassembly_unbound` | First each `IpLayer` dropped packets labelled with another network. Now each endpoint owns its `IpLayer` and its input, and input carrying several networks goes through `NetworkInput`, which passes on only one network's packets, before reassembly. | `packet::tests::inner_and_outer_fragments_with_one_key_stay_apart` |
| A fragment that arrived once its packet's time was up still completed it. The driver hands a packet in before it fires the layer's timer, and `Reassembly` only expired packets when the timer ran. | `Reassembly_lateexpiry` | `Reassembly::reassemble` expires due packets before it takes each fragment. This also covers the sandbox filter in `world/net/attachments.rs`, which shares `Reassembly`. | `ip::tests::a_late_fragment_completes_nothing_before_expire_runs`, `packet::tests::fragments_after_the_deadline_complete_nothing_before_the_timer_runs` |
| The UDP layer took any packet sorted to UDP: an observed copy (no IPv4 header checksum check, no host policy) or a packet of another network reached a bound socket. | `UdpSockets_unchecked`, `UdpSockets_noscope` | First a check in `UdpLayer`. Now the types: the UDP layer's lower port carries only `CheckedIpPacket`, whose header `CheckedIpPacket::checked` or the IP layer read and checked, and a captured copy is an `ObservedIpPacket`. Packets of another network are parted before IP intake (`NetworkInput`). | `udp::sockets::tests::malformed_and_foreign_host_packets_reach_no_socket`, `packet::tests::a_checked_packet_is_what_the_ip_layer_hands_up` |

## Properties and results

The `_base`, `_keyed` and `_wide` configs must report "No error has been found". Every other
config starts with `\* expect violation: <Property>` and must fail on
exactly that property; a parse error, another property or a pass is not
its result. TLC 2.19, `-workers 4`. Every run below completed with an
empty queue, or stopped at its expected violation. A violating run stops
at its first counterexample, and with four workers its state counts vary
from run to run, so only passing runs list them.

### Reassembly (`tla/Reassembly.tla`)

Two networks send a packet each under the same key, two fragments each.
A fragment carries one of two byte patterns. A second fragment at the
same place with the same bytes from the same network is an exact copy
and is ignored (`push_fragment`, ip.rs 727-737); with other bytes, or
from the other network, it is an overlap and kills the packet (RFC 5722,
ip.rs 757-774), which stays dead, dropping its later fragments, until it
expires or the cap drops it. That is what the code does with overlapping
data: never first-wins or last-wins, always reject. Time is in ticks,
sizes in units; the driver may hand a packet in while the timer is due.

The byte patterns were added in the drift audit at `e2858ccc4`. Before
them a fragment's bytes were its network's alone, so under `BindScope`
every piece under a key came from the layer's own network and the kill
and dead-packet branches were unreachable in `Reassembly_base` and
`Reassembly_keyed` (checked: an invariant forbidding a dead packet held
on the old model with the base constants, 11,485 states, and fails on
the new one at depth 4). `SizeAccounts`, `WithinBudget` and `NoLateJoin`
are now checked across `kill`. The Reassembly rows below are from that
rerun, `-workers 2`.

| Property | Meaning |
|---|---|
| `NoScopeMix` | a packet handed up is made of its own network's fragments |
| `WithinBudget` | at most `MAX_WAITING` waits after each fragment |
| `SizeAccounts` | `size` is the sum of the packets' sizes |
| `NoLateJoin` | no fragment joins a packet whose time is up |

| Config | Result | Generated | Distinct | Depth |
|---|---|---:|---:|---:|
| `Reassembly_base` | pass (all four, plus `TypeOK`) | 407,075 | 57,854 | 10 |
| `Reassembly_keyed` | pass: the other fix, scope in the key, one table | 707,523 | 237,894 | 11 |
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
observed, of the layer's network or a tunnel's, with or without room in
the budget), credit, the input's end, and closes by handle and by the
child's own end, with ports bound again. Child ids are never reused
(`Slots` generations, checked in `verification/layer`). The code visits
sockets in the order of its `ready` list and gives a socket's send credit
back before its next datagram; the model lets any socket with an event go
next, which includes that order.

| Property | Meaning |
|---|---|
| `NoCrossSocket` | a datagram goes up only on the child it was queued for, bound to its port, even across close and rebind |
| `NoCrossScope` | only the layer's own network reaches its sockets |
| `OnlyChecked` | an observed copy never reaches a socket |
| `Accounted` | every datagram, empty ones included, is refused, dropped with a report (a full queue, or no room in the budget), queued, gone up, or discarded with its socket |
| `QueueBounded` | a socket holds at most `Queue` datagrams, however small: `QUEUE / DATAGRAM_COST` in the code, where every passing config's `DatagramCost` is 1 |
| `RetiredSilent` | a closed child hears nothing more, except one `Closed` when it closed by its own end |
| `EndedLast` | a socket's end goes up once, after its last datagram |
| `PortsMatch` | the port map names exactly the open sockets |

The runs below are from the audit that added the budget's refusal to
`Arrive`: TLC 2.19, `-workers 2`, a 2 GB heap.

| Config | Result | Generated | Distinct | Depth |
|---|---|---:|---:|---:|
| `UdpSockets_base` | pass (all eight), three arrivals; 1 min 38 s | 14,123,053 | 3,627,578 | 23 |
| `UdpSockets_wide` | pass (all eight), four arrivals, two units of credit; 27 min 14 s | 189,444,612 | 39,248,068 | 26 |
| `UdpSockets_noscope` | `NoCrossScope` violated (the code before this pass) | — | — | — |
| `UdpSockets_unchecked` | `OnlyChecked` violated (the code before this pass) | — | — | — |
| `UdpSockets_skipempty` | `Accounted` violated: an empty datagram skipped | — | — | — |
| `UdpSockets_freeempty` | `QueueBounded` violated: with `DATAGRAM_COST` zero, empties never fill a queue | — | — | — |
| `UdpSockets_queuebyport` | `NoCrossSocket` violated: a queue kept by port goes to the next socket bound there | — | — | — |
| `UdpSockets_lazyclose` | `RetiredSilent` violated: a socket left in its slot hands up its queue after close | — | — | — |
| `UdpSockets_earlyend` | `EndedLast` violated: the end goes up with datagrams still queued | — | — | — |
| `UdpSockets_keepport` | `PortsMatch` violated: close keeps the port | — | — | — |

The UDP layer has no timers (`Timer = ()`, no deadline), so a closed
socket has none to retire; its slot, with its queue, and its port go with
`close` (`sockets.rs` 285-291). `close` leaves the socket's entry in
`ready` where it is: `socket_event` finds no socket for it and skips it
(377-379), and the id is never given to another child.

### Kani

Kani 0.68.0 with CBMC 6.11.0, default solver and safety checks, unwinding
assertions on. Each harness runs on its own; the files are included as
`proofs` child modules under `cfg(kani)`.

| Harness | File | What it proves | Result |
|---|---|---|---|
| `parse_reads_exactly_the_declared_length` | `kani/udp_wire.rs` | for all bytes up to 12, `Datagram::parse` takes exactly a length field in 8..=len and reads that many bytes, empty payloads included | 0 of 188 checks failed (rerun 2026-11-10) |
| `encoded_len_fits_one_ip_packet` | `kani/udp_wire.rs` | for every `usize` length, `encoded_len` refuses mixed families and accepts exactly what fits one IPv4 or IPv6 packet, so the 16-bit length never wraps | 0 of 100 failed (rerun 2026-11-10) |
| `ipv4_datagrams_roundtrip_and_one_bit_fails_the_checksum` | `kani/udp_wire.rs` | any ports, payloads of 0 to 3 bytes: `encode` then `parse` give the ports and payload back, the checksum field is nonzero and verifies, and any one flipped bit outside the length field fails it, except a flip that zeroes an IPv4 checksum field (RFC 768's "no checksum") | 0 of 454 failed, 43 s (rerun 2026-11-10) |
| `ipv6_datagrams_roundtrip_and_one_bit_fails_the_checksum` | `kani/udp_wire.rs` | the same over IPv6, where a zero field is never accepted | 0 of 454 failed, 57 s (rerun 2026-11-10) |
| `checksum_matches_rfc_1071` | `kani/ip_header.rs` | for all bytes up to 9, `ip::checksum` equals RFC 1071 written plainly | 0 of 200 failed, 76 s (rerun 2026-11-10) |
| `ipv4_reads_stay_inside_the_packet` | `kani/ip_header.rs` | for all IPv4 bytes up to 24, `parse` and `parse_truncated` give a payload from the header length to the total length (or the bytes present) | 0 of 495 failed (rerun 2026-11-10) |
| `ipv4_check_requires_the_header_checksum` | `kani/ip_header.rs` | for all 24-byte IPv4 packets, `check` takes only a verifying header checksum and agrees with `parse`; `parse_whole` takes no fragment | 0 of 874 failed (rerun 2026-11-10) |
| `ipv6_stripping_leaves_a_checked_packet` | `kani/ip_header.rs` | for all 56-byte IPv6 packets with 16 payload bytes starting with one or two 8-byte extension headers, a stripped packet is the original fixed header with the upper protocol (never an extension header) as next header, the upper bytes' length, and the upper bytes, read off the stripped bytes (`parse_whole` is not called on them; see below); fragments are never stripped | 0 of 1,100 failed, 68 s |
| `checked_ipv4_packets_are_host_packets` | `kani/packet.rs` | for all 48-byte IPv4 packets with a 20-byte header and every origin, `CheckedIpPacket::checked` takes exactly whole non-fragment packets, with the header `parse_whole` reads and the sort `Sort::of` names; otherwise it hands the bytes back. The recorded run was of `IpPacket::checked`, which also refused an observed origin; an observed copy is now its own type | 0 of 1,698 failed, 49 s |
| `checked_ipv6_packets_are_host_packets` | `kani/packet.rs` | the same for all 48-byte IPv6 packets, which must have no extension headers left | 0 of 1,696 failed, 131 s |

Earlier versions ran past the 12 GB memory cap: IPv4 reads over 28
symbolic bytes of any header length, IPv6 stripping with headers of any
length or with `parse_whole` called on the stripped packet, and the
checked-packet harnesses with an unwinding bound large enough for
48-byte and 16-byte comparison loops. The harnesses were narrowed as
their doc comments say: header lengths are held where noted, and bytes
and addresses are compared at a symbolic index or as integers.

### Kani failing controls

Each harness has a failing control in the same file that changes one
thing and must fail on the one assertion its comment names. Each failed
on exactly that check, and the proofs passed, in the integration run
(Kani 0.68.0, 10 GB cap); the checked-packet proofs now count 1,698 and
1,696 checks, as `Sort` took the place of the packet's own transport enum.

| Control | Covers | What it changes | Failed check |
|---|---|---|---|
| `parse_without_the_declared_length` | `parse_reads_exactly_the_declared_length` | claims `parse` reads every byte present | "a datagram is every byte present" (1 of 68) |
| `encoded_len_without_the_ipv4_header` | `encoded_len_fits_one_ip_packet` | claims IPv4 refuses only what would not fit 16 bits, leaving out the IP header | "only a datagram past 16 bits is refused" (1 of 17) |
| `ipv4_datagrams_without_the_zero_checksum_exception` | `ipv4_datagrams_roundtrip_and_one_bit_fails_the_checksum` | drops RFC 768's exception for a flip that zeroes the checksum field | "one flipped bit fails the checksum" (1 of 346) |
| `ipv6_datagrams_with_two_flipped_bits` | `ipv6_datagrams_roundtrip_and_one_bit_fails_the_checksum` | flips the same bit in two 16-bit words, which the sum cannot see when they go opposite ways | "two flipped bits fail the checksum" (1 of 511) |
| `checksum_without_the_end_around_carry` | `checksum_matches_rfc_1071` | compares with RFC 1071 less its end-around carry | "the sum without its carry" (1 of 198) |
| `ipv4_truncated_reads_to_the_total_length` | `ipv4_reads_stay_inside_the_packet` | claims a truncated read ends at the total length | "the payload ends at the total length" (1 of 490 in the 2026-11-10 rerun) |
| `ipv4_parse_without_the_header_checksum` | `ipv4_check_requires_the_header_checksum` | claims of `parse` what holds of `check` | "a header read has a verifying checksum" (1 of 648 in the 2026-11-10 rerun) |
| `ipv6_stripping_keeping_the_payload_length` | `ipv6_stripping_leaves_a_checked_packet` | claims a stripped packet keeps the original payload length | "the payload length is the original's" (1 of 631) |
| `checked_ipv4_packets_without_the_header_checksum` | `checked_ipv4_packets_are_host_packets` | claims `checked` hands back only bytes `parse` cannot read | "only unreadable IPv4 bytes are handed back" (1 of 1,424) |
| `checked_ipv6_packets_with_extension_headers_left` | `checked_ipv6_packets_are_host_packets` | claims `checked` takes every packet `parse_whole` takes | "every whole IPv6 packet is checked" (1 of 1,422) |

## Executed Rust validation

`cargo test -p fictionet --lib` passed, 3,915 tests, with the fixes, and
`cargo test -p fictionet --test it -- network udp dns fragment` passed,
404 tests. The four reproduction tests in the bug table that test the old
behavior (all but `a_checked_packet_is_what_the_ip_layer_hands_up`, which
tests the new constructor) fail with the fixes taken out and pass with
them. `cargo clippy -p fictionet --lib --tests -- -D warnings` passed.

## What is left out

- Reassembly's overlap rules beyond one place per fragment (partial
  overlaps, lengths that disagree, the "more fragments" flag on copies,
  the first fragment's header counted in its cost) are in the unit tests
  and the `ip_reassembly` fuzz target, not the model.
- Dispatch's `done` kind completes every waiting fragment and its `Timer`
  expires every one, where the code completes and expires per key; the
  slot properties see only whether a packet waits, so this hides nothing
  they check.
- The Kani harnesses do not reach `Reassembly` itself (its `HashMap`) or
  the UDP layer's state; TLA+ and the unit tests cover those.
- The UDP send side, ICMP port-unreachable answers and the `udp::endpoint`
  facade are not modeled. Nor are the multicast groups (`UdpControl::Join`
  and the `groups` check in `take_in`), the ephemeral port choice, the
  `HELD` back-pressure on `up` and `down`, or the UDP checksum and length
  checks in `take_in`: a datagram the model refuses for any of those
  reasons is one the code returns from without a report, and the model
  records them all as refused.
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
config's name starts with its spec's. With two workers and a 2 GB heap,
`UdpSockets_base` takes 1 min 38 s and `UdpSockets_wide` 27 min (about
five minutes with four workers and 6 GB before the budget was added);
every other config takes seconds.

Kani, one harness at a time, from the root of the repository:

```sh
cargo kani -p fictionet --lib --harness parse_reads_exactly_the_declared_length
```

Cap its memory (`systemd-run --user --scope -p MemoryMax=12G`), as this
pass did: wider versions of these harnesses ran past that cap. Each
harness takes under three minutes, compiling included.

The controls run the same way, one at a time or with their proof, and
must report `VERIFICATION:- FAILED` on the check named in the table above.
