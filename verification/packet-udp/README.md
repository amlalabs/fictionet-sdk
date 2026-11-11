# IP packet layer and UDP layer verification

Models and proofs of the IP layer (`src/stdlib/network/packet.rs`), the
fragment reassembly under it (`Reassembly` in `src/stdlib/network/ip.rs`)
and the UDP layer (`src/stdlib/network/udp/sockets.rs` and `wire.rs`).
TLA+ covers the state machines and checks two of them against specs
written from the RFCs; Kani covers header, length and checksum arithmetic
by calling the production code; the Lean proofs and their test vectors
are described in [lean/README.md](lean/README.md). Each spec and harness
file names the source lines it follows.

The first pass found three bugs. Each has a code fix and a test that fails
without it. Since then the IP layer takes raw packets from the input path
its endpoint owns, with no network label, hands transports a
`CheckedIpPacket`, and leaves captured copies to `ObservedIpPacket`; where
several networks' packets arrive together, `NetworkInput` parts them ahead
of reassembly. The TLA+ models were brought to that code on 2026-11-10 (at
`8c582367b`) and every config was run again; the results below are from
that run. The Kani harnesses in `kani/packet.rs` were rewritten for
`CheckedIpPacket` and have not been run since.

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
| The UDP layer took any packet sorted to UDP: an observed copy (no IPv4 header checksum check, no host policy) or a packet of another network reached a bound socket. | `UdpSockets_unchecked` and `UdpSockets_noscope` as they were then; both checks are now types, so `noscope` is retired and `unchecked` now leaves out `take_in`'s own checks | First a check in `UdpLayer`. Now the types: the UDP layer's lower port carries only `CheckedIpPacket`, whose header `CheckedIpPacket::checked` or the IP layer read and checked, and a captured copy is an `ObservedIpPacket`. Packets of another network are parted before IP intake (`NetworkInput`). | `udp::sockets::tests::malformed_and_foreign_host_packets_reach_no_socket`, `packet::tests::a_checked_packet_is_what_the_ip_layer_hands_up` |

The 2026-11-10 pass found no new bug. It found one departure, kept: a
datagram for a protocol the host has no transport for goes to the host's
ICMP, which drops it without the Protocol Unreachable that RFC 1122
section 3.2.2.1 says a host SHOULD send (see Dispatch below).

## Properties and results

The `_base` and `_wide` configs, and `Reassembly_unbound_rfc`, must
report "No error has been found". Every other config starts with
`\* expect violation: <Property>` and must fail on exactly that property;
a parse error, another property or a pass is not its result. Configs
named `_witness` are not controls: each checks a throwaway invariant that
must fail, to show that a case the base's properties speak about is
reached. TLC 2.19, `-workers 2`, a 2 GB heap. Every run below completed
with an empty queue, or stopped at its expected violation; each
counterexample was read to check it fails for the reason given. A
violating run stops at its first counterexample, and with two workers its
state counts vary from run to run, so only passing runs list them.

A refinement is checked as `PROPERTY RfcSpec`, where `RfcSpec` is the RFC
spec's `Spec` through a refinement mapping (`INSTANCE ... WITH`): TLC
checks that every step of the code's model is a step of the RFC spec or
leaves the mapped variables alone (stuttering). TLC reports a failure as
"Action property ... of module RfcReassembly (or RfcIpInput) is violated".

### Reassembly (`tla/Reassembly.tla`, `tla/RfcReassembly.tla`)

Two networks send a packet each under the same key, two fragments each.
`BindScope` says whether only one of them reaches the IP layer: TRUE for
the code, where an endpoint owns its input path or a `NetworkInput` parts
labelled input ahead of the IP layer; FALSE for one IP layer fed both,
the code before the first pass. The earlier `KeyHasScope` flag and its
`Reassembly_keyed` config, a design the code did not take, are retired.
A fragment carries one of two byte patterns and an arrival number. A
second fragment at the same place with the same bytes is an exact copy
and is ignored (`push_fragment`, ip.rs 728-742); the code compares bytes,
not networks, so this now holds for a copy from either network. With
other bytes it is an overlap and kills the packet (RFC 5722, ip.rs
762-779), which stays dead, dropping its later fragments, until it
expires or the cap drops it. A packet handed up carries the bytes
`finish` builds: each piece's bytes in offset order. Time is in ticks,
sizes in units; the driver may hand a packet in while the timer is due.

`RfcReassembly.tla` states the RFCs without the code's bookkeeping: one
buffer per key, created by its first fragment; RFC 791 section 3.2 puts
each fragment's data at its offset and hands the datagram up once whole;
RFC 8200 section 4.5 abandons a buffer at its timeout and on any overlap
(an exact copy may be dropped instead); RFC 5722 section 4 discards the
rest of an overlapped datagram, fragments not yet received included;
RFC 1122 section 3.3.2 lets the host give up a buffer for want of space.
Every arrival is a step of that spec, whether or not it changes a buffer.
`Reassembly.tla` maps its table onto those buffers (a live packet is an
open buffer, or a dead one, started `Timeout` ticks before it expires),
its delivered packets onto delivered datagrams with their bytes, and a
history variable `last` onto the last arrival. The code keeps no copy of
a fragment it drops, so without `last` a code that ignored an overlap
would look like a stuttering step; with it, an ignored overlap is a step
the RFC spec must match.

| Property | Meaning |
|---|---|
| `NoScopeMix` | a packet handed up is made of its own network's fragments |
| `WithinBudget` | at most `MAX_WAITING` waits after each fragment |
| `SizeAccounts` | `size` is the sum of the packets' sizes |
| `NoLateJoin` | no fragment joins a packet whose time is up |
| `RfcSpec` | the model refines `RfcReassembly` (RFC 791 section 3.2, RFC 8200 section 4.5, RFC 5722) |
| `RfcWholeOnly` | through the mapping: a datagram goes up whole, one fragment at each offset (RFC 791 section 3.2) |
| `RfcInTime` | every fragment of a datagram handed up came within the timeout of its first (RFC 8200 section 4.5) |
| `RfcTheirBytes` | the bytes handed up are the bytes its fragments carried, each at its offset |
| `RfcOnceEach` | at most once per arrival set: no arrival is part of two datagrams handed up |

| Config | Result | Generated | Distinct | Depth |
|---|---|---:|---:|---:|
| `Reassembly_base` | pass (all four, the four `Rfc` invariants, `RfcSpec` and `TypeOK`); 2 min 51 s | 7,923,834 | 2,918,576 | 11 |
| `Reassembly_unbound_rfc` | pass (`RfcSpec`): two networks into one layer still meet the RFCs, which know only keys | 1,069,424 | 844,240 | 10 |
| `Reassembly_unbound` | `NoScopeMix` violated: the outer network's first fragment, then the inner one's last, handed up as one packet | — | — | — |
| `Reassembly_lateexpiry` | `NoLateJoin` violated: first fragment, ticks past the deadline, last fragment before the timer | — | — | — |
| `Reassembly_nocap` | `WithinBudget` violated: two keys' first fragments pass the cap | — | — | — |
| `Reassembly_firstwins` | `RfcSpec` violated: fragment d1 at offset 0, then d2 at offset 0; the buffer stays open with d1, where the RFCs abandon it | — | — | — |
| `Reassembly_lastwins` | `RfcSpec` violated: d1 at offset 0, then d2 at offset 0 replaces it and the buffer stays open | — | — | — |
| `Reassembly_arrivalorder` | `RfcSpec` violated: the last fragment (d1) first, then the first (d2); handed up as d1 then d2, not d2 then d1 | — | — | — |
| `Reassembly_witness_dead` | `NoDeadPacket` fails at depth 4: an overlap kills a packet under the base's constants | — | — | — |
| `Reassembly_witness_bytes` | `NoMixedBytes` fails at depth 4: a packet whose fragments carry different bytes goes up, so the bytes' order is checked | — | — | — |

`Reassembly_unbound_rfc` shows what the refinement does not cover: the
RFCs key reassembly by addresses, identification and protocol, so an IP
layer fed two networks still meets them. Keeping networks apart is
`NetworkInput`'s job, and `NoScopeMix` is the property that catches it.

### Dispatch (`tla/Dispatch.tla`, `tla/RfcIpInput.tla`)

The IP layer's slots, and where what it hands up goes. What `take_in`
makes of each packet is fixed per packet and explored over every
assignment: a whole packet for TCP, UDP or ICMP; an ICMP error quoting a
TCP or UDP packet; a packet refused with an answer or without one (an
IPv6 extension-header refusal, or `IpReport::Malformed`); a waiting
fragment; or a completing one, whose datagram's kind is chosen too. Where
a packet goes is `Sort::read` and then the endpoint's `destination`
(endpoint.rs 30-36): TCP, UDP, or the host's ICMP for `Sort::Icmp` and
`Sort::Other`. The transports' sends are counted, up to `MaxSends`.

`RfcIpInput.tla` states a host's IP input from RFC 1122: each valid
datagram goes up once, to the protocol its header names (section 3.2.1),
a fragmented one once its fragments are all in and none was abandoned
(section 3.2.1.4); an ICMP error goes to the transport whose packet it
quotes (section 3.2.2, with 3.2.2.1, 4.1.3.3 and 4.2.3.9); a packet
refused for its IPv6 extension headers gets at most one Parameter Problem
back (RFC 8200 section 4, RFC 4443 section 3.4), and only before the
output's end; nothing goes down after the output's end, and nothing goes
up after the input's end has. `Dispatch.tla` maps packets taken in,
handed up (with where to), expired, answered and sent onto it.

Departure, kept: a datagram whose protocol has no transport goes to the
host's ICMP (`Sort::Other` to `Destination::Icmp`), which answers echo
requests only, so it is dropped without the Protocol Unreachable that RFC
1122 section 3.2.2.1 says a host SHOULD send. The model's "icmp" kind
stands for both; it is a SHOULD the simulator skips, and nothing a host
takes in is wrong because of it.

| Property | Meaning |
|---|---|
| `NothingLost` | every packet taken is in one place: waiting, refused, expired, the up slot, or handed up |
| `ExactlyOnce` | no packet goes up twice, and each goes where it was sorted |
| `AnswersKept` | an answer `take_in` made is never overwritten before it goes down |
| `NoSendAfterEnd` | nothing goes down after the end |
| `EndedOnce` | the end goes up once, after every packet |
| `RfcSpec` | the model refines `RfcIpInput` (RFC 1122 sections 3.2.1 and 3.2.2, RFC 8200's answer) |

| Config | Result | Generated | Distinct | Depth |
|---|---|---:|---:|---:|
| `Dispatch_base` | pass (all five, `RfcSpec` and `TypeOK`); 21 s | 5,841,572 | 1,732,422 | 15 |
| `Dispatch_noupcheck` | `NothingLost` violated: a second packet overwrites the one waiting to go up | — | — | — |
| `Dispatch_noanswercheck` | `AnswersKept` violated: a second refusal overwrites the first answer | — | — | — |
| `Dispatch_answerafterend` | `NoSendAfterEnd` violated: a refusal after the transports' end is answered | — | — | — |
| `Dispatch_noquote` | `RfcSpec` violated: an ICMP error quoting TCP is taken in and handed to the host's ICMP, where RFC 1122 section 3.2.2 names TCP | — | — | — |
| `Dispatch_witness` | `NoReassembledError` fails at depth 3: a reassembled ICMP error quoting UDP goes up, so the base checks that case | — | — | — |

### UDP sockets (`tla/UdpSockets.tla`)

The receive side of `UdpLayer`: binds, arrivals (empty or not, valid for
this host or not, with or without room in the budget), credit, the
input's end, and closes by handle and by the child's own end, with ports
bound again. Child ids are never reused (`Slots` generations, checked in
`verification/layer`). The code visits sockets in the order of its
`ready` list and gives a socket's send credit back before its next
datagram; the model lets any socket with an event go next, which includes
that order.

The lower port carries only `CheckedIpPacket`, made by the IP layer of the
endpoint that owns this input, so the earlier `CheckScope` and
`CheckChecked` flags, the `NoCrossScope` and `OnlyChecked` properties,
and the `UdpSockets_noscope` control are retired: the code has no branch
for either, the type and the input path are the check, and
`NetworkInput` sits ahead of reassembly (Reassembly above). What
`take_in` still checks itself (sort, protocol, the host's address or a
joined group, the UDP length and checksum) is the arrival's `valid`, and
`UdpSockets_unchecked` now leaves those checks out.

| Property | Meaning |
|---|---|
| `NoCrossSocket` | a datagram goes up only on the child it was queued for, bound to its port, even across close and rebind |
| `OnlyValid` | only a UDP datagram for this host with a good checksum reaches a socket (RFC 1122 sections 4.1.3.4 and 3.2.1.3) |
| `Accounted` | every datagram, empty ones included, is refused, dropped with a report (a full queue, or no room in the budget), queued, gone up, or discarded with its socket |
| `QueueBounded` | a socket holds at most `Queue` datagrams, however small: `QUEUE / DATAGRAM_COST` in the code, where every passing config's `DatagramCost` is 1 |
| `RetiredSilent` | a closed child hears nothing more, except one `Closed` when it closed by its own end |
| `EndedLast` | a socket's end goes up once, after its last datagram |
| `PortsMatch` | the port map names exactly the open sockets |

| Config | Result | Generated | Distinct | Depth |
|---|---|---:|---:|---:|
| `UdpSockets_base` | pass (all seven), three arrivals; 26 s | 12,638,525 | 3,627,578 | 23 |
| `UdpSockets_wide` | pass (all seven), four arrivals, two units of credit, two children; 15 s. With the base's three children it was killed at the 3 GB cap after 6.4 million distinct states (it took 27 minutes in the earlier run), so it now trades a child for the wider arrivals and credit | 6,850,332 | 1,629,900 | 22 |
| `UdpSockets_unchecked` | `OnlyValid` violated: a datagram with a bad checksum, for a bound port, goes up | — | — | — |
| `UdpSockets_skipempty` | `Accounted` violated: an empty datagram skipped | — | — | — |
| `UdpSockets_freeempty` | `QueueBounded` violated: with `DATAGRAM_COST` zero, empties never fill a queue | — | — | — |
| `UdpSockets_queuebyport` | `NoCrossSocket` violated: a queue kept by port goes to the next socket bound there | — | — | — |
| `UdpSockets_lazyclose` | `RetiredSilent` violated: a socket left in its slot hands up its queue after close | — | — | — |
| `UdpSockets_earlyend` | `EndedLast` violated: the end goes up with datagrams still queued | — | — | — |
| `UdpSockets_keepport` | `PortsMatch` violated: close keeps the port | — | — | — |

`UdpSockets_base` finds the same 3,627,578 distinct states as before the
flags were retired: the model already recorded every refused datagram
alike, so dropping the network and checked dimensions shrank only the
transitions.

The UDP layer has no timers (`Timer = ()`, no deadline), so a closed
socket has none to retire; its slot, with its queue, and its port go with
`close` (`sockets.rs` 276-282). `close` leaves the socket's entry in
`ready` where it is: `socket_event` finds no socket for it and skips it
(363-365), and the id is never given to another child.

### Trusted checksum flag (`tla/TrustedChecksum.tla`)

A packet type with a trusted-checksum flag is being written on
`comp/buf-core` and `comp/buf-tcp`. On 2026-11-10 neither branch had a
commit past main; the buf-core worktree held the new `buf` crate,
uncommitted, whose `Chunk` is a view of a backing that clones and pieces
share, with no flag yet. The model is ready for the flag: it states what
the flag must keep, with the operations that `Chunk` and the current
checksum code have, and its header names the Rust function each action
should be checked against once the flag lands.

A packet is a view [lo, hi) of a backing of three one-bit cells; its
checksum covers [cov, hi) and sits in cell cov, valid when that cell is
the parity of the rest. Parity stands in for the RFC 1071 sum: changing
any one covered cell breaks it, and it updates incrementally (RFC 1624).
Cells in [lo, cov) are uncovered, as the IPv4 TTL is not covered by a
transport checksum; pseudo-header fields count as covered. Actions:
`Arrive` (flag clear), `Compute`, `Verify`, `Write`, `Rewrite` (with an
incremental checksum update), `MakeMut` (copy-on-write), `Prepend`,
`Advance`, `SplitTo`, `Clone`, `Coalesce` and `Drop`. Writes through a
view need a backing it alone holds, as `get_mut`, `prepend`,
`extend_within` and `fill` require.

| Property | Meaning |
|---|---|
| `FlagMeansChecked` | a set flag was set by computing or verifying the checksum over exactly the covered bytes there now (an incremental update that kept the checksum counts) |
| `FlagMeansValid` | a packet whose flag is set carries a valid checksum: verifying again would pass |

| Config | Result | Generated | Distinct | Depth |
|---|---|---:|---:|---:|
| `TrustedChecksum_base` | pass (both, plus `TypeOK`); 52 s | 13,858,753 | 675,808 | 16 |
| `TrustedChecksum_noverify` | `FlagMeansValid` violated: a packet arrives with a bad checksum and a verify that did not check sets the flag | — | — | — |
| `TrustedChecksum_writekeeps` | `FlagMeansChecked` violated: checksum computed, then the checksum cell written, flag still set | — | — | — |
| `TrustedChecksum_sharedwrite` | `FlagMeansValid` violated: checksum computed, the packet cloned, one clone written in place; the other keeps its flag over the changed cell | — | — | — |
| `TrustedChecksum_rewritekeeps` | `FlagMeansValid` violated: checksum computed, a covered cell rewritten without the incremental update, flag kept | — | — | — |
| `TrustedChecksum_splitkeeps` | `FlagMeansChecked` violated: checksum over two cells, `split_to(1)`; both pieces keep the flag over one cell each | — | — | — |
| `TrustedChecksum_coalescekeeps` | `FlagMeansChecked` violated: checksum computed, another packet's cell appended, flag kept (the checksum still happens to verify, so only this property sees it) | — | — | — |
| `TrustedChecksum_witness_clone` | `NoFlaggedClone` fails at depth 4: two flagged clones share a backing | — | — | — |
| `TrustedChecksum_witness_header` | `NoFlaggedHeader` fails at depth 4: a flagged packet has uncovered cells in front | — | — | — |

Bounds: two packets and two backings are the fewest that show a clone, a
split, copy-on-write and a coalesce; three cells give a header cell, a
checksum and a covered cell; one-bit cells are enough for parity, where
any change to one covered cell is seen.

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

From the first pass (the 2026-11-10 pass changed no Rust):
`cargo test -p fictionet --lib` passed, 3,915 tests, with the fixes, and
`cargo test -p fictionet --test it -- network udp dns fragment` passed,
404 tests. The four reproduction tests in the bug table that test the old
behavior (all but `a_checked_packet_is_what_the_ip_layer_hands_up`, which
tests the new constructor) fail with the fixes taken out and pass with
them. `cargo clippy -p fictionet --lib --tests -- -D warnings` passed.

## Resource properties

The method is in `verification/README.md`, "Resource properties". This
section covers TCP and below: fragment reassembly, UDP sockets, the
blocks a sandbox's packets arrive in, the TCP socket's stores (whose
own README is `../tcp-store/README.md`), and DNS request parsing and the
resolver's cache. All three layers run from one command:

```sh
cargo xtask ip-verify resources   # the Kani harnesses, Holding.tla's configs, the costed sessions
cargo xtask ip-verify diff        # the Lean vectors, each reassembly step costed
```

The checks found five bugs, each now fixed with a test that fails
before its fix ("The bugs, fixed" below).

### What is charged, and the bounds

| Holder | What pays | The bound, at every moment of every step |
| --- | --- | --- |
| `Reassembly` | its cap, `MAX_WAITING` (4 MiB), counted with `PIECE_COST` (96), `PARTIAL_COST` (1,536) and `EXPIRED_COST` (384) | held ≤ `Reassembly::MOST_HELD`, the cap and the roots of its three maps (a leaf and an inner node each), besides a packet the step hands out; and held ≤ `counted()` and those roots after each step |
| a UDP socket (`Socket::keep`) | the layer's budget | held ≤ what the budget was charged: a datagram's bytes and `Chunk::HEADER` before they are allocated, the queue's places before they grow |
| a link from attach (`SocketLink::poll_recv`) | the sandbox's budget | a packet longer than a block is copied only into a block that budget paid for first |
| the TCP stores (`RxStore`, `TxStore`) | the store's budget for the blocks it makes, the budget that paid a packet's slot for what it keeps of it, and `PLACES` | held ≤ those charges and `PLACES`, the stores' places and a header for each backing they retain, with one more each way for a join |
| `Request::parse` | nothing: it is transient, and the request it makes is kept while the query is answered | held ≤ the records the message can carry decoded (twice a `Record` and a 383-octet name for every 12 octets) and the question; the request keeps at most the question and its octets |
| the resolver's `Cache` | its budget, at `Cache::storage` when made and by its estimate for each entry | held ≤ what the budget was charged |

The constants and why each covers what it counts:

- **`tree_leaf(kv)` = 16 + 11 kv, `tree_inner(kv)` = `tree_leaf` + 96.**
  A node of std's `BTreeMap`: a parent pointer, two `u16`s and room for
  eleven entries; an inner node adds twelve edges. Every node but the
  root holds at least five entries, so a map of n entries has at most
  n/5 leaves and (n/5 + 3)/5 inner nodes: at most a leaf and an inner
  node (`tree_root`) and n times `tree_entry(kv)` = leaf/5 + inner/25 + 2.
- **`PIECE_COST` (96)** ≥ `tree_entry` of a piece's entry (32 bytes).
  **`PARTIAL_COST` (1,536)** ≥ the entries of the map of packets and of
  the deadlines, and `tree_root` of the packet's map of pieces.
  **`EXPIRED_COST` (384)** ≥ `tree_entry` of a kept first fragment, and
  with 8 bytes of fragment header at most `PIECE_COST + PARTIAL_COST`, so
  a kept fragment never counts more than its packet did. Const
  assertions in `ip.rs` check each against `size_of` of the entries.
- **`DATAGRAM_COST` (256)**, what each datagram counts against a socket's
  1 MiB: ≥ `Chunk::HEADER` and a place in the queue (a const assertion).
- **`Chunk::HEADER`**: two reference counts and the `Backing` they share
  (96 bytes on 64-bit targets). No charge counts it, so a holder of many small chunks
  counts it with each.
- **`PLACES`**: `SEGMENTS` places each way and a `Chunk::HEADER` for each
  chunk a store retains, `SEGMENTS` each way, and one more each way for
  the block a join makes while the two it joins are held.

### TLA+

`tla/Holding.tla` threads three stores through `Resources.tla`: the
reassembly against its cap, a socket against its budget, and a receive
store against its charges and `PLACES`. Each holder's code order is a
flag, and each control turns one off.

| Config | Result |
| --- | --- |
| `Holding_base` | passes, with every `Paid`, `Tracks` and the cap and budget limits: 80,696 states generated, 15,580 distinct, depth 8 |
| `Holding_without_roomfirst` | a fragment copied in, then the soonest dropped while past the cap (the code before a2750ef02): violates `ReassemblyPaid` |
| `Holding_without_movefirst` | a first fragment copied while its packet is held: violates `ReassemblyPaid` |
| `Holding_without_chargefirst` | a datagram copied before it is charged: violates `SocketPaid` |
| `Holding_without_headers` | `PLACES` without the backings' headers (the code before e141c7cb3): violates `StorePaid` |

`Resources.tla` now checks each moment against the reservation it had:
a store records the most it ever held past what was reserved at that
moment (`short`), and `Paid` asks that it be zero. Before, `Paid`
compared the step's peak with the reservation at the step's end, so a
copy made before its charge in the same step, and a free followed by a
release, were judged against the wrong reservation. HPACK's five resource
configs give the same results and state counts on it.

### Kani

Three files of counted harnesses (`resources/kani/counting.rs`), each
compiled into its production module: `kani/resources.rs` into `ip.rs`
(`Reassembly::push`), `kani/udp_resources.rs` into `udp/sockets.rs`
(`Socket::keep`), and `../tcp-store/kani/resources.rs` into smoltcp's
`tcp.rs` (`RxStore::insert`, `TxStore::push`), with `counting.rs` now
compiled into smoltcp too. Kani 0.68 with `-Z stubbing -Z c-ffi -Z
mem-predicates -Z restrict-vtable`, the last because each harness reaches
a `Budget`, whose wakers are trait objects, as the layer's budget
harnesses do. One harness at a time, under a 14 GiB scope, on November
10, 2026.

| Harness | Bound | Result |
| --- | --- | --- |
| `the_counter_sees_every_allocation`, in `fictionet` and in smoltcp | the stubs see every allocation | successful (13.4 s in smoltcp) |
| `the_first_datagram_is_paid_before_it_is_kept` | the most live at once is at most what the budget was charged after the step and the budget's own state; the step asks for no more than it charged | successful, 36.1 s |
| `a_second_datagram_is_paid_before_it_is_kept` | the same, into a place already paid for | successful, 90.0 s |
| `a_third_datagram_is_paid_before_it_is_kept` | the same | **does not fit**: out of memory at 14 GiB (51,913 VCCs) |
| `a_fragment_into_an_empty_table_stays_within_its_count`, `a_second_packet_stays_within_its_count`, `a_packet_past_the_limit_makes_room_first` | the most live at once is at most the limit, the maps' roots and the packet built; after the step, at most the count and the roots; the step asks for at most twice its packet and a leaf of each map | **do not fit**: the second ran 27 minutes to 11 GiB at unwind 24 and was stopped; the first ran past 25 minutes at unwind 13; the third, larger, was not run. CBMC unrolls the `BTreeMap`s' node code |
| `a_segment_into_an_empty_store_is_paid_for` and the two across waiting pieces | the most live at once is at most what the budget was charged and `PLACES`, besides the budget's and pool's state | **do not fit**: the first ran past 25 minutes; `insert` keeps 64 pieces in an array, so it unwinds 66; the other two, larger, were not run |
| `a_first_short_write_is_paid_for`, `a_third_short_write_is_paid_for` | the same, for the send store | **do not fit**: the first ran past 25 minutes at unwind 8; the third was not run |

`ip-verify resources` runs the two UDP harnesses that finish and the
counter's own check in both crates; on November 10 it passed in full, with
`Holding.tla`'s five configs and every costed session. The harnesses that do not fit stay in their files,
so a lighter shape can take their place; the costed sessions check the
same bounds on the same code.

### The costed sessions

`tests/it/net_resources.rs`, `smoltcp/src/socket/tcp/store_costs.rs`,
`listen.rs`'s `a_packet_longer_than_a_block_is_paid_from_the_sandboxs_budget`,
and the reassembly vectors in `tests/ip_vectors/reassembly.rs` (every
step of `ip-verify diff`). Each step is costed with
`verification/resources/cost.rs` and the counting allocator. A step
builds the input it takes, so that freeing it is the step's.

| Session | Steps | The linear bound, and why |
| --- | --- | --- |
| reassembly: 40,000 one-fragment packets; 80,000 eight-byte pieces ascending, descending and interleaved; first fragments kept with no one taking them; packets completed from 1,000 shuffled pieces | 40,002; 3 × 80,000; 86,933; 20,000 | twice the packet (built, then its data and headers copied once) and a node split at each of 8 levels in three trees, 2 KiB a node; an expiry copies nothing and asks at most what was counted before it |
| UDP: floods of empty, one-byte and mixed datagrams past a socket's queue, drained and refilled; a flood past a 256 KiB budget | 24,002; 5,000 | twice the packet (built, then the datagram copied), two chunk headers, the layers' own queues (4 KiB), and what the step charged; a queue that doubles moves no more than it charged |
| TCP stores: random segments (both sources, 12 seeds), one-byte segments in and out of order, a slow reader's window joined, contiguous pieces out of order, small writes partly acknowledged (6 seeds) | 182 to 16,386 a session | over each session's steps together: each segment's or write's bytes once, what was charged, and a header for each piece and join |
| DNS queries of 0 to 4,000 compression-pointer records in each section | 18 | twice a `Record` asked over a section's growth and a 383-octet name for every 12 octets, and the question |
| the resolver's cache: 3,000 RRsets of 1, 4 and 32 addresses | 3 × 3,001 | over the session: the offer built, three times that for the normalized copy, what was charged, and the maps' room charged when made, once more for their doublings |

Every session passes (November 10, 2026, `comp/res-net`). "Closest" is
the step that came nearest its charge: bytes live at once against bytes
paid for.

| Session | Closest to the charge |
| --- | --- |
| 40,000 tiny packets | 2,033,876 of 4,202,432 |
| pieces in each of three orders | 2,867,444 of 4,202,432 |
| first fragments kept, no one taking them | 2,442,832 of 4,202,432 |
| packets completed from small pieces | 72,172 of 4,210,548 (with the packet handed out) |
| `ip-verify diff`, seeds 1 to 8, every reassembly step | 23,047 to 28,444 steps a seed; 140,342 of 4,333,758; 0 cases disagree |
| UDP floods | 724,821 of 725,603 |
| UDP flood past a 256 KiB budget | 263,175 of 266,157 |
| TCP stores, `rx joins` (both sources) | 382,260 of 394,720; 518,884 of 525,392 |
| TCP stores, random segments, 12 seeds | 35,413 to 63,123 of 53,140 to 78,464 |
| TCP stores, sending, 6 seeds | 21,846 to 53,631 of 37,480 to 70,668 |
| DNS queries, 4,000 records | 2,155,472 of 5,116,511 while parsing; the request then keeps no more than `keeps`, its question and the octets it echoes |
| cache, 32 addresses a set | 30,103,784 of 38,203,510 |

### The bugs, fixed

- **Reassembly counted a third of what it held** (a2750ef02). An
  unfinished packet counted 192 bytes besides its fragments; its entry in
  a `HashMap`, its deadline and its map of pieces held about 830, and the
  `HashMap` kept its grown table after its packets left. Forty thousand
  one-fragment packets held 15.2 MB against the cap of 4 MiB; the session
  `many_tiny_packets_stay_within_most_held` passed `MOST_HELD` at step
  5,826 with 4,202,556 bytes live, and before that one step that grew the
  `HashMap` asked for 86,920 bytes on 28 bytes of input. A fragment was
  copied in before the cap made room, a first fragment kept for its
  answer was copied while its packet was held, and `finish` gathered every
  piece's slice in a vector first. The maps are now `BTreeMap`s, the
  costs cover each entry's share of its trees, room is made first for the
  same packets, and a kept first fragment is moved, not copied. The Lean
  model takes the new constants and counts `EXPIRED_COST` with each kept
  fragment; `ip-verify diff` passes.
- **A UDP socket charged a third of what each datagram held**
  (b9252b397). 64 bytes for "its sender's address and its place", where a
  datagram held a chunk header (96) and a place (80) in a queue that
  doubled and never gave places back: one-byte datagrams held 228 bytes
  each against 65 charged. On the old code both UDP sessions fail at step
  32, 8,412 bytes live against 6,144 paid.
- **A packet longer than a block from attach was unpaid** (45ebd3386):
  copied into a `Vec` of its own and handed on as `Chunk::unpaid`, after
  72158929e made the blocks a sandbox's packets arrive in its budget's.
  Test `a_packet_longer_than_a_block_is_paid_from_the_sandboxs_budget`.
- **A TCP socket's open charge left out its backings' headers**
  (e141c7cb3), up to 12 KiB a connection beside the 5 KiB charged. With
  the old `PLACES` the joins sessions fail: 110,700 bytes live against
  106,300 paid.
- **A parsed DNS query kept every record it carried** (a75b820a4). Each
  two-octet compression pointer decodes to a name of up to 255 octets, and
  the `Request` kept the whole message while the resolver answered it: a
  64 KiB query kept 2,155,729 bytes. It now keeps none of the answer,
  authority and additional records. On the old code the session fails at
  ten records: 7,849 bytes kept against 1,963.

### Controls and mutations

| Layer | Mutation, in a scratch copy or a control config | What failed |
| --- | --- | --- |
| TLA+ | the four `Holding_without_*` controls above | the `Paid` each names |
| Kani | `Socket::keep` without its header charge, as datagrams were charged before b9252b397 | `the_first_datagram_is_paid_before_it_is_kept`: "the socket held more than its budget paid" (35.8 s) |
| sessions | each bug's old code, above | the step and bytes given above |
| sessions | `RxStore::commit` copying everything ready on each delivery | four of the six store sessions: `rx joins` asked 95,728 bytes in all against 89,008 by step 7; `rx one-byte, in order` 34,343,140 against 34,338,340 |

### Found, not fixed

- **A charged container's growth holds its old and new places for a
  moment.** `ChargedDeque` and `ChargedVec` (`layer/charged.rs`) charge
  the places they grow by, not the old block a reallocation holds while it
  moves. A UDP socket's queue growing from 2,048 places to 4,096 holds
  about 160 KiB more than charged until the old block is freed. Charging
  the old places again for the move breaks two tests of the layer's
  randomized model, whose wakes and refusals assume the old rule; it is
  left for the layer's owner. The UDP Kani harnesses stay within the
  first four places, and the replay's allocator counts a reallocation as
  its change in size, so neither sees it.
- **The cache's normalized copy deduplicates in quadratic time**
  (`normalized` in `resolver/cache.rs` compares each record with every
  one kept). Its memory is linear; its time for an RRset of n records is
  n². Not a memory bound, so not checked here.
- The resolver keeps each client's query (`Asker`) for its resolution,
  with no budget and no count of its own. Whether what feeds it bounds
  the queries in flight was not checked in this pass.

## What is left out

- Reassembly's overlap rules beyond one place per fragment (partial
  overlaps, lengths that disagree, the "more fragments" flag on copies,
  the first fragment's header counted in its cost) are in the unit tests
  and the `ip_reassembly` fuzz target, not the model. So the refinement
  covers overlap as "two fragments at one offset", not partial overlap.
- The refinements are checked against hand-written models of the code
  (`Reassembly.tla`, `Dispatch.tla`), not the Rust itself. The model's
  headers name the lines each step follows; that correspondence is
  reviewed by hand.
- The RFC reassembly spec lets the host give up any buffer for want of
  space (RFC 1122 section 3.3.2), so the refinement says nothing about
  which one goes; `WithinBudget` and `SizeAccounts` check the cap itself.
- Dispatch's `done` kind completes every waiting fragment and its `Timer`
  expires every one, where the code completes and expires per key; the
  slot properties see only whether a packet waits, so this hides nothing
  they check. A reassembled packet that `checked` then refuses is not
  modeled apart from a whole one refused.
- The protocol Kani harnesses do not reach `Reassembly` itself or the
  UDP layer's state; TLA+ and the unit tests cover those. The counted
  resource harnesses do (see "Resource properties").
- The UDP send side, ICMP port-unreachable answers and the `udp::endpoint`
  facade are not modeled. Nor are the multicast groups as state
  (`UdpControl::Join`; the `groups` check is one of the reasons an
  arrival is not valid), the ephemeral port choice, or the `HELD`
  back-pressure on `up` and `down`.
- `TrustedChecksum.tla` checks a design, not code: the flag does not exist
  yet. Its header lists the function each action maps to, for the check
  once `comp/buf-core` and `comp/buf-tcp` land.

## Rerunning

TLC, one config at a time, from this directory's `tla/` (the state
directory may be anywhere outside the repository):

```sh
cd verification/packet-udp/tla
java -XX:+UseParallelGC -Xmx2g -cp ~/.cache/adorably-fv/tla2tools.jar tlc2.TLC \
    -workers 2 -metadir "$CARGO_TARGET_DIR/packet-udp/Reassembly_base" \
    -config Reassembly_base.cfg Reassembly.tla
```

The specs are `Reassembly.tla` (with `RfcReassembly.tla`), `Dispatch.tla`
(with `RfcIpInput.tla`), `UdpSockets.tla` and `TrustedChecksum.tla`; each
config's name starts with its spec's. With two workers and a 2 GB heap, `Reassembly_base` takes about three
minutes, `TrustedChecksum_base` under one, `UdpSockets_base` and
`Dispatch_base` under half a minute, and every other config seconds.

Kani, one harness at a time, from the root of the repository:

```sh
cargo kani -p fictionet --lib --harness parse_reads_exactly_the_declared_length
```

Cap its memory (`systemd-run --user --scope -p MemoryMax=12G`), as this
pass did: wider versions of these harnesses ran past that cap. Each
harness takes under three minutes, compiling included.

The controls run the same way, one at a time or with their proof, and
must report `VERIFICATION:- FAILED` on the check named in the table above.
