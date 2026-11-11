# IP, UDP and ICMP: Lean 4 verification

Machine-checked proofs about the IP layer's pure functions, and an
executable Lean reference that writes test vectors for the differential
test `tests/ip_vectors.rs`. Lean core only, no Mathlib; the toolchain is in
`lean-toolchain`.

```sh
cd verification/packet-udp/lean
lake build                  # every proof, Ip/Axioms.lean and the generator
lake exe gen <dir> <seed>   # writes <dir>/<kind>.json
IP_VECTORS=<dir> cargo test --test ip_vectors -- --nocapture
```

## Checksum, header and UDP

`Ip/Checksum.lean`, `Ip/Header.lean` and `Ip/Udp.lean`. Each module holds
an RFC written plainly (the reference), the Rust code written in Lean
where a theorem needs it (the model), the theorems, and the vectors.
`cargo xtask ip-verify all` builds the proofs, checks their axioms, and
runs the vectors of seeds 1 to 8 against the Rust; run it under a memory
cap, as with Kani (`systemd-run --user --scope -p MemoryMax=8G cargo xtask
ip-verify all`).

### How the Lean maps to the Rust

| Lean | Rust (`src/stdlib/network/`) |
|---|---|
| `Checksum.words`, `onesSum`, `checksum` | RFC 1071 section 1, one 16-bit word at a time: the reference |
| `Checksum.quads`, `pairs`, `odd`, `sum` | `ip::sum`: four octets at a time as a `u32`, then pairs, then an odd octet shifted left 8 |
| `Checksum.foldNat`, `fold` | `ip::fold`: the carry loop, then `!(acc as u16)` |
| `Checksum.pseudoHeaderSum`, `transportChecksum` | `ip::pseudo_header_sum`, `ip::transport_checksum` |
| `Checksum.pseudo4`, `pseudo6` | the pseudo-headers of RFC 768 and RFC 8200 section 8.1, octet by octet |
| `Header.v4` | `Header::parse` (`truncated` false) and `Header::parse_truncated` (true) for IPv4: `ip::v4` |
| `Header.check`, `whole` | `Header::check` and `Header::parse_whole` for IPv4: `ip::v4_checked` |
| `Header.payload`, `dstPort` | `Header::payload`, `Header::dst_port` |
| `Header.build`, `build6` | `ip::packet_with_ipv4_options` (and `packet_with` with no options), `packet_with` over IPv6 |
| `Header.hop`, `hopChecksum` | `ip::hop` |
| `Header.setHeaderChecksum` | `ip::set_header_checksum` |
| `Udp.parse` | `udp::Datagram::parse` |
| `Udp.checksumOk`, `checksumOkRust` | `ip::udp_checksum_ok` and `Datagram::checksum_ok`: the reference over the RFC pseudo-header, and the Rust over `transport_checksum` |
| `Udp.encode`, `sentChecksum` | `udp::encode` |
| `Udp.encodedLen` | `udp::encoded_len` |

### Theorems

Octets are `Nat`s below 256 (`Octets`). Every theorem below is in
`Ip/Axioms.lean` and rests on `propext`, `Quot.sound` and
`Classical.choice` at most.

| Theorem | Statement | RFC |
|---|---|---|
| `foldNat_eq_rep`, `onesSum_eq_rep` | the carry loop and the word-by-word end-around carry both give 0 for a zero sum and otherwise the sum's representative modulo 65535 in 1 to 65535 (`rep`) | RFC 1071 section 1 |
| `rust_checksum` | `fold(sum(0, data))` is `checksum data` for data of every length, odd included | RFC 1071 section 1 |
| `rust_sum_sum` | two chained `sum` calls give the checksum of the two parts' words side by side, each part padding an odd octet on its own | RFC 1071 section 2(B) |
| `rust_split` | split at an even offset, that is the checksum of the whole | RFC 1071 section 2(B) |
| `rust_pseudo4` | `pseudo_header_sum` then `sum` and `fold` is the checksum of the RFC 768 pseudo-header and the data, for every length below 2^16 | RFC 768, RFC 9293 section 3.1 |
| `rust_pseudo6` | the same over the RFC 8200 pseudo-header, for every length below 2^32: `len` added as one integer equals its two 16-bit halves | RFC 8200 section 8.1 |
| `verifies` | a checksum written into a field at an even offset makes the whole checksum 0 | RFC 1071 section 1 |
| `fold_zero`, `fold_eq_ffff_iff` | `fold(0)` is 0xffff, and only a zero sum folds to 0xffff | RFC 1071 section 1 |
| `fold_eq_zero_iff` | `fold` gives 0 exactly for a nonzero multiple of 65535, the one's-complement negative zero | RFC 1624 section 3 |
| `checksum_of_zeros` | all-zero data of any length has checksum 0xffff | RFC 1071 section 1 |
| `zero_fields_agree` | when the rest of the data does not sum to 0, a field of 0x0000 and one of 0xffff give the same checksum | RFC 1624 section 3 |
| `one_octet_detected` | changing any one octet to any other value changes the checksum | RFC 1071 section 2(B) |
| `one_bit_detected` | so does flipping any one bit | RFC 1071 section 2(B) |
| `v4_some_iff` | `parse` and `parse_truncated` read exactly when the version is 4, the IHL is at least 5, IHL · 4 fits the bytes, and IHL · 4 ≤ total length, with total length ≤ bytes unless truncated | RFC 791 section 3.1, RFC 1122 section 3.2.1.1 |
| `v4_payload` | the payload runs from IHL · 4 to the total length (to the bytes present when truncated), inside the bytes; trailing bytes are not the packet's | RFC 791 section 3.1 |
| `check_some_iff` | `check` takes exactly what `parse` reads whose header checksum verifies and whose source is neither 255.255.255.255 nor multicast | RFC 1122 sections 3.2.1.2, 3.2.1.3 |
| `whole_some_iff` | `parse_whole` is `check` without fragments | RFC 791 section 3.2 |
| `v4_ignores` | the readers do not look at the type of service, the TTL or the checksum field, so a host does not drop a packet for its TTL | RFC 1122 section 3.2.1.7 |
| `v4_ignores_flag_bits` | the reserved bit and "don't fragment" change nothing the readers return; a fragment is MF set or an offset (in units of 8) other than 0 | RFC 791 section 3.1 |
| `dstPort_none` | no port for a later fragment or a protocol other than TCP and UDP | RFC 791 section 3.2 |
| `build_checks` | for all addresses, protocol, TTL, TOS, identification, DF, option octets up to 40 and payloads that fit, `check` takes what the builders write, with the header length the options make, the payload given, no fragment, and so a verifying checksum (the source a host may hear from) | RFC 791 section 3.1 |
| `hop_v4_expired` | a router drops an IPv4 packet with TTL 0 or 1, unchanged, and forwards any other | RFC 1812 section 5.3.1 |
| `hop_v6` | the same for the IPv6 hop limit, which is lowered by one and nothing else changes | RFC 8200 section 3 |
| `hop_v4` | the forwarded IPv4 packet differs only in the TTL, lowered by one, and the checksum field, which is RFC 1624 equation 3 | RFC 1624 section 3 |
| `hop_keeps_checksum` | the header after the hop has the checksum it had before: a header that verified still does, and a corrupted one stays corrupted | RFC 1624 section 3 |
| `hop_is_recompute` | for every header that verifies and TTL above 1, received checksum 0xffff included, the hop writes what `set_header_checksum` would | RFC 1624 sections 3 and 5 |
| `rust_checksumOk` | Rust's UDP check over `transport_checksum` is the reference over the RFC pseudo-header | RFC 768, RFC 8200 section 8.1 |
| `parse_some_iff` | `Datagram::parse` takes exactly bytes of at least 8 whose length field is at least 8 and within them, and keeps up to that length | RFC 768 |
| `zero_field_v4`, `zero_field_v6` | a zero checksum field is "no checksum" over IPv4 and always fails over IPv6 | RFC 768, RFC 8200 section 8.1 |
| `encode_parses` | `encode` writes what `parse` takes whole, with the ports and payload given and a checksum field that is never zero | RFC 768 |
| `encode_verifies` | what `encode` writes verifies over both families, including a computed 0 sent as 0xffff | RFC 768, RFC 8200 section 8.1 |
| `one_octet_fails` | one changed octet anywhere in a datagram that verified fails the check, except over IPv4 when it leaves a zero field | RFC 768 |
| `encodedLen_ok`, `encodedLen_mixed` | `encoded_len` refuses mixed families and takes exactly the payloads whose datagram fits one IP packet with a basic header, so the 16-bit lengths never wrap | RFC 768, RFC 791, RFC 8200 section 3 |

### Vectors

`Gen.lean` writes four files for this part per seed. Every expected value
comes from the reference (`checksum` over the RFC layout, `v4`, `check`,
`build`, `hop`, `setHeaderChecksum`, the UDP functions), and
`tests/ip_vectors/{checksum,header,udp}.rs` compare the Rust with it.

| File | Cases | Rust called |
|---|---|---|
| `checksum.json` | random data of every length 0 to 64; all-zero and all-0xff data; data with its checksum or its complement appended; `fold` of 0, 0xffff, carries, multiples of 65535 and random 48- and 62-bit sums; two chained sums of odd and even parts; IPv4 and IPv6 pseudo-headers with lengths 0, 0xffff, 0x10000, 2^32 - 1 and random | `checksum`, `fold`, `sum`, `pseudo_header_sum`, `transport_checksum` |
| `header.json` | 60 random IPv4 packets (options in a third, every fragment flag mix, TTL 0 and 1, broadcast, multicast, class E and zero sources, trailing bytes), each with 13 mutations: another version, IHL below 5, IHL past the bytes, total length below IHL, past the bytes and exactly the bytes, one flipped header bit, the checksum field's two zeros, the reserved and DF bits flipped, fewer than 20 bytes; 40 noise packets; 60 packets built with `packet_with` and `packet_with_ipv4_options` (No Operation and unknown options, TTL 0) and read back | `Header::parse`, `parse_truncated`, `check`, `parse_whole`, `payload`, `dst_port`, `packet_with`, `packet_with_ipv4_options` |
| `hop.json` | 80 valid IPv4 packets with every TTL edge, each also with a received checksum of 0xffff and with a checksum that does not verify; IPv6 with hop limits 0, 1, 2 and 255; packets too short for the field; other versions | `hop`, and `set_header_checksum` over the lowered header, which must equal what `hop` wrote |
| `udp.json` | `parse` with length fields below 8, 8, exact, past the bytes, with trailing bytes and 65535; `encode` over both families, a quarter with payloads whose checksum comes out 0; `checksum_ok` of each encoded datagram, with one octet changed, a zero field, a 0xffff field, the other family's source, mixed families, and fewer than 8 octets; `encoded_len` at 65,507, 65,527 and their neighbors | `Datagram::parse`, `udp_checksum_ok`, `Datagram::checksum_ok`, `encode`, `encoded_len` |

### Modelling choices

- The Rust accumulator is a `u64`; the model's is a `Nat`. `sum` and
  `pseudo_header_sum` document the room a caller must leave, so on every
  input the code takes they agree.
- Addresses are octet lists (4 for IPv4, 16 for IPv6), not typed
  addresses. Lengths are the list lengths.
- `Header.v4` is IPv4 only. Packets with version 6 go to the IPv6 reader,
  which `Ip/Ext6.lean` covers; the header vectors never set version 6.
- `Header.build` computes the header checksum with the reference
  `checksum`; `rust_checksum` says that is what `set_header_checksum`'s
  `fold(sum(0, header))` computes. Option octets are given as octets;
  the vectors give them as `Ipv4Option::NoOperation` and
  `Ipv4Option::Unknown`, which `encode_ipv4_options` writes as type,
  length and data (RFC 791 section 3.1).
- The hop theorems take the header as its first 12 octets and the rest
  (addresses and options, an even number of octets); `hop_v4` shows the
  payload after them is untouched.
- What `udp::UdpLayer::take_in` does with a datagram is these functions:
  it reads the IP payload (which ends at the IP total length), drops it
  without a report when `Datagram::parse` refuses it or
  `Datagram::checksum_ok` fails (RFC 1122 section 4.1.3.6), and otherwise
  delivers `payload()`. The layer's state is in `../tla/UdpSockets.tla`.

### Departures from the RFCs

- Fixed: `Header::check` took IPv4 packets from 255.255.255.255 and from
  multicast sources, which RFC 1122 section 3.2.1.3 says a host must
  silently discard. Test:
  `ip::tests::a_host_takes_nothing_from_a_broadcast_or_multicast_source`.
- Fixed: `ip::udp_checksum_ok` called a datagram between two families with
  a zero checksum field good. Test:
  `ip::tests::addresses_of_two_families_have_no_good_udp_checksum`.
- Kept: a directed broadcast source (RFC 1122 section 3.2.1.3, cases (d)
  to (f)) and a loopback source from outside (case (g))
  are not refused by `check`, which knows neither the subnet nor the
  interface. Class E sources are taken, as the RFC reserves them but does
  not call them invalid.
- Kept: `packet`, `packet_with` and `packet_with_ipv4_options` write any
  TTL they are given, 0 included, though RFC 1122 section 3.2.1.7 says a
  host must not send TTL 0. They are building blocks a world uses to
  imitate any host, a misbehaving one included. The stdlib's own senders
  use 64, 255, 1 or a world's choice (`icmp::Options`), never 0 unless a
  world asks for it.
- Kept: an IPv6 UDP length of 0 (a jumbogram, RFC 2675) is refused by
  `Datagram::parse`, as its doc comment says.
- Kept: a router does not check the IPv4 header checksum before the hop
  (RFC 1812 section 5.2.2 says it must). `hop_keeps_checksum` shows the
  error survives the hop, so the next host still drops the packet. The
  router (`route.rs`) is outside this part.

### Results

`cargo xtask ip-verify all` at commit `f3aee377a`, under an 8 GB cap:
`lake build` checks every proof, and `Ip/Axioms.lean` prints 37 headline
theorems, each resting on `propext`, `Quot.sound` and `Classical.choice`
at most (no `sorryAx`, no `native_decide`). For each of seeds 1 to 8,
0 cases disagree:

| File | Cases per seed |
|---|---:|
| `checksum.json` | 324 |
| `header.json` | 985 |
| `hop.json` | 336 |
| `udp.json` | 876 |

In seed 1 the vectors reach, among others, 9 datagrams whose computed
checksum is 0 and is sent as 0xffff, 105 headers `parse` reads and
`check` refuses (bad checksum or source), and 52 hops over a verifying
header with a received checksum of 0xffff.

## Reassembly

`Ip/Reassembly.lean` models `Reassembly` in `src/stdlib/network/ip.rs`
(ip.rs 527-952) step for step: `reassemble` (expire, then the fragment,
then the cap), `push_fragment` (split into `lookup`, the code's
`entry().or_insert_with`, and `admit`, the checks after it), `take`,
`kill`, `expire`, `arrived` and `finish`. Per key it keeps what the code's
`Partial` keeps: `dead`, the first fragment's headers, the pieces by
offset, `total`, `have` (named `got`: `have` is a Lean keyword), `size` and
the deadline; and the table's `size`, held under `MAX_WAITING` with
`PIECE_COST` and `PARTIAL_COST`.

### Theorems

Every theorem below is about the model of the code, not a separate
specification; each names the RFC text it states. They rest only on
`propext`, `Quot.sound` and `Classical.choice` (`Ip/Axioms.lean`).

| Theorem | Statement | RFC |
|---|---|---|
| `complete` | Any packet within the limits (key `k`, first-fragment headers `h`, data cut by `P` into nonempty contiguous pieces from 0 to `t`, every non-last piece with "more fragments" set and a multiple of 8 bytes, `lenField h t ≤ 65535`), delivered in any order with any exact copies, every arrival before the first arrival plus the timeout, into a table that keeps the invariant, holds nothing for `k` and has room for the packet under the cap: every step waits until the last missing fragment arrives, and that step hands out exactly one whole packet, `finish h` of the data in order. | RFC 791 section 3.2, RFC 8200 section 4.5 |
| `finish_ipv4` | For an IPv4 first-fragment header, the whole packet is that header with the total length rewritten (header plus data), "more fragments" and the offset cleared, "don't fragment" kept (byte 6 masked with `0x40`), every other byte but the checksum unchanged, and an RFC 1071 checksum that verifies (is 0), then the data. | RFC 791 sections 3.1, 3.2; RFC 1071 |
| `finish_ipv6` | For IPv6, the first fragment's headers with the payload length rewritten (headers after the fixed one plus the data), every other byte unchanged, then the data. | RFC 8200 section 4.5 |
| `arrived6_names_fragment` | The IPv6 first fragment's headers are those in front of the Fragment header, with the "next header" byte that named it (44) now naming what the Fragment header named. | RFC 8200 section 4.5 |
| `reassemble_sound` | Every whole packet a step hands out is built from a first fragment's headers and fragments taken for its key, which do not overlap and tile `[0, t)` exactly, the one ending at `t` with "more fragments" clear and every other with it set; each data byte is the byte of the one fragment that covers it (`BuiltFrom`). `hist_reassemble` keeps the premise that every waiting piece came from a fragment taken. | RFC 791 section 3.2, RFC 815, RFC 8200 section 4.5 |
| `complete_iff_noHoles` | For a packet in the table with length `t`, the code's test `have == total` holds exactly when the pieces tile `[0, t)`, and exactly when RFC 815's "no holes left" holds. The code keeps a map of non-overlapping intervals instead of a hole list; on such a map counting bytes finds the holes. `overlapOk_iff` shows the code's two neighbor checks see every overlap. | RFC 815 sections 3-6 |
| `overlap_kills` | A fragment that overlaps a waiting fragment of its packet and is not an exact copy of it (same offset, bytes and "more fragments" flag) is discarded, and what stays at the key is dead with the same deadline (or nothing, if the cap took it). | RFC 5722 section 4, RFC 8200 section 4.5, RFC 8900 section 3.5 for IPv4 |
| `copy_ignored` | An exact copy of a waiting fragment changes nothing; the step is the expiry alone, and the result is waiting. | RFC 8200 section 4.5 |
| `length_disagreement_kills` | A last fragment whose end is not the length already set kills the packet. | RFC 8200 section 4.5 |
| `dead_stays_dead` | Until its deadline, every fragment of a dead packet but a one-fragment packet is discarded, and the key stays dead with the same deadline, or empty. | RFC 5722 section 4 |
| `too_long_discarded` | A fragment ending past 65,535 bytes is discarded; a packet waiting at its key is killed; with none waiting, nothing is kept. | RFC 8200 section 4.5, RFC 791 section 3.1 |
| `finish_none_iff` | `finish` refuses exactly an IPv4 total length or IPv6 payload length over 65,535. | RFC 791 section 3.1, RFC 8200 section 3 |
| `reassemble_inv`, `reassemble_check` | After every step at most `MAX_WAITING` bytes are counted, the count is the sum of the packets' sizes, each packet's size is `PARTIAL_COST` plus its headers plus each piece's data and `PIECE_COST`, and everything `Reassembly::check` asserts holds. | (the cap is the code's own limit) |
| `first_fragment_deadline`, `arrived_timeout` | A packet's deadline is the arrival of its first fragment plus the timeout, 30 s for IPv4 and 60 s for IPv6, and stays so. | RFC 8200 section 4.5; Linux `ipfrag_time` for IPv4 |
| `late_completes_nothing` | A fragment arriving at or after its packet's deadline completes nothing: only a one-fragment packet can come out of that step. | RFC 8200 section 4.5 |
| `atomic_alone` | A one-fragment packet (offset 0, no more fragments) is handed up alone and changes nothing else. | RFC 6946 section 4 |
| `bad_discarded`, `arrived_header` | A non-last fragment whose length is not a multiple of 8, and an empty fragment, are discarded and change nothing; only a fragment at offset 0 carries headers. | RFC 8200 section 4.5 |
| `expire_out`, `reassemble_out` | Expiry keeps, after what it kept before, the first fragment of every packet whose deadline has come, if that fragment arrived; a step keeps nothing else (the fragment it takes and the cap add nothing). | RFC 1122 section 3.3.2, RFC 8200 section 4.5 |
| `firstPacket_none`, `firstPacket_dead` | A packet whose fragment zero never came, and one already dropped for a bad fragment, keep nothing: no answer. | RFC 1122 section 3.3.2 ("if fragment zero has been received"), RFC 5722 section 4 |
| `firstPacket_from`, `expire_from` | Every kept first fragment is the rebuild of one fragment taken for the packet's key at offset 0: its headers, its Fragment header (`frag6`) and its data (with `Hist`, which now also tracks `frag6`). | RFC 792, RFC 1122 section 3.3.2, RFC 4443 section 3.3 |
| `arrived4_rebuild`, `arrived6_rebuild` | That rebuild is the packet as it came, up to its IPv4 total length or IPv6 payload length: for IPv6, the "next header" byte names the Fragment header (44) again and the Fragment header's 8 bytes are back. | RFC 792, RFC 4443 section 3.3 |

The cap itself (4 MiB) is far too large for vectors; it is proved
(`reassemble_inv`) and not tested.

### Vectors (`reassembly.json`)

Each case is a run of steps with times, from an empty table: a packet for
`push`, or no packet for the timer (`expire`). Each step's expected result
is what the model makes of it: the whole packet's bytes, waiting,
discarded, or refused; and then the first fragments kept for Time Exceeded
answers, which the test takes (`take_expired`) and compares byte for byte.
It also checks the answer `reassembly_time_exceeded` builds for each: ICMP
Time Exceeded, code 1, from the fragment's destination, quoting its start.
`tests/ip_vectors/reassembly.rs` runs the same steps on `Reassembly` with
the same `Instant`s and compares every one. Thirteen
scenarios, each for IPv4 and IPv6, 25 rounds, plus four cases at the length
limit: fragments in any order with exact copies; partial overlaps (with the
original bytes there or others); the same place with other bytes; a copy
with the other "more fragments" flag; a last fragment that disagrees on the
length; a pause just before, at, or past the deadline; two packets
interleaved (another identification, or the other family); an end past
65,535; a non-last length not a multiple of 8 and an empty fragment; a
one-fragment packet next to waiting ones; a copy with its TTL changed (an
IPv4 header that no longer verifies, so not a fragment) or its hop limit
changed; a packet killed by an overlap that the same key makes again
after its deadline; and some fragments, then the timer just before, at,
or past the first deadline, then the rest. A pause may also run the timer.
IPv4 packets carry random options (copied to later
fragments or not), "don't fragment" and the reserved bit; IPv6 packets carry
an optional Hop-by-Hop header in front of the Fragment header and an
optional Destination Options header behind it, and later fragments may
name another next header. The limit cases reassemble to an IPv4 total
length or IPv6 payload length of 65,535 and 65,536.

### Modelling choices

- Octets are `Nat`s below 256; time is a `Nat` of milliseconds (the
  theorems only add and compare times).
- The map of packets (a `BTreeMap`) is an association list with distinct
  keys. The code's `by_expiry` index is read off its entries (`check`
  asserts the two agree). The cap drops the soonest deadline; between
  equal deadlines the model drops the first entry, the code the least
  `Key`. No theorem depends on which.
- The model takes a fragment, then caps. The code makes room first
  (`make_room`), dropping the same packets in the same order, then copies
  the fragment in, so the state and the result are the same; the vectors
  hold the code to them. The code keeps a timed-out packet's first
  fragment in the parts its packet held and rebuilds it when it is taken;
  the model keeps it rebuilt. Both count its bytes and `EXPIRED_COST`.
- A piece carries the "more fragments" flag of its fragment as a ghost
  field that the step never reads, for the soundness theorem.
- The table also holds `out`, the first fragments kept for answers, as
  the code's `expired` queue, counted in `size`. A packet keeps
  `frag6` (where the "next header" byte that named the Fragment header
  is, and the Fragment header) with its first fragment's headers, as the
  code does; `rebuild` reads at most 8 bytes of it, as the code keeps a
  `[u8; 8]`.
- The model keeps several first fragments expired in one step in its
  table's order, the code by deadline; the vector test compares them as
  sets. `complete` takes the IPv6 Fragment header of the first
  fragment as any `f6`.
- `arrived6` walks chains the way `chain6` walks the ones it accepts. A
  chain `chain6` refuses never reaches reassembly (`push` refuses it
  first); those checks belong to the extension-header model, and the
  vectors only hold accepted chains. `push` strips a whole IPv6 packet's
  extension headers as `strip_extension_headers` does for accepted chains.
- The theorems are about fragments as `arrived` reads them (`Frag`);
  `arrived4` and `arrived6` are checked against the code by the vectors.

### Departures from the RFCs

- RFC 8200 section 4.5 asks for ICMPv6 Parameter Problem, code 0, for a
  non-last fragment whose length is not a multiple of 8 (pointing at the
  Payload Length) and for one whose offset and length pass 65,535
  (pointing at the Fragment Offset). The code drops both silently. These
  are "should"s; kept. Answering would also change what the world's
  sandbox filter (`world/net/attachments.rs`) does with a refused packet
  bound elsewhere: it forwards it.
- Fixed: RFC 1122 section 3.3.2 says a host MUST send ICMP Time Exceeded
  (code 1) when IPv4 reassembly times out with fragment zero received;
  RFC 8200 section 4.5 asks the same of IPv6 ("should"). `expire` dropped
  the packet silently. Now it keeps the packet's first fragment, rebuilt
  as it came, for `take_expired`; `reassembly_time_exceeded` builds the
  answer with `icmp::error` (so nothing about an ICMP error or to a
  source that is not one host); `IpLayer` sends it down like a parameter
  problem; and the sandbox filter answers for the gateway and the
  machines, the hosts the world plays, and drops the rest silently.
- RFC 1122 section 3.3.2 recommends an IPv4 timeout of 60 to 120 seconds;
  the code waits 30, as Linux's `ipfrag_time`. Kept.
- RFC 791's algorithm accepts overlapping IPv4 fragments; the code applies
  RFC 5722's rule to IPv4 too, as RFC 8900 section 3.5 and RFC 1858
  advise against overlap attacks. Kept.
- RFC 8200 section 4.5 says to discard a fragment that passes 65,535; the
  code also kills a packet waiting at its key. Stricter; kept.
- An empty fragment is discarded. RFC 791 does not forbid an empty last
  fragment; kept.
- An IPv4 fragment whose header checksum fails is not read as a fragment
  and comes back as a whole packet; the IP layer's check
  (`CheckedIpPacket::checked`) then refuses it (RFC 1122 section
  3.2.1.2). Not a departure of reassembly.

### Results

Lean 4.35.0: `Ip/Reassembly.lean` checks with no `sorry`, 187 theorems,
of which the 29 named in the table above are listed in `Ip/Axioms.lean`; each
rests on `propext`, `Quot.sound` and `Classical.choice` or fewer.
`inv_empty` shows the empty table keeps the invariant, and `cut_witness`
that `Cut` is met by a real cut, so the premises of `complete` are not
empty. With seed 1, `reassembly.json` holds 654 cases and 13,808 steps
(2,298 whole packets, 9,337 waiting, 2,050 discarded, none refused, 123
timer steps) with 23 first fragments kept for answers (11 IPv4, 12
IPv6), and `Reassembly` agrees with the model on every step; seeds 2 and
3 agree too. About one IPv4 source in five is the limited broadcast or a
multicast address, which `arrived4` (with `Header.badSource`, RFC 1122
section 3.2.1.3) does not read as a fragment, as `v4_checked` does not.

The one finding that needed a fix was the missing ICMP Time Exceeded
(above); `packet::tests::a_timed_out_ipv4_packet_is_answered_when_fragment_zero_came`
and its IPv6 twin fail without the fix. No other bug was found.

### Rerunning

```sh
lake build && lake env lean Ip/Axioms.lean
lake exe gen <dir> 1
IP_VECTORS=<dir> cargo test -p fictionet --test ip_vectors reassembly
```

## IPv6 extension headers and ICMP

`Ip/Ext6.lean` covers how a destination host checks an IPv6 packet's
extension headers (`chain6`, `check_options`, `Header::check`,
`Header::parse`, `Header::parse_truncated` and `strip_extension_headers`
in `src/stdlib/network/ip.rs`). `Ip/Icmp.lean` covers every ICMP and
ICMPv6 message the engine builds: all of them come from `Options::error`
and `Options::echo_reply` in `src/stdlib/network/icmp.rs`. The callers
are `error`, `host_unreachable` (`world/net.rs`, for unrouted packets),
`time_exceeded` (`route.rs`, when a router's TTL or hop limit runs out),
`address_unreachable` (`world/net.rs`), `ip::parameter_problem` (the IP
layer's refusals) and the UDP layer's `port_unreachable`
(`udp/sockets.rs`: type 3 code 3, or ICMPv6 type 1 code 4). Nothing in the
tree generates Packet Too Big.

### Extension headers (`Ip/Ext6.lean`)

Octets are `Nat`s and a read past the end gives 0; the length checks make
that read harmless, as the Rust's `get` returning `None` takes the same
branch. `chain6` follows the Rust loop step for step. `rfcCheck` is the
RFC's account written separately: lay the chain out as RFC 8200 section 4
does (`decode`: each header's Next Header byte names the next, and a
non-first fragment's chain ends at its Fragment header, section 4.5), then
apply each header's rule in order (`faultOf`, `scan`), then RFC 7112's rule
for a first fragment (`tail`).

| Theorem | Statement | RFC |
|---|---|---|
| `chain6_check_eq_rfc` | for every byte list, the code's walk equals `rfcCheck`: a packet shorter than 40 bytes or than its payload length is discarded and bytes past the payload length are not its own; Hop-by-Hop anywhere but first is Parameter Problem code 1 pointing at the Next Header byte that names it; options are decided by `optionsVerdict`; a Routing header with Segments Left 0 is skipped, any other is code 0 pointing at its Routing Type; a second Fragment header discards; a first fragment (offset 0, more to come) that does not hold the whole chain and the upper-layer header's fixed part is code 3 with pointer 0; any other header that runs past the packet discards | 8200 §3, §4.1, §4.3, §4.4, §4.5; 7112 §5 |
| `optWalk_eq_rfc` | `check_options` equals the first option, in order, that asks for something: Pad1 and PadN nothing; other types by their two high bits, 00 skip, 01 discard, 10 and 11 code 2 pointing at the option; an option whose length runs past its header discards | 8200 §4.2 |
| `chain6_problem2` | a code 2 points at an option whose type's high bits are 10 or 11 | 8200 §4.2 |
| `chain6_pos` | a walked chain ends at the payload length cut to the bytes present, with the upper-layer header between byte 40 and the end, and with no Fragment header the protocol is no extension header | 8200 §3 |
| `strip_spec` | when `strip_extension_headers` takes headers out, the result is the fixed header with the upper protocol as Next Header, the upper bytes' length as payload length and its other bytes unchanged, then exactly the upper bytes; and `chain6` takes it with no extension headers left | 8200 §3, §4 |

Modelling choices, each kept as the code has it:

- Atomic fragments (offset 0, no more to come) are not first fragments for
  RFC 7112: they are processed as whole packets (RFC 6946 section 4), so a
  header running past one discards it, with no code 3.
- The upper-layer header a first fragment must hold is its fixed part: 20
  bytes of TCP (not its options), 8 of UDP, 4 of ICMPv6 (RFC 4443 section
  2.1), none for any other protocol. Linux asks 8 for ICMPv6 and 1 for others.
- A jumbogram (payload length 0 with a Jumbo Payload option, RFC 2675) is
  discarded, since its Hop-by-Hop header does not fit in a 40-byte packet.
  No link here carries more than 65,575 bytes.

Departures from the RFCs, kept:

- A second Fragment header is discarded. RFC 8200 section 4.1 asks a host
  to accept headers any number of times; a fragment inside a fragment is
  something no stack sends, and the code refuses it.
- An unrecognized Next Header value after the chain is not answered with
  code 1 (section 4, a "should"): the IP layer hands any protocol it does
  not know to the "everything else" interface, which the world may serve.
- An unknown option of type 10 to a multicast destination is not answered
  (section 4.2 asks for the answer, and RFC 4443 section 2.4(e.3) allows
  it). `parameter_problem` sends from the packet's destination, which is
  then a multicast address, and the IP layer has no unicast address of the
  host to send from. `parameter_problem_option` in `Icmp.lean` proves that
  every option answer the engine does send is one the RFC asks for.

### ICMP and ICMPv6 (`Ip/Icmp.lean`)

`error` and `echoReply` follow `Options::error` and `Options::echo_reply`
with the default `Options`; `parse` and `parseWhole` follow
`Header::parse` and `Header::parse_whole` (through `Ext6.chain6`), and
`ipPacket` follows `ip::packet_with`. Checksums use `Ip/Checksum.lean`'s
RFC 1071 reference.

| Theorem | Statement | RFC |
|---|---|---|
| `fill_word`, `filled_verifies` | writing the complement of the one's-complement sum into a zero checksum word makes the RFC 1071 checksum of the whole come out 0, over any even-length prefix | 1071 §1 |
| `error_message` | an error is the IP packet from the given address to the offending packet's source, whose message is the type, the code, the checksum, the second word (pointer or 0), then the quoted bytes | 792; 4443 §2.1, §3 |
| `error_checksum` | the error's checksum verifies: over the message for ICMP, over the pseudo-header (source, destination, 32-bit length, next header 58) and the message for ICMPv6 | 792; 4443 §2.3; 8200 §8.1 |
| `error_quote` | over IPv4 the error is at most 576 bytes and quotes at least the IP header and 8 bytes of data, or the whole packet when it is shorter; over IPv6 it is at most 1,280 bytes and quotes the whole packet or exactly as much as fits | 792; 1122 §3.2.2; 1812 §4.3.2.3; 4443 §2.4(c) |
| `error_v4_allowed` | no IPv4 error is sent about an ICMP error message (types 3, 4, 5, 11, 12), a datagram to the limited broadcast or a multicast address, a non-first fragment, or a datagram whose source is not one host (zero, network 0, loopback, broadcast, multicast, class E) | 1122 §3.2.1.3, §3.2.2; 1812 §4.3.2.7 |
| `error_v4_sent` | every other IPv4 error is sent, except about ICMP messages that are neither queries nor errors, or carry no type byte | 1122 §3.2.2 |
| `error_v6_allowed` | no ICMPv6 error is sent about an ICMPv6 error message (types below 128) or Redirect (137), a packet to a multicast address, or one from the unspecified or a multicast address | 4443 §2.4(e) |
| `error_v6_sent` | every other ICMPv6 error is sent, except from loopback, about Neighbor Discovery messages (133 to 136), about an ICMPv6 message with no type byte, and the (e.3) exceptions | 4443 §2.4(e) |
| `parameter_problem_option` | an option answer the engine sends points at a type starting 10 or 11 and goes to a non-multicast destination, so RFC 8200 asks for it | 8200 §4.2; 4443 §2.4(e.3) |
| `echo_reply_copies` | an echo reply goes from the address the request was sent to back to a source that names one host; its message is the request's with type 0 (IPv4) or 129 (IPv6), the same code, and every byte after the checksum (identifier, sequence number, data) unchanged; its checksum verifies | 792; 1122 §3.2.2.6; 4443 §4.2 |

Departures from the RFCs, kept:

- No rate limit. RFC 4443 section 2.4(f) says a node MUST limit the ICMPv6
  errors it originates, and RFC 1812 section 4.3.2.8 asks routers to. The
  functions are pure and the code claims no limit; a world that wants one
  limits its own loop.
- Over IPv4 the code does not know a subnet's directed broadcast address
  or whether a packet came as a link-layer broadcast (RFC 1122 section
  3.2.2), so it checks only the limited broadcast and multicast
  destinations.
- An echo request to a multicast address is not answered (RFC 4443
  section 4.2 says it SHOULD be), and IPv4 echo replies carry no options
  (RFC 1122 section 3.2.2.6 asks Record Route and Timestamp to be updated
  and a source route reversed). `extras::linux::ipv4_options` does the
  latter for TCP.
- With `Options::echo_nonzero_code` (the Linux profile) an IPv4 echo
  request with a nonzero code is answered and its code echoed; RFC 792
  gives code 0. The model and the vectors use the default options.

### Dispatch of ICMP errors (read, not proved)

`Sort::of` in `packet.rs` sends an ICMP error to the transport whose
packet it quotes (RFC 1122 section 3.2.2.1): for IPv4 types 3, 4, 11 and
12, and for IPv6 every type below 128, with at least 8 bytes, it reads the
quoted header with `Header::parse_truncated`, which walks IPv6 extension
headers to the upper protocol, and sorts by that protocol when it is TCP or
UDP and the quote is not a non-first fragment. Redirects and everything
else go to the ICMP interface. This holds as written. It does not compare
the quoted packet's family or source with the outer packet's: that is the
transport's check. TCP takes only a destination unreachable that quotes a
pending connect's addresses, ports and current SYN sequence number; UDP
drops every ICMP error. The TLA+ model `Dispatch.tla` covers the slots.

### Vectors

| File | Cases | What each case holds | Rust replay (`tests/ip_vectors/`) |
|---|---:|---|---|
| `ext6.json` | 4,000 | a random IPv6 packet with 0 to 4 extension headers (options of every action, Routing with and without segments left, first, later and atomic fragments, Authentication), upper protocols TCP, UDP, ICMPv6 and others, payload lengths right, too long, too short and 0, some cut short; and `chain6`'s result in check mode, both read modes, and `strip` | `ext6.rs` against `Header::check`, `Header::parse`, `Header::parse_truncated` and `strip_extension_headers` |
| `icmp.json` | 5,000 | IPv4 and IPv6 packets (sources and destinations of every kind above, fragments, ICMP of every type, up to 1,400 bytes) with `error`, `time_exceeded`, `host_unreachable`, `address_unreachable` and `parameter_problem` from addresses of both families; and echo requests (good, bad checksums, codes, types, short, fragments, extension headers, bad IPv4 header checksums), with the whole packet the model builds or none | `icmp.rs` against the same Rust functions and `echo_reply` |

The Rust replays compare the whole output packet, byte for byte, with the
Lean model's.

### Results

`lake build` checks the 15 headline theorems above with no `sorry`, and
`Ip/Axioms.lean` prints only `propext`, `Quot.sound` and
`Classical.choice` for each. With seed 1, `ext6.json` (4,000 cases) and
`icmp.json` (5,000 cases) replay with 0 disagreements. Every branch is
reached: in `ext6.json` the destination check gives 1,915 discards, 739
whole packets, 490 fragments, and Parameter Problem codes 0 (168), 1 (150),
2 (531) and 3 (7); `strip` removes headers from 152 packets. In
`icmp.json` each entry point both answers and stays silent: echo 408 and
877, `error` 438 and 1,403, `time_exceeded` 147 and 441,
`host_unreachable` 45 and 298, `address_unreachable` 114 and 203,
`parameter_problem` 171 and 455.

The model of `Options::error` found one bug, fixed in `icmp.rs`:
`is_one_host` let errors and echo replies go to sources in network 0 and
class E (RFC 1122 sections 3.2.1.3 and 3.2.2). The tests
`errors_go_only_to_one_host` and
`pings_from_an_address_that_is_not_one_host_get_no_reply` cover both and
fail without the fix.

The IPv6 Kani harness was rerun after the `CheckedIpPacket` change, with
no drift to fix: `ipv6_stripping_leaves_a_checked_packet` passed, 0 of
1,106 checks failed (32 unreachable), 85 s; its control
`ipv6_stripping_keeping_the_payload_length` failed on exactly "the payload
length is the original's", 1 of 631 checks. Both runs needed two other
areas' Kani modules (`verification/tls/kani/LayerProof.rs` and
`verification/layer/kani/mod.rs`, which no longer compile) switched off
for the run.
