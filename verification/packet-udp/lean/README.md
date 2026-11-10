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

(to be written)

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
- The `HashMap` is an association list with distinct keys. The code's
  `by_expiry` index is read off its entries (`check` asserts the two
  agree). The cap drops the soonest deadline; between equal deadlines the
  model drops the first entry, the code the least `Key`. No theorem depends
  on which.
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
empty. With seed 1, `reassembly.json` holds 654 cases and 12,407 steps
(688 whole packets, 9,386 waiting, 2,206 discarded, none refused, 127
timer steps) with 27 first fragments kept for answers (16 IPv4, 11
IPv6), and `Reassembly` agrees with the model on every step.

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

(to be written)
