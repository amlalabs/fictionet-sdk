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

(to be written)

## IPv6 extension headers and ICMP

(to be written)
