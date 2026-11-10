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

(to be written)

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
