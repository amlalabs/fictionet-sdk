# MPTCP in Lean 4

Lean core, with toolchain `leanprover/lean4:v4.35.0`; no Mathlib, axioms for
protocol behaviour, native decision oracles, or unfinished proofs. Use
`cargo xtask mptcp-verify lean` for the build and axiom audit and
`cargo xtask mptcp-verify diff` for all eight seeds.

| Module | Theorems and executable reference |
|---|---|
| Option, Codec | Every well-formed option round-trips through `emit` and `parse`; an independent length table matches acceptance of every multi-byte option; absent subtype, unknown/experimental subtypes and overlong data are errors |
| Pure | Network-order encoding preserves every representable key; token is the high 32 digest bits and IDSN the low 64; SHA-256 output is exactly 32 octets; ordered HMAC inputs have the required lengths; checksum is a 16-bit complement that balances the one's-complement sum; odd bytes occupy the high half-word; DSN expansion preserves the low bits, stays in 64 bits, and chooses a signed half-window offset |
| Layout | All combinations of standard options fit; padded headers align to four bytes; every extra option within `room` fits; explicit core and extras Linux SYN/segment room; the RFC 5681 second-full-segment ACK threshold |
| Data | Failed receive state is terminal; FIN prevents later data; fallback cannot discard a data gap |
| Axioms | Audit of every headline theorem above |
| Gen | Streaming JSON vectors for the Rust differential test, including send offsets through a full 32-bit subflow wrap and subsequent retransmissions |

`decode_encode` quantifies over all well-formed options and all their payload
bytes, not only the generated examples. Well-formedness restricts list lengths
and byte/bit ranges to the Rust types and RFC wire format. Because Lean represents
opaque byte fields as lists, `emit` alone does not enforce their lengths; callers
of the inverse theorem must supply `Wf`. This corrects the earlier draft's claim
that `Wf` was exactly equivalent to `emit` succeeding.

`parse_length_rule` covers all option data with at least two bytes;
`singleton_length_rule` proves that only MP_PRIO accepts a one-byte body, and
`empty_malformed` rejects empty input. The length case split covers every possible input within the RFC's
40-byte option limit. `overlong` covers all larger inputs. The table includes
version-zero MP_CAPABLE's two compatible layouts, unknown algorithms, all DSS
presence/width flags, and ADD_ADDR's echo, address size and optional port.
Reserved bits are ignored when parsing and emitted as zero. An arbitrary wire
string is therefore compared with its canonical encoding, not asserted to be
identical after decoding. Unknown subtypes are typed errors, not invented values.

The SHA-256 implementation follows FIPS 180-4 and HMAC uses the fixed 16-byte key
material of MP_JOIN. It is executable Lean, independent of Rust's ring calls.
The proofs establish the byte ordering, lengths, and digest extraction used by
MPTCP; they do not prove SHA-256 collision resistance or correctness of the
compression algorithm against a separate cryptographic specification. Differential
vectors compare the full concrete HMAC and both digest ends for zero, maximal,
and seeded keys. Key generation entropy is not a pure function and is not modelled.

Checksum arithmetic uses unbounded natural numbers and end-around carry modulo
65535, retaining the distinction between the two representations of zero. Rust
uses its Internet-checksum implementation. DSN arithmetic uses mathematical
integers and reduction modulo 2^64; Rust uses wrapping unsigned operations and
a signed 32-bit displacement. Exactly half a short sequence space goes backward.

The Layout model selects two policies. The core case is checked against default
settings. The Linux case is checked only through `fictionet_extras::linux::settings()`.
No Linux window size, TIME-WAIT duration or ACK-width choice is required of core.
The layout differential test observes emitted SYN-ACKs on simulated IP cables,
including all combinations of scale, SACK, timestamps and MPTCP additions.

Data uses complete one-byte mappings with offsets relative to IDSN + 1. It checks
the output and data ACK after each event, including duplicate data, all six
orders of three distinct mappings, checksums, FIN at every position, and loss
of mapping. It does not model partial TCP arrivals or multiple subflows; Rust
regression tests cover partial data and the single-subflow send sequence.

## Resource correction

An early `lake exe gen` invocation rebuilt `Codec` before running the generator.
A broad repeated symbolic case-splitting tactic in the length proof exhausted
24 GiB during elaboration; the kernel identified `lean`, not the compiled
reference executable. The proof now uses bounded, explicit header cases and
small acceptance lemmas. The property and input bounds are unchanged. The runner
separates compilation from execution, records both logs as they are written,
and puts each command in its own 12 GiB systemd scope. Generation also streams
individual cases instead of constructing and serializing an entire JSON tree.
The initial full streamed suite, including 65,543 send cases, used about 480 MiB
at the scope peak; this includes Lake startup. No vectors were removed.
