# World networking verification

The models of the world network's attachment lifecycle and the plumbing
under it: the ready-slot scheduler, the router's table, the cables and
their packet queues. What each one states, what it found and what it
leaves out is in [VERIFICATION.md](../../VERIFICATION.md) at the root of
the repository.

| Part | What it is | Where |
|---|---|---|
| TLA+ | Four specs checked with TLC: `Attachments`, `Ports`, `Table`, `Cable`. Each has a base config that must pass and ablations, marked `\* expect violation: <Property>`, that must fail on exactly that property | [`tla/`](tla) |
| Kani | Harnesses over the production `Prefix` arithmetic in `route.rs`, included into its test module under `cfg(kani)` | [`kani/`](kani) |

## Running

TLC, one config at a time, from this directory's `tla/`:

```sh
cd verification/world-net/tla
java -XX:+UseParallelGC -Xmx6g -cp ~/.cache/adorably-fv/tla2tools.jar tlc2.TLC \
    -workers 4 -metadir "$CARGO_TARGET_DIR/world-net-verify/Attachments_base" \
    -config Attachments_base.cfg Attachments.tla
```

`Attachments_base` explores about 1.3 million distinct states and takes a
few minutes; every other config finishes in seconds.

Kani, one harness at a time, from the root of the repository (the
harnesses live in test modules, so `--tests` is needed):

```sh
cargo kani -p fictionet --tests --harness ipv4_contains_compares_the_prefix_bits
```

Each harness is named in the file that holds it.

## Failing controls, and the rerun against the TCP layer

Each Prefix harness has a failing control at the end of `Prefix.rs` that
changes one thing and must fail on the one assertion its comment names.
Rerun on `comp/v-tcp-obs` with Kani 0.68.0, every proof passes and every
control fails on exactly its named check:

| Proof | Checks | Control | What it changes | Failed check |
| --- | ---: | --- | --- | --- |
| `ipv4_contains_compares_the_prefix_bits` | 105 | `ipv4_contains_without_the_last_prefix_bit` | asks `contains` with the length one short | "contains compares every prefix bit" |
| `ipv6_contains_compares_the_prefix_bits` | 105 | `ipv6_contains_without_the_last_prefix_bit` | the same for IPv6 | "contains compares every prefix bit" |
| `canonical_keeps_what_the_prefix_holds` | 182 | `canonical_without_clearing_host_bits` | clamps the length but keeps the host bits | "the canonical address is the network address" |
| `overlap_is_a_shared_address` | 105 | `overlap_without_both_directions` | asks only whether the first prefix holds the second's address | "an address in both means overlap" |
| `ipv4_offsets_size_last_and_broadcast_agree` | 158 | `ipv4_offsets_without_the_exact_size` | a size one too large | "the last offset is last" |
| `ipv6_offsets_and_size_agree` | 177 | `ipv6_offsets_without_the_exact_size` | the same for IPv6 | "the last offset is last" |

A control must report `VERIFICATION:- FAILED` with that check:

```sh
cargo kani -p fictionet --tests --harness ipv4_contains_without_the_last_prefix_bit
```
