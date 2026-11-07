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
