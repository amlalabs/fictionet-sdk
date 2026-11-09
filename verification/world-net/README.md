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
systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=10G -p MemorySwapMax=0 \
  java -XX:+UseParallelGC -Xmx2g -cp ~/.cache/adorably-fv/tla2tools.jar tlc2.TLC \
    -workers 2 -metadir "$CARGO_TARGET_DIR/world-net-verify/Attachments_base" \
    -config Attachments_base.cfg Attachments.tla
```

`Attachments_base` explores about 1.3 million distinct states and takes a
few minutes; every other config finishes in seconds.

Kani, one harness at a time, from the root of the repository (the
harnesses live in test modules, so `--tests` is needed):

```sh
CARGO_BUILD_JOBS=4 systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=10G -p MemorySwapMax=0 \
  cargo kani -p fictionet --tests --harness ipv4_contains_compares_the_prefix_bits
```

Each harness is named in the file that holds it.

World hosts stage one shared IP dispatcher and both transport layers before
publishing their route. Admission associates a TCP child opening with its
sandbox before allocating the application; reset and retained guards use the
public transport boundary. `Attachments` still models connections by peer and
attachment lifetime, independently of application children. It does not model
packet dispatch or the construction of protocol stacks. Transactional listener
staging is covered separately by `tcp-port-zero/Binding_preparation.cfg`.

The attachment model was rerun on November 8, 2026 with two TLC workers
and a 2 GiB Java heap: 11,046,773 generated states, 1,329,160 distinct
states, depth 36, no violation. The reset-by-route mutation violated
`AbortsOnlyOwn`; forgetting by address and naming by route each violated
`Attribution`, as required by their configurations.
