# World networking verification

The models of the world network's attachment lifecycle and the plumbing
under it: the ready-slot scheduler, the router's table, the cables and
their packet queues. What each one states, what it found and what it
leaves out is in [VERIFICATION.md](VERIFICATION.md).

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

## Resource properties

The method is in `verification/README.md`, "Resource properties". This
part covers the queues packets wait in, and the split of the whole
world's memory that a bound on it needs. It runs with
`cargo xtask layer-verify resources` (see `verification/layer/README.md`).

### The world's memory, four ways

A budget's `used() <= limit()` bounds only what is charged to it. The
world's memory is four parts, and only the first two grow with what the
agent sends:

1. **Charged payload.** What the agent's traffic makes the world keep,
   paid for before it is allocated: a sandbox's `Budget` (its
   connections' containers, every chunk through its backing's
   reservation, and the blocks attach reads packets into), each limited
   cable's count (`pair_with_limit`), each `PacketQueue`'s budget (the
   connection's outbound queue of 32 MiB in `listen.rs`), each
   `delay`'s or `bottleneck`'s store (`LINK_STORE`, 32 MiB a direction),
   and a report store's own budget. At most the sum of their limits.
2. **Bounded engine overhead.** What sits beside a charge, a constant per
   part: a limited cable direction's channel blocks (`CABLE_BLOCKS`
   below), a budget's record, the one report being made before the store
   sees it, a WebSocket step's scratch and an SSH packet's scratch, both
   charged by their callers. The moment a charged container moves its
   items is no longer here: it is charged (84530d0d5).
3. **Topology state.** What world code builds: cables made with `pair()`,
   `Ports` slots, routes, attachments and their address entries. It grows
   with the world's configuration and the attachments it makes.
4. **Trusted application allocations.** World code's own, behind
   `Job::poll` and its `Interface`s. Only the agent is adversarial, so
   these are trusted and outside every budget.

`tla/Memory.tla` checks this split on one limited link, a sandbox budget,
a report store, the engine's overhead, topology and application steps:
`AgentBounded` (what agent steps can raise is at most the link's,
sandbox's and report store's limits plus the overhead constants) and
`Decomposition` (the total is the four parts, and only world steps change
the last two).

**Binds.** The agent's first packet from an address can bind it: a
sandbox's first DHCP lease or first IPv6 source, through
`Filter::bound_now`, which adds a route, a port and an entry in
`Hooks::by_addr`. That happens once per attachment for each family: a
later source is dropped (`sent_v6` checks `bound6`). So these grow with
the attachments the world makes, not with what the agent sends.
`Hooks::by_addr` keeps its entries after detach, one for each address
any attachment ever bound (`VERIFICATION.md`, "What the model leaves
out").

### The queues

**The bug, fixed.** `PACKET_COST`, what a queued packet costs beyond its
capacity, was 64 bytes for its place, but a packet also keeps its
backing's record alive (`Chunk::RECORD_BYTES`), so a limited
cable of one-byte packets held about twice what it counted: a hundred kept
14,692 bytes against 6,500 counted. `PacketQueue`
counted the same and kept its packets in a `VecDeque` nothing paid for,
which doubles and never shrinks: a hundred one-byte packets kept 16,868
bytes against 6,500 charged. `delay` and `bottleneck` counted a packet's
length, not its capacity, in a `VecDeque` of their own. Now
`PACKET_COST` is the record plus a channel slot (the packet and two
words); `PacketQueue` charges each packet's capacity and record and keeps
them in a `ChargedDeque` on the same budget, given back when it empties;
and the link's queue does the same with each packet counted as a limited
cable counts it. Tests in `tests/it/world_memory.rs`, each failing on the
code before.

| Bound | Constant | Why |
| --- | --- | --- |
| a limited cable direction holds at most what it counts, each packet's capacity plus `PACKET_COST`, plus `CABLE_BLOCKS` | `PACKET_COST = Chunk::RECORD_BYTES + size_of::<Packet>() + 2 words`; `CABLE_BLOCKS = 3 * BLOCK`, `BLOCK = 31 * (size_of::<Packet>() + 1 word) + 1 word` | std's list channel keeps 31 slots of a packet and a state word in each block; a packet's share of a block is under a slot and a word. Beside the slots' share it keeps the block it reads from and the one it writes to, each partly empty, and the next, made before a block's last slot is written |
| a `PacketQueue` holds at most what its budget counts, as it fills, as it drains, and nothing once empty | | packets and places are charged before they are kept |
| a full `PacketQueue` holds at most its limit | the limit | |
| a `delay` keeps no more packets than fit `LINK_STORE` alone, and no fewer than fit with three places each | three places: twice what a doubling leaves, and the old ones while they move | `link.rs`, `a_delay_drops_what_does_not_fit` |

| Layer | Check | Result |
| --- | --- | --- |
| counted tests (`tests/it/world_memory.rs`) | zero, one, 31, 32, 100 and 1,000 packets of 0, 1 and 1,500 bytes through a limited cable and a `PacketQueue`, on the binary's counting allocator | pass; all three fail on the code before |
| Kani | the queues' places are `ChargedDeque`s, whose growth the layer's harnesses prove (`verification/layer/README.md`). The cable's channel is std's, with atomics and blocks; it has no harness | |
| TLA+ (`tla/Memory.tla`) | `LinkPaid`, `SandboxPaid`, `ReportsPaid`, `EnginePaid`, `TrustedPaid`, the limits, `StoresTrack`, `AgentBounded`, `Decomposition` | `Memory_base` passes, 16,561 distinct states |

Controls:

| Control | Fails |
| --- | --- |
| the cable and `PacketQueue` before the fix | all three counted tests |
| `Memory_without_countfirst` (queue, then count) | `LinkPaid` |
| `Memory_without_recordcost` (the old 64 bytes) | `LinkPaid` |
| `Memory_agentonpair` (the agent's path through `pair()`) | `AgentBounded` |
| `Memory_without_chargereportfirst` (keep a report, then charge it) | `ReportsPaid` |

