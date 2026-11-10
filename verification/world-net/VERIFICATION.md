# Verification of the world network

Branch `fv-net` off `8ccf47fae`. The source lines named here and in the
models were checked against `e2858ccc4` (`comp/fv-deep`) on November 9,
2026. The area is the world network's
attachment lifecycle (`src/stdlib/world/net/attachments.rs`) and the
plumbing under it: the ready-slot scheduler (`src/stdlib/network/ports.rs`),
the router's table (`src/stdlib/network/route.rs`), the packet queue
(`src/packet_queue.rs`) and the cables (`src/cable.rs`). The models are
under `verification/world-net/`; its README says how to run them.

## What was modeled and checked

### TLA+ (TLC)

Each spec has a base config, which must pass, and ablations marked
`\* expect violation: <Property>`, which must fail on exactly that
property. The ablations are the check that the properties have teeth: each
one removes a step the code takes and names the property that step holds
up.

**`Attachments.tla`**: the lifecycle of filtered and routed attachments
(`filter`, `Attached`, `Context::routed`, `Routed`), the leases
(`Bindings::bind`, `Filter::bound_now`, `Attached::drop`), `Hooks::by_addr`
and `Hooks::routes`, the router's edit queue (`Router::add`, `Edit::Route`)
and the link closes it sees later (`ports::Event::Closed`), the connections
`abort_peers` resets, and the attribution a machine makes with
`Hooks::sandbox_at` when a packet arrives. Two filtered names, one routed
name, one bindable address, one host, one outside address, two lives per
name. Constants `OwnByRoutesTo` and `KeepByAddr` switch between the code
before and after the fix.

| Config | Checks | Result |
|---|---|---|
| `Attachments_base` | `LeaseExclusive`, `ByAddrNamesLast`, `EntryWhileAlive`, `NoStaleConnections`, `AbortsOnlyOwn`, `Attribution`, `TableFollowsLeases`; liveness `StaleRoutesGo`, `DropsFinish` | passes: 11,046,773 states generated, 1,329,160 distinct, depth 36, 3 min 4 s |
| `Attachments_resetsbyroute` (`OwnByRoutesTo = FALSE`: the code at `8ccf47fae`) | `AbortsOnlyOwn` | violated as expected (2,410 states, 980 distinct on November 9, 2026; the count to the first violation varies between runs): attach `r`, detach `r`, a host connects to a host, the route is re-edited, the router sees the old link close, and the reset takes the hosts' connection |
| `Attachments_namesbyroute` (`OwnByRoutesTo = FALSE`) | `Attribution` | violated as expected (35 states, 29 distinct, depth 4 on November 9, 2026): with `r` attached a host's connection is put down to `r` |
| `Attachments_forgetbyaddr` (`KeepByAddr = FALSE`) | `Attribution` | violated as expected (2,556 states, 970 distinct, depth 8 on November 9, 2026): forgetting a `by_addr` entry on detach puts an in-flight packet down to the route |

**`Ports.tla`**: `Ports::next`'s search of the ready bitmap from after the
slot served last (`Ready::find`, `Ready::clear`), `SlotWaker::wake_by_ref`
setting a slot's bit and then waking the task if its parked flag is up,
and the task parking its waker and serving once more before it returns
Pending, with slots being added, closed and their peers closing. The
constant `RecheckAfterPark` is whether `next` serves once more after
parking, as the code does. The model was rewritten for the lock-free
bitmap on branch `comp/buf-locks` and has not been run with TLC yet.

| Config | Checks | Result |
|---|---|---|
| `Ports_base` | `TypeOK`, `FlagHasWaker`, `SlotIsSomewhere`, `NoLostTask`; liveness `Served` | not run yet |
| `Ports_norecheck` (`RecheckAfterPark = FALSE`) | `NoLostTask`, `Served` | not run yet; expected to fail: a slot woken between the empty search and the park finds the flag down while the task sleeps on |

**`Table.tla`**: the router's `Table` (`routes`, `by_port`, `lengths`) under
`Edit::Route` and `Event::Closed`, over the seven prefixes of a two-bit
address space, with `best` as the longest match. `CloseOrphans` is whether
an edit closes a port left with no prefix; `CountLengths` is whether
`insert` records the prefix's length for `best` to walk.

| Config | Checks | Result |
|---|---|---|
| `Table_base` | `ByPortInverse`, `LengthsCount`, `RoutedPortsOpen`, `OpenPortsRouted`, `BestIsLongest` | passes: 875,839 states, 16,384 distinct, depth 5 |
| `Table_keeporphans` | `OpenPortsRouted` | violated as expected, 384 states, 383 distinct |
| `Table_nolengths` | `BestIsLongest` | violated as expected, 2 states |

**`Cable.tla`**: a cable's two ends (`cable::pair`, `End::send`,
`End::poll_recv`, `End::drop`), each direction a lock-free queue up to
`MaxQueued` with the receiver's parked waker (`sync::Parked`). A send
queues, then looks at the parked flag; a receiver that finds the queue
empty parks, then looks once more before it returns Pending.
`RecheckAfterPark` is whether it looks once more, and `DropWakesPeer`
whether dropping an end wakes the other's parked receiver, as the code
does. The model was rewritten for the lock-free cable on branch
`comp/buf-locks` and has not been run with TLC yet.

| Config | Checks | Result |
|---|---|---|
| `Cable_base` | `TypeOK`, `FlagHasWaker`, `WakeIsComing`, `ClosedAfterDrain`, `NoQueueForTheDropped`, `ClosedMeansDropped`; liveness `WakeAfterPark`, `LearnsClosed` | not run yet |
| `Cable_norecheck` (`RecheckAfterPark = FALSE`) | `WakeIsComing`, `WakeAfterPark` | not run yet; expected to fail: a packet sent between the receiver's look and its park finds the flag down |
| `Cable_dropsilent` (`DropWakesPeer = FALSE`) | `WakeIsComing`, `LearnsClosed` | not run yet; expected to fail: the parked receiver at the other end never hears the close |

### Kani (over the production code)

The harnesses are in `verification/world-net/kani/Prefix.rs`, included
into `route.rs`'s test module under `cfg(kani)`, and run with `cargo kani
-p fictionet --tests --harness <name>` under an 8 GiB memory cap. Each
takes any prefix of its family (any address, any length, past the width
included) and, where it needs one, any address or second prefix.

| Harness | States | Result |
|---|---|---|
| `ipv4_contains_compares_the_prefix_bits` | `Prefix::contains` agrees with the first `len` bits for IPv4, never holds an IPv6 address; `mask` is those bits | passes, 0.3 s |
| `ipv6_contains_compares_the_prefix_bits` | the same over 128 bits | passes, 0.8 s |
| `canonical_keeps_what_the_prefix_holds` | `canonical` clears the host bits, clamps the length and is a fixed point, for both families. For IPv4 it keeps `contains`, `mask`, `network`, `last`, `size`, and `broadcast`; for IPv6, `contains`, `last`, and `size` | passes, 6.6 s |
| `overlap_is_a_shared_address` | `overlaps` holds exactly when some address is in both, is symmetric, never across families | passes, 3.6 s |
| `ipv4_offsets_size_last_and_broadcast_agree` | `nth` is defined exactly below `size`, offset 0 is `network`, the last offset is `last`, `broadcast` is `last` up to /30 and nothing past it | passes, 1.8 s |
| `ipv6_offsets_and_size_agree` | a /0 has no `size` and `nth` reaches every offset; otherwise `size` is 2^(128 - len) with `nth` defined exactly below it; no broadcast | passes, 4.3 s |

Harnesses were also written over `PacketQueue` (charges and order through
pushes and pops, clear and `mem::take`), `Ports`'s ready queue (each slot
queued at most once, in order) and the router's `Table` (its three views
in step with a reference, `best` the longest). Every one of them was
killed at the 8 GiB cap during CBMC's propositional reduction, at every
bound tried down to one push of a two-byte packet; the common factor is
state in a `VecDeque` or `HashMap`. They were not kept. The ready queue
and the table are modeled in `Ports.tla` and `Table.tla`; the packet
queue's accounting has only its unit tests.

## Bugs confirmed and fixed

### A route's sandbox detaching reset the hosts' own connections, and a host's connection was put down to the route

Reproduction: `stdlib::world::net::tests::a_route_detaching_leaves_host_connections_alone`
in `src/stdlib/world/net.rs`. Hosts `a` and `c` connect to host `b`, one
before and one while the sandbox routed at `0.0.0.0/0` is attached; then
that sandbox drops. At `8ccf47fae` the test fails twice over:

- `gone == 4`: both connections, both ends, were reset when the route
  detached. `Routed::drop` reset every peer no sandbox had bound whose
  longest route was the detaching one, and a host's address has no lease,
  so the hosts' addresses matched.
- `b` recorded the second connection as `(1, "internet")`: `Hooks::sandbox_of`
  named the route's sandbox for every address its prefix held, the hosts'
  included, although `Context::routes_to` never let the route carry those
  addresses.

Root cause: three places decided what a route's sources are, each
differently. The forwarding path used `Context::routes_to` (the prefix
holds the address, it is not martian, not in the sandboxes' subnet, not a
gateway, not under a longer trusted prefix, not a machine); the reset in
`Routed::drop` used "no lease and this is the longest route"; the
attribution in `Hooks::sandbox_of` used "the longest route".

Fix (commit `Decide what a route owns in one place`): `Destinations`,
which knows where the network has addresses other than at its routes,
moved from `Context` into `Hooks`, and its `routes_to` is the one answer
for the forwarding path (`Routed::poll_recv`), the attribution
(`Hooks::sandbox_of`) and the reset (`Routed::drop`). The reset asks
through `Destinations::sources`, which copies the machines' addresses
first, since `abort_peers` evaluates its predicate with the endpoints
locked and the machines are behind the world lock. `Shared::fixed` went
with it, since the trusted prefixes now live in `Destinations`.

The model found both: `Attachments_resetsbyroute` and
`Attachments_namesbyroute` are the code before the fix, and the base
config is the code after it. The test is the regression. After the fix
every test under `stdlib::world::net::`, `stdlib::network::route::`,
`stdlib::network::ports::`, `packet_queue::` and `cable::` passes, and
clippy with `-D warnings` and rustfmt are clean.

## What the model leaves out

- One routed name, one bindable address and two lives per name. A second
  routed name on the same prefix, or a route prefix equal to a LAN's, are
  configuration errors `Net` does not validate; the model does not reach
  them.
- `Hooks::by_addr` entries are never reclaimed; the model keeps them too
  (`KeepByAddr`), since forgetting them misattributes in-flight packets.
  For IPv4 the table is bounded by the subnet; for IPv6 it grows by one
  entry per address a sandbox ever bound.
- Attribution is by address: a packet from a sandbox that detached, whose
  address another sandbox has since bound and released, is put down to the
  later holder. The model states this as `ByAddrNamesLast` and accepts it
  in `Attributed`; nothing in the code tells the two apart.
- A route re-attaching under the same name gets a new attachment id; a
  connection made under the old id keeps it. The model does not check ids
  across lives.
- The TCP state machines, the DNS and DHCP services, the LAN members
  (`Member`, `join_lan`) and the UDP path are outside every spec.
- The `PacketQueue`, the ready queue's `push` and `pop`, and the `Table`
  code itself have no proof over the Rust: their TLA+ specs are models,
  tied to the functions by name, not the code.
- The route the network starts with at `0.0.0.0/0` (and `::/0`), the
  `unreachable` task that answers "host unreachable"
  (`src/stdlib/world/net.rs` 706-751 and 1102-1136), is not in the model.
  In the code the first routed attach moves the prefix and closes that
  interface (`route.rs` 297-301), which ends the task, and nothing puts
  it back. After the route's sandbox detaches, the prefix has no route at
  all: packets for outside addresses are dropped at the router with no
  ICMP answer, no `Unreachable` report, and no `Refusal::NoRoute`, where
  before the attach they were answered. The model's `routePort = None`
  stands for both states.
- `Destinations::routes_to` is evaluated when a packet arrives or a route
  detaches, against the machines then. The model's hosts are fixed. A host
  placed through `Net::handle` at an address an outside peer was using
  makes that peer a machine: its open connections through the route are
  no longer the route's, so `Routed::drop` does not reset them.
- `Ports.tla` has `add`, `close`, and `replace` into a free slot, between
  polls. `replace` over an open slot, the extra source polled before the
  bitmap, the deadline, the 64-packet budget, and cancellation are outside
  it. The bitmap is a set: its summary words, which only let a search skip
  idle words, are left out, and so is the order `Ready::clear` and
  `SlotWaker` keep between a word and its summary bit. The randomized
  test `every_waiting_port_is_served_within_one_turn_of_the_others` runs
  the real bitmap across a word and a summary word.
- `Cable.tla` counts packets against `MaxQueued`. The code charges bytes
  plus `PACKET_COST` against `Cable::limit` with an atomic counter
  (`Direction::reserve`), and a `pair()` has no limit. The model's steps
  are atomic and interleave in one order; the code gets that order from
  the two `SeqCst` fences in `Parked::park` and `Parked::wake`, which TLC
  does not check. The `std::sync::mpsc` queue is taken as a correct
  lock-free FIFO. The name guard a cable carries for `Attacher` is outside
  the model.
- `Table.tla` has one address family. The code keys `lengths` by family
  and length, and `best` ranges over the destination's family only.
- `src/stdlib/network/link.rs` (`delay`, `bottleneck`, `filter`, and
  `tap`) has no model. The links inside the network are cables
  (`link` in `net.rs`, `pair_with_limit`).
