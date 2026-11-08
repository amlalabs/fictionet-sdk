# Layer foundation: what was modeled and found

This pass covers the layer foundation in `src/stdlib/layer/`: how `Chain`
(`chain.rs`), `Switch` and `Handoff` (`switch.rs`) and the `Driver`
(`driver.rs`) move items between layers; `Children` (`children.rs`) over a
mux whose children live in `Slots` (`carrier.rs`); and the state of
`Slots`, `Budget` and `Charge` (`budget.rs`), `Timers` (`timers.rs`) and
`Chunk` (`carrier.rs`). The commands are in the [README](README.md).

No property failed on the code's safety rules. One liveness property fails
on the code as it is: a child command whose credit cost is larger than the
mux's whole window for that child never goes out (below, "Finding"). No
code in `src/` changed apart from the line that includes the Kani proofs.

## On the merged foundation

The pass was written on `comp/v-layer` and merged into `comp/foundation`
(commit `e68a070d3`); everything was rerun at code revision `6aa68ae5f`.
`children.rs`, `carrier.rs`, `budget.rs` and `timers.rs` did not change,
so `Children.tla` and the Kani proofs describe the same code. `chain.rs`,
`driver.rs` and `switch.rs` gained an urgent path: while the next layer
refuses an event, a layer's `take_urgent` events (TLS's write credit) go
past it, one at a time, through a slot of their own in `Chain`
(`chain.rs:140-149`) and in the `Driver` (`driver.rs:206-224`).
`Route.tla` has no layer with urgent events: with `take_urgent` answering
None, the trait's default, the code runs exactly the statements the model
does, and the line numbers above are the merged ones. The order in which
an urgent event passes a refused one, and that it still arrives once, are
not modeled; that is open.

| Config | Generated | Distinct | Result |
| --- | ---: | ---: | --- |
| `Route_base.cfg` | 1,569,747 | 1,058,166 | all four properties hold |
| `Route_wide_base.cfg` | 8,718,455 | 5,653,462 | all four properties hold |
| `Route_without_keepblocked.cfg` | 2,948 | 2,236 | `UpConserved` violated |
| `Route_without_keeprest.cfg` | 3,086 | 2,373 | `UpConserved` violated |
| `Route_without_blockedisstill.cfg` | 412,883 | 303,862 | `RunEnds` violated |
| `Route_without_leftoversfirst.cfg` | 28,572 | 27,317 | `UpConserved` violated |
| `Route_without_restfirst.cfg` | 115,023 | 97,468 | `UpConserved` violated |
| `Route_without_moveabove.cfg` | 1,981 | 1,280 | `DownConserved` violated |
| `Route_without_switchonce.cfg` | 10,908 | 10,042 | `HandoverOnce` violated |
| `Route_without_driverkeepsrest.cfg` | 261,078 | 209,874 | `UpConserved` violated |
| `Children_base.cfg` | 12,789,594 | 1,857,160 | all five invariants hold |
| `Children_refuse_base.cfg` | 14,398,126 | 2,645,648 | all four invariants hold |
| `Children_stalled_base.cfg` | 1,561,917 | 219,760 | the invariants and `ControlProgress` hold |
| `Children_commands_base.cfg` | 2,040 | 504 | `CommandCredit`, `CommandsGo` hold |
| `Children_without_checkoverrun.cfg` | 36 | 28 | `EventCredit` violated |
| `Children_without_checkcommandcredit.cfg` | 31 | 25 | `CommandCredit` violated |
| `Children_without_reserveforcontrol.cfg` | 1,270,241 | 213,928 | `ControlProgress` violated |
| `Children_without_muxchecksgeneration.cfg` | 2,313 | 1,010 | `NoStaleDelivery` violated |
| `Children_without_keybywholeid.cfg` | 1,009 | 502 | `NoStaleDelivery` violated |
| `Children_large_command.cfg` | 742 | 191 | `CommandsGo` violated: the finding below, still open on the code as it is |

Each was run with `-workers 4 -Xmx6g` under an 8 GB memory cap. The Kani
results on the merged code are in the Kani section below.

## Routing through Chain and Switch: `Route.tla`

[`Route.tla`](tla/Route.tla) is the stack `Chain<L, Switch<A, B>>` run by a
`Driver` whose owner plays the harness. Each byte is a token numbered in
the order it was sent, so a chunk is a sequence of tokens. The layers are
abstract: every entry point may give any answer rule 1 allows (take all,
take a prefix and hand back the rest, refuse whole as `Blocked` or
`Closed`), and every `advance` may move any prefix of what a layer holds.
`L` and `B` pass bytes through; `A` may use bytes from below as its own
protocol, pass bytes either way, and reach its boundary at any time. At the
boundary it takes nothing more, and once its output has been taken it hands
over what it took and did not use, which the switch cuts into any chunks.
`Chain::advance` and the switch run statement by statement, as the Rust
does, and `Driver::run` advances until nothing moves.

| Model | Rust (`src/stdlib/layer/`) |
| --- | --- |
| `OfferSlot`, `OfferMoved` | `chain.rs:62` `offer` |
| `StepL`, `StepS`, `StepTU`, `StepOU`, `StepTD`, `StepOD` | `chain.rs:133-171` `Chain::advance` |
| `StepS`, `StepH` (first phase) | `switch.rs:195-205` |
| `StepS`, `StepSB`, `StepSA` (second phase), `FeedQueue` | `switch.rs:207-223`, `feed` at `switch.rs:101` |
| `EventAnswers`, `CommandAnswers` | `switch.rs:128-159` `Switch::on_event`, `on_command` |
| `StartRun`, `StepE` | `driver.rs:168` `Driver::run` |
| `SendBelow`, `SendAbove` | `driver.rs:190-226` and `send` at `driver.rs:246` |
| `Deliver`, `OwnerQueue` | `driver.rs:142`, `harness.rs:249-263` |
| `Command` | `driver.rs:151` |

What is checked:

- `UpConserved`, `DownConserved`: no byte is lost, duplicated or
  reordered. Every byte sent is in exactly one place: on its line through
  the stack (from what the far end took back to what the owner still
  holds, in the order the layers hold it), used by `A`, or refused by a
  closed input. The line is strictly increasing, so the order is the order
  sent, across partial admission, refusal and the handover of both
  leftovers.
- `HandoverOnce`: the handover happens at most once.
- `RunEnds`: `Driver::run` always reaches an advance in which nothing moved,
  so the routing loop never needs its step limit. Weak fairness of the run's
  steps only.

Refusal keeping ownership is in the conservation properties: an item that
an entry point hands back stays with whoever offered it, at the front of
its queue.

| Config | Generated | Distinct | Depth | Result |
| --- | ---: | ---: | ---: | --- |
| `Route_base.cfg` (3 bytes up, 2 down) | 1,569,747 | 1,058,166 | 83 | all three invariants and `RunEnds` hold, 17 s |
| `Route_wide_base.cfg` (3 bytes each way) | 8,718,455 | 5,653,462 | 94 | all hold, 136 s |
| `Route_without_keepblocked.cfg` | 3,135 | 2,423 | 10 | `UpConserved` violated: `A` refuses the chain's held chunk and `offer` drops it |
| `Route_without_keeprest.cfg` | 3,341 | 2,627 | 10 | `UpConserved` violated: `A` takes a prefix and the slot keeps the whole chunk |
| `Route_without_blockedisstill.cfg` | 692,413 | 517,000 | | `RunEnds` violated: a chunk `A` refuses forever makes every advance report progress |
| `Route_without_leftoversfirst.cfg` | 31,157 | 29,842 | 18 | `UpConserved` violated: `B` takes the chain's newer chunk before `A`'s leftover |
| `Route_without_restfirst.cfg` | 113,931 | 96,628 | 24 | `UpConserved` violated: leftovers `<<1, 2>>, <<3>>`, `B` takes byte 1, the rest `<<2>>` goes behind `<<3>>` |
| `Route_without_moveabove.cfg` | 1,956 | 1,255 | 9 | `DownConserved` violated: the command `A` took is gone after the switch |
| `Route_without_switchonce.cfg` | 10,613 | 9,749 | 15 | `HandoverOnce` violated: the switch hands `A`'s leftovers over a second time |
| `Route_without_driverkeepsrest.cfg` | 266,551 | 214,495 | 30 | `UpConserved` violated: the top takes part of a chunk and the driver drops the rest |

### What `Route.tla` leaves out

- Timers, work and reports. They go to the part their `Side` names and are
  not routed between parts; a timer of `A`'s that fires after the switch is
  ignored by construction (`switch.rs:161-175`).
- Errors. An `Err` from any entry point ends the connection, and nothing
  routes after it.
- The contract on `Handoff` implementations. The model's `A` hands over
  only once its own output has been taken, as the trait asks. A layer that
  hands over with output still queued loses it; the switch cannot check this.
- Byte contents and protocol meaning. `A`'s handover keeps everything it did
  not use; a protocol that hands its successor less on purpose (STARTTLS
  dropping pipelined plaintext) is the protocol's choice, outside the model.
- Datagrams. They are never split, a special case of the chunks here (only
  whole answers).
- Nesting: one chain and one switch. A deeper stack is the same rules again
  at each `Chain`, but the model does not compose more than one.
- Sizes: three bytes up and two or three down. `Route_without_restfirst`
  needs three bytes up to cut the leftovers into two chunks.

## Children over a mux: `Children.tla`

[`Children.tla`](tla/Children.tla) is `Children` with the mux below it. A
child id is `<<slot, generation>>`. The mux is any mux that keeps its
children in `Slots`: it opens a child in any free slot, sends a child's
events, grants a child command credit within a window (`MaxCredit`), closes
a child when its peer resets it, and takes `Children`'s commands one at a
time, applying each to the child its id names if `Slots` finds one. Each
child's layer is abstract: on a visit it may take its next event or not,
hand over a command of any cost in `Costs`, or fail; on a late timer or
work result it may fail. Every `Children` entry point is one atomic action.
`Q` and `R` stand for `QUEUE` and `RESERVE`; the configs use 3 and 1.

| Model | Rust |
| --- | --- |
| `Opened` | `children.rs:262-279` (`on_event`, `Opened`, the limit and `Refused`) |
| `MuxSend` | `children.rs:280-290` (`on_event`, `Child`, the `Overrun` check) |
| `MuxCredit` | `children.rs:291-295` (`on_event`, `Credit`) |
| `MuxPeerClose` | `children.rs:296-298` (`on_event`, `Closed`) |
| `OfferControl` | `children.rs:309-319` (`on_command`) |
| `LateResult` | `children.rs:321-353` (`on_timer`, `on_done`) |
| `Advance`, `Visit`, `VisitOrder` | `children.rs:355-373` (`advance`), `:182-238` (`visit_child`), `:165-177` (`fail`) |
| `MuxTake` | `children.rs:375` (`take_command`) and the mux's lookups, `carrier.rs:458-496` (`Slots::entry`, `contains`, `get_mut`, `remove`) |

What is checked:

- `NoStaleDelivery`: a command (send, grant, close), timer or work result
  for a child that is gone never reaches the child that has its slot now,
  or any other.
- `EventCredit`: each child's event credit is in exactly one place, granted
  to the mux, in its inbox, or owed back; their sum is the window `W`. A
  child that stops reading holds at most `W`, even under a mux that sends
  past its credit (`Children_refuse_base.cfg` has such a mux; `Overrun`
  stops the connection first).
- `MuxEventCredit`: with a mux that keeps to its credit, its credit for a
  child is what `Children` granted less the grants still queued.
- `CommandCredit`: the mux never receives a send larger than the credit it
  has out, and its credit for a child is the child's credit plus its queued
  sends.
- `SendsLeaveReserve`: children's sends never take the `R` places kept for
  control and credit.
- `ControlProgress`: a control command from above is taken eventually,
  with children whose layers never read, under weak fairness of `Advance`,
  `MuxTake` and `OfferControl`. A child may still send as fast as its peer
  grants credit.
- `CommandsGo` (finding below): a child's command reaches the mux
  eventually while the child lives, when the peer keeps reading (weak
  fairness of `MuxCredit`).

| Config | Generated | Distinct | Depth | Result |
| --- | ---: | ---: | ---: | --- |
| `Children_base.cfg` (2 slots, 2 generations each, 2 children at once) | 12,789,594 | 1,857,160 | 25 | all five invariants hold, 16 s |
| `Children_refuse_base.cfg` (limit 1, a mux that may overrun) | 14,398,126 | 2,645,648 | 42 | all four invariants hold, 19 s |
| `Children_stalled_base.cfg` (children that never read, a mux window of 2, one generation) | 1,561,917 | 219,760 | 22 | all five invariants and `ControlProgress` hold, 216 s |
| `Children_commands_base.cfg` (one slot, a mux window of 2, costs 1 and 2) | 2,040 | 504 | 15 | `CommandCredit` and `CommandsGo` hold |
| `Children_without_checkoverrun.cfg` | 41 | 31 | 5 | `EventCredit` violated: a mux sends past credit and the inbox holds `W + 1` |
| `Children_without_checkcommandcredit.cfg` | 31 | 25 | 5 | `CommandCredit` violated: a send with no credit reaches the mux |
| `Children_without_reserveforcontrol.cfg` | 900,110 | 162,151 | | `ControlProgress` violated: two children's sends refill the queue each time the mux takes one, and the control command never finds room |
| `Children_without_muxchecksgeneration.cfg` | 2,497 | 1,091 | 8 | `NoStaleDelivery` violated: a queued command for a closed child reaches the successor in its slot |
| `Children_without_keybywholeid.cfg` | 1,157 | 567 | 7 | `NoStaleDelivery` violated: a late result for a closed child reaches the successor in its slot |
| `Children_large_command.cfg` (a mux window of 1, costs 1 and 2) | 742 | 191 | | `CommandsGo` violated on the code as it is (finding) |

The liveness configs use one generation per slot and a mux window of 2: with a
window of 1, two children can never have three sends queued, so the
mutation without the reserve could not fail.

### Finding: a command larger than the mux's window never goes out

`visit_child` (`children.rs:221-230`) sends a child's command only when its
whole cost fits the child's credit (`cost <= kid.credit`); otherwise it
keeps the command in the child's outbox and tries again on the next visit.
It never splits a command, and `Credited` gives it no way to. So a command
whose cost is larger than all the credit the mux will ever have out for that
child waits forever, and the child sends nothing after it.

Counterexample (`Children_large_command.cfg`, a mux window of 1): the mux opens a
child; `Children` grants it its event credit; the mux grants one unit of
command credit, which fills its window; the child's layer hands over a
command of cost 2. From there every visit keeps the command, the mux grants
nothing more because its window is full, and the command never reaches the
mux. With a window of 2 (`Children_commands_base.cfg`) the same property
holds.

On a byte-stream child the cost of `StreamCommand::Write` is the chunk's
length (`carrier.rs:140-147`). A mux that grants credit up to its peer's
flow-control window (an HTTP/2 stream's send window starts at 65,535 bytes)
would hold back for good any single write larger than that window. Whether
this happens depends on the mux's credit policy, and no mux on the layer
foundation exists yet to say. Two ways out, both a design change rather
than a local fix: let `Children` split a command to the credit it has (a
`split` on `Credited`, meaningful for byte-stream writes), or document that
a mux must always grant at least the cost of the largest command a child
may send. No code changed.

### What `Children.tla` leaves out

- Events and commands of more than one credit unit on the event side, and
  partial admission of a child's event (`Admit::Partial`,
  `children.rs:205-209`); events cost one unit each.
- Zero-cost events (`StreamEvent::Written`, `Ended`, `Reset`) pass
  `cost > kid.granted` and are queued without bound. A mux that sent them
  without end would grow a child's inbox; the mux is trusted code, so the
  model leaves them out.
- Control events going up (`MuxEvent::Control`, `children.rs:299-304`), and
  `take_work`, `deadline`, and reports.
- Closes pushed by `fail` and by a refused child skip the queue limit
  (`children.rs:174`, `:265`). The code bounds them by the mux's own limit on
  children; the model lets the queue grow past `Q` for them and checks
  nothing about its length.
- Fairness among children. `VisitOrder` keeps the rotation, but no property
  says a busy child cannot starve a sibling.
- Control progress with children that read. Their credit grants may use the
  reserved places, as control does, so `ControlProgress` is checked only
  with children that never read. The model also runs the entry points in
  any order, not the order a `Chain` calls them in.
- The `ChildId` scope across connections (that is the Kani proof below),
  and generation overflow (a `u64` per slot).
- Sizes: one or two slots, one or two generations, a limit of one or two,
  `W` of 1, a mux window of 1 or 2, `Q` of 3 and `R` of 1. The real
  `QUEUE` is 64 and `RESERVE` 8.

## Proofs against the Rust: `kani/mod.rs`

[`kani/mod.rs`](kani/mod.rs) is compiled into `src/stdlib/layer/mod.rs`
under `cfg(kani)` and calls the production code through its public API.

| Harness | Proves |
| --- | --- |
| `slots_refuse_past_the_limit` | for every limit up to 3, `insert` takes children while fewer than the limit are live and refuses after, handing the value back; `len` never passes the limit; a removal makes room for exactly one more |
| `slots_never_answer_a_stale_id` | with two live children, either one closed and its slot given to a successor, twice: the old ids answer no lookup (`contains`, `get`, `get_mut`, `ids`) and remove nothing, every new id differs from every old one, the other child is untouched |
| `slots_never_answer_another_connections_id` | an id of another `Slots` with the same slot and generation answers nothing, and the reverse |
| `charges_split_and_drop_within_the_limit` | over every `u8` limit and size: two charges, a split, a new size for the split part, and the three dropped in any order; `used()` is always the sum of the live charges and never past the limit; a split keeps the total and refuses a part larger than the charge; every charge is given back |
| `timers_in_order_three_names`, `timers_in_order_first_armed_again`, `timers_in_order_second_armed_again`, `timers_in_order_first_armed_twice`, `timers_in_order_one_name_three_times` | three arms at any times, under every pattern of names up to renaming: `next` is the earliest timer, ties go to the earlier arming (arming again is a new arming), `len` counts the names armed, and (all but the first) `get` is each name's last arming |
| `timers_get_three_names` | after three names armed at any times, `get` gives each its time and a name never armed nothing |
| `timers_cancel_fire_and_retain_touch_one_name` | after two arms at any times, `cancel`, `fire` at any moment, or `retain` on either name: `cancel` reports and disarms, `fire` disarms exactly a due timer and says so, `retain` disarms, and the other timer is untouched and comes next |
| `a_chunk_cursor_keeps_the_rest_in_place` | for any four bytes, with or without a charge, two advances of any lengths that fit leave exactly the suffix (`len`, `is_empty`, every byte); the charge stays whole and is given back on drop |
| `a_chunk_cursor_never_passes_the_end` | advancing past the end panics (a `should_panic` harness) |

| Harness | Unwind | Solver | Checks | Result |
| --- | ---: | --- | ---: | --- |
| `slots_refuse_past_the_limit` | 6 | CaDiCaL | 629 | all pass, 1.9 s |
| `slots_never_answer_a_stale_id` | 5 | CaDiCaL | 873 | all pass, 17 s |
| `slots_never_answer_another_connections_id` | 4 | CaDiCaL | 827 | all pass, 1.7 s |
| `charges_split_and_drop_within_the_limit` | 4 | CaDiCaL | 503 | all pass, 32 s |
| `timers_in_order_three_names` | 4 | MiniSat | 882 | all pass, 58 s |
| `timers_get_three_names` | 4 | MiniSat | 550 | all pass, 21 s |
| `timers_in_order_first_armed_again` | 4 | MiniSat | 883 | all pass, 63 s |
| `timers_in_order_second_armed_again` | 4 | MiniSat | 883 | all pass, 57 s |
| `timers_in_order_first_armed_twice` | 4 | MiniSat | 883 | all pass, 67 s |
| `timers_in_order_one_name_three_times` | 4 | MiniSat | 883 | all pass, 56 s |
| `timers_cancel_fire_and_retain_touch_one_name` | 4 | CaDiCaL | 714 | all pass, 26 s |
| `a_chunk_cursor_keeps_the_rest_in_place` | 6 | CaDiCaL | 1,327 | all pass, 3.7 s |
| `a_chunk_cursor_never_passes_the_end` | 6 | CaDiCaL | 1,143 | the one expected panic, 81 s |

On the merged foundation all thirteen were rerun in one
`cargo kani -p fictionet -Z stubbing --harness stdlib::layer::proofs`
under a 12 GB memory cap: each gave the same number of checks and the same
result as above, in 0.8 to 66 s of verification each.

Each run was `cargo kani -p fictionet --harness <name>` under a 10 GB memory
cap. The checks are CBMC's, the unwinding assertions among them, so every
loop bound above covers the loops it unrolls. The harnesses run fixed
sequences of calls over symbolic values and choices: harnesses that chose
every call symbolically, with a model table written at symbolic positions,
or with a symbolic limit or symbolic timer names (so the vectors grew by
symbolic amounts), took CBMC past the memory cap. The six timer harnesses
that arm three times use MiniSat: CaDiCaL passed the cap on their formula, which has
about 13 million variables and 117,000 clauses. Times are whole seconds,
which keeps the division in `Duration::from_millis` out of the formula.

Each kind of property was also run against a deliberately broken copy of the code
(the change applied with `sed`, the harness run, the file restored from
git); each change below made its harness fail:

| Change (file:line) | Harness | Result |
| --- | --- | --- |
| `Slots::entry` ignores the generation (`carrier.rs:464`) | `slots_never_answer_a_stale_id` | fails: `contains` answers the closed child's id |
| `Slots::entry` ignores the scope (`carrier.rs:459`) | `slots_never_answer_another_connections_id` | fails: `contains` answers the other connection's id |
| `Slots::insert` refuses only past the limit (`>` for `>=`, `carrier.rs:436`) | `slots_refuse_past_the_limit` | fails: an insert at the limit is taken |
| `Charge::split` skips its check (`budget.rs:127`) | `charges_split_and_drop_within_the_limit` | fails: subtraction overflow |
| `Charge`'s drop gives nothing back (`budget.rs:140`) | `charges_split_and_drop_within_the_limit` | fails: `used()` is not the sum of the live charges, and not zero at the end |
| `Timers::next` breaks ties to the last armed (`timers.rs:57`) | `timers_in_order_three_names` | fails: `next` is the later of two timers due at once |
| `Timers::fire` fires a timer not yet due (`timers.rs:65`) | `timers_cancel_fire_and_retain_touch_one_name` | fails: `fire` reports a timer that was not due |
| `Chunk::advance` cuts the end instead of the front (`carrier.rs:55`) | `a_chunk_cursor_keeps_the_rest_in_place` | fails: the bytes left are not the suffix |

One more change survived, and correctly so: `Timers::next` keyed by the
time alone, without the arming count (`timers.rs:57`, run against
`timers_in_order_first_armed_twice`), still passes. `set` removes a name
before pushing it at the end, and `retain` keeps the order, so the vector
is always in arming order and `min_by_key` already returns the first of
equal keys. The arming count is redundant; the order stays right without
it.

### What the Kani proofs leave out

- Sequences longer than those above: three or four calls to `Slots`, three
  arms and one more call to `Timers`. Longer sequences are not explored.
- `Timers` with more than three names, and `Chunk`s other than four bytes
  long (a symbolic length took the solver past the cap; zero and the full
  length are reached by the advances).
- Concurrent use of a `Budget`: the harness is single-threaded, so the
  atomics are checked as plain counters.
- Generation and scope overflow (`u64` counters).
- `Charge::set` on the first charge, which the lifecycle harness
  `charges_sum_to_the_budget_and_never_pass_its_limit` covers for the same
  `Budget`.

## Smaller observations, no change made

- `Layer::deadline` says "of two due at the same moment, the one armed
  first". `Chain::deadline` (`chain.rs:192-201`) gives the lower part's timer
  on a tie, and `Children::deadline` (`children.rs:389-394`) the child with
  the smallest id, whichever was armed first. Both are deterministic, so
  runs repeat, but they do not keep the trait's wording. `Timers::next`
  keeps it (proved above).
