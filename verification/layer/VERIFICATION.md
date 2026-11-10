# Layer foundation: what was modeled and found

This pass covers the layer foundation in `src/stdlib/layer/`: how `Chain`
(`chain.rs`), `Switch` and `Handoff` (`switch.rs`) and the `Driver`
(`driver.rs`) move items between layers; `Children` (`children.rs`) over a
mux whose children live in `Slots` (`carrier.rs`); and the state of
`Slots`, `Budget` and `Charge` (`budget.rs`), `Timers` (`timers.rs`) and
`Chunk` (`carrier.rs`). The commands are in the [README](README.md).

The original pass exposed a child-write liveness failure. The child-readiness
implementation now splits byte-stream commands within available credit; the
unchanged large-command scenario passes. The updated child model also covers
bounded empty events, retained receive credit, urgent completion and cancelled
work. Historical merged-branch results below remain identified separately.

## Historical run on the merged foundation

The pass was written on `comp/v-layer` and merged into `comp/foundation`
(commit `e68a070d3`); everything was rerun at code revision `6aa68ae5f`.
`children.rs`, `carrier.rs`, `budget.rs` and `timers.rs` did not change,
so `Children.tla` and the Kani proofs describe the same code. `chain.rs`,
`driver.rs` and `switch.rs` gained an urgent path: while the next layer
refuses an event, a layer's `take_urgent` events (TLS's write credit) go
past it, one at a time, through a slot of their own in `Chain`
(now `chain.rs:150-159`) and in the `Driver` (now `driver.rs:283-305`).
`Route.tla` has no layer with urgent events: with `take_urgent` answering
None, the trait's default, the code runs exactly the statements the model
does, and the line numbers above are the merged ones. The order in which
an urgent event passes a refused one, and that it still arrives once, are
were not modeled in that run. The current urgent projection and rerun are
recorded under bounded dispatch and urgent completion below.

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
| `Children_large_command.cfg` | 742 | 191 | historical `CommandsGo` counterexample before the child-readiness fix; current result below |

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
| `OfferSlot`, `OfferMoved` | `chain.rs:71` `offer` |
| `StepL`, `StepS`, `StepTU`, `StepOU`, `StepTD`, `StepOD` | `chain.rs:143` `Chain::advance` |
| `StepS`, `StepH` (first phase) | `switch.rs:247-266` |
| `StepS`, `StepSB`, `StepSA` (second phase), `FeedQueue` | `switch.rs:267-284`, `feed` at `switch.rs:140` |
| `EventAnswers`, `CommandAnswers` | `switch.rs:167-211` `Switch::on_event`, `on_command` |
| `StartRun`, `StepE` | `driver.rs:230` `Driver::run`, the loop at `driver.rs:238-256` |
| `SendBelow`, `SendAbove` | `Driver::send_below` at `driver.rs:267`, the `send` call in `send_above` at `driver.rs:292`, and `send` at `driver.rs:327` |
| `Deliver`, `OwnerQueue` | `driver.rs:192`, `Harness::settle` at `harness.rs:261-277` |
| `Command` | `driver.rs:205` |

The line numbers are those of main at `e2858ccc4` (November 9, 2026).

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
  ignored by construction (`switch.rs:213-243`).
- Errors. An `Err` from any entry point ends the connection, and nothing
  routes after it.
- The contract on `Handoff` implementations. The model's `A` hands over
  only once its own output has been taken, as the trait asks. A layer that
  hands over with output still queued loses it; the switch cannot check this.
  Urgent output (`take_urgent`) is output too: an `A` dropped at
  `switch.rs:264` with a completion not yet handed up loses it the same way.
- Urgent events, and what they leave unchecked. `UpLine` has no place for
  `Chain::urgent` (`chain.rs:22`) or `Driver::urgent` (`driver.rs:122`).
  No layer hands stream bytes through `take_urgent` (its thirteen
  implementations return a `Written` or delegate), so no byte can leave
  `UpLine` through those slots and `UpConserved` loses nothing by their
  absence. What is unproven is the handling of the urgent event itself:
  `offer` at `chain.rs:158` and the arms at `driver.rs:286-288` and
  `driver.rs:301-303` keep a `Partial` rest or a `Blocked` event, and a
  `Closed` answer drops it, by reading only. `Route_urgent` moves one whole
  token and assumes the upper layer takes it (`OfferChainUrgent` has no
  refusal). The switch once broke that assumption: in its second phase
  `Switch::on_event` answered `Blocked` to every event while leftovers
  waited, a `Written` included, although completions are counted apart
  from the data and need no ordering against it, so a successor that takes
  no data until its writes complete waited for ever. It now lets an event
  the port calls urgent (`Port::urgent`: a byte stream's `Written` and
  `Reset`) pass the leftovers (`switch.rs:193`); the test
  `a_write_completion_passes_the_leftovers_the_successor_waits_to_read` in
  `switch.rs` fails on the old switch. See the audit below.
- The trace check (`RouteTrace.tla`, `src/stdlib/layer/route_trace.rs`)
  sends only data: no `Written`, no `Ended`, no `Reset`, no timers. It
  checks the routing of bytes, not the urgent path.
- `Switch::owed` (`switch.rs:101`, set at `switch.rs:174-180`, consumed at
  `switch.rs:185-188`). With a `B` that inherits every event, as the model's
  does, `declined` is never true, the flag is never set and the consuming
  arm is never reached: the model is exact for that `B`. With a `B` that
  declines data, the event `A` refused before the switch is taken and
  dropped on its next offer: a byte leaves `UpLine` into nothing, which
  `UpConserved` would call a loss. That is the intended STARTTLS behaviour
  and is checked by `verification/tls-contract/Starttls.tla`, not here.
- Byte contents and protocol meaning. `A`'s handover keeps everything it did
  not use, and the model's `B` inherits every event, as tunnels and the
  HTTP upgrades do. A successor that declines input from before the switch
  (`Successor::inherits`: TLS after STARTTLS reads no earlier data) has the
  switch drop it; that is checked by
  `verification/tls-contract/Starttls.tla` and the careless-session test in
  `tests/it/services/tls.rs`, not here.
- Datagrams. They are never split, a special case of the chunks here (only
  whole answers).
- Nesting: one chain and one switch. A deeper stack is the same rules again
  at each `Chain`, but the model does not compose more than one.
- Sizes: three bytes up and two or three down. `Route_without_restfirst`
  needs three bytes up to cut the leftovers into two chunks.

## Children over a mux: `Children.tla`

The model follows `Children` over a mux whose scoped, generation-checked
handles come from `Slots`. `Opened`, `MuxSend`, `MuxCredit` and
`MuxPeerClose` correspond to child admission, events, grants and immediate
reset/close. `Visit` offers ordinary input, passes urgent completion,
splits stream output at available credit and returns released credit.
`MuxTake` checks the target generation before applying each queued command.
The constants use one or two slots and generations, queue size three and
one reserved control slot; production uses a queue size of 64 with eight
reserved places and at most 4096 configured children. Closing commands
have additional bounded space, one per admitted child.

`Readiness` enables retained buffers, zero-credit empty events, a reserved
completion slot, and owned work. Taking data moves its credit from the
inbox to `held`; only `Release` makes it available for a new grant. This
matches the receive reservation carried by `Chunk` until its last backing
owner drops. `MuxWritten` can arrive while ordinary input is refused and
`Visit` consumes it through the urgent slot. EOF remains ordinary input in
the Rust; reset removes the child, invalidates work and drops queued data.

`ExtractWork` reserves a bounded runtime job entry. Closing a child leaves
that entry invalid until `PollWork` removes it; the owner check prevents
polling invalid work. Weak fairness of runtime polling establishes release
of cancelled jobs. The model allows one outstanding job per child identity;
the readiness configuration sets a separate job limit of one, so reset
and reopen can exhaust it before the stale job is drained. Production
allows several within its separate limit of 64 jobs and bounds
intake to eight per visit. Delayed completion still goes through the scoped
child identity check.

The checked properties are byte-credit conservation (`EventCredit`,
`MuxEventCredit`, `CommandCredit`), generation isolation (`NoStaleDelivery`),
reserved control capacity (`SendsLeaveReserve`), queue and job item bounds
(`BoundedItems`, `BoundedJobs`), and absence of cancelled-owner polling
(`NoCancelledPoll`). `CommandsGo` assumes a peer continues granting credit;
`ControlProgress` does not assume stalled children begin reading.
`CompletionProgress` concerns an already queued completion and assumes only
continued child visits. `CancelledWorkLeaves` assumes continued common
runtime polling, not completion of the cancelled operation.

### Results after the child-readiness changes

Every command uses the supplied JDK with `java -Xmx6g`, an 8 GiB systemd
memory cap with swap disabled, and TLC state directories on the home volume.
The original positive configs and intentional mutations were rerun alongside
the readiness config. The readiness configurations were then rerun
with cancellation fairness restricted to stale owners and an independently
exhaustible job limit: a live operation may remain pending forever. Generated counts can vary for early-stopping
mutations with four workers.

| Config | Generated | Distinct | Result |
| --- | ---: | ---: | --- |
| `Children_base.cfg` | 13,067,962 | 1,857,160 | all safety properties pass |
| `Children_refuse_base.cfg` | 16,775,230 | 2,645,648 | all safety properties pass |
| `Children_stalled_base.cfg` | 1,639,585 | 219,760 | safety and control progress pass |
| `Children_commands_base.cfg` | 2,082 | 504 | command credit and delivery pass |
| `Children_large_command.cfg` | 760 | 191 | command credit and delivery pass with a one-byte window |
| `Children_readiness.cfg` | 71,116 | 10,066 | credit/item/job invariants, delivery, completion and cancellation progress pass |
| `Children_without_checkoverrun.cfg` | 41 | 31 | expected `EventCredit` violation |
| `Children_without_checkcommandcredit.cfg` | 31 | 25 | expected `CommandCredit` violation |
| `Children_without_reserveforcontrol.cfg` | 945,883 | 164,063 | expected `ControlProgress` violation |
| `Children_without_muxchecksgeneration.cfg` | 2,356 | 1,020 | expected `NoStaleDelivery` violation |
| `Children_without_keybywholeid.cfg` | 1,179 | 563 | expected `NoStaleDelivery` violation |
| `Children_without_urgent.cfg` | 8,120 | 1,927 | expected `CompletionProgress` violation |
| `Children_without_workownership.cfg` | 309 | 135 | expected `NoCancelledPoll` violation |
| `Children_without_joblimit.cfg` | 883 | 297 | expected `BoundedJobs` violation |

The readiness pass completed in 25 seconds; the stalled-child pass in
3 minutes 45 seconds. The large-command pass completed in under a second.
The two original long-running mutation/liveness scenarios retain their
original fairness and assertions. No test or property was weakened to
turn the formerly failing large-command scenario into a success.

### Results after storage is charged as children open

`Children` no longer reserves every child place, closing slot and inbox up
to its limit before the first child. Its queues are charged from its first
step; child places grow geometrically up to the limit, charged before they
grow, and go once no child is left (`make_room`, `release_places`); each
inbox grows on demand up to its bound, charged before it grows. A child
whose place, inbox growth or payload reservation the budget refuses is closed and reported
`Refused`, as one past the limit is, instead of failing the connection.
The model gains `BudgetRefuses`: `Opened` may refuse a child below the
limit, and `MuxSend` may close a live child instead of queuing its event.
Every existing configuration sets it false and keeps its behavior; two new
configurations set it true. Rerun with the same JDK, memory cap and state
directories:

| Config | Generated | Distinct | Result |
| --- | ---: | ---: | --- |
| `Children_base.cfg` | 13,067,962 | 1,857,160 | all safety properties pass |
| `Children_budget.cfg` | 13,657,794 | 1,857,160 | all safety properties pass |
| `Children_budget_stalled.cfg` | 1,713,569 | 219,760 | safety and control progress pass |
| `Children_refuse_base.cfg` | 16,775,230 | 2,645,648 | all safety properties pass |
| `Children_stalled_base.cfg` | 1,639,585 | 219,760 | safety and control progress pass |
| `Children_commands_base.cfg` | 2,082 | 504 | command credit and delivery pass |
| `Children_large_command.cfg` | 760 | 191 | command credit and delivery pass |
| `Children_readiness.cfg` | 71,116 | 10,066 | readiness invariants and progress pass |
| `Children_without_checkoverrun.cfg` | 36 | 28 | expected `EventCredit` violation |
| `Children_without_checkcommandcredit.cfg` | 36 | 28 | expected `CommandCredit` violation |
| `Children_without_reserveforcontrol.cfg` | 875,147 | 153,455 | expected `ControlProgress` violation |
| `Children_without_muxchecksgeneration.cfg` | 2,336 | 1,011 | expected `NoStaleDelivery` violation |
| `Children_without_keybywholeid.cfg` | 1,121 | 548 | expected `NoStaleDelivery` violation |
| `Children_without_urgent.cfg` | 8,250 | 1,972 | expected `CompletionProgress` violation |
| `Children_without_workownership.cfg` | 225 | 97 | expected `NoCancelledPoll` violation |
| `Children_without_joblimit.cfg` | 753 | 254 | expected `BoundedJobs` violation |

The model does not count bytes, so it does not show that the charges match
the allocations; the Rust test
`a_child_the_budget_cannot_hold_is_refused_and_its_siblings_go_on` checks a
refused child, its sibling going on, and the router's charge returning to
its idle value once no child is left. The Kani harnesses cover `Slots`,
`Charge`, `Timers`, `Chunk` and `WorkOwner`, none of which changed.

### Refusing a child whose inbox is full

The SSH port added `Children::refuse_full_inbox`: a wire mux such as SSH
must keep reading traffic for every channel, so a child whose bounded inbox
is full is refused and closed, its work cancelled and `Refused` reported,
instead of holding up the event for its siblings. The default still holds
the event back. The model gains `RefuseFullInbox`: with readiness on,
`MuxSend` to a child whose inbox and empty events fill `Q` closes that
child instead of waiting. Every existing configuration sets it false and
keeps its behavior. `Children_refuse_full.cfg` sets it true, with a child
that never reads and its successor in the same slot; the same configuration
without it reaches 6,915 distinct states, so the refusal path is reached.
The model was rerun in full after the change, with the same JDK, memory cap
and state directories on the home volume:

| Config | Generated | Distinct | Result |
| --- | ---: | ---: | --- |
| `Children_base.cfg` | 13,067,962 | 1,857,160 | all safety properties pass |
| `Children_budget.cfg` | 13,657,794 | 1,857,160 | all safety properties pass |
| `Children_budget_stalled.cfg` | 1,713,569 | 219,760 | safety and control progress pass |
| `Children_refuse_base.cfg` | 16,775,230 | 2,645,648 | all safety properties pass |
| `Children_refuse_full.cfg` | 59,704 | 8,594 | readiness invariants, `NoStaleDelivery` and `CancelledWorkLeaves` pass |
| `Children_stalled_base.cfg` | 1,639,585 | 219,760 | safety and control progress pass |
| `Children_commands_base.cfg` | 2,082 | 504 | command credit and delivery pass |
| `Children_large_command.cfg` | 760 | 191 | command credit and delivery pass |
| `Children_readiness.cfg` | 71,116 | 10,066 | readiness invariants and progress pass |
| `Children_without_checkoverrun.cfg` | 36 | 28 | expected `EventCredit` violation |
| `Children_without_checkcommandcredit.cfg` | 26 | 22 | expected `CommandCredit` violation |
| `Children_without_reserveforcontrol.cfg` | 1,098,207 | 183,419 | expected `ControlProgress` violation |
| `Children_without_muxchecksgeneration.cfg` | 2,373 | 1,042 | expected `NoStaleDelivery` violation |
| `Children_without_keybywholeid.cfg` | 1,256 | 592 | expected `NoStaleDelivery` violation |
| `Children_without_urgent.cfg` | 6,780 | 1,670 | expected `CompletionProgress` violation |
| `Children_without_workownership.cfg` | 317 | 134 | expected `NoCancelledPoll` violation |
| `Children_without_joblimit.cfg` | 745 | 250 | expected `BoundedJobs` violation |

A configuration that must fail stops at its first violation, so its counts
depend on the order four workers find states in. The Rust test
`refusing_a_full_inbox_keeps_siblings_and_cancels_its_work` checks the
refused child's work cancelled and its sibling's completion delivered.

The budget proof the serving engine kept over `Charge::set` moved here as
`charges_sum_to_the_budget_and_never_pass_its_limit` when the engine was
deleted: unwind 4, 429 checks, all pass in 2.6 s with Kani 0.68.

### Results after child isolation

`Children` used to hand a child's event back to the mux (`Blocked`) when
the child's inbox or urgent place was full, unless the composition asked
for refusal as above; HTTP/2 did not. The mux's events go up in one order, so the event waited at
the head, and the HTTP/2 connection stopped reading once its own events
backed up. One child that never reads stalled its siblings and the
connection's PING, SETTINGS and WINDOW_UPDATE. Now a full place gets the
child one visit at once (`Children::visit_child`), and a child still full
is refused alone (`Children::refuse`); the option is gone, and every
composition, HTTP/2 streams and SSH channels included, gets this one
behavior.

The model gains:

- `mHeld`, the event Children handed back. While it is held the mux sends
  nothing else, opens and closes nothing and reads no input; `MuxRetry`
  offers it again.
- `ctrlIn` and `MuxControl`, connection traffic the mux reads when nothing
  is held, with `ConnectionProgress` (`ctrlIn ~> ~ctrlIn`). The mux is
  assumed to read it whenever it can (strong fairness), so only an event
  held for good stops it.
- `Overload`: the mux sends a child's events whatever its place holds, as
  a wire mux parsing frames does. Arrivals at a full place take the
  `Arrivals` path: a visit, then refusal, or with `Isolate` off, the event
  handed back.
- `StuckSlots`: the layers in these slots never take an event, ordinary or
  urgent, and never drain empty events: any child a user installs.
- `MuxNeverHeld`: Children never hands a child's event back.
  `MuxEventCredit` counts the credit of a held data event.

`RefuseFullInbox` goes with the option it modeled: refusal without a
visit, and only for ordinary data. Every other configuration sets
`Isolate` true, `Overload` and `Connection` false and `StuckSlots` empty,
and keeps its behavior: each passing configuration reaches exactly the
distinct states it reached before, and each mutation still fails on its
property. `Children_refuse_full.cfg` keeps its stalled child and its
successor in the same slot, with `Overload` in place of `RefuseFullInbox`,
so their events reach a full place and take the isolation path; with
`Isolate` false the same configuration violates `MuxNeverHeld` after 230
distinct states, so the path is reached.
`Children_isolation.cfg` (one hour) has two children, one generation
each, the one in slot 1 stuck,
readiness traffic (empty data and completions), a mux that overloads, and
connection traffic. `Children_without_isolate.cfg` is the same with
`Isolate` false; its counterexample fills the stuck child's place with
empty events, the next one is held, and the system stutters with the
connection's traffic unread.

| Config | Generated | Distinct | Result |
| --- | ---: | ---: | --- |
| `Children_isolation.cfg` | 10,081,987 | 663,822 | `MuxNeverHeld`, `ConnectionProgress`, credit, item and generation invariants pass |
| `Children_without_isolate.cfg` | 183,050 | 29,305 | expected `ConnectionProgress` violation |
| `Children_refuse_full.cfg` | 77,750 | 10,411 | readiness invariants, `MuxNeverHeld`, `NoStaleDelivery` and `CancelledWorkLeaves` pass |
| `Children_base.cfg` | 13,067,962 | 1,857,160 | all safety properties pass |
| `Children_budget.cfg` | 13,657,794 | 1,857,160 | all safety properties pass |
| `Children_budget_stalled.cfg` | 1,713,569 | 219,760 | safety and control progress pass |
| `Children_refuse_base.cfg` | 16,775,230 | 2,645,648 | all safety properties pass |
| `Children_stalled_base.cfg` | 1,639,585 | 219,760 | safety and control progress pass |
| `Children_commands_base.cfg` | 2,082 | 504 | command credit and delivery pass |
| `Children_large_command.cfg` | 760 | 191 | command credit and delivery pass |
| `Children_readiness.cfg` | 71,116 | 10,066 | readiness invariants and progress pass |
| `Children_without_checkoverrun.cfg` | 36 | 28 | expected `EventCredit` violation |
| `Children_without_checkcommandcredit.cfg` | 26 | 22 | expected `CommandCredit` violation |
| `Children_without_reserveforcontrol.cfg` | 854,054 | 150,882 | expected `ControlProgress` violation |
| `Children_without_muxchecksgeneration.cfg` | 1,720 | 768 | expected `NoStaleDelivery` violation |
| `Children_without_keybywholeid.cfg` | 1,223 | 582 | expected `NoStaleDelivery` violation |
| `Children_without_urgent.cfg` | 58,884 | 8,422 | expected `CompletionProgress` violation |
| `Children_without_workownership.cfg` | 278 | 117 | expected `NoCancelledPoll` violation |
| `Children_without_joblimit.cfg` | 1,044 | 336 | expected `BoundedJobs` violation |

The Rust tests check the same contract on the code.
`a_child_that_refuses_everything_holds_up_neither_siblings_nor_control`
delivers four times a child's bound of empty data and completions to two
children that never take an event and to one that takes everything,
interleaved with control events, without running the driver: every event
is taken, every control event comes up at once, the two stuck children
alone are refused and closed, and the third took every event.
`a_child_that_never_reads_holds_up_neither_its_siblings_nor_the_connection`
(`http2.rs`) installs a custom stream child that refuses every event on
one stream while its body arrives in 200 small DATA frames, followed by
PING, SETTINGS, a sibling request and the client's WINDOW_UPDATE: the PING
and SETTINGS are acknowledged, the stuck stream alone is reset, the
connection window comes back, and the sibling's body goes out once the
WINDOW_UPDATE is read. With the old backpressure the first test fails at
the first refused delivery and the HTTP/2 server writes nothing at all;
with refusal but no visit, the child that takes everything is refused.

### Scope and limitations

The model covers partial stream output; atomic-message rejection above the
mux's declared maximum is checked by the Rust regression test. Input data
uses one credit unit at a time. The item-bound case adds empty data with no
byte credit. It does not model protocol-specific headers, trailers or their
payload sizes. Its job actions abstract polling and release, not the runtime
region's task-joining internals. Fixed byte reservations and shared backing
ownership are exercised against Rust; credit conservation alone does not
prove all allocations have charges.

A model `Advance` visits its ready children. Rust divides a sweep
into at most 64 child visits (`children.rs:1077-1081`) and explicitly continues until the sweep ends;
work selection rotates after its last successful extraction. A regression
with 70 continuously productive children exercises full output queues and
multiple bounded visit groups. Small model
sizes do not prove a throughput bound for 4096 children. Cross-connection
scope, generation exhaustion, byte-cursor bounds and backing retention are
covered by the production-code tests and Kani harnesses rather than this
finite interleaving model. Atomic opening context and factory semantics
are tested with real async HTTP children, including a stalled response,
a cancelled pending handler, a completing sibling and parent control.

## Proofs against the Rust: `kani/mod.rs`

[`kani/mod.rs`](kani/mod.rs) is compiled into `src/stdlib/layer/mod.rs`
under `cfg(kani)` (`#[path]` at `mod.rs:225-226`) and calls the production
code through its public API. It holds twenty-two harnesses: the thirteen in
the table below, `charges_sum_to_the_budget_and_never_pass_its_limit`
(under "Refusing a child whose inbox is full"),
`stream_credit_splits_keep_the_allocation_owned` and
`work_cancellation_stays_with_its_owner` (under "Shared stream backing
and cancellation harnesses"), `a_shared_chunk_edit_preserves_ownership_and_budget`
(under "Scoped output and retained receive credit"), and five for the
charged containers (under "Charged containers and the wake"). No harness
uses `#[kani::stub]`; the `-Z stubbing` flag in the combined run below
enabled nothing.

| Harness | Proves |
| --- | --- |
| `slots_refuse_past_the_limit` | for every limit up to 3, `insert` takes children while fewer than the limit are live and refuses after, handing the value back; `len` never passes the limit; a removal makes room for exactly one more |
| `slots_never_answer_a_stale_id` | with two live children, either one closed and its slot given to a successor, twice: the old ids answer no lookup (`contains`, `get`, `get_mut`, `ids`) and remove nothing, every new id differs from every old one, the other child is untouched |
| `slots_never_answer_another_connections_id` | an id of another `Slots` with the same slot and generation answers nothing, and the reverse |
| `charges_split_and_drop_within_the_limit` | over every `u8` limit and size: two charges, a split, a growth or a shrink of the split part, and the three dropped in any order; `used()` is always the sum of the live charges and never past the limit; a split keeps the total and refuses a part larger than the charge; every charge is given back |
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
| `Slots::entry` ignores the generation (now `carrier.rs:688`) | `slots_never_answer_a_stale_id` | fails: `contains` answers the closed child's id |
| `Slots::entry` ignores the scope (now `carrier.rs:683`) | `slots_never_answer_another_connections_id` | fails: `contains` answers the other connection's id |
| `Slots::insert` refuses only past the limit (`>` for `>=`, now `carrier.rs:654`) | `slots_refuse_past_the_limit` | fails: an insert at the limit is taken |
| `Charge::split` skips its check (`budget.rs:127`) | `charges_split_and_drop_within_the_limit` | fails: subtraction overflow |
| `Charge`'s drop gives nothing back (`budget.rs:140`) | `charges_split_and_drop_within_the_limit` | fails: `used()` is not the sum of the live charges, and not zero at the end |
| `Timers::next` breaks ties to the last armed (now `timers.rs:79`) | `timers_in_order_three_names` | fails: `next` is the later of two timers due at once |
| `Timers::fire` fires a timer not yet due (now `timers.rs:87`) | `timers_cancel_fire_and_retain_touch_one_name` | fails: `fire` reports a timer that was not due |
| `Chunk::advance` cuts the end instead of the front (now `carrier.rs:75-78`) | `a_chunk_cursor_keeps_the_rest_in_place` | fails: the bytes left are not the suffix |

The mutations were applied to the code of that time; "now" gives the line
of the same statement on main at `e2858ccc4`. They were not rerun for this
audit.

One more change survived, and correctly so: `Timers::next` keyed by the
time alone, without the arming count (then `timers.rs:57`, run against
`timers_in_order_first_armed_twice`), still passes. `set` removes a name
before pushing it at the end, and `retain` keeps the order, so the vector
is always in arming order and `min_by_key` already returns the first of
equal keys. The arming count is redundant; the order stays right without
it. That is now the code: `Timers` is eight inline slots with no arming
counter (`timers.rs:14-17`), `set` cancels then appends (`timers.rs:35-44`)
and `next` is `min_by_key` over them (`timers.rs:75-81`).

### What the Kani proofs leave out

- Sequences longer than those above: three or four calls to `Slots`, three
  arms and one more call to `Timers`. Longer sequences are not explored.
- `Timers` with more than three names, and `Chunk`s other than four bytes
  long (a symbolic length took the solver past the cap; zero and the full
  length are reached by the advances).
- Concurrent use of a `Budget`: the harness is single-threaded, so the
  atomics are checked as plain counters.
- Generation and scope overflow (`u64` counters).
- `Charge::grow_to` and `Charge::shrink_to` on the first charge, which the
  lifecycle harness `charges_sum_to_the_budget_and_never_pass_its_limit`
  covers for the same `Budget`.

## Equal-deadline scheduling

Local `Timers` retain their deterministic arming order. Across composed
owners, `Chain` rotates equal-deadline delivery between its two sides and
`Children` rotates it among child identities. Earlier deadlines still win.
This prevents an owner that continually rearms a timer for the current time
from starving another owner at that same deadline. Rust regressions keep
both sides, and separately three children, permanently due: each fires
within a bounded driver visit and their delivery counts differ by at most
one. Timer selection is not part of the child interleaving model; its
unconstrained `LateResult` action still checks stale-generation isolation
for every possible target.

## Bounded dispatch and urgent completion

The driver now caps both ordinary output draining and urgent output draining
at 1024 visits per call. It reports an exhausted internal visit explicitly,
and services a due timer and ordinary layer progress in the same iteration.
The runner continues after exhaustion. Composition still dispatches recursively;
constructors and the driver enforce a depth of at most 32, including erased
layers. Tests cover a permanently productive output source, a permanently due
timer, and repeated boxing. This is an explicit depth bound, not an iterative
routing proof.

The byte-routing configurations were rerun after these changes. Their finite
sources do not reach the new drain allowance, so their conservation properties
are unchanged. Route_base explored 1,058,166 distinct states and Route_wide_base
5,653,462; both passed all invariants and RunEnds. Each existing deliberate
mutation still produced its named conservation or progress counterexample.

Route_urgent checks a separate projection in the same model: normal data at
both a Chain edge and a Driver edge is refused until Written arrives. The
completion traverses the lower layer, Chain's urgent slot, the upper layer,
and Driver's urgent slot exactly once. UrgentConserved and UrgentProgress pass
in 10 distinct states, depth seven. Route_without_urgent disables the bypass
and produces the intended liveness counterexample in its initial state.
Only urgent acceptance and fair visits are assumed. There is no assumption
that a peer eventually accepts ordinary blocked data. This projection covers
the bypass mechanism; it does not prove arbitrary protocol-specific completion
semantics or arbitrary nesting together with the byte-routing model.

Reports now have separate item and byte limits. Report sizes must include all
retained backing allocations; unmeasurable payloads are omitted and counted.
Tests check a short vector retaining a large capacity, unknown-size omission,
and payload charge release on drain. Observation storage never draws from the
connection's protocol budget. Eight inline timer slots replace the timer vector
and arming counter; stable slot order preserves local tie ordering without an
overflowing arming sequence. These engine bounds do not account for arbitrary
application callback allocations.

## Shared stream backing and cancellation harnesses

All fifteen layer harnesses passed on the child-readiness implementation.
After the final inline-array initialization change, all seven timer harnesses
were rerun and passed again. Their unwind bound is twelve to cover the eight
inline slots; their symbolic inputs and assertions are unchanged. MiniSat
handles these array formulas within the requested memory cap. The combined
cancel/fire/retain harness took 195.63 seconds on the final run; the other six
took at most 1.70 seconds each. Earlier solver attempts that exceeded the cap
are not counted as verification results.

`Chunk` now shares an owned vector plus checked byte cursors. Its reservation
covers the vector capacity, and `split_to` only clones the shared owner and
moves a cursor: splitting for child credit cannot allocate or release the
backing early. A normalized receive buffer also carries its credit-return
lease until its last piece is released. Cursor/lease metadata remains
bounded engine storage rather than a claim about allocator overhead.

The following production harnesses were rerun with the unchanged symbolic
four-byte inputs, cursor choices and both release orders. No `Bytes` storage
or allocator behavior is stubbed in these proofs. Each run used the requested
12 GiB systemd cap with swap disabled.

| Harness | Checks | Result | Solver time |
| --- | ---: | --- | ---: |
| `stream_credit_splits_keep_the_allocation_owned` | 854 | all pass; concatenated prefix/suffix equals the input and the charge survives either first drop | 8.64 s |
| `a_chunk_cursor_keeps_the_rest_in_place` | 867 | all pass; two advances preserve the unread suffix and charge | 4.19 s |
| `a_chunk_cursor_never_passes_the_end` | 632 | the one required panic when advancing past the end | 0.50 s |
| `work_cancellation_stays_with_its_owner` | 243 | all pass; closing one owner invalidates its leases and leaves another owner live | 0.28 s |

The cancellation harness checks the lease, not executor scheduling or task
joining. The live worker tests exercise those runtime obligations. Child
budget-refusal, slot-storage reservation, exhausted-generation retirement,
atomic output rejection and the 70-child scheduling case are Rust regression
tests; they are not represented as additional symbolic proof coverage here.

## Child-readiness integration gate

The final production revision is `04ff2b09d` on `comp/foundation`. The
prerequisite includes typed child opening, separate retained receive credit,
bounded urgent routing and work ownership, and async HTTP children through
both the deterministic harness and the live stream runner. It does not port
HTTP/2, SSH or the remaining services or claim the later deletion milestone.

The final library run passed 3,865 tests and the integration binary passed
all 1,331 tests, including the unchanged request-budget regressions. Clippy
passed with warnings denied for fictionet, nuclear-world and web-world,
including all targets. Formatting passed. Both browser checks (without
default features, with and without tokio) and browser clippy passed. Cargo
doc passed with rustdoc warnings denied.

All 298 doctests passed in a serial run. The combined test invocation had
already passed its unit and integration suites, but its doctest phase failed
to compile because the shared-target library artifact was missing while
other Cargo invocations were active. After those exited, the unchanged
doctests compiled and passed. No assertion was weakened or test skipped.

The HTTP runtime benchmark completed on the final implementation: the last
HTTP/1 run reported 90,728 requests/second and the HTTP/2 run 72,116. These
are smoke-run measurements, not a before/after performance comparison.

All Cargo commands used the integration target directory, six build jobs,
and the requested 12 GiB systemd limit with swap disabled. TLC used the
cached JDK and jar, a 6 GiB heap under an 8 GiB limit, and state directories
on the home volume. Model assumptions and exclusions remain in the
individual verification reports.

### Results after children are visited when ready

`Children` no longer visits every child on every advance. A child joins
a ready list when it opens, when an event, credit, a timer, a work result,
handed-out work or a wake from its work reaches it, and when payload it
holds is released outside a call into it; it stays while its visits move
or find the mux's queue full. The model gives each child a `woken` flag
with those rules, and `Advance` visits only woken children, in any order,
since Rust visits them in the order they joined its list. The `turn`
variable went with the old id-ordered sweep. `Wakes` names the three rules
beyond events, timers and work, and each has a mutation that removes it.
`CreditReturns` is new: credit a live child owes the mux goes back
eventually. The timer heap and the slab keys are not modeled; the Rust
test `child_timers_fire_in_time_order_as_children_rearm_and_close` checks
the heap's order through re-arming and closing.

TLC 2.19 with two workers, a 2 GiB heap and the 10 GiB work slice, on
November 9, 2026. Every positive configuration passed with no states left
on the queue, and every mutation violated the property it names; the
counterexamples of the three new mutations and of `without_urgent` were
read to check the reason.

| Config | Generated | Distinct | Result |
| --- | ---: | ---: | --- |
| `Children_base.cfg` | 6,176,006 | 699,144 | all safety properties pass |
| `Children_budget.cfg` | 6,509,830 | 699,144 | all safety properties pass |
| `Children_refuse_base.cfg` | 10,687,510 | 1,523,224 | all safety properties pass |
| `Children_stalled_base.cfg` | 1,177,164 | 127,444 | safety and control progress pass |
| `Children_budget_stalled.cfg` | 1,250,904 | 127,444 | safety and control progress pass |
| `Children_commands_base.cfg` | 2,204 | 478 | command credit and delivery pass |
| `Children_large_command.cfg` | 851 | 191 | command credit and delivery pass |
| `Children_readiness.cfg` | 76,122 | 10,619 | invariants, delivery, completion, cancellation and credit return pass |
| `Children_refuse_full.cfg` | 83,193 | 10,035 | all configured properties pass |
| `Children_isolation.cfg` | 9,102,183 | 543,490 | all configured properties pass, in 2 min 46 s |
| `Children_without_checkoverrun.cfg` | 25 | 19 | expected `EventCredit` violation |
| `Children_without_checkcommandcredit.cfg` | 20 | 16 | expected `CommandCredit` violation |
| `Children_without_muxchecksgeneration.cfg` | 2,622 | 984 | expected `NoStaleDelivery` violation |
| `Children_without_keybywholeid.cfg` | 800 | 348 | expected `NoStaleDelivery` violation |
| `Children_without_urgent.cfg` | 54,191 | 8,510 | a live child's urgent completion stays pending around the cycle |
| `Children_without_workownership.cfg` | 253 | 106 | expected `NoCancelledPoll` violation |
| `Children_without_joblimit.cfg` | 836 | 274 | expected `BoundedJobs` violation |
| `Children_without_isolate.cfg` | 185,940 | 26,717 | expected `ConnectionProgress` violation |
| `Children_without_reserveforcontrol.cfg` | 1,903,788 | 200,468 | expected `ControlProgress` violation |
| `Children_without_wakeoncredit.cfg` | 2,352 | 510 | expected `CommandsGo` violation: a command waits for credit that came |
| `Children_without_keepwaiting.cfg` | 2,736 | 592 | expected `CommandsGo` violation: a command waits for room that came |
| `Children_without_wakeonrelease.cfg` | 78,317 | 10,944 | expected `CreditReturns` violation |

## Native world applications

On November 8, 2026, the native world TCP and UDP application routers were
checked with the same child isolation and readiness models. The production
routers select each child's budget before constructing it, drain application
commands before closing its child, and keep transport retirement independent
of application lifetime. Packet dispatch and the complete host composition
are outside these models; their execution checks and benchmark measurements
are recorded in [the layer runtime notes](../layer-runtime/README.md).

| Configuration | Generated states | Distinct states | Result |
| --- | ---: | ---: | --- |
| `Children_isolation.cfg` | 10,081,987 | 663,822 | All configured invariants and temporal properties pass; depth 26 |
| `Children_readiness.cfg` | 71,116 | 10,066 | All configured invariants and temporal properties pass; depth 21 |
| `Children_without_urgent.cfg` | 58,884 | 8,422 | A live child's urgent completion remains pending around the counterexample cycle |
| `Children_without_workownership.cfg` | 225 | 97 | `NoCancelledPoll` violated |
| `Children_without_joblimit.cfg` | 745 | 250 | `BoundedJobs` violated |

TLC used two workers and a 2 GiB Java heap inside the capped work slice.
The isolation run completed in 1 hour 32 minutes, including its final
temporal check. No configuration or property was weakened for this run.
All Cargo, Kani and TLC invocations used the 10 GiB scope with swap disabled;
Cargo used four build jobs and the dedicated world-composition target.

## Audit against main `e2858ccc4` (November 9, 2026)

Both models were read statement by statement against the code after the
profiling merge (`children.rs` kept in a slab with intrusive ready and work
lists and a deadline heap). No action, property, constant or config
changed; the edits are the line references above and in the models'
comments, the README's harness list, and this section.

`Children.tla` after the profiling pass. The ready rules of the model
are the code's: a child joins the ready list when opened
(`children.rs:919`), when an event is placed (`:985`), when credit comes
(`:992`, the `"credit"` wake), after a timer, a result or handed-out work
(`called` with `ready` true at `:1039`, `:1063`, `:1115`), when payload is
released or its work wakes it (`ChildWake::notify` → `collect_wakes`,
`:634-646`, the `"release"` wake), and after a visit that moved or found
the queue full (`visit`, `:726`, the `"waiting"` wake). `advance`
(`:1077-1086`) pops the head of the list as many times as it had members
when it started; a child pushed back goes to the tail and waits for the
next advance, so each advance visits each child that was ready at its
start exactly once, in list order. The model's `Advance` visits the same
set in any order: a superset. `visit_kid` (`:732-833`) is `Visit`
statement for statement: urgent place first (`:749-758`), one inbox event
(`:759-781`), a new command (`:782-785`), the send within credit and the
reserve (`:797-811`), released credit and the grant (`:813-823`). What the
model does not see:

- One event per visit. The code's inbox is one FIFO of data and empty
  events and a visit pops one of them (`:759`); the model's `Visit` may
  take a data event and consume an empty one in the same step. The
  model's visits are therefore never slower than the code's, which is
  sound for the safety invariants and for `BoundedItems` (the code admits
  only while `inbox.len() < QUEUE`, `:712`, as `Full` says), but a
  liveness failure that needs the single-pop pace would not show.
- Blocked opens and control. `Opened` is handed back when `down` is full
  (`:860-866`), a `Control` event when `up` is full (`:999-1001`), and a
  control command when `down` is full (`:1014-1016`). The model's
  `Opened` never blocks, and `MuxNeverHeld` speaks only of child events,
  so these holds are outside it. They clear as the mux takes commands and
  the layer above takes events, which the mux does without delivering
  anything (`MuxTake`), so no deadlock hides there; the model does not
  show it.
- Reset as an event. `MuxEvent::Child(id, Reset)` (`terminal_reset`,
  `:926-939`) removes the child, cancels its work, offers the reset to
  the layer and queues a `Close`. From Children's side that is the shape
  of the `MayFail` close in `Visit`, not of `MuxPeerClose`, which is
  `MuxEvent::Closed` (`:995-997`, no `Close` queued). Configurations with
  `MayFail` false do not reach it.
- `MuxWritten` only reaches a waiting child. The code places a `Written`
  at any time (`:960-961`); a child with `urgent` set and `waiting`
  false is unreachable in the model and ordinary in the code. Its visit
  offers the completion first either way.
- Refusals the model does not have: an atomic command past `max_command`,
  which closes the child as failed. Memory the model does not have
  either: a command whose payload the child's budget refuses waits in the
  outbox, and an event whose inbox place or payload it refuses goes back
  to the mux, each until the budget frees; routing storage the stack's
  budget refuses hands the event or command back. None closes a child or
  ends the connection. The exception is a charge larger than the child's
  whole limit, which no release meets: that child alone is closed as
  failed (`a_command_past_its_childs_limit_closes_that_child_alone`,
  `an_event_past_its_childs_limit_closes_that_child_alone`).
- The release handshake. `ChildWake::release` adds to a counter and wakes
  the child only outside a call (`:285-290`); `take_released` collects it
  at the end of a visit (`:813`). The model's `Release` moves the credit
  to `owed` and wakes the child in one step. The argument that no release
  is lost is the comment at `:278-283`; the model does not check it.
- The layer's own `advance` returning true (`:742`) keeps a child ready
  with nothing else moving; the model's `moved` has no such term.

`Route.tla` matches `Chain::advance`, `Switch::advance`, `Switch::on_event`
and `on_command`, `Driver::run`, `send` and the harness's input loop as the
table above says, with the urgent slots and `owed` left out as described
under "What `Route.tla` leaves out". One bug in the code followed from
that omission and was not a model finding, since no model here has a
`Written`; it is fixed:

- `Switch::on_event` in its second phase answered `Blocked` to every event
  while leftovers waited, a `Written` from the layer below included,
  whether it arrived through `Chain::urgent` or from the runner.
  `Layer::take_urgent`'s contract is that the port above takes every
  completion it is offered. `Http2` is a successor
  (`web/httpd/native.rs:97`, `detect.rs:33`), refuses data while
  `out_bytes >= OUT_LIMIT` (`http2.rs:1416`, 64 KiB at `:66`) and lowers
  `out_bytes` only in `written` (`:1337`). So: an h2c upgrade or a
  prior-knowledge preface whose leftovers held enough pipelined requests
  for the responses to pass 64 KiB before `Http2` took the next leftover
  chunk; the transport wrote them and reported `Written`; the switch
  refused it because `below` was not empty; `Http2` never learned, refused
  the leftover for ever, and the connection stopped. The `Tunnel` successor
  ignores `Written` (`stack/tunnel.rs:160`) and was not affected. The fix
  moves the question "may this event pass refused input" to the port
  (`Port::urgent`, `mod.rs`), asked alike by `Chain`, `Children` and now
  `Switch` (`switch.rs:193`); the test
  `a_write_completion_passes_the_leftovers_the_successor_waits_to_read`
  holds a write completion behind two leftovers a successor refuses until
  it arrives, and fails on the old switch.

The trace check ties `Route.tla` to the code it describes.
`src/stdlib/layer/route_trace.rs` runs the real `Chain<L, Switch<A, B>>`
and `Driver` under abstract layers whose every answer (`Taken`, a
`Partial` prefix, `Blocked`, `Closed`) and every `advance` choice comes
from a seed, and logs the owner's actions and every call into a layer.
`tla/RouteTrace.tla` extends `Route` with the log as a constant and pins
each step's `\E` to its entry: the chunk offered must be what the model
holds there and the answer must be the one the code gave; steps the code
makes without calling a layer consume nothing. The spec has one successor
per state, so a log the model cannot follow deadlocks at the first entry
it cannot explain, and `UpConserved`, `DownConserved` and `HandoverOnce`
are checked along the way. `cargo xtask layer-verify trace` makes 32 logs
(47 to 87 entries) and replays each: all pass, one to three seconds each.

Runs on main at `e2858ccc4` by the shared check (two workers, 2 GiB heap,
`check-all/results.tsv`): `Route_base` and `Route_urgent` pass; the nine
`Route_without_*` configs violate the property their README row names
(`RunEnds`, `UpConserved` ×5, `DownConserved`, `HandoverOnce`,
`UrgentProgress`); `Children_base`, `_budget`, `_budget_stalled`,
`_commands_base`, `_large_command`, `_readiness`, `_refuse_base`,
`_refuse_full` and `_stalled_base` pass; the fourteen `Children_without_*`
configs violate their named property (`CommandCredit`, `EventCredit`,
`BoundedJobs`, `NoStaleDelivery` ×2, `NoCancelledPoll` as invariants; the
rest as the only temporal property in their config). `Route_wide_base` and
`Children_isolation` had not finished when this was written. After the
comment edits, `Route_base` was rerun (1,569,747 generated, 1,058,166
distinct, depth 83, all pass) and `Children_readiness` (76,122 generated,
10,619 distinct, depth 21, all pass), the counts recorded above.

## Scoped output and retained receive credit

On November 9, 2026, `Route_base` passed with 1,058,166 distinct states and
`Route_urgent` passed with 10. `Route_without_urgent` produced its expected
`UrgentProgress` counterexample. Chain now extracts a waiting urgent event
before ordinary output even when its ordinary slot is empty. The urgent
projection already permits that extraction; Rust additionally tests simultaneous
written credit and reset delivery before a lower-layer error is returned.

The child budget, stalled budget and isolation configurations passed with
699,144, 127,444 and 543,490 distinct states. `Children_without_isolate`
produced its expected `ConnectionProgress` counterexample. Payload reservation
failure and an absent application now follow the model's child refusal path.

The new `a_shared_chunk_edit_preserves_ownership_and_budget` Kani harness
passed 1,207 checks. It keeps the four symbolic payload bytes and exercises both
copy reservation outcomes, sibling immutability and final charge release.
Receive credit across original and edited backing is covered by the Rust child
routing regression; the byte-copy harness does not model the receive-credit
callback. All these runs used a 10 GiB systemd scope without swap, six Cargo
build jobs, and, for TLC, two workers with a 2 GiB Java heap.

## Charged containers and the wake

Charges and the containers they pay for became one value: `ChargedBytes`,
`ChargedDeque`, `ChargedVec` and `BoundedMap` in `src/stdlib/layer/charged.rs`
grow only by charging first, and `Chunk::repay` pays the new budget before the
old one lets go. `Charge::set` became `grow_to`, which can refuse, and
`shrink_to`, which cannot; `charges_split_and_drop_within_the_limit` and
`charges_sum_to_the_budget_and_never_pass_its_limit` grow or shrink where they
set. The results recorded above are from those harnesses before the change.

Five harnesses were written for the new code in the same style, fixed
sequences over symbolic `u8` sizes, and have not been run:

| Harness | Proves |
| --- | --- |
| `charge_within_takes_what_fits_or_nothing` | a charge within a range takes its end if it fits, else all the room left if that covers its start, else nothing, changing nothing but the count of refusals |
| `transfer_within_one_budget_never_raises_used` | moving a charge within one budget changes nothing even when the budget is full; across budgets the target is charged first, a refusal changes neither count, and a move takes exactly the charge from one count to the other |
| `a_release_after_a_refusal_wakes_once` | a runner that asks after a refusal is woken once by the first release that leaves room for the refused charge, a release that leaves less wakes nothing, a charge past the limit is never woken for, asking again adds nothing, and asking when nothing was refused wakes nothing |
| `charged_bytes_capacity_is_its_charge` | for three fixed sizes, bytes are charged their capacity after being made, grown, overrun by a writer that is undone, written and trimmed; a growth without room is refused and everything comes back on drop |
| `a_refused_growth_changes_nothing` | a refused growth leaves a charge, bytes (their allocation included) and a queue as they were, with the count unchanged |

Each asker now charges through its own view of a budget (`Budget::view`),
which records its refusals and whether one needed more than the whole limit
(`Starved`). Two harnesses were written for the views, in the same style, and
`a_release_after_a_refusal_wakes_once` gained a second view whose runner is
never woken. None has been run:

| Harness | Proves |
| --- | --- |
| `a_view_records_only_its_own_refusals` | a charge through one view of a budget, while another view holds part of it, is refused exactly when it does not fit, and only the asking view (and its clones) records the refusal |
| `starved_is_a_need_over_the_limit_and_never_wakes` | a refused charge is starved exactly when its need passes the limit, with that need and the limit, and its runner is never woken for it, even when every byte comes back; a refused need within the limit is woken once memory returns |

The model test `random_calls_keep_cover_sum_order_return_move_and_wake` in
`charged.rs` runs 64 seeded sequences of 400 random calls on two budgets, each
charged through two views, and checks every invariant after each call,
including that a refusal is seen by the charging view only, that a view is
starved exactly when a need past the limit was refused through it, and that a
starved view's runner and a runner whose view was not refused are never
woken. Each of these changes made it fail,
along with the named unit test: a release that wakes nobody
(`a_release_after_a_refusal_wakes_each_waiting_runner_once`), a repay that
trims before it pays (`a_refused_repay_reallocates_and_releases_nothing`), and
a runner that asks after memory was freed left waiting
(`a_runner_that_asks_after_memory_freed_is_woken_at_once`).
