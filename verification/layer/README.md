# Layer foundation

The TLA+ models of how `Chain`, `Switch` and the `Driver` route items
between layers (`tla/Route.tla`) and of `Children` over a multiplexed
connection whose children live in `Slots` (`tla/Children.tla`), and the Kani
proofs over `Slots`, `Budget` and `Charge`, `Timers` and `WorkOwner`
(`kani/mod.rs`). The code is in `src/stdlib/layer/`. What each model covers,
what it leaves out, and what it found is in [VERIFICATION.md](VERIFICATION.md).

Each `.tla` has `*_base.cfg` configs of the code as it is, which must pass,
and `*_without_<flag>.cfg` configs that break one part of the code and name
the property TLC must then violate. `Route_urgent.cfg`,
`Children_budget.cfg`, `Children_budget_stalled.cfg`,
`Children_large_command.cfg`, `Children_readiness.cfg`,
`Children_refuse_full.cfg` and `Children_isolation.cfg` are additional
passing configurations.

`Children::budgets` may select a separate budget per child before its receive
window and application are allocated. The existing nondeterministic
`BudgetRefuses` abstraction covers refusal of a child by its selected budget,
its payload reservation or its factory. Failure to reserve the parent's fixed
routing storage still ends the router and is outside this child model. It
does not prove budget-selector purity or model byte arithmetic; the Rust
child-budget tests check allocation order, payload refusal, factory refusal,
reservation release and independent sibling admission.

| Config | Checks |
| --- | --- |
| `Route_base.cfg` | `UpConserved`, `DownConserved`, `HandoverOnce`, `RunEnds` |
| `Route_wide_base.cfg` | the same with three bytes each way (about two minutes) |
| `Route_without_keepblocked.cfg` | `offer` drops a Blocked item: violates `UpConserved` |
| `Route_without_keeprest.cfg` | `offer` keeps the whole of a partly taken item: violates `UpConserved` |
| `Route_without_blockedisstill.cfg` | `offer` calls a Blocked answer progress: violates `RunEnds` |
| `Route_without_leftoversfirst.cfg` | the switch lets new input pass the leftovers: violates `UpConserved` |
| `Route_without_restfirst.cfg` | `feed` puts a rest at the back of the queue: violates `UpConserved` |
| `Route_without_moveabove.cfg` | the switch drops the handover's commands: violates `DownConserved` |
| `Route_without_switchonce.cfg` | the switch keeps running `A` after the handover: violates `HandoverOnce` |
| `Route_without_driverkeepsrest.cfg` | the driver's `send` drops a rest: violates `UpConserved` |
| `Route_urgent.cfg` | the urgent projection (`UrgentSpec`): one completion through the lower layer, Chain's urgent slot, the upper layer and the Driver's urgent slot while both normal edges hold data: `UrgentConserved`, `UrgentProgress` |
| `Route_without_urgent.cfg` | no bypass: the completion waits behind the refused data: violates `UrgentProgress` |
| `Children_base.cfg` | `NoStaleDelivery`, `EventCredit`, `MuxEventCredit`, `CommandCredit`, `SendsLeaveReserve`, with two children at once |
| `Children_refuse_base.cfg` | the same but `MuxEventCredit`, with a limit of one child (so `Opened` is refused) and a mux that may send past credit |
| `Children_stalled_base.cfg` | the invariants and `ControlProgress`, with children that never read |
| `Children_budget.cfg` | the base invariants with `BudgetRefuses`: the budget may refuse a child's place at `Opened` or its inbox or payload reservation at `MuxSend`, closing that child |
| `Children_budget_stalled.cfg` | the stalled configuration with `BudgetRefuses` |
| `Children_refuse_full.cfg` | with `Overload`: a child that never reads, and its successor in the same slot, each refused and closed when its place is full instead of holding up the mux; the readiness invariants, `MuxNeverHeld` and `CancelledWorkLeaves` |
| `Children_commands_base.cfg` | `CommandsGo` when every command fits the mux's window |
| `Children_without_checkoverrun.cfg` | no Overrun check: violates `EventCredit` |
| `Children_without_checkcommandcredit.cfg` | commands sent without credit: violates `CommandCredit` |
| `Children_without_reserveforcontrol.cfg` | no reserved places: violates `ControlProgress` |
| `Children_without_muxchecksgeneration.cfg` | `Slots` ignore the generation: violates `NoStaleDelivery` |
| `Children_without_keybywholeid.cfg` | `Children` keys children by slot: violates `NoStaleDelivery` |
| `Children_large_command.cfg` | a command larger than the mux's window drains in legal prefixes: `CommandsGo` holds |
| `Children_readiness.cfg` | retained receive credit, bounded empty events and jobs, urgent completion, cancellation, and `CreditReturns`: owed credit goes back to the mux |
| `Children_without_urgent.cfg` | completion stays behind refused data: violates `CompletionProgress` |
| `Children_without_workownership.cfg` | runtime polls work after its owner closes: violates `NoCancelledPoll` |
| `Children_without_joblimit.cfg` | reset/reopen launches work past the job limit: violates `BoundedJobs` |
| `Children_isolation.cfg` | a mux that sends whatever a child's place holds, a child in slot 1 that never takes an event, and connection traffic: `MuxNeverHeld`, `ConnectionProgress`, credit and item bounds |
| `Children_without_isolate.cfg` | a full place hands the event back to the mux: violates `ConnectionProgress` |
| `Children_without_wakeoncredit.cfg` | credit from the mux does not ready the child: violates `CommandsGo` |
| `Children_without_keepwaiting.cfg` | a child whose command finds the queue full is not kept ready: violates `CommandsGo` |
| `Children_without_wakeonrelease.cfg` | released payload does not ready its child: violates `CreditReturns` |
| `BudgetWake_base.cfg` | the budget's wake, one atomic step at a time, four runners on views of one budget (one needing more than the limit), every runner holding only for a while: `WithinLimit`, `StarvedNeverWaits`, `AllServed` |
| `BudgetWake_spin_base.cfg` | the same where a runner may hold its memory for ever: `NoSpin` (no runner is woken over and over while nothing frees) and `WakeWhenRoom` (no runner is left asleep for good while the room covers its need) |
| `BudgetWake_without_owedwake.cfg` | `wake_when_freed` as it was before this pass, waking only the asker when the room already covers the least refused need: violates `NoSpin` |
| `BudgetWake_without_wokenmark.cfg` | the asker ignores a release that woke the runners since its mark: violates `WakeWhenRoom` |
| `BudgetWake_without_recheck.cfg` | no last try after noting the need and no room check when asking: violates `WakeWhenRoom` |
| `BudgetWake_lasttry_alone.cfg`, `BudgetWake_roomcheck_alone.cfg` | each of the two without the other: both pass, each covers the race the other closes |
| `ChildMemory_base.cfg` | `Children`'s memory rules for three children on views of one budget (one needing more than the limit), with other connections charging and releasing: `CauseMatches`, `MemoryClosesNothing`, `StarvedClosesAlone`, `WaitTold`, `ChildWakes`, `TellEnds` |
| `ChildMemory_without_waitonrefusal.cfg` | a refusal within the limit closes the child, as before the leftovers: violates `MemoryClosesNothing` |
| `ChildMemory_without_ownview.cfg` | children charge the stack's view: a child's need past the limit ends the run: violates `StarvedClosesAlone` |
| `ChildMemory_without_samecause.cfg` | `Refused` reports a memory refusal as prohibited: violates `CauseMatches` |
| `ChildMemory_without_wakeonrelease.cfg` | the release does not wake a waiting child: violates `ChildWakes` |
| `ChildMemory_without_tellevent.cfg` | a wait begun by an event's charge is not told to the runner: violates `WaitTold` |

Run one with TLC (JDK 11 or later):

```sh
cd verification/layer/tla
systemd-run --user --scope -p MemoryMax=8G -p MemorySwapMax=0 ~/.cache/adorably-fv/jdk/bin/java -Xmx6g -cp ~/.cache/adorably-fv/tla2tools.jar tlc2.TLC -workers 4 -metadir ~/.cache/adorably-fv/route-states -config Route_base.cfg Route.tla
systemd-run --user --scope -p MemoryMax=8G -p MemorySwapMax=0 ~/.cache/adorably-fv/jdk/bin/java -Xmx6g -cp ~/.cache/adorably-fv/tla2tools.jar tlc2.TLC -workers 4 -metadir ~/.cache/adorably-fv/children-states -config Children_base.cfg Children.tla
```

`CHECK_DEADLOCK FALSE` is set because a finished run of the owner, or a
mux with every slot used up, has nothing left to do.

`tla/RouteTrace.tla` replays a log of the real routing code against
`Route.tla`. The test `route_trace` in `src/stdlib/layer/route_trace.rs`
runs `Chain`, `Switch` and the `Driver` under seeded abstract layers and
writes one `RouteLog_<seed>.tla` and `.cfg` per seed when
`FICTIONET_ROUTE_TRACE_DIR` is set; each entry is a call the code made with
the bytes offered and the answer given, and the spec deadlocks at the
first entry the model cannot follow. Run it all with

```sh
TLA2TOOLS=~/.cache/adorably-fv/tla2tools.jar JAVA=~/.cache/adorably-fv/jdk/bin/java cargo xtask layer-verify trace
```

which writes the logs, TLC's output and its states under
`layer-verify/` in the Cargo target directory.

The Kani harnesses are compiled into `src/stdlib/layer/mod.rs` under
`cfg(kani)` and call the production code:

```sh
cargo kani -p fictionet --harness slots_refuse_past_the_limit
cargo kani -p fictionet --harness slots_never_answer_a_stale_id
cargo kani -p fictionet --harness slots_never_answer_another_connections_id
cargo kani -p fictionet --harness charges_split_and_drop_within_the_limit
cargo kani -p fictionet --harness charges_sum_to_the_budget_and_never_pass_its_limit
cargo kani -p fictionet --harness timers_in_order_three_names
cargo kani -p fictionet --harness timers_get_three_names
cargo kani -p fictionet --harness timers_in_order_first_armed_again
cargo kani -p fictionet --harness timers_in_order_second_armed_again
cargo kani -p fictionet --harness timers_in_order_first_armed_twice
cargo kani -p fictionet --harness timers_in_order_one_name_three_times
cargo kani -p fictionet --harness timers_cancel_fire_and_retain_touch_one_name
cargo kani -p fictionet --harness stream_credit_splits_keep_the_allocation_owned
cargo kani -p fictionet --harness charges_sum_to_the_budget_and_never_pass_its_limit
cargo kani -p fictionet --harness work_cancellation_stays_with_its_owner
```

None stubs anything: every call reaches the
production code. The proofs of `Chunk` itself moved with it to
[`verification/buf`](../buf/README.md).

Run Cargo under `systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=10G -p MemorySwapMax=0`
with `CARGO_BUILD_JOBS=4` and the worktree's `CARGO_TARGET_DIR`. Measured results
and proof scope are recorded in [VERIFICATION.md](VERIFICATION.md).

With `close_finished` enabled, application completion in `Children::visit_kid`
(`children.rs:824-831`) uses the same close and work cancellation path as
failure. The abstract `MayFail` close includes completion; Rust additionally
waits until the child has no command waiting and the queue has room. A
transport close is a request to release that child handle, not proof that a
TCP socket retired.

`Chunk::make_mut` reuses unique charged backing and reserves before copying a
shared view. Its receive-credit token is shared by all edited and original
pieces, so copying cannot release receive credit early. The Kani harness (now
in `verification/buf`) `a_shared_chunk_edit_preserves_ownership_and_budget`
checks a symbolic four-byte
payload, both sufficient and insufficient budgets, sibling immutability and
final charge release. Child routing tests also check credit return exactly once
after every edited piece is released. `Layer::take_command` now receives the
same scoped `Env` as admission; the proof harnesses extract through `Driver`.

On November 9, 2026 the child budget, stalled budget and isolation
configurations passed with 699,144, 127,444 and 543,490 distinct states.
The isolation control failed `ConnectionProgress`: a refused child event
kept the mux from delivering its waiting connection control message.

The November 9 Kani rerun completed all nine selected ownership, cursor,
charge and slot harnesses, including the new shared-edit property; the
interrupted TLS accounting harnesses are tracked in the TLS verification area.

## Resource properties

The method is in `verification/README.md`, "Resource properties". This
area adds all three layers for the runtime and layer machinery: the
charged containers (`ChargedDeque`, `ChargedVec`, `ChargedBytes`), the
budget's charges and refunds, `Children`'s places and the spares a closed
child leaves, and the report store (`Observations`). The cable queues,
the packet queues and the split of the whole world's memory are in
`verification/world-net/README.md`, "Resource properties"; SSH and
WebSocket in their own READMEs. One command runs them all:

```sh
cargo xtask layer-verify resources   # Kani, TLC and the costed replays of all four
```

**The bug, fixed (84530d0d5).** A charged container grew by reallocating
after charging only its new size. `Vec` and `VecDeque` move their items
into the new allocation before they free the old one, so for that moment
both were live, past the charge: a deque of four 16-byte places on a
budget of 130 bytes doubled to eight while its four were live, 192 bytes
against the limit. `Children`'s places grew every table the same way, and
gave places back by making each new table before the old one went.
`Budget`'s own rule says the limit holds at every moment, not only when
someone checks. Now a growth takes the old allocation's bytes with the new
ones, in one step (`Charge::grow_by_units_moving`, `Charge::grow_to_moving`),
so a refusal names their sum as its need, and gives them back once the
items have moved. A shrink moves the items too: it charges the smaller
allocation first with `Budget::try_charge`, which records no refusal, and
does not happen while there is no room. `Places::make_room` charges what
the places are charged now for the moment its tables move, and
`Places::release` the new tables. Test:
`a_growth_is_paid_for_while_the_old_places_are_live` (`charged.rs`), which
grew to eight places against a limit of eleven before; the budget's own
tests are `a_growth_that_moves_takes_the_old_allocation_with_it` and
`a_charge_tried_without_room_is_no_refusal`.

**What is charged.** Each container pays from a `Budget` before it
allocates; the harnesses give it a budget of its own, so its limit is the
charge. The report store has a budget of its own (`Observations::bounded`)
and charges a report's heap, then its place.

| Bound | Constant | Why |
| --- | --- | --- |
| no moment of a growth holds more than the budget's limit | the limit | the old allocation is charged while the items move |
| after a step, a container holds what its budget counts | | its charge is its capacity outside its own methods |
| a push asks for at most what the container is charged after it | | one new allocation, of the places charged |
| a refused growth allocates nothing | | the charge comes first |
| after a report, the store keeps at most what its budget counts, beside the budget's record | the record: what `Budget::new` allocates | the heap and the place are charged before the report is kept |
| no moment holds more than the record, the store's limit and the report being made | one report | the report exists before the store sees it |
| `Children`: open children and spares together never pass the places paid for | the places | see the TLA+ model below |

| Layer | Check | Result |
| --- | --- | --- |
| Kani (`kani/resources.rs`) | `a_full_charged_deque_grows_within_a_tight_budget` (four 8-byte places on a budget of 65 bytes, one more pushed), the same for `ChargedVec`, `charged_bytes_grow_within_their_budget_100` and `_160` (60 bytes, then 80), `kept_reports_are_charged_to_the_store` and `reports_past_the_store_are_omitted_with_nothing_kept`, with every allocation counted | all pass; times below |
| TLA+ (`tla/Growth.tla`) | a container's places and `Children`'s two tables of places and their spares as stores, in the code's order: `ContainerPaid`, `PlacesPaid`, `PartsPaid`, `BudgetWithinLimit`, and `Tracks` for each | `Growth_base` passes, 3,686 distinct states |
| replays | the layer foundation's trace replay (`layer-verify trace`) runs abstract layers that hold nothing of their own, so it is not costed; the costed replays of this command are SSH's and WebSocket's | |

The `Children` cap on spares (`Places::keep` keeps one only while a place
no child fills has room) turned out to be implied: opening a child takes a
spare when there is one, and closing turns a child into a spare, so open
children and spares never pass the places whatever `keep` checks. With
the cap removed, `PartsPaid` still holds. So the model has no control for
it; the cap stays as a guard.

`cargo xtask layer-verify resources` passed in full on November 10, 2026
(`comp/res-ssh-runtime`), each Kani harness in a `cargo kani` of its own
under a 14 GiB scope, with `-Z restrict-vtable` and one harness at a time
(`xtask/src/resources.rs`): run in one `cargo kani`, after the others,
the deque's harness ran out of 14 GiB, though alone it fits. The four
models' configs and the costed replays ran in the same command
(`world-net`, `ssh-layer` and `websocket` READMEs).

| Harness | Time |
| --- | --- |
| `the_counter_sees_every_allocation` | 12.0 s |
| `a_full_charged_deque_grows_within_a_tight_budget` | 437.3 s |
| `a_full_charged_vec_grows_within_a_tight_budget` | 212.0 s |
| `charged_bytes_grow_within_their_budget_100` | 33.4 s |
| `charged_bytes_grow_within_their_budget_160` | 10.2 s |
| `kept_reports_are_charged_to_the_store` | 143.2 s |
| `reports_past_the_store_are_omitted_with_nothing_kept` | 147.0 s |
| WebSocket's two and SSH's two | 0.8 to 6.1 s |

Controls, each run and then dropped:

| Control | Layer | Fails |
| --- | --- | --- |
| `charge_places` and `grow_to_moving` without the old allocation (the code before 84530d0d5) | Kani: `a_full_charged_deque_grows_within_a_tight_budget`, `a_full_charged_vec_grows_within_a_tight_budget`, `charged_bytes_grow_within_their_budget_100` | `the deque held more than its budget` (179 s), `the vector held more than its budget` (161 s), `the bytes held more than their budget` (13 s) |
| `Observations::observe` keeping a report without charging its heap | Kani: `kept_reports_are_charged_to_the_store` | `the store keeps more than it is charged` (69 s) |
| `Growth_without_chargemove` | TLA+ | `ContainerPaid` |
| `Growth_places_without_chargemove` | TLA+ | `PlacesPaid` |

**Not covered.** `Children`'s places have no Kani harness: one needs a
router with a mux, a factory and children, and none was attempted. The
TLA+ model and the unit test
`full_places_grow_every_table_by_the_places_that_fit` cover them. A
deque or vector pushed from empty through a doubling ran CBMC out of
14 GiB, so each harness starts from a full container of the first four
places, made inside the measurement. A full deque with room for its
doubling and the move (16-byte items, 200 bytes) did not finish: CBMC
ran 31 minutes at 11 GiB before it was stopped, and the vector's twin was
not run. So the growth that fits with its move is proved for
`ChargedBytes` only (`charged_bytes_grow_within_their_budget_160`); for
the deque and the vector, the harnesses prove the refusal, and the unit
test `a_growth_is_paid_for_while_the_old_places_are_live` the growth.
With 16-byte items, the deque's tight harness passed once (270.7 s) and
once ran out of 14 GiB, so its items are `u64`s.
