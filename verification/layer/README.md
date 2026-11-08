# Layer foundation

The TLA+ models of how `Chain`, `Switch` and the `Driver` route items
between layers (`tla/Route.tla`) and of `Children` over a multiplexed
connection whose children live in `Slots` (`tla/Children.tla`), and the Kani
proofs over `Slots`, `Budget` and `Charge`, `Timers` and `Chunk`
(`kani/mod.rs`). The code is in `src/stdlib/layer/`. What each model covers,
what it leaves out, and what it found is in [VERIFICATION.md](VERIFICATION.md).

Each `.tla` has `*_base.cfg` configs of the code as it is, which must pass,
and `*_without_<flag>.cfg` configs that break one part of the code and name
the property TLC must then violate. `Children_large_command.cfg` and
`Children_readiness.cfg` are additional passing configurations, as is
`Children_refuse_full.cfg`.

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
| `Children_base.cfg` | `NoStaleDelivery`, `EventCredit`, `MuxEventCredit`, `CommandCredit`, `SendsLeaveReserve`, with two children at once |
| `Children_refuse_base.cfg` | the same but `MuxEventCredit`, with a limit of one child (so `Opened` is refused) and a mux that may send past credit |
| `Children_stalled_base.cfg` | the invariants and `ControlProgress`, with children that never read |
| `Children_budget.cfg` | the base invariants with `BudgetRefuses`: the budget may refuse a child's place at `Opened` or its inbox's growth at `MuxSend`, closing that child |
| `Children_budget_stalled.cfg` | the stalled configuration with `BudgetRefuses` |
| `Children_refuse_full.cfg` | with `RefuseFullInbox` (`Children::refuse_full_inbox`, which SSH uses): a child that never reads, and its successor in the same slot, a child whose inbox is full refused and closed instead of holding up the mux; the readiness invariants and `CancelledWorkLeaves` |
| `Children_commands_base.cfg` | `CommandsGo` when every command fits the mux's window |
| `Children_without_checkoverrun.cfg` | no Overrun check: violates `EventCredit` |
| `Children_without_checkcommandcredit.cfg` | commands sent without credit: violates `CommandCredit` |
| `Children_without_reserveforcontrol.cfg` | no reserved places: violates `ControlProgress` |
| `Children_without_muxchecksgeneration.cfg` | `Slots` ignore the generation: violates `NoStaleDelivery` |
| `Children_without_keybywholeid.cfg` | `Children` keys children by slot: violates `NoStaleDelivery` |
| `Children_large_command.cfg` | a command larger than the mux's window drains in legal prefixes: `CommandsGo` holds |
| `Children_readiness.cfg` | retained receive credit, bounded empty events and jobs, urgent completion, and cancellation |
| `Children_without_urgent.cfg` | completion stays behind refused data: violates `CompletionProgress` |
| `Children_without_workownership.cfg` | runtime polls work after its owner closes: violates `NoCancelledPoll` |
| `Children_without_joblimit.cfg` | reset/reopen launches work past the job limit: violates `BoundedJobs` |

Run one with TLC (JDK 11 or later):

```sh
cd verification/layer/tla
systemd-run --user --scope -p MemoryMax=8G -p MemorySwapMax=0 ~/.cache/adorably-fv/jdk/bin/java -Xmx6g -cp ~/.cache/adorably-fv/tla2tools.jar tlc2.TLC -workers 4 -metadir ~/.cache/adorably-fv/route-states -config Route_base.cfg Route.tla
systemd-run --user --scope -p MemoryMax=8G -p MemorySwapMax=0 ~/.cache/adorably-fv/jdk/bin/java -Xmx6g -cp ~/.cache/adorably-fv/tla2tools.jar tlc2.TLC -workers 4 -metadir ~/.cache/adorably-fv/children-states -config Children_base.cfg Children.tla
```

`CHECK_DEADLOCK FALSE` is set because a finished run of the owner, or a
mux with every slot used up, has nothing left to do.

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
cargo kani -p fictionet --harness a_chunk_cursor_keeps_the_rest_in_place
cargo kani -p fictionet --harness a_chunk_cursor_never_passes_the_end
cargo kani -p fictionet --harness stream_credit_splits_keep_the_allocation_owned
```

Run Cargo under `systemd-run --user --scope -p MemoryMax=12G -p MemorySwapMax=0`
with `CARGO_BUILD_JOBS=6` and the worktree's `CARGO_TARGET_DIR`. Measured results
and proof scope are recorded in [VERIFICATION.md](VERIFICATION.md).
