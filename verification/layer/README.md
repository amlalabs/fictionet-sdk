# Layer foundation

The TLA+ models of how `Chain`, `Switch` and the `Driver` route items
between layers (`tla/Route.tla`) and of `Children` over a multiplexed
connection whose children live in `Slots` (`tla/Children.tla`), and the Kani
proofs over `Slots`, `Budget` and `Charge`, `Timers` and `Chunk`
(`kani/mod.rs`). The code is in `src/stdlib/layer/`. What each model covers,
what it leaves out, and what it found is in [VERIFICATION.md](VERIFICATION.md).

Each `.tla` has `*_base.cfg` configs of the code as it is, which must pass,
and `*_without_<flag>.cfg` configs that break one part of the code and name
the one property TLC must then violate. `Children_large_command.cfg` is a
finding: it violates `CommandsGo` on the code as it is.

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
| `Children_commands_base.cfg` | `CommandsGo` when every command fits the mux's window |
| `Children_without_checkoverrun.cfg` | no Overrun check: violates `EventCredit` |
| `Children_without_checkcommandcredit.cfg` | commands sent without credit: violates `CommandCredit` |
| `Children_without_reserveforcontrol.cfg` | no reserved places: violates `ControlProgress` |
| `Children_without_muxchecksgeneration.cfg` | `Slots` ignore the generation: violates `NoStaleDelivery` |
| `Children_without_keybywholeid.cfg` | `Children` keys children by slot: violates `NoStaleDelivery` |
| `Children_large_command.cfg` | a command larger than the mux's window: violates `CommandsGo` (finding) |

Run one with TLC (JDK 11 or later):

```sh
cd verification/layer/tla
java -Xmx6g -cp ~/.cache/adorably-fv/tla2tools.jar tlc2.TLC -workers 4 -config Route_base.cfg Route.tla
java -Xmx6g -cp ~/.cache/adorably-fv/tla2tools.jar tlc2.TLC -workers 4 -config Children_base.cfg Children.tla
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
cargo kani -p fictionet --harness timers_in_order_three_names
cargo kani -p fictionet --harness timers_get_three_names
cargo kani -p fictionet --harness timers_in_order_first_armed_again
cargo kani -p fictionet --harness timers_in_order_second_armed_again
cargo kani -p fictionet --harness timers_in_order_first_armed_twice
cargo kani -p fictionet --harness timers_in_order_one_name_three_times
cargo kani -p fictionet --harness timers_cancel_fire_and_retain_touch_one_name
cargo kani -p fictionet --harness a_chunk_cursor_keeps_the_rest_in_place
cargo kani -p fictionet --harness a_chunk_cursor_never_passes_the_end
```

Run each under a memory cap of about 10 GB; every one finishes in under two
minutes.
