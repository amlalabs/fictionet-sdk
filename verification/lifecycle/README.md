# Service and connection lifecycle

The TLA+ models of the serving state machine (`tla/Core.tla`, for
`src/stdlib/services/serve.rs`) and of one TCP connection's life
(`tla/Conn.tla`, for `src/stdlib/network/tcp.rs`), and the Kani proofs over
the pure parts of `serve` (`kani/ServeProof.rs`). What each models, what it
leaves out, and what it found is in [VERIFICATION.md](../../VERIFICATION.md)
at the root of the repository.

Each `.tla` has a config of the code as it is, and configs that keep an
earlier or weakened rule and name the property TLC must then violate:

| Config | Checks |
| --- | --- |
| `Core_fixed.cfg` | every invariant and property of `Core`, with an idle limit of two ticks |
| `Core_wide.cfg` | the same without an idle limit, with two of each kind of work and input |
| `Core_original_idle.cfg` | the idle clock before the fix: violates `IdleNeedsQuiet` |
| `Core_original_broken.cfg` | `broken` before the fix: violates `ObservedCancel` |
| `Conn.cfg` | every invariant and property of `Conn` |
| `Conn_without_orphantimer.cfg` | no `expire_orphans`: violates `OrphanRemoved` |
| `Conn_without_resetunread.cfg` | a drop with unread bytes closes instead of resetting: violates `DropResetsUnread` |

Run one with TLC (Java 11 or later and `tla2tools.jar`):

```sh
cd verification/lifecycle/tla
java -Xmx4g -cp "$TLA2TOOLS" tlc2.TLC -workers 2 -config Core_fixed.cfg Core.tla
java -Xmx4g -cp "$TLA2TOOLS" tlc2.TLC -workers 2 -config Conn.cfg Conn.tla
```

Every config finishes in seconds. `CHECK_DEADLOCK FALSE` is set because a
connection that has returned, or been removed, has nothing left to do.

The Kani harnesses are compiled into `serve` under `cfg(kani)` and call the
real `arm`, `due`, `Budget`, `Charge`, `Counted` and `WakeHandle`:

```sh
cargo kani -p fictionet --harness timers_are_armed_once_and_the_earliest_is_due
cargo kani -p fictionet --harness charges_sum_to_the_budget_and_never_pass_its_limit
cargo kani -p fictionet --harness connections_are_counted_up_to_the_maximum
cargo kani -p fictionet --harness a_wake_is_seen_once_and_not_after_close
```
