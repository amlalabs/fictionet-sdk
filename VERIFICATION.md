# Service and connection lifecycle: what was modeled and found

This pass covers the serving driver in `src/stdlib/services/serve.rs`
(serving state, cancellation on drop, wake handles, STARTTLS upgrades), the
`Connection` contract in `src/stdlib/network/connection.rs`, and one TCP
connection's life in `src/stdlib/network/tcp.rs` (close, orphan, half-close,
reset, unread data). The models are under `verification/lifecycle/`, with the
commands to run them in its [README](verification/lifecycle/README.md).

Two bugs were found in `serve.rs`, each confirmed by a test that failed on
the code before its fix, and fixed at the root. The TCP connection's life
checks clean; no code in `tcp.rs` or `connection.rs` changed.

## The serving state machine: `Core.tla`

[`Core.tla`](verification/lifecycle/tla/Core.tla) is `Core` as `run` drives
it over one connection. The core is a record; each operator is the Rust
function it stands for, and the actions compose them as the code does:

| Model | Rust |
| --- | --- |
| `Finish`, `EndNow`, `Broken`, `Apply`, `Call`, `Collect`, `CancelAll`, `FinishAfterWork`, `Recharge` | `Core::finish`, `end_now`, `broken`, `apply`, `call`, `collect`, `cancel_all`, `finish_after_work`, `recharge` |
| `Advance*` | the cases of `Core::advance`, in its order, each enabled only when those before it are not |
| `Ending*` | `Core::ending` |
| `Wait*` | the `poll_fn` of `run`'s `Next::Wait` arm (cancel first, then work, wake, read, gone, deadline) and `Core::poll_work` |
| `WriteStep`, `YieldCancel` | the write loop at the top of `run`'s loop; `Next::Again`'s `yield_now` seeing a cancel |
| `CloseReturn`, `UpgradeReturn` | `Next::Closed` with its shutdown race and what `run` returns; `Next::Upgrade` |
| `Cancel`, `Wake`, `TimerFires`, `Tick` | the region cancelled, `WakeHandle::wake`, a timer coming due, time passing while the driver waits |

The service is abstract: every call may append a reply, defer ordered or
keyed work, arm the timer, and hand back any `Flow` or an error. Bytes are
counted, not carried. `charged` is `Charge::now`: the budget can blow only
when the holding grew past the last charge that fit, as `Charge::set`
refuses nothing smaller. Two constants keep the code before its fixes:
`SuspendIdle` and `TotalBroken`.

What is checked:

- `OnEndOnce`, `NoLateCalls`: `on_end` runs at most once, and no call reaches
  the service after `Ended`.
- `WakeHandle`: the handle is open exactly while the service runs, closed
  from `Ending` on, and after a handoff; open across a STARTTLS upgrade.
- `WorkAtEnd`, `Unwritable`: no deferred work outlives the connection, keyed
  work ends with `Running`, and an end the connection cannot take a reply
  for writes nothing and runs no ordered work.
- `WritableEndHeard`: every writable end reached `on_end`.
- `ObservedCancel`: once a wait of the driver returned the cancel, `run`
  returns it, unless a failure wins or the budget blows meanwhile.
- `IdleNeedsQuiet`: an idle end comes only after the client had the whole
  idle time to speak while the driver listened.
- `EndingTerminates`, `CancelReturns`: an ending connection ends and a
  cancelled one returns, given that the driver keeps stepping, deferred work
  ends eventually, and the yield every 64th `Again` happens eventually.

| Config | Generated | Distinct | Depth | Result |
| --- | ---: | ---: | ---: | --- |
| `Core_fixed.cfg` (idle of two ticks, one of each work and input) | 593,496 | 111,078 | 21 | all eight invariants and three properties hold |
| `Core_wide.cfg` (no idle, two of each work and input) | 181,600 | 27,192 | 16 | all hold |
| `Core_original_idle.cfg` (`SuspendIdle = FALSE`) | 41,258 | 11,768 | 9 | `IdleNeedsQuiet` violated: a wake whose call defers ordered work, two ticks, the work ends, `Ended::Idle` |
| `Core_original_broken.cfg` (`TotalBroken = FALSE`) | 15,534 | 4,332 | 8 | `ObservedCancel` violated: a cancel, a wake whose call asks for a handoff, `apply`, the yield sees the cancel and `broken` does nothing, the connection is handed on |

The two passing runs explored their whole space with an empty queue; TLC
stops at the first violation in the other two.

### Bug 1: the idle clock ran under ordered work

The driver promises (module doc, "Idle") to close a connection as idle only
when the client sent nothing for the idle time *while the driver waits for
it*. While ordered work runs the driver does not read, but `idle_from` kept
counting from the client's last bytes. A handler deferred with
`Driver::defer` that outlasted the idle limit was followed at once by
`Ended::Idle`, with the client given no time to send its next request.
Keyed work had an ad-hoc reset of `idle_from` when it ended; ordered work had
nothing; `on_item` had a redundant reset of its own.

Reproduction: `the_idle_clock_restarts_after_ordered_work` in
`tests/it/serve_harness.rs`. A harness with a ten-second idle limit pushes
one line whose service defers work that ends when a flag is set; the clock
moves twenty seconds; the flag is set and the harness polled. Before the
fix the connection was closed with `Ended::Idle` right there (the assertion
"the client had no time to speak since the work ended" failed). After it,
the connection stays open for nine more seconds and closes as idle at ten.

Fix (`96a6f4824`): one rule. `Core` notes in `working` whether deferred work
of either kind ran at its last `advance`, and restarts `idle_from` when the
wait for the client resumes. The two ad-hoc resets are gone; the client's
bytes still restart the clock in `input`. `next_deadline` and the idle check
suspend the clock for `has_work()`, not for keyed work alone.

### Bug 2: a cancelled region handed a connection off

`connection` promises `ServeError::Cancelled` once its region is cancelled.
`broken`, which every wait calls on a cancel, did nothing in the `Upgrading`
state: when the yield between items saw the cancel after `apply` had set
`Upgrading(Handoff)`, the next `advance` handed the connection on and `run`
returned `Ok(Served::Upgraded)`. Without the yield the upgrade exit never
looked at the region at all, so whether a cancelled connection came back as
`Err(Cancelled)` or `Ok(Upgraded)` depended on how many items came before
the handoff.

Reproduction: `a_cancelled_region_hands_no_connection_off` in
`tests/it/serve_cancellation.rs`. A connection double hands the driver every
byte at once and cancels the connection's region as it does; the input is
`lines` echo lines followed by `handoff`, for every `lines` from 0 to 69,
which passes the driver's yield. Before the fix every count returned
`Ok(Served::Upgraded)`.

Fix (`105e1e07d`): `broken` is total over the states, so an
upgrading connection ends as an ending one does, and the `Next::Upgrade` arm
of `run` observes the cancel as the other exits do.

### What `Core.tla` leaves out

Writes take no time in the model: a write that stalls is the write limit's
affair (`ServeOptions::write_timeout`), and the idle clock keeps running
through it. The TLS handshake (`accept_tls`), the STARTTLS loop of
`serve_in_region`, and the region wrapper of `connection` are outside it.
The decoder is abstract: `Upgrade::Decoder` and the `fresh` rule are a
stutter, `Fail::Stuck` and `Fail::Refused` are one failure. `on_end`'s own
timers are not modeled. The budget's first charge at `open` is not modeled.
`ObservedCancel` admits a budget end over an observed cancel because
`recharge` renames the end; in Rust that takes a service whose `held()` grows
inside `on_end`, which no service does, so no code changed for it.

## One TCP connection: `Conn.tla`

[`Conn.tla`](verification/lifecycle/tla/Conn.tla) is one `TcpConnection`
from the moment `accept` or `connect` handed it out until its `Conn` is
removed: the smoltcp state, whether smoltcp still names the peer (so a RST
can go out), unread and unacknowledged bytes as booleans, the `Conn` flags
`rst`, `fin`, `shut`, `orphaned`, `retired`, the handle, membership in
`conns`, `orphans` and `time_wait`, what `hold_until_gone` keeps, the
FIN-WAIT-2 orphan timer, and `stopped`.

| Model | Rust |
| --- | --- |
| `Read`, `Write`, `Shutdown`, `Drop`, `ResetHandle`, `WatchReset`, `Hold` | `TcpConnection::poll_read`, `poll_write`, `poll_shutdown`, `Drop`, `reset`; `GoneWatch::reset`, `hold_until_gone` |
| `Orphan`, `AbortSocket`, `CloseIfDrained`, `Remove` | `State::orphan`, `abort`, `close_if_drained`, `remove_conn` |
| `PeerData`, `PeerAck`, `PeerFin`, `PeerRst` | `State::ingress` after smoltcp's `process`: the flags it sets, `held.clear()` and the wake on a RST, `close_if_drained` after every segment |
| `Timeout`, `Egress`, `TimeWaitExpires` | smoltcp's timeout (an abort), the RST going out, TIME-WAIT's expiry |
| `Housekeeping`, `ExpireOrphans`, `GivesUpDue`, `EvictTimeWait` | the orphan loop and TIME-WAIT cap of `State::housekeeping`; `State::expire_orphans` and `gives_up` |
| `Stop` | `Shared::stop` |
| `Gone` | `poll_gone` ready: stopped, removed, `rst`, or `retired` |

What is checked:

- `Bookkeeping`: `orphans` and `time_wait` agree with the `orphaned` and
  `retired` flags and with `conns`; a dropped handle's live connection is an
  orphan; nothing is held or listed once removed.
- `HeldOnlyWhileCounted`, `ResetReleases`, `RetireReleases`: what
  `hold_until_gone` keeps is released by the peer's reset and by retirement,
  and never survives them.
- `StopCleans`: a stopped endpoint has no orphan or TIME-WAIT state, and a
  handle dropped after the stop leaves nothing.
- `FinAfterDrain`: a FIN goes only after every queued byte is acknowledged.
- `DropResetsUnread`, `DropClosesRead`: dropping the handle resets a
  connection with unread bytes and closes one without them, as the doc of
  `TcpConnection` says.
- `OrphanWatched`, `OrphanRemoved`, `HeldReleased`: once the handle is
  dropped, the gone watch is eventually ready, the connection is eventually
  removed, and what it held is eventually released, whatever the peer does.

| Config | Generated | Distinct | Depth | Result |
| --- | ---: | ---: | ---: | --- |
| `Conn.cfg` | 2,934 | 720 | 10 | all five invariants and eight properties hold |
| `Conn_without_orphantimer.cfg` | 2,480 | 580 | 8 | `OrphanRemoved` violated: drop, the FIN acknowledged, the peer sends data forever and never closes |
| `Conn_without_resetunread.cfg` | 39 | 27 | 2 | `DropResetsUnread` violated at the first drop |

The connection checks clean. Two observations, neither a bug:
`hold_until_gone` after the peer's RST keeps the item until the socket is
removed (the race in `listen` between a RST and `accept`), which lasts until
the handle is dropped; and smoltcp's own timeout closes the socket without
waking the gone watch, which the next read or write reports as
`ConnError::TimedOut`.

### What `Conn.tla` leaves out

Segment validation, sequence numbers, windows, out-of-order data and
retransmission are smoltcp's: a peer event in the model is one smoltcp
accepted. Acknowledgements are whole, so a peer that acknowledges a byte at
a time, or holds a zero window and answers every probe, is not in the model;
its orphan would wait as a Linux orphan does in the same case. The handshake,
the listener's backlog and SYN cookies are outside (they are
`verification/tcp-port-zero/` and `verification/mptcp/Listener.tla`'s).
Data arriving for an orphan in FIN-WAIT-2 is buffered and acknowledged until
the orphan timer removes the connection; Linux resets such a connection. The
model keeps the code's behavior.

## Proofs against the Rust: `kani/ServeProof.rs`

[`ServeProof.rs`](verification/lifecycle/kani/ServeProof.rs) is compiled into
`serve` under `cfg(kani)` and calls the production code:

| Harness | Proves |
| --- | --- |
| `timers_are_armed_once_and_the_earliest_is_due` | `arm` keeps one entry per name, at `now + d` for a set timer and none for a cancelled one, leaving other names alone; `due` returns the earliest timer when due and nothing otherwise, over arbitrary names, durations and clock readings |
| `charges_sum_to_the_budget_and_never_pass_its_limit` | `Budget::charge` and `Charge::set` keep `used()` equal to the sum of the charges and never past the limit, refuse a change that would pass it without changing anything, and give a dropped charge back, over every `u8` limit and charge |
| `connections_are_counted_up_to_the_maximum` | `Counted::enter` never counts past the maximum and a dropped count makes room, for maxima up to three |
| `a_wake_is_seen_once_and_not_after_close` | over every sequence of four of wake, poll, take and close, a wake makes the next poll ready, `take` reports it once, and a closed handle ignores wakes |

| Harness | Unwind | Checks | Result |
| --- | ---: | ---: | --- |
| `timers_are_armed_once_and_the_earliest_is_due` | 6 | 1,256 | all pass, 68 s |
| `charges_sum_to_the_budget_and_never_pass_its_limit` | 4 | 429 | all pass, 1.3 s |
| `connections_are_counted_up_to_the_maximum` | 5 | 451 | all pass, 1.7 s |
| `a_wake_is_seen_once_and_not_after_close` | 6 | 813 | all pass, 30 s |

Each run was `cargo kani -p fictionet --harness <name>` under an 8 GB
memory cap; the checks are CBMC's, the unwinding assertions among them, so
every loop bound above covers the loops it unrolls. The connection count
harness keeps its guards in an array: a `Vec` of them passed the cap in the
solver.

## Connection contract

`connection.rs` holds traits and the `ConnError` mapping; it has no state of
its own. Its contract is what `Core.tla`'s waits and `Conn.tla`'s reads and
writes assume: `Ok(0)` on read is the peer's half-close, `poll_gone` is ready
on a reset, and a write after shutdown fails. `Prefixed` in `serve.rs` is
the one implementation here; its cancel-first read is the same rule as
`TcpConnection::poll_read`'s and was not modeled separately.
