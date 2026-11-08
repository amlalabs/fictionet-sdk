# Connection lifecycle: what was modeled and found

This pass covers the `Connection` contract in
`src/stdlib/network/connection.rs` and one TCP connection's life in
`src/stdlib/network/tcp/engine.rs` (close, orphan, half-close, reset, unread
data). The model is under `verification/lifecycle/`, with the commands to run
it in its [README](README.md). The TCP connection's life checks clean; no
code in `tcp.rs` or `connection.rs` changed for it.

## The serving engine's model and proofs, retired

This pass also modeled the serving engine in `src/stdlib/services/serve.rs`
(`Core.tla`, four configurations) and proved its pure parts with Kani
(`kani/ServeProof.rs`). It found two bugs there, the idle clock running
under deferred work and a cancelled region handing a connection off, each
fixed with a test. The engine has since been deleted: every service runs as
a layer stack on the stream and datagram runners in
`src/stdlib/services/stack/`. `Core.tla` and its configurations went with
the code they modeled, and so did `ServeProof.rs`; git history keeps both.
Their obligations now live with the code that replaced the engine:

| Engine obligation | Where it is checked now |
| --- | --- |
| `Core.tla`'s idle, write and end rules (`IdleNeedsQuiet`, `WritableEndHeard`, `EndingTerminates`) | `verification/layer-runtime/tla/StreamRunner.tla`: the idle clock restarts when the runner begins to wait and counts only while it waits with no work running (`StreamRunner_without_restartidleonwait.cfg`, `StreamRunner_without_idleresetonread.cfg`), the write timeout, and the end after every byte is written |
| Bug 1, the idle clock under deferred work | the runner's `waiting` excludes running work; `stack_harness::the_idle_clock_restarts_after_work` in `tests/it` |
| Bug 2, a cancelled region handing a connection off (`ObservedCancel`) | the stream and datagram runners return a cancel that landed while the stack ran unless the stack gave up; `stack_cancellation::a_cancelled_region_hands_no_connection_off` in `tests/it`. The runner models leave region cancellation out, as `Core.tla`'s region wrapper was left out |
| `timers_are_armed_once_and_the_earliest_is_due` (`arm`, `due`) | the timer harnesses in `verification/layer/kani/mod.rs` over `layer::Timers`, which every layer keeps its timers in: arming a name again moves it, `next` is the earliest with ties to the first armed, `get` and `len` agree, and `cancel`, `fire` and `retain` touch one name |
| `charges_sum_to_the_budget_and_never_pass_its_limit` | moved to `verification/layer/kani/mod.rs`, over the same `Budget` and `Charge` |
| `connections_are_counted_up_to_the_maximum` | moved to `verification/layer-runtime/kani/admission.rs`, over `services::stack::Counted`, which port servers count connections with |
| `a_wake_is_seen_once_and_not_after_close` (`WakeHandle`) | `WakeHandle` is gone: a stack waits for something from outside as work, which the runner polls with `Jobs::poll`. That work is never polled once its owner ends: `verification/layer/tla/Children.tla` (`NoCancelledPoll`, which `Children_without_workownership.cfg` breaks, and `CancelledWorkLeaves`) and `verification/runtime/tla/JobContext.tla`, and `cancelled_work_drops_before_another_poll` in `stack/job.rs`. A Kani harness over `Jobs::poll` was tried; Kani 0.68 stops with an internal error in its intrinsics pass on the region code `Jobs::poll` reaches, so it is not kept |

## One TCP connection: `Conn.tla`

[`Conn.tla`](tla/Conn.tla) is one `TcpConnection`
from the moment `accept` or `connect` handed it out until its `Conn` is
removed: the smoltcp state, whether smoltcp still names the peer (so a RST
can go out), unread and unacknowledged bytes as booleans, the `Conn` flags
`rst`, `fin`, `shut`, `orphaned`, `retired`, the handle, membership in
`conns`, `orphans` and `time_wait`, what `hold_until_gone` keeps, the
FIN-WAIT-2 orphan timer, and `stopped`.

The connection's state now lives in `TcpLayer`
(`src/stdlib/network/tcp/engine.rs`), and the handles in `tcp.rs` reach it
only through the layer's commands and events. The model's actions map onto
both:

World admission and service limits use the public `transport::Retirement`
boundary. `GoneWatch` delegates that boundary to the same operations below;
the transport holds admission guards independently of application lifetime.
The custom transport admission test in `world/net/hosts.rs` checks refusal,
reset, and releasing the peer count at retirement without a TCP application.

| Model | Rust |
| --- | --- |
| `Read`, `Write`, `Shutdown` | `TcpConnection::poll_read` (credit for the child, then its data), `poll_write` (a write within the send buffer's credit), `poll_shutdown` (the child's `End`) |
| `Drop`, `ResetHandle`, `WatchReset`, `Hold` | `TcpConnection`'s `Drop` (`TcpControl::Abort` first if bytes that came up are unread, then closing the child), `reset` (`Abort`, then the drop); `GoneWatch::reset` (`Abort`) and `hold_until_gone` (`TcpControl::Hold`) |
| `Orphan`, `AbortSocket`, `CloseIfDrained`, `Remove` | `TcpLayer::orphan` (closing a child), `abort`, `close_if_drained`, `remove_conn` |
| `PeerData`, `PeerAck`, `PeerFin`, `PeerRst` | `TcpLayer::ingress` after smoltcp's `process`: the flags it sets, `held.clear()` and `TcpNotice::Gone` on a RST, `close_if_drained` after every segment |
| `Timeout`, `Egress`, `TimeWaitExpires` | smoltcp's timeout (an abort), the RST going out, TIME-WAIT's expiry |
| `Housekeeping`, `ExpireOrphans`, `GivesUpDue`, `EvictTimeWait` | the orphan loop and TIME-WAIT cap of `TcpLayer::housekeeping`; `TcpLayer::expire_orphans` and `gives_up` |
| `Stop` | `Shared::stop`, which stops the layer (`TcpLayer::stop`) |
| `Gone` | `poll_gone` ready: stopped, removed, `rst`, or `retired`, as `TcpLayer::gone` reads it; `TcpNotice::Gone` wakes the watches |

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

## Connection contract

`connection.rs` holds traits, the `ConnError` mapping and the `ConnInfo`
a stack factory is given; it has no state of its own. Its contract is what
`Conn.tla`'s reads and writes and the stream runner's model assume: `Ok(0)`
on read is the peer's half-close, `poll_gone` is ready on a reset, and a
write after shutdown fails.
