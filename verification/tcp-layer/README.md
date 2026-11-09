# The TCP layer, as the layer above sees it

[`Layer.tla`](Layer.tla) models `TcpLayer`
([`tcp/engine.rs`](../../src/stdlib/network/tcp/engine.rs)) through the
`Tcp` port of [`transport.rs`](../../src/stdlib/network/transport.rs). The
host above it is a process that only sends `TcpControl` commands and child
commands, and only reads what comes up: children opening, `TcpNotice`, and
each child's stream. That is the boundary a replacement TCP implements. The
model checks that admission, reset and retirement work through it alone.

## What it covers

Connections are of two kinds. `Accepted` ones come from peers to one
listening port: SYN, the final ACK the listener's answer takes or refuses, a
RST or the handshake timer in SYN-RECEIVED, the backlog, and `offer`, which
opens a child for each `TcpControl::Accept`. `Connected` ones are
`TcpControl::Connect`: the child opens at once, carries bytes only after the
SYN-ACK, and is closed by `connect_failed` if the handshake fails.

For each connection the model follows the smoltcp state, the `Conn` flags
(`rst`, `retired`, `released`, `orphaned`), what `TcpControl::Hold` keeps,
whether `TcpNotice::Gone` went up, and the timers the code arms: the
handshake timer, smoltcp's timeout and keepalive, the orphan timer in
FIN-WAIT-2, and TIME-WAIT's end. The host may hold, abort, close or end a
child, read, set keepalives, and accept, at any time. The peer may send
data, a FIN, the ACK of this side's FIN, or a RST. smoltcp may time out. The
layer's own steps are fair: refresh, housekeeping, the RST going out,
TIME-WAIT's end, and the orphan timer. The host and the peer owe nothing.

The header of `Layer.tla` maps each action to its function and its lines in
`engine.rs` at `a96a0cae9`.

## Properties

Every property has a configuration that keeps one rule as it was, or
weakens it, and must fail on that property. The rule each control changes
is a constant of the model, `TRUE` for the code.

| Property | What it says | Control | What the control changes |
| --- | --- | --- | --- |
| `ChildAfterHandshake` | an accepted connection's child opens only after the listener's answer took the final ACK | `Layer_without_offerready` | `offer` also takes a connection still in SYN-RECEIVED |
| `OpenedWithinAccepts` | never more accepted children than `Accept`s | `Layer_without_countaccepts` | `offer` does not use up an `Accept` |
| `BacklogBound` | finished handshakes waiting for accept stay within the backlog | `Layer_without_boundbacklog` | a SYN starts a connection however many wait |
| `BytesAfterHandshake` | a child carries bytes and gets credit only once its socket finished the handshake | `Layer_without_liveafterhandshake` | a connecting child is live from the start |
| `HeldOnlyUntilGone` | what `Hold` kept is never kept while the connection is gone | `Layer_without_goneguards`, `Layer_without_resetreleases` | `Hold` asks only `retired`; `abort` keeps what was held |
| `CountedUntilGone` | what `Hold` kept is kept until the connection is gone, through every closing state, whatever the child does | `Layer_without_countuntilgone` | closing the child lets go of what was held |
| `GoneWhateverTheChild` | a connection in TIME-WAIT or closed is eventually gone and lets go, whether or not the child is ever closed | `Layer_without_releaseopen` | no release for an open child, as before `773c5c1a3` |
| `ReleaseSaid` | whenever what was held is let go, `Gone` goes up | `Layer_without_saygone` | refresh lets go without `Gone` |
| `SaidMeansReleased` | once `Gone` went up, nothing is held | `Layer_without_goneguards_said` | `Hold` asks only `retired` |
| `GoneIsSaid` | every child whose connection is gone was told so, so the port alone says what `gone()` says | `Layer_without_saygone_notice`, `Layer_without_offersaysgone` | refresh lets go without `Gone`; `offer` opens a child on a reset connection without `Gone` |
| `AbortAfterGoneIsNothing` | `Abort` on a connection that is gone changes nothing: no RST | `Layer_without_goneguards_abort` | `Abort` asks only `retired` |
| `StopHoldsNothing` | a stopped endpoint holds nothing | `Layer_without_stopreleases` | `stop` keeps what was held |
| `NoTimerWhenGone` | a retired, released or removed connection has no timer left but TIME-WAIT's end | `Layer_without_clearorphantimer` | `expire_orphans` leaves the orphan timer of a connection that left FIN-WAIT-2 |

How the properties answer what the layer must do:

- Children open only after the accepted handshake: `ChildAfterHandshake`,
  `OpenedWithinAccepts`, `BacklogBound`, `BytesAfterHandshake`.
- A connection's slot counts until the transport retires it, closing states
  included, never tied to the child's lifetime: `CountedUntilGone`,
  `HeldOnlyUntilGone`, `GoneWhateverTheChild`.
- Reset and admission go through the boundary: the model's host has no
  other way in. Admission is `Accept` against the backlog; reset is `Abort`
  (also the path of `AbortPeers`, a child's `Reset`, and ICMP errors, which
  call the same `abort`). `ReleaseSaid`, `SaidMeansReleased` and
  `GoneIsSaid` say a host that reads only `TcpNotice::Gone` knows exactly
  when a connection stops counting. `AbortAfterGoneIsNothing` says a late
  `Abort` is harmless.
- Timers and work of a retired connection never fire: `NoTimerWhenGone`
  for timers. For work: once gone, `Hold` drops its item at once
  (`HeldOnlyUntilGone`), `Abort` does nothing
  (`AbortAfterGoneIsNothing`), `KeepAlive` is refused for an orphan, and a
  retired connection's child is unmapped, so nothing comes up for it.

## Results

TLC 2.19, `-workers 4`. Both configurations of the code complete with an
empty queue; every control fails on the property it names.

| Config | Generated | Distinct | Result |
| --- | ---: | ---: | --- |
| `Layer_base` (one connection each way, backlog 1, one `Accept`) | 484,741 | 63,216 | every property holds |
| `Layer_admission` (two connections from peers, backlog 1, two `Accept`s) | 594,433 | 80,400 | every property holds |
| `Layer_without_offerready` | 91 | 51 | `ChildAfterHandshake`: SYN, then `offer` |
| `Layer_without_countaccepts` | 3,310 | 1,164 | `OpenedWithinAccepts` |
| `Layer_without_boundbacklog` | 309 | 166 | `BacklogBound`: two handshakes finish on a backlog of one |
| `Layer_without_liveafterhandshake` | 22 | 16 | `BytesAfterHandshake` |
| `Layer_without_goneguards` | 150 | 109 | `HeldOnlyUntilGone` |
| `Layer_without_resetreleases` | 227 | 137 | `HeldOnlyUntilGone`: connect, hold, abort |
| `Layer_without_countuntilgone` | 303 | 173 | `CountedUntilGone` |
| `Layer_without_releaseopen` | 285,386 | 35,262 | `GoneWhateverTheChild` |
| `Layer_without_saygone` | 1,511 | 659 | `ReleaseSaid`: connect, SYN-ACK, timeout, release |
| `Layer_without_goneguards_said` | 128 | 90 | `SaidMeansReleased`: a `Hold` after the stop |
| `Layer_without_saygone_notice` | 827 | 380 | `GoneIsSaid` |
| `Layer_without_offersaysgone` | 727 | 377 | `GoneIsSaid`: SYN, final ACK, the peer's RST, `offer` |
| `Layer_without_goneguards_abort` | 219 | 145 | `AbortAfterGoneIsNothing`: an `Abort` after the stop |
| `Layer_without_stopreleases` | 278 | 165 | `StopHoldsNothing` |
| `Layer_without_clearorphantimer` | 10,323 | 3,130 | `NoTimerWhenGone` |

## What it found

Three bugs, each fixed in `tcp/engine.rs` with a test in `tcp/tests.rs`
that drives the layer through its port alone and failed before the fix:

- `773c5c1a3`: a connection that timed out or reached TIME-WAIT while the
  layer above still held its child kept what `Hold` gave it, said no `Gone`,
  and left its gone watch pending until the child closed. The same held for
  a `Hold` after the peer's reset, for a stopped endpoint's open children,
  and `Abort` on an open child in TIME-WAIT sent a RST. Tests:
  `a_connection_that_times_out_is_gone_with_its_child_open`,
  `an_open_child_in_time_wait_lets_go_of_what_it_held`,
  `a_hold_after_the_peers_reset_is_let_go_at_once`,
  `a_stop_lets_go_of_what_open_children_held`,
  `an_abort_after_time_wait_sends_nothing`.
- `2124865df`: `abort` said `Gone` but kept what `Hold` gave it until the
  child closed, so `GoneWatch::reset`, `Abort`, `AbortPeers` and ICMP errors
  left a limit counting a connection already reported gone. Found as a
  violation of `HeldOnlyUntilGone`. Test:
  `an_abort_lets_go_of_what_the_connection_held`.
- `856e1971f`: a connection the peer reset while it waited in the backlog
  opened a child, gone from the start, with no `Gone`; the host heard of it
  only once it closed the child. Found as a violation of `GoneIsSaid`.
  Test: `a_connection_reset_before_it_is_accepted_opens_gone`.

`a_closed_childs_connection_counts_until_it_retires` (`e152e89a8`) checks
the other half of the counting rule in the code: a closed child's
connection still counts in FIN-WAIT-2 and is let go at TIME-WAIT.

## The boundary in the code

The tests in `mod layer` of `tcp/tests.rs` run `TcpLayer` under a `Driver`
over `IpLayer` with no runtime, and reach it only through the `Tcp` port:
`Listen`, `Accept`, `Connect`, `Hold` and `Abort` down, children,
`TcpNotice` and stream events up.

`tcp::Endpoint`, the async handles in `tcp.rs` that the world's hosts use
today, sends every reset (`Abort`, `AbortPeers`) and every admission
(`Listen`, `Accept`, `Backlog`, `Answer`) as a `TcpControl`. It still reads
the engine directly in four places, which the world integration replaces
when hosts attach to the port:

- `Endpoint::limit_isolated_peers` sets the per-peer SYN limits on the
  engine; `TcpControl` has no command for it.
- `Endpoint::abort_peers` filters peers with `TcpLayer::peers` before it
  sends `AbortPeers`, because the world passes a borrowed predicate.
- `poll_gone` reads `TcpLayer::gone`. `GoneIsSaid` shows the `Gone` notices
  carry the same answer.
- The connect, read, write and end verdicts read the socket's state.

## What it leaves out

Segment validation, sequence numbers, windows and retransmission are
smoltcp's: a peer event is one smoltcp accepted. Bytes are booleans. SYN
cookies, the per-peer limit, the listener's answer to a SYN, MPTCP and
`Unlisten` decide whether a handshake starts, not what follows, and are
left out (`verification/tcp-port-zero` and `verification/mptcp` cover the
listener). `AbortPeers` and ICMP errors are the same `abort` as `Abort`.
Both configurations are bounded: one connection of each kind, or two from
peers, and at most two `Accept`s.

## Running

From this directory, with the JDK and `tla2tools.jar` of
`~/.cache/adorably-fv`:

```sh
java -Xmx6g -cp ~/.cache/adorably-fv/tla2tools.jar tlc2.TLC -workers 4 \
  -metadir "$STATES/Layer_base" -config Layer_base.cfg Layer.tla
```

Each control's first line, `\* expect violation: <Property>`, names the
property it must violate. A control that passes, or fails on a parse error
or another property, is a failed run. Every configuration finishes in
seconds.

The tests:

```sh
cargo test -p fictionet --lib -- network::tcp::engine::tests::layer::
```
