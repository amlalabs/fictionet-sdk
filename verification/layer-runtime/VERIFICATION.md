# Layer runtime: what was modeled, proved and found

This pass covers the code of branch `comp/b3-ports`: `layer::Framed`
(`src/stdlib/layer/framed.rs`), the runners `services::stack::stream` and
`services::stack::datagrams` (then `src/stdlib/services/stack.rs`) behind
`Host::tcp_stack` and `Host::udp_stack`, the Nuclear PLC stack
(`demos/nuclear/world/src/plc.rs`) and the Search NTP datagram layer
(`demos/search/world/src/ntp.rs`). How to run everything is in the
[README](README.md).

The pass was then merged into `comp/foundation` (commit `9e5ac4aa1`),
where the single-file runner had been split into `stack/live.rs` (the
stream runner, `Live`), `stack/open.rs` (`Opened`, the same runner for a
stack with a byte stream above it), `stack/job.rs` (the stack's work)
and `stack/mod.rs` (`stream`, `datagrams`). The split had lost the fixes
of Bugs 2 and 3, and the stream runner also no longer restarted its idle
clock on a read; they were ported to the new code, not copied from the
old (commits `33fd898e0` and `6aa68ae5f`), and both models were updated
to the new loops and rerun at code revision `6aa68ae5f`. The runner
tables below now record a subsequent rerun with explicit whole-layer
completion and bounded datagram input retention in `090aba987`. The historical
reproductions remain below. The buffer fix merged as it was.

Five bugs were found, each confirmed by a test that failed on the code
before its fix:

1. `Framed` charged its decoder buffer less than the buffer grows to.
2. `stream` ended idle input at once after a time it was not reading.
3. `datagrams` dropped what a stack still had to send when its socket
   closed, if the stack needed more than 64 rounds to send it.
4. `Jobs::poll` polled work whose region failed for ever (found later,
   below).
5. A cancel that landed while the stack ran lost to how it ended (found
   later, below).

## Bug 1: `Framed` charged half its buffer

`Framed::charge` charged `max(limit, allocated) + held` before each push,
on the comment "the buffer never grows past its limit". The codec's
`Buffer` keeps a consumed prefix until it is at least as long as the
unread suffix, so its storage grows to twice its limit (proved in
`verification/codec/kani/buffer.rs`). And `Stream::push` raises the limit
to the decoder's capacity before it pushes, after `Framed` read the old
limit. In both cases the connection held bytes the budget was not charged
for, until its next read, and the limit could be passed.

It was found while writing the charge property for Kani, by reading
`Buffer`'s growth rule against `Framed::charge`; the first Kani harness for
it ran out of memory, so the tests below confirmed it, and the Kani charge
harnesses (which fail on the old code, see the mutations) came after.

Reproduction, in `src/stdlib/layer/framed.rs`:

- `the_budget_covers_everything_the_buffer_grows_to`: a 12-byte Modbus
  frame and the first 248 bytes of a 260-byte one fill the 260-byte limit;
  the small frame is answered; the last 12 bytes make the buffer grow.
  Before the fix: "the budget is charged 260 for a buffer of 520".
- `the_budget_covers_a_capacity_the_decoder_raised`: a decoder that widens
  from 4 to 16 bytes after its first item. Before the fix: "the budget is
  charged 4 for a buffer of 16".

Fix (commit `b006ab039`): charge twice the larger of the buffer's limit and
the decoder's capacity, or what is allocated if that is more, plus the
decoder's held state.

## Bug 2: the stream runner's idle clock ran while it did not read

`StreamLimits::idle` promises to end the input of a connection "that sends
nothing for this long while the runner waits for it with nothing to
write". The runner restarted `idle_from` only on bytes read or written.
While the stack refused input (it held input `Blocked`), or the runner held
output, or a shutdown was pending, the runner did not read, yet the clock
kept counting from the last read. Once the runner waited again the idle
limit could fire at once, with the peer given no time. This is the bug
`serve` had and fixed (`verification/lifecycle/VERIFICATION.md`, Bug 1).

TLC found it as a violation of `IdleNeedsQuiet` in
`StreamRunner_without_restartidleonwait.cfg` (the code as it was). The
shortest trace, 12 states: the stack ends its direction early; the
shutdown pends for two ticks while the runner holds the End; the shutdown
completes with no byte written; the next check finds the runner waiting
with `idle_from` still at zero, and ends the input at once.

Reproduction: `the_idle_clock_restarts_when_the_stack_takes_input_again`
in `src/stdlib/services/stack/tests.rs`, over the simulated TCP stack. A
stack takes its first byte, then refuses input for 1 s on its own timer;
the client's second byte waits with the runner; the idle limit is 300 ms.
Before the fix the stack heard `Ended` "0ns after the stack took input
again".

Fix (commit `1a183c83e`): the runner notes whether it waited at its last
check, and restarts `idle_from` when waiting resumes.

On the merged foundation. `Live::step` restarted `idle_from` at every
settled check where it was not waiting, but not on a read, and not when a
sleep for the stack's own timer woke it: progress goes straight to the
next round, so a check that saw the runner blocked could be the last one
before a long pause. The test above failed there ("input ended 0ns after
the stack took input again"), and so did a new one,
`the_idle_clock_restarts_when_the_client_speaks`: a client that writes a
byte, waits 250 ms and writes another, to a stack that writes nothing back,
under a 300 ms limit, had its input ended "300ms after the first bytes".
The port (commit `6aa68ae5f`) restarts the clock on bytes read
(now `live.rs:216`) and written (`live.rs:329`), and when waiting begins
(`was_waiting`, `live.rs:355-358`); both tests pass.

## Bug 3: a closed socket lost the stack's last datagrams

`datagrams` promises that when the socket closes "the stack hears
`DatagramEvent::Ended` and sends what it still has". The loop returned on
`socket_closed && input.is_none()` before looking at whether `settle` had
settled; `settle` gives up after `FAIR` (64) rounds that each moved
something, so a stack that sends its last datagrams one per step lost all
but the first 64 rounds' worth.

TLC found it as a violation of `CloseFlushes` in
`DatagramRunner_without_settlebeforeclose.cfg` (the code as it was), with
`Fair = 2` and a backlog of 3: Ended, two rounds that each send one, the
runner returns with one queued and one owed.

Reproduction: `a_closed_socket_gets_everything_the_stack_still_has` in
`src/stdlib/services/stack/tests.rs`: a stack that owes 200 goodbyes when
its socket closes, through one slot. Before the fix 63 were sent.

Fix (commit `1a183c83e`): return on a closed socket only once settled.

On the merged foundation, `run_datagrams` returned on
`socket_closed && input.is_none() && jobs.is_empty()` after its `FAIR`
rounds, settled or not, and the test failed again (64 sent, not 200).
The port (commit `33fd898e0`) adds `settled` to that condition
(now `stack/mod.rs:408`); the test passes.

## The stream runner: `StreamRunner.tla`

[`tla/StreamRunner.tla`](tla/StreamRunner.tla) is one connection under
`stream` (`src/stdlib/services/stack/mod.rs`) and `Live`
(`src/stdlib/services/stack/live.rs`), one round at a time. It was
rewritten for the split runner: `Live::step` reads first, offers the
stack its input, runs it and writes in the same round, and checks the
limits only when a round moved nothing; `stream` returns when `step` waits
and the run is finished, or the peer is gone.

| Model | Rust (`src/stdlib/services/stack/live.rs` unless named) |
| --- | --- |
| `Round` | one round of `Live::step`: read, deliver `Written`, offer held input, call `Driver::run`, and send output; reset or transport failure ends the run |
| `SendLoop` | `Live::step`'s `send_below` sink: failed or partial writes retain their suffix; shutdown follows prior writes |
| `Check` | the settled part of `Live::step`: write timeout, idle timing and sleep; `stream` then checks `Live::finished` and `poll_gone` |
| `EndBroken` | `Live::broken` offers a reset and drains remaining upward events |
| `Tick`, `PeerReset`, `Gone` | time passing while the runner waits; peer reset; `stream` noticing `poll_gone` |

A round from the wait runs only if something can move then: the peer
sent, the transport takes a write, the peer is gone, or the sleep is due.

The model's line references were written against commit `df01d0a5f` and
now name the lines of `e2858ccc4`; the code they stand for is unchanged
except where this file says so. After the `090aba987` reruns the runner
gained, in `f51fa312c` and `00e3c371b`, a `jobs.close_completed()` call
at the top of each round (`live.rs:226-228`) and the cancel-wins checks
of `stream` (`mod.rs:274-276`, `281-283`). The modeled stack asks for no
work, and cancellation is outside the model, so neither changes a modeled
round; the read, report, offer, run, send and limit steps of `Live::step`
are the same code at new line numbers. `Live::finished` also requires
`unreported == 0` (`live.rs:146`), which the model does not state: its
stack is `Framed`, which always takes a `Written` (`framed.rs:185`), so a
settled round has nothing unreported. A stack that blocks a `Written`
(none of the stacks here do) would keep `unreported` across a settled
round, and the model does not explore that.

The stack is abstract: an echo with room for one byte, which moves input to
output when it runs, asks to end its direction when it heard the end of
its input or early, refuses input for three ticks on a timer of its own,
and may ask for a reset. Its commands come out writes first, then reset or
end, as `Framed::take_command` (`framed.rs:251-263`) orders them; its
output after its End is refused, as `Framed::on_command` does. It asks for
no work, so the runner's `jobs` stay empty. The peer sends up to two
bytes, may end its direction, may reset, and may stop reading for good; a
write the transport is ready for takes at least one byte. A read's charge
may not fit the budget. Idle and write limits are two ticks each.

Properties:

- `ReadOnlyWhenTaken`: the runner reads only while the stack has taken all
  it read before, and its input is not over.
- `InputKept`: every byte read is taken by the stack, held for it, or
  refused by it as closed.
- `WrittenOnce`: each byte the transport took is reported once as
  `StreamEvent::Written`.
- `EndAfterWrites`: the shutdown goes out after every byte the stack wrote.
- `IdleNeedsQuiet`: the idle limit ends input only after the peer had the
  whole idle time while the runner waited for it with nothing to write.
- `StallNeedsNoProgress`: the write limit gives up only after the runner
  held output the transport took nothing of for the whole limit.
- `ResetHeardOnBreak`: a broken connection (failed read, write, shutdown,
  peer reset, budget) is offered to the stack as one `StreamEvent::Reset`;
  any other end offers none.
- `EndsAreEarned`: `Finished` and `Idle` mean the stack ended its
  direction, `Idle` only after the idle limit fired, `Reset` only after
  the stack's reset.
- `FinishNeedsInput`: for the modeled layer, which does not declare its
  whole lifetime terminal, `Finished` and `Idle` also mean input ended.
- `Terminates`: with both limits set, every connection ends.

| Config | Rule turned off | Generated | Distinct | Result |
| --- | --- | ---: | ---: | --- |
| `StreamRunner_base.cfg` | none | 27,865,057 | 185,569 | all invariants and `Terminates` hold, 7 min 6 s |
| `StreamRunner_halfclose.cfg` | none | 27,865,057 | 185,569 | `FinishNeedsInput` holds, 4 min 18 s |
| `StreamRunner_without_finishinput.cfg` | finish after write shutdown alone | 55,335 | 898 | `FinishNeedsInput` violated |
| `_without_readonlywhentaken` | read without `input.is_none()` | 53,515 | 885 | `ReadOnlyWhenTaken` violated |
| `_without_keeppartialrest` | a `Partial` rest dropped | 5,736 | 156 | `InputKept` violated |
| `_without_reportonce` | `unreported` not cleared once reported | 15,304 | 393 | `WrittenOnce` violated |
| `_without_writebeforeend` | the stack's End before its writes | 3,416 | 78 | `EndAfterWrites` violated |
| `_without_idleresetonread` | no `idle_from = now` on a read | 2,789,495 | 19,980 | `IdleNeedsQuiet` violated |
| `_without_restartidleonwait` | no restart when waiting begins | 2,549,268 | 18,646 | `IdleNeedsQuiet` violated |
| `_without_stallresetonprogress` | no `stalled_since = None` on bytes written | 3,806,460 | 27,185 | `StallNeedsNoProgress` violated |
| `_without_resetonbreak` | `broken` offers no reset | 528 | 26 | `ResetHeardOnBreak` violated |
| `_without_writetimeout` | `write_timeout: None` | 3,032,080 | 23,081 | `Terminates` violated: a peer that stopped reading holds the runner forever |

Each was rerun with `-workers 4 -Xmx6g` using the JDK in
`~/.cache/adorably-fv/jdk`, under an 8 GiB systemd memory cap and no
swap. State directories were on the home volume. TLC
stops at the first violation, so the state counts of a violated
configuration vary with the worker schedule between runs. On November 9,
2026, at `e2858ccc4` (the model's comments pointed at that commit's
lines, with no change to any action, property or configuration), the six
short mutations were rerun with `-workers 2 -Xmx2g` and each violated the
property its row names: `_without_finishinput` (61,160 generated, 976
distinct), `_without_readonlywhentaken` (52,869, 862),
`_without_keeppartialrest` (5,730, 150), `_without_reportonce` (15,043,
359), `_without_writebeforeend` (3,358, 65), `_without_resetonbreak`
(456, 20). The same day's run of the whole tree on `main` at that commit
reproduced `_without_idleresetonread` (`IdleNeedsQuiet`, 2,842,492
generated, 20,179 distinct), `_without_restartidleonwait`
(`IdleNeedsQuiet`, 2,772,001, 19,658) and `_without_stallresetonprogress`
(`StallNeedsNoProgress`, 3,815,554, 26,903); `StreamRunner_base.cfg`,
`StreamRunner_halfclose.cfg` and `_without_writetimeout.cfg` were still
running when this was written. The `_without_restartidleonwait` trace is
the one of Bug 2: the stack ends its direction at once, the shutdown pends
for two ticks while the runner holds the End, it completes with no byte
written, and the next check ends the input with `idle_from` still at zero.

The former half-close counterexample is now a passing base configuration.
`Live::finished` requires input to finish or the layer to declare its whole
lifetime terminal, in addition to write shutdown, drained output, delivered
write completions and no running jobs. Ending writes by itself is not a
terminal declaration. The model's abstract stack never declares itself
terminal, so `FinishNeedsInputOver = TRUE` corresponds to production.
`StreamRunner_without_finishinput.cfg` keeps the old failing behavior as
a mutation, replacing the former proposed-fix configuration.

`ending_writes_keeps_reading_the_peers_response` exercises the actual
runner over simulated TCP: the peer waits for EOF, then sends its response
and ends input; the layer must receive that complete response. HTTP's
closed phase and a tunnel application's released connection explicitly
mark the whole application terminal. Those application-specific states
are not modeled here. TLS and composition wrappers forward terminal
state while the runner still requires their output to drain.

At `f51fa312c`, completed jobs retain their ownership lease while spawned
producer tasks remain active; returning a streamed response must not cancel
its producer. Whole-stack termination or owner invalidation cancels them.
`b0fb45ee2` makes enclosing regions count descendant tasks, so dropping an
opened stack initiates cancellation without blocking its destructor and the
enclosing region joins the work before returning. The 19 stack tests pass,
including pending-job cancellation with a live sibling, producer survival
after job completion, dropped-opened-stack joining, and a real async HTTP
child over TCP with a two-byte command window. Region interleavings and the
unsupported direct Mutex Kani attempt are recorded in
[`verification/runtime/VERIFICATION.md`](../runtime/VERIFICATION.md).

What it leaves out: bytes are counts and the stack's room is one byte, so
chunk boundaries and data values are not modeled (`Framed`'s Kani proofs
cover those). The stack's work, cancellation of the region, the panic
note, the first charge of the read buffer, and the `ROUNDS` yield (which
only lets other tasks run) are not modeled. A read that fails while the
peer has not reset is one case with the peer's reset. Time moves only
while the runner waits, so a stack that keeps moving for ever without
settling is outside it. The stack is well behaved; a stack that never
ends its direction after its input ended is not modeled, and `Terminates`
would not hold for it. `Opened`, which runs `Live` with no limits under a
`Connection`, is covered by `verification/tls/tla/Write.tla` for its
writes, not here.

## The datagram runner: `DatagramRunner.tla`

[`tla/DatagramRunner.tla`](tla/DatagramRunner.tla) is one socket under
`datagrams` (`run_datagrams` in `src/stdlib/services/stack/mod.rs`).
On the merged foundation a round runs the stack before it sends, where the
old `settle` sent first; the model's round follows the new order.

| Model | Rust (`src/stdlib/services/stack/mod.rs`) |
| --- | --- |
| `SettleRound` | one `run_datagrams` round: offer held input, call `Driver::run`, then `send_below` |
| `Drain` | the `send_below` sink: send complete datagrams, accept End, refuse later output |
| `AfterSettle` | return on End or on a closed socket only after settling; otherwise yield and continue |
| `Wait` | receive only with no held input; drop a refused backing reservation and continue; wake for the next layer deadline |
| `Arrive`, `Close`, `Tick` | the environment |

The stack has the shape of `TimeServer`: at most one reply per datagram it
takes; and also a timer that sends one datagram when it fires (and may
hold input refused until then), a choice to close the socket itself with
one more datagram queued after the End, and a backlog of three replies it
sends one per step after the socket closes. It asks for no work, so `jobs`
stay empty. Three datagrams arrive; `Fair` is 2. Each receive may fail its
backing reservation; that input joins `dropped`, and the same conversation
continues. `TimeServer` also
refuses the next datagram while a reply waits to be taken, and the model
writes that rule down, but under this runner it never applies: the sink
takes every `Send` at once (`mod.rs:405-409`), so the stack's output
queue is empty whenever a round starts. The only refusal TLC explores is
the pause; the refusal while a reply waits is proved on the real server
by the Kani harness `one_conversation_answers_each_request_in_turn`.

The model's line references were written against `df01d0a5f`, pointed
at `e2858ccc4`, and now name the lines after the review fixes' budget
drop. Since the `090aba987` reruns the loop gained
`jobs.close_completed()` calls (`mod.rs:379`, `428`, `452`) and the
cancel-wins check before a return (`mod.rs:430-432`); with no work and
no cancellation in the model, the rounds it describes are unchanged.

Properties: `InOrderOnce` (one conversation took every datagram the socket
got, in order, each once, besides budget drops, the one held and those queued);
`SentInOrder` (each datagram the stack hands down goes out at once, once,
in order); `NothingAfterEnd`; `CloseFlushes` (when the socket closes the
stack hears `Ended` and sends all it has before the runner returns);
`TimerFires` (a timer goes off with no datagram coming); `CloseEnds` (a
closed socket ends the run); `ReturnHasReason` (only an application end or
socket close returns from the conversation).

| Config | Rule turned off | Generated | Distinct | Result |
| --- | --- | ---: | ---: | --- |
| `DatagramRunner_base.cfg` | none | 56,180 | 9,828 | every property holds |
| `_without_receiveonlywhentaken` | receive while a datagram is held | 6,038 | 1,198 | `InOrderOnce` violated |
| `_without_oneconversation` | a fresh stack per datagram | 1,593 | 322 | `InOrderOnce` violated |
| `_without_sendeachdatagram` | a send taken without `send_to` | 64 | 28 | `SentInOrder` violated |
| `_without_endclosesoutput` | output after End still sent | 179 | 48 | `NothingAfterEnd` violated |
| `_without_settlebeforeclose` | returning before settling | 1,164 | 221 | `CloseFlushes` violated |
| `_without_deadlineinwait` | the wait ignores the stack's deadline | 46,426 | 8,650 | `TimerFires` violated |
| `_without_returnonclose` | no return on a closed socket | 58,988 | 10,332 | `CloseEnds` violated |
| `_without_droponbudgetmiss` | a budget miss returns while the socket is open | 87 | 22 | `ReturnHasReason` violated |

The table's counts are for the model with the budget drop. Before that
action was added, the eight earlier configurations were rerun on
November 9, 2026, at `e2858ccc4`, after the model's comments were pointed
at that commit's lines (no action, property or configuration changed),
with `-workers 2 -Xmx2g`: the base configuration passed with 32,196
generated and 5,787 distinct states, `_without_deadlineinwait` and
`_without_returnonclose` violated their temporal properties (25,674/4,957
and 33,678/6,053), and the five
invariant mutations violated the invariant their row names (at counts
that vary with the worker schedule: 4,350/834, 1,385/274, 43/24, 147/43
and 1,133/210). The run of the whole tree on `main` at the same commit
gave the same verdicts.

What it leaves out: datagram contents and addresses (each datagram is its
number; that answers go to the address the stack names is a Kani property
of the time server below), the socket dropping datagrams it cannot queue,
the stack's work, and cancellation. The runner now takes an explicit
budget and charges the full capacity of each transport-owned receive
allocation before retaining it; socket allocations themselves remain the
transport's responsibility. The model covers the refusal decision, not
byte arithmetic or reporting. The Rust test
`an_oversized_datagram_is_dropped_without_ending_the_conversation` checks
full-capacity charging, a drop report, subsequent delivery to the same
conversation, independent peers, and release of every charge. Work is polled
even while continuous output prevents settling; `a_productive_datagram_layer_does_not_starve_its_pending_work`
checks this in bounded visits. Results go directly to the driver rather
than through an additional completion vector.

## Bugs 4 and 5: found by porting the serving engine's tests

When the serving engine was deleted, its cancellation tests were ported to
these runners (`tests/it/stack_cancellation.rs`). Two of them failed on the
runners as they were, and both were fixed at the root:

4. **Work whose region failed was polled for ever.** A task that work
   spawned and that failed cancelled the work's own region, but
   `Jobs::poll` kept polling the work, which never finished, so the run
   never ended (`a_background_failure_ends_the_run_and_spares_the_caller`
   deadlocked the lab). `Jobs::poll` now treats work whose region is
   cancelled like work whose owner ended: it is never polled again, and its
   failure goes to the run's region as before, which ends the run without
   touching the caller's. The job region is made before that check, so work
   of a run that is already cancelled is never polled at all.
5. **A cancel that landed while the stack ran lost to how it ended.** The
   stream runner looked at its region's cancel only at the top of each
   poll. A connection whose read cancelled the region, then handed over all
   its bytes, let the stack reach a handover and the code after it run, and
   the run returned `Ok` (`a_cancelled_region_hands_no_connection_off`).
   This is the bug the serving engine had and fixed
   (`verification/lifecycle/VERIFICATION.md`, Bug 2). The stream and datagram
   runners now return `StackError::Cancelled` for a cancel that landed while
   the stack ran, unless the stack itself gave up.

Neither runner model covers region cancellation or the work's own region
(see what each leaves out below), so these are covered by the ported tests,
not by TLC. The runner code changed for them, so both runner models were
rerun on it: `StreamRunner_base.cfg`, `StreamRunner_halfclose.cfg` and
`DatagramRunner_base.cfg` pass with the state counts recorded in their
tables above.

## Kani over the connection count: `kani/admission.rs`

`Counted` is the count a port server keeps of its open connections, held
with the socket so a closed connection counts until its socket is gone.
It moved here from the serving engine with its proof:

| Harness | Proves | Unwind | Checks | Result |
| --- | --- | ---: | ---: | --- |
| `connections_are_counted_up_to_the_maximum` | `Counted::enter` never counts past the maximum, and a dropped count makes room for one more, for maxima up to three | 5 | 451 | all pass, 2.1 s |

## Kani over the idle clock: `kani/lifetime.rs`

`Lifetime` keeps the idle and write limits for the stream runner and
`Session`. A stream that waits for memory is not waiting for its peer, so
`Outstanding::memory` stops the idle clock as work does, and leaves the
write clock alone:

| Harness | Proves | Unwind | Checks | Result |
| --- | --- | ---: | ---: | --- |
| `the_idle_clock_stops_while_memory_waits` | over three settles at symbolic `u8` times, with symbolic `u8` limits and flags: the idle deadline is never earlier than an idle limit after the first settle that found the stream quiet since its last busy one (busy: output, input, work or memory); a settle that finds the stream waiting for memory leaves no idle deadline; a twin that never waits for memory keeps the same write clock | 4 | not run yet | not run yet |

The random model test `the_idle_deadline_never_falls_inside_a_wait_for_memory`
(`lifetime.rs`) checks the same over 256 seeds of 64 steps, with the
clock resets (`took_input`, `wrote`, `interrupt`) mixed in.

## Kani over `Framed`

[`kani/framed.rs`](kani/framed.rs), included from `framed.rs` under
`cfg(kani)`.

Two decoders run under it: `Units`, which keeps the `Decode` contract
with a capacity of three (the smallest at which the buffer can outgrow
its limit; an even first byte is a one-byte unit, an odd one starts a
three-byte unit), and `Steps`, whose every step (item consuming any part
of the input, end, need, failure) the solver chooses. Underneath are the
real `Stream`, `Buffer`, `Budget`, `Charge`, `Chunk` and `Driver`.

| Harness | Proves | Result |
| --- | --- | --- |
| `the_buffer_is_charged_before_bytes_are_taken_A_B`, 9 harnesses, `A`, `B` in 1..3 | two pushes of `A` and `B` bytes of any value, with up to two items taken between: after each, `Framed`'s charge covers the decoder's input storage and held state and is all the budget holds; what a push hands back (`Partial`, `Blocked`) is exactly the bytes it did not take | all 9 verified, 39 to 72 s each |
| `every_charge_comes_back_*`, 10 harnesses | under budgets of 0, 6, 8, 13 and 14 bytes: two bytes from the peer and a value from above, either of which the budget may refuse, then two steps in ten orders (end, reset, end from above, taken event, taken write, its delivery): a refusal takes no byte; the budget holds exactly what `Framed` and the chunk in flight are charged, never past its limit; a written value is charged at least its length; nothing is left once they are dropped | all 10 verified, 2 to 9 s each |
| `units_come_up_in_order_and_the_rest_is_handed_back_odd_first_cut_3` | a three-byte unit (payload any) and a one-byte one in two pushes, then the end: each comes up once, in order, then `Ended` | verified, 3 s |
| `a_decoder_failure_comes_up_once_then_ended_first_*`, 7 harnesses | against any steps of `Steps`, through any three of input, end, reset and taken events and three more taken events: no item after a failure; a failure comes up once with `Ended` right after; nothing after `Ended`; once either came up, input is over, and input offered after its end is refused as `Closed` and changes nothing | all 7 verified under 10 GiB; exact cases below |
| `encoding_is_not_called_without_its_reservation` | a value whose `write_bound` is 64, under any budget below 64: `Framed::on_command` hands the value back as `Blocked`, the writer (which panics if entered) never runs, and the budget holds nothing | verified before writes waited for memory, when the answer was an error; not yet run since |
| `a_refused_write_keeps_its_value_and_writes_once_after_release` | any two-byte value, under a budget the rest of which is held: the send comes back `Blocked` with the value unchanged and nothing more charged; once the hold is dropped the same value is taken, written once, its bytes charged at least their length, and every charge comes back on drop | not yet run |
| `a_refused_packet_keeps_its_value_and_writes_once_after_release` | the same for `network::packet::Framed`: any two-byte packet comes back unchanged while the budget is held, then is framed once after the release with a length that agrees with it, and every charge comes back on drop | not yet run |
| `a_decoded_allocation_keeps_its_charge_outside_the_layer` | a decoder whose item allocates one byte, under a budget of 8: the item comes up `Owned` with a charge of at least its capacity, the charge stays in the budget after the layer is dropped, and leaves with the item | verified (the readiness pass, 1 to 3 s) |

Before Bug 1's fix, the charge harnesses fail (see the mutations below).

On the merged foundation the first 21 were rerun in one `cargo kani -p fictionet
-Z stubbing` (the flag was for a shared run; no harness in this directory
stubs anything) under a 12 GB memory cap, and all verified: the nine charge
harnesses in 47 to 80 s each, the ten `every_charge_comes_back_*` in 4 to
16 s, the ordering harness in 5 s and the decoder-failure harness in
303 s.

On November 9, 2026 the combined decoder-failure harness exceeded the
10 GiB scope limit with both MiniSat and CaDiCaL; neither attempt produced
a proof result. Its input-first partition also exceeded that limit with
CaDiCaL. The current seven cases call one shared helper: first actions end,
reset and take, and first input followed by each possible second action.
Input, end and reset correspond to selector values zero, one and two;
the take case represents every other value, whose numeric value is never
otherwise used. Third actions, decoder steps and payloads remain unconstrained,
as does the second action whenever the first action is not input. The three
actions, three drains, every assertion and the unwind bound of seven are
unchanged. The seven cases together cover exactly the original harness.

All seven cases verified with CaDiCaL, one verifier per 10 GiB scope, no
swap and `-j 1`. Each row names the suffix after
`a_decoder_failure_comes_up_once_then_ended_first_`; the counts include
unreachable checks. Times are wall times on a machine shared with other
verification work.

| Suffix | Checks | Unreachable | Seconds |
| --- | ---: | ---: | ---: |
| `end` | 2,374 | 47 | 3.00 |
| `reset` | 2,377 | 39 | 18.25 |
| `take` | 2,382 | 25 | 414.20 |
| `input_then_input` | 2,379 | 27 | 149.92 |
| `input_then_end` | 2,379 | 25 | 115.85 |
| `input_then_reset` | 2,378 | 32 | 25.20 |
| `input_then_take` | 2,381 | 23 | 2,205.13 |

The decoder filter in the README selects exactly these seven cases. Each
case was run separately with this command, replacing the final harness name
with its full name:

```sh
systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=10G -p MemorySwapMax=0 env CARGO_BUILD_JOBS=6 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_TARGET_DIR=/home/souvik/Projects/amlalabs/.fictionet-comp-work/target-reviewfix cargo kani -p fictionet --output-format terse -Z stubbing -j 1 --harness a_decoder_failure_comes_up_once_then_ended_first_input_then_take
```

No case was omitted after a resource failure.

Each harness fails when the rule it checks is broken. These manual
mutations of `framed.rs` were applied one at a time, the named harness
run, and the file restored:

| Mutation of `framed.rs` | Harness | Result |
| --- | --- | --- |
| `Framed::charge` as before Bug 1's fix: the limit alone, once | `..._taken_3_1` | FAILED: "the decoder's storage is charged" (43 s) |
| a reset forgets the held write (`mem::forget(self.out.take())`) instead of dropping it | `every_charge_comes_back_14_reset_then_write` | FAILED: the budget no longer equals what is held (2 s) |
| a push advances its chunk one byte short (`chunk.advance(n - 1)`) | `..._taken_1_3` | FAILED: the bytes handed back are not the suffix not taken (35 s) |
| an item ends the input (`input_over = true` after each item) | `units_come_up_in_order_..._odd_first_cut_3` | FAILED: the second push is refused as closed (2 s) |
| a failure leaves the input open (no `input_over = true` on `Err`) | `a_decoder_failure_comes_up_once_then_ended` | FAILED: "after a failure or the end, input is over" (298 s) |

What the Framed proofs leave out. The bounds are small: chunks of one to
three bytes, two pushes, a capacity of three. Lengths are fixed per
harness (one harness per length), as are the budget limits and the order
of operations in the charge harnesses, because leaving those to the
solver ran out of
10 GiB; the byte values and the decoder's steps are the solver's, and so
are the third operations of the decoder-failure cases and the second ones
when the first is not input; the exhaustive partitions collectively cover
every original selector. The ordering harness
covers only cuts at which each push is
taken whole: offering the bytes a push handed back again ran out of
10 GiB. That a handed-back suffix is exact is proved above; that the
units after it come up in order is the test
`every_cut_of_the_input_gets_every_frame_back_in_order` (every cut of
three Modbus frames, by execution) and the byte counting of
`StreamRunner.tla` (`InputKept`), not a proof. The capacity term of Bug
1's fix is shown by its unit test only: `Units` has a fixed capacity, and
`Steps` (whose capacity is fixed too) does not exercise the charge.
The framing adapter now requires `BoundedDecode`: decoding cannot grow
retained state or allocate errors, and the owned item's allocation has a
stated bound reserved before decoding. `Owned` carries that reservation
beyond the adapter. `BoundedWire` states an output-capacity bound without
temporary heap allocations, so the adapter reserves before invoking the
writer. These are implementer contracts, not inferred bounds for arbitrary
`Decode` or `Wire` implementations. The real Modbus implementation and the
small proof decoders implement these contracts; ordinary codec consumers
keep their existing interfaces.

The refusal harness (`encoding_is_not_called_without_its_reservation`)
makes its writer panic if entered and proves that no budget below its
output bound invokes it. The owned-allocation harness
(`a_decoded_allocation_keeps_its_charge_outside_the_layer`) decodes an
allocated byte vector, drops its layer while retaining the item, and
checks that the reservation remains until the item is dropped. Both are
in the table above.
The PLC proof setup now supplies and receives owned frames with reservations;
its request ordering and identity assertions are unchanged.

The readiness pass reran all 23 Framed harnesses after moving Chunk to
owned vector backing: all verified under the 12 GiB memory cap. The nine
buffer harnesses took 58 to 82 seconds each, the ten charge-release
harnesses 2 to 10 seconds, the ordering harness 4 seconds, and the two new
ownership/reservation harnesses 1 to 3 seconds. The symbolic decoder
failure harness verified in 277 seconds using MiniSat, with its original
three symbolic operations, unwind bound and assertions unchanged. Input
fixtures now use fixed-size symbolic arrays copied into the production
chunk rather than leaking an extra allocation for a static slice. Earlier
runs against the intermediate shared backing implementation did not
complete; only the completed vector-backed run is counted here.

## Kani over the PLC server and the time server

### The PLC server: `kani/plc.rs`

Included from `demos/nuclear/world/src/plc.rs`. The harnesses drive the
real `PlcServer` through a `Driver`, over a real `Plant` (built with
`Config::default()`), offering whole frames as `Framed` hands them up.
Two requests each, with any data byte, transaction and unit, and one
function code per harness: 0x00, 0x03 (a read the controller serves),
0x07 (one it does not), 0x10 (a write it serves), 0x2B (device
identification) and 0x83 (exception flag). No read or write fits in a
PDU of one or two bytes, so each request is answered from
`Request::parse`, an exception or the device identification, and the
plant's physics never run under the solver.

| Harness | Proves | Result |
| --- | --- | --- |
| `each_request_gets_one_answer_in_order_<function>_pdu_<1,2>`, 12 harnesses | each request gets exactly one answer, in order, with its own transaction and unit and its function (or the exception of it); the server keeps its side open while frames may come, ends it once the client's frames are over, sends nothing after its end, and ends once | all 12 verified, 45 to 66 s each |
| `a_pipelined_request_waits_for_the_answer_before_it_<function>`, 6 harnesses | the same, with the second request offered before the first answer was taken: it is refused as `Blocked` and handed back unchanged | all 6 verified, 48 to 65 s each |

Building the plant runs loops of up to 32 iterations (one per sensor), so
these run with a global unwinding bound of 8 and the plant's four loops
unwound to 40 by `--unwindset`, from [`kani/plant.unwindset`](kani/plant.unwindset).
The loop ids carry the crate's hash; if a rebuild changes it, an
unwinding failure names the loop, and its id is in the harness's
`*.pretty_name_map.json` under `target/kani`.

On the merged foundation all 18 were rerun with the command in the
README, the same `plant.unwindset` (the crate's hash had not changed)
and a 12 GB memory cap, and all verified, in 45 to 57 s each.

What it leaves out: Modbus bytes. Driving `Chain<Framed, PlcServer>` from
bytes in one harness ran out of 10 GiB, as did one symbolic function code
over every branch of `Request::parse`; the composition rests on the
Framed proofs and the PLC tests (`pipelined_requests_cut_anywhere_get_the_same_answers_in_order`
and the others in `plc.rs`), by execution. Reads and writes the
controller serves, which read and change the plant, are not covered.

| Mutation of `plc.rs` | Harness | Result |
| --- | --- | --- |
| a frame that arrives while an answer waits is taken and dropped instead of refused | `a_pipelined_request_waits_for_the_answer_before_it_unserved` | FAILED: "the second request waits for the first answer" (26 s) |
| the end of the client's frames is ignored | `each_request_gets_one_answer_in_order_unserved_pdu_2` | FAILED: "the server ends its side once the client's frames are over" (31 s) |

The readiness pass also reran all 18 PLC harnesses with owned request and
response reservations and the existing plant unwind set. All verified in
44 to 82 seconds each under the 12 GiB cap. The one- and two-byte input
domains, function cases, pipeline choices and identity/order assertions
are unchanged. These proofs exercise the application and ownership API;
the real framed PLC stack additionally passed all 24 PLC unit tests.

### The time server: `kani/ntp.rs`

Included from `demos/search/world/src/ntp.rs`. The harnesses drive the
real `TimeServer` through a `Driver`, with the session clock of its
tests, and the real `Packet::parse`, `ntp::server_reply` and
`Packet::write`. What counts as a request is written in the harness from
RFC 5905 and RFC 4330 on the bytes, not taken from the code: at least the
48-byte header, a trailer of whole 4-byte words, version 1 to 4, and mode
3 (client) or 1 (symmetric active).

| Harness | Proves | Result |
| --- | --- | --- |
| `the_time_server_answers_nothing_of_<n>_bytes`, n = 0, 1, 47, 49, 50, 51 | a datagram of that length, every byte any, gets no answer | all 6 verified, 1 to 2 s each |
| `the_time_server_answers_version_<v>_mode_<m>`, v 1..4, m 1, 3; with a 4-byte trailer (v4, m 1 and 3); with the leap bits set | a request with any poll, transmit time and trailer (other fields zero) gets exactly one answer, to its sender, 48 bytes long, whose origin is the request's transmit time, mode 4 for a client and 2 for a symmetric peer, with the request's version and poll | all 11 verified, 12 to 15 s each |
| `the_time_server_refuses_version_0_mode_<m>`, every mode | a header of version 0, which `Packet::parse` refuses, gets no answer | all 8 verified, about 1 s each |
| `one_conversation_answers_each_request_in_turn` | two client requests from any two ports, any transmit times: the second is refused as `Blocked` and handed back whole while the first answer waits, each answer goes to its own sender with its own transmit time as origin, and the socket's end sends nothing | verified, 31 s |

On the merged foundation all 26 `TimeServer` harnesses were rerun under a
12 GB memory cap and verified, in 0.8 to 34 s each.

After the reply reservation change in `090aba987`, all 27 harnesses,
including the new reservation proof, passed under the requested 12 GiB
systemd cap, no swap, six build jobs and `target-int`. Verification took
1.65 to 28.88 seconds per harness; the new refusal proof took 2.51 seconds.
The command was `cargo kani -p web-world -Z stubbing --harness the_time_server
--harness one_conversation_answers_each_request_in_turn`. The four NTP tests
also passed, including the actual sandbox clock exchange over the network.

[`kani/ntp_reply.rs`](kani/ntp_reply.rs), included from
`src/stdlib/protocols/ntp.rs`, proves on `ntp::server_reply` itself, for
every mode, every version 0 to 7 and any other field: a reply comes only
for a request and for every request, with the request's transmit time as
origin, its version, and mode 4 to a client and 2 to a symmetric peer
(`a_reply_comes_only_for_a_request_and_carries_its_transmit_time`,
verified, under 1 s), and that a header whose mode bits are 0, 6 or 7
does not parse whatever its other bytes (`a_header_of_mode_0_6_or_7_does_not_parse`,
verified, 1 s); `TimeServer` answers nothing it cannot parse. Both
verified again on the merged foundation.

| Mutation | Harness | Result |
| --- | --- | --- |
| `reply_mode` answers mode 4 (server) as it does a client | `a_reply_comes_only_...` | FAILED: "only a request is answered" |
| `Mode::from_bits` reads mode 6 as broadcast | `a_header_of_mode_0_6_or_7_does_not_parse` | FAILED: the header parses (1 s) |
| the reply's origin taken from the request's receive time | `a_reply_comes_only_...` | FAILED: "the origin is the request's transmit time" |
| `TimeServer` sends its answer to 0.0.0.0:123 instead of the client | `the_time_server_answers_version_4_mode_3` | FAILED: "the answer goes to the sender" (11 s) |

What it leaves out. A 48-byte header that is not a request but has a
version of 1 to 7 (modes 0, 2 and 4 to 7, or modes 1 and 3 with versions 5
to 7) ran out of 10 GiB when driven through `TimeServer`, and so did a
whole header with every byte the solver's. Those refusals are proved on
`Packet::parse` and `server_reply` above, and `TimeServer` sends nothing
when its `answer` gives `None` (`demos/search/world/src/ntp.rs:104-111`), which the length and
version-0 harnesses exercise; that the two compose inside `TimeServer`
for those headers is shown by the test
`one_conversation_answers_each_request_and_nothing_else` (a server's
reply, an empty datagram, bytes that are not NTP), not by a proof. The
answered headers have their fields other than the first byte, the poll,
the transmit time and the trailer set to zero. The reply path now reserves the copied request trailer plus two reply
headers before parsing or consulting the clock: the transactional packet
writer temporarily holds one header alongside its destination. After
encoding, only the final header reservation travels with the reply. The
unit test `reply_memory_is_reserved_before_parsing_and_encoding` exercises
both sides of this peak bound and retention after the server is dropped.
`the_time_server_reserves_reply_memory_before_reading_the_clock` proves
that every budget below the header-only peak rejects before consulting
the clock and leaves no reply or reservation.


On November 9, 2026 the stream baseline completed with 27,865,057 generated
and 185,569 distinct states. All ten negative controls violated their intended
invariant or temporal property. The half-close configuration has the same
specification and constants and only a subset of the baseline's properties;
its obligations were checked by that baseline, without a duplicate run.
The model does not represent reports emitted during command extraction.
Seven Rust regressions failed with the old drain order and passed after both
runners drained those reports before returning. The final worker-storage
backpressure change passed its targeted Rust tests; formal reruns stopped at
the user's request before that change.

## Framed reservation harnesses on main `3db7a847e` (November 10, 2026)

Three harnesses in `kani/framed.rs` were run alone, as
`cargo kani -p fictionet -Z stubbing --exact --harness stdlib::layer::framed::proofs::framed::<name>`,
under an 8 GB memory cap without swap:

| Harness | Result |
| --- | --- |
| `encoding_is_not_called_without_its_reservation` | out of memory, 153 s |
| `a_refused_write_keeps_its_value_and_writes_once_after_release` | out of memory, 144 s |
| `a_refused_packet_keeps_its_value_and_writes_once_after_release` | out of memory, 145 s |

No check failed. Each charges a budget, and CBMC runs out of memory on
the budget's release and wake path, as recorded in
`verification/layer/VERIFICATION.md` under "Kani on main `3db7a847e`".
