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
to the new loops and rerun at code revision `6aa68ae5f`. What each model
now describes is in its section below. Bug 1's fix merged as it was.

Three bugs were found, each confirmed by a test that failed on the code
before its fix:

1. `Framed` charged its decoder buffer less than the buffer grows to.
2. `stream` ended idle input at once after a time it was not reading.
3. `datagrams` dropped what a stack still had to send when its socket
   closed, if the stack needed more than 64 rounds to send it.

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
(`live.rs:213`) and written (`live.rs:320`), and when waiting begins
(`was_waiting`, `live.rs:346-349`); both tests pass.

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
(`stack/mod.rs:302`); the test passes.

## The stream runner: `StreamRunner.tla`

[`tla/StreamRunner.tla`](tla/StreamRunner.tla) is one connection under
`stream` (`src/stdlib/services/stack/mod.rs:163-203`) and `Live`
(`src/stdlib/services/stack/live.rs`), one round at a time. It was
rewritten for the split runner: `Live::step` reads first, offers the
stack its input, runs it and writes in the same round, and checks the
limits only when a round moved nothing; `stream` returns when `step` waits
and the run is finished, or the peer is gone.

| Model | Rust (`src/stdlib/services/stack/live.rs` unless named) |
| --- | --- |
| `Round` | one round of `step` (196-330): the read (202-221), the `Written` report (229-239), the held input (240-257), `Driver::run` (258), `send_below` into the transport (262-308), then a reset, a failed write or a failed read ends the run (309-327) |
| `SendLoop` | the sink of 264-308 under `Driver::send_below` and `send` (`layer/driver.rs:190-195`, `246-276`): a write that fails, or takes nothing, stays held |
| `Check` | 332-382: the write limit, the idle limit with `was_waiting` (346-349), the sleep; then `stream` on `Pending` (`mod.rs:190-196`): `Live::finished` (142-150), else `poll_gone` |
| `EndBroken` | `Live::broken` (392-418) |
| `Tick`, `PeerReset`, `Gone` | time passing while the runner waits; the peer's reset; `stream` noticing it with `poll_gone` |

A round from the wait runs only if something can move then: the peer
sent, the transport takes a write, the peer is gone, or the sleep is due.

The stack is abstract: an echo with room for one byte, which moves input to
output when it runs, asks to end its direction when it heard the end of
its input or early, refuses input for three ticks on a timer of its own,
and may ask for a reset. Its commands come out writes first, then reset or
end, as `Framed::take_command` (`framed.rs:183-195`) orders them; its
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
- `FinishNeedsInput`: `Finished` and `Idle` also mean the input ended. On
  the branch this was part of `EndsAreEarned`; it is apart now because the
  code does not keep it (below).
- `Terminates`: with both limits set, every connection ends.

| Config | Rule turned off | Generated | Distinct | Result |
| --- | --- | ---: | ---: | --- |
| `StreamRunner_base.cfg` | none (the code as it is) | 18,410,091 | 122,879 | every property but `FinishNeedsInput` holds (6 min 31 s) |
| `StreamRunner_halfclose.cfg` | none (the code as it is) | 70,986 | 1,023 | `FinishNeedsInput` violated: a design gap, below |
| `StreamRunner_finish_after_input.cfg` | none, plus `finished` needing the input over (not the code) | 27,865,057 | 185,569 | `FinishNeedsInput` holds |
| `_without_readonlywhentaken` | read without `input.is_none()` | 44,828 | 805 | `ReadOnlyWhenTaken` violated |
| `_without_keeppartialrest` | a `Partial` rest dropped | 5,736 | 156 | `InputKept` violated |
| `_without_reportonce` | `unreported` not cleared once reported | 14,536 | 388 | `WrittenOnce` violated |
| `_without_writebeforeend` | the stack's End before its writes | 3,416 | 78 | `EndAfterWrites` violated |
| `_without_idleresetonread` | no `idle_from = now` on a read | 2,584,842 | 19,315 | `IdleNeedsQuiet` violated |
| `_without_restartidleonwait` | no restart when waiting begins | 2,360,916 | 17,914 | `IdleNeedsQuiet` violated |
| `_without_stallresetonprogress` | no `stalled_since = None` on bytes written | 3,396,792 | 25,095 | `StallNeedsNoProgress` violated |
| `_without_resetonbreak` | `broken` offers no reset | 528 | 26 | `ResetHeardOnBreak` violated |
| `_without_writetimeout` | `write_timeout: None` | 2,647,837 | 21,169 | `Terminates` violated: a peer that stopped reading holds the runner forever |

Each was run with `-workers 4 -Xmx6g` under an 8 GB memory cap; TLC
stops at the first violation. The `_without_restartidleonwait` trace is
the one of Bug 2: the stack ends its direction at once, the shutdown pends
for two ticks while the runner holds the End, it completes with no byte
written, and the next check ends the input with `idle_from` still at zero.

The half-close gap. `Live::finished` returns `Finished` once the stack
ended its direction, every byte of it is written and no work is left,
whether or not its input is over, and `stream` then drops the stack. The
old runner also waited for the input to end (`FinishNeedsInputOver` in
the model). `StreamCommand::End` closes one direction, so a stack that
ends its own and then waits for the peer's answer is dropped before the
answer comes. TLC's trace is four states: the stack ends its direction
early, the shutdown completes, the next check finds the run finished with
the input still open. The review of the foundation lists this
(`crm/ideas/protocol-foundation-astra-review-20261108.md`, "the live
runner treats a write half-close as completion of the whole stack"), and
the fix belongs to the next step of the plan; `StreamRunner_finish_after_input.cfg`
shows that waiting for the input as well keeps the property in this
model. Whatever terminal state the fix adds should make that config the
code, and this one pass.

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
`datagrams` (`run_datagrams` in `src/stdlib/services/stack/mod.rs:242-359`).
On the merged foundation a round runs the stack before it sends, where the
old `settle` sent first; the model's round follows the new order.

| Model | Rust (`src/stdlib/services/stack/mod.rs`) |
| --- | --- |
| `SettleRound` | one round of the `for _ in 0..FAIR` at 268-299: the held input, `Driver::run`, then `send_below` into `send_to` |
| `Drain` | the sink of 283-294: send each datagram, take End, refuse the rest as closed |
| `AfterSettle` | 300-309: return on End or on a closed socket once settled, yield when not settled |
| `Wait` | the `poll_fn` of 318-337 and 340-357: receive only with no input held, sleep until the stack's deadline |
| `Arrive`, `Close`, `Tick` | the environment |

The stack has the shape of `TimeServer`: at most one reply per datagram it
takes, the next datagram refused while a reply waits; and also a timer
that sends one datagram when it fires (and may hold input refused until
then), a choice to close the socket itself with one more datagram queued
after the End, and a backlog of three replies it sends one per step after
the socket closes. It asks for no work, so `jobs` stay empty. Three
datagrams arrive; `Fair` is 2.

Properties: `InOrderOnce` (one conversation took every datagram the socket
got, in order, each once, besides the one held and those queued);
`SentInOrder` (each datagram the stack hands down goes out at once, once,
in order); `NothingAfterEnd`; `CloseFlushes` (when the socket closes the
stack hears `Ended` and sends all it has before the runner returns);
`TimerFires` (a timer goes off with no datagram coming); `CloseEnds` (a
closed socket ends the run).

| Config | Rule turned off | Generated | Distinct | Result |
| --- | --- | ---: | ---: | --- |
| `DatagramRunner_base.cfg` | none | 32,196 | 5,787 | every property holds |
| `_without_receiveonlywhentaken` | receive while a datagram is held | 4,120 | 822 | `InOrderOnce` violated |
| `_without_oneconversation` | a fresh stack per datagram | 1,365 | 283 | `InOrderOnce` violated |
| `_without_sendeachdatagram` | a send taken without `send_to` | 71 | 33 | `SentInOrder` violated |
| `_without_endclosesoutput` | output after End still sent | 160 | 53 | `NothingAfterEnd` violated |
| `_without_settlebeforeclose` | the code before Bug 3's port | 1,002 | 183 | `CloseFlushes` violated |
| `_without_deadlineinwait` | the wait ignores the stack's deadline | 25,674 | 4,957 | `TimerFires` violated |
| `_without_returnonclose` | no return on a closed socket | 33,678 | 6,053 | `CloseEnds` violated |

What it leaves out: datagram contents and addresses (each datagram is its
number; that answers go to the address the stack names is a Kani property
of the time server below), the socket dropping datagrams it cannot queue,
the stack's work, and cancellation.

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
| `a_decoder_failure_comes_up_once_then_ended` | against any steps of `Steps`, through any three of input, end, reset and taken events and three more taken events: no item after a failure; a failure comes up once with `Ended` right after; nothing after `Ended`; once either came up, input is over, and input offered after its end is refused as `Closed` and changes nothing | verified, 362 s |

Before Bug 1's fix, the charge harnesses fail (see the mutations below).

On the merged foundation all 21 were rerun in one `cargo kani -p fictionet
-Z stubbing` under a 12 GB memory cap, and all verified: the nine charge
harnesses in 47 to 80 s each, the ten `every_charge_comes_back_*` in 4 to
16 s, the ordering harness in 5 s and the decoder-failure harness in
303 s.

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
are the operations of the decoder-failure harness. The ordering harness
covers only cuts at which each push is
taken whole: offering the bytes a push handed back again ran out of
10 GiB. That a handed-back suffix is exact is proved above; that the
units after it come up in order is the test
`every_cut_of_the_input_gets_every_frame_back_in_order` (every cut of
three Modbus frames, by execution) and the byte counting of
`StreamRunner.tla` (`InputKept`), not a proof. The capacity term of Bug
1's fix is shown by its unit test only: `Units` has a fixed capacity, and
`Steps` (whose capacity is fixed too) does not exercise the charge.
Decoder state that grows in `take_event` is charged only at the next push;
no decoder in use holds state, and this is not proved either way.

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
when its `answer` gives `None` (`ntp.rs:96-101`), which the length and
version-0 harnesses exercise; that the two compose inside `TimeServer`
for those headers is shown by the test
`one_conversation_answers_each_request_and_nothing_else` (a server's
reply, an empty datagram, bytes that are not NTP), not by a proof. The
answered headers have their fields other than the first byte, the poll,
the transmit time and the trailer set to zero. A budget with no room for
the answer (the server then drops the request) is not covered.
