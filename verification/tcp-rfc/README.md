# TCP against RFC 9293

The other TCP models (`lifecycle`, `tcp-layer`, `tcp-port-zero`, `mptcp`)
describe the code and check it against properties of its own. This area
checks it against the RFC. [`tla/Rfc9293.tla`](tla/Rfc9293.tla) is one
endpoint as RFC 9293 writes it, from the RFC's text and not from the code;
[`tla/Engine.tla`](tla/Engine.tla) is the smoltcp socket at the level of
its fields and must refine it; [`tla/RfcTrace.tla`](tla/RfcTrace.tla)
replays logs of the real socket against the RFC model; and the Lean model
in [`lean/`](lean/README.md) proves the arrival rules over the full 32-bit
space and generates vectors that a Rust test replays through the socket.

## What the RFC model says

`Rfc9293.tla` covers, for one connection:

- the states and transitions of section 3.3.2, with the user calls of
  3.10.1 to 3.10.5 (OPEN active and passive, SEND, RECEIVE, CLOSE, ABORT)
  and the timeouts of 3.10.8 (the user timeout, TIME-WAIT's end);
- segment arrival, section 3.10.7: LISTEN (3.10.7.2), SYN-SENT (3.10.7.3)
  and every other state (3.10.7.4) in the RFC's order: the acceptability
  test of the first check with its four cases and the zero-window
  allowance for ACKs and RSTs, RST, SYN, the ACK field (SND.UNA < SEG.ACK
  =< SND.NXT, the duplicate, the ACK of data never sent), the text with
  text past a hole held or dropped, and the FIN, taken only in order and
  only once;
- RFC 5961: a RST exactly at RCV.NXT resets, one elsewhere in the window
  draws a challenge ACK, one outside it is dropped (3.2); a SYN in a
  synchronized state draws a challenge ACK whatever its number (4.2); an
  ACK of data never sent is answered and dropped (5.2), and section 7's
  rate limit may hold any challenge ACK back;
- sequence numbers modulo N, every comparison written as an offset from
  the left end of its interval (section 3.4), so the window test, the ACK
  test and the FIN position are the RFC's across wraparound, and the value
  exactly half the space from SND.NXT, where RFC 1982 defines no order, may
  be read either way but never as new.

The peer sends any segment at all: every sequence number, every
acknowledgment number or none, each control, up to `MaxText` octets.
Whatever the RFC leaves to the implementation stays open: an ACK of
accepted text may go now or later, text past a hole may be held or dropped,
the window's right edge may move right at any time but never left, and a
challenge ACK may be held back.

The model's own invariants, in `Rfc9293_base` (every departure off):
`SendOrder` (ISS =< SND.UNA =< SND.NXT =< the FIN plus one),
`WindowFits` (RCV.WND plus unread octets within the buffer),
`HeldInWindow`, `NothingAfterFin`, `FinOnlyAfterClose`, and the step
property `AckNoFurther` (an ACK never acknowledges a sequence number not
taken). They check the spec, not the code, and have no controls.

### The departures

Each is a constant of `Rfc9293`, `FALSE` for the RFC as written. The code
needs every one of them: `Engine_without_<name>` checks the code against
the RFC with that one departure taken out, and fails.

| Departure | The RFC says | The code does | Why |
| --- | --- | --- | --- |
| `AckBeforeSeqInSynReceived` | 3.10.7.4: the sequence check comes first, so an unacceptable segment in SYN-RECEIVED gets an ACK | a bad ACK in SYN-RECEIVED gets `<SEQ=SEG.ACK><RST>` before the sequence check | Linux's `tcp_check_req` order |
| `ChallengeSynInSynReceived` | fourth check: an acceptable SYN in SYN-RECEIVED returns a passive open to LISTEN | a challenge ACK, as in the synchronized states | RFC 5961 4.2's answer, which keeps a blind SYN from tearing the handshake down |
| `NoAckDroppedFirst` | a segment without ACK is dropped in the fifth check, after an unacceptable one was answered in the first | dropped silently before the sequence check | Linux's `tcp_rcv_state_process` order |
| `AckCheckedBeforeSeq` | the sequence check first, so an unacceptable segment with an ACK of unsent data gets an ACK | the challenge ACK (rate limited) before the sequence check | RFC 5961 5.2 and 7 treat it as a challenge |
| `RateLimitEmptyOutOfWindow` | every unacceptable segment is answered | an unacceptable segment with no text and no FIN gets a rate-limited challenge ACK | Linux's `tcp_oow_rate_limited`; a pure ACK cannot start an ACK war this way |
| `EmptyAckAtRightEdge` | an empty segment at RCV.NXT+RCV.WND is outside the window | acceptable when it carries no FIN, PSH or RST | a peer that filled the window sends its next ACK there (`segment_in_window`) |
| `FinAtRightEdge` | a FIN at RCV.NXT+RCV.WND lies outside the window | taken when it comes in order: right after text that fills the window, or alone at RCV.NXT of a closed window | Linux does the same; `test_zero_window_fin` |
| `OpenInTimeWait` | OPEN on a connection that exists, TIME-WAIT included, is an error | `listen` and `connect` start afresh from TIME-WAIT | the engine keeps TIME-WAIT in its own table (`tcp/engine.rs`) |

`RepeatSynAck` is a setting rather than a departure: with
`Settings::repeat_syn_ack` (on in the Linux look, `extras/src/linux.rs`),
a SYN in SYN-RECEIVED one before RCV.NXT and without ACK resends the
SYN-ACK instead of drawing a challenge ACK. `Engine_base` runs with it on
and `Engine_default` with it off.

## How the code is tied to it

- **Refinement.** `Engine.tla` keeps the socket's fields (`state`,
  `listen_endpoint`, `local_seq_no`, `local_seq_max`, `tx_buffer.len()`,
  `closed_before_syn_ack`, `remote_seq_no`, `rx_buffer.len()`,
  `remote_win_end`, the assembler, `rx_fin_received`) and transcribes
  `process` arm by arm, with `SeqNumber`'s order as the code has it (no
  order at all half the space away), `segment_in_window`,
  `receive_window_end`, `remember_window`, `accepts` and the interface's
  `rst_reply`. Its header names the lines. `Refines == RFC!Spec` checks
  every step under the refinement mapping, and `NoPanic` that no step
  underflows a `SeqNumber` subtraction or dequeues more than `tx_buffer`
  holds.
- **Trace replay.** `smoltcp/src/socket/tcp/rfc_trace.rs` drives a real
  `Socket` through seeded mixes of user calls, dispatches, time and peer
  segments drawn around the window's edges, RCV.NXT, SND.UNA and SND.NXT,
  with the ISS and IRS just below 2^32 so that the socket's numbers wrap.
  After each step it logs the socket's fields read as the RFC's variables.
  `RfcTrace.tla` replays each log: every entry is the Rfc9293 action of its
  name with the logged state as the next state, so the log is a behavior of
  the RFC model or TLC stops at the entry where they part. The replay uses
  N = 2^20, which tells apart every number the driver draws as 2^32 does;
  the half-space point is left to `Engine.tla` and the Lean vectors.
- **Vectors.** The Lean model's `arrive` is the RFC's arrival rule over
  `UInt32`; `Gen.lean` writes vectors at every boundary (window edges,
  wraparound, the 2^31 point, every state and control) and
  `smoltcp/src/socket/tcp/rfc_vectors.rs` sets a socket to each vector's
  state, feeds the segment through `process`, and compares the reply and
  the next state, once with the challenge-ACK rate limit open and once
  closed. The last run: 61 theorems, the 41 headline ones on Lean's own
  axioms only; 746,960 vectors a seed (696,960 at the boundaries, 50,000
  drawn) for each of seeds 1 to 8, none in disagreement. The Lean model
  names the same departures, and also `textOnSynDropped` for the text on a
  SYN-ACK that the TLA+ model lists below as a SHOULD not followed. See
  [`lean/README.md`](lean/README.md).

## What it found

Six departures from RFC 9293 that are bugs, each fixed in
`smoltcp/src/socket/tcp.rs` with a test that failed before the fix, and
each with a control that puts the old code back and fails:

| Commit | Bug | Test | Control |
| --- | --- | --- | --- |
| `8b882f969` | An ACK exactly 2^31 from SND.UNA is unordered in `SeqNumber`'s order, so `ack >= SND.UNA && ack > SND.MAX` was false and the ACK went through as new: SND.UNA jumped half the space and every later real ACK read as old, so the connection stalled. On a socket closed in SYN-RECEIVED before its SYN-ACK went out, the same ACK read as acknowledging 2^31 - 1 octets of an empty `tx_buffer`, and `dequeue_allocated`'s assert panicked: one segment from a peer crashed the stack. | `test_established_ack_half_the_space_away_is_challenged`, `test_closed_syn_received_challenges_an_ack_half_the_space_away` | `Engine_without_unorderedackfix` (`NoPanic`), `_refines` (`Refines`) |
| `8b882f969` | An unacceptable bare FIN, which occupies sequence space, went through the rate-limited challenge path, so TIME-WAIT left the peer's retransmitted FIN unanswered for a second after any challenge ACK. | `test_time_wait_bare_fin_retransmission_is_acked_after_a_challenge` | `Engine_without_barefinfix` |
| `5a652ed66` | In SYN-SENT a bad ACK with PSH or FIN set was dropped without the RST of 3.10.7.3. | `test_syn_sent_bad_ack_with_psh_or_fin_is_reset` | `Engine_without_synsentfinfix` |
| `d33b8023e` | Text the peer sent past its own FIN's sequence number, held out of order before the FIN came, was taken with the FIN and read by the application before the end of the stream. | `test_text_held_past_the_peers_fin_is_not_read` | `Engine_without_finboundsfix` |
| `d33b8023e` | A FIN after the peer's first fell to the catch-all arm, which dropped the segment and the ACK beside it, so LAST-ACK or CLOSING missed the ACK of its own FIN. | `test_last_ack_takes_the_ack_beside_a_second_fin` | `Engine_without_secondfinfix` |
| `d33b8023e` | TIME-WAIT dropped every acceptable segment, so text at RCV.NXT of a closed window, which counts for its ACK and is answered everywhere else, went unanswered. | `test_time_wait_answers_text_in_a_closed_window` | `Engine_without_timewaitackfix` |

Found by reading the code against the RFC, outside what the models check,
and not changed:

- **The send window's update order (3.10.7.4, fifth check).** The RFC
  takes SEG.WND only from a segment newer than the last update (SND.WL1,
  SND.WL2); the socket takes it from every segment whose ACK is not old,
  so a reordered older segment can set a stale window. The models leave
  the peer's window out.
- **Timestamps (RFC 7323).** The option is parsed and echoed, but
  TS.Recent is taken from every accepted segment, not only one that
  covers Last.ACK.sent (4.3); there is no PAWS (5); and a segment without
  the option after it was negotiated is not dropped (3.2, a SHOULD). The
  engine does not claim PAWS.
- **SACK (RFC 2018).** The first block is the one with the segment that
  triggered the ACK, as section 4 requires, but only one block is sent
  where the RFC asks for as many as fit.
- **Text on a SYN** is not queued (3.10.7.2 and 3.10.7.3, a SHOULD); it is
  not acknowledged, so the peer sends it again.
- **SYN and FIN together, and other control mixes but RST,** are refused
  by the parser (`wire/tcp.rs`), which gives RST precedence.
- **Urgent data** is not signalled; it stays in the byte stream (RFC 6093).
- **A closed window's segment whose ACK closes LAST-ACK** is answered with
  an ACK from a connection that has just closed. The model allows it: the
  answer is the first check's to an unacceptable segment, sent with the
  numbers from before the ACK closed the connection.

## Results

TLC 2.19, `-workers 2`, N = 8, Cap = 2, Data = 1, MaxText = 2, IRS = 7.
Every passing configuration completes with an empty queue; each control
fails on the property its first line names.

| Config | Generated | Distinct | Result |
| --- | ---: | ---: | --- |
| `Rfc9293_base` (the RFC as written) | 4,050,124 | 3,650 | the spec's invariants and `AckNoFurther` hold |
| `Engine_base` (with `repeat_syn_ack`) | 6,892,445 | 12,527 | `Refines`, `NoPanic`, `TypeOK` hold |
| `Engine_default` | 6,892,452 | 12,527 | `Refines`, `NoPanic`, `TypeOK` hold |
| `Engine_without_unorderedackfix` | 4,901 | 33 | `NoPanic`: close in SYN-RECEIVED, ACK at ISS + N/2 |
| `Engine_without_unorderedackfix_refines` | 4,241 | 31 | `Refines`: SND.UNA jumps half the space |
| `Engine_without_barefinfix` | 2,665 | 21 | `Refines` |
| `Engine_without_synsentfinfix` | 529 | 5 | `Refines`: FIN with a bad ACK in SYN-SENT, no RST |
| `Engine_without_finboundsfix` | 12,911 | 78 | `Refines` |
| `Engine_without_secondfinfix` | 42,822 | 218 | `Refines`: a second FIN in CLOSING drops the ACK |
| `Engine_without_timewaitackfix` | 303,884 | 983 | `Refines` |
| `Engine_without_ackbeforeseqinsynreceived` | 1,216 | 10 | `Refines` |
| `Engine_without_challengesyninsynreceived` | 1,046 | 8 | `Refines` |
| `Engine_without_noackdroppedfirst` | 1,200 | 10 | `Refines` |
| `Engine_without_ackcheckedbeforeseq` | 4,975 | 38 | `Refines`: an ACK of unsent data on out-of-window text |
| `Engine_without_ratelimitemptyoutofwindow` | 3,901 | 28 | `Refines`: an empty segment past the window, unanswered |
| `Engine_without_emptyackatrightedge` | 4,574 | 29 | `Refines`: an empty ACK at RCV.NXT+RCV.WND, taken |
| `Engine_without_finatrightedge` | 3,543 | 25 | `Refines`: text that fills the window, then its FIN |
| `Engine_without_openintimewait` | 209,205 | 717 | `Refines`: `listen` from TIME-WAIT |

The trace replay (`RfcTrace.tla`, N = 2^20, Cap = 4, Data = 3): eight seeds
of 2,000 driver steps, 6,229 logged entries in all (679 to 858 a seed),
covering every state, every control, RST and ACK replies, text held past
a hole and the peer's FIN; all eight logs are followed to the end. A log
with one reply's acknowledgment number changed deadlocks at that entry.

## What it leaves out

- **The bounds.** One connection at a time, a receive buffer of two
  octets, one octet to send, segments of at most two octets of text, and
  sequence numbers modulo 8. Every comparison in both models is an offset,
  so the arithmetic is the same at any N; 8 is the smallest that leaves
  room for every kind of value a peer can send: inside the window, behind
  it, ahead of it, and half the space away. The trace replay runs a buffer
  of four octets, three to send and segments of up to four, and the Lean
  vectors the full 32-bit space.
- **What the socket does that the RFC leaves open** is not checked:
  retransmission, RTT and congestion, Nagle, delayed ACKs, keep-alive, the
  zero-window probe's timer, window scaling (the models use a shift of
  0, and nothing here checks a scaled window), the MSS, timestamps and SACK beyond the reading above, segment
  options (MPTCP), and the peer's window (the endpoint may always send).
  `remote_last_seq`, which only retransmission reads, is left out.
- **The listener of the engine.** `TcpLayer` answers SYNs itself with SYN
  cookies and per-peer limits before a socket exists
  (`verification/mptcp/tla/Listener.tla`); this area starts at the socket.
  CLOSED's answer to a segment for no socket is the interface's
  `rst_reply`, modelled only for a LISTEN socket that does not accept.
- **The TIME-WAIT timer's restart** on a retransmitted FIN (3.10.7.4) is
  not modelled; the TIME-WAIT test above checks the ACK.

## After the buffers merge

`comp/buf-tcp` replaces smoltcp's rings with `RxStore`/`TxStore`. The RFC
model does not depend on the buffers; the code model and the replay do.
After the merge, check again:

- `Engine.tla`'s reading of `rx_buffer.len()`, `rx_buffer.capacity()` and
  `rx_buffer.window()` (RCV.NXT, `receive_window_end`, `remember_window`),
  `tx_buffer.len()` (the ACK's length and `ack_of_fin`), and the assert in
  `dequeue_allocated` that `NoPanic` stands for;
- the text path in `Finish`: `add_then_remove_front`, `write_unallocated`,
  the enqueue in `arrived`, and the fix that clears the assembler when a
  FIN is taken (`fin_taken` in `process`);
- `rfc_trace.rs` and `rfc_vectors.rs`, which build sockets and read these
  fields directly; then rerun the configs, the controls, the replay and
  the vectors.

## Running

From `tla/`, with the JDK and `tla2tools.jar` of `~/.cache/adorably-fv`:

```sh
java -Xmx2g -cp tla2tools.jar tlc2.TLC -workers 2 -metadir "$STATES/Engine_base" \
  -config Engine_base.cfg Engine.tla
```

`cargo xtask tcp-rfc-verify trace` (with `JAVA` and `TLA2TOOLS` set) makes
the logs, replays each, and checks that a copy of each log with one reply's
acknowledgment number moved on is refused;
`cargo xtask tcp-rfc-verify lean` and `diff` build the Lean model and
replay its vectors. The tests:

```sh
cargo test -p smoltcp --lib -- socket::tcp::test::
```
