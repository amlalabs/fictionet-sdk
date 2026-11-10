# SSH as a layer

These finite TLA+ models check the transport/authentication boundary, ordered
key changes, completion ownership, channel lifecycle and the honeypot policy.
The positive Kani harnesses call production Rust arithmetic in
`src/stdlib/services/ssh.rs`. Each model has source references in its header.
These are bounded checks of the specified transitions, not a refinement proof
of all Rust code or a cryptographic proof of SSH.

## Conformance with the RFCs (2026-11-10)

Four models put the server as written against any client the RFCs allow,
over FIFO links, and check what the RFCs require of both sides. A fifth
counts window adjustments at full scale. Each header names the RFC sections
and the source functions it follows.

| Model | What it checks | Bounds and why |
| --- | --- | --- |
| `Transport.tla` | RFC 4253 sections 6.4, 7, 7.1, 7.3; strict KEX; RFC 8308 section 2.4. Version, KEXINIT both ways, ECDH, NEWKEYS per direction, rekeys started by either side or both at once with data in flight, first_kex_packet_follows with a right or wrong guess, IGNORE. `SequenceAgreement` and `KeyAgreement` (every packet opens under the receiver's own number and key, across wraps and NEWKEYS), `NoApplicationInExchange`, `ExchangeOrder`, `ExtInfoPlacement`, `StrictEnforced`, `NoServerFault`; `ExchangeEnds` and `Established` under fairness. | Sequence numbers modulo 4, so every run wraps; one rekey started by each side; two application packets each way; one IGNORE and one guess. |
| `Auth.tla` | RFC 4252 sections 5, 5.1, 5.3, 7; RFC 4256 section 3. Pipelined requests of every kind, partial success, delayed failure, probes, signatures that do not verify, keyboard-interactive, connection messages before and after success. `AnsweredInOrder`, `NoServiceBeforeSuccess`, `NoSuccessWithoutProof`, `NoServerFault`; `RequestsAnswered`. | Three requests, below `max_attempts`; user and service names fixed (a change is a disconnect the RFC allows). |
| `Close.tla` | RFC 4254 sections 5.1, 5.3, 5.4, 6.10. One OPEN_CONFIRMATION or OPEN_FAILURE per open with the cause's reason code (limit, declined or refused: 1; failed before confirmation: 2; no memory for the opening or the child: 4); data, requests with and without want_reply, EOF and CLOSE from both sides, including what the client sent before it had the server's CLOSE. `OneOpenReply`, `ReasonCode`, `NothingAfterClose`, `NoDataAfterEof`, `RepliesSolicited`, `NoServerFault`; `CloseAnswered`. | One channel; two data packets and two requests from the client, two data from the server. Windows are `Channel.tla`'s and `Window.tla`'s subject. |
| `Window.tla` | RFC 4254 section 5.2 on echo channels against russh 0.64: one loop that pushes every channel message into a queue of `channel_buffer_size` places and sends nothing while a push waits. The client of `full_windows_on_open_channels_finish_with_an_adjustment_per_half_window` (all channels open, then each sends a full window and EOF before it reads) and one that reads while it sends. `ReceiveWindow`, `WindowAccounting` (what the peer may send equals what it was told, less data on the way, plus adjustments on the way), `AdvertisedWithinCredit`; `AllClosed` (no stall) under fairness. | Batch: 2 channels, window 4, 4 one-unit packets each, queue 8. Reads: 1 channel, window 2, 4 packets (so adjustments are needed), queue 2; two channels did not finish in 24 minutes. The queue is scaled with the window; see Adjust. |
| `Adjust.tla` | The adjustments one channel sends while its peer sends one full window, over every order of consuming, the child taking (with any lag) and adjusting. `Few` (at most floor(log2 W) + 1), `NeverDry` (at zero room left, any room owed is due), `WithinCredit`. | Full scale: W = 64 units of 1 KiB, the server's 64 KiB window and the test's packets. |

So the half-window policy (df905b036) sends at most 7 adjustments per 64 KiB
window whatever the child's timing, and some order reaches 7. With the exec
reply and 64 echoes that is 72 messages per channel, under russh's 100; the
per-packet policy it replaced sends 64, which with the echoes is 129. Each
channel's queue is its own and the batch client reads a channel's queue only
after it has sent on it, so the bound holds for any number of channels;
`Window_batch` checks two. `Window_tight` shows the scaled bound is exact
(queue 7 stalls), and `Window_perpacket` that the old policy stalls with the
queue the new one needs. A client that sends more than one window before it
reads gets one echo per packet, so its queue fills whatever the adjustment
policy; that is outside what any server can promise.

| Baseline | Generated | Distinct |
| --- | ---: | ---: |
| `Transport_base` (strict, ext-info-c) | 190,337 | 74,659 |
| `Transport_loose` (neither) | 126,452 | 45,007 |
| `Transport_inject` (`StrictEnforced` only) | 178,268 | 71,038 |
| `Auth_base` | 84,922 | 30,986 |
| `Auth_badhandler` (a handler that accepts unverified signatures) | 89,313 | 32,274 |
| `Close_base` | 892,058 | 261,598 |
| `Window_batch` | 700,230 | 239,048 |
| `Window_reads` | 46,275 | 16,477 |
| `Adjust_base` | 106,087 | 51,907 |

Controls. Each must fail the named property and did:

| Configuration | Mutation | Fails |
| --- | --- | --- |
| `Transport_reset` | reset sequence numbers at NEWKEYS without strict KEX | `SequenceAgreement` |
| `Transport_keep` | keep them under strict KEX | `SequenceAgreement` |
| `Transport_sendinkex` | `write_packet` while the server's KEXINIT is out | `NoApplicationInExchange` |
| `Transport_strictlax` | no strict checks; the client sends IGNORE during the initial exchange | `StrictEnforced` |
| `Transport_noguess` | handle a wrongly guessed ECDH_INIT | `NoServerFault` |
| `Transport_extrekey` | EXT_INFO after every exchange | `ExtInfoPlacement` |
| `Auth_nowait` | the code before cca5c2ae2: take a request while a failure waits | `NoServerFault` |
| `Auth_strictsig` | the code before cca5c2ae2: disconnect on a bad signature the handler rejected | `NoServerFault` |
| `Auth_trustsig` | let a handler's Accept of a bad signature through | `NoSuccessWithoutProof` |
| `Auth_deliver` | pass a connection message on before success | `NoServiceBeforeSuccess` |
| `Auth_answerafter` | answer requests after SUCCESS | `AnsweredInOrder` |
| `Close_latefault` | the code before cca5c2ae2: fail on data or a request after our CLOSE | `NoServerFault` |
| `Close_allone` | the code before 96688e01c: reason 1 for every refusal | `ReasonCode` |
| `Close_replyafter` | answer a request after our CLOSE | `NothingAfterClose` |
| `Close_doubleclose` | answer CLOSE after sending one | `NothingAfterClose` |
| `Window_perpacket` | the per-packet adjustment policy | `AllClosed` |
| `Window_tight` | queue 7 | `AllClosed` |
| `Window_never` | no adjustments | `AllClosed` |
| `Window_over` | advertise one unit more than owed | `AdvertisedWithinCredit` |
| `Adjust_perpacket` | the per-packet adjustment policy | `Few` |

Coverage configurations must fail their predicate, which shows the runs the
baselines rely on exist: `Transport_coverage`, `_coverage_strict` and
`_coverage_wrong` (a quiet end after a rekey started by each side, all data
both ways, a right or a wrong guess, an IGNORE), `Auth_coverage` (success
after three pipelined requests), `Close_coverage` (data and a request with
want_reply arrive after the server's CLOSE), `Adjust_coverage` (7 is reached).
All did.

`Transport_pending` is a known departure, not a control: see below.

### Tied to the code

* `src/stdlib/protocols/ssh/transport/replay.rs` replays the coverage traces
  in `traces/` (TLC's action names, one per line, regenerated with the
  command below) on the production `Transport`, step for step, against a
  client written from the RFCs with real X25519, ChaCha20-Poly1305 and Ed25519.
  Every server packet must open under the client's own sequence number and
  key, the server must sign the exchange hash the client computed, and the
  model's order, EXT_INFO and §7.1 checks are made on the bytes. Without
  strict KEX the sequence numbers start at `u32::MAX - 1` and wrap. The
  `inject` trace must be refused at the injected IGNORE. With the incoming
  sequence number reset at every NEWKEYS the replay fails at step 18.
* `a_full_window_brings_at_most_seven_adjustments_in_any_order`
  (`src/stdlib/services/ssh/tests.rs`) is `Adjust.tla` on the production
  `Channel`: an exhaustive search of every order, with `consume_receive`,
  `adjustment` and the credit `on_command` adds, gives at most 7 and reaches 7,
  never owes room to a peer with none, and never advertises past the credit.
* `lean/Adjust.lean` proves, for every u32 and u64 value, the facts the
  bounded models rely on: consuming and crediting keep advertised within
  receive, an adjustment tells exactly the credit and never overflows, a peer
  with no room hears of any room owed, each adjustment at least doubles what
  the peer may send, and none is due while the peer has more than half the
  credit. Core Lean 4.35, `omega` only; axioms `propext`, `Classical.choice`
  and `Quot.sound`.
* The Auth and Close models are tied by the three tests below, each run
  against the code before the fix.

### Departures found

Fixed in cca5c2ae2, each with a test that fails on the code before:

* Data, a request or EOF the peer sent before it had our CLOSE failed the
  connection and every sibling channel (RFC 4254 section 5.3). Now dropped,
  with no reply on the closed channel.
  `what_the_peer_sent_before_our_close_arrived_is_dropped`.
* A USERAUTH_REQUEST that arrived while an earlier failure waited out its
  delay failed the connection (RFC 4252 section 5 lets a client send
  requests without waiting). Nothing more is read until the delayed FAILURE
  is out. `a_request_sent_before_the_last_failure_waits_for_it`.
* A signature that did not verify ended the connection even when the handler
  rejected it (RFC 4252 section 7: answer with FAILURE). A handler that
  accepts an unverified signature still ends it.
  `a_signature_that_does_not_verify_is_answered_with_failure`.

Reported, not fixed:

* **Packets during a server-initiated rekey.** Between the server's KEXINIT
  and the client's, the client may go on sending application messages
  (RFC 4253 section 7.1). `progress` keeps them in `pending_packets` while
  rekeying and fails the connection past 128 packets or 256 KiB. A client
  with several channels' windows in flight, or one sending small packets,
  can pass that. `Transport_pending` shows it with a cap of one. It is reached
  only after `needs_rekey` (half a GiB or 2^29 packets on one key). Handling
  them during the exchange would need replies to wait for the new keys.
* **Unknown channel types are refused with reason 1.** `SessionLayer`
  answers `Accept(false)` for a type it does not run, which becomes
  ADMINISTRATIVELY_PROHIBITED; RFC 4254 section 5.1 has
  UNKNOWN_CHANNEL_TYPE (3) for it. `ChannelCommand::Accept` carries no reason,
  so this is an API change.

### Not covered

Algorithm negotiation beyond the guess, key derivation inputs other than the
X25519 path the replay uses, AES-GCM in the replay, DISCONNECT, rekeys driven
by the real `needs_rekey` limits, user or service name changes, the
`max_attempts` disconnect, X11 and agent forwarding, global requests,
`exit-signal`, server send windows smaller than the echo (the output limit
and the client's window are taken as never binding in `Window.tla`), and two
channels in the reading-client configuration. The models are hand-written
from the code; only `Transport.tla` (by replay) and `Adjust.tla` (by the
exhaustive test) are run against it.

Rerun one configuration as below (from `tla/`), one at a time:

```sh
systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=3G \
  -p MemorySwapMax=0 ~/.cache/adorably-fv/jdk/bin/java -Xmx2g \
  -cp ~/.cache/adorably-fv/tla2tools.jar tlc2.TLC -workers 2 \
  -metadir <dir outside the tree> -config Transport_base.cfg Transport.tla
```

Regenerate a trace by running its coverage configuration and keeping the
action names: `... -config Transport_coverage.cfg Transport.tla | grep -E
'^State [0-9]+: <' | grep -v 'Initial predicate' | sed -E 's/^State [0-9]+:
<([A-Za-z]+).*/\1/' > ../traces/loose.txt` (`_coverage_strict` gives
`strict.txt`, `_coverage_wrong` `wrong.txt`, `Transport_strictlax`
`inject.txt`). Check the Lean file with `lean lean/Adjust.lean`.

## Properties and negative controls

Every row has a passing baseline and a mutation configuration that must fail
**the named invariant**, not parsing, deadlock, an unrelated assertion or a
resource limit. Configuration names below are relative to `tla/` and include
`.cfg`. Each baseline checks every invariant of its module.

| Baseline | Property | Mutation configuration | Why the mutation fails |
| --- | --- | --- | --- |
| `Boundary_base` | `Authenticated` | `Boundary_authentication` | Deliver a connection open before authentication succeeds. |
| `Boundary_base` | `Negotiated` | `Boundary_failure` | Deliver queued application input after fatal negotiation failure. |
| `Boundary_base` | `Negotiated` | `Boundary_rekey` | Deliver queued application input while rekeying. |
| `Boundary_base` | `FactoryAfterOpen` | `Boundary_factory` | Construct an application child before an authorized open. |
| `Epoch_base` | `EpochOrder` | `Epoch_install` | Decode the packet after NEWKEYS before installing its incoming epoch. |
| `Epoch_base` | `OutgoingOrder` | `Epoch_fifo` | A later encoded packet overtakes the head of the output queue. |
| `Completion_base` | `Fence` | `Completion_fence` | Credit plaintext after only part of its encoded flight completes. |
| `Completion_base` | `Exact` | `Completion_take` | Leave an emitted credit pending and count it again. |
| `Completion_base` | `WireConservation` | `Completion_count` | Count two delivered bytes for one byte removed from a flight. |
| `Channel_base` | `ReservedBeforeConfirmation` | `Channel_reserve` | Confirm an accepted child before receive backing is reserved. |
| `Channel_base` | `ReceiveWindow` | `Channel_receive` | Consume data after the advertised receive window is exhausted. |
| `Channel_base` | `AdvertisedCapacity` | `Channel_advertise` | Advertise one byte more than the reserved receive credit. |
| `Channel_base` | `SendWindow` | `Channel_send` | Send without sufficient peer window or granted command credit. |
| `Channel_base` | `DirectionalEof` | `Channel_inputeof` | Deliver data after peer EOF. |
| `Channel_base` | `DirectionalEof` | `Channel_outputeof` | Send data after local EOF. |
| `Channel_base` | `EofOnce` | `Channel_eofonce` | Send EOF twice. |
| `Channel_base` | `Retired` | `Channel_retire` | Keep the application child alive after local close. |
| `Channel_base` | `NoTimer` | `Channel_timer` | Retain a child timer after retirement. |
| `Channel_base` | `NoWork` | `Channel_work` | Retain child work after retirement. |
| `Honeypot_base` | `NeverExecute` | `Honeypot_execute` | Execute a submitted line, exec or subsystem request instead of hanging up. |
| `Honeypot_base` | `StopInput` | `Honeypot_gate` | Invoke another application input callback while draining. |

All five baselines passed and all twenty-one negative configurations violated
the invariant named above. TLC used four workers and a 6 GiB Java heap.

| Baseline | Generated states | Distinct states |
| --- | ---: | ---: |
| `Boundary_base` | 132 | 57 |
| `Epoch_base` | 388 | 168 |
| `Completion_base` | 387 | 216 |
| `Channel_base` | 3,734 | 2,316 |
| `Honeypot_base` | 9 | 9 |

## Model boundaries

* **Boundary** has at most two queued opens and two deliveries. Authentication
  succeeds only when transport negotiation is established. Failure is terminal;
  rekey can begin and finish repeatedly. Auth rejection, probes and invalid
  signatures do not set authenticated state. Signature checking and encryption
  are assumptions supplied by the standard transport and authentication code,
  with real-client regression coverage. The application factory follows an
  authorized open. The **transport** factory intentionally runs at arrival,
  before negotiation, with a `transport::Opening` (connection, budget and
  deadlines); it is not the application factory. See `Server::with_transport`,
  `WithTransport::serve` and `tests/ssh_transport.rs`.
* **Epoch** checks three data packets separated by two NEWKEYS boundaries.
  Incoming decoding and outgoing queue delivery interleave independently.
  NEWKEYS is decoded using the old key, and installation precedes the next
  decode. Outgoing encoding is synchronous; the carrier preserves the packet
  order, including old-key packets already queued when keys change. This does
  not prove cipher correctness, sequence-number cryptography or key derivation.
* **Completion** has up to three two-byte flights, each carrying either zero
  control credit or one application credit. One-byte completions exercise
  partial delivery. Removing a flight creates its credit once; taking a
  notification consumes it once. Retirement explicitly accounts for discarded
  notifications, including completions arriving afterward. Carrier completion
  amounts are valid; the Rust regression also checks excess completion errors.
* **Channel** has one child, a two-byte receive reservation, up to three total
  peer-granted send bytes and up to three receives. Returned receive credit
  reflects release of retained data, not merely delivery to the child. EOF in
  either direction leaves the opposite direction open. Local or peer close
  retires the application, timers and work; a wire tombstone can remain until
  the peer acknowledges local close. The model treats routing of terminal reset
  through `Children` atomically. It relies on the foundation's owner cancellation
  and generation checks; it does not re-prove the runtime scheduler or isolation
  between siblings. Those are modeled under `verification/layer`.
* **Honeypot** abstracts terminal parsing into empty/edited lines and interrupts
  (prompt again), or nonempty line/EOF/error/exec/subsystem (hang up). It checks
  no execution and no further application callbacks. Echo and prior output may
  drain; window adjustments remain allowed. It does not claim eventual TCP
  close if a peer never replenishes a zero window. The terminal editor and real
  demo policy have their own Rust tests.

`CHECK_DEADLOCK FALSE` permits completed bounded traces. There are no fairness
assumptions or liveness claims. Resource refusal, arbitrary packet parsing,
cryptographic failure details, memory allocation and transport implementations
that violate `PacketTransport`'s documented contract are outside these models.

## Rust arithmetic

The positive harnesses are compiled as a child module of `ssh` under `cfg(kani)`.
They exercise production methods, not copied positive models:

| Harness | Scope | Negative harness |
| --- | --- | --- |
| `ssh_receive_window` | Full-width receive and advertised windows, arbitrary packet length, confirmation/EOF/close gates; exact subtraction or unchanged refusal. | `ssh_receive_without_bound`: the same subtraction without its guard, written in the harness (`wrapping_sub`), not `consume_receive`. |
| `ssh_send_window` | Full-width peer window, command credit and packet bound; exact subtraction or unchanged refusal after EOF/close. | `ssh_send_without_bound`: the same subtraction without its guard, written in the harness (`wrapping_sub`), not `consume_send`. |
| `ssh_output_buffer` | All reachable byte counts through the output limit and arbitrary `usize` input length; admission never overflows or exceeds the buffer, and exit refuses writes. | `ssh_output_without_count` calls `next_bytes` and subtracts the increment from its result in the harness; `ssh_output_without_limit` is the unguarded addition written in the harness (`wrapping_add`); `ssh_output_without_exit` asserts that an open buffer refuses an empty write. |

The negative harnesses are arithmetic written out in `kani/mod.rs`, or
assertions the production code is right to fail; none calls `consume_receive`,
`consume_send` or `next_bytes` with a guard removed. They show that the guards
matter, not that Kani would catch their removal from `ssh.rs`. A mutation of
`ssh.rs` itself has not been run against the positive harnesses.

The buffer proof calls `Output::next_bytes`, which `Output::push` uses before
allocation and commits only after reservation succeeds. It assumes the existing
byte count is within the buffer limit and abstracts previously queued storage.
It does not prove the allocator, the item-count bound, or concurrent budgets.
An initial attempt to prove allocated output queues did not complete; the final
proof isolates the requested arithmetic and leaves allocation paths to Rust tests.
The positive receive, send and buffer harnesses passed 95, 95 and 103 checks
respectively using Kani 0.68.0 and CBMC 6.11.0. Each negative harness fails only
its intended arithmetic or admission assertion.
Negative arithmetic harnesses are intentionally failing, separately selected
harnesses; do not run every SSH harness expecting overall success.

## Implementation corrections and tests

Local `ChannelCommand::Close` previously sent wire close without retiring the
application child until the peer replied. It now sends the same terminal reset
used by channel reset, allowing `Children` to cancel its owner and drop its
queues, timers and work immediately. The wire channel remains until peer close
so the close handshake is still accepted. Commands from that retired child are
ignored, just as commands for a removed child are ignored.

A repeated local EOF previously emitted another EOF. It now returns a protocol
state error without emitting another packet. The close and EOF regressions were
run with the original behavior restored: both failed at their intended
assertions, while the authentication/reservation and completion tests passed.
The fixes were then restored.

`src/stdlib/services/ssh/tests.rs` also checks that unauthenticated opens cannot
create children, confirmation waits for receive credit, partial ciphertext
completion cannot credit plaintext, and excess completion cannot credit twice.
The existing real-client tests cover authentication probes/signatures, rekey,
window backpressure, siblings, subsystems, stderr and connection shutdown policy.

## Validation results

Checked on 2026-11-08, under the requested 12 GiB systemd memory cap and no
swap, with six Cargo build jobs:

* TLC: five positive configurations passed; all twenty-one mutations failed
  their named invariants. The state counts above are from the final models.
* Kani: all three positive harnesses passed; all five negative harnesses failed
  exactly one intended assertion each, with no failed arithmetic safety checks.
* Rust: fourteen SSH unit tests, one custom-transport integration test, three
  honeypot policy tests and eleven child-runtime tests passed.
* `cargo clippy` for the core library and `cargo doc --no-deps`, both with
  warnings denied, passed. Formatting and `git diff --check` passed.
* `cargo bench --profile dev --bench decoders -- ssh_algorithm_selection`
  completed both cases (100 iterations each): median 5.496 ms for 12,500 names
  and 22.73 ms for 50,000 names. This is a dev-profile smoke benchmark, not a
  release-performance comparison.

The two regression tests were also run with the old implementation restored:
local close failed at the missing terminal-reset assertion, and repeated EOF
failed because the second command returned success. Neither test was weakened.

## Rerun

Run from the repository root. Keep state and build directories outside `/tmp`.
The following are commands to invoke the existing tools, not a separate checker.

```sh
export CARGO_TARGET_DIR=/home/souvik/Projects/amlalabs/.fictionet-comp-work/target-vssh
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_BUILD_JOBS=6

systemd-run --user --scope -p MemoryMax=12G -p MemorySwapMax=0 \
  ~/.cache/adorably-fv/jdk/bin/java -Xmx6g \
  -cp ~/.cache/adorably-fv/tla2tools.jar tlc2.TLC -workers 4 \
  -metadir /home/souvik/Projects/amlalabs/.fictionet-comp-work/vssh-states \
  -config Channel_base.cfg verification/ssh-layer/tla/Channel.tla
```

Substitute every configuration in the table and its matching module. Baselines
must exit successfully with no error; mutations must report the named invariant
violation. A parse error or resource termination is not a successful negative
control.

```sh
systemd-run --user --scope -p MemoryMax=12G -p MemorySwapMax=0 \
  cargo kani -p fictionet --harness ssh_receive_window \
  --harness ssh_send_window --harness ssh_output_buffer

systemd-run --user --scope -p MemoryMax=12G -p MemorySwapMax=0 \
  cargo kani -p fictionet --harness ssh_receive_without_bound
systemd-run --user --scope -p MemoryMax=12G -p MemorySwapMax=0 \
  cargo kani -p fictionet --harness ssh_send_without_bound
systemd-run --user --scope -p MemoryMax=12G -p MemorySwapMax=0 \
  cargo kani -p fictionet --harness ssh_output_without_count
systemd-run --user --scope -p MemoryMax=12G -p MemorySwapMax=0 \
  cargo kani -p fictionet --harness ssh_output_without_limit
systemd-run --user --scope -p MemoryMax=12G -p MemorySwapMax=0 \
  cargo kani -p fictionet --harness ssh_output_without_exit

systemd-run --user --scope -p MemoryMax=12G -p MemorySwapMax=0 \
  cargo test -p fictionet --features tokio --lib stdlib::services::ssh
systemd-run --user --scope -p MemoryMax=12G -p MemorySwapMax=0 \
  cargo test -p fictionet --features tokio --test ssh_transport
systemd-run --user --scope -p MemoryMax=12G -p MemorySwapMax=0 \
  cargo test -p honeypot-world ssh::tests
systemd-run --user --scope -p MemoryMax=12G -p MemorySwapMax=0 \
  cargo test -p fictionet --features tokio --lib stdlib::layer::children
systemd-run --user --scope -p MemoryMax=12G -p MemorySwapMax=0 \
  cargo clippy -p fictionet --features tokio --lib -- -D warnings
systemd-run --user --scope -p MemoryMax=12G -p MemorySwapMax=0 \
  env RUSTDOCFLAGS='-D warnings' cargo doc -p fictionet --no-deps --features tokio
systemd-run --user --scope -p MemoryMax=12G -p MemorySwapMax=0 \
  cargo bench -p fictionet --profile dev --bench decoders -- ssh_algorithm_selection
systemd-run --user --scope -p MemoryMax=12G -p MemorySwapMax=0 \
  cargo fmt --all -- --check
```

Delete `CARGO_TARGET_DIR` after all commands have completed.
