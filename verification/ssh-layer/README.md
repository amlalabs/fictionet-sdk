# SSH as a layer

These finite TLA+ models check the transport/authentication boundary, ordered
key changes, completion ownership, channel lifecycle and the honeypot policy.
The positive Kani harnesses call production Rust arithmetic in
`src/stdlib/services/ssh.rs`. Each model has source references in its header.
These are bounded checks of the specified transitions, not a refinement proof
of all Rust code or a cryptographic proof of SSH.

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
