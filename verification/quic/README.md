# QUIC

The vendored `quinn-proto` engine uses the workspace rustls fork. It is
now wired into a single-connection Fictionet layer. Owned stream writes retain charged
payloads, but engine metadata and the legacy byte APIs are not budgeted. This directory records evidence as that work grows;
it does not claim verification of the whole transport or HTTP/3.

The intended boundary is a layer over the world's datagram carrier, with
typed multiplexed streams and application datagrams above it. The engine
must remain sans-I/O. Directional stream errors, datagram send completion,
ECN, injected time and entropy, and admission before engine allocation are
integration obligations, not properties supplied by vendoring.

## Amplification during connection establishment

`RfcAmplification.tla` states the byte limit from RFC 9000 section 8.1,
independently of packet construction. `Amplification.tla` follows
`Connection::poll_transmit`: reserve a segment, include earlier segments
in the same batch, and account for the bytes when the batch leaves. A
segment includes headers, tags and padding. Building a batch stutters in
the RFC model; handing it over is a send. Validation removes the limit.

The original engine admitted an entire segment whenever one byte of
allowance remained. The regression test received 1200 bytes and observed
3840 sent at MTU 1280. The corrected engine bounds the segment before
construction and checks the entire batch. Strict accounting also exposed
an omitted authentication tag in the first received packet: its size is
now captured before decryption. Small path validation packets remain
possible when amplification credit cannot pay for full padding.

Evidence run on 2026-11-10:

- All 314 vendored library tests passed, including the regression over
  MTUs 1200, 1280, 1400 and 1500, with segmentation both enabled and
  disabled. Each case completes the handshake after checking its first
  flight. Existing migration and three-packet handshake tests pass
  unchanged.
- `Amplification_base.cfg`: refinement and invariants pass, 19,393 states
  generated, 2,185 distinct, depth 15.
- `Amplification_without_wholesegment.cfg` violates `WithinCredit` after
  receiving one unit and reserving four. `Amplification_without_countpending.cfg`
  violates it after reserving two segments whose sum exceeds credit.
- Two Kani harnesses call the production allowance helper with arbitrary
  64-bit counters. They prove exact admission while the prior send count
  is legal, and zero credit when exhausted, including arithmetic near the
  integer limits. Both passed without stubs.

Run Cargo, Kani and TLC under the required scope, with the target directory
outside the worktree:

```sh
export CARGO_TARGET_DIR=/home/souvik/Projects/amlalabs/.fictionet-comp-work/target-quic
systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=14G -p MemorySwapMax=0 cargo test -p fictionet-quinn-proto
systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=14G -p MemorySwapMax=0 cargo kani -p fictionet-quinn-proto --lib -Z stubbing --harness amplification_proofs
```

From `tla/`, run each configuration with the same scope prefix and
`java -XX:+UseParallelGC -Xmx2g -cp "$TLA2TOOLS" tlc2.TLC -workers 2
-metadir <outside-the-tree> -config <configuration> Amplification.tla`.
The base must pass; controls must report the invariant their first line
names.

## Limits of this evidence

The TLA+ model abstracts byte sizes, validation and packet formation. It
does not replay production traces. Kani proves the allowance calculation,
not its callers, cryptography, packet parsing or whole-connection behavior.
The regression runs two vendored endpoints, not an independent peer.
Off-path responses, migration accounting, recovery, stream storage,
HTTP/3 and QPACK still need their own verification. The arithmetic change
allocates nothing; the engine's existing allocations remain outside the
resource claims until the three resource verification layers are added.

## Datagram send completion

`Datagram::with_completion` requests a `DatagramEvent::Sent` after the
local send attempt retires. This includes local drops and is not a claim
of network delivery. The native UDP layer retires sends when handing their
packets below; the socket runner does so after `DatagramSocket::send_to`.
Completions are ordered, consume no receive credit, and pass refused
receive input through the urgent path. Closing cancels outstanding
completions. Callers must request completion only from carriers implementing
this contract; all in-tree datagram transports implement it.

The native layer retains a dropped tracked send in its existing bounded
queue until earlier sends retire. This prevents a later local drop from
completing an earlier packet that is still waiting. The socket runner
keeps one completion inline and offers it before receive input. Neither
path allocates a separate completion queue. Datagram credit admission now
also repays the retained payload to the receiving budget.

`DatagramCompletion.tla` models the ordered queue and completion extraction.
Its base passes safety and progress under weak fairness: 287 generated
states, 160 distinct, depth 8. The controls violate `AfterHandoff` when
completion happens at admission, `OnceInOrder` when extraction fails to
clear pending completions, and `CompletionsProgress` when receive blocking
also blocks completion. The last is a temporal counterexample with a
stuttering suffix. Run these configs as above, with
`DatagramCompletion.tla` as the module.

Production tests cover tracked and untracked empty datagrams, local drops,
completion before credit is granted, exactly-once urgent extraction, a
socket-backed sender waiting for completion before its next send, and
payload ownership after budget refusal. All 4,329 SDK library tests passed
on 2026-11-10. The model does not yet replay production traces or prove
allocation costs; the existing UDP queue storage still has its documented
count limits rather than a heap reservation.

## Directional stream cancellation

`ByteStream<Code>` uses the existing byte, credit, lease and completion
contract, with copyable application errors for `ReceiveReset` and
`SendStopped`, and `ResetSend` and `StopReceive` commands. The default
`ByteStream` has the uninhabited error type, so existing TCP and TLS layers
cannot construct these events. A QUIC application can use the typed
carrier directly; adapting it to the default carrier requires an explicit
policy for directional errors.

`ReceiveReset` follows previously admitted receive bytes. `SendStopped`
passes blocked receive input, without discarding it. Neither is a terminal
child reset. The production `Children` test checks that both retain the
child and that the existing full `Reset` still retires it. A second test
checks error codes, zero-credit cancellation, and shared backing after
splitting a write on the typed carrier.

The Kani harness
`stdlib::layer::proofs::directional_stream_cancellation_keeps_its_code_and_other_direction`
passed over every 64-bit error code, calling the production carrier methods
without stubs. It checks terminal status, urgent routing, credit and code
preservation. It proves the carrier decisions, not a QUIC stream state
machine. It adds no allocation or resource bound.

Compiling this harness required updating stale calls in four existing
verification areas: `ChargedVec::from_charge`, the `Packet` wrapper at
packet-layer entry points, and the HTTP body reader's explicit partial
input flag. No harness was disabled and no assertion was weakened.

The four HTTP pipeline-boundary harnesses passed after that update. The
existing packet-refusal and charged-vector harnesses both exhausted their
14 GiB scopes before returning a verdict; they are not reported as proved.
The host-dispatch harness was compiled but not rerun. These limits do not
affect the separate successful directional-cancellation proof.

The SDK's 4,331 library tests and 1,413 integration tests passed with the
typed carrier. All 302 doctests passed after updating four stale examples
to the merged APIs, including checking the closed-child example for the
intended use-after-move error. The 19 UDP tests passed again after avoiding a scan of
receive-ready sockets when no completion is pending. Clippy with warnings
denied passed; rustdoc completed with its existing redundant-link warning
in `network/udp.rs`. The existing `quic_sparse_reassembly` benchmark ran
at 16 KiB and 64 KiB. This is a baseline for the old codec's reassembler,
not a benchmark of the vendored transport or an interoperability result.

## Connection ID entropy

The endpoint now supplies its RNG to connection ID generators and their
factories, including the client's Initial destination ID provider. The
built-in random and keyed generators no longer consult host entropy. The
keyed generator also rejects every length other than its eight-byte wire
format before slicing the input.

The repeated-seed regression failed before this change: two endpoints
with the same seed produced different local IDs. It now checks successive
IDs, validity under the generator's key, and divergence with another seed.
A second regression checks both routing IDs in emitted Initial packets.
All 317 vendored library tests and three doctests passed. These tests
compare executions and inputs; they do not pin particular random output.

`random_ids_use_the_supplied_bytes` passed in Kani without stubs for every
valid length and arbitrary source bytes. It checks length, content and
entropy consumption. The separate malformed-length harness also passed for
every supported input length and arbitrary key and bytes. The keyed-ID
round-trip harness also passed over arbitrary key and nonce bytes. All
three passed without function stubs after separating the independent
round-trip and malformed-length assertions. The diagnostic
run with stop-on-failure stopped on Kani's internal assertion reachability
check, so it is neither a production counterexample nor proof evidence.

These claims concern connection ID generation, not cryptographic strength,
complete packet determinism or endpoint allocation costs. The endpoint's
reset key, server token keys, TLS provider and calendar time still need
explicit world sources. Standard hash maps also retain their own hash
seeding. Engine storage admission, RFC 9221 and the HTTP/3 coordinator remain
incomplete. The later section describes the first datagram layer and its
application stream multiplexing.

## Retained application send backings

`SendStream::write_chunk` admits Fictionet chunks only after stream and
connection flow control permit a write. It preserves backings already paid
by the receiving budget and uses `Chunk::repay` to transfer other backings. A budget
refusal takes no bytes and has its own error, distinct from peer flow
control. A partial write shares the admitted backing with its remainder.
The send buffer stores the chunk directly alongside its existing byte
buffers; it does not allocate a separate owner wrapper for the chunk.
Charges and leases therefore survive loss and retransmission, prefix ACKs
and out-of-order ACKs, and are released with the final view on ACK or reset.
A shared backing paid elsewhere may be copied by `repay`, with payment first.

The tests check source preservation on budget refusal, physical sharing
on partial admission, payment held through retransmission and partial
ACKs, final release exactly once, and preservation of the final stream
offset on reset. A protected two-endpoint transfer discards the first
outbound flight and then delivers the retransmission, checking both the
received bytes and release of the sender's payload budget. All 321 engine
tests and three doctests passed. These are vendored peers, not independent
interoperability.

`SendBacking.tla` models four payload bytes in a backing of capacity four
or eight, with source and retained views, using the shared `Resources`
store. Its base passes: 174 generated states, 70 distinct, depth 6. The copy-before-payment and early-release
controls both violate `BackingPaid`. Queue and range metadata, packet
recovery and the ordering of arbitrary stream ranges are not modeled here.
Freeing and repayment are separate internal steps so the peak before a
free is checked against its reservation. Run the configs with the same
scope as above and add
`-DTLA-Library=<repository>/verification/resources/tla` to Java.

The Rust source-admission replay uses the shared allocator and `Costs`.
For four payload bytes in a backing of capacity four or eight already paid
by the receiving budget, taking one byte or the whole backing needs no new
allocation. A
refusal by a zero-byte budget also allocates nothing. Each step checks
`peak <= 0` and `requested <= 0 * input + 0`. The caller's paid backing and
budget are built before the measured step; queue insertion is excluded.
A temporary mutation copying into a fresh unpaid chunk failed this bound
on the first step. It was removed, and the unchanged tests passed again.

The spare-capacity case first failed because `Chunk::repay` shrank the
backing during admission. Admission now queries `Chunk::is_paid_by` and
keeps an already-paid allocation unchanged. The bound was not loosened;
all 54 buffer tests and the 321 engine tests pass after the fix. Clippy
with warnings denied passes for the buffer, SDK and engine crates.

Five Kani harnesses retain these same bounds, arbitrary four-byte input
and ownership assertions, with whole and partial admissions at each
capacity and refused admission separated for solver size. They use only the shared allocation stubs. The
shared counter's own allocation-detection harness passed in this crate;
the source-admission runs were stopped without verdicts. The last paid
partial-admission and refused-admission runs each spent more than sixteen
minutes expanding paths, without reaching the solver. They did not hit the
memory cap, and no proof failure or success is inferred from stopping them.
The remaining paid shapes were queued behind the first paid harness and
did not complete either.
Run them with `cargo kani -p fictionet-quinn-proto --lib -Z stubbing
-Z c-ffi -Z mem-predicates -Z restrict-vtable --harness source_proofs` under
the required scope. The ordinary tests, model and counter check do not
substitute for these unfinished proofs.

This is a payload-ownership step. Descriptor capacity, interval nodes,
packet records, receive reassembly, crypto queues and endpoint routing
storage still require admission and resource evidence. The entire engine
must not yet be described as bounded by a Fictionet budget.

## Congestion controller entropy

`ControllerFactory::build` now receives the connection's RNG when a path
is first created or reset, including migration to a new address. BBR seeds
its pacing RNG from it. Cubic and NewReno consume no entropy. A NAT rebind
that retains the previous path's congestion state clones that state
without reseeding it.

The pacing-cycle regression compares two runs with the same seed and a
run with a different seed, and checks the legal cycle positions. Restoring
the host RNG makes the equality assertion fail. A path test checks the
source draws at construction and reset and that cloning a path draws
nothing. All 323 engine library tests and three doctests pass; clippy with
warnings denied and rustdoc pass.

The Kani harness `bbr_uses_supplied_entropy` checks arbitrary seed bytes,
entropy consumption and equality of the complete initialized RNG state
with a generator seeded directly from those bytes. It does not verify the
BBR congestion algorithm or cryptographic properties. Its verdict remains
unfinished: both bundled SAT solvers were tried, and the runs were stopped
without a verdict. A diagnostic variant supplying the same arbitrary seed
one byte at a time also did not complete. The earlier comparison of four
generated samples was replaced by the stronger full-state equality,
without restricting the seed domain. Run it under the required scope with `cargo kani
-p fictionet-quinn-proto --lib -Z stubbing --harness bbr_uses_supplied_entropy`.
The selected harness does not stub production functions; `-Z stubbing`
permits compiling the separate allocation harnesses in this crate.

## Datagram-backed connection layer

`services::quic::QuicLayer` implements `Layer` with
`Datagrams<SocketAddr>` below and
`Mux<ByteStream<VarInt>, Control, Stream>` above. Each stream has its own
receive credit, bounded pending-write queue and directional cancellation.
The adapter reserves its slot and queue storage and output backings before
allocation. Its pending writes use the engine's charged chunk API, so their
backings stay owned across engine backpressure and retransmission. `Written`
means the engine took the bytes, not that the peer acknowledged them.
Generic child closures use an application-supplied error-code policy.

Connection time comes from `Env`, translated using an epoch the caller
supplies. Endpoint entropy is drawn from `Env` after reserving slots.
Crypto provider entropy and calendar time still belong to the supplied
configuration. The adapter does not create an async task or read a socket
or clock. It keeps at most one tracked UDP send outside the layer, accepts
its completion even while receive input is blocked, and closes the lower
carrier after the engine's draining period. Engine notifications continue
to be polled while application receive output is blocked.

The production tests exercise protected bidirectional transfer,
Initial loss and timer-driven retransmission, lower-send completion gating,
directional reset with reverse-direction traffic, independent sibling
receive credit, urgent STOP_SENDING with buffered receive bytes, ownership
and credit preservation on storage refusal, and draining to lower-carrier
closure. Another test keeps a hundred writes queued while reading the
reverse direction, checking progress before the write queue drains. These
use two vendored peers; they are not independent interop.

All 4,340 SDK library tests pass with this adapter on 2026-11-10. Clippy
with warnings denied passes for the SDK library and tests. Rustdoc builds
with the pre-existing redundant-link warning in `network/packet.rs`.

`one_datagram_waits_for_its_completion` passes Kani without function stubs
over eight arbitrary handoff/completion operations and every 64-bit
completion count. It calls the production `Flight` methods and proves
single outstanding ownership, rejection without mutation of invalid
completions, and exact retirement. `LayerFlight_base.cfg` passes safety
and progress under weak fairness: 65 generated states, 46 distinct,
depth 17. Removing the gate violates `OneOutstanding`; blocking completion
on receive input violates the temporal property `Completes`. Run the
configs as above with `LayerFlight.tla`. Run the harness using
`cargo kani -p fictionet --lib -Z stubbing --harness
one_datagram_waits_for_its_completion`, under the same required scope.
These proofs cover the completion gate, not the entire adapter, scheduling,
stream protocol, cryptography or allocations. The TLA+ model is not yet
replayed from production traces.

The adapter is a connection boundary, not a multi-connection listener: a
server accepts one connection on its lower carrier. ECN and local-address
metadata are not present in that carrier, and path MTU discovery is disabled.
Only post-handshake stream data is exposed. Application datagrams, the
HTTP/3 coordinator and handler integration are still absent. The vendored
engine implements QUIC version one, not version two. Engine receive
storage, recovery records, routing and TLS allocations remain uncharged;
the complete three-layer resource evidence is therefore still outstanding.
This is not yet the fully verified QUIC and HTTP/3 build-out.

## Independent peer interoperability

`tests/quic-interop` runs the actual datagram-backed layer against quiche
0.30.1 in both client and server roles. Each test verifies the certificate,
negotiates an application protocol, and exchanges a request, response and
FINs over a bidirectional stream. The peer driver exchanges owned UDP
payloads directly; it opens no sockets. The peer supplies its own entropy
and clock, so these tests do not establish deterministic replay or adverse
network scheduling. They also do not cover HTTP/3 or application datagrams.

The separate test crate keeps its BoringSSL link dependencies out of the
SDK's OpenSSL-using integration binaries. Its eleven tests pass, including
the nine shared adapter regressions. Run `cargo test --locked
-p fictionet-quic-interop` under the scope above. Quiche's libc upper bound
requires libc 0.2.189 in the lockfile; the peer is a development dependency
only. The SDK library also builds for `wasm32-unknown-unknown`, using the
same monotonic-instant type as the engine on that target. Its existing
unused-variable warning in `attach.rs` remains.

After isolating the peer dependency, all 4,340 SDK library tests, 1,413
integration tests and the SSH transport integration test pass. The
`quic_sparse_reassembly` benchmark also runs at 16 KiB and 64 KiB; it still
measures the legacy codec, not this adapter.

## Stream final sizes

The engine accepted a first FIN ending before data it had already received.
The regression first supplies bytes at offsets three through six, then
tries FINs ending at zero through five, both with and without a local
STOP_SENDING. It failed before the fix: the first FIN returned success.
`Recv::ingest` now checks the existing high-water mark before touching
credit, state or reassembly. `Recv::reset` shares the same validation. The
test checks rejection without changing the high-water mark or declaring
a final size, then verifies that a FIN at six is accepted. All 324 engine
library tests pass, as do the adapter and independent-peer tests above.

`RfcFinalSize.tla` states RFC 9000 sections 4.5 and 20.1 independently:
the final size cannot omit accounted data, change once known, or permit
data beyond it. `FinalSize.tla` refines that specification through the
production guard. Its high-water value projects the flow-accounted end,
including the final size declared by reset; it is not always `Recv::end`.
The base passes with 91 generated states, ten distinct states and depth
three. Removing the high-water check violates `WithinFinal`. Ignoring an
already known final size violates `Refines`. The reachability control
violates `NoFinal`, so the base does not pass by preventing final sizes.
Run the four configs as above, with `FinalSize.tla`.

`final_sizes_preserve_received_bytes_and_known_end` passes Kani over
arbitrary 64-bit ends, known final sizes and the FIN bit, without stubs.
It proves both the acceptance conditions and that a rejection has a
conflict. Run `cargo kani -p fictionet-quinn-proto --lib -Z stubbing
--harness final_sizes_preserve_received_bytes_and_known_end` under the
required scope. The separate
`a_short_final_frame_leaves_receive_state_unchanged` harness calls the
full production receive path. Kani 0.68.0 fails while compiling it with
an internal assertion in `kani-compiler/src/intrinsics.rs`; it has no
proof verdict. It remains present and is not replaced by a stub.

The model does not cover data delivery, flow-control limits, allocation,
or forgetting closed streams, and has no production trace replay yet.
The successful Kani proof is of the guard, not those caller properties.
Clippy with warnings denied passes for the SDK, engine and interop crate,
including their tests.

## Sustained transfers under adverse delivery

`sustained_streams_survive_loss_duplicates_and_reordering` sends 128 KiB
in one direction and 96 KiB in the other through the production adapter.
Both exceed the configured stream and connection flow-control windows.
Application receive grants are only 113 and 127 bytes; each delivered
chunk returns exactly its consumed credit. The link drops every eleventh
packet, duplicates every seventh surviving packet, and alternates queue
ends on delivery. Both peers use the same virtual network time for
pacing and recovery, without a host clock or sleeps driving the schedule.

The test checks the complete streams against their supplied inputs,
ordered FIN delivery exactly once, including late duplicates after both
FINs, the exact total of write completions,
and that loss, duplication and reordering actually occurred in each
direction. Dropping the link and both layers returns all adapter budget
charges. This does not measure uncharged engine allocations or prove
congestion behavior. It passes with the existing receive and send windows;
none was raised to make progress. The shared regression also runs in the
isolated interoperability crate, alongside the two independent peers.
All twelve tests in that crate pass. Clippy with warnings denied and the
workspace formatting check pass after adding the regression.

All 302 SDK doctests and three engine doctests pass. Rustdoc builds both
libraries, retaining the pre-existing redundant-link warning in
`network/packet.rs`.

## Datagram wire admission

The engine compared a received datagram's payload plus heap metadata with
its advertised wire limit. A legal frame could therefore close a connection
whose receive storage was small. The new protected-peer regression failed
on that closure before the fix. Storage pressure now drops the datagram
without closing the connection. The frame iterator retains the actual
encoded size, including non-minimal type and length integers, and admission
checks that size against the advertised limit before considering storage.
A disabled or zero-size advertisement rejects every datagram.

All 326 engine tests and three doctests pass. The parser regression covers
both frame forms and wider integer encodings, rejection without queue
mutation, local drops, and successful delivery. Kani's
`datagram_wire_limits_are_independent_of_storage` passes without stubs over
arbitrary machine-sized frame sizes and optional receive windows. It calls
the production guard; it does not prove the parser or queue implementation.

`DatagramReceive_base.cfg` passes with 502 generated states, 70 distinct,
depth four. Both the storage-as-wire and omitted-header controls violate
`WireAdmission`; the reachability control violates `NoDelivery`. The model
covers wire admission, local drops and oldest-first eviction. It does not
replay production traces, count heap storage or establish a resource bound.
Run these configs with `DatagramReceive.tla`, and the Kani harness with the
same commands and scope above.

## Charged application datagrams

The engine's `Datagrams::send_chunk` admits one charged backing into an
inline slot. It allocates no queue descriptor, including for empty
messages, and preserves already-paid spare capacity. A busy slot or a
budget refusal returns without changing the source. The payload remains
charged until packet construction, path-size eviction, explicit discard,
or connection closure. Packet construction copies directly into the
caller's wire buffer; loss does not retain or retransmit the datagram.
The legacy byte-buffer queue remains separate and uncharged. Mixing its
explicit drop mode with the chunk API can evict the chunk.

`recv_chunk` reserves its output before removing a received datagram;
a refusal leaves the next datagram available. This does not charge the
engine's existing receive queue or packet backing. Sending uses the peer's
advertisement, independently of local receive support. A peer limit too
small for an empty frame with a length field makes sending unavailable.

The engine's 331 library tests and three doctests pass. The tests cover
backing identity, spare capacity, empty messages, refusal, path-size
changes, loss without retransmission, receive refusal without consumption,
and one-way negotiation. A new closure regression failed while the
accepted chunk remained retained; connection closure now discards it.

The shared counting allocator and `Costs` measure slot admission for
payload/capacity pairs zero/zero, four/four and four/eight, and refusal
by a zero-byte budget. The caller's input backing and budget are fixtures;
the slot is inline. Each step checks `peak <= 0` and
`requested <= 0 * input + 0`. Temporarily copying into a fresh unpaid
chunk failed the resource bound, including for an empty message; that
mutation was removed. These bounds concern admission of already-paid
backings and refusal, not repayment, wire encoding or the complete engine.

`a_paid_datagram_moves_into_its_slot_without_allocating` retains the same
bounds in Kani over arbitrary four-byte input. It uses the shared
allocation stubs, without stubbing production functions. Its run was stopped after more than fourteen minutes expanding paths,
without reaching the solver or the memory cap. It has no proof verdict;
the ordinary allocation test is not a substitute.
Run it with `cargo kani -p fictionet-quinn-proto --lib -Z stubbing
-Z c-ffi -Z mem-predicates -Z restrict-vtable --harness
a_paid_datagram_moves_into_its_slot_without_allocating` under the required
scope. Receive storage, recovery, TLS, routing and other engine metadata
still prevent any whole-engine resource claim.

## Application datagram carrier

`Control` now carries the connection's `Datagrams<()>` commands and events
alongside its stream controls. These datagrams belong to the connection,
not a QUIC stream. `ReceiveDatagrams` grants credit in whole datagrams,
including empty ones. `DatagramSize` announces the sendable payload limit
after the handshake and when it changes. This carrier uses the charged
engine slot above. Unsupported sends return the original command as
closed; a busy slot or budget refusal returns it as blocked. Oversized
sends are local drops. `DatagramCommand::End` closes the connection with
the supplied generic closure policy, while `ControlCommand::Close` takes
an explicit application error code.

A tracked send remains outstanding through engine serialization and the
lower datagram carrier's completion. It then emits one urgent `Sent(1)`,
including when the lower carrier locally drops its packet. Local size
eviction also retires an attempt. Closure cancels outstanding completions.
Completion does not report peer acknowledgment or application delivery.
Stream receives and datagram receives alternate when both can progress;
queued writes do not give datagrams priority over ready stream data.

The isolated interoperability crate's 20 tests pass. Its four independent
peer tests now cover streams alone and streams with application datagrams,
in both endpoint roles. The datagram cases exchange a nonempty message and
an empty message each way with quiche. Shared layer regressions cover
receive credit, same-backing refusal, unavailable budgets, local size
drops, lower-send completion gating, urgent completion past pending receive
input, and stream reads before queued writes and datagrams drain.

`application_completion_requires_retirement_and_is_taken_once` passes Kani
without stubbing production functions over eight arbitrary completion-state
operations and both tracked/untracked sends. It checks local drops, lower
retirement and exactly-once extraction. It does not prove the scheduler or
that a particular encrypted packet contains a particular datagram.
Run it with `cargo kani -p fictionet --lib -Z stubbing --harness
application_completion_requires_retirement_and_is_taken_once`.

`DatagramSend.tla` models the charged input, inline slot, separately charged
wire output and lower completion. Its base passes: 42 generated states,
28 distinct, depth six. The resource model checks the transient copy while
input and output coexist; freeing and releasing reservations are separate
steps. Copy-on-admission violates `PaidBacking`, premature completion
violates `AfterRetirement`, repeated extraction violates `Once`, and the
reachability control violates `NoReport`. Run its five configurations with
the shared resource library as for `SendBacking`. This model has no
production trace replay and does not cover receive storage, cancellation,
packet recovery or cryptography.

The full receive-path Kani harness was retried unchanged. It still fails
inside the compiler's intrinsic handling before producing a proof verdict.
Restricting virtual call targets and compiling tracing out did not resolve
it. The selected guard proofs and completion proof remain separate from
that unresolved full-path harness.

Application datagrams are now integrated, but this remains an incomplete
QUIC and HTTP/3 build-out. Outstanding work includes whole-engine resource
admission and all three resource evidence layers, the HTTP/3 coordinator
and handler integration, multi-connection listener routing, QUIC version
two, ECN/local-address carrier metadata, and broader transport refinement
and production trace replay. Existing unfinished allocation and BBR proofs
remain unfinished unless a later section records a verdict.

Final Cargo checks for this datagram step pass: 4,347 SDK library tests,
1,413 integration tests, the SSH transport integration test, all 302 SDK
doctests, and the engine and independent-peer suites recorded above.
Rustdoc builds both libraries with the existing redundant-link warning in
`network/packet.rs`. The existing `quic_sparse_reassembly` benchmark runs
at 16 KiB and 64 KiB; it still measures the legacy codec, not throughput of
the new datagram carrier. Clippy with warnings denied and the workspace
formatting check pass.

## Charged datagram receive storage

Received application datagrams now occupy a reusable byte ring, including
inline length words. They no longer retain slices of the decrypted packet
backing or grow a descriptor queue. A regression retains four bytes from a
four-kilobyte packet and checks that receipt releases the packet owner; it
fails against the preceding implementation and passes with the ring.
The configured receive window keeps its conservative per-message allowance,
including for empty datagrams, so oldest-first eviction is unchanged.

`Endpoint::set_datagram_receive_budget` installs a budget in each future
connection before it processes any packets. The arena is reserved lazily,
at the configured receive-window capacity, before the first retained
message. A refusal drops the incoming message locally without changing the
queue or closing the connection. Storage is reused until connection drop.
The engine regressions cover refusal and recovery over protected packets,
and resumed early datagrams with both an available and an empty budget.
`Datagrams::receive_budget` also allows an existing connection to transfer
its arena's charge, with no mutation on refusal. Engine callers that set
neither budget keep the explicitly unbudgeted compatibility behavior.

The counting-allocator replays check initial reservation, a hundred
admissions through wraparound and eviction, allocation-free refusal,
reservation transfer, and the overlap of old and new storage during growth.
The initial and growth steps request at most the configured new capacity;
subsequent admissions request zero bytes. The arena peak is at most its
reservation, including both allocations during reallocation. An intentional
extra byte in the allocation fails both the replay and the Kani allocation
bound; the mutation was removed. Separate tests cover empty datagrams,
receive-output refusal without consumption, unrepresentable capacities,
and complete release on drop.

Three Kani allocation proofs pass with the shared allocation stubs, without
stubbing production functions:

- `receive_ring_reservation_covers_its_allocation`: initial reservation and
  a sixty-four-byte allocation.
- `receive_ring_growth_pays_for_old_and_new_storage`: growth from thirty-two
  to sixty-four bytes within the ninety-six-byte transient reservation.
- `receive_ring_growth_refuses_without_allocating`: the same growth refused
  by a sixty-four-byte budget, preserving the old allocation and charge.

The shared `the_counter_sees_every_allocation` harness also passes. Run
these using `cargo kani -p fictionet-quinn-proto --lib -Z stubbing
-Z c-ffi -Z mem-predicates -Z restrict-vtable --harness receive_ring_`,
under the required scope. These are bounded proofs of the allocation
primitive, not of payload admission or delivery. The separate
`received_datagrams_allocate_only_the_reserved_ring` harness includes
arbitrary four-byte payload admission and reading. It reached propositional
conversion but exhausted the fourteen-gigabyte cap without a verdict.
Reducing CBMC object bits either exhausted that representation or still
reached the memory cap. Its assertions remain intact and it is unfinished.

`DatagramStorage.tla` uses the shared resource store to model reservation,
allocation, reallocation overlap, release, reuse and oldest-first eviction.
The base passes with 479 generated states, 242 distinct and depth twelve.
Missing reservation, forgetting the old allocation during growth, and an
extra payload copy each violate `PaidStorage`; the reachability control
violates `NoDelivery`. Run its five configs with the resource library and
the same scoped TLC command used above. The model does not replay
production traces, prove ring indexing, or include copying to application
output. The old uncharged `recv` output API and the transient decrypted
input packet are also outside this resource claim.

This closes the datagram receive arena's storage gap, not whole-engine
budgeting. Stream reassembly, packet input, recovery records, endpoint
routing, TLS, and other engine metadata still need admission and resource
evidence. HTTP/3, listener routing, QUIC version two and broader protocol
refinement remain outstanding, as do the previously unfinished allocation,
BBR and full stream receive-path proofs.

All 338 engine library tests and three doctests pass after this storage
change. Rustdoc builds the engine and SDK, retaining the existing
redundant-link warning in `network/packet.rs`.

## Layer receive budgeting

`QuicLayer` now supplies its environment budget to the endpoint before
creating a client or accepting a server connection. Its shared layer
regression exhausts that budget after reserving the wire scratch, delivers
a protected application datagram, and checks a local drop without consuming
receive credit. Releasing the reservation does not resurrect the dropped
message; a subsequent datagram consumes the still-available credit. Dropping
the pair returns all adapter and arena charges. The arena remains separate
from application receive credit and the charged copy returned to the caller.

All 21 isolated peer tests pass, including this regression and the four
quiche interoperability cases. All 4,348 SDK library tests, 1,413 integration
tests, the SSH transport test and 302 doctests pass. Clippy with warnings denied and the
workspace formatting check pass. The existing `quic_sparse_reassembly`
benchmark runs at sixteen and sixty-four kibibytes; it still measures the
legacy codec, not the new receive ring or transport throughput.

## Authenticated version information

The rustls adapter now validates received Version Information against the
connection's exact wire version. The parameter decoder checks its length,
rejects zero in either field and duplicate parameters, and requires a
client's Available Versions to include its Chosen Version. A server's list
can be empty or omit the chosen version. Every entry is checked, including
entries after the chosen version. Unknown nonzero versions and repeated
versions within a list remain legal. Malformed input becomes
`TRANSPORT_PARAMETER_ERROR`; disagreement with the connection becomes
`VERSION_NEGOTIATION_ERROR`. Draft wire aliases remain distinct even when
they use the same rustls key schedule.

This is the receive side of RFC 9368 section four for the existing profile,
which never switches versions or retries a failed connection after a
Version Negotiation packet. Missing Version Information is still permitted.
The parameter is not emitted yet, and its list is not retained. The generic
decoder validates its structure; the rustls session also checks the chosen
version. This does not implement compatible negotiation or authenticated
fallback and does not enable QUIC version two. Version-bound session
tickets and tokens, packet mappings and protection, and interoperability
remain prerequisites for enabling that version.

The new unit tests cover list validation, both peer roles, every split of
a three-word list across two input buffers, parameter boundaries and
duplicate parameters. A TLS handshake test feeds peer-supplied parameter
bytes through the production rustls adapter in both roles for version one
and two draft aliases. It checks matching versions, mismatches and zero
versions without changing certificate verification. This is a TLS adapter
test, not independent QUIC version-two interoperability.

The allocation replay parses a list with a thousand and twenty-four
available versions and then a repeated parameter. Its inputs are caller
fixtures. The parser borrows them and keeps only inline state, so every
step has a zero-byte reservation and a linear bound with both coefficients
zero. The conversion of a decoding error into an allocated diagnostic
string is outside that measurement, as are TLS and packet processing.

Two Kani harnesses in `kani/version_information.rs` pass over arbitrary
values for a chosen version, two available versions, the connection version
and the receiving role. The first checks list validation and consumption.
The second checks the body's error classification and zero-allocation bound
with the shared allocation stubs. The shared allocator's sanity harness
also passes. No production functions are stubbed. Run these under the
required scope with `cargo kani -p fictionet-quinn-proto --lib -Z stubbing
-Z c-ffi -Z mem-predicates -Z restrict-vtable --harness
version_information_validates --harness version_information_body --harness
the_counter_sees_every_allocation`.

The separate `version_information_checks_the_connection_without_allocating`
harness calls the entire transport-parameter decoder. It retains its
classification and allocation assertions, but has no verdict. Runs were
stopped while expanding paths through unrelated parameters, before the
solver. A contiguous fixed-shape input and a smaller sufficient unwind
bound did not resolve that expansion. This unfinished harness is separate
from the successful body proofs and the whole-decoder allocation replay.

`VersionInformation.tla` models length checks, scanning all entries,
role-specific validation, the connection comparison and duplicate
detection. Its configurations include controls for each guard, an
uncharged list copy using the shared resource store, and reachability of
acceptance. The model uses two abstract nonzero versions, zero and lists
of up to two entries. It does not model cryptography or replay production
traces. Run its configurations with the shared resource library and the
scoped TLC command described above.

The base passes with 1,760 generated and distinct states, depth six. The
five guard controls violate `Decision`, the copy control violates
`PaidStorage`, and the reachability control violates `NoAcceptance`.

Three scratch mutations were tested and removed. Ignoring the parameter,
as the earlier engine did, fails three regressions, including the TLS
adapter test. Removing the connection comparison fails the Kani assertion
requiring `VersionMismatch`. Copying the body into an uncharged vector
fails the replay on its first step, with 4,100 bytes live against zero,
and fails Kani's `cost.peak <= 0` assertion. The restored body proofs pass
again with unchanged assertions and arbitrary version values.

All 342 engine library tests, 21 isolated layer and interoperability tests,
and three engine doctests pass. Clippy with warnings denied and the
workspace formatting check pass. Rustdoc builds the engine and SDK with
the existing redundant-link warning in `network/packet.rs`. The existing
`quic_sparse_reassembly` benchmark completes at sixteen and sixty-four
kibibytes; it measures the legacy codec, not version validation.
The full QUIC and HTTP/3 build-out remains
incomplete: whole-engine budgeting, HTTP/3 with QPACK, listener routing,
QUIC version two and the previously unfinished proofs still need work.

The unchanged BBR entropy harness was also retried with `-Z restrict-vtable`
under both bundled SAT solvers. Both reached the solver; CaDiCaL was stopped
after more than nine minutes and Kissat after more than five, without a
verdict. A separate run with arithmetic refinement also reached the solver
and was stopped without a verdict. These runs did not exhaust their memory
limits. The arbitrary seed domain and complete RNG-state equality assertion
remain unchanged; this does not close the previously recorded BBR proof gap.

## Version-bound address tokens

The client token-store contract now includes the connection's exact wire
version on insertion and retrieval. `TokenMemoryCache` keeps that version
alongside each token and removes only the first matching token. A miss
preserves tokens from other versions. The existing per-server count limit
covers all versions together, with oldest-first eviction; changing versions
does not multiply the cache limit. Custom `TokenStore` implementations must
adopt the new version argument and enforce that contract.

Retry and NEW_TOKEN protection now authenticates the four-byte wire version
as AEAD associated data. The server supplies the received Initial's version
when opening a token, before considering its payload or consulting the
replay log. A token from a different version leaves the address unvalidated
and does not consume the log entry. Tokens issued by the preceding code,
which authenticated no version, are also rejected; clients can establish a
fresh connection and obtain new tokens. The token's wire length is unchanged.

This supplies the address-token isolation required by
[RFC 9369 section five](https://www.rfc-editor.org/rfc/rfc9369.html#section-5).
It does not enable version two. TLS session tickets still need independent
version binding, alongside packet mappings and protection, outgoing Version
Information and negotiation policy. No rustls files changed in this step.

The protected-peer regression first failed when a connection using a draft
wire alias reused a version-one token. It now makes four connections across
the two versions, checking independent validation and later reuse. Its cache
fixture holds both versions' tokens; a separate test exercises eviction at
the ordinary two-token limit. Other regressions use the production AEAD
with version one, version two and a draft alias, checking both token kinds,
wrong-version rejection, old-token rejection and unchanged replay-log state.
These token-level version-two cases do not exercise a version-two transport.

`TokenVersions.tla` models issuance, two cache slots shared by two versions,
first-match extraction, eviction and server validation of tokens that a peer
can present independently of the honest cache. The base passes with 4,736
generated states, 744 distinct states and depth eight. Omitting the client
check violates `ClientVersion`, omitting server binding violates
`ServerVersion`, retaining a taken token violates `TakenOnce`, and the
reachability control violates `NoValidation`. Run its five configs under
the same scoped TLC command as above. The model assumes authenticated token
versions; it proves neither cryptography nor replay-log behavior and does
not replay production traces or count allocated bytes.

Kani's `token_queue_removes_only_the_first_matching_version` passes without
production stubs. It executes `CacheEntry::take` on two distinct payloads
with arbitrary stored and requested 32-bit versions, including equal
versions. It checks the returned payload, exact remaining length and the
version and payload of every remaining entry. Returned values and the
fixture are left undropped to exclude destructor paths. Run it with
`cargo kani -p fictionet-quinn-proto --lib -Z stubbing -Z restrict-vtable
--harness token_queue_removes_only_the_first_matching_version`, under the
required scope. This is a bounded queue-operation proof, not a proof of
cache hashing, eviction, mutexes, cryptography or the whole connection.

Two broader harnesses remain without verdicts. The full-cache harness was
stopped after four minutes expanding hash-map paths, before the solver.
The repeated-extraction queue harness exhausted the fourteen-gigabyte
scope during propositional conversion, both with default object bits and
with ten object bits. Excluding returned-value destructors did not make
that sequence fit. Their version and extraction assertions remain present
in `kani/token_cache.rs`; the one-step proof does not replace them.

Two production mutations were tested and removed. Restoring empty AEAD
associated data in both sealing and opening fails both server version
regressions. Ignoring the cache's version filter fails its ordinary test
and the one-step Kani assertion about the returned token. The restored Kani
harness passes again with the same arbitrary version domain and assertions.

All 346 engine library tests, three engine doctests, 21 isolated layer and
interoperability tests and 4,348 SDK library tests pass. Clippy with warnings
denied and the workspace formatting check pass. Rustdoc builds both
libraries with the existing redundant link warning in `network/packet.rs`. The existing sparse-reassembly
benchmark runs at sixteen and sixty-four kibibytes; it measures the legacy
codec. The cache remains count-limited, not charged to a Fictionet budget;
adding a version to its descriptors is not a whole-engine resource claim.
Whole-engine budgeting, HTTP/3 with QPACK, listener routing, version two
and the earlier unfinished proofs remain outstanding.

The unchanged BBR entropy assertions were also tried with CBMC's SMT backend
and the installed Z3 solver. CBMC exited during SSA conversion with an
internal `map::at` error, before a solver verdict. An equivalent spelling
using plain boolean assertions had the same result and was reverted. This
is a tool failure, not a production counterexample or a completed proof.

## Finished stream retirement

The connection adapter now retires a stream slot after both directions have
ended and its pending write and directional-stop notifications have been
handed up. The engine continues to own any retransmission state. Retirement
emits `MuxEvent::Closed` without resetting a finished stream.

The protected-peer regression serves thirty-two streams through sixteen
adapter slots, checks receive-end and write-completion ordering before
closure, and checks that no reset was emitted. Removing retirement makes
the test fail at its first missing closure; restoring it passes. The TLS
fixture now accepts an ALPN value for the HTTP/3 interoperability tests.
