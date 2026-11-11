# QUIC

The vendored `quinn-proto` engine uses the workspace rustls fork. It is
wired into both a single-connection layer and a shared datagram listener.
Owned stream writes retain charged payloads, but engine metadata and the
legacy byte APIs are not budgeted. This directory records evidence as that work grows;
it does not claim verification of the whole transport or HTTP/3.

The current server composes HTTP/3 and static QPACK over `QuicLayer` into
the SDK's existing web handlers, with independent quiche interoperability.
The shared listener also serves these handlers through a world host UDP
socket, tested with several independent quiche connections at once. See
[Shared datagram listener](#shared-datagram-listener) for the latest boundaries.
Wire input now retains reservations through packet and frame ownership;
see [Reserved reassembly storage](#reserved-reassembly-storage) for the latest
resource evidence and the acknowledgment admission fix. Earlier sections record the state at each step. QUIC version two and
version negotiation are implemented; see [QUIC version two](#quic-version-two).
Remaining priorities are whole-engine budgeting, proofs of the version-two
code and unresolved proofs.

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

## HTTP/3 handlers over QUIC streams

`web::httpd::Http3` now implements a server connection with `Quic` below
and `Mux<HttpExchange, Top, Opening>` above. `Responder::http3` composes it
with the existing `Respond` children. A stack is
`Chain::new(quic_layer, responder.http3())`; the caller configures its QUIC
TLS server to negotiate `h3` and supplies connection metadata through
`Responder::conn`. The stack still serves one connection. Shared UDP
listener routing and its world-host integration are the next build-out step.

The coordinator opens the control and both QPACK streams, sends SETTINGS,
and enforces peer critical-stream uniqueness, SETTINGS ordering and critical
stream closure. The QPACK profile advertises zero dynamic-table capacity
and zero blocked streams. Static references, literal fields and Huffman
strings work in both directions, including sensitive field marks. Dynamic
insertions that exceed that capacity fail the connection. No dynamic
references or section acknowledgments can arise in this profile. Dynamic
compression, blocked-section scheduling, server push and extended CONNECT
are not enabled.

Requests use the existing HTTP/3 message validator, including content-length
and trailer ordering. Their retained fields become the same charged head
carrier used by HTTP/2, with HTTP/3 version metadata and cookie joining.
Bodies reach independently credited exchange children. Trailers wait for
FIN and final content-length validation before completing a request. The
shared handler adapter supplies body limits and deadlines, asynchronous
replies, streamed responses, body suppression, virtual-host routing and
delivery observations. Header and stalled-write deadlines use `Env` time.
Request cancellation and malformed-message errors retire one exchange;
framing, compression and critical-stream errors close the connection.

One output frame per stream remains owned until all its pieces have been
handed to QUIC and their local write completions received. Response body
credit is returned at that completion. Completion accounting runs in the
event handler and its notification uses the urgent path, including while
request input is blocked. GOAWAY rejects requests at or above the admitted
cutoff, permits lower identifiers arriving out of order and drains admitted
exchanges. It leaves the transport open for retransmission until peer closure
or the configured QUIC idle timeout: local write completion means the engine
accepted bytes and cannot justify dropping queued response data. The public
exchange carrier now preserves HTTP/3 application error codes in its closure
event.

A peer granting only two unidirectional streams initially stalled the
coordinator behind its third open command. The new generic
`ControlCommand::OpenOrClose` permits an application to require a stream or
close with its own error when peer stream credit or adapter slots are
exhausted. HTTP/3 uses `H3_STREAM_CREATION_ERROR`. The independent regression
fails on the prior blocking open and passes with this command.

Independent interoperability uses quiche's HTTP/3 implementation and
BoringSSL, with certificate verification enabled and `h3` negotiated. Each
of two runs serves forty POST requests, four concurrently, with twenty
thousand body bytes each, through sixteen adapter slots. One returns
collected responses; the other polls streamed responses through `Pending`
and sends request and response trailers. The tests check exact echoed
bytes, status, content length policy, split-cookie joining, HTTP/3 metadata,
trailers and all forty delivery observations. Packets cross the SDK's
`Datagrams<SocketAddr>` carrier in memory; this is not a host UDP-listener
test. The existing QUIC loss, duplication, reordering and both-role
interoperability tests also pass; no HTTP/3-specific lossy replay is claimed.

Eighteen coordinator regressions cover fragmented critical prefixes,
duplicate critical streams, FIN and reset, missing and repeated SETTINGS,
forbidden dynamic capacity and push streams, ignored unknown streams,
sibling progress under receive backpressure, trailer and length validation,
directional cancellation, empty DATA before FIN, both deadlines, GOAWAY
cutoffs, sensitive field marks, storage refusal and completion through a
blocked receive event.

`Http3Critical.tla` models critical-stream lifetime, completion arithmetic
and connection-slot reservation order. The base passes with 261 generated
states, 168 distinct states and depth seven. Its four controls violate
`OneOfEach`, `CriticalOpen`, `PaidStorage` and `CompletionOwned` respectively.
The resource store also checks `WithinLimit` and `Tracks`. Allocation size
is one abstract slot-store unit; it is not a byte bound on the codecs or
whole coordinator. The model does not replay production traces or prove
handler scheduling, message validation, QPACK compression or cryptography.
Run the configurations with the scoped TLC command and shared resource
library described above, with `Http3Critical.tla` as the module.

Two Kani harnesses call the production `Critical::accept` and
`Sending::complete` methods. Critical-stream admission passes over six
arbitrary type choices, arbitrary unknown and push identifiers, and a
zero-allocation bound using the shared counting stubs. Completion passes
for arbitrary sixty-four-bit flight counts, completions and body counts,
with either no unsent bytes or one arbitrary unsent byte. It checks
excess-completion refusal without mutation, exact retirement and that
unsent bytes prevent completion. The shared allocator sanity harness also
passes. No production functions are stubbed. Run under the required scope:

```sh
cargo kani -p fictionet --lib -Z stubbing -Z c-ffi -Z mem-predicates \
  -Z restrict-vtable --harness http3_critical_types \
  --harness http3_write_completion --harness the_counter_sees_every_allocation
```

The separate `http3_refuses_connection_storage_before_allocating` harness
has no verdict. It was stopped after more than three minutes expanding
budget, mutex and destructor paths before solving. Its assertions remain;
the successful replay does not substitute for this allocation proof.

The allocation replay constructs the production coordinator and admits its
connection event with a zero-byte budget and a sufficient budget. The two
slot stores are reserved before allocation. Every measured allocation must
fit the actual reservations; there are no input bytes, and the fixed costs
are those charged slots. This covers initial connection storage only.
Input buffers, request fields and output payloads carry budget charges;
the allocating frame and QPACK codecs run under a conservative temporary
reservation. Per-chunk backing metadata and complete codec cost bounds,
including linear copying across fragmented input, still need resource
proofs and replays. Whole-engine budgeting remains unfinished.

Two scratch mutations were tested and removed. Omitting the critical-type
duplicate check fails the Kani decision assertion. Allocating the initial
channel slots against an unrelated unlimited budget fails the resource
replay: 4,824 bytes live against zero charged. Restoring both changes passes
the unchanged checks again. These controls add no test-only production path.

Validation on this step: all 4,368 SDK library tests, including the eighteen
coordinator regressions, and 1,413 integration tests passed. The isolated
layer/interoperability suite passes all 27 tests. All 302 SDK doctests pass.
Clippy with warnings denied and rustfmt pass. Cargo doc succeeds with the
pre-existing redundant-link warning in `network/packet.rs`. The decoder
benchmark ran the QPACK long-instruction cases at both configured sizes;
this is not an HTTP/3 server throughput measurement.
No rustls files changed. Remaining build-out priority is listener
routing, whole-engine budgeting, version two, then the previously
unfinished proofs. A full HTTP/3 client/proxy and optional dynamic QPACK
profile are separate from this working server profile.

## Shared datagram listener

`services::quic::Listener` owns one vendored endpoint over
`Datagrams<SocketAddr>` and exposes `Mux<Quic, Top, ConnInfo>`. Its children
reuse the stream and application-datagram adapter from `QuicLayer`.
`Children` can therefore put `Responder::http3()` on each connection. This
stack attaches directly to `Host::udp_stack`; no second UDP socket or async
transport task is created per connection. The constructor's documentation
has the composition example. TLS configuration must negotiate `h3`.

The listener initializes on its first environment step, reserving the
connection slots before constructing the endpoint or drawing entropy.
Before accepting a new connection it reserves that connection's stream
slots. Handshakes and draining connections count against the configured
connection limit. When full it ignores new Initials and cleans up their
incoming handles; existing connections continue. One shared socket budget
pays for adapter storage. This is not per-sandbox admission or a bound on
all engine allocations.

The endpoint routes packets by connection ID, and the adapter processes
its identifier issuance, retirement and draining events even while an
application cannot read. A connection is exposed only after handshake
completion, with local and peer addresses, TLS, SNI and ALPN metadata.
The application factory may choose a different application for each
negotiated protocol. Metadata reflects acceptance, not later migration.
Connection events add no second credit window around the independently
credited streams and application datagrams; the existing children router
bounds their queued descriptors and repays their payload storage.

Sends and application events rotate among live connections. Engine and
stream work is scanned in bounded slot order, including when upper output
is blocked; this is not a new constant-time scheduler claim. At most one
tracked send is outstanding on the lower carrier. Its owner is either the
endpoint or a generation-bearing connection child. Completion reaches only
that owner, and excess completion counts leave the ownership unchanged.
A connection is retained until its final endpoint event, its application
events and its local send have retired. Closing one connection never ends
the shared datagram carrier. Closing that carrier cancels pending completions
and retires all children.

The distinction between engine handles and child generations matters: an
engine handle can be reused after `Drained` while its old adapter still
owns an outstanding UDP send. The listener disables routing to the old
adapter before returning `Drained` to the endpoint. A regression forces
that reuse, checks that incoming events select the new adapter, and checks
that send completion still retires the old one's send. Other regressions
cover a close while a send is outstanding, invalid completion refusal,
full-listener admission, zero-budget input preservation and lower-carrier
closure with a pending application-datagram completion.

Independent HTTP/3 tests run three quiche clients concurrently from the
same socket address, with different connection IDs and different
20,000-byte POST bodies. Exact echoed responses establish separation of
request state. Every client retires its first destination connection ID
and continues through a replacement issued by the shared endpoint. Three
rounds serve nine connections through three slots, exercising drain
deadlines and reuse. Another test leaves one entire QUIC application
unread while its sibling completes an HTTP/3 request.

The world-host test attaches the listener stack to `Host::udp_stack`,
connects three quiche clients through one native UDP socket on a sandbox
machine, and checks all three HTTP/3 responses and accepted metadata.
Packets traverse the world's native IP and UDP layers. This is a world
host test, not a live OS UDP test. Certificate verification remains on.
The earlier single-connection tests still cover collected and streamed
responses and trailers. No new listener-specific lossy or migration replay
is claimed.

`Listener.tla` models three distinct child lifetimes, two recycled engine
handles, two admitted connections and one outstanding send. The base passes:
2,827 generated states, 955 distinct states, depth eleven. Its controls
violate `Bounded`, `RoutesCurrent`, `CompletionOwned` and `PaidStorage` when
admission, route retirement, send retention or reservation is removed.
The resource store models per-connection stream-slot storage as one abstract
unit, with freeing and releasing its reservation in separate steps. It
checks payment, the limit and tracked storage; it does not measure bytes,
model the fixed listener table or account for endpoint allocations.
The model does not replay production traces or prove cryptography,
connection-ID authentication, packet recovery or scheduler progress.
Run its five configurations using the scoped TLC invocation and shared
resource library described earlier, with `Listener.tla` as the module.

The Kani harness
`listener_completion_preserves_its_owner_without_allocating` passes with
arbitrary owner values, arbitrary sixty-four-bit completion counts and all
three ownership states. It calls the production generic completion method,
proving exact ownership, no mutation on refusal or zero completion, and
zero peak and requested allocations with the shared counting stubs. The
counter sanity harness also passes. No production function is stubbed.
A temporary mutation discarding the connection owner fails the owner
assertion; it was removed and the original harness passes again. Run:

```sh
cargo kani -p fictionet --lib -Z stubbing -Z c-ffi -Z mem-predicates \
  -Z restrict-vtable --harness listener_completion_preserves_its_owner_without_allocating \
  --harness the_counter_sees_every_allocation
```

The allocation replay constructs the listener and offers caller-owned input
against a zero-byte budget. Both peak allocation and requested bytes must
be zero: per-input and fixed costs are both zero for refusal. Constructing
slots against an unrelated unlimited budget makes this replay fail with
22,572 live bytes against zero charged. That mutation was removed. This
replay proves refusal before allocation; successful endpoint admission,
wire copies, handshake metadata and engine routing still lack complete
resource bounds. The earlier unfinished Kani harnesses remain unfinished.

No rustls files changed. The next build-out priority is whole-engine
budgeting, followed by the remaining version-two work and unresolved
proofs. The HTTP/3 server retains its static QPACK profile; an HTTP/3
client/proxy and optional dynamic compression remain separate work.

Validation for this step: all 4,373 SDK library tests, 1,413 integration
tests and 303 doctests pass. The isolated QUIC/HTTP/3 suite passes all 31
tests. Clippy with warnings denied passes for both crates and all their
targets; rustfmt passes, including the included listener test source.
Cargo doc succeeds with the existing redundant-link warning in
`network/packet.rs`. The QPACK long-instruction decoder benchmark ran both
7,500-byte and 30,000-byte cases with ten samples; this is not a listener
throughput measurement. All Cargo, Kani and TLC commands ran in the required
memory-limited scope with artifacts in the separate target directory.

At the end of the listener step, both datagram adapters still copied incoming
payloads into `BytesMut` before `Endpoint::handle`. The reserved wire-backing
step below replaces those copies. Those backings can be
split and retained through packet and frame processing, so a temporary
reservation around the call alone would not cover their lifetime. Endpoint
routing and incoming queues, stream receive state, packet recovery and TLS
allocations likewise remain in scope for whole-engine admission. The new
listener's connection and stream limits must not be presented as that
missing heap bound.

## Reserved wire backings

`PacketBuffer::copy_from` reserves the input payload, shared backing metadata
and the first immutable-owner descriptor before copying. The reservation
follows the mutable backing through endpoint queues, coalesced packets,
header removal and decryption. Each mutable split reserves its immutable
owner before splitting. Freezing keeps the original buffer and its charges
inside `Bytes::from_owner`; frame slices and clones share that owner without
another allocation. The last view releases the backing, including when an
application retains stream bytes after the connection has been dropped.

`Endpoint::handle_buffer` accepts this storage. The old `handle(BytesMut)`
entry point remains unbudgeted for compatibility. The bound covers the
current bytes crate's mutable shared metadata and immutable owner layout;
the allocation checks must run when that dependency changes. Packet keys
are still the supplied provider's responsibility: this storage claim uses
the existing rustls provider's in-place decryption, not arbitrary allocating
implementations of the packet-key trait.

Five Kani harnesses call production allocation and split methods with every
four-byte input, using only the shared allocation stubs. Refusal against a
zero-byte budget allocates nothing. Copying and either split direction,
followed by freezing both halves, stay within the actual reservation and
request at most one input copy plus the backing and owner metadata. All five
pass, as does the allocator sanity harness. The refused-split harness also
checks zero allocation and preservation of the source pointer, bytes and
reservation. The combined split harness was
terminated without a verdict; separate prefix and suffix harnesses preserve
both operations and all their assertions and finish successfully. Run:

```sh
cargo kani -p fictionet-quinn-proto --lib -Z stubbing -Z c-ffi \
  -Z mem-predicates -Z restrict-vtable --harness packet_storage_ \
  --harness the_counter_sees_every_allocation
```

The allocation replay covers empty, one-byte, 64-byte, 1,200-byte and
65,527-byte input. It measures copying, mutable splitting, freezing and
immutable cloning/slicing as distinct steps. The refusal replay covers
zero room and insufficient metadata room; refused prefix and suffix splits
preserve the source bytes, pointer and reservation with no allocation.
A protected endpoint regression retains received slices after partial
stream reads and after dropping the connection, checking payment through
the final slice. Another regression checks that mutable packet views stay
disjoint and freeze without copying their payload.

`PacketStorage.tla` models one backing and three mutable/immutable owners,
with frame slices sharing immutable owners. Its base passes: 1,184 generated
states, 369 distinct states and depth eleven. The three controls violate
`StoragePaid`, `SplitReserved` and `StoragePaid` when copy admission, split
admission or last-view retention is removed. The shared resource store also
checks the limit and tracked storage. Units abstract backing and descriptor
sizes; this is not a byte-level packet parser or a production trace replay.
Run its four configurations with the scoped TLC invocation and shared
resource library described above.

These bounds cover wire storage, including retained views, not all receive
storage. Reassembly compaction can still copy into uncharged storage, and
its heap nodes, interval sets and stream records remain outside this claim.
TLS queues, recovery metadata and endpoint routing also remain unbudgeted.
There is no dedicated reserve for receiving ACK/control packets when retained
application data exhausts the shared budget; dropping input is safe for
acknowledgment correctness, but progress under sustained budget exhaustion
is not established. Whole-engine budgeting is still the next build-out priority, before the
remaining version-two work and unresolved older proofs. No rustls files
changed.

Validation for the wire-storage engine step: all 351 engine tests and three
engine doctests pass. Clippy with warnings denied passes for the SDK and
engine on all targets. Cargo doc succeeds with the existing redundant-link
warning in `network/packet.rs`. The `quic_wire_admission` benchmark measures
charged input copying at 1,200 and 65,527 bytes with ten samples; it is not
a transport throughput measurement.

A scratch commit moved the input copy before reservation. The unchanged
refusal replay failed with 64 live bytes against zero charged; Kani failed
the zero-peak-allocation assertion. The scratch commit is not on this branch.
Restoring the reservation order passes the unchanged checks again.

Both `QuicLayer` and `Listener` now use `PacketBuffer::copy_from` and
`Endpoint::handle_buffer`. Refusal of input storage drops the unreliable
wire datagram before endpoint processing, leaving it unacknowledged. It
does not block the shared carrier behind an unread connection. Existing
initialization and output-queue backpressure keep their prior contracts.
The initial blocking implementation failed the existing application-datagram
memory-pressure regression; changing the code to drop unpaid wire input
restored that test without changing its assertions. A listener regression
also exhausts its budget after initialization, checks that an Initial
creates no connection, releases the memory and successfully retransmits it.

The independent QUIC/HTTP/3 suite passes all 31 tests with the charged input
path, including sustained loss/reordering, both quiche roles, concurrent
HTTP/3 connections, streamed responses/trailers and the world UDP host.
All 4,373 pre-existing SDK library tests, the new listener regression,
1,413 integration tests and 303 SDK doctests pass. Rustfmt and clippy with
warnings denied pass. All Cargo, Kani and TLC invocations use the required
memory-limited scope and the separate target directory.


## Reserved reassembly storage

`Endpoint::set_reassembly_budget` installs a budget on future connections
before either STREAM or CRYPTO frames are processed. The assembler reserves
its descriptor growth before allocating. It retains the geometric growth
history as its charge, less than twice the current descriptor capacity;
that covers old and replacement allocations together and each replacement's
copying cost. Clearing or recycling a receive stream retains both capacity
and its reservation. Dropping it releases both.

Compaction now sorts, deduplicates and rebuilds in the same descriptor
allocation. It reserves one new payload and its shared owner before copying,
while original wire owners remain live. Every contiguous output run shares
that new backing. Application slices keep its payment after the connection
and other slices are gone. A refused compaction still removes duplicate
ranges in place and preserves every useful byte; it allocates nothing.
An insertion that cannot reserve another descriptor, or that leaves more
than the existing gap limit after compaction, ends the connection with an
internal transport error. It does not silently discard reliable data.

The pressure regression exposed an acknowledgment error in the previous
receive path. Authentication inserted the packet number into pending ACKs
before frame processing. When storage admission then failed, the closing
packet ACKed the rejected bytes and the sender reported its stream finished.
ACK admission now follows successful processing, including the first Initial
packet. Closing packets can still acknowledge earlier successfully processed
packets. This enforces the enqueue-before-ACK rule in
[RFC 9000 section 13.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-13.1).
The unchanged pressure regression now receives a connection error without
stream success or application acceptance. No rollback of earlier frames in
that rejected packet is claimed; the connection closes.

The resource replays measure descriptor growth and reuse, successful copies
from charged wire input at one, sixty-four, twelve hundred and sixteen
thousand bytes per fragment, and allocation-free descriptor/copy refusal.
Compaction makes at most one copy of its retained useful input plus one owner;
it creates no new descriptor allocation. These are individual compaction
costs, not an amortized bound over arbitrary packet delivery. A seeded
regression mixes small copied spans, large retained spans, overlaps, gaps and
partial reads, checking every byte and final budget release. A protected-peer
regression checks CRYPTO admission from the endpoint's budget, then exhausts
that budget and checks STREAM refusal and close behavior.

Four Kani harnesses pass with the shared counting stubs and no production
stubs: copy refusal, arbitrary four-byte copying with two shared slices,
descriptor refusal and two empty descriptor-capacity growth steps. Each
checks actual peak allocation against its reservation and requested bytes
against a linear bound. The copy coefficient is one, with one owner as its
fixed term. Descriptor growth has no input-byte term and a fixed term for
four initial and eight replacement descriptors. The allocator sanity
harness also passes. Run under the required scope:

```sh
cargo kani -p fictionet-quinn-proto --lib -Z stubbing -Z c-ffi \
  -Z mem-predicates -Z restrict-vtable --harness reassembly_copy_ \
  --harness reassembly_empty_descriptor --harness reassembly_descriptors_refuse \
  --harness the_counter_sees_every_allocation
```

The broader `reassembly_descriptor_growth_fits_its_reservation` harness
inserts five descriptors with an arbitrary offset and checks their contents
as well as both allocation bounds. Its first run exhausted the fourteen
GiB scope during propositional conversion. A repeat with twelve object bits
also exhausted the scope; ten object bits failed on the tool's addressed-object
limit before a solver verdict. The focused empty-capacity proof
does not prove heap ordering, payload preservation or the full insertion
path. The existing five-insertion assertions remain in the broader harness.

`ReassemblyStorage.tla` models descriptor growth, shared compacted backings,
retained source owners and application slices. Its base passes with 473
generated states, 173 distinct states and depth twenty-one. Removing
descriptor admission, removing copy admission, or releasing payment while
a slice remains each violates `StoragePaid`. The model checks the combined
budget and tracked storage in abstract descriptor/backing units; it is not
a byte bound or a production trace replay.

`ReceiveAdmission.tla` separately models two protected packets with two
reliable frames each, partial processing, storage refusal, malformed frames
and normal or closing ACK output. Its base passes with 61 generated states,
41 distinct states and depth eight. Restoring ACK admission at authentication
violates `AckAfterProcessing`. The reachability control violates
`NoCompletedPacket`. This model abstracts cryptography, frame parsing and
application consumption; it does not prove the production packet loop.
Run both modules' configurations with the scoped TLC command and shared
resource library described above.

Whole-engine budgeting remains incomplete. Wire backings must still enter
through `PacketBuffer`; the legacy byte APIs cannot acquire a retrospective
charge. Unordered-read interval sets, stream records and maps, sent-packet
and retransmission metadata, TLS queues and endpoint routing are outside
these bounds. A dedicated control-input reserve and progress under sustained
budget pressure also remain unresolved. No rustls files changed. The next
priority remains those engine allocations, followed by version two and the
older unresolved proofs.


Two scratch allocation mutations were tested and removed. Omitting heap
admission makes the refusal replay observe 224 live bytes against zero
reserved; its Kani refusal assertion fails too. Allocating the compaction
vector before reserving makes the copy-refusal replay observe five live
bytes against zero; Kani fails the zero-peak-allocation bound. The restored
production code passes the unchanged replays and focused proofs. The
scratch commits are not on this branch. The acknowledgment regression
also failed before moving admission, as described above.

Both datagram adapters now install the reassembly budget before creating
any connections. The same world/socket budget therefore covers the layer's
storage, wire owners, application datagram arena, and the newly reserved
STREAM and CRYPTO storage. They still make no whole-engine memory claim.
The independent suite passes all 31 tests, including HTTP/3 handler traffic
through the shared world UDP listener, concurrent quiche clients, streamed
responses and trailers, and sustained QUIC loss and reordering.

Validation: all 357 engine library tests, 4,374 SDK library tests, 1,413
integration tests, 303 SDK doctests and three engine doctests pass. Clippy
with warnings denied and workspace formatting pass. Rustdoc succeeds with
the existing redundant-link warning in `network/packet.rs`. The existing
`quic_wire_admission` benchmark ran at 1,200 and 65,527 bytes with ten samples;
it measures wire copying, not reassembly throughput. All Cargo, Kani and
TLC commands ran under the required memory-limited scope with Cargo targets
outside the worktree.

## QUIC version two

The engine now runs [RFC 9369](https://www.rfc-editor.org/rfc/rfc9369.html)
and the compatible and incompatible negotiation of
[RFC 9368](https://www.rfc-editor.org/rfc/rfc9368.html). This step adds the
implementation and its tests; it adds no proofs or models.

`quinn-proto/src/version.rs` names versions 1 (`0x00000001`) and 2
(`0x6b3343cf`), the drafts the engine already ran, and which versions are
compatible: 1 and 2 in both directions, every version with itself. Lists of
versions are `VersionList`, an inline set of known versions, so a peer's
list is reduced to the versions the engine knows without allocating.

Long header type bits follow the packet's version: `LongHeaderType::from_byte`
and `to_byte` in `packet.rs` map version 2's Initial 1, 0-RTT 2, Handshake
3 and Retry 0. The rustls adapter maps `0x6b3343cf` to the fork's version 2
key schedule, whose Initial salt and `quicv2` labels were already present.
Retry tags use the version 2 key and nonce in `retry_integrity`, and Retry
validation takes the Retry packet's own version.

Every connection sends Version Information, which `TransportParameters`
now keeps as a `VersionInformation`: the Chosen Version, the known
Available Versions in order, and whether others were listed. The decoder's
existing checks are unchanged. A server compares the client's Chosen
Version with the version of the client's first flight; a client compares
the server's with the negotiated version.

A client's `ClientConfig::version` is its Original Version and
`preferred_versions` its preference, versions 2 then 1 by default. Its
first flight offers the preferred versions that the first flight converts
to and its endpoint accepts. Endpoints accept versions 1 and 2 by default,
in that order of preference.

A server chooses before its TLS session reads the ClientHello, since its
own Version Information names the chosen version.
`version::client_version_information` reads the client's offer from the
decrypted first Initial: its CRYPTO frames, the ClientHello, the transport
parameter extension and Version Information, in place and without copying.
`select_compatible` takes the first version of the server's preference
that the first flight converts to and the client offered. When the
ClientHello does not fit the first packet, or anything is unexpected, the
server keeps the client's version, as RFC 9368 allows.

`Endpoint::compatible_upgrade` then charges the original version's Initial
keys to the connection's budget, derives them and the negotiated version's
keys, and starts the TLS session with `set_negotiated_version`. The server
keeps the original Initial receive keys until a Handshake packet in the
negotiated version is processed, then drops them and their charge. If the
budget refuses them, the server keeps the original version.

The client accepts Initial packets in the versions it offered until its
version is settled. `connection/negotiation.rs` decides each long header:
`Negotiation::admit` returns the current keys, the other version's keys, a
trial of an offered version, or a drop. A trial charges the offered
version's Initial keys before deriving them. The client adopts the version
only after a packet authenticates under those keys, and before its CRYPTO
data reaches TLS, in `Connection::adopt_tried_version`. CRYPTO data in the
original version settles the original version. Handshake packets must use
the negotiated version, 0-RTT stays in the original version, and a client
follows a Retry only in its original version before settling.

After a Version Negotiation packet, `Negotiation::react` ignores it when it
lists the Original Version or when the client already reacted once.
Otherwise the client starts again in its most preferred listed version that
its endpoint accepts, through `Connection::restart_in_version`. That
replaces the TLS session and Initial keys and abandons any 0-RTT.
`Negotiation::check_server` then requires the server's Version Information
and applies RFC 9368 section 4's downgrade check,
`version::negotiation_was_genuine`. Servers ignore Version Negotiation.

The rustls fork changed in two separate commits. A QUIC connection can
switch to a negotiated version until its handshake secrets exist; 0-RTT
keys keep the original version. Session tickets record the QUIC version of
the connection that issued or received them. A server resumes only a
ticket of its connection's version, and a client offers only one of its
first flight's version. The client constructor now sets the version before
the ClientHello chooses a ticket, which the first commit missed. Address
tokens were already bound to versions.

`QuicLayer::version` reports the settled version, and
`with_address_validation(AddressValidation::Retry)` makes a server layer
answer unvalidated clients with a Retry. HTTP/3 above the layer needs no
change; callers offer and accept version 2 through the configurations
they already pass.

### Tests

The RFC 9369 Appendix A client Initial, server Initial and Retry run
through the engine's encoder, protection and decoder as known answers in
`packet/rfc9369_vectors.rs`; changing the version 2 type bits fails all
four tests. The fork adds the Appendix A.5 key update vector beside its
existing version 2 key vectors, and a ticket encoding round trip.

Unit tests cover version lists, compatibility, server selection, the
downgrade check, the first-flight reader on shuffled CRYPTO frames and the
RFC's sample ClientHello, and each negotiation decision. Two engines in
`tests/version.rs` complete version 2 handshakes, an upgrade from version
1, a version 2 Retry, a Retry before an upgrade, Version Negotiation into
version 2, and a refusal without a common version. They check the version
of every long header on the wire and a stream exchange. A forged Version
Negotiation packet ends in `VERSION_NEGOTIATION_ERROR`, and one listing the
Original Version is ignored. A version 1 ticket is not offered to a version
2 connection, a version 2 ticket gives 0-RTT, and a server refuses a version
1 ticket presented as version 2.

The `versions` module of `services/quic/tests.rs`, which the
interoperability crate also includes, runs two `QuicLayer`s on the simulated
datagram carrier: a version 2 handshake, an upgrade, a client offering only
version 1, a version 2 Retry, a Retry before an upgrade and Version
Negotiation into version 2. Each checks the versions on the carrier and a
stream exchange.

Scratch mutations, all reverted: removing the server's ticket check fails
the relabelled-ticket test; offering tickets of any version fails the
ticket offer check; skipping the downgrade check fails the forged Version
Negotiation test and its unit test; never upgrading fails both upgrade
layer tests.

All 386 engine library tests, 287 fork library tests, 31 SDK QUIC tests and
37 tests of the independent interoperability crate pass. Clippy with warnings denied
passes for the engine, the fork and the SDK library and tests. quiche 0.30
speaks only version 1, so independent version 2 interoperability is not
tested.

### Resources

New storage is the other version's Initial keys: on a server after an
upgrade, and on a client trying an offered version. Both are charged to the
connection's reassembly budget before derivation, using
`Keys::heap_size`, and released with the keys. `heap_size` counts each key
box and the rustls key behind it; ring keys hold no further heap, which an
allocation replay should confirm. Version lists, Version Information and
the first-flight reader are inline and allocate nothing.

A restart after Version Negotiation replaces the TLS session and Initial
keys; like the session it replaces, the new session is not charged. A
layer Retry reaches the engine's existing token encoding and Retry tag
code, which allocate uncharged buffers. Tickets taken from the client store
in the wrong version are dropped, not returned.

### Limits

A server upgrades only when the whole ClientHello is in the first Initial
packet, at most eight CRYPTO frames. A ticket from an upgraded connection
belongs to the negotiated version, so a client starting in version 1 does
not resume it; a client resumes by starting in that version. With the
default preference for version 1, endpoints that both prefer version 2 must
say so. The server's Available Versions are its known accepted versions.

### Proof targets

Version rules: `version::compatible`, `select_compatible`,
`negotiation_was_genuine`, `VersionList::{new, known, push,
compatible_with, first_offered}` and `TypeBits::of`.

Packet types: `LongHeaderType::from_byte` and `to_byte` in `packet.rs`, a
bijection per version, and `ProtectedHeader::decode` and `Header::encode`.

First-flight reading: `version/first_flight.rs`,
`client_version_information`, `CryptoData::{read, byte}` and the `Cursor`
reads. Bounds, no allocation, and agreement with the transport parameter
decoder on the offer.

Negotiation decisions in `connection/negotiation.rs`:
`Negotiation::{client, server, decodable, admit, react, check_server}`,
for example that Handshake packets are only admitted in the current
version, 0-RTT only in the original, that a client reacts at most once and
never to a list with its Original Version, and that `check_server` rejects
every forged downgrade.

Connection integration in `connection/mod.rs`: `handle_decode`,
`prepare_other_initial`, `adopt_tried_version`, `restart_in_version`, the
Retry and Version Negotiation arms of `process_decrypted_packet`, the
Handshake arm that drops the server's other keys, `read_crypto` settling a
client, and the 0-RTT header version in `packet_builder.rs`.
`packet_crypto::{unprotect_header, decrypt_packet_body}` with other keys.

Endpoint: `Endpoint::compatible_upgrade`, `accept` and `connect`.

Transport parameters: `read_version_information` and the
`VersionInformation` arm of `TransportParameters::write` and `read_inner`;
the existing Kani harnesses in `kani/version_information.rs` were adjusted
to the returned structure only.

Retry integrity: `crypto/rustls.rs` `retry_integrity`, `retry_tag`,
`is_valid_retry` and `interpret_version`.

Resources: the charge-before-derivation in `prepare_other_initial` and
`compatible_upgrade`, `Keys::heap_size` against measured allocation, and
the release of the other keys.

rustls fork: `ConnectionCommon::set_negotiated_version` and the
`handshake_secrets_derived` flag set in `tls13/key_schedule.rs`,
`zero_rtt_keys` using `early_version`, ticket binding in
`server/tls13.rs` (`get_server_session_value` and the resumption filter),
`client/hs.rs` (`ClientSessionValue::retrieve`), `client/tls13.rs` and
the `ServerSessionValue` codec in `msgs/persist.rs`, and
`ConnectionCore::for_client` setting the version before the ClientHello.

Layer: `QuicLayer::version`, `with_address_validation` and the Retry
branch of the layer's datagram handling.

## QUIC version two: correctness proofs

These proofs cover the version two code of [QUIC version two](#quic-version-two):
packet types and protection keys per version, the negotiation decisions,
and the negotiation as a whole against an attacker on the path. Resource
bounds are left to their own section.

### What the proofs found

The downgrade check judged the wrong version. RFC 9368 section 4 asks
whether the client would have attempted the same version had the Version
Negotiation packet listed the server's Available Versions plus the
Negotiated Version. `negotiation_was_genuine` compared that choice with the
final negotiated version. When a server upgrades the attempt, as in RFC
9368's Figure 1, the two differ, and a negotiation with no attacker failed
with `VERSION_NEGOTIATION_ERROR`. One case: a client starting in a draft
the server does not run, preferring version 2, restarted in 2 from the
server's list of 1 and 2. A server preferring 1 then upgraded it to 1.
The model's `NoFalseRefusal` and the Kani lemma both state the property
this broke. c589fee32 compares with the attempted version. Its two-engine
test, `version_negotiation_followed_by_a_compatible_upgrade_completes`,
failed before the fix and passes after it.

### Kani

The harnesses are compiled into the production modules under `cfg(kani)`
and call the production functions. Run each with `cargo kani -p
fictionet-quinn-proto --lib -Z restrict-vtable --harness <name>` under
the required memory scope.

`kani/version_packets.rs`, in `packet.rs`, has no stubs. The expected type
bits are the tables of RFC 9000 section 17.2 and RFC 9369 section 3.2.

- `long_header_types_are_each_versions_rfc_bijection`: for every 32-bit
  version and type, `to_byte` writes the RFC's bits with the form and fixed
  bits set. `from_byte` reads them back whatever the other bits are, and
  is one-to-one on the two type bits.
- `version_one_and_two_never_share_a_type_byte`: no type's byte in one
  version reads as that type in the other.
- `decoding_types_a_long_header_by_its_own_version`: for any first byte
  and version, `ProtectedHeader::decode` types the header by the table of
  its own version. Version zero is Version Negotiation, and other versions
  are refused with the version named.
- `encoded_{initial,zero_rtt,handshake,retry}_headers_decode_in_their_version`:
  `Header::encode` of each type in version 1 or 2 decodes as that type and
  version. One symbolic type in a single harness ran past an hour in the
  solver, so there is one harness per type.

`kani/version_keys.rs`, in `crypto/rustls.rs`, runs the fork's real
`Suite::keys`, `Keys::initial`, `KeyBuilder` and HKDF-Expand-Label. Only
the hash and the ciphers are replaced, by a symbolic suite: an extraction
records its salt and whether its input was the connection ID, and each
expansion adds its label. Each key so names its own derivation, and the
harness reads it back through the engine's `PacketKey` and `HeaderKey`.
The expected salts, labels, keys and nonces are copied from RFC 9001
sections 5.2 and 5.8 and RFC 9369 section 3.3.

- `initial_keys_use_the_salt_and_labels_of_their_version`: for every
  32-bit version and both sides, the engine derives Initial keys exactly
  for the versions it knows. Each packet key, IV and header key comes from
  that version's salt and the client's Destination Connection ID, through
  the sending side's `client in` or `server in` secret. It then uses
  `quicv2 key`, `quicv2 iv` and `quicv2 hp` for version 2 and the
  `quic` labels otherwise.
- `retry_integrity_and_type_bits_follow_the_version`: Retry tags use RFC
  9369's key and nonce exactly for version 2, RFC 9001's for version 1 and
  drafts 33 and 34, other keys for drafts 29 to 32, and none for unknown
  versions. The adapter runs version 2's key schedule exactly when the
  type bits are version 2's.
- `a_retry_in_an_unknown_version_is_never_valid`: such a Retry is never
  valid and gets no tag.

`kani/version_negotiation.rs`, in `connection/negotiation.rs`, has no
stubs. Lists are the known versions of three arbitrary 32-bit values.

- `the_server_chooses_only_from_the_clients_offer`: `select_compatible`
  answers in a version it supports, that the client listed and the first
  flight converts to. It takes its own most preferred such version, and
  otherwise keeps the original.
- `a_client_reacts_once_never_to_its_own_version_and_by_preference`:
  `react` ignores a list naming the Original Version, and any list after
  it reacted once. Otherwise it restarts in its most preferred listed
  version that it supports, or fails when there is none.
- `the_downgrade_check_is_sound_and_complete`: suppose an honest server
  accepted the attempt and negotiated the attempt or a compatible version
  both offered. Then `negotiation_was_genuine` passes exactly when no
  version the server reports comes before the attempt in the client's
  preferences. That includes the case where the server upgraded the
  attempt. With the `react` harness, a forged Version Negotiation packet
  can only end an attempt, never move it. This harness runs over two-entry
  lists of each kind of version: 1, 2, two drafts and an unknown version.
  Three entries, or composing `Negotiation::client`, `select_compatible`
  and `check_server` in one harness, ran CBMC past 10 GiB during symbolic
  execution.
- `a_client_accepts_only_a_chosen_version_it_offered`: `check_server`
  accepts an honest compatible choice, and any Chosen Version exactly when
  it was offered. A client's offer holds its Original Version and only
  preferred versions its first flight converts to.
- `{initial,zero_rtt,handshake,retry}_packets_are_admitted_only_in_their_version`:
  in every state, `admit` takes Handshake packets only in the current
  version, and 0-RTT only on a server and in the Original Version. It
  takes an Initial in another version only with that version's retained
  keys on a server, or as a client's trial of an offered compatible
  version before it settles. It takes a Retry only in the Original Version
  before the client settles. Every admitted version is one the header
  decoder accepts. One harness per kind: a symbolic kind ran past eighteen
  minutes, and dropping the boxed test keys ran CBMC out of memory.

The Chosen Version comparison itself is the decoder's, proved by the
existing `version_information_body_checks_the_connection_without_allocating`.

### TLA+

`tla/VersionNegotiation.tla` follows one client and one server through
compatible and incompatible negotiation over versions 1, 2 and a draft
compatible with neither. Its header names the code of each action. The
attacker can deliver, at any moment, a Version Negotiation packet listing
any versions and a server Initial in any version, since Initial keys come
from the connection ID. It can also send the server a client Initial with
any offer. It cannot make Handshake packets, and TLS authenticates the
client's offer. Honest messages stay in the network, so they can be
delayed, reordered, replayed or dropped. Every client and server
preference list over the three versions is checked, with every Original
Version the client prefers.

The base config checks these invariants:

- `Agreement`: a client that completes runs the server's version.
- `NoDowngrade`: the final version is one an honest network gives. That
  is the server's choice for the Original Version, or for the client's
  most preferred version the server lists. RFC 9368 allows the second even
  when the server accepts the Original Version.
- `NoFalseRefusal`: with no attacker, the client fails only when it shares
  no version with the server.
- `ServerChoosesOffered`: the server runs a supported version the client
  offered, compatible with the first flight.
- `ClientRunsOffered`: the client runs only a version it offered.
- `ClientSingleVersion`: once settled, the client holds and accepts only
  its version's Initial keys and packets, and Handshake keys of that
  version alone.
- `ServerSingleVersion`: the server drops the original Initial keys on a
  Handshake in the negotiated version and never reads an original Initial
  after it.

Run each config with the scoped TLC command above. The base passes:
109,230,241 states generated, 3,797,295 distinct, depth 11.

| Config | Change | Result |
| --- | --- | --- |
| `_without_genuine` | no downgrade check | violates `NoDowngrade` |
| `_without_transcript` | the client's offer unauthenticated | violates `NoDowngrade` |
| `_without_server_offer` | the server ignores the client's list | violates `ServerChoosesOffered` |
| `_without_try_offered` | the client adopts any Initial's version | violates `ClientRunsOffered` |
| `_without_drop_other` | the server keeps original keys | violates `ServerSingleVersion` |
| `_with_negotiated_judged` | the check before c589fee32 | violates `NoFalseRefusal` |
| `_reaches_completion` | | violates `NoCompletion` |
| `_reaches_upgrade` | | violates `NoUpgrade` |
| `_reaches_restart_upgrade` | | violates `NoRestartUpgrade` |

The `_with_negotiated_judged` trace has no attacker. A client prefers 1,
2, then a draft and starts in the draft. The server lists 2 and 1 and
prefers 2. The client restarts in 1, is upgraded to 2, and is refused.
That is the bug above.

The model has no control for ignoring a list that names the Original
Version. With the downgrade check in place, reacting to such a list still
ends in a version `NoDowngrade` allows, because the check pins the attempt
to the client's top choice among the server's versions. The Kani `react`
harness proves the code ignores such lists. The model leaves out
cryptography, Retry, 0-RTT, session tickets, a ClientHello split across
packets, and fleets whose Available Versions differ from the accepted
ones.

### Negative controls in the code

Each scratch mutation was applied to the production code, its harness was
run, and the code was restored.

| Mutation | Harness that failed |
| --- | --- |
| `negotiation_was_genuine` compares with the negotiated version (the old bug) | `the_downgrade_check_is_sound_and_complete` |
| `react` answers a list naming the Original Version | `a_client_reacts_once_never_to_its_own_version_and_by_preference` |
| `select_compatible` ignores the client's list | `the_server_chooses_only_from_the_clients_offer` |
| `admit` takes Handshake packets in any version | `handshake_packets_are_admitted_only_in_their_version` |
| `admit` tries Initials of versions not offered | `initial_packets_are_admitted_only_in_their_version` |
| `check_server` skips the offered check | `a_client_accepts_only_a_chosen_version_it_offered` |
| `from_byte` reads version 2's Initial bits as 0 | `long_header_types_are_each_versions_rfc_bijection`, `decoding_types_a_long_header_by_its_own_version` |
| `interpret_version` maps version 2 to version 1 | `retry_integrity_and_type_bits_follow_the_version`, `initial_keys_use_the_salt_and_labels_of_their_version` |
| the fork's version 2 salt starts with version 1's bytes | `initial_keys_use_the_salt_and_labels_of_their_version` |
| the fork's version 2 IV label is `quic iv` | `initial_keys_use_the_salt_and_labels_of_their_version` |
| version 2's Retry nonce is version 1's | `retry_integrity_and_type_bits_follow_the_version` |

All 387 engine library tests pass after the fix. Clippy with warnings
denied and the formatting check pass on the engine.

## QUIC version two: resource proofs

This section covers what version two and version negotiation hold and
copy, using the method in
[`verification/README.md`](../README.md#resource-properties). Every key
derivation they add is charged to the connection's reassembly budget
before it starts. A charge is given back only after the storage it paid
for is freed. A server's Retry and Version Negotiation packets are
written into its send buffer. Version Information and the version rules
allocate nothing. When a budget refuses a charge, only the packet that
needed it is lost, and the attempt goes on. This section replaces the
Resources notes under [QUIC version two](#quic-version-two).

### What is charged

| Path | Storage | Charge |
| --- | --- | --- |
| Client tries an offered version (`prepare_other_initial`) | that version's Initial keys | `initial_keys_charge`, held while the keys are kept |
| Server upgrades (`Endpoint::compatible_upgrade`) | the original version's Initial keys, kept until a Handshake packet in the new version | `initial_keys_charge`, held while the keys are kept |
| Client restarts after Version Negotiation (`restart_in_version`) | the new version's Initial keys, beside the old ones | `initial_keys_charge`, until the old keys are freed |
| Client follows a Retry | the copy the tag is checked over (`packet/retry.rs` `PseudoPacket`), then the new Initial keys | the copy's length, then `initial_keys_charge` |
| Server sends a Retry (`Endpoint::retry`) | the token and the Retry Pseudo-Packet | none: both are built in the send buffer |
| Server sends Version Negotiation (`write_version_negotiation`) | the packet | none: it is written in the send buffer |
| Version Information, first-flight reading, version choice | none | none |

`crypto::Session::initial_keys_charge` and the same method of
`crypto::ServerConfig` give the most heap a derivation of Initial keys
holds at once. For rustls this is the four keys and two HKDF expanders:
rustls' `Keys::initial` holds the expander of the Initial secret while
each direction's `KeyBuilder` holds one more. `InitialSuite` measures
both sizes once, when a configuration is made.

`OtherInitial::derive` charges first and derives only after the charge
is granted. `OtherInitial::install` puts tried keys in place of the
current ones. It frees the old keys first, then releases the charge.
The fields of `OtherInitial` drop in order, so its keys are always freed
before its charge is released.

A refused charge loses only the packet that needed it. A client that
cannot try an offered version drops that server Initial. The server sends
it again, and the client tries again once the budget has room. A server
that cannot pay for the original keys keeps the client's version, as RFC
9368 allows. When a Version Negotiation packet or a Retry cannot be
processed for lack of budget, it is treated as lost:
`Connection::unprocess_packet` takes it out of the count of processed
packets. Otherwise, under RFC 9000 sections 6.2 and 17.2.5.2, the client
would ignore every later one.

### Found and fixed

- The charge for another version's keys was `Keys::heap_size`, the size
  of the keys alone: 1728 bytes with ring. A derivation holds 2032 bytes
  at its peak, because HKDF expanders are live beside the keys while
  they are built. The client's tried keys and the server's retained keys
  were allocated past their charge. The charge is now
  `initial_keys_charge`: the keys and two expanders, 2096 bytes with ring.
  The replay below fails with the old charge.
- `adopt_tried_version` dropped the tried keys' charge before it replaced
  the original keys. For a moment both sets were held while only one was
  charged. It now calls `OtherInitial::install`.
- A restart after Version Negotiation and a followed Retry derived new
  Initial keys while the old ones were still held, with nothing charged.
  Both now take a `KeyCharge` first and give it back once the old keys
  are freed. A refusal ignores the packet.
- A client checking a Retry copied the whole packet into an uncharged
  `Vec` (`is_valid_retry`). The copy is now a `PseudoPacket` that is
  charged before it is allocated. `crypto::Session::is_valid_retry` now
  takes the Pseudo-Packet.
- A server Retry allocated its token, the token's boxed AEAD key and a
  copy of the packet for the tag. Each grew with the input, and none was
  charged. `Token::encode_into` now seals the token in place in the send
  buffer. `HandshakeTokenKey::{seal, open}` replace the boxed
  `AeadKey`, and the token key lives on the stack. `retry::tag_in_place`
  rotates the Original Destination Connection ID in front of the packet
  inside the buffer to compute the tag, then rotates it back.
  `crypto::ServerConfig::retry_tag` takes the Pseudo-Packet. A returned
  token is opened in a stack buffer of `Token::MAX_ENCODED` bytes. A
  longer token cannot be one this server sealed, so it is refused before
  any copy.
- The counted Kani harnesses for Version Information parsing,
  `version_information_body_checks_the_connection_without_allocating`
  and `version_information_checks_the_connection_without_allocating`,
  failed their unwinding assertions. `VersionList::push` scans the eight
  known versions, which their bounds of 4 and 3 did not cover. Both
  bounds are now 10. The correctness harness beside them,
  `version_information_validates_all_versions_and_the_peer_role`, has the
  same bound of 4 and is left to the correctness proofs.
- A token whose issue time overflows `SystemTime` panicked in
  `Token::decode`. The masking stand-in key in Kani reached it. With the
  real key, only a token this server sealed gets that far. Decode now
  refuses such a token, and `a_token_issued_past_the_end_of_time_is_refused`
  seals one under the real key.

### Kani (`kani/negotiation_storage.rs`, `retry_storage.rs`, `version_negotiation_storage.rs`, `token_storage.rs`, `first_flight_storage.rs`, `version_storage.rs`)

These are counted harnesses (`counted_proof!`), run with `-Z stubbing -Z
c-ffi -Z mem-predicates -Z restrict-vtable`. Kani cannot run ring, so the
keys in `negotiation_storage.rs` are fixed 32-byte stand-ins. Each one
asserts, when it is freed, that its charge is still held. The token key
in `token_storage.rs` is a masking stand-in for the AEAD that checks its
tag. The real derivation's peak is bounded by the replay below.

| Harness | States | Verdict | Control (scratch edit), result |
| --- | --- | --- | --- |
| `other_initial_keys_are_charged_before_they_are_derived` | with a budget one byte short, nothing is derived or allocated; with room, peak and bytes asked ≤ the charge, and every key is freed while its charge is held | passes | derive before charging: fails ("a key outlived its charge"); `OtherInitial`'s charge field before its keys: fails, same check |
| `installed_keys_free_the_old_ones_before_the_charge_goes` | `install` frees the replaced keys while the charge is held; peak ≤ two key sets | passes | release the charge first: fails, same check |
| `a_key_charge_is_all_or_nothing` | a `KeyCharge` holds all of its bytes or none, and returns them | passes | ignore a refusal: fails |
| `negotiation_decisions_allocate_nothing` | reading a Version Negotiation list, `react`, `admit` and `decodable` ask for 0 bytes | passes | `react` copies the supported list: fails |
| `a_server_tags_a_retry_in_its_send_buffer` | 0 bytes asked; the tag covers the Pseudo-Packet; the packet is left unchanged, then the tag | passes | copy the packet for the tag: fails |
| `a_client_copies_a_retry_only_within_its_charge` | a refusal asks for 0 bytes; otherwise peak ≤ the charge and bytes ≤ 1 × Retry + 21 | passes | allocate before charging: fails |
| `version_negotiation_is_written_in_the_send_buffer` | 0 bytes asked; IDs swapped, a greasing version, then the supported ones | passes | copy the version list: fails |
| `a_retry_token_is_sealed_in_place` | 0 bytes asked, at most `MAX_ENCODED` bytes of the buffer used, and the token opens again | passes | copy the nonce to the heap: fails |
| `a_returned_token_never_allocates` | any returned token of up to `MAX_ENCODED + 1` bytes asks for 0 bytes; a longer one is refused | passes | open it in heap storage: fails |
| `the_transport_parameter_offer_is_read_in_place` | the offer is read with 0 bytes asked and found exactly when valid | passes | the reader allocates: fails |
| `version_choices_allocate_nothing` | `VersionList::known`, `compatible_with`, `select_compatible` and `negotiation_was_genuine` ask for 0 bytes | passes | `select_compatible` copies its preference: fails |
| `version_information_is_encoded_in_place` | `TransportParameters::write` with Version Information asks for 0 bytes | passes | copy the available list: fails |
| `version_information_body_checks_the_connection_without_allocating` (existing, bound raised) | `read_version_information` asks for 0 bytes | passes | allocate in the decoder: fails |
| `version_information_checks_the_connection_without_allocating` (existing, bound raised) | the same, through `TransportParameters::read_for_version` | no verdict: CBMC ran out of 10 GiB at bound 10 | none |
| `the_counter_sees_every_allocation` | the counter's own check | passes | none |

Two earlier forms of these harnesses also ran out of 10 GiB, and the
harnesses above replace them. One was a token round trip with every field
symbolic. The other was the whole first-flight reader over symbolic CRYPTO
frames, on a 69-byte ClientHello and on 8 to 24 arbitrary bytes. The
replay `version::first_flight::tests::the_reader_allocates_nothing_on_any_first_flight`
costs the whole reader instead. It covers 170 payloads: a whole offer,
shuffled frames, every truncation and every flipped byte. Each asks for
0 bytes.

### TLA+ (`tla/VersionResources.tla`)

The model has one client connection and one server connection. Each
threads a store through `Resources.tla`, in the code's order. The steps
are: trying an offered version, adopting it, dropping tried keys,
settling, restarting after Version Negotiation, copying and checking a
Retry and deriving its keys, a server accepting with or without
retaining keys, and dropping them. The rest of each connection takes and
frees budget between steps, so any charge can be refused. `Resources.tla`
compares a step's peak with what is reserved at the step's end. A charge
given back after the storage it paid for is freed therefore starts a step
of its own (`ClientRelease`, `ServerRelease`). A release inside a step
would hide the storage it paid for. Units are K = 2 (a key set), T = 1
(the expanders), P = 1 (a Retry copy), with a limit of 5.

| Config | Must | Result |
| --- | --- | --- |
| `VersionResources_base` | pass `ClientPaid`, `ServerPaid`, `ClientWithinLimit`, `ServerWithinLimit`, `ClientTracks`, `ServerTracks` | passes, 7,584 distinct states |
| `_without_chargefirst` | violate `ClientPaid`: keys derived, then the budget refuses | violated by `ClientTry` |
| `_without_coverderivation` | violate `ClientPaid`: the charge is the keys' size alone (the bug fixed above) | violated by `ClientTry` |
| `_without_freefirst` | violate `ServerPaid`: the charge is released before the keys are freed | violated by `ServerDrop` |
| `_without_chargerederive` | violate `ClientPaid`: a restart derives beside the old keys uncharged | violated by `ClientRestart` |
| `_without_chargeretrycopy` | violate `ClientPaid`: the Retry copy is uncharged | violated by `ClientRetryCopy` |
| `_without_honorrefusal` | violate `ClientWithinLimit`: a charge goes on past a refusal | violated by `ClientTry` |
| `_reaches_refusal` | violate `NeverRefused` | violated |
| `_reaches_upgrade` | violate `NeverUpgradedWithRetry`: a client follows a Retry and adopts version 2 while a server retains keys | violated |
| `_reaches_restart` | violate `NeverRestartedAfterRefusal` | violated |

### Replays and tests

- `crypto::rustls::tests::initial_key_derivations_stay_within_their_charge`
  covers 18 real derivations through the counting allocator: drafts,
  version 1 and version 2, both sides, and connection IDs of 0, 8 and 20
  bytes. Each holds at most its charge. Each asks for at most the charge
  plus one expander, since three expanders are made but only two live at
  once. Closest: 2032 of 2096 bytes held, 2280 of 2280 bytes asked for.
- `tests::version_budget::a_server_retry_allocates_nothing_beyond_its_buffer`
  costs `Endpoint::retry` for versions 1 and 2 with nothing allowed. It
  passes: 0 bytes asked for.
- `tests::version_budget` also runs two engines with a budget that has
  room for everything but one charge: one byte short of
  `initial_keys_charge`, or no room at all for the Retry copy. A server
  that cannot pay for retained keys completes in version 1. A client that
  cannot try version 2 holds nothing more and stays in version 1. Once
  the budget frees, the server's next Initial completes the handshake in
  version 2. A client that cannot restart ignores Version Negotiation,
  then restarts on the next one. A client that cannot check or follow a
  Retry discards it, then follows the next one. All five pass.
- `packet::retry::tests` checks the Pseudo-Packet layout and its charge.
  The RFC 9369 Appendix A.4 Retry vector now runs through
  `tag_in_place` and `PseudoPacket`.

Scratch controls for the replays and tests, each reverted:

- Charging the keys' size alone (`initial_keys_charge` without the
  expanders) fails `initial_key_derivations_stay_within_their_charge`:
  2032 bytes held against a charge of 1728.
- Making `unprocess_packet` do nothing fails the Version Negotiation and
  Retry budget tests. The client ignores every later packet.
- Copying the packet for the server's tag fails
  `a_server_retry_allocates_nothing_beyond_its_buffer`.
- Ignoring a refused `KeyCharge` fails the four budget tests that need a
  refusal.
- The old decode of a token's time fails
  `a_token_issued_past_the_end_of_time_is_refused`: it panics.
- In `VersionResources.tla`, each `_without_` config above is a control,
  and each violates the invariant it names.

### Not covered

- A restart after Version Negotiation starts a new TLS session. The TLS
  session is outside the budget on every path, version 1 included.
  `initial_keys_charge` covers only the Initial keys.
- `initial_keys_charge` is measured from the rustls provider's types.
  That two expanders at most are live comes from reading rustls'
  `Keys::initial` and `KeyBuilder`. The replay confirms it for ring.
- The Kani harnesses use stand-in keys and a stand-in token AEAD. The
  real derivation is bounded only by the replay.
- `cargo xtask quic-verify resources` runs the harnesses that passed
  above and the ten configs. Its Kani step runs in a 16 GiB scope, as for
  HPACK. The verdicts recorded here come from the same harnesses and
  flags, run one at a time in a 10 GiB scope, and from TLC run by hand on
  each config. The command itself has not been run end to end.
- `version_information_checks_the_connection_without_allocating` has no
  verdict, and `quic-verify` leaves it out.
