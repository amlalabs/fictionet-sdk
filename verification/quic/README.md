# QUIC

The vendored `quinn-proto` engine uses the workspace rustls fork. It is
not yet wired into a Fictionet layer. Owned stream writes can retain charged
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
seeding. Engine storage admission, the datagram layer, application stream
multiplexing, RFC 9221 and the HTTP/3 coordinator remain unimplemented.

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
the source-admission harnesses have not yet returned completed verdicts.
Run them with `cargo kani -p fictionet-quinn-proto --lib -Z stubbing
-Z c-ffi -Z mem-predicates -Z restrict-vtable --harness source_proofs` under
the required scope. The ordinary tests, model and counter check do not
substitute for these unfinished proofs.

This is a payload-ownership step. Descriptor capacity, interval nodes,
packet records, receive reassembly, crypto queues and endpoint routing
storage still require admission and resource evidence. The entire engine
must not yet be described as bounded by a Fictionet budget.
