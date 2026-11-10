# QUIC

The vendored `quinn-proto` engine uses the workspace rustls fork. It is
not yet wired into a Fictionet layer, and its storage is not yet charged
to Fictionet budgets. This directory records evidence as that work grows;
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
systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=14G -p MemorySwapMax=0 cargo kani -p fictionet-quinn-proto --lib --harness amplification_proofs
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
