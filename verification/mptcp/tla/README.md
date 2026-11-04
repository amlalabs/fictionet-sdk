# MPTCP and listener state machines

Sources are [RFC 8684](https://www.rfc-editor.org/rfc/rfc8684),
[RFC 9293](https://www.rfc-editor.org/rfc/rfc9293), and
[RFC 5681](https://www.rfc-editor.org/rfc/rfc5681). These are finite models of
specific cuts through the implementation, not a proof of an arbitrary TCP
network or a refinement proof of all Rust instructions.

| Spec | Cut and Rust correspondence | Properties |
|---|---|---|
| Connection | `demos/honeypot/src/mptcp.rs`: MP_CAPABLE third ACK with/without data or the option; MP_JOIN SYN/ACK authentication, cookie retention/eviction, missing or bad HMAC, MP_TCPRST refusal, plain fallback, keyed MP_FASTCLOSE | Joined subflows authenticated; cookie state retained; fast close authenticated; joining never falls back to plain TCP; third ACK data mapped; reset reason defined |
| Data | `src/stdlib/protocols/mptcp.rs`: mappings from subflow offsets to data offsets, complete checksum-validated arrivals, data-level reassembly, DATA_FIN and fallback | Mapping immutable; delivery contiguous and ordered; no bytes at or beyond DATA_FIN; corrupt data never accepted; fallback cannot discard a gap or FIN |
| Listener | `src/stdlib/network/tcp.rs`: SYN backlog, cookies when full, repeat SYNs, completion, application accept, close and TIME-WAIT expiry | Ready queue bounded; unauthenticated cookies never open connections; repeat SYNs reuse state; TIME-WAIT and a live connection cannot own the same tuple |
| Observation signals | Per-attachment endpoint tuple and initial sequence; first and repeated SYNs, matching server answers and third ACKs, payload, close and expiry | Trigger needs initial IPv4 options and a live pending repeat; no-data needs MP_CAPABLE and no payload; handshake sequences match; repeat SYN preserves initial evidence and other attempts; completed attempts stay complete |
| Observation | `demos/honeypot/src/observe.rs` and the source lifetime contract around routed connections | Exact sliding-window counts; no source retained after its last connection closes; cleanup of an obsolete answer epoch preserves a fresh answer |

Bounds are fixed in the checked configurations: Data has three subflow slots
and three data offsets; Listener has three tuples and a backlog of two;
Observation has two sources, three SYN events, two connections per source,
a window of two ticks, and a clock through four. No state constraint prunes
exploration. Connection has one initial connection and one concurrent joining
attempt. Boolean guards represent protocol rules, not reduced bounds. Every
ablation uses the same bounds as its passing configuration.

The Connection model treats matching SHA-256 HMACs as authentication facts.
It explores absent/mismatching/matching final tags and loss of the remembered
cookie exchange. The Lean/Rust crypto vectors check the concrete algorithms,
key and nonce order, and both digest ends. Cryptographic collisions, key
entropy, simultaneous token insertion, and multiple cookie hash slots are
outside this state model. The existing Rust token/cookie tests cover their
concrete storage operations. TCP cookie authentication is symbolic here;
Linux's cookie encoding is tested in fictionet-extras, not asserted as a core
standard.

Data models complete one-byte mappings, so its finite offsets can explore
all permutations and reinjections without tracking payload strings. The Rust
regressions also exercise partial mappings and full TCP sequence wraparound.
Checksum validation is an atomic guard; the independent Lean arithmetic
checks its bytes. The model represents accepted data as its position in the
stream and makes delivery of a gap visible in `Ordered`. DATA_FIN is a data
boundary, not the subflow FIN. Loss of mappings after buffered data or FIN
requires an error instead of silently discarding the data-level state.

Listener abstracts time into explicit expiry transitions. It checks safety,
not TCP retransmission timing or congestion-control convergence. It separates
the ready backlog from embryonic connections: a valid cookie ACK may make
their combined count exceed the backlog, while the ready queue remains bounded.
`duplicate` is a history bit recording that a repeated SYN allocated duplicate
state, and `forged` records accepting an unauthenticated cookie.

Observation's `recent` is history used by its independent count specification;
Rust expires and frees those records. `epoch` represents the most recent SYN
for an answer key, including repeated SYNs. Old pending records cannot delete
its fresh answer count. Routing is already stateless per source on this branch:
`Routed::poll_recv` does not insert source entries at all. `routed` models the
source ownership contract of live connections, not an actual extra routing
map. The Rust test `a_public_route_keeps_nothing_per_source` checks that property
with real simulated connections and detachment. No new source table was added.

`Observation_signals.cfg` runs an independent signal sub-specification in the
same module. It retains the two sources, three SYNs, two-tick window and four-tick
clock, adding two initial sequence values per tuple. This avoids the unrelated
counter/routing state product without pruning any signal states. A source here
abstracts attachment plus both endpoints; distinct initial sequences retain
separate attempts. Plain SYNs without IPv4 options or MP_CAPABLE create no probe.
The first SYN can carry payload; a repeat retains the first options and time,
and cannot reopen a completed attempt. Matching SYN-ACKs can replace the server
sequence. Pending data and close require the client's next sequence, while
completed data follows the tuple. Close and expiry are per-attempt subactions;
payload on a third ACK is included in completion. Packet parsing, checksums,
32-bit arithmetic and simultaneous mutation of several attempts are covered by
Rust tests rather than asserted as a refinement of this finite state model.
The model permits closing pending attempts, so no-data is not claimed to prove
a completed handshake or malicious intent.

Signal evidence and completed-handshake records are sets of every distinct
emitted record. The first version kept ordered sequences; neither transitions
nor properties read their ordering or multiplicity. Mapping each sequence to
its set of elements commutes with every update, and universal safety invariants
have exactly the same truth value over both representations. This removes
irrelevant event permutations and duplicates while retaining every distinct
piece of evidence. No source, clock, sequence, event or probe bound is reduced,
and no event condition or safety requirement is relaxed. The original
Observation counting history is unchanged because its multiplicity matters.

The two properties that quantify `SignalSyn` first test its shared guard:
`syns < MaxSyns /\ now < MaxTime /\ syns' = syns + 1`. Every `SignalSyn`
action already implies that guard, so when it is false every implication under
the original quantifier is true. Guarding the unchanged quantified formula is
therefore logically equivalent and avoids reevaluating all SYN parameter
combinations on non-SYN transitions. This changes no transition, bound or
property requirement.

## Ablations

Each `without_...cfg` disables one guard and names the one invariant that must
fail. The runner checks each ablation property separately and rejects unexpected
passes. Passing configurations keep all their checks enabled in one complete
exploration; only a successful, error-free completion passes the entire group.
Connection removes HMAC validation, cookie retention, fast-close key validation,
or the ban on join fallback. Data removes mapping immutability, gap waiting,
the FIN boundary, checksum validation, or fallback preservation. Listener removes
queue bounds, cookie validation, SYN reuse, or TIME-WAIT protection. Observation
removes expiry, last-close deletion, or matching of answer epochs.

## Modelling corrections

The first draft omitted parentheses around Boolean assignments in TLA+.
That excluded some false-valued transitions and caused two ablations to pass.
Parenthesizing the assigned expressions restored those transitions; bounds and
properties were unchanged. Parse errors in the fallback conjunction were also
corrected. All sixteen ablations then produced the expected counterexample.
