# MPTCP and listener state machines

Sources are [RFC 8684](https://www.rfc-editor.org/rfc/rfc8684),
[RFC 9293](https://www.rfc-editor.org/rfc/rfc9293), and
[RFC 5681](https://www.rfc-editor.org/rfc/rfc5681). These are finite models of
specific cuts through the implementation, not a proof of an arbitrary TCP
network or a refinement proof of all Rust instructions. Each model's header
names the functions its actions and flags stand for.

| Spec | Cut and Rust correspondence | Properties |
|---|---|---|
| Connection | `extras/src/linux/mptcp.rs` (the listener moved there from `demos/honeypot/src/mptcp.rs` in 5494f1ad1): `complete` and `read_ack` on the MP_CAPABLE third ACK with or without data or the option, and the first mapping `DataLevel::new` seeds; `answer_syn` and `Answers::syn` on an MP_JOIN SYN; `JoinCookies` keeping or losing what a cookie-answered join carried; `Answers::cookie`, `complete`, and `answer_ack` on the join's third ACK with a missing or bad HMAC, MP_TCPRST refusal, and plain fallback; `Dss::received` on a keyed MP_FASTCLOSE | Joined subflows authenticated; cookie state retained; fast close authenticated; a join the server recognizes never falls back to plain TCP; third ACK data mapped; reset reason defined |
| Data | `src/stdlib/protocols/mptcp.rs`: `Receiver::received` maps subflow offsets to data offsets, `Receiver::arrived` completes and checksums each mapping, `DataStream::admit` and `deliver` reassemble in data order behind the DATA_FIN boundary, and `Receiver::fallback` chooses plain TCP or failure | Mapping immutable; delivery contiguous and ordered; no bytes at or beyond DATA_FIN; corrupt data never accepted; fallback cannot discard a gap or FIN |
| Listener | `src/stdlib/network/tcp/engine.rs`: `TcpLayer::attempt` keeps a SYN or issues a cookie, `ingress` sends a repeated SYN to the handshake that owns its tuple, `take_cookie` and `completed` put a finished handshake in `ready`, `offer` hands it to `accept`, `housekeeping` retires a closed connection in TIME-WAIT, and `expire_handshakes`, smoltcp's TIME-WAIT timer, and the `MAX_TIME_WAIT` cap free state | Unauthenticated cookies never open connections; repeat SYNs reuse state; TIME-WAIT and a live connection cannot own the same tuple; the ready queue stays within the backlog, which the code failed until `ingress` dropped a kept handshake's ACK while it is full (see Listener below) |
| Observation signals | `demos/honeypot/src/observe.rs`, `Observer::observe` and `expire`: one probe per attachment and endpoint tuple with its current initial sequence; first and repeated SYNs, matching server answers and third ACKs, payload, close, and expiry | Trigger needs the first SYN's IPv4 options and a live repeat; no-data needs MP_CAPABLE and no payload; handshake sequences match; a repeat SYN preserves the first SYN's options and time and changes no other attempt, except that a new initial sequence ends its tuple's attempt; completed attempts stay complete |
| Observation | `demos/honeypot/src/observe.rs`, `Observer::syn`, `answered`, and `expire`, and the source lifetime contract around routed connections | Exact sliding-window counts; no source retained after its last connection closes; cleanup of an obsolete answer epoch preserves a fresh answer |

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
outside this state model. The listener's own tests of token and cookie
storage went with 26bae22a5; `extras/src/linux/mptcp.rs` now tests only how
joined subflows release their wakers. TCP cookie authentication is symbolic
here; Linux's cookie encoding is tested in fictionet-extras
(`extras/tests/linux.rs`), not asserted as a core standard.

The model starts a join after its SYN-ACK. `answer_syn` refuses a join SYN at
once when its token names no open connection (MP_TCPRST "MPTCP-specific
error"), a connection on another port, or, after a SYN cookie, a full one
("administratively prohibited"). Those refusals, `MAX_SUBFLOWS`, an ACK that
carries MP_CAPABLE as well, and a connection that closes while its join is
in flight are outside the model. `phase = "plainCookie"` is what the code
does with a cookie-answered join whose third ACK carries no MP_JOIN:
`Answers::cookie` looks for the kept join only when the ACK has MP_JOIN, so
`complete` sees a plain SYN cookie return and the connection is taken as
plain TCP, as Linux does (`mptcp_subflow_init_cookie_req`). `JoinNeverPlain`
therefore covers the joins the server can recognize: a kept SYN, or a cookie
whose ACK carries MP_JOIN.

Data models complete one-byte mappings, so its finite offsets can explore
all permutations and reinjections without tracking payload strings. The Rust
regressions also exercise partial mappings and full TCP sequence wraparound.
Checksum validation is an atomic guard; the independent Lean arithmetic
checks its bytes. The model represents accepted data as its position in the
stream and makes delivery of a gap visible in `Ordered`. DATA_FIN is a data
boundary, not the subflow FIN. Loss of mappings after buffered data or FIN
requires an error instead of silently discarding the data-level state. Where
the model disables a step, the code ends the connection: a conflicting
mapping, a wrong checksum, and a FIN before data already admitted are each a
terminal `DataError` that drops the queues (`DataLevel::update`). The code
refuses data past the FIN at admission (`DataStream::admit`,
`DataRange::within`); the model refuses to deliver it, so `RespectFin`
stands for that check at a different point. The MP_CAPABLE mapping with
data, which a DSS at the same subflow offset may replace once
(`ReceivedMapping::seeded`), is outside the model.

Listener abstracts time into explicit expiry transitions. It checks safety,
not TCP retransmission timing or congestion-control convergence. It separates
the ready backlog from embryonic connections. `attempt` issues a cookie once
embryonic and ready handshakes together reach the backlog. While `ready`
alone is full, `take_cookie` refuses a cookie ACK and `ingress` drops an
ACK that would complete a kept handshake, which stays in SYN-RECEIVED and
sends its SYN-ACK again, as Linux does (`sk_acceptq_is_full` in
`tcp_v4_syn_recv_sock`). Before that check in `ingress`, `completed`
pushed a kept handshake into `ready` unchecked, and `Listener_base` failed
`BoundedBacklog`: with a backlog of two, two kept handshakes and one
cookie, the cookie ACK brought `ready` to one and the two kept handshakes
then completed, so `ready` held three (in general up to twice the
backlog). The test
`kept_handshakes_complete_only_while_the_backlog_has_room` in
`src/stdlib/network/tcp/tests.rs` plays that trace against the code. The
per-peer limit, `reset_full_queue`, and a missing cookie codec are not
modeled.
`duplicate` is a history bit recording that a repeated SYN allocated
duplicate state, and `forged` records accepting an unauthenticated cookie.

Observation's `recent` is history used by its independent count specification;
Rust expires and frees those records. `epoch` represents the most recent SYN
for an answer key, including repeated SYNs. Old pending records cannot delete
its fresh answer count. One `Window` stands for both the burst window and
the 63-second answer timeout; no property relates the two. Routing is already
stateless per source on this branch: `Routed::poll_recv` does not insert
source entries at all. `routed` models the source ownership contract of live
connections, not an actual extra routing map, and `LastClose` is a flag of
the model alone: nothing in the code corresponds to it, and
`Observation_without_lastclose` shows only that `RoutedExact` depends on it.
The Rust test `a_public_route_keeps_nothing_per_source` checks that property
with real simulated connections and detachment. No new source table was
added.

`Observation_signals.cfg` runs the signal sub-specification in the same
module (`SPECIFICATION SignalSpec`) with its three invariants and three
action properties enabled, and must pass. It retains the two sources, three
SYNs, two-tick window and four-tick clock, adding two initial sequence
values per tuple. This avoids the unrelated counter/routing state product
without pruning any signal states. A source here abstracts attachment plus
both endpoints. The code keeps one probe per tuple with its current initial
sequence (`Probe::seq`, since a07862da5; before, the sequence was part of
the key): a SYN with a new initial sequence on a tracked tuple ends that
tuple's attempt without a report, whether or not the new SYN starts one, and
the model resets the other sequence's probe the same way. Plain SYNs without
IPv4 options or MP_CAPABLE create no probe. The first SYN can carry payload;
a repeat retains the first options and time, and cannot reopen a completed
attempt. A repeated SYN on a probe that had IPv4 options is a trigger
whether the attempt is pending or completed; the code's
`IpOptionsRetransmit` carries its `phase`. Matching SYN-ACKs replace the
server sequence until the handshake completes. Pending data and close
require the client's next sequence, while completed data follows the tuple.
Close and expiry are per-attempt subactions; payload on a third ACK is
included in completion. Packet parsing, checksums, 32-bit arithmetic, the
`STATE_LIMIT` cap, and simultaneous mutation of several attempts are covered
by Rust tests rather than asserted as a refinement of this finite state
model. The model permits closing pending attempts, so no-data is not claimed
to prove a completed handshake or malicious intent.

Signal records and completed-handshake records are sets of every distinct
emitted record. The first version kept ordered sequences; neither transitions
nor properties read their ordering or multiplicity. Mapping each sequence to
its set of elements commutes with every update, and universal safety invariants
have exactly the same truth value over both representations. This removes
irrelevant event permutations and duplicates while retaining every distinct
record. No source, clock, sequence, event or probe bound is reduced,
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
fail. The runner (`cargo xtask mptcp-verify`) checks each ablation property
separately and rejects unexpected passes. Passing configurations keep all
their checks enabled in one complete exploration; only a successful,
error-free completion passes the entire group. Connection removes HMAC
validation, cookie retention, fast-close key validation, or the ban on join
fallback. Data removes mapping immutability, gap waiting, the FIN boundary,
checksum validation, or fallback preservation. Listener removes queue bounds,
cookie validation, SYN reuse, or TIME-WAIT protection. Observation removes
expiry, last-close deletion (the model's own flag, see above), or matching
of answer epochs.

## Modelling corrections

The first draft omitted parentheses around Boolean assignments in TLA+.
That excluded some false-valued transitions and caused two ablations to pass.
Parenthesizing the assigned expressions restored those transitions; bounds and
properties were unchanged. Parse errors in the fallback conjunction were also
corrected. All sixteen ablations then produced the expected counterexample.

On 2026-11-09 three models were brought to the code at e2858ccc4.
Connection gained the `plainCookie` outcome. Listener's `Ack` was first
changed to bound `ready` only for an ACK that returns a cookie, as the code
did, which made `Listener_base` fail; the code was then fixed to drop a
kept handshake's completing ACK while `ready` is full, and `Ack` bounds
both paths again (results below the paragraph after this one). Observation's signal
sub-specification got one probe per tuple, a trigger in any phase, and a
server sequence fixed at completion; `TriggerEvidence` no longer requires a
pending attempt, and `OtherAttemptsPreserved` allows the same tuple's other
sequence to be ended. TLC with two workers: Connection_base finds no error
(102 states generated, 66 distinct) and each of its four ablations violates
the property it names. Listener_base, with `Ack` following the code as it
was, violated `BoundedBacklog` (1,158 generated, 257 distinct; the
seven-state trace is the one above) while the other three invariants
passed (6,439 generated, 973 distinct); with the fix in `ingress` and
`Ack` bounding both paths it finds no error (5,053 generated, 966
distinct), and each of its four ablations violates the property it names
(`_without_boundqueue`: `BoundedBacklog`, 1,332 generated, 273 distinct).
Data_base finds no error (8,524 generated, 2,061 distinct) and each of its
five ablations violates the property it names. Observation_base finds no
error (253,639 generated, 48,357 distinct) and its three ablations violate
the property they name. Observation_signals finds no error (97,225,453
generated, 12,098,730 distinct, 25 minutes with two workers).
