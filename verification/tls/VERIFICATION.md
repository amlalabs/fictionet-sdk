# TLS layer: what was modeled and found

This pass covers the server TLS layer of the protocol-layer work:
`TlsLayer` in `src/stdlib/services/tls/layer.rs` (handshake progress,
application data each way, close_notify and the peer's close, reset, write
completion and backpressure from the stream below), the live adapter in
`src/stdlib/services/tls.rs` (`Io` and `TlsConnection`, with write
cancellation and retry), and the crypto provider in
`src/stdlib/services/tls/provider.rs`, which now carries the run's entropy
in the `Arc` fields of the vendored rustls `CryptoProvider`
(`rustls/src/crypto/mod.rs`). The write accounting that used to live in
`tls/output.rs` is now `TlsLayer`'s `produced`, `delivered`,
`pending_plaintext`, `fence` and `credit`, and `TlsConnection`'s
`credited` and `pending_write`; both are covered here. The file itself
moved to `tests/support/sandbox/output.rs`, the sandbox's test client on
upstream rustls, and is not part of this pass. The models are under
`verification/tls/`, with the commands to run them in its
[README](README.md).

Two bugs were found, each confirmed by a test that failed on the code
before its fix. Both let the layer write ciphertext after it had ended
its stream.

## Bug 1: a bad record after close_notify panicked rustls

After the server queued close_notify, a client that sent one more record
with a bad MAC (or any record rustls rejects) made rustls call
`send_fatal_alert`, which starts with `debug_assert!(!self.sent_fatal_alert)`.
`send_close_notify` sets that flag, so in debug builds, which include the
test profile, any client could panic the world's TLS task this way. In
release builds rustls queued the alert, and the layer wrote it after its
`StreamCommand::End`. The TLS 1.2 `no_renegotiation` warning had the same
path: a renegotiating ClientHello after close_notify queued a warning
alert after End. The release behavior and the renegotiation path are read
from the code and the model; the test below runs the debug path.

Found by `Layer_without_quietafterclose.cfg` (rustls as it was): after the
handshake the application ends its side, the layer drains close_notify
and sends End, the peer sends a record rustls rejects, rustls queues an
alert, and the layer hands it below after End (`NoWriteAfterEnd`).

Reproduction: `a_bad_record_after_close_notify_writes_nothing_after_the_end`
in `tests/it/tls_layer.rs`. After the handshake the server ends its side;
the client writes `still talking` and flips the last byte of the record.
Before the fix the test panicked at `rustls/src/common_state.rs:606`,
`assertion failed: !self.sent_fatal_alert`.

Fix (`37e035ba1`): in the vendored rustls, `send_fatal_alert` and the
`no_renegotiation` warning queue nothing once close_notify or a fatal
alert is sent, as `send_close_notify` already did. The error is still
returned. The fork's README lists the change.

## Bug 2: hello work finished after the client left wrote a handshake

`TlsLayer` blocks the peer's bytes while the world chooses a config, but
not the end of its input. A client that closed its side then failed the
layer with `HandshakeError::Closed`, and the layer ended its stream. When
the world's answer came afterwards, `on_done` still built the
`ServerConnection` and wrote its first flight, or the `unrecognized_name`
alert for `None`, after End. The live adapter cannot reach this (it reads
no more input until the hello is answered), but any driver that delivers
input while the work is outstanding can, including `Harness` and a
`Chain` under a world that answers asynchronously.

Found by `Layer_without_droplatedone.cfg` (`on_done` as it was): the
hello arrives, the layer asks for work, the peer ends its input, the
layer fails and sends End, the world rejects the name, and the layer
writes the alert below after End.

Reproduction: `hello_work_finished_after_the_client_left_sends_nothing`
in `tests/it/tls_layer.rs`, for both `Some(config)` and `None`. Before the
fix the commands below were `["End", "Write(Chunk { len: 1087, .. })"]`.

Fix (`37e035ba1`): `on_done` takes the hello and sends nothing once the
layer has failed (`layer.rs:394`).

The existing tests missed both because `Harness` answers a write after End
with `Admit::Closed` and drops it.

## The layer: `Layer.tla`

[`Layer.tla`](tla/Layer.tla) is `TlsLayer` as `Driver` runs it, with the
driver's held command, a carrier that takes ciphertext as slowly as it
likes (in parts) and reports completions with `StreamEvent::Written`, an
application above that offers writes, End and Reset (and drops a refused
write: a cancelled write), the world doing the hello work, and a peer.
The connection is one record; its fields named after `TlsLayer`'s are
those fields, and each operator is the Rust function it names:

| Model | Rust |
| --- | --- |
| `Handshaking`, `OutputPending`, `Fail`, `CreditWritten`, `Abort` | `is_handshaking` (`layer.rs:120`), `output_pending` (`:140`), `fail` (`:148`), `credit_written` (`:199`), `abort` (`:171`) |
| `AdvanceNext`, `Produce`, `Read` | one call of `advance` (`:416-534`) that returns `Ok(true)` or an error, in its order: reset, hello, the output arm (`:455-490`, fence at `:482-488`), the plaintext arm (`:491-521`), End (`:522`), the failure (`:527`) |
| `DeliverInput`, `DeliverData`, `DeliverEnded`, `Accept`, `Process` | `on_event` for the peer's bytes, its end and a reset (`:217-330`), with what the acceptor and `process_new_packets` may make of the bytes |
| `DeliverWritten` | `on_event(Written)` (`:223-233`) |
| `UpperCommand`, `UpperCancels` | `on_command` (`:332-383`); dropping a refused write |
| `UpperTakes`, `TakeWork`, `Done` | `take_event` (`:540-545`), `take_work` (`:547`), `on_done` (`:385-414`) |
| `TakeCommand`, `CarrierTakes` | `Driver::send_below` and `take_command`; a carrier taking part or all of a write, End, or Reset, and refusing (dropping) a write after End or a reset, as `Harness` does |

rustls is abstract: its send queue (other output, the pending write's
record, output after it), a queued KeyUpdate reply that goes out with the
next message, decrypted plaintext, close_notify received, EOF, and
close_notify or a fatal alert sent. In "hs" the peer's bytes may make
progress, finish the handshake (with or without a NewSessionTicket), or
fail it (with or without an alert); in "open" they may carry plaintext,
close_notify, a KeyUpdate, a TLS 1.2 renegotiation, or fail. Bytes are
units: CHUNK is two units and a record adds one, so a record of two units
spans two chunks, as a 16 KiB record does.

Two constants are the fixes (`QuietAfterClose`, `DropLateDone`), one is
an assumption about rustls (`RustlsHoldsEarlyData`), and the rest drop one
rule of the code each.

What is checked:

- `Conservation`, `Bounded`: every unit counted in `produced` is
  completed, still out (in the layer, in the driver, taken but not yet
  reported) or dropped by a closed carrier; completions never pass what
  was produced, even from a carrier that reports a byte it never took.
- `ExactlyOnce`: each accepted plaintext unit is acknowledged upward,
  lost to a reset, or still owed: never acknowledged twice.
- `CreditAfterDelivery`: a write is acknowledged only after the carrier
  completed every unit of the ciphertext that carries it.
- `NoWriteBeforeHandshake`, `NoReadBeforeHandshake`: no plaintext is
  accepted for sending, or handed up, before the handshake ends. The
  second rests on rustls: the layer itself does nothing to stop it.
- `NoPlaintextAfterClose`, `NoWriteAfterEnd`, `EndAfterDrainInv`,
  `OneEnd`: nothing is accepted after close_notify is queued, nothing goes
  below after End, End follows all ciphertext, and goes once.
- `ResetStops`: after a reset nothing more is written or credited.
- `FlushedMeansCredited`: when the driver holds nothing, every completion
  was delivered and the layer has no output pending, no accepted write is
  still waiting for credit. This is what `TlsConnection::poll_write`
  relies on when it returns Pending without a waker (`tls.rs:587`, `614`,
  `623`).
- `PendingResolves`, `CloseCompletes`, `FailureReported`,
  `PlaintextDelivered`: an accepted write is eventually acknowledged or
  the layer returns an error; close_notify or a failure ends the stream
  below; a failure is returned once its alert is out, unless a reset comes
  first; decrypted plaintext reaches the application, half-closed or not.
  These hold given weak fairness of `advance`, the driver moving output,
  the carrier taking what it is given, completions being delivered, the
  application taking events, and input being offered.

| Config | Generated | Distinct | Depth | Result |
| --- | ---: | ---: | ---: | --- |
| `Layer_base.cfg` (4 inputs, 3 commands) | 87,442,726 | 19,064,177 | 78 | all 13 invariants hold |
| `Layer_live_base.cfg` (3 inputs, 2 commands) | 4,582,386 | 1,178,906 | 58 | all 13 invariants and 4 properties hold |
| `Layer_repeat_base.cfg` (a carrier that lies once) | 220,748,032 | 48,257,577 | 79 | `Bounded`, `ExactlyOnce` hold |
| `Layer_without_quietafterclose.cfg` | 2,048,577 | 567,978 | 24 | `NoWriteAfterEnd` violated: bug 1 |
| `Layer_without_droplatedone.cfg` | 81,654 | 26,715 | 14 | `NoWriteAfterEnd` violated: bug 2 |
| `Layer_without_checkwritten.cfg` | 263 | 181 | 5 | `Bounded` violated |
| `Layer_without_countproduced.cfg` | 309 | 188 | 6 | `Conservation` violated |
| `Layer_without_fence.cfg` | 80,545 | 26,236 | 14 | `CreditAfterDelivery` violated |
| `Layer_without_takecredit.cfg` | 258,827 | 79,974 | 18 | `ExactlyOnce` violated |
| `Layer_without_checkhandshake.cfg` | 56 | 47 | 5 | `NoWriteBeforeHandshake` violated |
| `Layer_without_rustlsholdsearlydata.cfg` | 20,017 | 7,293 | 11 | `NoReadBeforeHandshake` violated |
| `Layer_without_checkclosing.cfg` | 273,888 | 85,152 | 18 | `NoPlaintextAfterClose` violated |
| `Layer_without_endafterdrain.cfg` | 17,925 | 6,637 | 11 | `EndAfterDrainInv` violated |
| `Layer_without_endonce.cfg` | 5,395 | 2,174 | 9 | `OneEnd` violated |
| `Layer_without_abortclears.cfg` | 839 | 417 | 6 | `ResetStops` violated |
| `Layer_without_creditonwritten_flush.cfg` | 198,944 | 62,115 | 17 | `FlushedMeansCredited` violated |
| `Layer_without_creditonwritten.cfg` | 317,450 | 93,546 | | `PendingResolves` violated |
| `Layer_without_clearalert.cfg` | 325,600 | 96,357 | | `FailureReported` violated |
| `Layer_without_clearalert_close.cfg` | 259,628 | 78,017 | | `CloseCompletes` violated |
| `Layer_without_readafterclose.cfg` | 4,136,305 | 1,077,659 | | `PlaintextDelivered` violated |

The passing runs explored their whole space; TLC stops at the first
violation in the others (the liveness ones report no depth). Each was run
as `java -Xmx5g ... tlc2.TLC -workers 4 -config <cfg> Layer.tla` under an
8 GB memory cap.

### What `Layer.tla` leaves out

rustls is abstract: record framing, where chunk boundaries fall, real
bytes and cryptography are not modeled, and each delivery of the peer's
bytes is one of the outcomes listed above, with a chunk split at most once.
That rustls yields no plaintext before the handshake ends, and encrypts a
whole accepted write at once into its send queue, are assumptions; the
first is a constant so its role shows. The acceptor's `Ok(0)` read
(`layer.rs:294`), a `read_tls` error on EOF, and `process_new_packets`
failing on EOF are not modeled. The budget never refuses: a refusal
changes nothing by the layer rules, so it is a stutter for safety, and
the liveness properties assume the budget eventually has room. Driver
steps interleave freely with inputs, which covers `Harness` and `Io`,
both of which run `advance` in a loop between inputs. One write is in
flight at a time, as the code allows. Timers are not modeled (the layer
has none). Hello contents (SNI, ALPN) and the `first_byte` rule are
reduced to "a TLS hello or not".

Observations, not changed: completing hello work after a reset returns
`Err("TLS configuration without a client hello")` instead of being
ignored (`Done` in the model, `layer.rs:390`); after a reset the driver
still writes the chunk it already holds before the Reset, and its
completion is refused as closed; `Io` turns `StreamCommand::Reset` into
`poll_shutdown`, a clean close, because `Connection` has no reset (the
live adapter never sends one).

## Write cancellation: `Write.tla`

[`Write.tla`](tla/Write.tla) is `TlsConnection::poll_write`
(`tls.rs:570-633`) over `Io::poll_flush` (`tls.rs:165`), one call per
step, as the synchronous function it is. A caller writes a short string;
the flushes inside may return Pending (the connection registered the
waker), fail, or return Ready. After a Pending the caller retries the same
bytes, or drops the future and later writes other bytes. The layer is
abstract: it takes one write at a time, and a Ready flush has credited
every accepted write, which is `FlushedMeansCredited` above.

What is checked: `ConfirmedOnce` (no write is confirmed twice),
`ConfirmedIsTheCallers` (`Ok(k)` only when the call's first `k` bytes are
the write it confirms), `NoDuplicate` (a retry never sends its bytes
again: a new write is accepted only after the one before was confirmed or
given up for other bytes), `NoHang` (Pending only when the connection will
wake the caller).

| Config | Generated | Distinct | Depth | Result |
| --- | ---: | ---: | ---: | --- |
| `Write_base.cfg` (strings of up to 3 bytes over 2 letters, 2 per write, 5 calls) | 3,639,133 | 1,297,110 | 16 | all four hold |
| `Write_without_matchcontent.cfg` | 1,611 | 991 | 6 | `ConfirmedIsTheCallers` violated |
| `Write_without_takepending.cfg` | 1,823 | 1,148 | 6 | `ConfirmedOnce` violated |
| `Write_without_rememberwrite.cfg` | 131 | 110 | 4 | `NoDuplicate` violated |
| `Write_without_flushcredits.cfg` | 19 | 18 | 3 | `NoHang` violated |

### What `Write.tla` leaves out

The layer and the connection below are abstract; credit moves only inside
`poll_write`'s flushes, while in the code `poll_read` also collects it,
which only makes credit arrive sooner. `poll_shutdown` and the budget
charges are not modeled. Matching a retry by content is a design limit
the code states (`tls.rs:617`): a caller that drops a pending write and
writes other bytes leaves the earlier bytes sent and never confirmed.

## Proofs against the Rust: `kani/LayerProof.rs`

[`LayerProof.rs`](kani/LayerProof.rs) is compiled into `tls::layer` under
`cfg(kani)` and calls the production code. rustls is too large for CBMC,
so no harness builds a `ServerConnection`: each starts from an
accounting state the code reaches after a write was accepted and its
ciphertext produced. Kani does not run the output arm of `advance`, which
sets the fence: it allocates a 16 KiB chunk, and with it in a harness
CBMC passed the 10 GB cap twice (as the first and the only step of a
schedule). Where the fence goes is checked in `Layer.tla` and by the
existing test `ciphertext_completion_is_not_admission_and_close_follows_data`.
The layer is given an `Entropy` that panics on any draw.

| Harness | Proves |
| --- | --- |
| `a_completion_credits_the_pending_write_once_at_its_fence` | from any reachable accounting state and any `Written(n)`: refused with an error and no change when `n` is more than what is out; otherwise `delivered` grows by `n`, the pending write is credited exactly when `delivered` reaches the fence, `credit + pending_plaintext` is unchanged, and `take_event` hands the whole credit up once; no overflow |
| `a_write_is_acknowledged_once_after_its_ciphertext_completes` | after one accepted write of up to CHUNK bytes whose ciphertext of any length is out, with the fence where `advance` puts it, over every schedule of six steps (complete any part of what is out, take events): acknowledged + owed + pending equals the write, the write is credited exactly when the completions reach the fence, and `produced = delivered + out` |
| `a_reset_drops_what_is_owed_and_sends_only_a_reset` | from any accounting state, a reset from above drops what is owed and pending, refuses later completions as closed without counting them, credits nothing more, and sends one Reset and nothing else |

| Harness | Checks | Result |
| --- | ---: | --- |
| `a_completion_credits_the_pending_write_once_at_its_fence` | 16,584 | all pass, 12.8 s |
| `a_write_is_acknowledged_once_after_its_ciphertext_completes` | 16,544 | all pass, 30.7 s |
| `a_reset_drops_what_is_owed_and_sends_only_a_reset` | 18,389 | all pass, 35.5 s |

Each run was `cargo kani -p fictionet --harness <name>` under a 10 GB
memory cap. The counts stay below 2^62 by assumption: a connection does
not move 4 EiB.

Each harness was also run against a deliberately broken `layer.rs`, and
the change reverted:

| Mutation | Harness | Result |
| --- | --- | --- |
| `credit_written` keeps `pending_plaintext` (`layer.rs:202` deleted) | `a_completion_credits_...` | 1 of 16,578 failed: `layer.pending_plaintext == 0` |
| `credit_written` credits one byte before the fence (`delivered + 1 >= fence`) | `a_write_is_acknowledged_...` | 1 of 16,545 failed: `layer.delivered >= end` |
| `abort` keeps the credit (`layer.rs:189` deleted) | `a_reset_drops_...` | 1 of 18,383 failed: `(credit, pending_plaintext) == (0, 0)` |

## Entropy: `entropy.rs`

The provider's randomness reaches rustls in three places: the
`SecureRandom`, each key exchange group, and the signing key (RSA
blinding and PSS salts; ECDSA is RFC 6979 and draws nothing). The tests
build rustls client and server configs on `crypto_provider` with counting
seeded entropy and run whole connections in memory (handshake, a request
and a reply, close_notify both ways) for the CA's ECDSA key and an
RSA-2048 key from the rustls test CA, for each group (X25519, P-256,
P-384), over TLS 1.2 and 1.3:

- `the_provider_draws_only_from_its_own_entropy`: the same seeds send the
  same bytes each way and draw the same amounts; each side's bytes change
  when, and because, its own seed changes; each provider draws.
- `each_part_of_the_provider_draws_from_its_entropy`: a server provider
  whose `SecureRandom`, groups or key provider alone come from other
  entropy sends different bytes (the key provider only for RSA).
- `connections_stepped_in_turn_send_what_each_sends_alone`: two
  connections with different providers, stepped alternately on one thread,
  send exactly what each sends alone: no state is shared between
  providers, and nothing depends on a thread-local.

All three pass. Each was run against a deliberately broken provider and
the change reverted:

| Mutation of `provider.rs` | Result |
| --- | --- |
| X25519 secrets from `ring::rand::SystemRandom` (operating-system randomness) | all three fail; first: `example.test X25519 TLSv1_2: the same seeds sent different bytes` |
| `CxRandom::fill` from one process-wide seeded source instead of its own | all three fail; the interleaving test with `connection a` |
| X25519 secrets constant, ignoring the entropy | `each_part_...` fails with `key exchange`; the other two pass |

What the tests do not cover: a draw whose bytes never reach the wire, or
ambient randomness that happens to repeat within one process, would not
show. ECH (which also keeps its random source in an `Arc` in the fork) is
not exercised. That `CryptoProvider` holds its parts in `Arc`s rather than
`&'static` is checked by the compiler, not here.
