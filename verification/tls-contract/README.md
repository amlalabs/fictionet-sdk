# TLS replacement contract

These bounded models extend [the TLS verification suite](../tls/README.md).
They check composition and selection, not cryptography or the correctness of
arbitrary replacement implementations. Models follow the named Rust transitions;
there is no mechanically checked refinement from Rust to TLA+.

The contract requires ordered, owned plaintext, sticky failure, and stable
negotiated metadata. The application may refuse input indefinitely. Safety holds under refusal; eventual
delivery additionally requires fair scheduling and an application that eventually
accepts. Handshake success itself is not a liveness claim.

Two requested guarantees need qualification:

- DoT intentionally answers in completion order. HTTP/2 has independent exchanges.
  Neither guarantees global request-order responses. The unmodified
  `EncryptedDns_dot_request_order.cfg` and `EncryptedDns_doh2_request_order.cfg`
  both fail `RequestOrder`: accept queries one and two, complete two first, send
  its answer while one is pending. The models check completion order for DoT,
  request order for HTTP/1, and identity and byte order for each HTTP/2 exchange.
- STARTTLS safety no longer rests on each plaintext protocol. `Switch` asks its
  successor which input from before the switch it reads
  (`Successor::inherits`), and `Secure` reads no data, so the switch drops
  whatever plaintext the predecessor hands over or refused and the layer below
  still holds. The STARTTLS model checks the mail handoff in
  `tests/it/services/tls.rs` with the switch's drop: `Starttls_careless.cfg`
  keeps the session's pipelined plaintext and still passes. Stopping at the
  command (`NoPlainPastBoundary`) and handing over only after the go-ahead is
  written (`PlaintextFence`) remain the plaintext protocol's: the switch cannot
  see what it parsed or wrote. Bytes the layer below has not offered by the
  switch reach TLS as its first input, as any bytes in transit do; plaintext
  there fails the handshake.

## Models and results

All negative configurations below terminate with a counterexample to the named
property, rather than a parse error, deadlock, or resource failure. Baselines use
TLC exhaustive breadth-first search. Counts are distinct reachable states; the
liveness run uses weak fairness. Runs used TLC 2.19, Kani 0.68.0 and CBMC
6.11.0 on November 8, 2026.

| Configuration | Result and property |
| --- | --- |
| `Secure_base.cfg` | Pass, 152 states; all six safety invariants |
| `Secure_live.cfg` | Pass, 152 states; `Progress` and `FactoryProgress` |
| `Secure_without_waitestablished.cfg` | Fails `Deferred`: construct before establishment |
| `Secure_without_stopfailed.cfg` | Fails `NoPlaintextOutsideEstablished`: deliver buffered plaintext after failure |
| `Secure_without_takefactory.cfg` | Fails `FactoryOnce`: reuse construction closure |
| `Secure_without_capturenegotiated.cfg` | Fails `NegotiatedValue`: give application the wrong ALPN |
| `Secure_without_takebuffer.cfg` | Fails `ExactlyOnce`: retain a delivered offset |
| `Secure_without_fifo.cfg` | Fails `InOrder`: take the newest buffered offset first |
| `Secure_without_construct.cfg` | Fails `FactoryProgress`: never construct the established connection’s application |
| `Secure_without_drain.cfg` | Fails `Progress`: established connection never drains its buffer |
| `Listener_base.cfg` | Pass, 6,608 states; all eight invariants |
| `Listener_without_keepfirst.cfg` | Fails `FirstFactory`: later site replaces listener owner |
| `Listener_without_localfactory.cfg` | Fails `FactoryIsolation`: use another listener's factory |
| `Listener_without_localcertificate.cfg` | Fails `CertificateIsolation`: select another listener's certificate |
| `Listener_without_localprotocols.cfg` | Fails `ProtocolIsolation`: advertise another site's ALPN |
| `Listener_without_copyconfig.cfg` | Fails `ConfigUnchanged`: mutate the shared source config |
| `Listener_without_waitestablished.cfg` | Fails `ApplicationAfterNegotiation`: build before success |
| `Listener_without_takefactory.cfg` | Fails `ApplicationOnce`: build twice |
| `Listener_without_usenegotiated.cfg` | Fails `NegotiatedApplication`: route using requested rather than negotiated metadata |
| `Starttls_base.cfg` | Pass, 28 states; all three invariants |
| `Starttls_careless.cfg` | Pass, 28 states; the session keeps its pipelined plaintext and the switch drops it |
| `Starttls_without_discard.cfg` | Fails `NoPlaintextReplay`: neither the session nor the switch drops old plaintext, which reaches TLS |
| `Starttls_without_stop.cfg` | Fails `NoPlainPastBoundary`: plaintext parser consumes beyond STARTTLS |
| `Starttls_without_fence.cfg` | Fails `PlaintextFence`: switch before old output completes |
| `EncryptedDns_dot.cfg` | Pass, 106 states |
| `EncryptedDns_doh1.cfg` | Pass, 15 states |
| `EncryptedDns_doh2.cfg` | Pass, 1,802 states |
| `EncryptedDns_without_gate.cfg` | Fails `EstablishedOnly`: admit and answer before TLS establishes |
| `EncryptedDns_without_fifo.cfg` | Fails `ResponseOrder`: interleave/reorder completed DoT answers |
| `EncryptedDns_without_identity.cfg` | Fails `ResponseIdentity`: send an answer to the wrong exchange |
| `EncryptedDns_without_consume.cfg` | Fails `CompletedOnce`: complete the same query twice |
| `EncryptedDns_without_prefix.cfg` | Fails `ByteOrder`: emit an answer suffix before its prefix |
| `EncryptedDns_dot_request_order.cfg` | Expected failure of `RequestOrder` with all production guards enabled |
| `EncryptedDns_doh2_request_order.cfg` | Expected failure of `RequestOrder` with all production guards enabled |

`Secure` explores three distinguishable stream offsets, three ALPN values,
handshake success and failure (including failure after success), and arbitrary
buffer admission/delivery interleavings. One offset per event abstracts partial
chunks. It excludes urgent/control events and outgoing application commands.
`Listener` explores two listeners with two sites each, all installation orders,
exact names, one fallback, one absent-name rejection, and absent negotiated ALPN,
with one connection per behavior. Each site's configured list independently
either overrides ALPN with two protocols or stays empty and inherits its
provider's protocol. Negotiated names may differ from requested names. It does
not model cache timing, duplicate-name installation, normalization, or
certificate bytes.
`Starttls` explores five byte positions with the switch boundary after byte two,
and all input chunk boundaries. `EncryptedDns` uses three queries and two distinguishable bytes per answer;
HTTP parsing, framing, and post-establishment transport failure are outside its
model. The latter is covered at the composition boundary by `Secure`.

## Code defect and regression

`Secure` previously checked establishment only when constructing the application.
After construction, `Chain` could retain a refused plaintext chunk, observe TLS
failure, and deliver that chunk when the application became ready. The new
regression failed on the original code: 35 bytes reached the application after
failure instead of zero.

`Secure::advance` now drives the lower layer and stages its pending output before
checking authoritative negotiation. Only `Established` permits `Chain` to run.
The private `Driven` adapter prevents another TLS advance or output extraction
between that check and delivery. It retains at most one normal and one urgent
event in addition to Chain's slots, preserving the original allocation charges.
TLS still advances and exposes its outgoing alerts after failure. This stops
plaintext input delivery; it does not claim to freeze upper timers or work.

`failure_stops_plaintext_waiting_for_the_application` covers failure from a work
completion, from `advance`, and from urgent output extraction. Existing tests
cover early buffered bytes, application refusal, factory count and negotiated
metadata, failed construction, and timer/error propagation. The model's FIFO
queue abstracts both lower buffering and the new staging slot. Urgent-event
fairness is outside the liveness proof.

## Kani

[kani/Buffers.rs](kani/Buffers.rs) calls the real `Chunk::advance` and
`Chunk::split_to`, over four arbitrary bytes, every split, and two arbitrary
partial admissions, including zero and full consumption. It proves bounded
cursor arithmetic and preservation of byte identities; it assumes the caller
selected the correct STARTTLS boundary. It does not execute TLS cryptography.

| Harness configuration | Result |
| --- | --- |
| `tls_partial_admissions_preserve_the_suffix` | Pass, 740 checks |
| `starttls_split_excludes_the_plaintext_prefix` | Pass, 768 checks |
| `without_consuming_tls_input` | Expected failure, exactly the assertion “only unread bytes remain” |
| `without_excluding_the_plaintext_prefix` | Expected failure, exactly “the secure suffix excludes plaintext” |

The original [TLS accounting harnesses](../tls/kani/LayerProof.rs) also passed on
the final code, using their existing commands without stubbing: completion at
its fence (17,132 checks), acknowledgment after ciphertext completion (16,960),
and reset clearing owed work (18,344).

The negative harnesses use Kani method stubbing to replace the real cursor
operation with a broken one. Inputs and assertions are identical to the positive
harnesses. An intentional negative is not a passing proof. Select harnesses
explicitly: unfiltered Kani runs include these intentional negatives.

## Rerun

From the repository root, run any configuration with the corresponding module:

```sh
~/.cache/adorably-fv/jdk/bin/java -Xmx6g \
  -cp ~/.cache/adorably-fv/tla2tools.jar tlc2.TLC -workers 2 \
  -metadir /home/souvik/Projects/amlalabs/.fictionet-comp-work/vtls-states \
  -config verification/tls-contract/Secure_base.cfg \
  verification/tls-contract/Secure.tla
```

Replace both names for `Listener`, `Starttls`, or `EncryptedDns`. Baseline and
live configurations must exit zero. Each invariant negative must exit 12 and
report the specific invariant above; the drain and construct negatives exit 13
and report a temporal-property violation. Give each configuration its own state
directory to avoid timestamp collisions. Keep state directories outside the
repository and outside `/tmp`.

Use this environment and memory cap for every cargo command:

```sh
export CARGO_TARGET_DIR=/home/souvik/Projects/amlalabs/.fictionet-comp-work/target-vtls
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_BUILD_JOBS=4
systemd-run --user --scope -p MemoryMax=12G -p MemorySwapMax=0 \
  cargo kani -p fictionet -Z stubbing \
  --harness tls_partial_admissions_preserve_the_suffix
```

Repeat with each harness name. Positives must exit zero, negatives must exit one
with the specified assertion failure only. `--harness contract_buffers` runs all
four and therefore exits one. Delete the target directory after verification.

## Rust validation

On the final code, the following passed with the environment and systemd scope
above:

| Command after the systemd prefix | Result |
| --- | --- |
| `cargo test -p fictionet --lib stdlib::services::tls` | 7 passed |
| `cargo test -p fictionet --lib stdlib::world::net::dns::encrypted` | 10 passed |
| `cargo test -p fictionet --test it tls` | 108 passed, including STARTTLS, replacement factories, real TLS and HTTP/2 |
| `cargo test -p fictionet --test it encrypted` | 9 passed |
| `cargo clippy -p fictionet --lib -- -D warnings` | Pass |
| `env RUSTDOCFLAGS='-D warnings' cargo doc -p fictionet --no-deps` | Pass |
| `cargo bench -p fictionet --profile dev --bench network tcp_round_trips` | Pass, three samples; a runner smoke benchmark, not a TLS performance comparison |

Formatting and whitespace checks also passed:

```sh
rustfmt --edition 2024 --config skip_children=true --check \
  src/stdlib/services/tls/secure.rs src/stdlib/services/tls.rs \
  verification/tls-contract/kani/Buffers.rs
git diff --check
```
