# TLS against its RFCs

Models of TLS 1.3 (RFC 8446) and TLS 1.2 (RFC 5246 with RFC 7627) as the
vendored rustls (`rustls/`, 0.23.46 with the budget changes) implements them
for the SDK's server layer (`src/stdlib/services/tls/layer.rs`). Each
spec-level model states the RFC; each code-level model follows rustls's
functions, names its source lines in its header (checked at `b3f4510d7` and
the commits after it on `comp/fv-tls`), and is checked by TLC to refine the
spec. Real runs of rustls are tied to the models three ways: handshake logs
and record logs replayed by TLC, and Lean vectors replayed by Rust tests.

The SDK's own layer around rustls (credit, completions, close) is the
`tls` area; what a replacement TLS must keep is `tls-contract`.

## What is proved

| Property | RFC | Where |
| --- | --- | --- |
| The server takes handshake messages only in the order of the RFC figures, with HelloRetryRequest at most once, early data only with a PSK on the first hello, client authentication (CertificateVerify only after a non-empty Certificate), and no application data before the client Finished is verified | 8446 §2, §4.1.4, §4.2.10, §4.3.2, §4.4; 5246 §7.3 | `Handshake.tla`, refined by `ServerHs.tla` |
| Rejected early data: records are skipped by trial decryption only within the allowance, and after a HelloRetryRequest only by the skip rule | 8446 §4.2.10 | `ServerHs` (`TrialWithinBudget`, `NoEarlyAfterHrr`) |
| A handshake message before a key change ends its record | 8446 §5.1 | `ServerHs` (`KeyChangeAligned`) |
| A TLS 1.2 resumption whose session used EMS is refused for a hello without EMS | 7627 §5.3 | `ServerHs` (`EmsResume`) |
| A refused server flight changes no protocol state, and its retry does what the first call would have | (budget) | `ServerHs` (`UnpaidChangesNothing`, `RetryAsFirst`) |
| No record's plaintext reaches the application unless it was authenticated under the current read key at the next sequence number, and accepted; each byte once, in order | 8446 §5.2, §5.3 | `Record` (`AuthBeforeDeliver`), refined by `RecordCode` |
| No (key, sequence number) pair is used twice | 8446 §5.3 | `Record` (`NonceUnique`), `RecordCode` (`EncUnique`); Lean `Nonce.nonce_unique` for every sequence of budget outcomes and key updates |
| Records leave with no sequence number skipped; a record encrypted and lost fails the connection and nothing goes after it | 8446 §5.3 | `Record` (`NoGap`), `RecordCode` (`HoleMeansFailed`, `NothingAfterGap`); Lean `wire_chain`, `wire_suffix`, `live_loses_nothing` |
| Key update order: every record after a KeyUpdate is under the new key, every one before under the old; the answer to update_requested goes before the next application data; the reader switches right after it | 8446 §4.6.3 | `Record` (`KUOrder`, `KUReplyFirst`); Lean `wire_chain` |
| A refused growth (read buffer, plaintext place, output, control room) changes no sequence number, key, queued output or buffered input, and the call can be repeated | (budget) | `RecordCode` (`RefusalChangesNothing`, `RefusalsRetry`); Lean `refused_changes_nothing` |
| One record per read: at most one record is buffered, so a record skipped by trial decryption is charged once | (budget) | `RecordCode` (`AtMostOneRecord`, `SkipDiscardsSkipped`, `TrialChargedOnce`) |
| Nothing is sent after close_notify or a fatal alert; data after a received close_notify is ignored | 8446 §6.1, §6.2 | `Record` (`NoSendAfterClose`, `IgnoreAfterCloseProp`, `FatalEnds`) |
| Record sizes and types: no unprotected record over 2^14, no protected TLS 1.3 record over 2^14 + 256, no TLS 1.2 record over 2^14 + 2048, no empty fragment but application data; record_overflow and unexpected_message where the RFCs name them; no legal record refused | 8446 §5, §5.1, §5.2; 5246 §6, §6.2, §7.2.2 | `Record` (`AccLegal`, `RightAlert`, `NoFalseReject`); Lean `Header.lean` |

## Files and configs

`tla/Handshake.tla` is RFC 8446 and RFC 5246 with RFC 7627 as the server
sees them: records received with the epoch each is protected under,
messages queued, and the server's read and write epochs. It covers
HelloRetryRequest, PSK, 0-RTT accepted and rejected (trial decryption and
the HRR skip), client authentication, 0.5-RTT, NewSessionTicket,
KeyUpdate, CCS compatibility records, alerts, the TLS 1.2 full and
abbreviated handshakes, EMS on resumption, and refused renegotiation.
Crypto is abstract: a Finished or CertificateVerify is valid or not.

`tla/ServerHs.tla` is the vendored rustls server (`server/hs.rs`,
`server/tls13.rs`, `server/tls12.rs`, `server/server_conn.rs`, trial
decryption in `record_layer.rs` and `conn.rs`, the budget's refused flight
and the SDK's retry in `layer.rs` `connect`) and refines `Handshake`
under `Map` (`PROPERTY RefinesSpec`).

`tla/Record.tla` is the record layer of RFC 8446 §5, §6 and §4.6.3 (and
RFC 5246 §6.2), both ways over one connection, with an attacker that
forges and replays records and a client that may send records the RFCs
forbid. `tla/RecordCode.tla` is the vendored rustls server as
`services/tls/layer.rs` drives it (`read_tls` one record per call,
`process_new_packets` with `reserve_step`, `reserve_plaintext` before
decryption, decryption in place and `keep_plaintext` moving the buffer to
the plaintext queue, `send_single_fragment` paying before encrypting,
`queue_paid` and the waiting KeyUpdate, `with_control_room`), with every
budget growth refusable; it refines `Record` (`PROPERTY Refines`).

`lean/` holds the Lean proofs of the record checks before decryption and
of nonce use on the sending side; see [lean/README.md](lean/README.md).

| Config | Result of the last run (states generated / distinct, depth) |
| --- | --- |
| `Handshake_base` | pass, 25,944,838 / 1,041,095, 16 |
| `ServerHs_base13` (early data, 0.5-RTT, HRR, coalesced records, Acceptor) | pass with `RefinesSpec`, 2,665,127 / 539,263, 20 |
| `ServerHs_base13auth` (optional and mandatory client auth, `ServerConnection::new`) | pass, 962,200 / 134,054, 15 |
| `ServerHs_base12` | pass, 979,695 / 198,946, 21 |
| `ServerHs_without_reservebeforekx` | `UnpaidChangesNothing` violated, depth 3 |
| `ServerHs_without_trialbound` | `TrialWithinBudget`, depth 5 |
| `ServerHs_without_hrrskipbound` | `TrialWithinBudget`, depth 5 |
| `ServerHs_without_rejectearlyonretry` | `NoEarlyAfterHrr`, depth 4 |
| `ServerHs_without_abortsecondhrr` | `OneHrr`, depth 4 |
| `ServerHs_without_checkfinished` | `NoDataBeforeFinished`, depth 5 |
| `ServerHs_without_checkemsonresume` | `EmsResume`, depth 3 |
| `ServerHs_without_replyku` | `KeyUpdateBeforeData`, depth 6 |
| `ServerHs_without_dropccsonlyinhandshake` | `CcsOnlyInHandshake`, depth 5 |
| `ServerHs_without_checkeoedaligned` | `KeyChangeAligned`, depth 5 (rustls before 3631403cc) |
| `Record_base` | pass, 5,117,517 / 1,941,222, 27 |
| `Record_12_base` | pass, 334,991 / 122,968, 25 |
| `Record_early_base` | pass, 225,024 / 84,326, 24 |
| `Record_accept_base` | pass, 1,847,879 / 672,465, 27 |
| `Record_misbehave_base` | pass, 139,868 / 57,497, 25 |
| `Record_without_replyfirst` | `KUReplyFirst` violated |
| `Record_without_checkseq` | `AuthBeforeDeliver` |
| `Record_without_quietafterclose` | `NoSendAfterClose` |
| `Record_misbehave_without_ignoreafterclose` | `IgnoreAfterCloseProp` |
| `Record_misbehave_without_checksize` | `AccLegal` |
| `RecordCode_base` | pass with `Refines`, 2,094,281 / 544,464, 36 |
| `RecordCode_12_base` | pass, 707,916 / 188,324, 36 |
| `RecordCode_early_base` | pass, 162,048 / 45,830, 28 |
| `RecordCode_refresh_base` | pass, 121,791 / 33,532, 42 |
| `RecordCode_size_base` | pass, 2,008,235 / 544,682, 30 |
| `RecordCode_size12_base` | pass, 2,630,398 / 732,831, 33 |
| `RecordCode_inexact_base` (encrypters whose allocation passes the length they report; no refinement, see departures) | pass, 3,101,415 / 833,074, 36 |
| `RecordCode_inexact_without_markunpaidafterencrypt` | `NoGap` (rustls before 1f181ea41) |
| `RecordCode_inexact_without_dropafterlostkeyupdate` | `KUOrder` (rustls before 1f181ea41) |
| `RecordCode_without_reservebeforedecrypt` | `RefusalChangesNothing` (read_seq moves across a refusal) |
| `RecordCode_without_reservestep` | `RefusalsRetry` |
| `RecordCode_early_without_onerecordperread` | `TrialChargedOnce` (review finding 3, reachable only with several records buffered) |
| `RecordCode_early_frag_without_failtrialwhenjoining` | `SkipDiscardsSkipped` |
| `RecordCode_size_without_plaintextlimit` | `AccLegal` (rustls before dec84f1c2) |
| `RecordCode_size_without_ccssizecheck` | `RightAlert` (rustls before 4ae1c83e6) |
| `RecordCode_size_without_ciphertextlimit13` | `RightAlert` (rustls before dec84f1c2) |
| `RecordCode_size12_without_headerboundinclusive` | `NoFalseReject` (rustls before dec84f1c2) |
| `RecordCode_size12_without_headeroverflowalert` | `RightAlert` (rustls before dec84f1c2) |
| `RecordCode_early_frag` | documented departure: `RightAlert` violated, see below |

Each control's counterexample was read and shows the departure its flag
names. Every base was checked for reachability by making each target state
an invariant in a throwaway module and confirming TLC violates it: for
the handshake, 22 states (full 1.3, early data used up then Finished,
trial skip, HRR skip, HRR then ServerHello, one and two refusals then
success, the KeyUpdate reply queued and sent, 0.5-RTT, the client's CCS
dropped, a refusal inside the connection, client CertificateVerify, an
empty client Certificate, 1.2 full, resumed and with client auth,
renegotiation refused, the EMS abort); for the record layer, refusals at
read, process, `reserve_plaintext`, write and control room, a KeyUpdate
reply before application data, delivery and close_notify both ways, a
mandated alert, record_overflow, an accepted 2^14 + 2048 record in TLS 1.2,
a trial skip, a server-initiated key update with the client's reply, and
`output_unpaid` under over-allocating encrypters.

Bounds: the handshake configs read at most 4 records (TLS 1.3) or 6 (TLS
1.2), enough for each handshake shape and one application data or
KeyUpdate record after it; one KeyUpdate each way; an early-data
allowance of 1 and a skip allowance of 1; at most 2 refusals of a flight
in a row. The record configs bound records per direction, key updates and
refusals as their headers say; sizes are length classes around each
limit, not bytes.

## Tied to the code

| Command | Checks | Last run |
| --- | --- | --- |
| `cargo xtask tls-verify handshake-trace` | `rustls/src/server/hs_trace.rs` runs the crate's client against the vendored server in 21 scenarios (TLS 1.3 full, HRR, resumed, early data accepted, rejected and after HRR, EndOfEarlyData sharing a record, client auth with and without a certificate, 0.5-RTT, KeyUpdate both ways; TLS 1.2 full, resumed by id and by ticket, client auth, EMS mismatch, bad Finished; refused and retried flights for both versions, a refusal inside the connection). Every record is logged with the epoch it decrypted under, found by trying every derived key at its own sequence number; `HandshakeTrace.tla` checks each log is a behavior of `Handshake.tla`. The test also checks a refused-then-retried run logs what an unrefused run logs. | 21 of 21 logs are behaviors of the spec. Two logs with one epoch changed were refused. |
| `cargo xtask tls-verify record-trace` | `rustls/src/budget/record_trace.rs` drives a real budgeted server and client through 24 seeded schedules per version: reads split at random, writes of 0, 1 and 2^14 bytes, key updates both ways, close_notify, garbage records of normal and oversize length, refusals at read, process, write, close and key update. It logs each record each side sends and reads, the sequence numbers after each call, and each refusal with whether state changed; `RecordTrace.tla` checks each log against `Record.tla`. | 48 of 48 logs, 3,692 entries. Four corrupted logs (a read_seq off by one, a refusal that changed state, a wrong plaintext size, two records swapped) were refused. |
| `cargo xtask tls-verify lean` | the Lean proofs build with no `sorry`; every headline theorem rests on Lean's standard axioms only | 16 theorems |
| `cargo xtask tls-verify vectors [seed]` | `record_vectors`: 1755 headers (9 types, 5 versions, 13 lengths at the limits, 3 read states) against a real server, with the alert the client then receives; `nonce_vectors`: 2000 random sequences of records, KeyUpdate requests and replies under budget outcomes against a real `CommonState` whose encrypter writes its key and sequence number into each record | seed 1: 1755 and 2000 cases agree. With the 1f181ea41 fix taken out, 968 of the 2000 nonce cases disagree. |

The first `record_vectors` run disagreed on 30 cases: the model had a TLS
1.2 change_cipher_spec record protected, while rustls reads every
change_cipher_spec unprotected (it supports no renegotiation, so the
only legal one comes before the keys change). The model was corrected.

## What the models found, and the fixes

All on `comp/fv-tls`, each with a Rust test that fails before its fix:

- **1f181ea41.** A record refused by the budget after encryption
  (`push_paid` charging an allocation larger than reported) took its
  sequence number, and `send_appdata_encrypt` returned without failing
  the connection: the caller wrote the bytes again under the next
  sequence number, a hole on the wire (security review finding 1). A
  KeyUpdate notification refused the same way set `output_unpaid` but the
  record after it still went out under the new keys without it. Both
  fail closed at the peer; the fix fails the connection at once and
  sends nothing after the hole. Unreachable with ring's encrypters,
  whose allocations match.
- **dec84f1c2.** Record sizes: an unprotected record was accepted up to
  2^14 + 2047 bytes (RFC: 2^14, record_overflow); a protected TLS 1.3
  record over 2^14 + 256 was decrypted and failed as bad_record_mac (RFC:
  record_overflow before decryption); the header check refused a TLS 1.2
  length of exactly 2^14 + 2048, which is legal, and answered longer ones
  with decode_error instead of record_overflow.
- **4ae1c83e6.** The 2^14 limit did not reach unprotected records taken in
  TLS 1.3 past `decrypt_incoming` (change_cipher_spec).
- **3932d115e, cc39562af.** An unknown record type, a heartbeat record and
  an unknown TLS 1.3 inner type were answered with decode_error; RFC 8446
  §5 and RFC 5246 §6 name unexpected_message.
- **3631403cc.** `ExpectEarlyData` took EndOfEarlyData without
  `check_aligned_handshake`, so a Finished sharing its record was taken
  under the early keys (RFC 8446 §5.1). Upstream 0.23.46 is the same. It
  needs the PSK, and the Finished MAC was still checked.

## Departures not fixed

- **Trial decryption ends at the first whole handshake message**, not at
  the first record that deprotects (`conn.rs` `process_more_input`, the
  `Ok(None) if !self.hs_deframer.is_aligned()` arm). A record that fails
  between fragments of the client's first message after rejected early
  data fails with `RejectedEarlyDataInterleavedWithHandshakeMessage` and
  no alert, where RFC 8446 §4.2.10 and §5.2 call for bad_record_mac.
  Upstream; fails closed. `RecordCode_early_frag.cfg` shows it.
- **Trial decryption skips any record that fails under the handshake
  keys**, plaintext handshake records included, within an allowance of
  16384 bytes when `max_early_data_size` is 0 (`tls13.rs:79-92`). Bounded.
- **Buffered rustls sends application data and KeyUpdates after its own
  close_notify** (`common_state.rs` `send_plain` does not check
  `has_sent_close_notify`; the unbuffered API does). RFC 8446 §6.1.
  Upstream; unreachable from the SDK, whose layer refuses commands once
  closing.
- **A refused write still queues a waiting KeyUpdate reply**:
  `buffer_plaintext` calls `perhaps_write_key_update` before it pays, so
  a write that takes nothing grows `sendable_tls` by an already-paid
  record. RFC-correct, but it contradicts "a refusal changes nothing";
  found by the record trace.
- **Alerts need budget room** (security review finding 2): with an
  encrypter that over-allocates, a fatal alert or close_notify can be
  dropped; the connection still fails. `RecordCode_inexact_base` is
  checked without refinement for this reason.
- **A third CCS during the TLS 1.3 handshake fails with no alert**
  (`allowed_middlebox_ccs = 2`); the RFC says drop. A deliberate limit.
- **legacy_record_version** must have high byte 3; RFC 8446 §5.1 says
  ignore it. Deliberate, to tell TLS from other protocols.
- **RFC 7627 §5.3 SHOULD**: a session without EMS is resumed by a hello
  without EMS (`hs.rs:61`). Deliberate legacy behaviour.
- **A refused flight leaves `negotiated_version` and `handshake_room`
  set**, both overwritten before being read on every path that
  continues, and runs the certificate resolver again on the retry.
- An unprotected outer type other than application data after the TLS
  1.3 handshake (handshake, alert) goes to decryption and fails as
  bad_record_mac; RFC 8446 does not name the alert.

## What the models leave out

- Crypto beyond epoch labels and authentic/forged; binders, ALPN, SNI,
  certificate and cipher suite failures other than CertificateVerify and
  Finished.
- The client side, QUIC, TLS 1.2 sequence-number exhaustion,
  renegotiation warnings, `want_close_before_decrypt`, the limit of 32
  empty fragments in a row, and plaintext written during the handshake.
- In `RecordCode`, the client is `Record`'s abstract one: the real client
  is checked only through the trace; accepted early data goes to a
  separate reader the SDK never uses.
- Fragment joining beyond the coalesced flag and one fragmented message;
  junk headers that allocate before rejection (review finding 4).
- The trace tests drive the buffered API only.

## To re-check after `comp/buf-tls` (rustls's unbuffered API)

The RFC models (`Handshake.tla`, `Record.tla`) and the Lean header rules
apply to both APIs. The code models and the tie need checking again:

- One record per read no longer holds: several records arrive at once.
  `AtMostOneRecord` and the skip path (`add_discard` after skipped
  records, the re-trial-decryption of skipped records when
  `reserve_plaintext` refuses: `RecordCode_early_without_onerecordperread`)
  become reachable.
- `write_plaintext` calls `perhaps_write_key_update` and then
  `write_fragments` encrypts straight into the caller's buffer, past
  `queue_paid`'s new check: a lost KeyUpdate could again let new-key
  records out without it, and it does not check `output_unpaid`.
- The unbuffered loop (`conn/unbuffered.rs` `process_tls_records_common`)
  calls neither `reserve_step` nor `release_step`, so the place
  `reserve_plaintext` charges is not given back there, and output made
  for a message is not checked with `output_paid`.
- Plaintext is copied (`append_with`) rather than moved
  (`keep_plaintext`, `take_plaintext`, `push_charged`); early data is
  read with `pop_early_data`.
- `UnbufferedServerConnection` has no Acceptor: a refused flight goes
  through `ExpectClientHello::handle` and is fatal unless a retry is
  added.
- 0.5-RTT and `may_send_application_data` when encoding;
  `eager_send_close_notify` and `refresh_traffic_keys`.
- The flag lines in the headers of `ServerHs.tla` and `RecordCode.tla`
  for `conn.rs` and `common_state.rs`, and `nonce_vectors` (which drives
  `CommonState` directly and still applies).
- The trace tests need an unbuffered driver.

## Run

```sh
cd verification/tls-rfc/tla
java -Xmx2g -cp "$TLA2TOOLS" tlc2.TLC -workers 2 -config ServerHs_base13.cfg ServerHs.tla
java -Xmx2g -cp "$TLA2TOOLS" tlc2.TLC -workers 2 -config RecordCode_base.cfg RecordCode.tla
cargo xtask tls-verify handshake-trace
cargo xtask tls-verify record-trace
cargo xtask tls-verify lean
cargo xtask tls-verify vectors 1
```

`CHECK_DEADLOCK FALSE` is set where a behavior ends when its inputs run
out or the connection fails.
