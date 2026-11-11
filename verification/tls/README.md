# TLS layer

The TLA+ models of the server TLS layer (`tla/Layer.tla`, for
`src/stdlib/services/tls/layer.rs` as `Driver` and `Harness` drive it) and
of write cancellation in the live connection (`tla/Write.tla`, for
`Opened::poll_write` in `src/stdlib/services/stack/open.rs`), the Kani
proofs over the layer's write accounting (`kani/LayerProof.rs`), and the
tests that the crypto provider draws only from the entropy it was given
(`entropy.rs`). What each covers, what it leaves out, and the two bugs it
found are in [VERIFICATION.md](VERIFICATION.md).

Each `.tla` has configs of the code as it is (`*_base.cfg`) and configs
that drop one rule and name the one property TLC must then violate
(`*_without_<flag>.cfg`):

| Config | Checks |
| --- | --- |
| `Layer_base.cfg` | every invariant of `Layer`, four peer inputs and three commands |
| `Layer_live_base.cfg` | every invariant and the four liveness properties, three peer inputs and two commands |
| `Layer_repeat_base.cfg` | a carrier that reports a byte it never took: completions still never pass what was produced |
| `Layer_without_quietafterclose.cfg` | rustls before fix 1: violates `NoWriteAfterEnd` |
| `Layer_without_droplatedone.cfg` | `on_done` before fix 2: violates `NoWriteAfterEnd` |
| `Layer_without_checkwritten.cfg` | no bound on `Written`, with the broken carrier: violates `Bounded` |
| `Layer_without_countproduced.cfg` | alert bytes not counted in `produced`: violates `Conservation` |
| `Layer_without_fence.cfg` | credit without the fence: violates `CreditAfterDelivery` |
| `Layer_without_takecredit.cfg` | `take_event` keeps the credit it hands up: violates `ExactlyOnce` |
| `Layer_without_checkhandshake.cfg` | writes taken while handshaking: violates `NoWriteBeforeHandshake` |
| `Layer_without_rustlsholdsearlydata.cfg` | rustls's reader yields plaintext mid-handshake: violates `NoReadBeforeHandshake` |
| `Layer_without_checkclosing.cfg` | writes taken after close_notify: violates `NoPlaintextAfterClose` |
| `Layer_without_endafterdrain.cfg` | End before the ciphertext is complete: violates `EndAfterDrainInv` |
| `Layer_without_endonce.cfg` | no `end_sent`: violates `OneEnd` |
| `Layer_without_abortclears.cfg` | `abort` keeps queued output: violates `ResetStops` |
| `Layer_without_creditonwritten_flush.cfg` | `Written` never credits: violates `FlushedMeansCredited` |
| `Layer_without_creditonwritten.cfg` | the same: violates `PendingResolves` |
| `Layer_without_clearalert.cfg` | a written alert is never dropped: violates `FailureReported` |
| `Layer_without_clearalert_close.cfg` | the same: violates `CloseCompletes` |
| `Layer_without_readafterclose.cfg` | no reading after close_notify is queued: violates `PlaintextDelivered` |
| `Write_base.cfg` | every invariant of `Write` |
| `Write_without_matchcontent.cfg` | a retry credited whatever its bytes: violates `ConfirmedIsTheCallers` |
| `Write_without_takepending.cfg` | the earlier write kept after it is settled: violates `ConfirmedOnce` |
| `Write_without_rememberwrite.cfg` | no `pending_write`: violates `NoDuplicate` |
| `Write_without_pumpfirst.cfg` | `poll_write` looks at the earlier write before it runs the stack: violates `NoHang` |

Run one with TLC (Java 11 or later and `tla2tools.jar`):

```sh
cd verification/tls/tla
java -Xmx6g -cp "$TLA2TOOLS" tlc2.TLC -workers 4 -config Layer_base.cfg Layer.tla
java -Xmx6g -cp "$TLA2TOOLS" tlc2.TLC -workers 4 -config Layer_live_base.cfg Layer.tla
java -Xmx2g -cp "$TLA2TOOLS" tlc2.TLC -workers 2 -config Write_base.cfg Write.tla
```

`CHECK_DEADLOCK FALSE` is set because a behavior ends when its inputs and
commands run out, or when the layer returns an error.

The Kani harnesses are compiled into `tls::layer` under `cfg(kani)` and
call the real `on_event`, `on_command`, `advance`, `take_command` and
`take_event`:

```sh
cargo kani -p fictionet --harness a_completion_credits_the_pending_write_once_at_its_fence
cargo kani -p fictionet --harness a_write_is_acknowledged_once_after_its_ciphertext_completes
cargo kani -p fictionet --harness a_reset_drops_what_is_owed_and_sends_only_a_reset
```

The entropy tests are compiled into `tests/it` as a child of `tls.rs`:

```sh
cargo test -p fictionet --test it tls::entropy
```

The November 9 rerun of all three TLS accounting harnesses was interrupted before any completed result; it remains incomplete after the requested proof stop.

## Resource properties

The method is in `verification/README.md`, "Resource properties". TLS
has all three layers, over the SDK's layer and the vendored rustls
together: a TLS connection's buffers are rustls's and the layer's, paid
from one budget. Each layer fails on the code from before the fixes
below. These checks found three bugs in rustls, now fixed ("The bugs,
fixed").

```sh
cargo xtask tls-verify resources   # the Kani harnesses, Join.tla's configs and the costed replays
```

### What a connection allocates, by who sets its size

Every allocation of the server's path, from the client's first byte to
its last record: the SDK's layer (`src/stdlib/services/tls/layer.rs`),
the Acceptor that reads the hello and the unbuffered connection after it
(`rustls/src/server/server_conn.rs`, `conn.rs`, `conn/unbuffered.rs`), the
deframer (`msgs/deframer/`), the record layer, the output queue
(`vecbuf.rs`), the handshake states and the session store
(`server/handy.rs`).

| Allocation | Size set by | How it is held |
| --- | --- | --- |
| The bytes of a record arriving across chunks, and the parts of a handshake message being joined, in the layer (`take_input`, `join`) | the client: a record, and a message's parts up to `JOINED`, 64 KiB | charged before it grows (`Chunk::block`, `Chunk::repay`); a new buffer has room for twice what is held, so what is held moves a few times; a message whose parts need more than 64 KiB fails the connection (6371855ae) |
| rustls's read buffer, on the buffered path: every ClientHello, read by the Acceptor (`DeframerVecBuffer`) | the client: a record, and a message's parts up to 64 KiB | charged before it grows, the new allocation in full while the old one is held; grows to at least twice its capacity (3675b51f1) |
| What parsing a handshake message allocates: its lists of cipher suites, groups, key shares, protocols, PSK identities, CA names, certificate entries | the client: up to 37.5 bytes for each byte of the message | charged before the message is taken (`parse_room`, `reserve_parse`); an `Accepted` keeps its hello's room until it is answered (db6df25cc) |
| The deframer's spans, one for each handshake message it hands out | the client: a record may hold 4,000 messages | at most three: the rest of a record is cut a message at a time (6c37525d7) |
| A record's plaintext | the client | none made: decrypted where it lies and handed up as a slice of its chunk |
| The output a client's message makes: the server's flight, a KeyUpdate's reply, an alert | the config (the flight: certificate chain, CA names, tickets) and the protocol (control records) | room charged before the message (`reserve_step`, `handshake_room` from `ServerConfig::most_connection`), and the room for the final alert from the first byte |
| The session store's slots | the config: `size` slots of 32 + 1,024 bytes | made and paid for once (`ServerSessionSlots::with_budget`); a session put is copied into its slot, one found or taken is copied out, at most 1,024 bytes |
| rustls's protocol state: the handshake state, the key schedule, the record protection each way, the transcript hash | constant for a connection | not a buffer and not charged, by design (`TlsLayer`'s docs). `budget_oracle`'s `tls_bulk_holds_no_heap_its_budget_does_not_cover` measures it once the handshake settles and holds the connection to it, within 1 KiB, through a mebibyte echoed; a KeyUpdate replaces the keys |
| A chunk's shared backing (`Chunk::HEADER`) | constant for a chunk | not charged, by design; at most two chunks each way in the layer |

Two allocations a client sets are kept from one step to a later one with
no charge. Both need a config that asks for client certificates, and each
is at most one message, 64 KiB on the wire:

- TLS 1.2 with client authentication keeps every handshake message, the
  hello included, in `HandshakeHash`'s `client_auth` buffer until the
  client's CertificateVerify.
- TLS 1.3 keeps the client's certificate chain in
  `ExpectCertificateVerify` until the next message.

rustls's QUIC path (`rustls/src/quic.rs`) has no budget: its read buffer
is `DeframerVecBuffer::default()`, and `Quic::hs_queue` holds the server's
handshake output, the config's flight, in an ordinary queue that
`write_hs` drains. The read buffer now grows by doubling like the others.
Nothing in the SDK makes a rustls QUIC connection: the SDK's QUIC
(`src/stdlib/protocols/quic.rs`) is a codec with no TLS in it. So it is
reported here, not fixed.

### TLA+: `tla/Join.tla`

`Join.tla` threads two stores through every allocation, free and charge,
in the code's order (`verification/resources/tla/Resources.tla`): the
buffer a handshake message is joined in, which is both the layer's input
and rustls's read buffer, and what parsing the message allocates. One
unit is a byte of the message. A message of any length up to
`MaxMessage` arrives in parts of up to `Piece`; one longer than `Joined`
fails at the cap. The code gives a charge back right after the free it
paid for; a TLA+ step's `Paid` compares its peak with the reservation at
its end, so a charge given back is a step of its own (`Settle`), which
must follow before anything else moves.

| Property | States |
| --- | --- |
| `BufferPaid`, `ParsePaid` | no moment of a step held more than was charged |
| `BufferWithinLimit` | the join buffer's charge stays within twice `Joined`: the old allocation and the new while both are held |
| `ParseWithinLimit` | the parse's charge stays within `ParsePer` times `Joined` |
| `StoresTrack`, `ChargesHeld` | each store holds what the model says, and once settled each charge is what its place holds |
| `Linear` | the bytes asked for the join buffer, in all, are at most four times the bytes delivered |

| Config | Result (`Joined` 16, `Piece` 4, `MaxMessage` 20, `ParsePer` 3) |
| --- | --- |
| `Join_base` | passes: 7,178 states generated, 3,818 distinct, depth 15 |
| `Join_without_doubling` | the buffer grows to exactly what it holds: violates `Linear` (depth 11) |
| `Join_without_chargeold` | a growth charges only the difference while the old allocation is held: violates `BufferPaid` (depth 3) |
| `Join_without_cap` (`MaxMessage` 36) | no cap on a message's parts: violates `BufferWithinLimit` (depth 7) |
| `Join_without_parseroom` | parsing charges nothing: violates `ParsePaid` (depth 3) |

### Kani

Each harness runs production code with every allocation counted
(`verification/resources/kani/counting.rs`), with `-Z restrict-vtable`:
without it, calls through a budget, a reader or an error's drop were
followed to every function of their shape, and the harnesses did not
finish.

`kani/deframer.rs`, compiled into rustls's `msgs/deframer/buffers.rs`,
sizes the read buffer as `DeframerVecBuffer::read` does for a message
joined from one-byte records (`resize` from `prepare_read`, every
allocation a read makes), on a budget whose limit is room for everything
or less room than the records need at three points. Harnesses on `read`
itself, with the headers parsed, did not finish in 20 minutes: CBMC
followed every error a header may give.

| Harness | Bound | Time |
| --- | --- | --- |
| `reading_a_record_stays_within_its_charge` | the most bytes live at once is at most the most the budget held at once; the bytes asked for are at most 4 × the bytes sized for + 2 × (a header and the body declared) | 7.1 s |
| `joining_three_records_stays_within_its_charge` | the same, three records | 32.4 s |
| `joining_eight_records_copies_linearly` | the same, eight records: enough that copying what is held once a record breaks the linear bound | 160.8 s |
| `the_counter_sees_every_allocation` (rustls) | the counter's own check, in this crate | 14.0 s |

| Mutation, in a scratch copy | Harness | Failed check |
| --- | --- | --- |
| `resize` grows to exactly the length (no doubling) | `joining_eight_records_copies_linearly` | `the buffer copied what it held once a record` (154.2 s) |
| `resize` charges only the difference while the old allocation is held, as before 3675b51f1 | `reading_a_record_stays_within_its_charge`, `joining_three_records_stays_within_its_charge` | `the buffer held more than its charge` (5.5 s, 23.8 s) |

`kani/join.rs`, compiled into the layer, runs the layer's `join`, which
`take_input` calls for each chunk while bytes are held, for a message of
one-byte records each in a chunk of its own: after each record, what the
step left allocated is at most what the budget is charged and one
backing; the bytes asked for are at most 4 × the bytes taken + 2 records
+ a backing for each buffer made (at most `blocks(N)`) and the first
record's. **It does not fit:** `joining_three_records_is_paid_for` did
not finish in 25 minutes under 14 GiB on November 10, 2026, with CBMC
still unwinding the budget's compare-and-swap loops, its lock's spin and
the drop of its list of runners to wake, which every release reads (an
earlier version with refusals, and one without the I/O error forgotten,
did not finish in 10). `joining_eight_records_copies_linearly` was not
run. Neither is in `tls-verify resources`. The layer's join is checked by
`Join.tla` and by the replay `a_message_joined_from_one_byte_records_is_moved_a_few_times`,
whose control is the code from before 6371855ae.

The constants: `Chunk::HEADER` is the backing's size, two counts and the
`Backing` struct (`buf/src/chunk.rs`); `blocks(N)` is one more than the
doublings from two records to `N`.

### The replays

The area's replays are run costed (`verification/resources/cost.rs`),
each session's steps within their charge and a linear bound, both stated
before the step runs. Chunks and the budget are made before the steps
that take them, as the transport and the caller make them.

`rustls/src/budget/costs.rs` (`cargo test -p fictionet-rustls --lib budget::costs`):

| Session | Charge | Linear bound | Closest, November 10, 2026 |
| --- | --- | --- | --- |
| A ClientHello sent a byte a record into an Acceptor, one step | the most the budget held, and the deframer's spans (4 × `FragmentSpan`) | 4 × input + 2 × `MAX_WIRE_SIZE` + spans | 65,695 of 106,686 bytes; 147,610 of 383,632 |
| Hellos near 64 KiB of one-byte key shares, one-byte protocol names and cipher suites, accepted, then the `Accepted` held while the client's hello is read | the same; then what the budget is charged | 41.5 × input + `parse_room(0)` + the join's fixed | 942,659 of 2,321,184; 1,778,331 of 4,854,650 |
| A hello and 4,000 empty handshake messages in one record | the same | the same | 17,088 of 21,506; 17,101 of 728,101 |
| The session store made, then 200 seeded puts, gets and takes, some too large to keep | the store's own struct (256 bytes) and its slots | 0 × input + a slot's encoding (1,024) | 4,416 of 4,544; 1,005 of 1,024 |

`tests/it/tls_costs.rs` (`cargo test -p fictionet --test it tls::costs`),
the layer with rustls under it. The charge is the room the budget had
when the session started and `HEADERS`, what the budget does not count:
at most five chunk backings of 128 bytes and four spans of 48:

| Session | Linear bound | Closest, November 10, 2026 |
| --- | --- | --- |
| Application data of seeded sizes in chunks cut at seeded places, TLS 1.3 (638 steps) and TLS 1.2 (576), a step a chunk | 0 × input + a record (`HEADER` + `BODY`) + `HEADERS`: at most one record gathered a chunk | 16,502 and 16,509 of 262,749 bytes; 16,502 and 16,509 of 19,269 |
| The security review's 60,000-byte message a byte a record, a step a record (10,921 steps) | 0 × input + twice `JOINED` + a record: a step may move what is held | 65,631 of 1,049,181; 65,631 of 150,339 |
| The same, one step for all | 4 × input + 2 records + `HEADERS` | 165,331 of 299,810 bytes asked for |
| A 60 KiB hello of one-byte protocol names on a 256 KiB budget, which waits, and on a 4 MiB one, which is taken | 66.5 × input (the read buffer 4, parsing 50, the `Hello`'s copies 12.5) + fixed | 66,391 of 262,976 and 1,567,756 of 4,195,136 live; 115,563 and 2,529,220 of 4,044,191 asked |

A step frees the chunks it is handed, which were made before it, and that
lowers the live bytes it is counted with. The joined message is therefore
also run a step a record, where each step frees one chunk of six bytes.

| Control, in a scratch copy | Session | Result |
| --- | --- | --- |
| rustls's `resize` from before 3675b51f1 | a ClientHello a byte a record | 600,410,229 bytes asked for on 60,018 read |
| no parse room, as before db6df25cc | the key shares hello | 656,515 bytes live against 98,504 |
| the deframer cutting a whole record at once, as before 6c37525d7 | a record of many messages | 180,768 bytes live against 21,506 |
| `take_input` copying what it holds on every chunk, as before 6371855ae | the joined message, one step | 717,760,840 bytes asked for on 65,526 against 299,810 |
| `reserve_parse` charging nothing | the hello on 256 KiB | 943,388 bytes live against 262,976 |

### The bugs, fixed

- **rustls's read buffer moved what it held once a record (3675b51f1).**
  `DeframerVecBuffer::resize` grew the buffer to exactly the record
  arriving, twice a record (its header, then its body). The Acceptor
  reads every ClientHello this way, so a hello sent a byte a record cost
  600,410,229 bytes asked of the allocator for 60,018 read. Each move
  also held the old and the new allocation while only the new was
  charged. Fixed as the layer's join was fixed after the security review:
  the buffer grows to at least twice its capacity, charged in full while
  the old one is held. Test:
  `budget::costs::a_hello_joined_from_one_byte_records_is_moved_a_few_times`.
- **Parsing a handshake message charged nothing (db6df25cc).** A client's
  hello of 55,096 bytes of one-byte key shares parsed into 590,984 bytes,
  31 of them charged, and the SDK's layer holds the `Accepted` while the
  world picks its config. Room for what parsing allocates is now charged
  before the message is taken; without it the message waits, whole, and
  the layer asks again when memory frees. Tests:
  `budget::costs::a_hello_is_charged_what_parsing_it_holds`,
  `tls::layer::a_hello_without_room_to_parse_waits_for_memory_and_then_goes`.
- **The deframer cut a whole record into spans at once (6c37525d7).** A
  hello followed by 4,000 empty handshake messages in one record held
  180,768 bytes against 21,346 charged. It now cuts a message at a time.
  Test: `budget::costs::a_record_of_many_messages_is_cut_a_message_at_a_time`.

### What the resource checks leave out

- The two client-authentication allocations above, kept uncharged from
  one step to the next.
- rustls's QUIC path, which has no budget.
- `parse_room`'s rate, 37.5 bytes a byte, is from the elements' sizes (a
  24-byte vector and its byte for two bytes on the wire, at most twice
  that in a vector, three times while it grows). No harness parses: the
  parser is too large for CBMC. The replays' worst hello, of one-byte
  protocol names, held 15.7 bytes a byte at its peak.
- The Kani harnesses are bounded: one, three and eight records of one
  byte, a few budget limits, and rustls's only: the layer's does not
  finish (see above). The replays have no such bound but are finite.
