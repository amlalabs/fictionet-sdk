# The dissector's passive path

The dissector (`src/stdlib/dissect`) reads what the observer saw of each
TCP connection and shows it the way Wireshark does. `Dissector::apply`
(`mod.rs`) hands each connection's bytes, gaps and ends to its
`Conversation` (`conversation.rs`), which holds a prefix of each direction
until a protocol is chosen and then drives that protocol. A registered
protocol is a `Pair` (`registry.rs`) of `Observed` readers (`present.rs`),
one per direction. The readers checked here are TLS (`tls.rs`, its records
framed by `TlsRecords` in `protocols.rs`), HTTP/1 (`protocols/http1.rs`),
HTTP/2 (`http2.rs`) and DNS over TCP (`protocols/dns.rs`). TLS 1.3 records
are opened with the keys of the key log, through rustls's key schedule and
record protection, and the decrypted bytes go to a `Conversation` of their
own.

This directory checks that path for bugs: four TLA+ models of the state
across directions, gaps and ends, and Kani proofs of the readers on bounded
inputs. The models' headers name the source lines they follow, at commit
0b884a309 on `comp/v-dissect` (the code after the fixes below). Every property
has a configuration or a broken copy of its function that must fail it,
and each failure was read to check that it fails for the stated reason.

What is checked:

- A reader never panics and never stops making progress on any bytes
  within the bound: each step takes at most its input, and something
  unless it waits for more (Kani, every framing step).
- After a gap, a reader whose framing only a length marks (TLS records,
  HTTP/2 frames, DNS over TCP) stops that direction; HTTP/1 reads again
  only from a head; nothing shown joins bytes from both sides of a gap
  (`Stream.tla`, `dns.rs` and `frames.rs` proofs).
- A FIN finishes what a reader held, so a message read to the close
  completes; any other end discards it and tags the packet incomplete
  (`Stream.tla`).
- An item points into the packet shown only when all its bytes came in
  that packet; bytes held from another packet, the end of the capture,
  and decrypted bytes get a buffer of their own (`Stream.tla`,
  `place.rs`).
- A TLS record opens only under its own direction's key in use and at its
  own sequence number; KeyUpdate moves only its own direction; the
  decrypted stream is told of the bytes of every record it did not get,
  ends cleanly only after whole, opened records, and gets only what an
  endpoint takes as application data (`Tls.tla`, unit tests with real
  keys).
- HTTP/2's passive HPACK tables stay in step with the endpoints' decoders
  in both directions, through blocks the capture could not read, size
  updates and the cap on what it keeps; a gap stops that direction and
  forgets its table, and the other direction reads on with its own
  (`Hpack.tla`, `Stream.tla` "stop").
- Each HTTP/1 response is framed by the method of the request it answers,
  or by none (`Pairing.tla`).

## Running

TLC 2.19 on JDK 21; Kani 0.68.0 with CBMC 6.11.0. From
`verification/dissector/tla`, one configuration at a time, with state
directories off `/tmp`:

```sh
states=${STATES:?a directory for TLC states, not under /tmp}
systemd-run --user --scope -q -p MemoryMax=10G -p MemorySwapMax=0 \
  ~/.cache/adorably-fv/jdk/bin/java -Xmx2g -XX:+UseParallelGC \
  -cp ~/.cache/adorably-fv/tla2tools.jar tlc2.TLC -workers 2 \
  -metadir $states/Stream_stop_base -config Stream_stop_base.cfg Stream.tla
```

Every `*_base.cfg` must pass; every `*_without_<flag>.cfg` must report the
violation its first comment line names. `CHECK_DEADLOCK FALSE` is set
everywhere: a finished run has nothing left to do.

The Kani harnesses are compiled into the files whose functions they prove,
under `cfg(kani)`, and call the production code:

```sh
systemd-run --user --scope -q -p MemoryMax=10G -p MemorySwapMax=0 env CARGO_BUILD_JOBS=4 \
  cargo kani -p fictionet --lib \
  --harness records_take_exactly_what_their_header_names \
  --harness records_take_something_from_a_full_buffer \
  --harness frames_take_exactly_what_their_header_names \
  --harness padding_comes_off_exactly \
  --harness tcp_messages_take_exactly_what_their_length_names \
  --harness a_reset_stops_tcp_only \
  --harness a_resumed_search_finds_the_first_end \
  --harness whole_messages_are_read_and_the_rest_is_held \
  --harness an_extension_block_is_read_inside_its_length \
  --harness extensions_lie_inside_the_hello \
  --harness an_item_points_only_at_its_own_bytes
```

The regression tests for the bugs below, and the dissector's other tests:

```sh
cargo test -p fictionet --lib -- stdlib::dissect
```

## Stream.tla: one direction, from the observer to its reader

The sender's bytes are tokens in messages of `L` tokens. The observer
delivers them one or two at a time, from the packet shown or released from
an earlier one, reports gaps, and ends the direction with a FIN, a reset,
or, at the end of the capture, as truncated or finalized. Before a protocol
is chosen the tokens wait in the conversation's prefix; the choice comes
from this direction's bytes or the other's. Three kinds of reader frame
what they hold: `stop` (only a length marks a message: TLS records,
HTTP/2, DNS over TCP), `head` (HTTP/1, which reads again from a head after
a gap) and `close` (a message read to the end of the stream, as a decoder
a user registers may be). Packets are numbered; 0 is the end of the
capture, which shows no packet.

| Property | States |
| --- | --- |
| `ItemsAreMessages` | every message shown whole is one message of the sender's, all of it and nothing else; read to the close, it is the whole stream |
| `NoJoinAcrossGap` | nothing shown holds bytes from both sides of a gap |
| `StopsAfterGap` | a `stop` reader shows nothing from after its first gap |
| `PointsOnlyIntoItsPacket` | an item that points into a packet points into the packet shown, never the end of the capture, and all its bytes came in it |
| `FinFinishesHeld` | after a FIN nothing is held: what was held is shown, whole for `close`, cut short otherwise |
| `OthersDiscardHeld` | after any other end nothing is held, nothing of it is shown, and the packet is tagged incomplete if a message was cut |

| Config | Setting | Result |
| --- | --- | --- |
| `Stream_stop_base` | `stop`, three messages of two tokens, three packets, one gap | passes: 354,592 states generated, 274,488 distinct, depth 12 |
| `Stream_head_base` | `head`, the same | passes: 371,216 generated, 297,104 distinct, depth 12 |
| `Stream_close_base` | `close`, one message, no gap | passes: 1,180 generated, 870 distinct, depth 8 |
| `Stream_without_stoponreset` | `Dns::reset` before 9ce2440c9: DNS over TCP reads on after a gap | violates `ItemsAreMessages` (4 states) |
| `Stream_without_headonly` | HTTP/1 reads on from the byte after a gap | violates `ItemsAreMessages` (4 states) |
| `Stream_without_dropbuffer` | `Observed::reset` keeps the bytes it held | violates `NoJoinAcrossGap` (5 states) |
| `Stream_without_tellearly` | the conversation does not tell the protocol it chooses of a gap before the choice | violates `StopsAfterGap` (4 states) |
| `Stream_without_shownpacket` | `apply` before 045b537eb: the end of the capture places bytes of the last packet in it | violates `PointsOnlyIntoItsPacket` (5 states) |
| `Stream_without_clearatend` | `Pair::end` before 045b537eb: an end keeps the last run's offsets | violates `PointsOnlyIntoItsPacket` (5 states) |
| `Stream_without_finfinishes` | a FIN discards what was held | violates `FinFinishesHeld` (4 states) |
| `Stream_without_endafterchoice` | `Conversation::end` before 71f61b9e4: a FIN before the choice never reaches the protocol | violates `FinFinishesHeld` (5 states): the other direction chose, and the prefix stays held |
| `Stream_without_othersdiscard` | a reset finishes what was held, as a FIN does | violates `OthersDiscardHeld` (4 states) |

## Tls.tla: opening both directions' records

A record opens exactly when it was sealed by that direction's sender under
the key tried at the number tried (`open_with`, rustls's
`MessageDecrypter`). Each sender seals, in order: for the client, early
data under a key the key log lacks (with `Early`); a handshake record
under the handshake key; then under each application key a data record
and a KeyUpdate, `K` times, and a last data record. With `Refused`, each
sender also seals records an endpoint refuses: application data under the
handshake key, and a record of another content type under application key
0. The attacker adds copies of records sent before, of either direction.
A FIN may cut the next record short.

| Property | States |
| --- | --- |
| `OpenedInOrder` | each direction opens only its own sender's records, each once and in the order sealed: never a copy, never the other direction's |
| `NoSilentHole` | the decrypted stream never gets bytes past bytes it did not get without being told they are missing |
| `InnerEndClean` | the decrypted stream ends cleanly only after whole records, with every byte since the last mark |
| `KeysInStep` | with every key in the key log, each direction opens every record its sender sent, through every KeyUpdate of its own |
| `InnerOnlyAppData` | the decrypted stream gets only what an endpoint takes as application data |

| Config | Setting | Result |
| --- | --- | --- |
| `Tls_base` | early data, one KeyUpdate each way, one copy, refused records | passes: 5,640 generated, 1,921 distinct, depth 17 |
| `Tls_noearly_base` | no early data, two KeyUpdates each way, one copy | passes: 5,635 generated, 2,142 distinct, depth 16 |
| `Tls_without_checkseq` | a record opens at any number | violates `OpenedInOrder` (3 states): a copy opens |
| `Tls_without_keepseq` | a record that does not open moves the number on | violates `KeysInStep` (5 states) |
| `Tls_without_appatzero` | the application key is never tried during the handshake | violates `KeysInStep` (4 states) |
| `Tls_without_updateown` | a KeyUpdate moves the other direction's key | violates `KeysInStep` (6 states) |
| `Tls_without_resetseq` | the key after a KeyUpdate keeps the old number | violates `KeysInStep` (6 states) |
| `Tls_without_markunopened` | `Tls::record` before 9fe091d0b: a record not opened leaves no mark | violates `NoSilentHole` (4 states) |
| `Tls_without_wholeend` | `TlsSession::end` before 9fe091d0b: the decrypted stream always ends cleanly on a FIN | violates `InnerEndClean` (3 states) |
| `Tls_without_appdataonly` | `Tls::record` before 6fc3f7e3a: every opened record that is not a handshake message or an alert reaches the decrypted stream | violates `InnerOnlyAppData` (4 states): the client's application data under the handshake key |

The model takes rustls's AEAD as given: a record opens only under its key
and nonce. Two unit tests in `tls.rs` run the real key schedule and record
protection: `records_open_only_at_their_own_number_and_key` (copies,
records ahead of their number and the other direction's records open
nothing and leave the number; a KeyUpdate in either direction moves only
that direction) and `a_key_update_replaces_the_key`.

## Hpack.tla: the passive HPACK tables of both directions

Each direction's encoder sends header blocks: a literal with incremental
indexing and a new name, one named by index 62 or 63, or a size update.
Its endpoint decodes each (`hpack::Table::read_block`: insert, then evict
to the maximum). The capture reads a block, cannot read it (and forgets
the table), or misses bytes, which stops that direction. Entries are
their sizes, in units where the smallest HPACK entry (32 bytes) is 2;
the passive table keeps at most 7 (`hpack::MAX_TABLE`), and maximums go
up to 8, past it.

| Property | States |
| --- | --- |
| `InStep` | at every index both tables hold, a read direction's passive table has the endpoint's entry; while it is sure, it holds every entry the endpoint holds |
| `NeverFails` | a block the encoder could send and the capture read never fails |

The passive table may hold older entries its endpoint evicted, when
inserts came while its maximum was not known (after a block it could not
read). The encoder cannot name them, since the endpoint would refuse the
block, so they never show in place of a header; `InStep` allows them.

| Config | Setting | Result |
| --- | --- | --- |
| `Hpack_base` | three blocks each way | passes: 12,791,641 states generated, 301,512 distinct, depth 7 |
| `Hpack_long_base` | four blocks each way | passes: 192,387,181 generated, 3,145,857 distinct, depth 9, 4 min 13 s |
| `Hpack_without_strictsure` | sure again once one more smallest entry would fill the table exactly (`>=` in `evict`) | violates `InStep` (4 states): after a block not read, a size update to the smallest entry leaves an empty table sure while the endpoint holds one entry |
| `Hpack_without_forgetunsure` | `forget` leaves the table sure | violates `InStep` (3 states) |
| `Hpack_without_capunsure` | evicting past the cap leaves the table sure | violates `InStep` (6 states) |
| `Hpack_without_unknownnameforgets` | a new entry whose name is not known is skipped and the table kept | violates `InStep` (5 states): every later entry sits one index off |
| `Hpack_without_gapstops` | a gap resets the reader but not `Capture` (the direction reads on with its table) | violates `InStep` (3 states) |

## Pairing.tla: which request each HTTP/1 response answers

The request direction queues each request's method; the response
direction takes one per response, since a response to HEAD has no body and
a 2xx to CONNECT starts a tunnel. Either direction may miss requests or
responses, and the queue may fill.

| Property | States |
| --- | --- |
| `FramedByItsRequest` | every response read is framed by the method of the request it answers, or by none |
| `PairedWithoutLoss` | with nothing missed and the queue never full, every response is framed by its request's method |

| Config | Setting | Result |
| --- | --- | --- |
| `Pairing_base` | three requests, a queue of two, one gap | passes: 560 generated, 440 distinct, depth 7 |
| `Pairing_full_base` | four requests, a queue of one, two gaps | passes: 5,792 generated, 3,088 distinct, depth 9 |
| `Pairing_without_markrequestgap` | `Http1::reset` before 834104fac: a missed request leaves no mark | violates `FramedByItsRequest` (5 states) |
| `Pairing_without_forgetonresponsegap` | before 834104fac: missed responses leave the methods waiting | violates `FramedByItsRequest` (3 states) |
| `Pairing_without_markfull` | `Methods::push` before 834104fac: a full queue drops its oldest method | violates `FramedByItsRequest` (4 states) |
| `Pairing_without_noheadforgets` | a direction that read no head counts as one of requests | violates `FramedByItsRequest` (5 states) |
| `Pairing_without_sticky` | the pairing is known again once Lost is passed | violates `FramedByItsRequest` (3 states) |
| `Pairing_without_popeach` | a response leaves its method waiting | violates `PairedWithoutLoss` (5 states) |

## Kani

Each harness is a child module of the file whose function it proves
(`kani/records.rs` in `protocols.rs`, `frames.rs` in
`http2.rs`, `dns.rs` in `protocols/dns.rs`, `find.rs` in
`protocols/http1.rs`, `handshake.rs` in `tls.rs`, `place.rs` in
`present.rs`), with Kani's overflow and bounds checks on every operation.
"Takes something" below is the progress half of the `Decode` contract: a
step that takes nothing and is not `Need` or `End` would make the driver
loop.

| Harness | Proves | Time |
| --- | --- | --- |
| `records_take_exactly_what_their_header_names` | for any 8 bytes, any payload left to skip, at EOF or not: one `TlsRecords` step takes at most its input and something unless it waits; a skip takes exactly what is left of the payload; a record is its header and exactly the length it names, or the header alone with the length left to skip when that is longer than the buffer and not all there; it waits only while the record is not all there | 0.32 s |
| `records_take_something_from_a_full_buffer` | once the input fills the decoder's capacity, up to the 65,540 bytes a session reads ahead, a step always gives a record: the driver never finds it stuck at a full buffer | 16 s |
| `frames_take_exactly_what_their_header_names` | the same for an HTTP/2 direction (`CaptureInputs::decode`) on any 11 bytes, before or after the preface; at EOF with payload left to skip it fails rather than waiting | 118 s |
| `padding_comes_off_exactly` | `unpad` on any 4-byte DATA payload and flags: the payload itself without PADDED, else the bytes after the pad length short of exactly that many, or nothing when the pad is longer than the rest | 0.25 s |
| `tcp_messages_take_exactly_what_their_length_names` | `Dns::next` on any 6 bytes of a TCP direction, with any skip, after a gap or not: after a gap it stops and takes nothing; otherwise as for records, by the two-byte length | 0.35 s |
| `a_reset_stops_tcp_only` | after a gap a TCP direction stops; a datagram's decoder reads on | 0.05 s |
| `a_resumed_search_finds_the_first_end` | `Http1::find`, resuming where an earlier search of the same growing buffer stopped, finds the same end of a head as a search from the first byte, on any 8 bytes | 9.9 s |
| `whole_messages_are_read_and_the_rest_is_held` | `whole_messages` on any 10 bytes walks whole handshake messages to exactly the count it gives, and the rest does not start with a whole message | 2.6 s |
| `an_extension_block_is_read_inside_its_length` | `extensions_at` on any 14 bytes from any start: each extension lies inside the block its length names, in order, without overlap, as long as its header says | 80 s |
| `extensions_lie_inside_the_hello` | `extensions` on any 44-byte hello body of a client or a server: each extension lies inside the body, however the body lies about the lengths before the extensions | 48 s |
| `an_item_points_only_at_its_own_bytes` | `Place::locate` for any run and any item of up to 3 bytes: it points into the run only at exactly the item's bytes, else gives a new buffer holding exactly them; a run with no offset never points | 2.9 s |

Each reports `VERIFICATION:- SUCCESSFUL`. Each was also run once against a
broken copy of its function (every harness in one run, the full-buffer
one alone), and each failed for that break:

| Broken function | Harness | Failed check |
| --- | --- | --- |
| `TlsRecords::decode` takes a record as oversized only past the whole buffer (`> MAX_BUFFER`) | `records_take_exactly_what_their_header_names` | `length <= MAX_BUFFER - 5 && len < 5 + length` |
| the same | `records_take_something_from_a_full_buffer` | `a full buffer must give a record` |
| `CaptureInputs::decode` skips half an oversized payload | `frames_take_exactly_what_their_header_names` | `frames.skip == length` |
| `unpad` keeps the pad length byte | `padding_comes_off_exactly` | `data.is_none()`, `data.as_ptr() == payload.as_ptr() + 1` |
| `Dns::next` takes a message as oversized only past the whole buffer | `tcp_messages_take_exactly_what_their_length_names` | `length <= MAX_BUFFER - 2 && len < 2 + length` |
| `Dns::reset` leaves a TCP direction reading (the code before 9ce2440c9) | `a_reset_stops_tcp_only` | `stopped == tcp` |
| `Http1::find` resumes at the end of the last search, not three bytes before it | `a_resumed_search_finds_the_first_end` | `found == first_end(..)` |
| `whole_messages` leaves out the four header bytes when checking a message fits | `whole_messages_are_read_and_the_rest_is_held` | `whole <= len` |
| `extensions_at` steps over an extension's header but not its data | `an_extension_block_is_read_inside_its_length` | `at >= end + 4` |
| `extensions` reads the compression methods' count without a bounds check | `extensions_lie_inside_the_hello` | index out of bounds in `extensions` |
| `Place::locate` checks only where an item starts | `an_item_points_only_at_its_own_bytes` | `delta + n <= at.len` |

## The bugs, fixed

Each has a test that failed before its fix and passes after.

1. **Bytes decoded at the end of the capture pointed into a packet.** The
   end of the capture shows no packet, yet bytes held from the last packet
   were placed at their offsets in it; and a message a FIN completed, in a
   later packet than its bytes, pointed into the FIN's packet. `apply` now
   takes the packet it shows, none at the end, and an end clears the
   packet run first (045b537eb). Tests:
   `held_bytes_decoded_at_the_end_bring_their_own_buffer`,
   `a_message_the_fin_completes_brings_its_own_buffer` (`mod.rs`). Models:
   `Stream_without_shownpacket`, `Stream_without_clearatend`.
2. **DNS over TCP read on after missing bytes.** Only the two-byte length
   before each message marks where it starts; after a gap the next byte
   was read as a length and what followed shown as a message. A TCP
   direction now stops there (9ce2440c9). Test:
   `lost_bytes_end_dns_over_tcp_in_their_direction` (`app.rs`). Model:
   `Stream_without_stoponreset`; proof: `a_reset_stops_tcp_only`.
3. **HTTP/1 responses were framed by the wrong request's method.** A gap
   in the request direction dropped the requests it held from the queue,
   a gap in the response direction left their methods waiting, and a 65th
   waiting request dropped the oldest method; a response to a lost HEAD
   then read the next response as its body. A missed request now leaves
   Lost in the queue, a missed response makes the pairing unknown for
   good, and a full queue marks its newest entry Lost (834104fac). Tests:
   `responses_past_lost_requests_are_not_framed_by_the_wrong_method`,
   `a_full_method_queue_does_not_shift_later_responses`
   (`protocols/http1.rs`). Models: `Pairing_without_markrequestgap`,
   `Pairing_without_forgetonresponsegap`, `Pairing_without_markfull`.
4. **The decrypted stream was not told of records it did not get, and
   ended cleanly after a cut record.** Early data under a key the key log
   lacks comes before records that open, and the bytes after it were
   joined to those before. A FIN inside a record, or after records that
   did not open, ended the decrypted stream as finished. The stream is now
   told the bytes are missing, and ends as truncated unless its records
   ended whole and all opened (9fe091d0b). Tests:
   `a_record_not_opened_leaves_a_gap_in_the_decrypted_stream`,
   `a_fin_inside_a_record_does_not_end_the_decrypted_stream_cleanly`
   (`capture_tests.rs`). Models: `Tls_without_markunopened`,
   `Tls_without_wholeend`.
5. **A FIN before the protocol was chosen never reached it.** A direction
   that ended cleanly while the conversation was still choosing kept its
   prefix, and the protocol the other direction chose got the prefix but
   not the end: a message the FIN completed was never shown, and the
   direction stayed waiting. The conversation now remembers the end and
   passes it on after the prefix (71f61b9e4). Test:
   `a_fin_before_the_choice_finishes_the_prefix_after_it`
   (`conversation.rs`; before: no message shown). Model:
   `Stream_without_endafterchoice`.
6. **The decrypted stream got records an endpoint refuses.** Every opened
   record that was not a handshake message or an alert went to the
   protocol inside: application data under the handshake key, and other
   content types such as heartbeat. The peer never reads either, so the
   dissector could show a request the server never saw. Only application
   data under an application key goes on now; the rest is a malformed
   record (6fc3f7e3a). Test:
   `only_application_data_reaches_the_decrypted_stream` (`tls.rs`;
   before: the protocol inside read `h` from the handshake key's record).
   Model: `Tls_without_appdataonly`.

DNS framing moved from `Dns::decode` into `Dns::next` (4bd7a0b23) so the
harness reaches it without the DNS parser behind each message.

## What is left out

- What messages say: the DNS parser, HTTP/1 header parsing (the lenient
  head readers in `src/stdlib/protocols/http1.rs`), HPACK's grammar and
  Huffman coding (`src/stdlib/protocols/hpack.rs`), gRPC, and the text
  each item shows. `Stream.tla` takes a head as naming itself: HTTP/1
  reading again after a gap is only as good as a head's first line is
  told from other bytes.
- The observer itself (`network/tcp*`), which `Stream.tla` takes as
  delivering bytes in order with gaps and ends as its contract states.
- `Stream.tla` follows one direction; the other shares only the choice
  of protocol, which `OtherChooses` models. Read-ahead limits and refused
  input are left out (a refused direction stops, as after a gap).
- `Tls.tla` takes the keys as known from the start: the hellos and the
  key log lookup are not in it, nor handshake messages cut across
  records. Early data is never opened (the key log has no early secret).
- HPACK sync is checked in `Hpack.tla` only. A Kani harness over
  `PartialTable` against an endpoint `DynamicTable` (three blocks, entries
  of 32 or 33 bytes) was still in symbolic execution after 19 minutes,
  with the parser bypassed and in a two-block form too, and was dropped:
  the table's `VecDeque` and `Arc` storage are beyond what CBMC gets
  through here. The model has a cap where the code has `hpack::MAX_TABLE`
  (64 KiB). HTTP/2 SETTINGS are not read by the passive table: it follows
  the encoder's size updates, which bound the endpoint's table.
- The Kani proofs cover the framing steps, not `Capture`,
  `Http1` or `Tls` as a whole, whose state lives in strings, maps and
  shared queues; the TLA+ models take those on.
