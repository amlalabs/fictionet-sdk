# HPACK and gRPC message framing

HPACK (`src/stdlib/protocols/hpack.rs`, with `prefix_int.rs` and
`huffman.rs`) compresses every header block the HTTP/2 server writes and
reads, and the capture dissector rebuilds tables with its `DynamicTable`
and `Representations`. gRPC calls ride on the server as length-prefixed
messages: `protocols/grpc.rs` reads and writes the prefix, and the `Grpc`
layer (`web/httpd/http2/grpc.rs`) reads one call's DATA through it.

This directory checks both: two TLA+ models of what happens over
sequences (encoder and decoder tables across blocks and SETTINGS; a call's
bytes split anywhere, with the application behind), and Kani proofs of the
parsers and the table arithmetic the models take as given. Each model's
header and each harness file name the source they follow. Every property
has a configuration or a broken copy of the code that must fail it, and
each failure was read to check it fails for the stated reason. A Lean 4
model of HPACK as RFC 7541 states it, with unbounded sizes, proves the
rules the Kani harnesses could not reach (the decoder's size updates,
eviction after insertion, encode-then-decode round trips) and writes
vectors that a Rust test replays on the code (see "Lean" below).

## Running

TLC 2.19 on JDK 21; Kani 0.68.0 with CBMC 6.11.0. From `tla/`, one
configuration at a time, with state directories off `/tmp`:

```sh
states=${STATES:?a directory for TLC states, not under /tmp}
systemd-run --user --scope -q -p MemoryMax=10G -p MemorySwapMax=0 \
  ~/.cache/adorably-fv/jdk/bin/java -Djava.io.tmpdir=$states -XX:+UseParallelGC -Xmx2g \
  -cp ~/.cache/adorably-fv/tla2tools.jar tlc2.TLC -workers 2 \
  -metadir $states/HpackSync_base -config HpackSync_base.cfg HpackSync.tla
```

Every `*_base.cfg` must pass; every `*_without_<flag>.cfg` must report the
violation its first comment line names. `CHECK_DEADLOCK FALSE` is set
everywhere: a finished run has nothing left to do.

The Kani harnesses compile into `prefix_int.rs`, `huffman.rs`, `hpack.rs`
and `grpc.rs` under `cfg(kani)` and call the production functions. The
HPACK harnesses use stubs, so stubbing must be on. One harness at a time:

```sh
systemd-run --user --scope -q -p MemoryMax=10G -p MemorySwapMax=0 env CARGO_BUILD_JOBS=4 \
  cargo kani -p fictionet -Z stubbing --exact \
  --harness stdlib::protocols::hpack::proofs::table_size_is_exactly_its_entries
```

The tests that go with them:

```sh
cargo test -p fictionet --lib -- protocols::huffman protocols::hpack protocols::grpc
cargo test -p fictionet --test it -- a_length_over_the_limit_is_refused_while_the_application_is_behind
```

## HpackSync.tla: encoder and decoder tables over blocks and SETTINGS

One direction of a connection: an `Encoder` writing blocks, the decoding
endpoint's `Table` reading them, and the SETTINGS_HEADER_TABLE_SIZE values
the decoding endpoint announces (`Session::apply_peer`), which the encoder
applies on arrival (`peer_setting`) and acknowledges, and which the decoder
applies on the ACK (`acknowledge_settings`). The encoder may also choose a
smaller capacity (`Encoder::set_capacity`). Sizes are scaled: the table
starts at 4, `MAX_TABLE` is 5, SETTINGS carry 0, 3 or 6, one or two values
a frame, an entry costs 1 for its 32 octets of overhead plus 0 or 1 each
for its name and value, and the static table is one entry. With
`Adversary` the blocks are any one or two representations (size updates
of 0 to 6, indexes 1 to 3, a literal with incremental indexing with a new
or an indexed name, and one without indexing; no never-indexed literal),
and only the decoder's own guarantees are checked.

`EncoderInit` is the settings limit `Encoder::new` is given. The base
configs give it 4096 (`Initial`), the `Encoder` at its default, which the
tests and the HTTP/3 code build; the encoder then uses its dynamic table,
and `set_capacity` (`MaxCaps`) is open to it. The server builds its
encoder as `Encoder::new(0)` (`Http2::new`, `web/httpd/http2.rs` line
221) and never calls `set_capacity`, so its table stays at capacity 0:
its first block carries a size update of 0, every field after is a static
index or a literal without indexing, and the client's reductions never
find a table to shrink (`header_block`, lines 1169-1172).
`HpackSync_server_base` is that encoder (`EncoderInit` 0, `MaxCaps` 0),
checked against the same decoder; `without_minpending` and
`without_secondupdate` break rules the server's encoder cannot reach.

| Property | States |
| --- | --- |
| `NoError` | every block the `Encoder` writes decodes without error |
| `RoundTrip` | ... to exactly the fields encoded, never-indexed flags included |
| `InStep` | ... and leaves the decoder's table and maximum what the encoder's were after writing it |
| `WithinMax` | each table fits its maximum, and the encoder's maximum its settings |
| `Settled` | with no reduction owed, the decoder's maximum is within its acknowledged settings |
| `Reduced` | every accepted block brought the table down to the least limit acknowledged since the block before, before its first field |
| `Ordered` | every accepted block had its size updates before its fields |

| Config | Setting | Result |
| --- | --- | --- |
| `HpackSync_base` | the `Encoder` and the decoder; two SETTINGS frames, two blocks, one capacity choice | passes: 22,730,309 states generated, 7,575,842 distinct, depth 12, 3 min 32 s |
| `HpackSync_adversary_base` | any encoder | passes: 78,742,468 generated, 27,403,587 distinct, depth 11, 6 min 30 s |
| `HpackSync_server_base` | the server's encoder, `Encoder::new(0)`, no capacity choice | passes: 1,359,822 generated, 470,588 distinct, depth 11 |
| `HpackSync_without_minpending` | `resize` keeps the last capacity as the pending update, not the least | violates `NoError` (7 states): SETTINGS `[0, 3]`, then `set_capacity(1)`, and the block carries 1 where 0 is owed |
| `HpackSync_without_secondupdate` | `write_block` sends only the pending minimum | violates `InStep` (7 states): the encoder's table is at 1, the decoder's at 0 |
| `HpackSync_without_encevict` | `write_block` does not evict after inserting | violates `WithinMax` (2 states) |
| `HpackSync_without_resizeonlower` | `Encoder::set_settings_limit` does not shrink a larger table | violates `NoError` (6 states): SETTINGS 0 acknowledged, the next block carries no update |
| `HpackSync_without_immediateack` | the encoder writes blocks between applying SETTINGS and acknowledging them | violates `NoError` (10 states); see below |
| `HpackSync_adversary_without_checksettings` | `read_block` takes an update above the settings | violates `Settled` (3 states) |
| `HpackSync_adversary_without_requirereduction` | `read_block` takes a block without the owed reduction | violates `Reduced` (6 states) |
| `HpackSync_adversary_without_minonack` | `acknowledge_settings` applies only a frame's final value | violates `Reduced` (6 states): SETTINGS `[0, 3]` acknowledged, then a block that only shrinks to 1 is taken |
| `HpackSync_adversary_without_updatesfirst` | `Representations` takes an update after a field | violates `Ordered` (3 states) |

`HpackSync_without_immediateack` is a contract, not a bug in the code. RFC
7541 section 4.2 puts the size update that answers a SETTINGS reduction
after the SETTINGS acknowledgment. The server's `Http2` queues the ACK
right after applying the values (`on_frame`, `web/httpd/http2.rs` lines
897-911), on the one FIFO every outbound frame takes (`queue`, lines
357-375), so no block encoded after the values is written before the ACK,
which is what `ImmediateAck` models. (The server's encoder, at capacity
0, also never has a table to shrink; the hazard needs an encoder that
raised its capacity above an owed minimum before the ACK.)
An `Encoder` used by code that writes a block first sends the reduction
early: with SETTINGS `[0, 3]`, then `set_capacity(1)`, the block carries
updates 0 and 1 before the ACK, the decoder then owes 0 again, and the
next block has no update. `Encoder::set_settings_limit` now says to send
the acknowledgment first.

## GrpcCall.tla: one connection's calls, read as messages

Each call's client writes messages (any flag from 0 to 2, any declared
length up to one past the limit, the body as long as declared) and ends
the call at any point, mid-message included. Its DATA reaches its own
`Grpc` layer in chunks of one to three bytes; the layer reads whole
messages while the application has room (`WAITING` events), checks the
prefixes of the messages still waiting, and reports the client's end once
the messages before it are read. The application reads an event at a time
and may answer at any point. The prefix is scaled to a flag byte and a
length byte (Kani proves the 4-byte length is read exactly), `MAX_MESSAGE`
to 2 and `Http2::WINDOW` to 1. A body byte names its call, its message
and its place, so a message read across a boundary or from another call
shows.

| Property | States |
| --- | --- |
| `Exact` | each call's application reads exactly the messages its client wrote, in order, however the chunks split them, and none of another call's |
| `WithinRules` | no message with a flag other than 0 or 1, or longer than the limit, reaches the application |
| `Bounded` | a call holds at most a message and a window of unread bytes |
| `RefusedAtHeader` | a prefix that breaks the rules is refused as it arrives: no call holds one while its application is behind |
| `EndedWhole` | the application sees the end only once every byte of the call made whole messages and all of them reached it |
| `TruncationReported` | a call whose bytes stop inside a message is failed, not ended |
| `NoFalseTruncation` | a call is reported truncated only when its bytes stop inside a message |

| Config | Setting | Result |
| --- | --- | --- |
| `GrpcCall_base` | one call, up to four messages, `WAITING` 2 | passes: 10,898,272 states generated, 3,111,805 distinct, depth 18, 22 s |
| `GrpcCall_two_base` | two calls of one message each, interleaved, `WAITING` 1 | passes: 388,963 generated, 117,649 distinct, depth 15 |
| `GrpcCall_without_checklimit` | a length over the limit is not refused | violates `WithinRules` (5 states) |
| `GrpcCall_without_boundbuffer` | no bound on the unread bytes | violates `Bounded` (9 states) |
| `GrpcCall_without_checkearly` | the code before the fix below | violates `RefusedAtHeader` (6 states): two messages wait for the application and a flag of 2 sits behind them |
| `GrpcCall_without_endcheck` | an end inside a message ends the call | violates `EndedWhole` (4 states) |
| `GrpcCall_without_endwhenroom` | the end is handled while whole messages still wait for room | violates `NoFalseTruncation` (7 states): three empty messages, two queued, the third taken for a cut-off one |
| `GrpcCall_without_ownbuffer` | the calls share one buffer | violates `Exact` (4 states) |

## Kani

Kani's overflow and bounds checks are on in every harness. Where a harness
takes cases in turn rather than as one symbolic value, it says so: CBMC
did not finish, or ran out of 10 GiB, on the symbolic form.

| Harness | Proves | Time |
| --- | --- | --- |
| `read_is_the_rfc_integer` | for every prefix width from 1 to 8 and any input of up to 11 bytes, `prefix_int::read` gives what RFC 7541 section 5.1 gives, worked out in `u128`: the same value and length, `Truncated` when the input stops inside the integer, `Overflow` for a value past `u64::MAX` or an encoding past 11 bytes; the flag bits never change the value; other widths are refused | 9.9 s |
| `write_reads_back_in_the_shortest_form` | every `u64` written with any width and flags reads back as itself in at most 11 bytes, flags kept, with no zero continuation byte at the end; bad widths and flags leave the output as it was | 7.1 s |
| `the_lookup_is_exactly_the_code_table` | the lookup the Huffman decoder makes at every bit finds each of the 257 symbols from its own code, finds only real codes for every code of 1 to 30 bits, and finds no run of fewer than 30 one bits | 7.8 s |
| `decoding_accepts_only_encoded_strings_1`, `_2` | any one or two bytes the decoder accepts are exactly the codes of the octets it returns, from the table, then fewer than eight one bits | 5.9 s, 197 s |
| `decoding_keeps_to_the_limit` | for two bytes and any limit up to four, what the decoder returns is within the limit | 19 s |
| `encoding_is_the_codes_then_ones` | any two octets encode, after what the output held, to their codes from the table and the fewest one bits that fill the last byte, in `encoded_len` bytes | 139 s |
| `table_size_is_exactly_its_entries` | each insertion adds exactly name + value + 32 and puts the entry first, and an eviction to any capacity leaves the size within it, removes the fewest oldest entries that do, and says whether it removed any, for tables of zero to three entries of up to four-octet names and values; so any sequence keeps the size the exact sum | 200 s |
| `indexes_resolve_only_inside_the_tables` | with zero to three dynamic entries: indexes 1 to 61 give the static table, 0 is an error, 62 on give the dynamic entries newest first, and every index past them is absent, never wrapped | 90 s |
| `representations_read_back_exactly` | a size update, an indexed field and a literal of each indexing kind, with any size or index up to 14 (the incremental literal carries a new, empty name), read back exactly | 84 s |
| `size_updates_come_only_first` | in every block of three representations, each a size update or an indexed field (8 blocks in turn), each reads back exactly until an update follows a field, which is `SizeUpdateOrder`, and nothing is read after | 8.6 s |
| `the_prefix_is_read_exactly` | for any input of up to eight bytes and any limit: nothing is a message before the 5-byte prefix is whole, except that a flag above 1 is refused at the first byte; a big-endian length over the limit is refused from the prefix alone; a message is exactly the flag and the next `length` bytes; `message_len`, which the layer's early check calls, refuses the same prefixes with the same errors and gives `5 + length` without waiting for the body | 5.1 s |
| `messages_write_and_read_back` | any message of up to three body bytes is written as its flag, its length big-endian and its body, after what the output held, and reads back as itself; a body over `MAX_MESSAGE` is refused, for every length | 8.3 s |

The two `Representations` harnesses stub one function: `prefix_int::read`
becomes `rfc`, the model `read_is_the_rfc_integer` proves it equal to at
widths 1 to 8 (HPACK uses 4 to 7). `Representations` borrows each string
and decodes none, so no Huffman code runs in them.

Harnesses on `Table::decode_block` did not finish in ten minutes, even on
a fixed one-byte block, so the decoder's size-update rules, the eviction
after a literal with incremental indexing, and encode-then-decode round
trips have no Kani proof here. They are `HpackSync.tla` (`NoError`,
`RoundTrip`, `InStep`, `WithinMax`, `Settled`, `Reduced`, with their
controls) and the tests in `hpack.rs` (`size_updates_and_settings_reductions`,
`constructors_require_the_initial_reduction`,
`rfc_c5_c6_response_sequences_evict_entries`,
`zero_capacity_and_oversized_entry_clear_the_table`, and the RFC 7541
Appendix C examples). The Lean model below proves them for unbounded
sizes and holds `decode_block` to that model with vectors.

The Huffman code (`HUFFMAN_LENGTHS`, from which `build_huffman` derives
the canonical codes) was compared, symbol by symbol, with h2 0.4.20's
`ENCODE_CODES` and `ENCODE_CODE_LENGTHS`, which h2 generates from RFC 7541
Appendix B: all 256 codes and lengths agree, EOS is `0x3fffffff` in 30
bits, and the lengths fill the code space exactly (the Kraft sum is 1).

Inputs past two bytes made the decoder's formulas too large for CBMC.
EOS and padding after each of the 256 symbols take up to six bytes, so
they are exhaustive tests in `huffman.rs` instead:
`eos_after_every_symbol_is_refused` (EOS after each symbol, then padding,
and between the symbol and itself) and
`padding_after_every_symbol_is_at_most_seven_one_bits` (every value of the
padding to either of the next two byte boundaries).

Each harness reports `VERIFICATION:- SUCCESSFUL` at commit b49f068c4.
Each was also run against a broken copy of its function (four breaks in
different functions a run, each harness reading only its own), and each
failed for that break:

| Broken function | Harness | Failed check |
| --- | --- | --- |
| `prefix_int::read` without its `low > u64::MAX >> shift` check | `read_is_the_rfc_integer` | `read(input, prefix) == rfc(input, prefix)` |
| `prefix_int::write` loops while `rest > 128` | `write_reads_back_in_the_shortest_form` | `read(written, prefix) == Ok((value, written.len()))` |
| `huffman::symbol` takes `offset <= count` | `the_lookup_is_exactly_the_code_table` | `HUFFMAN.codes[s] == code`, and the all-ones check |
| `decode_limited` accepts eight bits of padding | `decoding_accepts_only_encoded_strings_1` | `bits <= total && total - bits <= 7` |
| `decode_limited` refuses only past `limit + 1` | `decoding_keeps_to_the_limit` | `out.len() <= limit` |
| `encode` pads with zero bits | `encoding_is_the_codes_then_ones` | `got == (value << pad) \| ((1 << pad) - 1)` |
| `DynamicTable::insert` leaves out the 32 octets | `table_size_is_exactly_its_entries` | `table.size() == before + size` |
| `DynamicTable::evict` also evicts when the size equals the capacity | `table_size_is_exactly_its_entries` | `removed == kept < count`, `table.len() == kept` |
| `DynamicTable::get` subtracts 61 for dynamic indexes | `indexes_resolve_only_inside_the_tables` | the dynamic entry's lengths, and an `unwrap` on `None` |
| `Representations` takes an update after a field | `size_updates_come_only_first` | `read.next() == Some(Err(Error::SizeUpdateOrder))` |
| `message_len` refuses a length equal to the limit | `the_prefix_is_read_exactly` | `early == Ok(Some(end))` |
| `Message::write` writes the length little-endian | `messages_write_and_read_back` | `&wire[1..5] == &(len as u32).to_be_bytes()` |

The two exhaustive tests fail the same way: with eight bits of padding
accepted, `padding_after_every_symbol_is_at_most_seven_one_bits` fails;
with the EOS check removed, `eos_after_every_symbol_is_refused` fails.

## Lean: the RFC model and the Rust replay

`lean/` is a Lean 4 project (core only, no Mathlib, toolchain
`leanprover/lean4:v4.35.0`). It is an executable model of RFC 7541 with
theorems about it, and a generator of vectors that
`tests/hpack_vectors.rs` replays on the Rust code. The model keeps the
Rust code's resource bounds as named constants, so the vectors compare
exact results, error kinds included; each bound is listed under
"Departures" below.

```sh
cargo xtask hpack-verify lean        # lake build, then the axioms of every headline theorem
cargo xtask hpack-verify diff [seed] # vectors from seed (or 1 to 8), then the Rust test on them
```

Lake is `$LAKE` or `lake`. Each command runs in its own scope in
`fictionet-work.slice`, Lean and the generator at 6 GiB, cargo at 8 GiB.
Vectors go to `hpack-verify/run-*/vectors/<seed>/` in Cargo's target
directory and are never committed (nor is `.lake/`).

### Theorems

`Hpack/Axioms.lean` prints the axioms of the 35 headline theorems; each
rests on `propext`, `Quot.sound` and `Classical.choice` at most, and none
on `sorryAx`. The three tree facts are decided by the kernel
(`decide +kernel`), which adds no axiom.

| Module | Theorem | Proves |
| --- | --- | --- |
| `Int` | `decode_encode` | Section 5.1: every value below 2^64, behind every prefix width from 1 to 8 and any flags above the prefix, reads back as itself, using exactly the bytes written, whatever follows |
| `Int` | `encode_length`, `encode_bytes` | the encoding takes at most 11 bytes, each a byte, and the first keeps the flags |
| `Int` | `decode_ignores_flags` | the bits above the prefix never change what is read |
| `Int` | `decode_complete` | a complete section 5.1 integer is accepted, with its value and length, exactly when the value is below 2^64 and it takes at most 11 bytes; otherwise it is an overflow. So the bound is exactly where Rust refuses |
| `Int` | `decode_truncated` | input that ends inside an integer is never accepted; it is `truncated` exactly when one more final byte would make an accepted integer, and an overflow when it is past the bound already |
| `Huffman` | `paths_ok`, `leaves_ok`, `ones_ok` | the tree of Appendix B's codes (taken row by row from the RFC text): each code leads to its symbol, every leaf is a symbol reached by its own code, 1 to 29 one bits stay inside the tree and 30 reach EOS |
| `Huffman` | `decode_encode_huffman` | Section 5.2: any octets, encoded, decode to themselves within any limit at least their length |
| `Huffman` | `decode_exact` | the decoder accepts exactly the codes of at most `limit` octets followed by fewer than eight one bits, and nothing else |
| `Huffman` | `padding_too_long` | padding of eight or more one bits is an error |
| `Huffman` | `padding_not_ones` | bits left inside a code that are not all ones, so not the start of EOS, are an error |
| `Huffman` | `eos_refused` | EOS in a string is an error, wherever it is and whatever follows |
| `Huffman` | `too_long` | more octets than the limit are refused as too long |
| `Table` | `insert_is_rfc` | adding an entry first and evicting after, as `DynamicTable` does, is section 4.4's insertion (evict to make room, then add; an entry larger than the capacity empties the table) |
| `Table` | `evict_fit`, `insert_exact` | section 4.1 and 4.4: after eviction or insertion the size is the exact sum of name + value + 32 over the entries, and within the capacity |
| `Table` | `insert_first`, `fit_longest` | an entry that fits goes first, and only the fewest oldest entries are evicted to make room |
| `Table` | `insert_oversized` | section 4.4: an entry larger than the capacity empties the table and is not added |
| `Table` | `lookup_some`, `lookup_insert` | section 2.3.3: index 0 and every index past both tables name nothing, every index from 1 to the end of the dynamic table names an entry; after an insertion, 62 is the new entry and each kept older entry moves up one |
| `Rules` | `parse_write` | section 6: any well-formed representations (both string codings, all five kinds), size updates first, written one after another, read back as themselves |
| `Rules` | `parse_updates_first` | section 4.2: whatever the bytes, every size update read comes before every field; an update after a field ends the block with `SizeUpdateOrder` |
| `Block` | `decodeBlock_ok_iff` | `decodeBlock`, which checks a block in Rust's order, accepts exactly the blocks its decoded view `decodeParsed` accepts, with the same fields and decoder after: the theorems below that name `decodeBlock` are proved through it |
| `Rules` | `decode_reduced` | section 4.2: with a reduction owed, a block is accepted only if it starts with a size update at or below it |
| `Rules` | `acks_then_block` | after acknowledged SETTINGS limits below the table's maximum, the next accepted block starts with a size update at or below each of them, so at or below the least |
| `Rules` | `decode_updates` | section 6.3: each size update is at or below the acknowledged settings limit; and Rust's rule: at most two, the second at least the first |
| `Rules` | `decode_state` | after any accepted block the table's size is the exact sum and within its maximum, the maximum is the old one or an update's at or below the settings limit, and no reduction is owed |
| `RoundTrip` | `inStep_new`, `inStep_settings`, `inStep_capacity` | an encoder and the decoder at the other end start in step, and stay in step through SETTINGS limits (applied by the encoder on arrival and the decoder on the acknowledgment, which goes out before the next block) and capacities the encoder chooses |
| `RoundTrip` | `block_round_trip` | sections 2.2, 4.2 and 6: from ends in step, any block the encoder writes, for any policy (exact references, name references, indexing, Huffman per string) whose Huffman strings fit `MAX_STRING`, decodes to exactly its fields with their never-indexed flags, and leaves the ends in step with nothing owed |
| `RoundTrip` | `rustPolicy_wf` | the choice `Encoder::encode_block` makes is such a policy |

The round trip's hypotheses are met by real values: `inStep_new` gives
ends in step, `rustPolicy_wf` a policy, and the generator runs that
encoder against that decoder.

Writing `decode_truncated` found a mistake in the first model, not in
Rust: ten continuation bytes that all continue are an overflow in Rust's
loop before it looks for an eleventh byte, and the model first said
`truncated`.

### How the model is tied to Rust

`Gen.lean` writes six kinds of vectors from a seed; every expected value is
computed by the model. `tests/hpack_vectors.rs` (`HPACK_VECTORS`) runs the
Rust code on each case and compares:

| Kind | Rust called | Compared with the model |
| --- | --- | --- |
| `int_decode` | `prefix_int::read` | value and length, or `Truncated` / `Overflow` |
| `int_encode` | `prefix_int::write` | the bytes (the encoding is canonical) |
| `huffman_encode` | `huffman::encode`, `encoded_len` | the bytes and their count |
| `huffman_decode` | `huffman::decode_limited` | the octets, or `InvalidCode` / `TooLong` |
| `blocks` | `Table::new`, `set_settings_limit`, `decode_block` | per block: the kept fields with never-indexed flags and `Block::more`, or the error kind (each `hpack::Error` that `decode_block` returns has one); the table's entries newest first (read through a copy of the table that decodes a block naming every dynamic index), `table_size` and `table_capacity` |
| `encoder` | `Encoder::new`, `set_settings_limit`, `set_capacity`, `set_huffman`, `encode_block`, `table_size`, and a `Table` acknowledging the same limits | the bytes of each block, `Unwritable` with nothing written, whether a capacity is refused, the table size, and the fields the decoder reads back |

Which model function stands for which Rust function:

| Lean | Rust |
| --- | --- |
| `decodeInt`, `encodeInt` | `prefix_int::read`, `prefix_int::write` |
| `Huffman.decode`, `encode` | `huffman::decode_limited`, `huffman::encode` (the code is `HUFFMAN_LENGTHS` with `build_huffman`) |
| `Dyn.evict`, `Dyn.insert`, `lookup`, `resolveName` | `DynamicTable::evict`, `insert`, `get`, `name` |
| `readInt`, `readRaw`, `readRawRep`, `parseRaw` | `ReadFields::integer`, `Reader::text`, `Representations` |
| `Raw.decoded`, `RawRep.decoded` | `Text::decoded_len`, `Text::decode_into` |
| `Decoder.new`, `Decoder.ack`, `St.precheck` then `applyRep` (together `applyRaw`), `decodeBlock` | `Table::new`, `Table::set_settings_limit`, `Table::read_block`, `Table::decode_block` |
| `retain` | `Block::keep` |
| `Encoder.new`, `setSettings`, `setCapacity`, `resize` | `Encoder::new`, `set_settings_limit`, `set_capacity`, `resize` |
| `Encoder.updates`, `chooseRep` with `rustPolicy`, `writeStr`, `writable` | `Encoder::write_block`, `put_string`, `checked` |

**The order of errors.** A block with two faults reports the first one
Rust meets. `Representations` reads each string's length and checks that
its octets are there, and leaves its Huffman code to whoever uses it;
`Table::read_block` then checks the reduction owed and a name's index
before it decodes the name, and the name before the value. So of a
truncated value, an owed reduction or a bad index and an invalid Huffman
name in one literal, the first three come first. RFC 7541 orders no
decoding error before another (each ends the connection with
`COMPRESSION_ERROR`), so the order is the code's documented contract, and
the model takes it: `parseRaw` reads as `Representations` does and
`applyRaw` checks as `read_block` does. Until November 10 the model
decoded each string as it read it, and seeds 4, 6, 7 and 8 stopped on
such a block (seed 4: `00 81 03 01 61`, a one-byte Huffman name that is
not a code, with a reduction owed: `MissingSizeUpdate` in Rust, `Huffman`
in the model). The theorems are stated over `parseBlock` and `applyAll`,
which decode as they read; `decodeBlock_ok_iff` shows the two orders
accept the same blocks with the same results.

The blocks kind runs sessions: a settings limit from 0 to past
`MAX_TABLE`, then up to 12 steps, each an acknowledged limit or a block.
Three blocks in four follow the rules (size updates that pay what is owed,
references in range when the block starts); the rest break a rule now and
then (an index just past the table, 0, or far past it, up to 2^42; an update above the
settings, above what is owed, decreasing, three of them, or after a
field; a Huffman string of random bytes) and may be cut short, have a
byte changed, or have bytes added. A session stops at its first error, as
the connection does. Strings are names and values from the static table,
random octets of up to 40, texts of 100 to 1,500, and texts of 2,000 to
5,000 octets, which make the table evict. Fixed sessions add RFC 7541
Appendix C.3 to C.6 (wire bytes from the RFC, results from the model) and
every bound at and past its edge: a Huffman string that decodes to
`MAX_STRING` + 1 octets, a raw length of `MAX_STRING` + 1, a block of
`MAX_BLOCK` and `MAX_BLOCK` + 1 bytes, an index and a size update at
2^64 - 1 and 2^64, an update to `MAX_TABLE` + 1, an entry exactly the
capacity and one octet more, and references past `MAX_DECODED` octets and
past `MAX_HEADERS` headers. The integer kind takes every first byte at
every width, and around every mask and power of two up to 2^70 the
encoding, flagged, with bytes after, cut at every length, and padded with
up to four zero groups (nonminimal, up to past 11 bytes). The Huffman kind
takes every symbol with each padding of 0 to 16 bits that fills a byte,
each padding bit in turn made zero, EOS before and after the symbol,
runs of 1 to 5 bytes of ones, and random strings under limits around
their length, with padding a byte too long, a bit flipped, and EOS
between two symbols. The encoder kind runs 400 sessions of up to 16
steps: settings limits, capacities (some above the settings), Huffman on
and off, and blocks of up to 11 fields (one in 50 with 257 fields, one in
100 with a value of `MAX_STRING` + 1 octets), values repeated so later
fields find their entries.

With the model's two-update rule broken on purpose, the blocks kind fails
on the first session that sends three updates.

`cargo xtask hpack-verify diff` over seeds 1 to 8, at commit e85df19c7:

| Kind | Cases per seed | Over 8 seeds | Disagree |
| --- | --- | --- | --- |
| `int_decode` | 27,231 | 217,848 | 0 |
| `int_encode` | 5,200 | 41,600 | 0 |
| `huffman_encode` | 514 | 4,112 | 0 |
| `huffman_decode` | 8,294 to 8,323 | 66,444 | 0 |
| `blocks` | 618 sessions | 4,944 sessions: 10,906 accepted blocks, 2,430 acknowledged limits, every error kind `decode_block` returns | 0 |
| `encoder` | 400 sessions | 3,200 sessions (seed 1 alone: 2,581 blocks, 413 settings limits, 252 capacities, 103 refused blocks) | 0 |

After the buffers round, seeds 4, 6, 7 and 8 stopped on a block's error
kind ("The order of errors" above). With the model in Rust's order, all
eight pass again (November 10, 2026, `comp/fv-fixup`): per seed 27,231
`int_decode`, 5,200 `int_encode`, 514 `huffman_encode`, 8,294 to 8,323
`huffman_decode` cases, 619 `blocks` and 400 `encoder` sessions, none
disagreeing. With the generator switched back to the old order
(`decodeParsed`) in a scratch copy, seed 4 fails again on `00 81 03 01
61`.

A seed's vectors take about two minutes to write and the Rust test under
a second to read.

### Departures from RFC 7541

None changes what a conforming peer sees; each is a documented bound,
modelled as that bound, and the vectors check Rust keeps to it exactly.

- **At most two size updates in a block, the second at least the first**
  (`Error::SizeUpdateOrder`). Section 4.2 has an encoder signal the least
  size and then the final one, so a conforming encoder sends at most two,
  nondecreasing; it does not ask a decoder to refuse others.
- **`MAX_STRING` (65,536 octets) on each string, encoded and decoded.** A
  Huffman string whose coded length is over it is refused even if it
  would decode shorter.
- **`MAX_BLOCK` (262,144 bytes) on an encoded block.**
- **`MAX_TABLE` (65,536) caps the settings limit.** A size update above it
  is `TableSize` even if a larger SETTINGS_HEADER_TABLE_SIZE was
  announced. The module says a server must announce at most `MAX_TABLE`;
  the capture dissector, which decodes other endpoints' traffic, would
  refuse a table above 65,536 that a peer allowed.
- **Integers fit 64 bits and 11 bytes** (`IntegerOverflow`); section 5.1
  leaves the limit to the implementation.
- **`MAX_HEADERS` (256) and `MAX_DECODED` (65,536 octets) on what a block
  keeps.** Fields past them still change the table and are counted in
  `Block::more` for the caller to refuse; they are not an HPACK error.

No Rust code departs from the RFC otherwise, so nothing was fixed. The
recent budget changes were read for one case the task named: a block
refused for its heap bound. `Http2::read_headers` charges request
trailers at `Table::most_block`'s bound before `decode_block` runs; if the
budget refuses, the frame is held and read again once memory frees, and
the table was never touched. A block that does not decode ends the
connection with `COMPRESSION_ERROR` (`HeaderBlocks::read_fragment`), so
`decode_block` leaving the maximum and the owed reduction changed after
an error (it clears only the entries) never meets another block. A
header block past the block limit ends the connection with
`ENHANCE_YOUR_CALM` before any decoding (`HeaderBlocks::read_fragment`),
and one without room to join its CONTINUATION fragments waits for memory
like the trailers (`HeaderBlocks::reserve`), the table untouched.

### What the Lean model leaves out

- HTTP/2 framing: `HeaderBlocks` (CONTINUATION assembly, the block
  limit, the budget) and `Session`'s SETTINGS bookkeeping
  (`apply_peer`, `acknowledge_settings`). The model's `Decoder.ack` is
  `Table::set_settings_limit`; the order of the acknowledgment and later
  blocks is `HpackSync.tla`'s, and `block_round_trip` assumes the
  acknowledgment goes out before the next block, as the server does.
- The bounds `Table::most_block`, `most_held`, `held` and
  `Encoder::block_bound`, and the wire forms `Field` and `StringLiteral`.
- The capture dissector's `PartialTable`.
- The vectors are finite: the settings limits and capacities come from
  fixed lists and small random sizes, sessions are up to 12 (blocks) or 16
  (encoder) steps, blocks up to 24 fields, strings up to 5,000 octets,
  and random byte strings up to 13 bytes. The theorems have no such
  bound.

## Resource properties

The method is in `verification/README.md`, "Resource properties". HPACK
has all three layers. Each one fails on the decoder from before
d914d14e9, which copied an entry's name and value and then evicted, and
on the encoder from before its fix, which did the same. These checks
found three bugs, now fixed (see "The bugs, fixed" below).

```sh
cargo xtask hpack-verify resources   # the Kani harnesses and the TLC configs below
cargo xtask hpack-verify diff        # the vectors, each block costed
```

`cargo xtask hpack-verify resources` passed in full on November 10, 2026
(`comp/fv-fixup`, with `most_held_at`), nothing switched off: the ten
Kani harnesses in one `cargo kani` under a 14 GiB scope, in 1.4 to 716 s
each (`encoding_into_a_table_of_four_stays_within_its_charge` the
longest), and the five configs below with their stated results. The
tables of times below are from the first runs, in a scratch copy with
four other areas' modules switched off, before those compiled again.

**What is charged.** The HTTP/2 server charges a connection's decoder
table at `Table::most_held()` when the connection opens (`Input::open`,
`web/httpd/http2.rs`). It never raises its own settings limit and never
gives the charge back. `Encoder::most_held()` is the encoder's charge,
while its capacity stays where it is.

### TLA+

`HpackSync.tla` threads each table's storage through every eviction and
insertion, in the code's order (`AddEntry`, `Resize`). One unit is an
entry's size. The entry slots are left to Kani. The decoder's reservation
is the larger of its settings limit and its maximum, raised when either
rises. The encoder's reservation is its capacity.

| Property | States |
| --- | --- |
| `DecoderPaid`, `EncoderPaid` | no moment of a step held more than the table's charge |
| `ChargedWithinLimit` | the charges stay within `MAX_TABLE` |
| `StoresTrack` | each store holds what its table does |

| Config | Result |
| --- | --- |
| `HpackSync_base` | passes, with the four above added: 23,562,398 states generated, 7,902,591 distinct, depth 12, 3 min 42 s |
| `HpackSync_adversary_base` | passes: 79,219,058 generated, 27,628,238 distinct, depth 11, 6 min 9 s |
| `HpackSync_server_base` | passes: 1,363,662 generated, 472,521 distinct, depth 11 |
| `HpackSync_adversary_without_evictfirst` | the decoder inserts, then evicts: violates `DecoderPaid` (3 states). A block of two literals `a: v` with incremental indexing at maximum 4: the second goes in before the first leaves, peak 6 against a charge of 4 |
| `HpackSync_without_encevictfirst` | the encoder inserts, then evicts: violates `EncoderPaid` (3 states). A block of `a: v` then `a:` at capacity 4: peak 5 against 4 |

Every other control still violates the invariant its first line names.

### Kani

`kani/resources.rs`, compiled into `hpack.rs`, runs the production
insertion with every allocation counted (`resources/kani/counting.rs`).
The decoder's step is `Table::index`: what `read_block` does for a literal
with incremental indexing, made a function of its own so a harness can
call it. Harnesses on `decode_block` itself did not finish (see above).
The encoder's step is `Encoder::encode_block_into` of one field.

The tables hold zero to four entries, each empty (32 octets) or with a
four-octet name and value (40 octets). Capacity and settings limit are any
value up to 200. The new entry has a one-octet name and a four-octet value
(37 octets), so it is larger than the table, or evicts all, some or none
of the entries before it. With four entries it doubles the slots. Each
length is a constant: with lengths and the entry count symbolic, CBMC ran
out of 16 GiB.

| Harness | Bound | Time |
| --- | --- | --- |
| `decoding_a_literal_name_stays_within_its_charge` | the most bytes live at once, counting the table from its first allocation, is at most `Table::most_held()` taken before the step; the step asks for at most the octets it reads + `name_copy()` + the slot term `most_held(c) - c` | 88.7 s |
| `decoding_a_dynamic_name_stays_within_its_charge` | the same, the name the newest dynamic entry's (one to four entries) | 104.3 s |
| `decoding_a_static_name_stays_within_its_charge` | the same, the name `:method` | 83.3 s |
| `encoding_into_an_empty_table_stays_within_its_charge` and `_a_table_of_one` to `_four` | the same against `Encoder::most_held()`; one harness a count, as all five in one ran out of 16 GiB | 79.6 s, 121.8 s, 140.9 s, 159.6 s, 197.6 s |
| `the_longest_static_name_is_counted` | `name_copy()`'s constant is at least every static name's length | 1.2 s |
| `the_counter_sees_every_allocation` | the counter sees `Box`, `Vec` (grown, then shrunk to a boxed slice), `VecDeque` and `Arc` at their layouts' sizes, and all of it freed | 10.7 s |

`name_copy()` is a shared name's header (two `usize` counts, padded to
their alignment) and the longest static name. The slot term covers the
one doubling of the slots a step can make. A reallocation counts as a new
block of its full size, then the old one freed: for a moment both are
live.

| Mutation, in a scratch copy | Harness | Failed check |
| --- | --- | --- |
| `Table::index` as before d914d14e9: copy, insert, then evict | `decoding_a_literal_name_stays_within_its_charge` | `the table held more than its charge` (55.3 s) |
| `Encoder::write_block` as before its fix: insert, then evict | `encoding_into_an_empty_table_stays_within_its_charge`, `encoding_into_a_table_of_one_stays_within_its_charge` | `the table held more than its charge` (109.7 s, 102.4 s) |

The two code changes that came from these harnesses, a name copied after
the eviction and `most_held` counting the slots' doubling, were found by
the decoder harnesses failing on the code after d914d14e9 ("The bugs,
fixed").

### The replay

`tests/hpack_vectors.rs` costs each step of every `blocks` and `encoder`
session with `resources/cost.rs`. Steps are blocks decoded or encoded, and
the encoder's settings and capacity changes, which free entries. The
charge is the table's `most_held()` as it is before the step, which
counts the slots it grew before a fall. The server holds a looser one:
`most_held()` when the connection opens, never given back.
The head block a block decodes into is made before the step, as the
server does, at `most_block`'s size. The linear bounds, with their
constants in the test:

- **Decoding a block of `len` bytes** asks for at most `(266/10)·len`
  bytes plus twice the slot term. Literals decode to at most 8 octets
  for every 5 bits. Each insertion takes at least 2 bytes of the block
  and copies at most a name's header (23 bytes) and the longest static
  name (27) besides.
- **Encoding fields** asks for at most 23 bytes for each of their name
  and value octets and one per field, plus twice `most_held()`.

`cargo xtask hpack-verify diff` over seeds 1 to 8 on November 10, 2026
(`comp/fv-fixup`), every step charged `most_held()` afresh; every seed
passes, 619 `blocks` and 400 `encoder` sessions each, none disagreeing:

| Seed | `blocks` steps, closest to the charge, closest to the linear bound | `encoder` steps, closest to the charge, closest to the linear bound |
| --- | --- | --- |
| 1 | 1,816; 256 of 257; 184 of 469 | 5,930; 128 of 128; 313 of 1,237 |
| 2 | 1,796; 179 of 192; 171 of 624 | 5,611; 128 of 128; 144 of 336 |
| 3 | 1,737; 128 of 128; 155 of 762 | 5,814; 128 of 128; 195 of 844 |
| 4 | 1,768; 128 of 128; 157 of 469 | 5,599; 128 of 128; 145 of 430 |
| 5 | 1,850; 128 of 129; 294 of 2,461 | 5,733; 256 of 256; 152 of 336 |
| 6 | 1,783; 256 of 256; 167 of 597 | 5,696; 256 of 256; 155 of 496 |
| 7 | 1,784; 128 of 128; 162 of 704 | 5,674; 256 of 256; 299 of 1,344 |
| 8 | 1,778; 128 of 128; 162 of 757 | 5,878; 1,024 of 1,024; 153 of 591 |

"Closest" is the step whose bytes came nearest its bound, as a share of
the bound. A step that reaches its charge exactly is a table whose slots
are all it holds: at a capacity of 0, or 1 to 31, no entry fits, and the
slots it grew before are the whole of `most_held_at`. Every encoder
session decodes its blocks too, and those steps are counted in its
column. Charged as the server holds it (the highest `most_held()` so
far), the closest were 4,152 to 4,458 of 12,288 for `blocks` and 182 or
183 of 192 for `encoder`, seeds 1 to 8, before this change.

A fixed session at the server's settings decodes an entry as large as a
string may be, after one that fits. On the decoder from before d914d14e9
that block held 65,713 bytes against a charge of 12,288 (seed 1). Without
that session, no vector had an entry large enough to pass the charge. The
encoder from before its fix held 230 bytes against 192 in seed 1's first
encoder session.

## The bugs, fixed

The resource properties found three, each a moment when a table held
more than its charge:

- **The encoder copied an entry, then evicted.** `Encoder::write_block`
  inserted a field it indexed and then evicted to its capacity. That is
  the decoder's bug d914d14e9 fixed. A field larger than the table was
  copied in full, only to be evicted at once. It now does as the decoder
  does. Test: `an_encoder_entry_larger_than_the_table_is_not_copied_for_it`
  in `tests/it/hpack_codec.rs`, which allocated the whole 60,000-octet
  value before the fix. Model: `HpackSync_without_encevictfirst`. The
  server's encoder has capacity 0, so the server never reached it.
- **The decoder copied a new entry's name before evicting.** After
  d914d14e9, `read_block` still copied a literal or static name before
  the eviction that made room. Only a name in the dynamic table has to
  be read first, because the eviction may remove its entry, and sharing
  that name allocates nothing. With one 32-octet entry at capacity 37,
  inserting a 37-octet entry held 168 bytes against a `most_held` of
  165. `Table::index` now copies any other name after the eviction.
- **`most_held` left out the slots' doubling.** The slots double through
  a reallocation, which holds the old block and the new one for a
  moment. With three 40-octet entries and an empty one at capacity 189
  to 191, inserting a 37-octet entry held 512 bytes against 509 to 511.
  `DynamicTable::most_held` now counts three times the most slots that
  can double. Room is made before every insert, so they number fewer than
  the entries that fit. The server's charge at 4096 is unchanged, 12,288
  bytes.

The last two were found by the Kani harnesses on the code after
d914d14e9. A search over the same tables (every count, both shapes, every
capacity and settings limit up to 200, a reallocation counted as moving)
gave those cases and no others. After both fixes it gave none.

Three more, fixed after them:

- **`most_held()` left out the slots a table grew before its limit
  fell.** Slots are never given back, so after a fall they stayed beside
  a bound computed for the smaller capacity. In seed 1's `blocks` session
  350, charged at `most_held()` afresh each block, the table held 256
  bytes against 129. `DynamicTable::most_held_at` now takes the larger of
  `most_held(capacity)` and the slots held with `capacity`; `Table` and
  `Encoder::most_held` use it. The server charges once at open and never
  lowers its own limit, so it was not affected. Tests:
  `a_decoder_table_lowered_stays_within_most_held` and
  `an_encoder_table_lowered_stays_within_most_held` (`hpack_codec.rs`):
  64 slots grown at 4096, then a capacity of 64, held 2,073 bytes against
  a `most_held()` of 192. The replay now charges every step `most_held()`
  afresh.
- **`held()` left out each name's allocation header.** A name lives in a
  shared allocation with two counts before its octets; `DynamicTable::held`
  counted only the octets, up to 23 bytes an entry short. It now counts
  the header and padding, which fit the 32 octets each entry is counted
  with (a const assertion), so `most_held` still bounds it. The same tests
  failed on it first: 2,073 bytes allocated against a `held()` of 2,053.
- **The capture dissector's `held()` reported RFC sizes.**
  `PartialBlocks::held` summed the table's RFC 7541 size and the length
  of a block waiting for its CONTINUATION. It now reports the table's
  `held()` and the buffer's capacity. Test:
  `a_captured_table_and_open_block_are_within_held` (`hpack_codec.rs`):
  3,335 bytes allocated against 1,757 before.

A block with two faults reported a different `hpack::Error` from the Lean
model's. That is a difference of order, not a bug on either side: see
"The order of errors" above. The model now takes Rust's order.

The earlier one:

**A gRPC prefix over the limit waited while the application was
behind.** With `WAITING` messages queued for the application, the `Grpc`
layer stopped reading the call's bytes: a later prefix declaring more than
`MAX_MESSAGE`, or a bad flag, sat in the buffer with up to a window of
body after it, and the call did not end until the application caught up,
which a stalled application never does. The task's rule is that a message
longer than the limit is refused before it is buffered. `Grpc::messages`
now checks each prefix as it arrives, past the whole messages still
waiting (`grpc::prefix_len`), and ends the call with `RESOURCE_EXHAUSTED`
or `INTERNAL` at once (commit 702d43d28). Test:
`a_length_over_the_limit_is_refused_while_the_application_is_behind` in
`tests/it/http2_server/layers.rs`, which got no answer on stream 1 before
the fix. Model: `GrpcCall_without_checkearly`.

## What the models and proofs leave out

- The resource harnesses are bounded: up to four entries of two shapes,
  one size of new entry, capacities up to 200, raw strings only (the
  Huffman decoders are stubbed with functions that fail the proof if
  reached), and only the insertion step. `HpackSync.tla` counts entries
  by their RFC sizes and leaves the slots and a name's copy to Kani. The
  replay's allocator counts a reallocation as made in place, so the
  slots' doubling shows only in Kani.
- The capture dissector's `PartialTable` has no costed steps. It decodes
  every name and value into vectors of its own for display before its
  table sees them, then inserts and evicts. So the entry is allocated
  whichever order the table goes in, and the table's order changes no
  peak. What it keeps is counted: `held()` is checked against the
  counting allocator (`a_captured_table_and_open_block_are_within_held`).

- `HpackSync.tla` has one direction, scaled sizes, a one-entry static
  table, two blocks of one or two fields, and two SETTINGS frames. Block
  limits (`MAX_BLOCK`, `MAX_HEADERS`, `MAX_DECODED`), string limits and
  Huffman coding are not in it; the Kani harnesses and the tests in
  `hpack.rs` cover them. The server's own decoder announces no table size
  change, so its reductions come only from clients.
- `GrpcCall.tla` leaves out the connection's budget (running out fails a
  call the way an oversized buffer does), compression (`check_encoding`),
  the response side, and HTTP/2 flow control, which `verification/http2-layer`
  models. Its `up` queue holds messages and the end only: the code's also
  holds the `Call` event first (`Grpc::new`, lines 129-134), so until the
  application takes it one fewer message waits than `WAITING`. The
  `Overflow` arm (a body the connection could not hold, lines 327-329)
  and the `Closed` arm (the stream gone, lines 331-336) are not in it.
- `HpackSync.tla` reads the server's SETTINGS path for the ACK's place
  only. The server's encoder is `Encoder::new(0)`: in
  `HpackSync_server_base` its table is empty throughout, so `RoundTrip`
  and `InStep` there check the first block's update to 0 and literal
  fields, and the eviction and indexing rules are checked only with
  `EncoderInit` 4096, the library's default.
- The Kani harnesses are bounded: Huffman inputs of one or two bytes,
  tables of up to three entries with short names and values, integers of
  one byte in the grammar harnesses, three representations a block.
  Longer inputs are the tests and the models.
- The dissector's `PartialTable`, which uses `DynamicTable` with its own
  knowledge of missing entries, is checked only through `DynamicTable`.
