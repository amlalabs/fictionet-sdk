# The TCP socket's stores

Kani proofs over the stores a TCP socket keeps its bytes in
(`smoltcp/src/socket/tcp/rx.rs` and `tx.rs`) instead of byte rings: the
receive store retains the chunks segments arrived in, with the assembler
saying what is contiguous, and the send store retains the chunks the
application wrote until they are acknowledged. `kani/mod.rs` is compiled
as a child of `smoltcp/src/socket/tcp.rs`, so every harness calls the
stores themselves and stubs nothing. Stores are six bytes wide.

| Harness | Claim |
| --- | --- |
| `rx_insert_keeps_retained_equal_to_the_union_of_accepted_ranges` | after two segments at any offsets and lengths in the window, overlapping or not, the store holds each byte of their union once, the first copy, and no other |
| `rx_window_is_capacity_minus_unread` | over any commits and reads, the window is the capacity less the bytes ready and unread |
| `tx_ack_releases_exactly_the_acked_bytes` | after two writes, acknowledging any number of the queued bytes leaves exactly the rest, in order, and the window grows by that number |
| `a_piece_never_spans_two_chunks` | for any offset and length, the piece a segment gets is the store's bytes there, no longer than asked, and no chunk ends inside it |

The differential test beside the stores (`smoltcp/src/socket/tcp/store_tests.rs`)
drives them and the ring they replaced with the same random segments,
reads, writes and acknowledgements, at windows of 4 KiB, 64 KiB and
256 KiB, and checks the same bytes in the same order, the same window and
the same assembler after every step, with the stores' bounds on chunks and
memory.

None of these has been run yet. To run one:

```sh
cargo kani -p smoltcp --harness rx_insert_keeps_retained_equal_to_the_union_of_accepted_ranges
```

Run Cargo under `systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=10G -p MemorySwapMax=0`.
