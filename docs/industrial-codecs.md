# Industrial codecs

DNP3, IEC 104, EtherNet/IP, OPC UA, and RDP use `stdlib::codec`.
Create `Stream::new(module::Frames::new())` for transport frames.
Use `pump` to push a batch while draining it. Call `finish` at EOF.
The stream reports each error once and retains it in `failed()`.
Unread bytes remain available through `unread()` or `into_parts()`.

`Wire::parse` reads exactly one value. Inherent frame parsers read a prefix.
`Wire::write` appends bytes and leaves the destination unchanged on error.
`Wire::to_bytes` is the shared convenience method for a new output vector.
Import `Wire` to use either method. No module has a separate byte writer.

OPC UA uses `Frames` for raw chunks and `Messages` for whole messages.
`Messages` checks sequence numbers, channel and token matching, message size,
and chunk counts. It reports an unfinished assembly at EOF, including an
assembly of empty chunks. Set receive limits through `stream.decoder()`
between messages. Input is bounded by `capacity()`; `held()` counts the
unfinished message body.

For OPC UA output, call `message.chunks(&peer_limits)` and write each returned
`Chunk` with `Wire::write`. This applies peer limits before producing chunks.
Built-in binary values and services also implement `Wire`. The borrowed
`Reader` and `Binary` trait read individual fields. They can read reserved
Variant types. Exact `Wire` parsing rejects those types because senders may
not write them. Writers reject dates, picoseconds, and namespace fields that
would read back differently. NaNs have a canonical wire form and compare
equal within the same floating type.

DNP3 transport reassembly remains in `Reassembler`. RDP packet construction
remains in `Connection::to_packet` and `write_data`; these return typed TPKT
packets. `Vec<DataBlock>` implements `Wire` for a bounded GCC block sequence.

Tests and fuzz targets use `codec::contract` for partition invariance, EOF,
progress, resource limits, and transactional writes. Random input and chunk
schedules use `codec::test_support`.
