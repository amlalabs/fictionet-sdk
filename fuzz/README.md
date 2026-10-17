# Fuzzing Fictionet

The agent in the sandbox is the one adversary in Fictionet's trust model.
Every byte it sends reaches world-side code. The targets here feed the
parsers and state machines on that path. A panic, a hang or memory that
grows without end in one of them is a denial of service against the
world.

The targets use [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) and
libFuzzer, and need a nightly toolchain:

```sh
cargo install cargo-fuzz
cargo +nightly fuzz list
```

## The targets

`cargo +nightly fuzz list` names every target. Most targets exercise a
stdlib module. Others cover generated code, packet handling and the relay:

- [`codegen_ir`](fuzz_targets/codegen_ir.rs) checks generated recursive values and stream frames.
- [`packets`](fuzz_targets/packets.rs) checks IP protocol sorting, ICMP echo replies and DHCP messages.
- [`proxy_http`](fuzz_targets/proxy_http.rs) checks HTTP proxy request heads, authentication and response heads.
- [`proxy_socks5`](fuzz_targets/proxy_socks5.rs) checks SOCKS5 greetings, authentication and requests across chunk boundaries.
- [`relay`](fuzz_targets/relay.rs) checks relay message decoding and encoding.
- [`stack`](fuzz_targets/stack.rs) feeds IPv4 and IPv6 packets to TCP, UDP and ICMP endpoints.

The proxy targets call the doors' protocol side in
`fictionet::relay::proxy`, the same code the `fictionet` binary runs over
its connections. Code that the targets need from inside the SDK is in
`fictionet::fuzzing`, which exists only when `cargo fuzz` builds with
`--cfg fuzzing`.

Some paths are reached only in part:

- `tls` cannot finish a handshake, since the fuzzer cannot compute the
  client's Finished. `web_http` finishes real handshakes with a rustls
  client and then sends the fuzzer's bytes as plaintext, so encrypted
  records that are themselves malformed are not fuzzed after the
  handshake.
- The proxy targets fuzz the doors' parsers and the SOCKS5 handshake, not
  accepting clients, forwarding or the tunnel's pump.
- Under `cfg(fuzzing)`, smoltcp accepts every IPv4 and TCP checksum. A
  crash the `tcp` or `stack` target finds with a bad checksum must be
  checked again without it.

## Running a target

```sh
cargo +nightly fuzz run -O -a tcp -- -max_total_time=600
```

`-O` builds with optimizations, and `-a` keeps debug assertions and
overflow checks on, as in a debug build of a world. No corpus is committed:
a run starts from `fuzz/corpus/<target>`, empty the first time, and adds
the inputs it finds there. Git ignores that directory. A crash is saved in
`fuzz/artifacts/<target>/`.
To run one input again, or to shrink it:

```sh
cargo +nightly fuzz run -O -a tcp fuzz/artifacts/tcp/crash-...
cargo +nightly fuzz tmin -O -a tcp fuzz/artifacts/tcp/crash-...
```

On a system whose default target is not `x86_64-unknown-linux-gnu`, add
`--target x86_64-unknown-linux-gnu`: the sanitizer does not work with
musl's static libc.

To build and run every target in turn for some seconds each:

```sh
cargo xtask fuzz 60 -timeout=20 -rss_limit_mb=4096
```

Run one target by hand with `cargo xtask fuzz tcp`, adding libFuzzer arguments
after the target name. Set `FUZZ_TRIPLE=x86_64-unknown-linux-gnu` when the
default target uses musl.

`FUZZ_SHARD_INDEX` defaults to 0 and `FUZZ_SHARD_COUNT` defaults to 1:
one shard runs every target. Targets are sorted in C locale and dealt
round-robin to zero-based shards, so the shards are disjoint and together
cover every target. Both values must be decimal integers without leading
zeros; the count must be positive and the index less than the count.
Invalid values fail before target discovery. To run the first of four
shards:

```sh
FUZZ_SHARD_INDEX=0 FUZZ_SHARD_COUNT=4 cargo xtask fuzz 60 -timeout=20 -rss_limit_mb=4096
```

It goes on past a target that fails and lists the failures at the end.
It fails without running any targets if `cargo fuzz list` fails or
lists no targets.
Every target needs a `[[bin]]` in `fuzz/Cargo.toml`. Add the `[[bin]]`
entry directly when adding a target.
`cargo xtask fuzz --check` checks the sources and `[[bin]]` records against
each other.

The `tcp` target never sleeps by default, which keeps it fast. To reach
the timers too (delayed ACKs, TIME-WAIT), let each input sleep up to some
milliseconds in all:

```sh
FICTIONET_FUZZ_SLEEP_MS=30 cargo +nightly fuzz run -O -a tcp
```

Each bug a target found has a regression test in the SDK's own tests, so
`cargo test` keeps it fixed without a fuzzer.

## Resource limits

Memory and fairness under a flood are a test, not a fuzz target:
`tests/it/flood.rs` floods `web::Sites` from one sandbox with made-up names,
fragments, SYNs and held connections, checks the limits, and checks that
the process grows by less than 200 MiB and that another sandbox is still
served.

The `dnp3`, `iec104`, `enip`, `opcua`, and `rdp` targets drive `Frames`
through `codec::Stream` and `test_support::contract`. OPC UA also checks `Messages`
with its assembly limit. Typed values use `Wire` writer contracts.
RDP uses `DataBlocks` for bounded GCC block sequences.
The module docs describe the APIs:
[DNP3](../src/stdlib/protocols/dnp3.rs), [IEC 104](../src/stdlib/protocols/iec104.rs),
[EtherNet/IP](../src/stdlib/protocols/enip.rs), [OPC UA](../src/stdlib/protocols/opcua.rs), and
[RDP](../src/stdlib/protocols/rdp.rs). The shared [codec docs](../src/stdlib/codec/mod.rs)
cover `pump`, `finish`, stream errors, and unread bytes.
