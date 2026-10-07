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

`cargo +nightly fuzz list` names them. A target named for a stdlib module
feeds that module, and the Fuzz column of the module catalog in
[`src/stdlib/mod.rs`](../src/stdlib/mod.rs) marks every module that has
one. The rest feed the layers under the stdlib: the relay protocol,
packets and IP reassembly, the TCP/IP stack, `serve` and `web`, the
observe decoders and the proxy doors. Each target's source in
`fuzz_targets/` shows what it builds from the input.

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
cargo +nightly fuzz run -O -a tcp fuzz/corpus/tcp -- -max_total_time=600
```

`-O` builds with optimizations, and `-a` keeps debug assertions and
overflow checks on, as in a debug build of a world. Runs read and add to
`fuzz/corpus/<target>`. A crash is saved in `fuzz/artifacts/<target>/`.
To run one input again, or to shrink it:

```sh
cargo +nightly fuzz run -O -a tcp fuzz/artifacts/tcp/crash-...
cargo +nightly fuzz tmin -O -a tcp fuzz/artifacts/tcp/crash-...
```

On a system whose default target is not `x86_64-unknown-linux-gnu`, add
`--target x86_64-unknown-linux-gnu`: the sanitizer does not work with
musl's static libc.

To run every target in turn, as CI does, for some seconds each:

```sh
cargo +nightly fuzz build -O -a
fuzz/run-all.sh 60 -timeout=20 -rss_limit_mb=4096
```

It goes on past a target that fails and lists the failures at the end.
Every target needs a `[[bin]]` in `fuzz/Cargo.toml` and a directory in
`fuzz/corpus/`, even an empty one; `fuzz/check-targets.sh` checks both,
and CI runs it.

The `tcp` target never sleeps by default, which keeps it fast. To reach
the timers too (delayed ACKs, TIME-WAIT), let each input sleep up to some
milliseconds in all:

```sh
FICTIONET_FUZZ_SLEEP_MS=30 cargo +nightly fuzz run -O -a tcp fuzz/corpus/tcp
```

The corpora here are seeds, cut down to the fewest inputs that reach every
edge the larger corpus reached. Cut a corpus down the same way before you
commit it: merge it into an empty directory with libFuzzer's set cover,
counting edges only, and commit the result.

```sh
mkdir /tmp/tcp
cargo +nightly fuzz run -O -a tcp /tmp/tcp fuzz/corpus/tcp -- -set_cover_merge=1 -use_counters=0
```

`stack`, `tcp`, `web`, `web_http` and `ip_reassembly` run timers and
threads, so the edges an input reaches vary from run to run, and a cut
loses some. Their corpora are kept whole.

Each bug a target found has a regression test in the SDK's own tests, so
`cargo test` keeps it fixed without a fuzzer.

## Resource limits

Memory and fairness under a flood are a test, not a fuzz target:
`tests/flood.rs` floods `web::Sites` from one sandbox with made-up names,
fragments, SYNs and held connections, checks the limits, and checks that
the process grows by less than 200 MiB and that another sandbox is still
served.

The `dnp3`, `iec104`, `enip`, `opcua`, and `rdp` targets drive `Frames`
through `codec::Stream` and `codec::contract`. OPC UA also checks `Messages`
with its assembly limit. Typed values use `Wire` writer contracts.
RDP uses `DataBlocks` for bounded GCC block sequences.
The module docs describe the APIs:
[DNP3](../src/stdlib/dnp3.rs), [IEC 104](../src/stdlib/iec104.rs),
[EtherNet/IP](../src/stdlib/enip.rs), [OPC UA](../src/stdlib/opcua.rs), and
[RDP](../src/stdlib/rdp.rs). The shared [codec docs](../src/stdlib/codec/mod.rs)
cover `pump`, `finish`, stream errors, and unread bytes.
