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

| Target | What it feeds | Code it reaches |
|---|---|---|
| `relay` | relay messages | `relay::decode` |
| `packets` | whole packets | `ip::split_protocols`'s sorting, `icmp::echo_reply`, `dhcp::Message::parse` |
| `ip_reassembly` | IPv4 and IPv6 fragments, with timing | fragment reassembly in `ip::split_protocols` |
| `stack` | packets, with checksums made right or not | a machine: `split_protocols`, `tcp::endpoint`, `udp::endpoint`, ping replies, over IPv4 and IPv6 |
| `tcp` | TCP segments and the world's own calls, structured | `tcp::endpoint`: smoltcp's state machine and the stdlib's code around it |
| `tls` | the client's bytes | `tls::server` (the ClientHello and SNI), `ClientHello::finish`, `TlsConnection` |
| `dns` | DNS messages | hickory-proto's parser, and attach's resolver reading an answer |
| `web` | packets, DNS queries, DHCP messages, TCP segments | `web::Sites`: the filter, DHCP, DNS over UDP and TCP, routing, the machines |
| `web_http` | HTTP/1.1 and HTTP/2 bytes, plain or over TLS | `web::Sites` serving HTTP through hyper and h2 |
| `proxy_http` | a request head | the HTTP proxy door of `fictionet attach`: CONNECT and absolute URIs, `Proxy-Authorization` |
| `proxy_socks5` | a SOCKS5 client's bytes | the SOCKS5 door: greeting, login and request |

The proxy targets compile the `fictionet` binary's proxy modules from
their source files (`src/proxy.rs` here), because a binary's modules
cannot be imported. Code that the targets need from inside the SDK is in
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

The `tcp` target never sleeps by default, which keeps it fast. To reach
the timers too (delayed ACKs, TIME-WAIT), let each input sleep up to some
milliseconds in all:

```sh
FICTIONET_FUZZ_SLEEP_MS=30 cargo +nightly fuzz run -O -a tcp fuzz/corpus/tcp
```

The corpora here are small seeds. Shrink a corpus before you commit it:

```sh
cargo +nightly fuzz cmin -O -a tcp fuzz/corpus/tcp
```

Each bug a target found has a regression test in the SDK's own tests, so
`cargo test` keeps it fixed without a fuzzer.

## Resource limits

Memory and fairness under a flood are a test, not a fuzz target:
`tests/flood.rs` floods `web::Sites` from one sandbox with made-up names,
fragments, SYNs and held connections, checks the limits, and checks that
the process grows by less than 200 MiB and that another sandbox is still
served.
