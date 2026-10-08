# Contributing

Thank you for your interest in Fictionet. Issues and pull requests are welcome.

## Before you start

For a large change, open an issue first, so we can agree on the design before you
write the code. Security problems go by email, not in issues: see
[SECURITY.md](SECURITY.md).

## The checks

CI runs these commands on every pull request, in two feature sets: once with the
default features, and once with `--no-default-features`, which leaves out the
`tokio` feature (`fictionet::tokio` and `web::proxy`). A pull request must pass
both. Run them before you push:

```console
$ cargo build --all-targets
$ cargo nextest run --workspace
$ cargo test --doc --workspace
$ RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
$ cargo clippy --all-targets -- -D warnings

$ cargo build --all-targets --no-default-features
$ cargo nextest run --workspace --no-default-features
$ cargo test --doc --workspace --no-default-features
$ RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --no-default-features
$ cargo clippy --all-targets --no-default-features -- -D warnings
```

The library also builds for the browser, and CI checks that too. It needs the
`wasm32-unknown-unknown` target (`rustup target add wasm32-unknown-unknown`) and
a clang with that target, which compiles ring's C code:

```console
$ cargo check --lib --no-default-features --target wasm32-unknown-unknown
$ cargo clippy --lib --no-default-features --target wasm32-unknown-unknown -- -D warnings
```

CI also checks that the crate builds with Rust 1.91, the minimum version in
`Cargo.toml`, and runs every fuzz target for a minute.

## Running the tests

The tests run under [cargo-nextest](https://nexte.st), installed with
`cargo install cargo-nextest --locked`. It runs each test in its own process
and runs all the test binaries at once. The slowest tests wait on 10-second
protocol timeouts, so a whole run takes about as long as the slowest test.
`cargo nextest run` does not run doctests, so `cargo test --doc` runs them.
`.config/nextest.toml` holds the settings: tests are never retried, a test
is flagged after 15 seconds, and the tests that run whole worlds run a few
at a time.

`cargo test` runs everything too, doctests included, one test binary after
another. It takes about a minute longer.

The test profile builds the crate with `opt-level = 1` and its dependencies
with `opt-level = 2` (see `Cargo.toml`). The randomized protocol tests run
about five times faster that way, and the dependencies are built once.

Randomized and large-input tests size their loops with
`stdlib::codec::test_support::rounds`. A default run is fast. For a deep
run, scale them up:

```console
$ FICTIONET_TEST_SCALE=100 cargo nextest run --workspace
```

A test that checks for linear time uses
`stdlib::codec::test_support::assert_linear`. It compares the time for an
input with the time for one 4 times larger, so it does not fail on a busy
machine the way a fixed time limit would.

A change to `fictionet attach` or to how a world is reached should also pass the
Docker tests (`tests/docker/*/run.sh`), and for the Helm chart, the Kubernetes test
(`tests/k8s/run.sh`). Each script builds what it needs, checks, and cleans up.

## Adding a protocol module

A protocol is one file in `src/stdlib/`, declared with `pub mod` in
`src/stdlib/mod.rs`. It is written with no I/O, on the tools in
`stdlib::codec`: its message types implement `Wire`, and its framer implements
`Decode`. It uses only public `fictionet::` items, so that a world can copy the
file and edit it. The module's own docs explain the protocol and show how to use
it, with examples that run as doctests.

A new module is registered in three places, and a test holds each to the code:

- a row in the protocol catalog in `src/stdlib/mod.rs`, which says what the
  module can do (`tests/stdlib_catalog.rs` checks every column);
- a fuzz target in `fuzz/fuzz_targets/`, named after the module, with a
  `[[bin]]` entry in `fuzz/Cargo.toml`;
- a `#[path]` entry in `tests/copy_and_own/modules.rs`, which compiles the file
  as a module of a separate crate.

The catalog row and the module docs are where a module is described. The front
pages (`README.md`, the crate root in `src/lib.rs`, and the top of
`src/stdlib/mod.rs`) tell one story about the core and do not gain a paragraph
per protocol.

## Names

A protocol module follows these rules. The `stdlib::codec` module docs give
each with examples.

- **E1.** One `pub enum Error` per module, for every `Wire` and `Decode` impl in it. An item fault that carries more than the reason is a struct named for the fault (`fix::FieldFault`).
- **E2.** `FrameError` only where a decoder yields `Result<Unit, Error>`: it is the fault that ends the stream.
- **E3.** An error the peer sends keeps the protocol's word (`modbus::Exception`, `grpc::Status`).
- **E4.** No `DecodeError`, `EncodeError`, `ParseError`, `WireError`, `<Unit>ParseError`, `<Unit>Error`, `<Module>Error`.
- **E5.** The only wrappers are the codec's (`Fail`, `PipeError`, ...). A wrapper returns its inner error from `source()`, and its `Display` says only its own context. `fictionet::ErrorChain` prints the whole chain.
- **N1.** A decoder that only frames a `Wire` value is `codec::Frames<T>`,
  with `Prefixed` implemented on `T`. Other `Decode` types are the plural of
  their item: `Messages` yields `Message`.
- **N2.** A `Wire` type is the specification's word for its unit, with no module prefix (`rtp::Packet`).
- **N3.** One decoder per direction: the items carry the side (`ClientMessages` yields `ClientMessage`).
- **N4.** One side of a protocol is `Client` or `Server`, either side is `Session`, and its progress is `Phase`. A session fed bytes uses `push`, `next` and `end`; one fed messages uses `receive`, `send` and `tick`.
- **N5.** A `Service` is named for what it serves, with `type Decoder` and `type State`.
- **N6.** `Present` is implemented on the decoder it presents.

All code, not only protocol modules, names its contexts one way:

- **C1.** The Fictionet context is `fcx`: `fcx: &Cx`, `fcx.spawn(|fcx| ..)`, `fn fcx(&self)`. The std task context is `cx`, as in tokio and futures: `cx: &mut Context<'_>`, `poll_fn(|cx| ..)`. `ctx` is not written.
- **C2.** A `Service` method takes `driver: &mut serve::Driver`, its side of the driver; deferred work takes `driver: &mut serve::PendingDriver`. Both record events with `record`, as `Cx` does.
- **C3.** A panic in world code is the world's bug. Fictionet does not catch it: it ends the run.

## Performance

`benches/perf.rs` is a performance suite. Each group builds a small world, pushes
traffic through it, and prints a table. Run all of it, or name the groups you want:

```console
$ cargo bench --bench perf
$ cargo bench --bench perf -- tcp path
$ cargo bench --bench perf -- sites --reps 5
$ cargo bench --bench perf -- --quick
```

`--list` says what each group measures:

```console
$ cargo bench --bench perf -- --list
tcp      bulk TCP between two endpoints on one pair: 1, 10 and 100 flows
path     bulk TCP through a protocol split at each end and a router: 1, 10 and 100 flows
idle     one active TCP flow beside 0 and 99 idle connections on the same endpoints
delay    bulk TCP over a delayed link (10 ms and 50 ms each way)
sched    the scheduler: packet ping-pong through a pair, and small TCP exchanges
memory   memory held by a delay and a bottleneck whose output is never read
relay    the relay protocol: socketpair sends, and an echo through listen
sites    HTTP/1.1 and HTTP/2 over TLS to a Sites site, from 1 and 10 sandboxes
observe  the cost of an observer watching the graph and ten sandbox links
graph    HTTP/2 latency with 1,000 sites while an observer watches the graph
proxy    fictionet attach --type http_proxy: DNS queries for cold and missing names
```

Each run of a case repeats three times by default (`--reps`). Rates and times are
medians, with the range of the runs in brackets. A shared machine makes any single
timing noisy, so trust the counts first: allocations, and packets sent and lost.
Those barely change from run to run. Observer rows are different: the observer keeps
a sample of packets in each 100 ms, so a faster run yields fewer rows per request.
Compare observer costs only between runs with similar request rates. To judge a change, run the same groups on
the commit before it and on the change, one after the other, and compare.

The `proxy` group runs the `fictionet` binary built with the suite, or the one that
`FICTIONET_BIN` names. The suite is not a test, and CI does not run it. A full run takes a few minutes and
uses one core per world, plus one for the observer in `observe` and `graph`.

## Docs

The crate docs are the guide, and they are written as a spec: they say what the code
does, and what is not built yet. A change in behavior comes with the matching change
in the docs. Every public item has docs (`#![warn(missing_docs)]`), and examples in
the docs compile and run as tests.

Write plain English, in short sentences.

## License

By contributing, you agree that your contributions are dual licensed under the MIT
and Apache-2.0 licenses, as described in [README.md](README.md#license).
