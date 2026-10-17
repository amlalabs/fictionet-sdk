# Contributing

Thank you for your interest in Fictionet. Issues and pull requests are welcome.

## Before you start

For a large change, open an issue first, so we can agree on the design before you
write the code. Security problems go by email, not in issues: see
[SECURITY.md](SECURITY.md).

## The checks

CI runs these commands on every pull request, in five feature sets:

| Configuration | Cargo feature flags |
| --- | --- |
| Default features | No flags |
| No default features | `--no-default-features` |
| All features | `--all-features` |
| Std and observation without Tokio | `--no-default-features --features std,observe` |
| Tokio without observation | `--no-default-features --features tokio` |

A pull request must pass each configuration. Run all five commands below
for each row before you push. They show the default configuration. For the
other rows, append the listed feature flags to each Cargo command, before
`-- -D warnings` for clippy:

```console
$ cargo build --locked --workspace --all-targets --test host
$ cargo nextest run --locked --workspace
$ cargo test --locked --doc --workspace
$ RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --no-deps
$ cargo clippy --locked --workspace --all-targets --test host -- -D warnings
```

CI also checks that every crate in the repository is formatted with the
default rustfmt style. Run `cargo fmt --all` before you push. The crates
outside the workspace (`fuzz`, `tests/copy_and_own` and the example worlds)
each need `cargo fmt --all --manifest-path <crate>/Cargo.toml`.

The library also builds for the browser, and CI checks that too. It needs the
`wasm32-unknown-unknown` target (`rustup target add wasm32-unknown-unknown`) and
a clang with that target, which compiles ring's C code:

```console
$ cargo check --locked --lib --no-default-features --target wasm32-unknown-unknown
$ cargo clippy --locked --lib --no-default-features --target wasm32-unknown-unknown -- -D warnings
```

CI also checks that the crate builds with Rust 1.91, the minimum version in
`Cargo.toml`, and checks every fuzz target with `cargo check` on the nightly
toolchain in `fuzz/rust-toolchain.toml`. CI does not run the fuzzers; see
[fuzz/README.md](fuzz/README.md) to run one by hand. From `fuzz/`:

```console
$ RUSTFLAGS="--cfg fuzzing" cargo check --locked --bins
```

CI also runs the fuzz helper library's regression tests on the pinned stable
toolchain. Run this command from the repository root:

```console
$ RUSTFLAGS="--cfg fuzzing" cargo test --locked --manifest-path fuzz/Cargo.toml --lib
```

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

The integration tests are two binaries. `tests/it` runs on any machine.
`tests/host` holds the tests that need user namespaces, root or a tun device,
and fails where the machine lacks them, so neither command above runs it.
`--all-targets` leaves it out too, so the build and clippy commands name it.
Run it by name:

```console
$ cargo nextest run --locked --test host
```

The test profile builds the crate with `opt-level = 1` and its dependencies
with `opt-level = 2` (see `Cargo.toml`). The randomized protocol tests run
about five times faster that way, and the dependencies are built once.

Randomized and large-input tests size their loops with
`stdlib::test_support::rounds`. A default run is fast. For a deep
run, scale them up:

```console
$ FICTIONET_TEST_SCALE=100 cargo nextest run --locked --workspace
```

A test that checks for linear time uses
`stdlib::test_support::assert_linear`. It compares the time for an
input with the time for one 4 times larger, so it does not fail on a busy
machine the way a fixed time limit would.

A change to `fictionet attach` or to how a world is reached should also pass the
Docker tests (`tests/docker/*/run.sh`), and for the Helm chart, the Kubernetes test
(`tests/k8s/run.sh`). Each script builds what it needs, checks, and cleans up.

CI runs the TCP/UDP, web, ping and proxy Docker scripts and the restricted
kind proxy test (`tests/k8s/proxy.sh`) on every push and pull request.
The nightly integration workflow runs the tun kind test (`tests/k8s/run.sh`)
and the QEMU VM test, with its prepared image cached. Nested VM and gVisor
tests remain manual. Missing host capabilities fail when `CI` is set.

The Docker web and proxy tests and `tests/k8s/proxy.sh` check full transfer
sizes and counts, with a 30-second deadline per bulk transfer (60 seconds for
the 32 parallel web downloads, which share one attach socket). They print
throughput and timing measurements without imposing performance thresholds.
Incomplete or failed transfers and transfers that exceed the completion
deadline fail.

## Releases

Set the package version in `Cargo.toml` and refresh the lockfiles with Cargo.
Run the checks above, check `fictionet --version`, and check the observer's
`world` reply. Both report the package version.

Give this repository Actions write access to the `fictionet-attach` and
`fictionet-web-world` packages in GHCR before the first release. After the
release commit passes CI, a maintainer creates and pushes the matching tag,
such as `v0.1.0`. The release workflow checks the tag against `Cargo.toml`,
logs into GHCR with `GITHUB_TOKEN`, and publishes both `deploy/Dockerfile`
targets for `linux/amd64` and `linux/arm64`. The image tags include the `v`,
for example `ghcr.io/amlalabs/fictionet-attach:v0.1.0`.

Check that both published images contain both architectures and smoke-test
them before updating the Inspect package's image pins in a separate change.
Creating a local release commit does not publish images; pushing a version
tag does.

## Adding a protocol module

A protocol is one file in `src/stdlib/protocols/`, declared with `pub mod` in
`src/stdlib/mod.rs`. A `#[path]` attribute on the declaration loads the file,
so the public path stays `stdlib::<name>`. It is written with no I/O, on the
tools in `stdlib::codec`: its message types implement `Wire`, and its framer
implements `Decode`. Crate-private helpers and shared types are fine.
The module's own docs explain the protocol and show how to use it, with examples
that run as doctests.

A large protocol may be a directory instead, as `protocols/cme_mdp3/`,
`protocols/json_schema/` and `protocols/smb2/` are. Its entry file is `mod.rs`,
which declares private child modules next to it. The module's public paths stay
flat: re-export child items from `mod.rs`.

For modules generated from schemas, see [code generation](docs/codegen.md).

Add the module declaration and a one-line description to the table in
`src/stdlib/mod.rs`. Add a fuzz target in `fuzz/fuzz_targets/` and its `[[bin]]`
entry in `fuzz/Cargo.toml`. The module's own docs describe its behavior and limits.
`tests/copy_and_own/stdlib.rs` compiles the whole stdlib in a separate crate.

## Names

A protocol module follows these rules. The `stdlib::codec` module docs give
each with examples. The E rules apply to protocol modules.

- **E1.** One `pub enum Error` per module, for every `Wire` and `Decode` impl in it. An item fault that carries more than the reason is a struct named for the fault (`fix::FieldFault`). `Unwritable` is the one variant every module may have: a value the writer refuses because it would not read back the same. Prefer a variant named for the clause when there is one.
- **E2.** `FrameError` only where a decoder yields `Result<Unit, Error>`: it is the fault that ends the stream.
- **E3.** An error the peer sends keeps the protocol's word (`modbus::Exception`, `grpc::Status`).
- **E4.** No `DecodeError`, `EncodeError`, `ParseError`, `WireError`, `<Unit>ParseError`, `<Unit>Error`, `<Module>Error` or `Malformed`.
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

Run the Divan benchmarks with Cargo. Each file in `benches/` is a benchmark
binary; pass a name after `--` to filter its benchmarks:

```console
$ cargo bench --locked
$ cargo bench --locked --bench network -- tcp
$ cargo bench --locked --bench services -- sites
$ cargo bench --locked --bench runtime -- observe
$ cargo bench --locked --bench decoders
$ cargo bench --locked --bench network -- --list
```

`network` covers TCP throughput, routed paths, idle connections, delayed links,
scheduling and unread-link memory. `services` covers relay traffic, HTTPS sites
and proxy DNS caching. `runtime` covers timers, event logging and observation,
including a graph with 1,000 sites. `decoders` feeds TPKT/COTP, HTTP/1 requests
and ITCH add orders in 16 KiB chunks.

Divan reports timing distributions, byte or item rates, allocation counts and
peak heap growth. World setup and cleanup happen outside measurement. The memory
benchmarks keep queued packets alive until measurement ends; allocation,
reallocation and free byte totals show heap growth. Counts are per iteration:
divide allocations by the workload's bytes, requests, packets or round trips
for per-item costs.
The world workloads use three samples of one iteration by default; Divan's
`--sample-count` changes that. Compare the same workloads on two commits on the
same machine.

Packet sends and losses, unread packets, HTTP request latency percentiles and
process CPU time, observer rows and proxy DNS queries are printed to stderr
for the last iteration. These are diagnostics, not performance thresholds. Observer row counts
depend on request rate because packet observation samples every 100 ms.

Every benchmark binary uses `divan::AllocProfiler`. It counts allocations on the
benchmark thread; it does not count background relay, observer or event-writer
threads or the proxy subprocess. The simulated worlds run on the benchmark
thread. See [Divan's allocation profiler](https://docs.rs/divan/0.1.21/divan/struct.AllocProfiler.html).

Proxy benchmarks run the `fictionet` binary built by Cargo, or `FICTIONET_BIN`.
Responses must have the expected status and a complete Content-Length body;
the successful site's bytes must match its page. Observer subscriptions must
acknowledge their request ids and remain alive throughout measurement. Invalid
responses and failed worlds abort the run; timings have no pass/fail thresholds.

CI compiles benchmarks in `cargo build --locked --workspace --all-targets` and
does not run them. To compile just the benchmark targets locally:

```console
$ cargo bench --locked --no-run
```

## Docs

The crate docs are the guide, and they are written as a spec: they say what the code
does, and what it does not support. A change in behavior comes with the matching change
in the docs. Every public item has docs (`#![warn(missing_docs)]`), and examples in
the docs compile and run as tests.

Write plain English, in short sentences.

## License

By contributing, you agree that your contributions are dual licensed under the MIT
and Apache-2.0 licenses, as described in [README.md](README.md#license).
