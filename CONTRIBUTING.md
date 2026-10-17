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
$ cargo build --locked --workspace --all-targets
$ cargo nextest run --locked --workspace
$ cargo test --locked --doc --workspace
$ RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --no-deps
$ cargo clippy --locked --workspace --all-targets -- -D warnings
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
`Cargo.toml`. On pushes and pull requests, CI builds every fuzz target in
one job and runs `fuzz/check-targets.sh`. Nightly and manual runs use four
concurrent shard jobs on GitHub's `ubuntu-latest` runners. Each job builds
and runs its assigned targets for 60 seconds each. A failed target or shard
does not stop the others. Crash artifacts are named `fuzz-artifacts-0`
through `fuzz-artifacts-3`. See [fuzz/README.md](fuzz/README.md) for running
a shard locally.

CI also runs the fuzz helper library's regression tests on the pinned stable
toolchain. Run this command from the repository root:

```console
$ RUSTFLAGS="--cfg fuzzing" cargo test --locked --manifest-path fuzz/Cargo.toml --lib
```

CI runs `cargo bench --locked -p fictionet-copy-modules --bench tcp` in release to compare copied TCP throughput and allocation counts with the built-in module.

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
throughput and timing measurements on every run. Strict download timings
(including the web test's spread and recovery comparison) require
`FICTIONET_PERF_CHECK=1`:

```console
$ FICTIONET_PERF_CHECK=1 tests/docker/web/run.sh
$ FICTIONET_PERF_CHECK=1 tests/docker/proxy/run.sh
$ FICTIONET_PERF_CHECK=1 tests/k8s/proxy.sh
```

Use a controlled machine for these performance checks. Routine runs check
transfer completion, sizes and counts. They do not enforce strict timing
thresholds or provide strict throughput regression coverage. Incomplete or failed
transfers and transfers that exceed the completion deadline fail.

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
implements `Decode`. It uses only public `fictionet::` items; see
[the stdlib docs, section Changing a protocol by copying it](src/stdlib/mod.rs).
The module's own docs explain the protocol and show how to use it, with examples
that run as doctests.

A large protocol may be a directory instead, as `protocols/cme_mdp3/`,
`protocols/json_schema/` and `protocols/smb2/` are. Its entry file is `mod.rs`,
which its catalog record names in `file`, and it declares private child modules
next to it. A copy takes the whole directory. The module's public paths stay
flat: re-export child items from `mod.rs`.

For modules generated from schemas, see [code generation](docs/codegen.md).

A new module is registered in two places, and a test holds each to the code:

- a record in `catalog/stdlib.rs`, which says what the module can do
  (`tests/stdlib_catalog.rs` checks every column) and names its entry file,
  such as `protocols/<name>.rs`, in `file`. Regenerate the table in
  `src/stdlib/catalog.md` with
  `BLESS_STDLIB_CATALOG=1 cargo nextest run --locked --test stdlib_catalog`.
  The same command writes the module's `pub mod` declaration in
  `src/stdlib/mod.rs` and its `#[path]` entry in
  `tests/copy_and_own/modules.rs`, which compiles the file as a module of a
  separate crate;
- a fuzz target in `fuzz/fuzz_targets/`, with a record in `catalog/stdlib.rs`
  that names the module as its owner. The same bless command writes its
  `[[bin]]` entry in `fuzz/Cargo.toml`.

The catalog record and the module docs are where a module is described. The front
pages (`README.md`, the crate root in `src/lib.rs`, and the top of
`src/stdlib/mod.rs`) tell one story about the core and do not gain a paragraph
per protocol.

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

`benches/perf.rs` is a performance suite. Each group builds a small world, pushes
traffic through it, and prints a table. Run all of it, or name the groups you want:

```console
$ cargo bench --locked --bench perf
$ cargo bench --locked --bench perf -- tcp path
$ cargo bench --locked --bench perf -- sites --reps 5
$ cargo bench --locked --bench perf -- --quick
```

Use `--list` for the complete list of groups and what each measures. The suite
covers network throughput and latency, scheduler and timer costs, memory and
allocations, logging and observation overhead, and decoder throughput:

```console
$ cargo bench --locked --bench perf -- --list
```

Each run of a case repeats three times by default (`--reps`). Rates and times are
medians, with the range of the runs in brackets. A shared machine makes any single
timing noisy, so trust the counts first: allocations, and packets sent and lost.
Those barely change from run to run. Observer rows are different: the observer keeps
a sample of packets in each 100 ms, so a faster run yields fewer rows per request.
Compare observer costs only between runs with similar request rates. To judge a change, run the same groups on
the commit before it and on the change, one after the other, and compare.

The `proxy` group runs the `fictionet` binary built with the suite, or the one that
`FICTIONET_BIN` names. It records timings only after every response has the expected
status and exactly the bytes declared by Content-Length. The successful site's body
must also match its page. Read errors, incomplete responses and ambiguous framing
panic instead of producing a timing. The 30-second read timeout bounds stalled reads.
The suite is not a test, and CI does not run it. A full run takes a few minutes and
uses one core per world, plus one for the observer in `observe` and `graph`.

The `observe` and `graph` groups report an observed row only when the observer
outlived the measurement. Each subscription must first acknowledge its own request id.
Early EOF, ended streams, error replies and invalid events fail the run. After
measurement, the suite signals the observer to stop before cancelling the world, then
joins it before reporting the row.

## Docs

The crate docs are the guide, and they are written as a spec: they say what the code
does, and what it does not support. A change in behavior comes with the matching change
in the docs. Every public item has docs (`#![warn(missing_docs)]`), and examples in
the docs compile and run as tests.

Write plain English, in short sentences.

## License

By contributing, you agree that your contributions are dual licensed under the MIT
and Apache-2.0 licenses, as described in [README.md](README.md#license).
