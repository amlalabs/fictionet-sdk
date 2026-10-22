# Contributing

Issues and pull requests are welcome. For a large change, open an issue first.
Security problems go by email, not in issues: see [SECURITY.md](SECURITY.md).

## Building and checking

The `fictionet` command is the `fictionet-cli` package in `cli/`, and Cargo
builds it with the SDK from the top directory. Install it from a checkout with
`cargo install --locked --path cli`.

The stdlib's packet dissectors use the same decoders as its services. Pcap
output takes caller-supplied packets, and the optional `page` feature streams
one typed state. Worlds own their observation and browser pages.

Run these commands with four sets of flags:

- the default features: `-p fictionet -p fictionet-codegen -p fictionet-codegen-golden -p fictionet-codegen-layouts -p xtask`
- no default features: `-p fictionet -p fictionet-codegen -p fictionet-codegen-golden -p fictionet-codegen-layouts --no-default-features`
- the command: `-p fictionet-cli`
- all features: `--workspace --all-features`

The command turns on the SDK's `tokio` feature, which is not a default, and
Cargo builds the SDK once for all the packages in one command. So the first
two sets name their packages and leave the command out, and a plain
`cargo nextest run` in the top directory tests the SDK with `tokio`. The
example worlds enable `web-proxy`, so only the all-features set builds them.
Add the set's flags to each Cargo command, before `-- -D warnings` for clippy:

```console
$ cargo build --locked --all-targets
$ cargo nextest run --locked
$ cargo test --locked --doc
$ RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps
$ cargo clippy --locked --all-targets --test host -- -D warnings
$ cargo fmt --all
```

The library also builds for the browser. That needs the `wasm32-unknown-unknown`
target and a clang with that target, which compiles ring's C code:

```console
$ cargo check --locked -p fictionet --lib --no-default-features --target wasm32-unknown-unknown
$ cargo check --locked -p fictionet --lib --no-default-features --features tokio --target wasm32-unknown-unknown
$ cargo clippy --locked -p fictionet --lib --no-default-features --target wasm32-unknown-unknown -- -D warnings
```

The fuzz crate is outside the workspace, since cargo-fuzz builds it on nightly.
From `fuzz/`, check every target with `RUSTFLAGS="--cfg fuzzing" cargo check --locked --bins`.
From the root, run the fuzz helpers' tests and check their formatting:

```console
$ RUSTFLAGS="--cfg fuzzing" cargo test --locked --manifest-path fuzz/Cargo.toml --lib
$ cargo fmt --all --manifest-path fuzz/Cargo.toml
```

## Tests

The tests run under [cargo-nextest](https://nexte.st), installed with
`cargo install cargo-nextest --locked`. `cargo nextest run` does not run
doctests, so `cargo test --doc` runs them. `.config/nextest.toml` holds the
settings: tests are never retried, a test is flagged after 15 seconds, and the
tests that run whole worlds run a few at a time.

The SDK and the command each have two integration test binaries. `tests/it`
and `cli/tests/it` run on any machine, one module per area. They need node,
curl and Chromium (set `CHROMIUM` if the browser is not named `chromium`).
`tests/host` and `cli/tests/host` hold the tests that need user namespaces,
root or a tun device, and fail where the machine lacks them. Helpers that
several test binaries or benchmarks use are in `tests/support`, the
`fictionet-test-support` crate. The host tests run only when named:

```console
$ cargo nextest run --locked --test host
```

The Python package's tests run with uv, and need Docker and helm:

```console
$ uv run --project python/inspect_fictionet --locked --extra k8s pytest python/inspect_fictionet/tests
```

## Benchmarks

The benchmarks in `benches/` and `cli/benches/` use [Divan](https://docs.rs/divan) and run with
`cargo bench`. Pass a name after `--` to filter them:

```console
$ cargo bench --locked
$ cargo bench --locked --bench network -- tcp
$ cargo bench --locked --bench network -- --list
```

`network` covers TCP throughput, routed paths, idle connections, delayed links,
scheduling and unread-link memory. `services` covers relay traffic, HTTPS sites
and proxy DNS caching. `runtime::http` measures HTTPS throughput over HTTP/1
and HTTP/2.
`network::sched::packet_round_trips` compares no observer, event-only
interest and packet interest. `runtime::timers` covers timers.
`decoders` feeds TPKT/COTP, HTTP/1 requests and ITCH add orders in 16 KiB
chunks. Divan reports timings, rates and allocation counts; no benchmark has a
pass or fail threshold. Compare two commits on the same machine.

## h2spec

`cargo test --features web-proxy,tokio --test h2spec` runs the h2spec
conformance suite against the native HTTP/2 server, over TLS and h2c. It
downloads h2spec, so plain `cargo test` leaves it out.
