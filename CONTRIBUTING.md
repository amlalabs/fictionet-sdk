# Contributing

Issues and pull requests are welcome. For a large change, open an issue first.
Security problems go by email, not in issues: see [SECURITY.md](SECURITY.md).

## Building and checking

The `fictionet` command is the `fictionet-cli` package in `cli/`, and Cargo
builds it with the SDK from the top directory. Install it from a checkout with
`cargo install --locked --path cli`.

CI runs these commands in three feature sets: the default features,
`-p fictionet -p fictionet-codegen -p fictionet-codegen-layouts
--no-default-features`, and `--workspace --all-features`. The command turns on
the SDK's default features, so the set without them names its packages and
leaves the command out. The example worlds enable `web-proxy`, so only the
all-features set builds them. For the other two sets, add the flags to each
Cargo command, before `-- -D warnings` for clippy:

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
$ cargo clippy --locked -p fictionet --lib --no-default-features --target wasm32-unknown-unknown -- -D warnings
```

The minimum Rust version is 1.91:

```console
$ cargo +1.91 check --locked --workspace --all-targets
```

The fuzz crate is outside the workspace, since cargo-fuzz builds it on nightly.
From `fuzz/`, CI checks every target with `RUSTFLAGS="--cfg fuzzing" cargo check --locked --bins`,
and from the root it runs the fuzz helpers' tests and checks their formatting:

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
root or a tun device, and fail where the machine lacks them. They run only
when named:

```console
$ cargo nextest run --locked --test host
```

Randomized and large-input tests size their loops with
`stdlib::test_support::rounds`. For a deep run, scale them up:

```console
$ FICTIONET_TEST_SCALE=100 cargo nextest run --locked
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
and proxy DNS caching. `runtime` covers timers, event logging and observation.
`decoders` feeds TPKT/COTP, HTTP/1 requests and ITCH add orders in 16 KiB
chunks. Divan reports timings, rates and allocation counts; no benchmark has a
pass or fail threshold. Compare two commits on the same machine. CI compiles
the benchmarks and does not run them.

## cargo xtask

Jobs that need Docker, Kubernetes, a VM or other tools are `cargo xtask`
commands. `cargo xtask --help` lists them.

| Command | What it does |
| --- | --- |
| `cargo xtask images [artifactory\|hosted]` | Builds the Artifactory images and the hosted example's binaries. |
| `cargo xtask docker <ping\|tcpudp\|proxy\|web>` | Runs a Docker Compose test of `fictionet attach`. |
| `cargo xtask k8s [tun\|proxy]` | Runs the Helm chart on kind. |
| `cargo xtask vm ...` | Boots the development VM and runs test suites in it ([vm/README.md](vm/README.md)). |
| `cargo xtask demo <name>` | Runs a demo in the VM. [demos/README.md](demos/README.md) lists them. |
| `cargo xtask eval <border\|fakewiki\|adaptive-web\|artifactory>` | Builds a world's images and runs its Inspect eval. |
| `cargo xtask fuzz [--check \| <target> \| <seconds>]` | Runs the fuzz targets ([fuzz/README.md](fuzz/README.md)). |
| `cargo xtask scan [output directory]` | Records the scan example's dashboard. |

A change to `fictionet attach` or to how a world is reached should also pass
`cargo xtask docker`, and a change to the Helm chart `cargo xtask k8s`.
