# Contributing

Thank you for your interest in Fictionet. Issues and pull requests are welcome.

## Before you start

For a large change, open an issue first, so we can agree on the design before you
write the code. Security problems go by email, not in issues: see
[SECURITY.md](SECURITY.md).

## The checks

A pull request must pass the same checks as CI, in both feature sets:

```console
$ cargo build --all-targets
$ cargo nextest run --workspace
$ cargo test --doc --workspace
$ RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
$ cargo clippy --all-targets -- -D warnings
```

Then run each command again with `--features tokio`.

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
proxy    fictionet attach --type https_proxy: DNS queries for cold and missing names
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
