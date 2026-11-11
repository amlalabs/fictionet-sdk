# Faster checks

Keep Fictionet in one crate. The goal is to stop rebuilding and re-exploring
identical work, with every assertion, test, model bound and proof intact.
These commands are opt-in developer tools, not commit or merge requirements.
Kani is never part of the light gate and runs only when explicitly requested.

## Where the time went

The November 9 logs were collected on a shared machine, often with a cold
per-agent target directory. They are approximate baselines, not benchmarks of
this change. The conversation log records nextest's 6,739 tests passing in
14.154 seconds; the supplied total including compilation was 262 seconds.

| Work | Observed cost | Expected effect of this change |
| --- | --- | --- |
| Light checks | About 30 minutes cold under load | Fewer repeated builds and stable features should remove minutes. No defensible total until measured on comparable load. |
| Formatting | Seconds | Overlaps other work; essentially unchanged. |
| Workspace clippy | 3m25s cold; 1m29s–1m47s warm | A warm cache previously saved about 1.5–2 minutes. This is evidence for reuse, not a guaranteed saving per edit. |
| Library test build | 2m25s–3m33s | Removing workspace optimization should reduce code generation; shared dev/test settings avoid duplicate compatible artifacts. Magnitude unmeasured. |
| Integration test build | 35s–3m20s | Same profile/cache benefit. The binary remains intact. |
| Honeypot and world tests | About one minute each, including builds | One workspace invocation shares dependencies and a single feature graph. No separate cold directories. |
| Test execution | 14s nextest; doctests 2.3s | Lower optimization can increase execution time. Even a fivefold increase from 14s to 70s costs only 56s; this is a tradeoff estimate, not a measured result. |
| Wasm build | 109s | Warm dependencies and smaller debug output should help. It still needs its own target artifacts; native artifacts cannot replace them. |
| h2spec | 203s in its own target | Reuse the same target and feature set; keep its explicit invocation. Network download and execution costs remain. |
| TLA+ | 447 configs, 43,327s summed (about 12h serial) | DNS passing configs explore once instead of once per property. A config with N checks removes N−1 graph explorations, but combined temporal checking still has a cost. |
| Kani | About 1min codegen per invocation; roughly 4min each when run singly | Batch compatible harnesses. For 213 harnesses grouped into G compilations, the avoidable codegen is roughly (213−G) minutes; solver time remains. |
| Other crates' Kani | 3,455s together | Batch within each crate/target; no measured solver improvement. |
| Lean | Seconds cached | Keep Lake caches; no proof or toolchain changes. |

## Build profiles

Development now uses line tables, matching the previous test debug setting.
Tests compile workspace code at optimization level one, so timing-bound tests
(the UDP ephemeral-port test has a five-second limit) stay fast; they share the
development line-table setting. External dependencies stay at level two: their cold optimization
cost is amortized by the shared cache, and cryptography remains fast. The
wildcard dependency override does not optimize workspace packages such as the
vendored Rustls and smoltcp. Test assertions and overflow checks remain enabled.
Release and benchmark profiles are unchanged.

Incremental compilation and 256 codegen units already default on for dev/test;
there is no benefit in restating those defaults. Increasing units does not
parallelize the single crate's front end, and can increase memory and linking
work. Cargo documents these defaults and profile inheritance in its
[profile reference](https://doc.rust-lang.org/cargo/reference/profiles.html).

The linker remains rustc's bundled LLD. There is no link-only timing establishing
that mold is faster here; switching globally also changes artifact fingerprints
and must avoid applying native linker flags to wasm. Do not charge a speculative
linker win against the estimates above. Similarly, sccache is not installed or
made mandatory by this change. Evaluate it separately for repeated dependency
builds across machines/worktrees; it does not replace incremental compilation
of the large local crate. Avoid disabling incremental globally just to obtain
cache hits.

## One warm target

On this machine, set these once in the shell used by collaborating agents:

```sh
export CARGO_BUILD_JOBS=8
export CARGO_TARGET_DIR=/home/souvik/Projects/amlalabs/.fictionet-comp-work/target-gatespeed
```

Use the pinned toolchain and stable flags. Cargo locks its target directory
while building; preserve that lock and never clean a target another task uses.
The gate holds a separate advisory lock for its entire run, so another gate
cannot replace its test executables between compilation and execution. Direct
Cargo or Kani invocations do not take that lock: coordinate those with the gate
owner and do not run them against the same target during a gate. This also
applies to the initial `cargo xtask` bootstrap, before its gate lock is held.
A shared target prevents duplicate dependency builds but does not promise full
reuse of path-dependent workspace artifacts across different checkouts. Do not
change source files during a check whose result will be attributed to a commit.
Do not invoke a shared target's un-hashed executable by hand while another
checkout can replace it. Run through Cargo. Build scripts and tests that write
outside Cargo's artifact directories still need their own isolation.

Keep targets and TLC state on disk rather than the RAM-backed `/tmp`. The
machine's 91GB physical memory includes about 27GB already occupied by tmpfs;
the work slice has its own 48GB limit. Eight Cargo jobs is a starting budget,
not permission for each agent to start eight more jobs in a separate cache.

## Light gate

```sh
cargo xtask gate --dry-run
systemd-run --user --scope -q --slice=fictionet-work.slice \
  -p MemoryMax=10G -p MemorySwapMax=0 cargo xtask gate
```

The dry run only prints commands. The actual command starts formatting, native
checks, and the wasm build in separate lanes. Native checks run workspace
clippy with warnings denied, nextest, then Cargo doctests. All commands share
one target and their failures are collected; no retry hides a failure. Cargo
may serialize compilation across lanes because of its build lock. Formatting
and test execution can overlap other work; this is not a claim of simultaneous
native and wasm compilation in one locked directory.

The existing nextest heavy/world resource groups and timeout remain. Total test
concurrency is now eight to leave capacity for other work in the slice. Nextest
is the light command's default runner; install it explicitly before invoking
the command. A missing nextest is a failure, not a silent fallback or skip.
[Nextest runs tests across binaries](https://nexte.st/docs/running/);
Cargo still runs doctests separately. No test selection filters are added.

This light command does not replace the contributor feature matrix, explicit
host tests, h2spec, fuzzing, documentation builds, benchmarks, or formal checks.
It preserves the described light workload and adds workspace coverage.
The host-tool feature is explicit in its native commands, retaining the old
xtask compilation coverage. To run a particular test, `cargo test` still works.

## Lightweight xtask

Verification and gate orchestration now build xtask with only the standard
library. SDK, demo, image and capture dependencies are behind `host-tools`;
`rawnic` also enables that feature. This removes an entire SDK/demo build from
cold proof-tool startup and prevents xtask from enabling SDK web features in
otherwise minimal commands. Host tools remain available through
`cargo xtask-host`, and the all-features matrix continues to check them.

## TLA+ cost tiers

Cost tiers describe scheduling; they do not change model bounds or turn a
partial run into a full verification result. There is no new registry of
configs or automatic skip list. Use the existing spec/config selectors for DNS
and MPTCP. Other models retain their documented commands.

| Tier | Scheduling cost | Selection |
| --- | --- | --- |
| Quick | Seconds per config | Configs whose existing logs show second-scale completion; include their ablations. An unmeasured config is not assumed quick. |
| Standard | Minutes | Remaining measured configs outside the tail; run when working on their model family. |
| Long tail | Tens of minutes to hours | The expensive configurations below; reserve a separate explicit run when their model or dependencies change. |

| Long-tail configuration | Observed runtime |
| --- | --- |
| DNS `Resolution_concurrent_live` | More than 3h, unfinished, about 9 million states |
| MPTCP `Observation_signals` | 2h48m |
| Layer runtime `StreamRunner_base` | 33m |
| Observer `Observer_wide` | 27m |
| TLS `Layer_live_base` | 26m |
| HTTP/2 layer `Lifecycle_base` | 25m |
| TLS `Layer_repeat_base` | 22m |

A change includes imported TLA modules, the config, shared operators, the
runner, tool version, or assumptions relating the model to production code.
When dependencies are uncertain, include the affected family. A prior full
result may only be reused for unchanged inputs; no automatic change detector
or proof-result cache is introduced here. A full audit still runs every config.
The single-property DNS liveness tail gets no benefit from property batching.
MPTCP already batched its passing properties before this change.

DNS now uses two TLC workers rather than all available CPUs. Passing configs
retain their original complete text; ablations still check every expected
violation separately with one worker. No constants, fairness assumptions,
symmetry sets or properties change. In particular, do not enable symmetry on
liveness configs as a shortcut. Smaller constants would prove a smaller claim.

DNS, MPTCP and layer verification allocate an exclusive run directory using
atomic directory creation. Copied specs, generated configs, logs, states and
Java temporary files live beneath it. The command prints the directory; logs
are retained. This prevents two invocations sharing Cargo's cache from racing
over generated TLC modules or removing each other's states. Direct Java runs
must likewise use distinct working, temporary and state directories; a unique
`-metadir` alone does not isolate `/tmp/TLC.tla`. Lake's existing source caches
are unchanged; don't concurrently mutate the same Lean checkout.

## Kani batching

Only when requested, group passing harnesses from the same package and target:

```sh
cargo xtask kani fictionet lib FULLY_QUALIFIED_HARNESS FULLY_QUALIFIED_OTHER_HARNESS
```

The command makes one cargo-kani invocation with repeated exact selectors,
stubbing support, and solver concurrency one, in the work slice with a 12GB
memory cap and no swap. Use `tests` in place of `lib` for test-target harnesses.
Supply actual names from that model's existing instructions; there is no new
harness inventory. Preserve any extra flags required by a model by using its
documented direct invocation instead. `CARGO_BUILD_JOBS=8` controls compilation;
it does not make eight solvers safe. Harnesses observed at 9–10GB leave little
headroom even in the 12GB scope. An OOM remains a failed run.

This command and every area's `resources` command first take one of the
work slice's Kani slots (`xtask/src/kani_slot.rs`): its `MemoryHigh` divided
by the run's memory cap, shared by every worktree. A run waits while all are
taken. Past `MemoryHigh` the kernel reclaims from every process in the slice
at once, and a CBMC process then does its own work at a few percent of a core.
Before the slot, a run takes its Cargo target directory alone (`kani.lock`
there): Kani rewrites each harness's goto binary in place under
`target/kani/`, so two runs in one target directory break each other.

Do not mix expected-failure ablations into a passing group or interpret an
arbitrary nonzero exit as an expected counterexample. Retain their documented
individual classification and property checks. The grouped command propagates
failure and never retries. Distinct targets, features and incompatible options
still require separate compilations. No Kani harness or proof is removed.

## Validation of this change

No gate, test suite, TLA+ configuration, Kani harness or Lean proof was run.
Build/runtime savings above are reasoned estimates unless explicitly described
as prior log observations. One permitted targeted build confirmed the dependency isolation:

```sh
systemd-run --user --scope -q --slice=fictionet-work.slice \
  -p MemoryMax=10G -p MemorySwapMax=0 \
  env CARGO_BUILD_JOBS=8 \
  CARGO_TARGET_DIR=/home/souvik/Projects/amlalabs/.fictionet-comp-work/target-gatespeed \
  bash -c 'TIMEFORMAT="elapsed=%3R seconds"; time cargo build --locked -p xtask --bin xtask'
```

It compiled only xtask: Cargo reported 0.32s, shell elapsed time was 0.346s.
This confirms the default orchestrator does not need an SDK/demo build; it is
not a measurement of the light gate or host-feature build. The initial attempt
used unavailable `/usr/bin/time` and exited before starting Cargo. No other
build was run. The whole-gate advisory lock was added after this measurement
and was reviewed without rebuilding. Changed Rust tooling files were formatted
with rustfmt, including a corrected line wrap in the host-command usage text;
the diff was checked for whitespace errors. Clippy, cargo doc,
benchmarks and all runtime checks were intentionally left unrun.
