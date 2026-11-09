# Layer runtime verification

The code that runs layer stacks on live sockets, and the first stacks
ported onto it: `layer::Framed` (`src/stdlib/layer/framed.rs`), the
runners `services::stack::stream` and `services::stack::datagrams`
(`src/stdlib/services/stack/`, the stream runner in `live.rs`), the Nuclear controllers' Modbus/TCP
stack (`demos/nuclear/world/src/plc.rs`) and the Search time server
(`demos/search/world/src/ntp.rs`).

| Part | What it is | Where |
|---|---|---|
| TLA+ | The two runners' loops over an abstract stack and an abstract peer, checked with TLC, each rule with a configuration that turns it off and must fail | [`tla/`](tla/) |
| Kani | Bounded proofs over the production Rust of `Framed`, the connection count port servers keep (`Counted`), the PLC server, the time server and `ntp::server_reply` | [`kani/`](kani/) |

[VERIFICATION.md](VERIFICATION.md) says what each model and proof covers,
what it leaves out, the results, and the three bugs found.

```sh
export CARGO_BUILD_JOBS=4 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
# Use a dedicated CARGO_TARGET_DIR for this worktree.
# TLC. Every *_base.cfg must pass; every *_without_<flag>.cfg must violate
# the one property it names. StreamRunner_halfclose.cfg must pass;
# StreamRunner_without_finishinput.cfg preserves its old counterexample.
cd verification/layer-runtime/tla
systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=10G -p MemorySwapMax=0 \
  ~/.cache/adorably-fv/jdk/bin/java -Xmx2g -cp ~/.cache/adorably-fv/tla2tools.jar \
  tlc2.TLC -workers 2 -metadir ~/.cache/adorably-fv/states/stream \
  -config StreamRunner_base.cfg StreamRunner.tla
systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=10G -p MemorySwapMax=0 \
  ~/.cache/adorably-fv/jdk/bin/java -Xmx2g -cp ~/.cache/adorably-fv/tla2tools.jar \
  tlc2.TLC -workers 2 -metadir ~/.cache/adorably-fv/states/datagrams \
  -config DatagramRunner_base.cfg DatagramRunner.tla

# Kani, from the root of the repository. A --harness filter matches by
# substring and runs the harnesses one after another; none needs more
# than a few GiB.
cd ../../..
systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=10G -p MemorySwapMax=0 cargo kani -p fictionet --harness the_buffer_is_charged_before_bytes_are_taken \
  --harness every_charge_comes_back --harness units_come_up_in_order \
  --harness a_decoder_failure_comes_up_once_then_ended \
  --harness a_reply_comes_only_for_a_request --harness a_header_of_mode_0_6_or_7 \
  --harness connections_are_counted_up_to_the_maximum
systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=10G -p MemorySwapMax=0 cargo kani -p nuclear-world --harness each_request_gets_one_answer_in_order \
  --harness a_pipelined_request_waits -Z unstable-options \
  --cbmc-args --unwindset "$(cat verification/layer-runtime/kani/plant.unwindset)"
systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=10G -p MemorySwapMax=0 cargo kani -p web-world --harness the_time_server \
  --harness one_conversation_answers_each_request_in_turn

# The regressions for the bugs.
systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=10G -p MemorySwapMax=0 cargo test -p fictionet --lib -- layer::framed services::stack
```

TLC 2.19; Kani 0.68 with CBMC 6.11.

World hosts now attach stacks directly to TCP and UDP children. `Session`
in `services/stack/session.rs` supplies stream idle and write timeouts. Its
completion predicate requires the output end, no unreported writes or running
work, and either input end or application termination. The stream model's
`shut`, `inputOver`, and `written` project those conditions for a nonterminal
application without jobs. The full `Session` adapter and packet dispatch loop
are not modeled by `StreamRunner`; child isolation and budget refusal remain
in the layer models, and integration tests check their composition.

The native TCP and UDP adapters share `network/applications.rs` for bounded
child progress, job cancellation, deadlines and wake delivery. A completed
application closes its child only after draining commands. TCP's `Hold` and
`Gone` contract retains admission guards independently of that child; the
public `Retirement` interface also lets a custom transport own those guards.
The connection-count Kani harness proves the counter arithmetic, not the
transport's decision to retire. World admission tests exercise that separation
with an independently controlled retirement implementation.
Shutdown regressions retain an endpoint handle inside a listener factory or
an unpolled UDP application. Stopping the driver must release that capture
outside the transport lock, even while another endpoint handle remains live.

`tests/it/packet_composition.rs` runs the unchanged Echo stack directly and
inside a stream carrying framed inner IP/TCP, both through pure drivers and
the live world. Inner and outer traffic includes reversed fragments and
overlapping fragments with changed payload and valid transport checksums, so
accepting an overlapping datagram would corrupt the application result.
`tests/it/tls_stack.rs` adds IP/TCP below the pure TLS/HTTP stack; existing live
TLS tests exercise the world installation path. Persistent DNS and NTP tests
send empty datagrams between valid requests. `examples/custom-ip` installs
an external implementation of the public packet layer under unchanged HTTP.
A live IP-factory test refuses transport output until a layer timer fires;
the dispatcher must let virtual time advance while preserving that output.
It fills the reply queue with ICMP traffic and checks that a bound UDP
application's earlier deadline still fires while IP output is refused.

The stream packet format has a four-byte big-endian length and raw IP payload.
Its scope and interface metadata are local construction inputs. The adapter
reserves the declared packet size before allocation and keeps one packet per
direction; it does not preallocate the largest possible IP packet for every
tunnel. Unit tests cover all stream cuts, empty frames, refused output,
partial writes, truncation, allocation refusal, end and reset. These are
execution tests, not a formal proof of the new packet adapter.

The world integration was checked on November 8, 2026 with the whole
workspace test suite: 3,970 core unit tests, 1,353 integration tests and
299 core documentation tests passed, along with the extras, honeypot,
Nuclear, Search and external example tests. Workspace build, clippy with
warnings denied, formatting and documentation with warnings denied passed.
The core also built for wasm32 with and without the Tokio feature, and
the Tokio wasm configuration passed clippy with warnings denied.

The stream completion model rerun generated 27,865,057 states and found
185,569 distinct states, with no violation. Removing the input-end
requirement still violates `FinishNeedsInput`. The connection admission
Kani harness had no failures among 451 checks, including two unreachable
checks. The lifecycle connection model passed
with 720 distinct states; removing orphan expiry or unread-data reset
still violates the corresponding temporal or action property. Transactional
binding preparation passed with 9,986 distinct states. These checks retain
their existing abstraction limits; they do not prove the entire host loop.

The existing network and runtime benchmarks were run on the same workstation
against the integration branch before world composition and after batching
packet ingress and child events. Each row is a median of three samples.
Other verification jobs shared the workstation, so these are diagnostic
measurements, not isolated performance guarantees.

| Workload | Integration baseline | World composition |
| --- | ---: | ---: |
| TCP, one connection, 32 MiB | 28.13 ms | 36.36 ms |
| TCP, ten connections, 4 MiB each | 45.03 ms | 59.52 ms |
| TCP, one hundred connections, 1 MiB each | 209.2 ms | 381.8 ms |
| TCP round trips | 34.66 ms | 51.44 ms |
| TCP transfer with 99 idle connections | 81.11 ms | 83.98 ms |
| HTTP/1, 100,000 requests | 1.356 s | 2.094 s |
| HTTP/2, 100,000 requests | 1.976 s | 3.429 s |

The new packet and child drivers add scheduling and ownership bookkeeping.
Batching removed a repeated transport sweep per received packet and a
repeated child sweep per queued child event. Before those changes the
HTTP runs took 4.004 s and 7.208 s. The remaining slowdown is material;
these results do not establish performance parity. Peak measured HTTP/1
allocations were 1.040 MB versus 1.073 MB at baseline, and HTTP/2 used
1.101 MB versus 0.984 MB. Allocation counts increased from 10.843 million
to 11.741 million for HTTP/1 and from 19.266 million to 22.654 million
for HTTP/2. The measurements do not attribute the remaining CPU cost to
individual components.
The unchanged HTTP/1 decoder benchmark, using 100 samples, measured
26.08 ms versus 25.50 ms at baseline.

The datagram model rerun generated 32,196 states and found 5,787 distinct
states, with no violation. Disabling whole-datagram preservation, which
allows an empty datagram to disappear, violated `SentInOrder` as expected.
The child readiness model passed with 71,116 generated and 10,066 distinct
states. Its mutations retained the expected counterexamples: completion
remains blocked without urgent delivery, cancelled work is polled without
work ownership, and retained jobs exceed their limit without the job bound.
