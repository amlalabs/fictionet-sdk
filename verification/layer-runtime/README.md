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
  --harness encoding_is_not_called_without_its_reservation \
  --harness a_decoded_allocation_keeps_its_charge_outside_the_layer \
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
completion predicate (`Session::is_terminal`, `session.rs:110-117`) is a
reset, or the output end with no unreported writes, no running work, no
command still held, and either the input end or the application's own
termination. The stream model's `shut`, `inputOver`, and `written` project
those conditions for a nonterminal application without jobs; `Session`
itself is not modeled. The full `Session` adapter and packet dispatch loop
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

The network and runtime benchmarks compare three builds of the same
benchmark code: the integration branch before world composition
(`comp/integ` at 3a9e9b99e), the demo fallback (tag
`demo-fallback-20261109`), and world composition after the changes below.
Each build ran three times, the builds interleaved, under the 10 GiB work
slice. `perf stat -e instructions:u` counted each bench process, setup
included; instruction counts repeat to within a fraction of a percent, so
they are the primary measure. Times are Divan medians of the three runs
and carry the noise of other jobs on the workstation. Bench binaries were
built with frame pointers and line tables, the same way for all builds.

| Workload | Demo fallback | Integration | World, first | World, now |
| --- | ---: | ---: | ---: | ---: |
| HTTP bench process, instructions | 27.56 G | 47.17 G | 80.10 G | 49.94 G |
| HTTP/1, 100,000 requests | 0.895 s | 1.301 s | 2.032 s | 1.337 s |
| HTTP/2, 100,000 requests | 1.394 s | 2.043 s | 3.373 s | 2.094 s |
| HTTP/1 allocations | 4.54 M | 10.84 M | 11.74 M | 11.10 M |
| HTTP/2 allocations | 7.11 M | 19.27 M | 22.65 M | 19.59 M |
| TCP bench process, instructions | 4.51 G | 5.72 G | 10.01 G | 5.83 G |
| TCP, one connection, 32 MiB | 23.73 ms | 28.38 ms | 35.63 ms | 31.09 ms |
| TCP, ten connections, 4 MiB each | 51.27 ms | 53.21 ms | 60.01 ms | 47.99 ms |
| TCP, one hundred connections, 1 MiB each | 166.8 ms | 269.1 ms | 388.4 ms | 212.1 ms |
| TCP round trips, instructions | 0.428 G | 0.616 G | 0.834 G | 0.698 G |
| TCP round trips | 23.04 ms | 35.09 ms | 51.77 ms | 38.46 ms |
| Transfer with 99 idle connections, instructions | 2.21 G | 2.63 G | 2.78 G | 2.67 G |

"World, first" is `comp/p3-world` at a2ec922a8, measured once the same way.
Profiles (`perf record --call-graph fp`) attributed its extra cost to these
causes, each removed in the design:

- `Children` advanced every child on every pass and read every child's
  deadline and depth through its whole stack on every driver step, so one
  packet for one connection stepped every connection. It now keeps its
  children in a slab, links ready children and children with work into
  intrusive lists, and keeps deadlines in an indexed heap. This took the
  HTTP bench from 80.1 G to 63.4 G instructions.
- The packet driver let one packet of a transport walk through the IP layer
  per turn, so the TCP engine was stepped for every packet or two, each
  step visiting every connection; it walked the transports again with
  nothing new; and it re-stepped a saturated engine before writers refilled
  it, which sent buffer tails as extra short segments (fifteen percent more
  data packets with a hundred connections). It now drains a walk's output
  in the same turn, walks only when something is new, and lets a saturated
  engine continue after the run's other tasks, as before composition.
- Application work was polled once after the router's turns, so a response
  body finished one walk late and went out as a second TCP segment: one
  more packet per HTTP/1 request. Work is now polled within the turns.
- Smaller costs: full fences in child visits, polling an empty router,
  self-wakes for the task's own commands, and reading the clock per packet.

The remaining gap to the integration branch, about six percent for HTTP
and thirteen for round trips, lies in the composition's own layers: the IP
layer and TCP behind their factories, `Session` and two levels of boxed
stacks per connection, and boxed work and results, about three more
allocations per request. The demo fallback predates the layer runtime and
is faster on every row.

The datagram model rerun generated 32,196 states and found 5,787 distinct
states, with no violation. Disabling whole-datagram preservation, which
allows an empty datagram to disappear, violated `SentInOrder` as expected.
The child readiness model passed with 71,116 generated and 10,066 distinct
states. Its mutations retained the expected counterexamples: completion
remains blocked without urgent delivery, cancelled work is polled without
work ownership, and retained jobs exceed their limit without the job bound.
