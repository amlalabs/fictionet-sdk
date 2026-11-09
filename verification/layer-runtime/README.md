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
# substring. Run one verifier at a time within the memory cap. The decoder
# failure property is partitioned exhaustively by its first action and,
# for input first, its second action.
cd ../../..
systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=10G -p MemorySwapMax=0 env CARGO_BUILD_JOBS=6 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_TARGET_DIR=/home/souvik/Projects/amlalabs/.fictionet-comp-work/target-reviewfix cargo kani -p fictionet --output-format terse -Z stubbing -j 1 --harness the_buffer_is_charged_before_bytes_are_taken \
  --harness every_charge_comes_back --harness units_come_up_in_order \
  --harness a_decoder_failure_comes_up_once_then_ended_first_ \
  --harness encoding_is_not_called_without_its_reservation \
  --harness a_decoded_allocation_keeps_its_charge_outside_the_layer \
  --harness a_reply_comes_only_for_a_request --harness a_header_of_mode_0_6_or_7 \
  --harness connections_are_counted_up_to_the_maximum
systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=10G -p MemorySwapMax=0 env CARGO_BUILD_JOBS=6 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_TARGET_DIR=/home/souvik/Projects/amlalabs/.fictionet-comp-work/target-reviewfix cargo kani -p nuclear-world --output-format terse -j 1 --harness each_request_gets_one_answer_in_order \
  --harness a_pipelined_request_waits -Z unstable-options \
  --cbmc-args --unwindset "$(cat verification/layer-runtime/kani/plant.unwindset)"
systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=10G -p MemorySwapMax=0 env CARGO_BUILD_JOBS=6 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_TARGET_DIR=/home/souvik/Projects/amlalabs/.fictionet-comp-work/target-reviewfix cargo kani -p web-world --output-format terse -Z stubbing -j 1 --harness the_time_server \
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

The datagram runner drops a receive whose backing reservation does not fit
and reports `DatagramReport::Dropped`, keeping the same application and socket
alive. `DatagramRunner` includes nondeterministic payload reservation refusal;
`InOrderOnce` excludes exactly those dropped inputs, and `ReturnHasReason`
requires an application end or socket close. The
`DatagramRunner_without_droponbudgetmiss.cfg` control ends on a reservation
miss and must violate `ReturnHasReason`. The Rust regression also checks that
an oversized backing is refused even when the payload is one byte, and that
later empty datagrams and another peer still reach the same conversation.

On November 9, 2026 the updated datagram model passed with 56,180 generated
and 9,828 distinct states. All eight negative controls failed as intended;
the budget-miss counterexample returns while its socket is open and its
application has not ended. The deadline and return-on-close controls still
end in their intended stalled timer and closed-socket traces.

`Framed` now encodes through `BoundedWriter`, a fixed slice with sticky overflow.
A codec that exceeds its declared bound receives a connection-local write error
without growing the destination. DNS and Modbus share their encoding routine
between ordinary and bounded writers. The Kani harness
`a_bounded_writer_refuses_every_encoding_past_its_capacity` explores arbitrary
four-byte inputs and every split against a three-byte destination. Existing
reservation and ownership harnesses use the bounded interface, and command
extraction runs through `Driver` to supply the layer's budget and reports.

The runtime job table reserves one initial slot and grows with retained work,
up to its unchanged engine limit. Each growth is charged before asking the
layer for another job. This lets small conversations run without reserving
an entire unused job table; a zero-byte budget still extracts no work. The
bounded-intake and exhausted-storage Rust tests cover this allocation policy;
the models abstract only job counts and cancellation.

The decoder-failure harness partitions its first action into input, end,
reset and take. The input-first case is further partitioned by its second
action, for seven cases in total. The original selector maps zero to input,
one to end, two to reset, and every other byte to the same take action.
The union therefore preserves the original state space. Each case still
executes three actions and three drains, with every assertion and the unwind
bound of seven unchanged. The third action is always unconstrained; the
second action is unconstrained in the end-, reset- and take-first cases.
Run the `a_decoder_failure_comes_up_once_then_ended_first_` filter with
`-j 1`, or each complete harness name separately.

The seven decoder-failure cases passed under the 10 GiB cap. The combined
harness had exceeded that cap with both MiniSat and CaDiCaL, and the
input-first case also exceeded it before the second-action partition.
The exact case results and unchanged coverage are recorded in
[VERIFICATION.md](VERIFICATION.md).

The November 9 time-server Kani rerun was stopped at the user's request after 26 of 27 harnesses passed; `the_time_server_answers_with_a_trailer_mode_1` had no result.

The November 9 PLC Kani rerun was stopped at the user's request during compilation, before any of its 18 harnesses produced a result.

The November 9 stream-runner TLC baseline completed with 185,569 distinct states and all ten negative controls produced their intended violations; the identical half-close configuration's properties are included in the baseline, so it was not run separately.

The final worker-storage backpressure change has targeted Rust coverage; no formal rerun followed it after the requested proof stop.

## The performance pass of November 9, 2026 (`comp/perf2`)

This pass started from the question why the composition allocated per
request at all, and went through the whole stack with profiles. It
compares three builds of the same benchmark code: `main` at e2858ccc4, the
demo fallback (tag `demo-fallback-20261109`) and `comp/perf2`.

### Method

Bench binaries were built the same way for every build: the bench profile
with frame pointers and line tables, in a target directory of their own.
Each bench process ran under `perf stat -e instructions:u`, so the count
covers the whole process, setup included; counts of the same build repeat
to within a fraction of a percent, so they are the primary measure. Times
are Divan medians and carry the noise of the other jobs on the
workstation. Allocations were counted exactly, not sampled: a preloaded
counter (`mallocsites.c`, kept with the pass's scripts) records every
`malloc`, `calloc` and `realloc` with a hash of its call stack, and a
script symbolizes the sites after the run. Profiles are `perf record -g`
with frame pointers, aggregated two ways: self time by module, and callers
of a leaf, so that a `memcpy` or a `Mutex::lock` is charged to the code
that asked for it.

The workloads are the existing benches: the HTTP bench (ten sandboxes,
each 10,000 requests after 100 of warmup, over TLS, HTTP/1 then HTTP/2,
with a 1 KiB body: 202,020 requests over the two runs), TCP bulk with one,
ten and a hundred connections, a transfer beside 99 idle connections, and
TCP round trips.

### Why there were allocations per request

`main` made 110 allocations per HTTP/1 request and 194 per HTTP/2
request. The sites, with what each turned out to be:

- Every TLS write zeroed a 16 KiB buffer, wrote one record or two into it
  and charged the whole 16 KiB; every decrypted record was copied out of
  rustls into a new vector. The layer now asks rustls how many bytes are
  queued (`CommonState::sendable_tls_len`, added to the fork), allocates
  that, and takes the vector rustls decrypted into
  (`Reader::take_first_chunk`, added to the fork). 808,221 buffers of
  16 KiB were no longer zeroed over the two HTTP runs, 13 GB of `memset`.
- A tower service's response body became a stream even when it was all
  there, so a finished body cost two more jobs after the handler's: one
  for its frame, one for its end, each a round through the stack, a job
  context (two allocations) and a boxing. A ready body is now taken when
  the handler's job finishes and goes out with the head: jobs per request
  three to one.
- Boxing a job for the type-erased stack allocated once for the box and
  once more for its result, and a boxed stack inside a boxed stack boxed
  the work again at each level. The box now carries its own result back,
  and a boxed job passes through an outer `Boxed` as it is.
- `Children` walked every child's stack for its depth on every call, and
  the driver did the same on every step, so the depth check scaled with
  the number of connections times the stack's height on every packet. The
  depth is checked where the composition grows (boxing, a later layer, a
  switch, a new child) and nowhere else.
- Every TCP receive zeroed its buffer before copying out of the socket;
  every engine step listed the open connections into a vector first;
  every HTTP/2 send listed the stream ids into a vector and every
  completion two more.
- The receive-window charge of a chunk was taken by allocating a new
  backing; the charge now lives in the backing and a whole, unshared chunk
  is recharged in place.

Those were the first seven commits of the pass (6fbf79cf5 to 018fb530c),
each checked alone. Together they took the HTTP bench from 50.28 G to
43.36 G instructions, the HTTP/1 run from 11.10 M to 6.56 M allocations
and the HTTP/2 run from 19.59 M to 12.01 M.

### Where the time goes after that

Self time in the HTTP bench, from the profile of the seven-commit build
(10,995 samples):

| Component | Share |
| --- | ---: |
| libc: the allocator and copies | 17% |
| `Mutex::lock` and `unlock` (uncontended) | 11% |
| the layer machinery (`Children::visit`, `Env::scoped_in`, `Chain`, the driver) | 10% |
| `Arc` counts and other atomics | 8% |
| B-tree lookups (connections, streams) | 3% |
| smoltcp | 3% |
| SipHash | 1% |
| AES-GCM | 1.5% |

The bench's client half (hyper, h2, the sandbox `TlsClient` over
`TcpConnection`) is about 45 percent of the inclusive time; the world's
packet driver and its connection stacks are about 50.

The mutexes are one lock per packet or per poll, spread over the sandbox
transports (`Ports`, the cable, the connection table in `Host`), the
timer wheel, the region's cancel registration and the run queue. None is
contended; the cost is the atomic read-modify-write on each side. The
cable is a single-producer, single-consumer queue per direction and could
be lock-free; `register_cancel` locks the region on every pending poll to
compare wakers. Neither was changed in this pass.

### Packet buffers: Linux's design and what pays here

Linux keeps a packet as an `sk_buff`: a small header struct from a slab
cache, pointing at a data buffer with headroom (headers are pushed in
front without a copy), a tail, and a shared-info block with fragments.
Receive pulls headers off by moving a pointer; clones share the data and
copy only the header struct; `truesize` charges the socket for the whole
allocation, not the bytes in use. BSD's `mbuf` chains fixed-size buffers
and `mbuf` clusters the same way. DPDK keeps `rte_mbuf`s in a per-core
mempool so the steady state allocates nothing.

The SDK already has the window part: a `Chunk` is a refcounted window
into one allocation, split and advanced without copying, and carries its
budget charge in the backing. What it lacked was the rest of the path. A
packet went `Vec` (the cable) to `Chunk` (the endpoint) to `Vec`
(reassembly) to `Chunk` (the IP layer's event) to `Vec` (smoltcp's
receive token) to the socket ring by copy; out again from the ring to a
zeroed `Vec` (the transmit token) to `Chunk` to `Vec` to the cable. That
is four wrappers and a zeroed buffer per packet, each a `malloc` and a
`free`.

The plan had five stages: a refcounted packet buffer with a recycling
pool charged by true size; segment chains in the TCP receive queue
instead of the copy into smoltcp's ring; TLS decrypting in place with
rustls's unbuffered API; parsing by spans over those buffers in HTTP/1,
HTTP/2 and the dissector; and, where simulation allows, handing buffers
between in-process stacks without serializing and skipping the checksum
between them. The profile set the ceiling before any of it was built. In
the HTTP bench, every copy and allocation on the packet path together is
about three percent of self time: the copy into the socket ring 1.0
percent, the endpoint's wrappers 0.9, the transmit buffers and their
zeroing 0.4, the copy out of the ring 0.2, the sandbox side's wrappers
and copies the rest. TCP bulk, which moves 1.5 KiB segments and little
else, has more of it. The rest of the time is control flow per layer,
locks and atomics, which no buffer design touches.

#### Skywalk against skb

Souvik asked how Apple's Skywalk compares. Skywalk (the user-space
networking in XNU: nexus, flowswitch, netif) does without most of what
makes skb cost: a channel gets an arena at creation, with a fixed pool of
packets, so there is no per-packet allocation and the arena's size is
the channel's memory bound; a packet is a metadata object plus a chain
of fixed-size buflets, the two in separate pools; a channel is a pair of
rings, and crossing a boundary moves a slot index with one owner and no
refcount; the flowswitch is one demux point that feeds per-flow channels
and sends flow advisories back for backpressure; and syncs are batched.

What the SDK already does the Skywalk way, and what it does not:

- Ownership. A packet crosses the cable as a `Vec` moved from one end to
  the other, and a `Chunk` moves through a `Chain` by value: one owner,
  no count touched. The `Arc` in a chunk is touched only when a chunk is
  split, cloned for an observer, or dropped. That is the slot model with
  Rust's ownership in place of the slot index; it is also why the
  remaining wrappers cost under one percent. Skywalk itself keeps a
  slot's ownership and its backing's lifetime apart, and its buffer
  controls count outstanding uses; `Chunk` makes the same split, the
  window owned and the backing counted.
- Arenas. Stage 1's kept buffers are a per-engine pool bounded by the
  egress allowance: the Skywalk shape, owned by the engine (sans-I/O, no
  global cache as skb's slabs are) and so deterministic and fine on
  wasm32. What Stage 1 did not do is make the budget the arena. The
  SDK's budget is shared: a parent's window is split among its children
  as they need it (`Charge::split`, `reserve_receive`), and a child that
  is quiet gives its pages back. A fixed arena per child would set each
  child's share at creation and lose that sharing; it fits a per-engine
  packet pool, which is what was built, and would fit the socket
  buffers (`Pages`) if their size were fixed per connection, which the
  window settings already make it.
- Buflet chains. Not adopted. The parsers want one contiguous buffer
  (Stage 4's spans are offsets into one allocation), and the copy chains
  would save is the copy into smoltcp's ring: one percent of the HTTP
  bench, more of bulk transfer. Chains in the TCP receive queue are the
  Stage 2 question above, with the same answer.
- Flowswitch and advisories. The packet driver hands each packet to
  smoltcp, which demuxes by four-tuple to a socket; each socket's bytes
  go to one child of `Children`, which keeps the children with
  something to do in intrusive ready and work lists and visits only
  those. Backpressure goes back as `Admit::Blocked` and as the window
  charge each child holds: the advisory, per flow, before the bytes move.
- Batching. The endpoint drains a turn's packets, output and work
  together, up to 64 turns a poll, before it yields.
- From skb, kept: pull. `CheckedIpPacket` keeps the header and its payload as a
  range into one chunk, and `Chunk::advance` moves the window without a
  copy. Headroom for pushing headers is not needed: smoltcp writes a
  packet's headers and payload into one buffer in one pass. Shared
  storage is for lifetimes that overlap. Today those are the passive
  observers (the dissector's copy, the normalized original an IPv6
  packet keeps), which clone a chunk. TCP transmission is the other
  one: a sender keeps unacknowledged bytes while packets carrying them
  are in flight, and today smoltcp's send ring keeps the bytes and each
  packet is written from it, a copy. Packets that reference retained
  ranges instead (Astra's stage 6 below) would make that a share, so
  "clones only for observers" holds for what is built, not as a rule.

So the blend chosen is Skywalk's ownership and per-engine pools, skb's
pull, shared storage where lifetimes overlap, and no chains. The
measured ceiling decides the rest: the packet path is three percent of
the HTTP bench, and the next step that pays is not a buffer design but
the locks and the layer machinery listed under what is left.

#### Astra's review, and what this pass takes from it

GPT-6 Astra reviewed the question against `main` (the note is in the
CRM, `ideas/astra-packet-buffers-20261109.md`). Its recommendation is
to extend `Chunk` rather than add a second buffer system: pooled
storage, move-only mutable blocks with headroom, frozen immutable
ranges shared on split or clone, a packet as metadata plus a small
inline run of fragments (normally one), stream queues apart from
packets, and three separate accounts, physical storage charged at full
capacity, retention quotas including descriptor counts, and protocol
credit, with capacity reserved for the control traffic (ACKs, window
updates, resets, alerts) that relieves pressure. Its migration order:
preserve contiguous ownership through the existing boundaries; split
the accounts; pool the common allocations; remove the TLS adapter copy
and add HTTP head spans; then TCP receive storage, TCP transmit
retention, in-place TLS last; checksums and simulated link behavior
never skipped between in-process stacks.

This pass is that order's first steps, measured. Contiguous ownership:
the IPv4 intake keeps its chunk (84a16d742); the TCP layer still takes
the chunk's vector for smoltcp's borrowed receive token, which costs the
wrapper's release and no copy. Pooling: the engine's packet buffers
(the same commit). The TLS adapter copy: gone (2eb943ec2). HTTP head
spans: below. The `reserve_receive` copy Astra points at is skipped
only when the chunk is the sole owner of its whole backing; the backing
then carries the window charge in place of its own, so the
receive-window guarantee it backs holds (f2aa5f35c). The accounting
split, the transport-storage rewrite and in-place TLS were not started:
each is a design of its own, and the profile puts their payoff in bulk
transfer, not in the request traffic the worlds serve. Checksums were
not skipped, as the Stage 5 paragraph says; a faster checksum fold in
the fork (32-bit words into a 64-bit accumulator) was tried and
reverted: TCP bulk 0.6 percent fewer instructions, the HTTP bench one
to two percent more in two runs each, under a loaded machine, with no
explanation worth keeping it for.

**Stage 1, done** (84a16d742). smoltcp's device keeps the buffer of each
packet it has read and writes the next packet it sends into it, so in a
steady exchange the buffers the peer's packets arrived in carry the
answers, and the engine allocates no packet buffers. It keeps at most
the egress allowance of buffers, none above 16 KiB, so the kept memory
is bounded by a constant per engine. A whole IPv4 packet goes up from
the IP layer in the chunk it came in, since reassembly would have handed
it back unchanged. The engine's own socket ids, which it hands out in
order, are hashed by one multiplication instead of SipHash; the maps
keyed by the peer's addresses keep the keyed hash on purpose. HTTP bench
43.36 G to 42.58 G instructions, TCP bulk 5.89 G to 5.71 G, round trips
0.692 G to 0.665 G, allocations over the two HTTP runs 19.15 M to
18.14 M. No Kani harness ran in this pass. The harnesses in
`verification/packet-udp` covered the former combined packet constructor
at the time of that pass; the later split into host and observed packet
types has not been verified by those harnesses; the IP layer's intake, which did, has none. The layer
models in `tla/` and `verification/layer` describe the driver, the
children and the stream runner, whose rules did not change: the depth
check moved to where the composition grows, chunks carry their charge
in the backing, and boxed work comes back in its own box, none of which
the models see.

What Stage 1 did not do: a core `Packet` type with headroom and a
refcount. `interface::Packet` is `pub struct Packet(pub Vec<u8>)`, built
in 72 places, and the core cannot see the stdlib's `Chunk`. The two
wrappers that remain per packet (one at the endpoint, one at the
transport layer's output) are that type boundary. Changing it is a
public API change for every program that sends raw packets; the gain
measured here is under one percent, so it was left for a release that
changes the interface anyway. True-size charging was not added: the
engine's kept buffers are bounded by count and size instead, and the
budgets charge bytes in use as before.

**Stages 2 and 3, not done.** smoltcp's socket buffer is a ring that the
whole TCP state machine indexes by sequence offset: retransmission, SACK
and the receive window all address bytes in it. Holding segment chains
instead means a different buffer abstraction through `socket/tcp.rs`,
and the copy it would save is one percent of the HTTP bench. TLS in
place is further off than the plan assumed: the vendored rustls's
unbuffered API does not hand plaintext back in the caller's record
buffer either. Its `ReadTraffic` keeps an owned `Vec<u8>` and
`next_record` pops owned plaintext from a queue
(`rustls/src/conn/unbuffered.rs`, `common_state.rs`), so switching APIs
removes no copy; in-place delivery is a deliberate change inside the
fork's connection machinery, which must keep authentication, record
limits, key updates and alerts as they are. What could be removed now
was the adapter's own copy of the plaintext out of rustls, and Stage 0
removed it (`Reader::take_first_chunk`). Both stages are worth returning
to for bulk transfer, not for request traffic.

**Stage 4, spans.** The HTTP/1 request head becomes one buffer with
spans (method, target and every field as offsets into it): see the
commit for the numbers. HTTP/2 header blocks are the biggest remaining
per-request family: `hpack::Block::keep` copies each decoded field, 909,000
times over the HTTP/2 run, 4.5 per request. The dissector's parsers were
not changed.

**Stage 5.** The cable already hands the sender's buffer to the receiver
without serializing; there is no wire copy. Skipping the checksum between
in-process stacks needs a flag on the packet saying a trusted stack
computed it and nothing has changed it since, as Linux's
`CHECKSUM_UNNECESSARY` does. The sandbox's raw interface can inject any
bytes, so the flag cannot be assumed; it has to travel with the packet,
which again needs a core packet type with metadata. Not done.

### What is left

- The per-request allocations that remain: HTTP/2 header fields
  (`Block::keep`, 4.5 per request) and response head encoding (a
  `Vec<hpack::Field>` and a copy of the block per response);
  `request_host`, which lowercases the authority into a new `String`;
  `http::Extensions` inserts in dispatch (two per request); `HeaderMap`
  growth in `to_request`; the two allocations of a job context per job;
  the two `Arc` wrappers per packet described above.
- The locks: a lock-free cable, and cancel registration that compares
  wakers without the region lock.
- B-tree lookups of connections by id on every packet; a slab indexed by
  id would be constant time but changes the order sockets are scanned in,
  which the engine relies on for determinism.
- The gap to the demo fallback. The fallback has no layer runtime: a
  connection is one future over a socket, with no `Children`, `Session`,
  boxed stacks, budgets or observers. Each of those is a guarantee the
  composition keeps (isolation, backpressure, cancellation, the swappable
  boundaries), and each costs a few hundred instructions per packet. The
  remaining gap is that cost. On the HTTP bench the pass closed about a
  third of it; the rest is the design.
