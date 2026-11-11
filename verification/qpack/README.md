# QPACK synchronization and storage

The models in `tla/` describe the dynamic QPACK encoder in
`src/stdlib/protocols/qpack.rs` and the storage obligations of its HTTP/3
caller. Run all configurations with:

```sh
systemd-run --user --scope -q --slice=fictionet-work.slice \
  -p MemoryMax=8G -p MemorySwapMax=0 \
  env TLA2TOOLS=/path/to/tla2tools.jar JAVA=/path/to/java \
  cargo xtask qpack-verify models
```

`resources` is an alias for this model suite. `replay` runs the allocator
and compression replay in `tests/qpack_dynamic.rs`; `all` runs both. These
commands do not run Kani. Each TLC process runs under the existing
verification helper's 6 GiB scope. Logs and state directories go in a fresh
`target/qpack-verify/run-*/` directory, respecting `CARGO_TARGET_DIR`.

Every base configuration must complete without an error. Each negative
control disables one guard and must violate the specific invariant named
in its first line. A parser error, timeout, or different failure is not a
successful negative control.

`QpackSync` explores four insertions, a two-entry table, two request
streams, and up to three outstanding field sections. It checks that the
encoder references only acknowledged entries, retains both unacknowledged
inserts and outstanding references, bounds insert-count increments,
acknowledges sections in stream order, and does not advance the known
received count on cancellation. Its oldest reference stands for the
minimum of all references in one section, as `Outstanding::oldest` does.
The model assumes valid decoded instructions; malformed wire encodings,
integer overflow, and string compression belong to the codec tests.

`QpackFeedback` checks the decoder's reported-count bookkeeping separately.
An acknowledgment advances `Table::reported` when the section is decoded,
before the peer receives it. Applying the pending feedback in order must
bring the encoder's count to exactly that reported count. Negative controls
drop an acknowledgment on cancellation, reverse feedback order, or allow
unbounded admission to the pending queue. The model bounds that queue at
two values; the server enforces its own bounded pending and sending owners.

`QpackStorage` follows retained section descriptors, encoded bodies, a
temporary source body overlapping its owned copy, and feedback values. It
threads each allocation and release through the shared `Resources` model,
which records transient shortfalls inside an atomic step. Its limits are
three section slots, four body units, two distinct blocked streams, and
two output units. This describes the generic bounded blocked-section
store; the server's one blocked section per request stream is stricter.
Scratch reserves the source and copy before decoding. The retained-body
charge must be acquired before scratch is released. Cancellation frees body
storage while descriptor capacity remains charged.

`QpackTable` models wire entry overhead separately from allocated slots
and payloads. The table has five wire units; slot storage grows through
two, four and eight units. Growth reserves the new allocation while the
old allocation is still held. Eviction frees payloads while retaining the
slot charge. Controls omit growth or payload charges, release slot charges
on eviction, or insert before obtaining wire capacity. The synchronization
model separately establishes which entries may be evicted.

These are exhaustive checks of finite models, not proofs that arbitrary
Rust executions refine them. They do not model QUIC scheduling, Huffman
allocation, byte-accurate `VecDeque` layouts, header semantics, or liveness.
Production `held` and `most_held` bounds, allocator replays, malformed-wire
tests and HTTP/3 interoperability are complementary evidence. In particular,
wire table size includes 32 bytes per entry but is not an allocation bound.

Evidence from 11 November 2026: all four base models passed and all twenty
negative controls violated their named invariants. The bases explored 320
states for synchronization, 3328 for storage, 109 for table allocation, and
130 for feedback. The allocator replay passed seven tests, costing 1134
decoder steps and 1028 encoder/reference steps. Those steps include a
capacity fall that retains slots and the encoder's literal fallback when
1024 sections await acknowledgment. This is finite model and concrete
allocator evidence; no Kani result is claimed.

The independent suites passed 45 quiche tests and 14 ngtcp2 tests. Quiche
0.30.1 has a static-only HTTP/3 QPACK codec, so its dynamic cases use raw
RFC sections over its QUIC transport. Nghttp3 1.18.0 over ngtcp2 1.25.0
generated dynamic requests and decoded dynamic responses: nineteen of
twenty sections in each direction. The twenty browser requests used 1940
QPACK bytes including insertions and feedback, versus 3820 with the SDK's
static encoder. The synthetic response replay used 1451 versus 4540 bytes.
These measurements exclude HTTP/3 envelopes and transport overhead.

Interop exposed and now tests coalesced stream input: a QUIC delivery can
include a stream-type prefix and more data than the prefix decoder's
sixteen-byte input limit. The HTTP/3 connection retains the charged
remainder through partial admission, decodes, then admits the rest. A
separate connection unit test covers coalesced control and both QPACK
instruction streams.

The SDK's `qpack` unit-test filter passed 33 tests and `http3` passed 68;
the filters overlap. Clippy with warnings denied passed for the SDK,
xtask, and both interoperability crates including their tests.
