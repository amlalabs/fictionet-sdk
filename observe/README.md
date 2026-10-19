# Fictionet Observe

`fictionet-observe` collects a run's events, topology, packet copies and TLS
keys. The base crate is sans-I/O.
It starts no threads, opens no files or sockets, and reads no clocks.

There are no default features. `decode` adds packet decoding and
presentation, pcapng output, and the dashboard observer with its
transport-independent request sessions. `native` enables `decode` and adds
the Unix observation endpoint, client and `Jsonl` worker.
`tracing` adds `Tracing`, which uses a dispatch supplied by the integrator.
It never installs a global dispatcher.

Install one `Collector` per run. Use `Fanout` to combine it with your own
observers:

```rust
use std::sync::Arc;
use fictionet::{RunOptions, Seed};
use fictionet::events::{Fanout, Memory};
use fictionet_observe::{Collector, Options};

let collector = Arc::new(Collector::new(Options::default()));
let grader = Arc::new(Memory::default());
let options = RunOptions::new(Seed::from_u64(7)).observer(Arc::new(
    Fanout::new(vec![collector.clone(), grader]),
));
```

`Options` bounds events, topology, packet copies, TLS keys and loss detail.
The defaults capture sandbox links from startup and other links on demand.
Hold a `capture_demand` handle to capture a demand link. Dropping the last
handle stops new copies. Sampling uses run time: keep the first 64 packets
per 100 ms, then thin exponentially. A copy keeps its original stream stamp,
original length, and the number sampled out before it. Its separate copy
cursor makes evictions distinguishable from sampling gaps.

Topology can arrive after packets produced in a task poll. If either startup
policy is enabled, the collector provisionally captures unknown links within
the same limits. Link registration applies the policy and discards provisional
copies for links whose policy does not retain them. Removed links retain
captures within the same limits. Budget pressure evicts removed captures first,
in removal order. Topology snapshots contain current entities and a revision;
compare snapshots to compute changes. Counter handles read live totals.

Loss totals persist by stream and cause. When the configured stream detail
budget fills, further losses are counted by cause in `LossStatus::untracked`.
They cannot be attributed to individual streams. Topology refusal and missing
references also mark snapshots incomplete. Byte budgets charge retained data;
packet payload budgets exclude fixed copy metadata, which is count bounded.
Snapshots and copies held by readers are outside retention budgets.

Retained keys can be rendered as SSLKEYLOGFILE text. Key debug output hides
secrets. `Jsonl::finish` must run outside observer callbacks to drain its
worker and report incomplete output or writer errors. The collector uses
`fictionet::events::Memory` for events.

`DashboardObserver` owns one collector and serves one run. Its default captures
all links on demand and retains TLS keys from startup. `DashboardOptions::demo()`
captures sandbox links from startup too. Set bounds through
`DashboardOptions::collector` before constructing the observer.

```rust
# #[cfg(feature = "decode")] {
use fictionet_observe::{DashboardObserver, DashboardOptions};
use fictionet::{RunOptions, Seed, block_on, lab};

let dashboard = DashboardObserver::new(DashboardOptions::demo());
let handle = dashboard.handle();
block_on(lab(
    RunOptions::new(Seed::from_u64(7)).observer(dashboard.observer()),
    |_cx| async { Ok(()) },
))?;
dashboard.finish();

let mut caller = handle.session();
let now = std::time::Instant::now();
let replies = caller.request(1, r#"{"op":"world"}"#, now, None);
assert!(replies[0].end);
# }
# Ok::<(), fictionet::Error>(())
```

A session accepts flat JSON requests with caller-assigned ids. `world`, `graph`,
`counters`, `events`, `link`, `packet` and `keylog` return whole values; keylog
is binary SSLKEYLOGFILE text. `watch` creates a subscription: call `poll` at
`next_poll` to receive its snapshot, changes, events and final `end`.
`packets` (`link`, `after`) subscribes to one link's decoded packets: it sends
`link`, then `packet` rows and `packet_gap` events, then `end` once the link
is gone or the run has ended and every captured row was sent. `packet`
(`link`, `seq`) returns one row's layers and bytes. `pcap` (`link`) returns a
pcapng file of the link's kept rows with the TLS keys of the watch and the
collector. It is written as it is read, in several binary values; the last has
`end`. `cancel` names a subscription's request id. Each caller may hold at
most 64 subscriptions and downloads.
The caller supplies monotonic time for scheduling and optional wall time since
the Unix epoch for real-run elapsed time. Lab time always comes from observations.
Neither the handle nor the collector reads clocks. Snapshot `revision`, `hosts`
and `status` extend the dashboard JSON; status includes topology completeness
and persistent losses by stream and reason.

Each watched link decodes its captured copies in order with
`DashboardOptions::protocols`, by default the built-in `Registry`. Decoding
happens when a session polls or asks, on the caller's thread, never in an
observer callback. A `packets` subscriber holds the link's capture demand, so
on-demand links capture only while someone watches; startup links keep
capturing. A capture gap from sampling or eviction resets the link's
connections, so no decoder joins bytes across it. TLS 1.3 is decrypted with
the collector's keys and a per-watch key cache bounded like the collector's.

Each watch keeps at most 4,096 rows and 32 MiB. `DashboardOptions::watch_bytes`
bounds rows across all watches, 256 MiB by default: past it, idle watches are
forgotten first, longest idle first, then the oldest rows of any watch.
Subscribers behind the kept rows get a `packet_gap` with the count missed.
`DashboardOptions::watches` bounds watched links, 64 by default. At capacity a
new link evicts the longest-idle watch, with the lowest link id breaking ties;
when every watch has a subscriber, `packets` replies
`{"error":"this world has too many watched links"}`. A watch keeps its rows
for a minute after its last subscriber leaves, by the times callers supply.
`packet` and `pcap` on a link with no kept watch reply
`{"error":"nothing is watching that link"}`. Captures of removed links can
still be watched while the collector keeps them.

On Unix, `serve(handle, path)` creates a private socket for external clients.
Keep the returned `Endpoint` alive; dropping it disconnects sessions, joins
threads and removes its socket. `Endpoint::set_session_limit` adjusts the default
64-session admission limit. `Client::connect(path)` requires protocol
`fictionet-observe`, API version 2, with no attach fallback. `Client::request`
returns an id; `next_value` joins reply chunks and preserves their original bytes.
`Value::envelope` inspects JSON events and errors without rewriting them.

Messages use a four-byte big-endian length prefix, with a maximum body of
65,536 bytes. Body tags are hello (1), accept (2), refuse (3), request (4) and
reply (5). Hello carries a big-endian version followed by the UTF-8 protocol
name. Refuse carries its UTF-8 reason. Requests carry a big-endian request id
and JSON bytes; replies carry an id, one flag byte, then payload bytes. Reply
flags are `MORE` (1), `END` (2) and `BINARY` (4). Only the final chunk may carry
`END`. Sends and server handshakes time out after ten seconds. The client's
hello allows eleven seconds; accepted clients wait for replies until their
optional read timeout expires.
