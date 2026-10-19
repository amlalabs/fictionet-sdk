# Fictionet Observe

`fictionet-observe` collects a run's events, topology, packet copies and TLS
keys. The base crate is sans-I/O.
It starts no threads, opens no files or sockets, and reads no clocks.

There are no default features. `decode` reserves packet decoding and
presenters. `native` enables `decode` and adds the `Jsonl` worker.
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
copies for links whose policy does not retain them. Removed links release
capture state. Topology snapshots contain current entities and a revision;
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
