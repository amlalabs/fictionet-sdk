# Fictionet Observe

`fictionet-observe` consumes the four streams produced by
[`fictionet::events`](../src/events.rs):
events, tapped packets, TLS keys and topology. A `Policy` selects observations
before work and sorts them into classes with independent budgets. Typed stores
share ring retention and one loss ledger. The world's page and
`fictionet observe` read those stores; JSONL and pcapng exports use one selection
without requiring a packet watch. Core retains no history. Install the observer
before the run starts.

There are no default features.

| Feature | Contents |
|---|---|
| Base | `Memory`, `Aggregate`, `Collector`, bounded topology, packet copies, TLS keys and loss totals. Sans-I/O: no threads, files, sockets or clock reads. |
| `decode` | Packet decoders, protocol presenters, pcapng output, `DashboardObserver` and transport-independent request sessions. |
| `native` | Enables `decode`. Adds `Jsonl` workers on native targets and `serve`, `Endpoint` and `Client` on Unix. |
| `page` | Enables `native`. Adds `page`: a loopback web page served from a `DashboardHandle` in the same process, with world state topics, typed command ports and ticketed screen and terminal consoles. It uses Tokio. |
| `tracing` | `Tracing`, with a dispatch supplied by the integrator. It installs no global dispatcher. |

## Retain events for grading

Install `Memory` through `RunOptions`. Wrap it in `Aggregate` to combine
repeated network facts. `checked_of` checks losses for the exact event kind, including unknown kinds.
`Limits` sets standalone event budgets.

```rust
use std::sync::Arc;
use fictionet::{RunOptions, Seed, block_on, lab};
use fictionet_observe::{Aggregate, Memory};

let grader = Arc::new(Memory::default());
let options = RunOptions::new(Seed::from_u64(7))
    .observer(Arc::new(Aggregate::new(grader.clone())));
block_on(lab(options, |fcx| async move {
    fcx.emit("shop", "order", |event| event.field("item", "tea"));
    Ok(())
}))?;
assert_eq!(grader.checked_of("shop", "order")?.len(), 1);
# Ok::<(), fictionet::Error>(())
```

## Use a dashboard handle in process

With `decode`, install a `DashboardObserver` beside your own observers with
`fictionet::events::Fanout`. Its handle serves the same requests in process
as the external commands. A session's caller supplies time and polls streams.

```rust
# #[cfg(feature = "decode")] {
use std::sync::Arc;
use fictionet::{RunOptions, Seed, block_on, lab};
use fictionet::events::Fanout;
use fictionet_observe::{DashboardObserver, DashboardOptions, Memory};

let dashboard = DashboardObserver::new(DashboardOptions {
    collector: fictionet_observe::Options::default(),
    ..Default::default()
});
let grader = Arc::new(Memory::default());
let options = RunOptions::new(Seed::from_u64(7)).observer(Arc::new(
    Fanout::new(vec![dashboard.observer(), grader.clone()]),
));
block_on(lab(options, |_fcx| async { Ok(()) }))?;

let mut session = dashboard.handle().session();
let replies = session.request(1, r#"{"op":"world"}"#, std::time::Instant::now(), None);
assert!(replies[0].end);
# }
# Ok::<(), fictionet::Error>(())
```

## Serve a page

The `page` feature serves a loopback page directly from the run's
`DashboardHandle`. Compose hosts and standard panels with `Page`, add tables
over `StateTopic` values, and connect typed controls with `CommandPort`.
Events and packets share a bounded list and loss-line component. Export buttons
use the selected host or links. Services name protocols on connections;
`Page::protocols` installs their presenters before the first watch. Unclaimed
flows still use port and prefix matching.
Screen and terminal consoles share the page's bearer and single-use ticket
boundary; browser screen input also needs a host lease. The browser
libraries pinned in `libraries.json` are embedded from `downloads/vendor`.

The [builder example in `fictionet_observe::page`](src/page/mod.rs) is compiled
by `cargo test --doc --all-features`. It shows hosts, state, tables, event
filters, custom panels and typed controls. The default crate remains sans-I/O;
only `native` and `page` add native I/O.

## Serve an external world

With `native` on Unix, serve the handle on its own private socket.
`serve_observation` installs a `DashboardObserver` served at an optional
path, beside the world's own observer if it has one, behind one `Aggregate`.
Keep the returned endpoint alive alongside the run. This needs the
`fictionet` crate's `std` feature, for `listen` and `run`. World code supplies
the network and services.

```rust,no_run
# #[cfg(all(feature = "native", unix))] {
use fictionet::{RunOptions, Seed};
use fictionet_observe::serve_observation;

let (options, _endpoint) = serve_observation(
    RunOptions::new(Seed::random()),
    Some("/run/fictionet/observe.sock".into()),
    None,
)?;
let (_listener, mut attachments) = fictionet::Listening::bind(
    fictionet::WorldSocket::UnixSocket("/run/fictionet/world.sock".into()),
)?;
fictionet::block_on(fictionet::run(options, move |fcx| async move {
    let _agent = attachments.get(&fcx, "agent").await?;
    // Build the world's network and services here.
    fcx.cancelled().await;
    Ok(())
}))?;
# }
# Ok::<(), fictionet::Error>(())
```

Then read it from a shell:

```sh
fictionet observe --observation unix:/run/fictionet/observe.sock
```

The sections below, in the crate documentation, cover the dashboard
walkthrough, shell commands, drawing, groups, hosts, events, packets,
decoding, user protocols, access rules, costs, resource limits and observation
protocol reference. On GitHub, read them in `src/lib.rs`.
To open the rendered docs locally, run
`cargo doc --open -p fictionet-observe --all-features`.
