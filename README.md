# Fictionet

Fictionet is a simulated internet for AI agent evals and reinforcement learning.
The agent uses its own tools (`curl`, `dig`, `traceroute`, a browser, a Python
script) against real servers at the names and addresses it expects. All of them
run inside a *world*: a Rust program you write, which decides what every name
resolves to, which sites exist, what they serve, and how packets are routed,
delayed and dropped.

When the harness makes the world the sandbox's only network path, the world sees
every DNS query, TLS handshake and HTTP request the agent makes. It can log each
one in its own process, outside the sandbox. The harness must keep the world's
socket, files and processes out of the agent's reach so it cannot read or change
the log. Fictionet supplies the network; the harness supplies the rest of the
sandbox and prevents the agent from changing or escaping that boundary. Within
that boundary, a name or address the world does not serve fails, as it would on a
network cut off from the internet. The world can still forward a site to a real
server on purpose. See [the security model](SECURITY.md).

## Who it is for

Fictionet is for people who build evals and RL environments for agents that use
the network. The demos in this repository show three such worlds:

* [Artifactory](demos/artifactory): a company package mirror with no upstream.
  When a package is missing, does the agent fall back to public PyPI, ask the
  mirror to fetch from upstream, install a typosquat, or answer a message left
  in the cache?
* [Search](demos/search): any public host name, any URL, any search. Pages and
  results are made from a short seed the first time the agent asks, then kept,
  so the same URL always returns the same page.
* [Nuclear](demos/nuclear): a simulated two-loop pressurized water reactor,
  whose controllers and operator screen the agent reaches over Modbus.

A world can give each run the same sites, with no live pages that change and no
real accounts. Keeping the agent inside it depends on the harness's sandbox boundary.
The sandbox can be a network namespace, a Docker Compose service, a Kubernetes
pod, a hosted sandbox or a VM. An
[Inspect](https://inspect.aisi.org.uk/) eval can use a world as its sandbox with
one call.

## How it works

The world runs as its own process and listens on a Unix socket. `fictionet attach`
runs next to the sandbox and relays the sandbox's IP packets to the world. With
`attach tun`, attach puts a `tun` device in the sandbox's network namespace and
routes the sandbox's traffic through it. In a namespace with no other way out, such
as a new one from `ip netns add`, every packet the sandbox sends off the machine
ends up in world code. The sandbox needs no proxy settings and no special software.
Where a sandbox can't have a `tun` device, attach serves it as an HTTP or SOCKS5
proxy instead.

<p align="center">
  <img src="docs/diagrams/attach.svg" width="580" alt="The agent's programs send IP packets through a TUN device in the sandbox's network namespace. fictionet attach holds the device and relays each packet over a Unix socket to the world process, where it arrives as an Attachment, an interface the world reads and writes.">
</p>

The standard library covers IPv4 and IPv6, TCP, UDP, ICMP, routing, whole
networks of websites with `stdlib::web`, and codecs (no I/O) for about a hundred
protocols and data formats, listed in [the stdlib docs](src/stdlib/mod.rs).
HTTP has a ready server, `Net` serves DNS and DHCP, and TLS is built in.
For other protocols, a world writes a `Service` around the module's decoder.
The crate is not on crates.io, so build it from this repository.

A run supplies the world's clock and seeded randomness. With real sandboxes
it uses real time. Tests can use simulated time. The same seed and ordered
inputs, interests and limits in a lab give the same observations and stamps.
External I/O and opt-in axum upgrades have separate timing limits; see
[Repeatable runs](src/guide/running.rs).

## Install

Add `fictionet` to your Cargo dependencies. It always uses Rust's standard
library and builds without tokio. Enable `tokio` for the tokio adapters
(`into_tokio`) and axum WebSocket upgrades. Enable `web-proxy` and inject a
transport from `fictionet-host` for upstream HTTP requests over host sockets.
Host I/O works in real and simulated clock modes; repeatable tests control
external inputs themselves. See the [feature table](src/lib.rs).

The `fictionet` command is the `fictionet-cli` package in `cli/`. Install it
from a checkout with `cargo install --locked --path cli`.

## Quick start

Follow [Getting started](src/guide/getting_started.rs) for the full Linux namespace
walkthrough: build the `web_fixture` example, attach a namespace, make HTTPS requests, watch
the world's events, and clean up. It includes expected output and troubleshooting.
You need Linux, Rust 1.99 or later, `sudo`, iproute2 and `curl`.

This is a **trusted connectivity demonstration**. A network namespace isolates
networking only. The tutorial's root commands share the host's filesystem,
users and processes, and root can leave the namespace. Do not use it as a
sandbox for an untrusted agent.

## A world in a few lines

`stdlib::web::Sites` builds a whole network of websites from one callback: DNS,
addresses, a router, one machine per address, TLS and HTTP. Each site is a
[tower](https://docs.rs/tower) service, such as an axum `Router`.

```rust
use std::{net::Ipv4Addr, sync::Arc};
use fictionet::{Attachments, Cx, Result, stdlib::web};
use rustls::ServerConfig;

fn world(
    fcx: Cx,
    attachments: Attachments,
    wiki: axum::Router,
    fake_stripe: axum::Router,
    wikipedia_tls: Arc<ServerConfig>,
    stripe_tls: Arc<ServerConfig>,
) -> Result {
    web::Sites::new(move |host: &str| match host {
        "en.wikipedia.org" => Some(
            web::Site::new(wiki.clone())
                .at(Ipv4Addr::new(185, 15, 59, 224))
                .tls(wikipedia_tls.clone()),
        ),
        "api.stripe.com" => Some(
            web::Site::new(fake_stripe.clone())
                .tls(stripe_tls.clone()),
        ),
        _ => None, // NXDOMAIN: the world stays closed
    })
    .start(&fcx, attachments)
}
```

A longer version, which the docs compile as a test, is at the top of
[`stdlib::web`](src/stdlib/web/mod.rs), and
[`extras/src/web_world.rs`](extras/src/web_world.rs) is a complete world.

Underneath, a world is a set of tasks joined by packet interfaces: a delay, a
bottleneck, a router, a TCP endpoint. The crate docs show each layer.

## Hosts, services and protocols

| Optional crate | Components |
|---|---|
| [`fictionet-extras`](extras/src/lib.rs) | Search engine results and reusable site skins with local stylesheets and assets. |

`stdlib::world::net` builds a network of hosts, each with addresses, DNS names and
services on its ports. A service is the server side of one protocol for one
connection, written with no I/O: it gets decoded items and appends reply bytes,
and one driver runs it over any connection. HTTP is a service
(`stdlib::web::httpd`), and `web::Sites` is a preset on `Net` for websites. Every
service emits structured events. Core produces four streams through
[`fictionet::events`](src/events.rs): events, packets, TLS keys and topology.
The integrator installs one observer through `RunOptions` before the run.
`Fanout` combines observers. With no observer, core skips observation work.

The companion crate owns consumption and retention: `Memory` for grading,
`Aggregate` to combine repeats, `Jsonl` for files, and `DashboardObserver` for
watching a world. Graders check that retained events are complete. See
[Fictionet Observe](observe/README.md) for watching a running world, setup and
limits, and [services](docs/services.md) for a small world.

Protocol codecs also work in unit tests and fuzz targets. The companion's
`decode` feature supplies presenters that use those codecs for captured traffic.
The [stdlib docs](src/stdlib/mod.rs) list the modules and describe their uses.
To change a protocol, see
[the stdlib docs, section Changing a protocol by copying it](src/stdlib/mod.rs).
To show a protocol of your own in the dashboard, see
[adding an observe protocol](docs/observe-protocols.md).

## Where sandboxes can run

| Where the sandbox runs | How it attaches |
|---|---|
| A network namespace on the host (`ip netns`), as in [Getting started](src/guide/getting_started.rs) | `tun` |
| Docker Compose: the agent shares the network namespace of an `attach` container | `tun` |
| Kubernetes: `world` and `attach` as native sidecars, from the Helm chart in [`charts/fictionet-sandbox`](charts/fictionet-sandbox), which the k8s sandbox of [Inspect](https://inspect.aisi.org.uk/), a framework for running AI evals, accepts | `tun`, under runc and gVisor |
| Daytona and E2B: the Compose setup inside one hosted sandbox | `tun` |
| A sandbox with no privileges and no `tun`, where the platform blocks all other egress, including a pod under Pod Security "restricted" | `http_proxy` or `socks5` |
| A virtual machine: QEMU over its stream socket, with no root; Firecracker, Cloud Hypervisor or QEMU on a TAP device | `tap` |

Attach takes each sandbox's addresses as flags, and hands a VM its addresses by DHCP.
Remote sandboxes, DHCP in attach for `tun`, Python worlds and more are on the
[roadmap](src/guide/roadmap.rs).

## From an Inspect eval

[`python/inspect_fictionet`](python/inspect_fictionet) gives an Inspect task a
Fictionet world as its sandbox in one call, on Docker or Kubernetes:

```sh
pip install "git+https://github.com/amlalabs/fictionet-sdk#subdirectory=python/inspect_fictionet"
```

## Documentation

The crate docs are the guide. Build them with:

```console
$ cargo doc --no-deps -p fictionet -p fictionet-observe --all-features --open
```

Start at the crate root, which explains the main ideas, then read in this order:

1. [`getting_started`](src/guide/getting_started.rs): from `cargo build` to an HTTPS
   request from a sandbox.
2. [`running`](src/guide/running.rs): the program around a world, how it starts and
   stops, and worlds in tests.
3. [`lowering`](src/guide/lowering.rs): how each attach type turns what its sandbox
   sends into IP packets.
4. [`stdlib`](src/stdlib/mod.rs): the pieces a world is built from, and the
   protocol modules. Then [`stdlib::world::net`](src/stdlib/world/net.rs) and
   [`stdlib::services::serve`](src/stdlib/services/serve.rs) for a network of hosts and
   services, and [`stdlib::web`](src/stdlib/web/mod.rs) for a network of
   websites.
5. [Fictionet Observe](observe/README.md): collection, grading, files, and watching
   a world from its page or a shell. [Events](src/events.rs) covers production.
6. [`proto`](src/guide/proto.rs): the relay protocol between attach and a world, for
   writing an attach of your own.
7. [`roadmap`](src/guide/roadmap.rs): what is planned.

## Building and testing

[CONTRIBUTING.md](CONTRIBUTING.md) has the commands to build, test and
benchmark in each feature set.

## License

Licensed under either of

* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual
licensed as above, without any additional terms or conditions.
