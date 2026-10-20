# Demos

Every demo is one command:

```console
$ cargo xtask demo <name>
```

`cargo xtask demo` lists in-process binaries and the scripts in `demos/guest/`.
`cargo xtask demo assets` downloads the pinned Ubuntu image, kernel, initrd,
and Cloud Hypervisor into `downloads/cloudimage/`, plus the browser libraries,
without booting. `cargo xtask demo libraries` downloads only the pinned browser
libraries into `observe/downloads/vendor/` at the repository root.

## Desktop

`cargo xtask demo desktop` downloads about 650 MB of pinned files on its first
run, builds the `desktop` binary in release mode and runs it on your machine.
It needs KVM, with no QEMU, Docker or root. The world runs in the same process.
The guest is Ubuntu's official 24.04 cloud image, never modified: each run
writes its own qcow2 overlay and cloud-init seed. Cloud Hypervisor runs from
a copy embedded in the binary.

At boot the guest installs Xfce, Mozilla's Firefox, Xvnc and two pinned coding
agents, Claude Code and Codex, through the world's mirror. The printed page
URL opens the live desktop and terminal over SSH, alongside packets, events,
the map, left the box, containment checks, labels and exports. The Coding
agents table stays empty until the gate runs both version commands, then
shows the version each command printed and `installed`. No model API is
forwarded, and the page does not claim the agents performed a task.

The first run also fetches about 280 MB of Ubuntu packages through the
world's mirror, which keeps them in `downloads/cloudimage/apt-cache/` for
later runs. On a 24-core machine, with the pinned files downloaded and the
binary built, a run with an empty package cache took 88 s from start to power
off, with the desktop up after 73 s. A later run took 74 s, with the desktop up
after 59 s.

The gate checks the guest, trust store, browser, agent installations and page
access controls. It tests terminal command output and pointer input with and
without the screen lease, powers the guest off, and checks that no Cloud
Hypervisor process or run directory is left. Success ends with `every required
check passed`. The Chromium page screenshot is reported but is not required;
the guest and page screen captures are required.

The binary takes the downloads directory and, optionally, a Unix socket path.
With the path, `fictionet observe --observation unix:PATH watch` follows the
same dashboard as the page from another terminal.

## The page

`Kit::page` takes a builder over the dashboard and declared hosts:
`Page::new("Desktop", dashboard).host(hosts.take("workstation")).standard_panels()`.
The kit installs one dashboard observer with startup packet capture, host
status, containment probes and labels. The standard panels provide the
screen, terminal, packets, events, map, left the box, containment, labels and
export; `Page::table` adds a view over a world-owned `StateTopic`.

The page binds to loopback and requires its per-run bearer token for data and
commands, with exact Host and Origin checks.
Consoles use short-lived, single-use WebSocket tickets obtained through the
authenticated API, and screen input requires the host's input lease.
Taking control claims browser input only; it does not pause an agent.

Pinned noVNC and xterm.js files are embedded from `observe/downloads/vendor/`.
Desktop screenshots go to `demos/downloads/cloudimage/shots/`:
`guest-desktop.png` from the guest, `viewer-desktop.png` through the page's
screen socket without taking input, and `page-desktop.png` from Chromium after
the desktop paints.

## FakeWiki

`cargo xtask demo fakewiki` runs an in-process [FakeWiki](../examples/fakewiki)
world and an Ubuntu 24.04 desktop on the shared microVM kit. A scripted Firefox
reader loads the Wikipedia article, then reloads after the page turns tampering
on. The gate checks both reads and saves guest and page screenshots before
shutdown.

The page puts an article panel beside the guest's screen. It has the Tamper
switch, the true and the false claim, and the real and tampered article side
by side with the changed sentences marked. It marks the version the world
serves now and the version Firefox last received, from the world's facts about
each request, and keeps a strip of this run's reads. The inspector has the
standard panels and a Reads table.

It needs KVM and Chromium. Measured on a 24-core machine: the pinned files are
about 650 MB, shared with the desktop demo. The first run also fetches about
78 MB of Ubuntu packages through the world's mirror into
`downloads/cloudimage/apt-cache/`. With the files downloaded and the binary
built, the desktop was up with the article read 67 s after boot on an empty
package cache, and 52 s after boot with a warm cache. A whole run with a warm
cache took 54 s.

For page design without a VM, run `cargo run --locked -p fictionet-demo --example fakewiki_page`.
It uses the same page and world with a placeholder screen. The first stdout
line is its loopback URL. Press Enter to make the in-world scripted client
read the article, use the page's Tamper switch, then press Enter again. Type
`drop` to close the placeholder screen's connections. EOF stops the example.
Its markers name the scripted client; the VM demo names Firefox (scripted).
The design screenshots of every panel and state come from this example; the
gate's screenshots come from the VM. Article component tests run with
`node --test demos/src/bin/fakewiki/article.test.mjs`.

## VM scripts

The other demos are scripts in `demos/guest/` that run in the Fictionet VM.
The command boots the VM if it is not running ([vm/README.md](../vm/README.md)),
builds Fictionet inside it, runs the demo, and cleans up. Each step says in plain
words what happens next, then shows the commands and their real output. Nothing
needs root or Docker on your machine: QEMU, KVM and
[the other host tools](../vm/README.md#the-fictionet-vm) are required. No demo
needs a model key.

The first demo on a machine downloads and prepares the VM image, about two
minutes, and builds Fictionet in the VM, about one more. After that a demo boots
the VM in seconds. A rebuild after a change to an example takes seconds, and
after a change to the SDK itself about a minute. A demo that booted the VM
shuts it down at the end. Run `cargo xtask vm up` first to keep one VM for
several demos, and `cargo xtask vm down` when you are done; `VM_KEEP=1` keeps a
VM that a demo booted.

| Demo | What it shows | Needs | First run |
|---|---|---|---|
| [`cargo xtask demo web`](guest/web.sh) | The sandbox is a network namespace named `agent`, and `fictionet attach --type tun` puts `tun0` in it. From inside: `dig` answers the world's names and NXDOMAIN for the rest, `curl` reaches `https://example.test/` with the world's CA and fails without it, `ping` reaches the gateway, an address with no machine fails at once, and `example.com` and `1.1.1.1` are not there. | | 3.5 min; then 10 s |
| [`cargo xtask demo proxy`](guest/proxy.sh) | A sandbox with only a loopback interface, whose commands run as an unprivileged user with no capabilities. Two attaches inside its namespace serve `--type http_proxy` and `--type socks5`. `curl` and Python reach the world through `http_proxy`, and `curl` through SOCKS5. A wrong token gets 407, an unknown name gets 502 with the reason, and around the proxy there is no network. | | 10 s |
| [`cargo xtask demo dashboard`](guest/dashboard.sh) | The world and sandbox of `cargo xtask demo web`, with the world's third argument opening an observation socket. `fictionet dashboard --observation unix:PATH` reads that collector and serves the live view on the VM's port 7878, which `cargo xtask vm` forwards to `127.0.0.1` on your machine. It prints the address to open, and `fictionet observe` shows the same API from a shell: the graph, and the world's events as they happen. A loop in the sandbox makes requests until you press Enter (or for `DASHBOARD_SECONDS`). | a browser | 25 s |
| [`cargo xtask demo k8s`](guest/k8s.sh) | A kind cluster in the VM, the Helm chart in `charts/fictionet-sandbox` with `examples/attach/k8s-tun.yaml`, and the agent's pod. Its `eth0` is down, `tun0` is its only route, it reaches `https://example.test/`, and the internet, the cluster's DNS and the API server are out of reach. | pulls kind's node image | 1.5 min; then 1 min |
| [`cargo xtask demo border`](guest/border.sh) | [Border](../examples/border)'s world under Docker Compose in the VM, with a scripted agent. First the real bank: sign-in, balance, three hops, one BGP route. Then the hijack: a fourth hop and a more specific route from AS 65002, an impostor certificate that `curl` refuses, and with `curl -k`, the password sent to the impostor, as the world's log shows. | pulls Debian and Python images | 2 min; then 20 s |
| [`cargo xtask demo adaptive-web`](guest/adaptive-web.sh) | [The adaptive web](../examples/adaptive-web) under Docker Compose in the VM, with its stub generator. A search on `google.com` answers with ten results made for the query; the page behind the first result is made when it is asked for and kept; the world's log says why each site exists. | pulls Debian and Python images | 30 s; then 15 s |
| [`cargo xtask demo scan`](guest/scan.sh) | [The scan example](../examples/scan) under Docker Compose in the VM: four simulated hosts and a real container with nginx and OpenSSH on one office subnet. `nmap` in the agent's sandbox finds all five, and a SYN scan with service detection names what runs on each. The world's second argument opens its observation socket. The dashboard connects to that socket and shows the scan, with its HTTP port forwarded to your machine. | a browser; pulls Debian and Alpine images | 1.5 min; then 1 min |

The times are from a 24-core machine with other work running, with the VM's
default 4 vCPUs and 5 GB. "First run" is the whole command on a machine that
has run `cargo xtask demo web` once, so the VM image and the SDK build are
there; "then" is a later run of the same demo. The first runs went in the
table's order, so a Compose demo reused the Debian and Python images that the
demos above it pulled. Docker's images and build cache, cargo's build output
and uv's cache stay on the VM's cache disk, so only the first run of each demo
pays for them.

## How the scripts work

The scripts that run inside the VM are in [`guest/`](guest), one per demo, with
[`lib.sh`](guest/lib.sh) for the steps, the commands and the checks. Each starts
with a `# needs:` line that says what [`vm/guest/build.sh`](../vm/guest/build.sh)
builds for it: `sdk` is `fictionet` and the crate's examples, and `border`,
`fakewiki` and `adaptive-web` are those examples' worlds (the FakeWiki target
remains for eval probes). The Compose demos run the examples' own Compose files,
plus a small file next to the script (`border.compose.yaml` and the others) that
puts the binaries the VM built in place of the Dockerfile's build stage, so
nothing compiles twice.

A demo stops at the first step that does not go as it says, and prints the
world's log. A refusal, such as `curl` failing without the world's CA, must
end with the expected exit status and diagnostic: a timeout, a missing command
or a signal is a failure, not a refusal. The expected curl statuses come from
its [exit-code documentation](https://curl.se/docs/manpage.html#exit-codes)
and the world's DNS, TLS and routing behavior.

## The evals, and the recipes

Four examples are also Inspect evals: [Border](../examples/border),
[FakeWiki](../examples/fakewiki), [the adaptive web](../examples/adaptive-web)
and [Artifactory](../examples/artifactory). `cargo xtask eval <world>` builds a
world's images with your machine's Docker and runs its eval; with `--probes` or
`--scripted` it needs no model. Each README says how, and how to run the world
by hand with `docker compose`. The evals and the VM are also test suites:
`cargo xtask vm test <name>` ([vm/README.md](../vm/README.md)).

[`examples/attach`](../examples/attach) has the Compose and Kubernetes recipes
for `fictionet attach` on your own machine or cluster, and
[`examples/hosted`](../examples/hosted) runs the Compose setup inside a Daytona
or E2B sandbox. `cargo xtask scan` records the scan demo's dashboard as a video.
[Fictionet Observe](../observe/README.md) covers the collector, browser sign-in
and capture limits. The dashboard and `fictionet observe` use the observation
socket served by `fictionet_observe::serve`; attachments use the world socket.

## Making a demo of your own

The shared `fictionet_demo::kit` boots one or more Ubuntu cloud guests with
Cloud Hypervisor and a world in the same process. A binary in
`src/bin/<name>/main.rs` declares its guests, world and page:

```rust
use fictionet_demo::kit::{self, Guest, Kit};
use fictionet_observe::page::Page;

let kit = Kit::new("office")
    .guest(Guest::ubuntu("workstation", "analyst").packages(&["curl"]))
    .world(|cx, mut world| async move {
        let mirror = world.mirror(&cx)?;
        fictionet::stdlib::web::Sites::new(move |host: &str| match host {
            "archive.ubuntu.com" | "security.ubuntu.com" =>
                Some(fictionet::stdlib::web::Site::new(mirror.clone())),
            _ => None,
        })
        .into_net()
        .route(kit::JUMP, kit::jump_prefix())
        .start(&cx, world.into_attachments())
    })
    .page(|dashboard, hosts| Page::new("Office", dashboard)
        .host(hosts.take("workstation"))
        .standard_panels());
let run = kit.boot(downloads).await?;
run.shutdown().await?;
```

The guest image is never modified; each run gets its own overlay and seed.
See the [kit API](src/kit/mod.rs) and the desktop's
[guest](src/bin/desktop/guest.rs) and [world](src/bin/desktop/world.rs) definitions.

### Adding a VM script

Start from [`examples/scan`](../examples/scan), the smallest Docker example with
an agent container: the world in one file, a Dockerfile with one stage per
container, and a Compose file.

1. Copy `examples/scan` to `examples/<name>`, and add the world to the crate's
   `Cargo.toml` as an example, next to `scan`'s entry: `name = "<name>"`,
   `path = "examples/<name>/main.rs"`. Write your world in `main.rs`;
   `cargo run --example <name> -- /tmp/world.sock` runs it on its own.
2. In `docker/Dockerfile`, build and copy your example instead of `scan` (its
   `build` and `fictionet` stages name it), and give the agent's stage the
   tools your agent uses instead of nmap. Drop the `container` stage if your
   world has no real host.
3. In `compose.yaml`, set `name` and the image tags to your name, the world's
   `command` to your binary, and the agent's address, name and sandbox. Drop
   `container` and `container-attach` with the stage.
4. Run it from the repository root with your machine's Docker, as the scan
   README does: `docker compose -f examples/<name>/compose.yaml up -d --build --wait`,
   then `exec` into the agent's service, and `down -v` at the end.
5. For `cargo xtask demo <name>`, copy `demos/guest/scan.sh` to
   `demos/guest/<name>.sh` and `scan.compose.yaml` to `<name>.compose.yaml`,
   and change the Compose file, the project name and the steps. Keep the
   `# needs: sdk` line: the VM builds every example. `cargo xtask demo` finds
   the script by its name. Add a row to the table above.
