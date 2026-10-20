# Demos

Every demo is one command:

```console
$ cargo xtask demo <name>
```

`cargo xtask demo` with no name lists the demos. Six are microVM demos: one
binary each, with the world in the same process. Four are scripts in
[`guest/`](guest) that run in the Fictionet VM.

`cargo xtask demo assets` downloads the files the microVM demos need, without
booting anything. `cargo xtask demo libraries` downloads only the pinned
browser libraries, into `observe/downloads/vendor/` at the repository root.
Options for a demo go after its name, as in
`cargo xtask demo search --seed corvane-acquisition`.

## The microVM demos

A microVM demo needs Linux with KVM. It needs no QEMU, Docker or root. The
command downloads the pinned files on its first run, about 650 MB shared by
every demo: Ubuntu's official 24.04 cloud image, its kernel and initrd, Cloud
Hypervisor and the browser libraries. It then builds the demo's binary in
release mode and runs it. The binary carries Cloud Hypervisor and runs it from
memory.

The guest image is never modified. Each run writes its own qcow2 overlay and
cloud-init seed, and the guest installs its packages at boot through the
world's mirror. The mirror keeps them in `downloads/cloudimage/apt-cache/`, so
the first run on a machine also fetches about 280 MB of Ubuntu packages and
later runs reuse them.

Each run prints its page URL before the guests boot. It then runs the
demo's story and its checks. Every demo checks that no containment probe was
forwarded or answered from outside the world. The run saves screenshots,
powers the guests off, and checks that no Cloud Hypervisor process or run
directory is left. A passing run ends with `every required check passed`. A
failing run prints the guests' cloud-init report, log tails and console tail.
The page screenshots need Chromium on your machine.

Five demos also run without a VM: `cargo xtask demo <name> preview` serves
the same page with an in-world client in place of the guests, and needs only
the browser libraries. In Artifactory, Border, FakeWiki and Search, a screen
that says NO VM takes the guest's place. Scan's preview has no screen and
shows its two hosts with status only. Every preview reads its standard input
the same way. In Border and FakeWiki, Enter runs the in-world client again.
The other previews run their story once. Where the page has a screen, type
`drop` to close its connections. The end of input or Ctrl-C stops a preview.

The times below are from one run of each demo on a 24-core machine with other
work running, the pinned files downloaded, the package cache filled and no
page tab open. All six ran one after another on the same build.

### Desktop

`cargo xtask demo desktop` boots an Ubuntu desktop with Xfce, Mozilla's
Firefox and two pinned coding agents, Claude Code and Codex. The page shows
the live desktop and terminal over SSH, beside packets, events, the map, Left
the box, containment, labels and export. Its Coding agents table fills in once
the checks have run both version commands. No model API is forwarded, so the
agents run no task.

The checks cover the guest's address and devices, the trust store, Firefox, the
agents' own TLS clients, and the page's access controls. They type a command
in the page terminal and move the pointer with and without the screen lease.

- Options: a Unix socket path. With it,
  `fictionet observe --observation unix:PATH watch` follows the same
  dashboard from another terminal.
- Screenshots: `downloads/cloudimage/shots/`, with `guest-desktop.png` from
  the guest, `viewer-desktop.png` through the page's screen socket, and
  `page-desktop.png` from Chromium.
- Times: SSH up after 7.2 s, desktop after 44.8 s, cloud-init done after
  47.5 s, whole run 52.8 s. One 88 MB file was not in the package cache.

### Artifactory

`cargo xtask demo artifactory` runs the [Artifactory](../examples/artifactory)
world and a scripted agent in a terminal on an Ubuntu desktop. Firefox loads
the internal package index during setup, then closes so the terminal fills the
screen. The agent makes no model calls. Its wheels are small and inert. The
package mirror forwards only during setup and then answers 403.

The page opens on Doors tried: the variant, the story's steps, every door the
agent tried with denied egress in red, the upstream techniques it used, and
the July 2026 incident beside the rows of this run that match it. Packages
shows the simulated server's inventory with the lookalike flagged, and
Requests lists every request with its classification.

The checks cover each command's exit status and the facts the world observed,
then read the same facts from the page's API as a browser does. Each command
declares its destinations. Other traffic from the guest is kept, printed
apart, and shown in a muted band in Doors tried.

- Options: `--variant normal|missing|lookalike|peer`, `lookalike` by default.
  `--stay` keeps the page open after the checks until Ctrl-C. With `--variant
  peer`, `--sessions shared|separate` boots a colleague's laptop beside
  Maya's. The colleague leaves a note in the cache first, and then Maya lists
  it. With `shared`, both sessions use one repository state and Maya's
  listing shows the note. With `separate`, each session has its own state and
  it does not. The page shows the cache for each state.
- Screenshots: `downloads/cloudimage/shots/artifactory-screen.png` and
  `artifactory-page.png`, with the world's log in `artifactory.jsonl`, each
  replaced on every run.
- Without a VM: `cargo xtask demo artifactory preview` serves the same page,
  labeled "Replay without VMs". An in-process client replays the variant's
  requests and door probes, about one step every two seconds, so there are no
  guest exit statuses. It takes `--variant` and `--sessions` too, and
  `--extra-reads N` adds N index reads after the story, enough to fill the
  page's row bound.
- Times: for `lookalike`, SSH up after 7.8 s, story 59.8 s, whole run
  118.3 s. Earlier runs of the other variants, before the demos were merged,
  took 4.9 s and 63.4 s for the story and the whole run of `normal`, 70.6 s
  and 128.0 s for `missing`, 23.4 s and 74.1 s for `peer`, and 29.2 s and
  79.8 s for `peer` with `--sessions shared`.

### Border

`cargo xtask demo border` runs the [Border](../examples/border) world with one
Ubuntu workstation and a scripted agent. The agent signs in to the bank,
reads the balance, inspects the certificate, traces three hops and reads two
BGP routes. Then the page's Routing control hijacks the route. It rejects a
stale repeat, breaks the open HTTPS connection, and brings four hops, three
BGP routes and curl's certificate refusal. An insecure sign-in reaches the
impostor, and the page's events show it without the password. Restoring the
route makes a fresh balance request work again.

The terminal watches tmux `main` read-only. Press Ctrl-b d to open your own
login shell and run `bank-check` subcommands. Taking browser input does not
pause the script. After the story, Routing stays available and the page stays
open until Ctrl-C.

- Options: `--checks` shuts down after the story. A run without a terminal on
  stdin does the same.
- Screenshots: `normal.png`, `hijacked.png`, `page-hijacked.png` and the
  world's `log.jsonl` in the `downloads/cloudimage/shots/border-<run>/`
  directory the run prints. Each screen capture is kept once two captures in a
  row match, so Firefox has finished loading. `page-hijacked.png` is the page
  in Chromium at the hijack, once the route, the four-hop traceroute and the
  credential alert show.
- Without a VM: `cargo xtask demo border preview` serves the page with an
  in-process scripted client and real world traffic. Change the route on the
  page, then press Enter to run sign-in, balance and traceroute on it.
- Times: SSH up after 6.4 s, desktop after 48.8 s, story done after 60.8 s,
  whole run 61.5 s.

### Search

`cargo xtask demo search` runs [the adaptive web](../examples/adaptive-web)
with a stub generator, so no model is called, and a scripted Firefox searcher
on an Ubuntu desktop. The page shows each search as it arrives, with the host
that asked, its time and its outcome. Select one to see the result list the
world made for it, or the earlier search whose list it reused. Beside it grows
a tree of every made-up site and page, with the world's reason for each, how
it was made and how fast it was served. A switch turns page generation off and
on. The desktop sits above the inspector.

The checks search on Google, Bing and DuckDuckGo, open results and a typed
address, and check each page's reason and how it was made. The seed names the
words to search for and the address to type. The checks confirm that a stored
search comes from memory once generation is off, that Left the box names
every forwarded mirror, and that the guest's background requests made no
pages. The story holds each step for 1.5 s, so you can follow
it on the page.

- Options: `--seed halvard-cve|corvane-acquisition|fastjsonl-package`,
  `halvard-cve` by default. `--stay` keeps the page open after the checks until
  Ctrl-C.
- Screenshots: `downloads/cloudimage/runs/search-<time>/`, with `desktop.png`,
  `page.png` and the world's `log.jsonl`.
- Without a VM: `cargo xtask demo search preview` drives real in-process
  searches with a scripted client. The story runs once. `--spend-budget` ends
  it with new searches until the world refuses one for its generation budget.
  Type `drop` to show the lost screen. The preview holds the package cache
  while it runs, so a VM run started beside it fetches its packages without
  the cache.
- Times: SSH up after 6.7 s, Google loaded in Firefox after 44.9 s, story done
  after 67.3 s, whole run 68.1 s.

### FakeWiki

`cargo xtask demo fakewiki` runs the [FakeWiki](../examples/fakewiki) world
with a scripted Firefox reader on an Ubuntu desktop. The reader loads a
Wikipedia article, and reloads it after the page turns tampering on. The page
puts an article panel beside the guest's screen: the Tamper switch, the true
and the false claim, and the real and tampered article side by side with the
changed sentences marked. It marks the version the world serves now and the
version Firefox last received, from the world's facts about each request, and
keeps a strip of this run's reads. The inspector adds a Reads table.

The checks cover both reads, the switch's revisions, a stale switch command,
and that the panels have data.

- Screenshots: `desktop.png` and `page.png` in a new directory under
  `downloads/cloudimage/shots/` for each run.
- Without a VM: `cargo xtask demo fakewiki preview` serves the same page and
  world. The first line it prints is the page URL. Press Enter to have the
  in-world scripted client read the article, use the page's tamper switch, and
  press Enter again.
- Times: SSH up after 7.3 s, article read after 48.5 s, whole run 53.2 s.

### Scan

`cargo xtask demo scan` boots two Ubuntu guests in an in-process office. A
script, not a model, types three nmap steps into the workstation's terminal:
host discovery, a SYN scan of ports 1 to 1,024 with service detection, and OS
detection. Four office machines are simulated. The fifth is the second guest,
a real Ubuntu server with nginx and OpenSSH. The page shows both guests, the
office subnet lighting up as hosts answer, each host's 1,024 ports, and the
banners seen on the wire beside what nmap says, with the shared panels. See
[the scan example](../examples/scan/README.md#the-in-process-demo).

The checks compare each nmap report with the ports the world served, and the
page's access controls and terminal.

- Screenshots: `downloads/cloudimage/shots/`, with `viewer-scan.png`,
  `page-scan.png`, and each step's nmap report and the world's ports beside it.
- Without a VM: `cargo xtask demo scan preview` serves the same page,
  labeled "replay without VMs". An in-world scanner sends the story's
  probes, a stand-in answers at 10.0.0.50 with the banners the real server
  sent, and nmap's reports are the ones recorded in a KVM run, so no step has
  an exit status.
  `--bound` keeps probing new ports until the port map is full, and
  `--no-os-match ADDR` removes nmap's OS matches for one host.
- Times: both guests SSH up after 7.1 s, boot 29.7 s, story 53.4 s, whole run
  85.4 s.

## The page

`Kit::page` takes a builder over the dashboard and the declared hosts:
`Page::new("Desktop", dashboard).host(hosts.take("workstation")).standard_panels()`.
The kit adds one dashboard observer with startup packet capture, each host's
status, the containment probes and labels. The standard panels are the
screen, terminal, packets, events, map, Left the box, containment, labels and
export. `Page::table` adds a view over a world-owned `StateTopic`.

The page binds to loopback. Data and commands need its per-run bearer token,
with exact Host and Origin checks. Consoles use short-lived, single-use
WebSocket tickets from the authenticated API, and screen input needs the
host's input lease. Taking control claims browser input only. It does not
pause an agent. A host takes four screen sessions and four terminal sessions
at once. The checks' own captures use one or two, so with several page tabs
open a page shot can be refused a session and fail. The pinned noVNC and
xterm.js files are embedded from `observe/downloads/vendor/`.

The page's consoles and the checks reach each guest over SSH from the kit's
jump host, so that traffic crosses the guest's link too. The packet list hides
packets to and from the jump host's address, counts them, and shows them on
request. The list for all hosts covers the declared hosts' links. A packet
list keeps its rows when the run stops.

The containment panel shows each startup probe and the world's answer to it.
A probe is contained when Left the box shows the world's own answer: a world
site or service served it, the world refused it, the world had no route for
it, or the world's DNS had no such name. Worlds built on `Net` report all of
these. A world that answers some packets itself before they reach its `Net`
reports its refusals as `net.blocked` too, naming the sandbox in a `sandbox`
field, as Border's path does for addresses with no machine. A guest with no
route for the IPv6 probe's address is contained for IPv6.

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
run.guest("workstation").wait_cloud_init(Duration::from_secs(300)).await?;
run.shutdown().await?;
```

The checks use the same few calls in every demo, all in
[`kit::checks`](src/kit/checks.rs) and [`kit::client`](src/kit/client.rs):

- `GuestHandle::wait_cloud_init` waits for the guest's setup and fails with
  cloud-init's report.
- `Run::screenshots` saves a guest's screen through the page and the page from
  Chromium. `Run::settled_screen` keeps a screen capture once two in a row
  match, so a page the guest is loading has finished, and `Run::screen`
  saves one capture. `Run::page_shot` saves the page once a condition holds
  in it.
- `Run::containment` waits for every guest's containment probes on the page
  and fails if one was forwarded or answered from outside the world.
- `Run::shutdown` powers the guests off and fails unless no Cloud Hypervisor
  process or run directory is left.
- `kit::checks::check` prints `[pass]` or `[FAIL]` with the check's name.
- `kit::checks::bearer_required`, `single_use_ticket` and `terminal_runs_on`
  check the page's access controls and its terminal.
- `GuestHandle::diagnostics` collects the guest's side of a failed run.
- `PageClient` reads the page's API as a signed-in browser does, reads one
  state topic with `state`, posts commands, waits for a state or an event,
  pages through events with `find_event`, and reads the state stream with
  `state_stream`.
- `kit::checks::STEP_PAUSE` holds each story step for 1.5 s, so a person
  watching can follow it. No check may depend on it.
- `kit::checks::stay_open` keeps the page open until Ctrl-C.
- `kit::preview::Console` is a screen that says NO VM, for a page without a
  guest, and `kit::preview::Input` reads a preview's standard input.

`kit::desktop::browser` declares an Ubuntu desktop with Mozilla's Firefox,
quieted through enterprise policies so it makes no requests a page did not ask
for. `kit::desktop::terminal` declares one full-screen terminal that types and
runs each command `GuestHandle::type_command` sends, for at most the time the
call gives.
`Guest::typed_commands` adds that program to any guest, as Artifactory's
browser desktop does. `Guest::validate` refuses a guest whose names, files,
packages or commands contain one of the words in `kit::FORBIDDEN`, such as
eval or world, and `Guest::forbid` adds a demo's own words. A demo's page
without a VM is its `preview` subcommand. See the [kit API](src/kit/mod.rs)
and the desktop's [guest](src/bin/desktop/guest.rs) and
[world](src/bin/desktop/world.rs).

## VM scripts

A new demo is a microVM demo on the kit. See
[Making a demo of your own](#making-a-demo-of-your-own).

The other demos are scripts in [`guest/`](guest) that run in the Fictionet VM.
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
several demos, and `cargo xtask vm down` when you are done. `VM_KEEP=1` keeps a
VM that a demo booted.

| Demo | What it shows | Needs | First run |
|---|---|---|---|
| [`cargo xtask demo web`](guest/web.sh) | The sandbox is a network namespace named `agent`, and `fictionet attach --type tun` puts `tun0` in it. From inside: `dig` answers the world's names and NXDOMAIN for the rest, `curl` reaches `https://example.test/` with the world's CA and fails without it, `ping` reaches the gateway, an address with no machine fails at once, and `example.com` and `1.1.1.1` are not there. | | 3.5 min; then 10 s |
| [`cargo xtask demo proxy`](guest/proxy.sh) | A sandbox with only a loopback interface, whose commands run as an unprivileged user with no capabilities. Two attaches inside its namespace serve `--type http_proxy` and `--type socks5`. `curl` and Python reach the world through `http_proxy`, and `curl` through SOCKS5. A wrong token gets 407, an unknown name gets 502 with the reason, and around the proxy there is no network. | | 10 s |
| [`cargo xtask demo dashboard`](guest/dashboard.sh) | The world and sandbox of `cargo xtask demo web`, with the world's third argument opening an observation socket. `fictionet dashboard --observation unix:PATH` reads that collector and serves the live view on the VM's port 7878, which `cargo xtask vm` forwards to `127.0.0.1` on your machine. It prints the address to open, and `fictionet observe` shows the same API from a shell: the graph, and the world's events as they happen. A loop in the sandbox makes requests until you press Enter (or for `DASHBOARD_SECONDS`). | a browser | 25 s |
| [`cargo xtask demo k8s`](guest/k8s.sh) | A kind cluster in the VM, the Helm chart in `charts/fictionet-sandbox` with `examples/attach/k8s-tun.yaml`, and the agent's pod. Its `eth0` is down, `tun0` is its only route, it reaches `https://example.test/`, and the internet, the cluster's DNS and the API server are out of reach. | pulls kind's node image | 1.5 min; then 1 min |

The times are from a 24-core machine with other work running, with the VM's
default 4 vCPUs and 5 GB. "First run" is the whole command on a machine that
has run `cargo xtask demo web` once, so the VM image and the SDK build are
there. "Then" is a later run of the same demo, which reuses the build output on the
VM's cache disk.

### How the scripts work

Each script starts with a `# needs:` line that says what
[`vm/guest/build.sh`](../vm/guest/build.sh) builds for it: `sdk` is
`fictionet` and the crate's examples. [`lib.sh`](guest/lib.sh) has the steps,
the commands and the checks.

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
world's images with your machine's Docker and runs its eval. With `--probes` or
`--scripted` it needs no model. Each README says how, and how to run the world
by hand with `docker compose`. The evals and the VM are also test suites:
`cargo xtask vm test <name>` ([vm/README.md](../vm/README.md)).

[`examples/attach`](../examples/attach) has the Compose and Kubernetes recipes
for `fictionet attach` on your own machine or cluster, and
[`examples/hosted`](../examples/hosted) runs the Compose setup inside a Daytona
or E2B sandbox. `cargo xtask scan` records the scan example's dashboard as a video.
