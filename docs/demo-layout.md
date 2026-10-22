# Demo file layout

Tracked demo files, moved shared support, and the shared components used by Search. Counts use newline bytes, as `wc -l` does. Downloaded VM images, browser libraries and WARC captures are local assets, not tracked source.

| File | Lines | Purpose |
| --- | ---: | --- |
| `demos/README.md` | 93 | Usage, architecture or world instructions. |
| `demos/artifactory/.gitignore` | 5 | .gitignore implementation. |
| `demos/artifactory/README.md` | 646 | Usage, architecture or world instructions. |
| `demos/artifactory/app/Cargo.toml` | 51 | Crate dependencies and build targets. |
| `demos/artifactory/app/src/artifactory.css` | 141 | Artifactory implementation. |
| `demos/artifactory/app/src/common.mjs` | 80 | Common implementation. |
| `demos/artifactory/app/src/common.test.mjs` | 38 | Retained behavior coverage and its input data. |
| `demos/artifactory/app/src/doors.mjs` | 260 | Doors implementation. |
| `demos/artifactory/app/src/doors.test.mjs` | 237 | Retained behavior coverage and its input data. |
| `demos/artifactory/app/src/facts.rs` | 1346 | The world's facts for the checks and the page. An observer tags each request |
| `demos/artifactory/app/src/fake-services.mjs` | 76 | Fake services implementation. |
| `demos/artifactory/app/src/guest.rs` | 143 | Maya's workstation: the Ubuntu desktop guest, its project and pip |
| `demos/artifactory/app/src/main.rs` | 247 | Runs the Artifactory world and a scripted agent on an Ubuntu desktop, and |
| `demos/artifactory/app/src/packages.mjs` | 275 | Packages implementation. |
| `demos/artifactory/app/src/packages.test.mjs` | 188 | Retained behavior coverage and its input data. |
| `demos/artifactory/app/src/page.rs` | 366 | The Artifactory page: Doors tried, Packages and Requests beside the |
| `demos/artifactory/app/src/preview.rs` | 857 | artifactory preview: the page without a VM. An in-process client |
| `demos/artifactory/app/src/requests.mjs` | 163 | Requests implementation. |
| `demos/artifactory/app/src/requests.test.mjs` | 139 | Retained behavior coverage and its input data. |
| `demos/artifactory/app/src/story.rs` | 846 | The scripted story. Each step is one command from the eval's scripted |
| `demos/artifactory/app/src/world.rs` | 53 | The network the guest sees: the Artifactory world's sites, the jump route |
| `demos/artifactory/docker/Dockerfile` | 77 | Builds the world or guest container. |
| `demos/artifactory/docker/Dockerfile.dockerignore` | 19 | Dockerfile implementation. |
| `demos/artifactory/docker/agent/pip.conf` | 4 | Pip implementation. |
| `demos/artifactory/docker/agent/project/ledger.csv` | 5 | Page, protocol or world input data. |
| `demos/artifactory/docker/agent/project/report.py` | 14 | Report implementation. |
| `demos/artifactory/docker/agent/project/requirements.txt` | 1 | Page, protocol or world input data. |
| `demos/artifactory/world/Cargo.toml` | 33 | Crate dependencies and build targets. |
| `demos/artifactory/world/src/events.rs` | 347 | Reference for the JSON-lines log read by the eval and egress report. |
| `demos/artifactory/world/src/facts.rs` | 1365 | Bounded request rows and door facts projected from observer events. |
| `demos/artifactory/world/src/inventory.rs` | 416 | Public package metadata and revisioned cache contents. |
| `demos/artifactory/world/src/lib.rs` | 258 | A Python package mirror with no upstream and a simulated shared cache. |
| `demos/artifactory/world/src/log.rs` | 217 | The world's JSON-lines log at /var/lib/fictionet/log.jsonl. |
| `demos/artifactory/world/src/main.rs` | 112 | The Artifactory world process. |
| `demos/artifactory/world/src/packages.rs` | 558 | Seeded package contents and stored ZIP wheels. |
| `demos/artifactory/world/src/repository.rs` | 1742 | The simple indexes, remote caches, storage API, and peer folders. |
| `demos/artifactory/world/src/ssrf.rs` | 415 | Off-site targets named by a request, with bounded log output. |
| `demos/artifactory/world/tests/common/mod.rs` | 557 | An in-world TCP, TLS, and DNS client and an in-memory log. |
| `demos/artifactory/world/tests/facts.rs` | 178 | Request rows and door facts from real observer streams. |
| `demos/artifactory/world/tests/golden/lookalike.jsonl` | 79 | Retained behavior coverage and its input data. |
| `demos/artifactory/world/tests/golden/missing.jsonl` | 79 | Retained behavior coverage and its input data. |
| `demos/artifactory/world/tests/golden/normal.jsonl` | 79 | Retained behavior coverage and its input data. |
| `demos/artifactory/world/tests/golden/peer.jsonl` | 83 | Retained behavior coverage and its input data. |
| `demos/artifactory/world/tests/golden/topology.json` | 13 | Retained behavior coverage and its input data. |
| `demos/artifactory/world/tests/inventory.rs` | 91 | Inventory changes through the served network. |
| `demos/artifactory/world/tests/sessions.rs` | 119 | Repository state per sandbox: shared by every sandbox, or separate. |
| `demos/artifactory/world/tests/world.rs` | 655 | The four worlds, driven through their own network. |
| `demos/attach/README.md` | 34 | Usage, architecture or world instructions. |
| `demos/attach/compose-proxy.yaml` | 78 | Container or deployment configuration. |
| `demos/attach/compose-tun.yaml` | 58 | Container or deployment configuration. |
| `demos/attach/k8s-proxy.yaml` | 40 | Container or deployment configuration. |
| `demos/attach/k8s-tun.yaml` | 29 | Container or deployment configuration. |
| `demos/attach/netns.sh` | 61 | Guest setup or demo commands. |
| `demos/border/.gitignore` | 4 | .gitignore implementation. |
| `demos/border/README.md` | 480 | Usage, architecture or world instructions. |
| `demos/border/REPLICATION.md` | 257 | Usage, architecture or world instructions. |
| `demos/border/app/Cargo.toml` | 51 | Crate dependencies and build targets. |
| `demos/border/app/src/client.rs` | 241 | An in-process workstation using the same bank, packet path and BGP speaker. |
| `demos/border/app/src/control.rs` | 202 | The World menu's commands and the authoritative route state. |
| `demos/border/app/src/guest.rs` | 96 | The workstation: Firefox on the bank, Claude Code, and the login in ~/.bank. |
| `demos/border/app/src/main.rs` | 122 | The Border demo: an Ubuntu workstation with Firefox and Claude Code, its |
| `demos/border/app/src/picture.mjs` | 32 | Picture implementation. |
| `demos/border/app/src/picture.test.mjs` | 31 | Retained behavior coverage and its input data. |
| `demos/border/app/src/preview.rs` | 257 | Serves the VM's page with an in-process workstation and real world traffic. |
| `demos/border/app/src/style.css` | 41 | Style implementation. |
| `demos/border/app/src/tests.rs` | 422 | Retained behavior coverage and its input data. |
| `demos/border/app/src/trace.rs` | 285 | Bounded UDP traceroute reconstruction from a guest link's IPv4 packets. |
| `demos/border/app/src/view.mjs` | 175 | View implementation. |
| `demos/border/app/src/view.rs` | 806 | Bounded observations for Border. Routing stays in its authoritative topic. |
| `demos/border/app/src/world.rs` | 70 | The bank, the package mirrors, Claude Code's model site, and the admin |
| `demos/border/compose.home.yaml` | 96 | Container or deployment configuration. |
| `demos/border/compose.yaml` | 108 | Container or deployment configuration. |
| `demos/border/docker/Dockerfile` | 120 | Builds the world or guest container. |
| `demos/border/docker/Dockerfile.dockerignore` | 19 | Dockerfile implementation. |
| `demos/border/docker/bird.conf` | 26 | Bird implementation. |
| `demos/border/world/Cargo.toml` | 33 | Crate dependencies and build targets. |
| `demos/border/world/src/bank.rs` | 1055 | Kestrelmoor Bank's site, and the neutral status page. |
| `demos/border/world/src/bgp.rs` | 496 | BGP-4: the speaker that plays Harbourline's border router. |
| `demos/border/world/src/certs.rs` | 128 | The Border world's roots, intermediate, and server certificates. |
| `demos/border/world/src/events.rs` | 273 | Network and world observer facts as the eval's log lines. |
| `demos/border/world/src/lib.rs` | 286 | The Border world on Fictionet. |
| `demos/border/world/src/log.rs` | 178 | The world's log: one JSON object per line, at |
| `demos/border/world/src/main.rs` | 140 | The Border world process. |
| `demos/border/world/src/path.rs` | 779 | The path between a sandbox and the world: hops, delay, and the two |
| `demos/border/world/src/routing.rs` | 308 | The run's routing revision and typed command boundary. |
| `demos/border/world/src/scenario.rs` | 486 | The Border scenario: two countries, the prefixes they announce, the |
| `demos/border/world/tests/bank.rs` | 914 | The bank's pages and answers, without a network. |
| `demos/border/world/tests/certs.rs` | 184 | The CAs on disk, and the chains a client builds from them. |
| `demos/border/world/tests/common/mod.rs` | 188 | A Border world in one process, and a sandbox built from stdlib parts |
| `demos/border/world/tests/extra.rs` | 106 | Extra hosts share the gateway hop while the scenario keeps its paths. |
| `demos/border/world/tests/golden/hijack.jsonl` | 26 | Retained behavior coverage and its input data. |
| `demos/border/world/tests/golden/legitimate.jsonl` | 26 | Retained behavior coverage and its input data. |
| `demos/border/world/tests/pages/about.html` | 1 | Retained behavior coverage and its input data. |
| `demos/border/world/tests/pages/accessibility.html` | 1 | Retained behavior coverage and its input data. |
| `demos/border/world/tests/pages/contact.html` | 1 | Retained behavior coverage and its input data. |
| `demos/border/world/tests/pages/cookies.html` | 1 | Retained behavior coverage and its input data. |
| `demos/border/world/tests/pages/help.html` | 1 | Retained behavior coverage and its input data. |
| `demos/border/world/tests/pages/home.html` | 1 | Retained behavior coverage and its input data. |
| `demos/border/world/tests/pages/pay_form.html` | 1 | Retained behavior coverage and its input data. |
| `demos/border/world/tests/pages/privacy.html` | 1 | Retained behavior coverage and its input data. |
| `demos/border/world/tests/pages/robots.txt` | 4 | Retained behavior coverage and its input data. |
| `demos/border/world/tests/pages/security.html` | 1 | Retained behavior coverage and its input data. |
| `demos/border/world/tests/pages/signed_in.html` | 1 | Retained behavior coverage and its input data. |
| `demos/border/world/tests/pages/terms.html` | 1 | Retained behavior coverage and its input data. |
| `demos/border/world/tests/routing.rs` | 838 | Live commands change packet delivery, peer routes and observer facts. |
| `demos/border/world/tests/traffic.rs` | 252 | Exercise real bank requests through legitimate and hijacked routes. |
| `demos/border/world/tests/world.rs` | 1563 | The whole Border world in one process, with a sandbox played by the |
| `demos/bottleneck_sites/Cargo.toml` | 15 | Crate dependencies and build targets. |
| `demos/bottleneck_sites/main.rs` | 121 | A sandbox on a slow link: stdlib::network::bottleneck in front of web::Sites, |
| `demos/capture_sites/Cargo.toml` | 15 | Crate dependencies and build targets. |
| `demos/capture_sites/main.rs` | 162 | The packets between the sandboxes and web::Sites, written to a pcap |
| `demos/custom_protocol/Cargo.toml` | 14 | Crate dependencies and build targets. |
| `demos/custom_protocol/README.md` | 29 | Usage, architecture or world instructions. |
| `demos/custom_protocol/main.rs` | 187 | A Modbus gateway that accepts nonzero protocol identifiers on a simulated network. |
| `demos/custom_protocol/modbus.rs` | 1915 | Modbus/TCP: reading and writing frames, requests and responses, with no |
| `demos/delayed_sites/Cargo.toml` | 15 | Crate dependencies and build targets. |
| `demos/delayed_sites/main.rs` | 52 | A website 200 ms away from every sandbox: stdlib::network::delay in front of |
| `demos/desktop/app/Cargo.toml` | 51 | Crate dependencies and build targets. |
| `demos/desktop/app/src/guest.rs` | 34 | The workstation resources and pinned coding agents. |
| `demos/desktop/app/src/main.rs` | 32 | An Ubuntu desktop with coding agents that sign in inside the VM. |
| `demos/desktop/app/src/world.rs` | 85 | The desktop sites and Firefox request observer. |
| `demos/fakewiki/.gitignore` | 4 | .gitignore implementation. |
| `demos/fakewiki/README.md` | 451 | Usage, architecture or world instructions. |
| `demos/fakewiki/app/Cargo.toml` | 51 | Crate dependencies and build targets. |
| `demos/fakewiki/app/src/article.css` | 98 | Article implementation. |
| `demos/fakewiki/app/src/article.mjs` | 239 | Article implementation. |
| `demos/fakewiki/app/src/article.test.mjs` | 266 | Retained behavior coverage and its input data. |
| `demos/fakewiki/app/src/guest.rs` | 34 | Guest implementation. |
| `demos/fakewiki/app/src/main.rs` | 60 | Main implementation. |
| `demos/fakewiki/app/src/page.rs` | 115 | Page implementation. |
| `demos/fakewiki/app/src/preview.rs` | 93 | The article page and world without a VM: a placeholder screen and an |
| `demos/fakewiki/app/src/tests.rs` | 423 | Retained behavior coverage and its input data. |
| `demos/fakewiki/app/src/world.rs` | 67 | World implementation. |
| `demos/fakewiki/compose.yaml` | 100 | Container or deployment configuration. |
| `demos/fakewiki/docker/Dockerfile` | 63 | Builds the world or guest container. |
| `demos/fakewiki/docker/Dockerfile.dockerignore` | 19 | Dockerfile implementation. |
| `demos/fakewiki/fixtures/corpus.json` | 467 | Page, protocol or world input data. |
| `demos/fakewiki/fixtures/scenario.json` | 353 | Page, protocol or world input data. |
| `demos/fakewiki/world/Cargo.toml` | 20 | Crate dependencies and build targets. |
| `demos/fakewiki/world/src/content.rs` | 180 | Serves the embedded pages. Page labels live in response extensions for |
| `demos/fakewiki/world/src/events.rs` | 301 | The request log, written from the events of everything the network |
| `demos/fakewiki/world/src/lib.rs` | 112 | The FakeWiki world on Fictionet. |
| `demos/fakewiki/world/src/main.rs` | 124 | The FakeWiki world process. See the library ([fakewiki_world]) for |
| `demos/fakewiki/world/src/pages.rs` | 664 | Embedded FakeWiki pages, with a variant chosen for each request. |
| `demos/fakewiki/world/src/pages/diff.rs` | 389 | Side-by-side source text from the embedded corpus and one tampering snapshot. |
| `demos/fakewiki/world/src/pages/scenario.rs` | 299 | Scenario implementation. |
| `demos/fakewiki/world/src/pages/tests.rs` | 543 | Retained behavior coverage and its input data. |
| `demos/fakewiki/world/src/pages/text.rs` | 134 | Text implementation. |
| `demos/fakewiki/world/src/pages/wiki.rs` | 672 | Wiki implementation. |
| `demos/fakewiki/world/src/tamper.rs` | 336 | Revisioned tampering state and commands applied by a world task. |
| `demos/fakewiki/world/tests/requests.rs` | 226 | Exercise HTTP, TLS, HEAD delivery and redirects against the world. |
| `demos/fakewiki/world/tests/tampering.rs` | 324 | Runtime switches through the sites a sandbox client uses. |
| `demos/goad/Cargo.toml` | 14 | Crate dependencies and build targets. |
| `demos/goad/README.md` | 159 | Usage, architecture or world instructions. |
| `demos/goad/main.rs` | 129 | A private IP LAN for real GOAD or GOAD-like virtual machines. |
| `demos/h2spec_world/Cargo.toml` | 16 | Crate dependencies and build targets. |
| `demos/h2spec_world/main.rs` | 117 | The world cargo xtask h2spec runs the h2spec conformance suite |
| `demos/hosted/.gitignore` | 5 | .gitignore implementation. |
| `demos/hosted/Dockerfile` | 4 | Builds the world or guest container. |
| `demos/hosted/README.md` | 224 | Usage, architecture or world instructions. |
| `demos/hosted/agent.Dockerfile` | 5 | Builds the world or guest container. |
| `demos/hosted/check.sh` | 146 | Guest setup or demo commands. |
| `demos/hosted/compose.yaml` | 74 | Container or deployment configuration. |
| `demos/hosted/eval.py` | 88 | Eval implementation. |
| `demos/hosted/harbor/fictionet-web/instruction.md` | 2 | Usage, architecture or world instructions. |
| `demos/hosted/harbor/fictionet-web/solution/solve.sh` | 12 | Guest setup or demo commands. |
| `demos/hosted/harbor/fictionet-web/task.toml` | 23 | Task implementation. |
| `demos/hosted/harbor/fictionet-web/tests/test.sh` | 113 | Retained behavior coverage and its input data. |
| `demos/hosted/package_harbor.py` | 59 | Package harbor implementation. |
| `demos/hosted/run_hosted.py` | 125 | Run hosted implementation. |
| `demos/hosted/tests/test_checks.py` | 144 | Retained behavior coverage and its input data. |
| `demos/hosted/tests/test_harbor.py` | 328 | Retained behavior coverage and its input data. |
| `demos/hosted/tests/test_packaging.py` | 155 | Retained behavior coverage and its input data. |
| `demos/k8s/guest.sh` | 61 | Guest setup or demo commands. |
| `demos/kit/Cargo.toml` | 55 | Crate dependencies and build targets. |
| `demos/kit/build.rs` | 29 | Embeds the files cargo xtask demo assets downloads to |
| `demos/kit/guest/lib.sh` | 132 | Guest setup or demo commands. |
| `demos/kit/guest/web_setup.sh` | 50 | Guest setup or demo commands. |
| `demos/kit/src/bin/open.rs` | 27 | Opens a demo's page in a Chromium app window: open <file>, with the |
| `demos/kit/src/kit/bridge.rs` | 44 | Ethernet frames between one guest and its attachment. |
| `demos/kit/src/kit/client.rs` | 680 | Browser authentication and console byte streams for demo checks. |
| `demos/kit/src/kit/containment.rs` | 814 | Read-only startup probes over the guest's admin SSH session. |
| `demos/kit/src/kit/desktop.rs` | 741 | Ubuntu desktops on Xvnc, reached through the admin SSH session: a |
| `demos/kit/src/kit/desktop/packages.mozilla.org.asc` | 19 | Packages.mozilla.org implementation. |
| `demos/kit/src/kit/jump.rs` | 49 | The admin's endpoint on the world's management subnet. |
| `demos/kit/src/kit/mirror.rs` | 1300 | A bounded host cache for immutable apt objects and versioned release |
| `demos/kit/src/kit/mirror/tests.rs` | 1846 | Retained behavior coverage and its input data. |
| `demos/kit/src/kit/mod.rs` | 1590 | Shared guests, networking, provisioning, and run lifetime. |
| `demos/kit/src/kit/net.rs` | 381 | A vhost-user-net backend in our process, so Cloud Hypervisor's guest |
| `demos/kit/src/kit/page.rs` | 475 | Page hosts backed by the kit's admin SSH sessions, and the loop that |
| `demos/kit/src/kit/preview.rs` | 342 | A placeholder screen and the standard input of pages that run without |
| `demos/kit/src/kit/seed.rs` | 188 | NoCloud provisioning for an unmodified Ubuntu cloud image. |
| `demos/kit/src/kit/shot.rs` | 622 | Chromium screenshots after an explicit page readiness condition. |
| `demos/kit/src/kit/ssh.rs` | 351 | An embedded SSH client: it reaches Ubuntu's own sshd on the guest's port |
| `demos/kit/src/kit/ssh/tests.rs` | 406 | Retained behavior coverage and its input data. |
| `demos/kit/src/kit/tests.rs` | 1616 | Retained behavior coverage and its input data. |
| `demos/kit/src/kit/util.rs` | 87 | Util implementation. |
| `demos/kit/src/kit/vm/disk.rs` | 93 | A per-run qcow2 overlay over the read-only download, written in Rust. |
| `demos/kit/src/kit/vm/mod.rs` | 284 | Cloud Hypervisor as a child process: it boots the unmodified image's |
| `demos/kit/src/lib.rs` | 3 | Shared microVM support for in-process demos. |
| `demos/kit/tests/guests.rs` | 29 | Reads real NoCloud filesystem bytes and checks installed file preservation. |
| `demos/lossy_sites/Cargo.toml` | 15 | Crate dependencies and build targets. |
| `demos/lossy_sites/main.rs` | 57 | A lossy link: stdlib::network::filter in front of web::Sites drops 5% of the |
| `demos/nuclear/viewer/.prettierrc.json` | 4 | Page, protocol or world input data. |
| `demos/nuclear/viewer/board-layout.mjs` | 353 | Board layout implementation. |
| `demos/nuclear/viewer/board-layout.test.mjs` | 542 | Retained behavior coverage and its input data. |
| `demos/nuclear/viewer/control-board.mjs` | 1461 | Control board implementation. |
| `demos/nuclear/viewer/control-board.test.mjs` | 965 | Retained behavior coverage and its input data. |
| `demos/nuclear/viewer/control-room.css` | 419 | Control room implementation. |
| `demos/nuclear/viewer/control-room.mjs` | 1320 | Control room implementation. |
| `demos/nuclear/viewer/desk-screens.mjs` | 351 | Desk screens implementation. |
| `demos/nuclear/viewer/desk-screens.test.mjs` | 310 | Retained behavior coverage and its input data. |
| `demos/nuclear/viewer/fixtures/gate-run-extremes.json` | 0 | Page, protocol or world input data. |
| `demos/nuclear/viewer/hmi/hmi.css` | 484 | Hmi implementation. |
| `demos/nuclear/viewer/hmi/hmi.mjs` | 825 | Hmi implementation. |
| `demos/nuclear/viewer/hmi/hmi.test.mjs` | 936 | Retained behavior coverage and its input data. |
| `demos/nuclear/viewer/hmi/index.html` | 15 | Page, protocol or world input data. |
| `demos/nuclear/viewer/instruments.mjs` | 343 | Instruments implementation. |
| `demos/nuclear/viewer/instruments.test.mjs` | 394 | Retained behavior coverage and its input data. |
| `demos/nuclear/viewer/knobs.mjs` | 472 | Knobs implementation. |
| `demos/nuclear/viewer/knobs.test.mjs` | 433 | Retained behavior coverage and its input data. |
| `demos/nuclear/viewer/look.mjs` | 253 | Look implementation. |
| `demos/nuclear/viewer/look.test.mjs` | 95 | Retained behavior coverage and its input data. |
| `demos/nuclear/viewer/meters.mjs` | 371 | Meters implementation. |
| `demos/nuclear/viewer/meters.test.mjs` | 395 | Retained behavior coverage and its input data. |
| `demos/nuclear/viewer/palette.test.mjs` | 27 | Retained behavior coverage and its input data. |
| `demos/nuclear/viewer/plant-scene.mjs` | 1006 | Plant scene implementation. |
| `demos/nuclear/viewer/plant-scene.test.mjs` | 591 | Retained behavior coverage and its input data. |
| `demos/nuclear/viewer/room-motion.mjs` | 156 | Room motion implementation. |
| `demos/nuclear/viewer/room-motion.test.mjs` | 135 | Retained behavior coverage and its input data. |
| `demos/nuclear/viewer/viewer.css` | 243 | Viewer implementation. |
| `demos/nuclear/world/Cargo.toml` | 25 | Crate dependencies and build targets. |
| `demos/nuclear/world/src/bin/viewer.rs` | 327 | Runs the Nuclear plant, operator network and control room page. |
| `demos/nuclear/world/src/command.rs` | 123 | Bounded operator commands. Position units are tenths of a percent for rods |
| `demos/nuclear/world/src/driver.rs` | 547 | A shared handle to one plant. |
| `demos/nuclear/world/src/facts.rs` | 1012 | Plant facts for the Fictionet event log. |
| `demos/nuclear/world/src/faults.rs` | 122 | Fault slots are bounded by the physical equipment and instrument list. |
| `demos/nuclear/world/src/hmi.rs` | 2348 | The supervisory client hmi01, at 10.40.0.20 on the operations network. |
| `demos/nuclear/world/src/kinetics.rs` | 134 | Six delayed groups in the prompt jump approximation. |
| `demos/nuclear/world/src/lib.rs` | 146 | Nuclear is a fictional educational two-loop pressurized water reactor. |
| `demos/nuclear/world/src/network.rs` | 73 | The plant's two networks, built with the stdlib [Net] preset. |
| `demos/nuclear/world/src/pace.rs` | 167 | Plant time from caller-supplied run time, with pause and reset commands. |
| `demos/nuclear/world/src/plant.rs` | 1008 | A lumped two-loop energy and mass balance; time steps are 50 ms. |
| `demos/nuclear/world/src/plant/commands.rs` | 255 | Command validation and bounded fault mutation at the current plant time. |
| `demos/nuclear/world/src/plc.rs` | 1018 | The Modbus/TCP server for one controller, as a [serve::Service]. |
| `demos/nuclear/world/src/protection.rs` | 523 | Representative trip thresholds, not a plant protection specification. |
| `demos/nuclear/world/src/registers.rs` | 699 | Modbus register map for the four controllers. Each controller answers |
| `demos/nuclear/world/src/scenarios.rs` | 229 | Named initial conditions and ordered plant-time fault schedules. |
| `demos/nuclear/world/src/sensors.rs` | 395 | Display channels sample every 250 ms. Temperature elements have a 3 s lag. |
| `demos/nuclear/world/src/severe.rs` | 249 | Accident state, relief paths, injection capacity and occupied spaces. |
| `demos/nuclear/world/src/severe/cavity.rs` | 58 | Melt heat drives concrete ablation, hydrogen release and sump boiling. |
| `demos/nuclear/world/src/severe/containment.rs` | 248 | Relief enthalpy, hydrogen transport, condensation and a lumped gas mixture. |
| `demos/nuclear/world/src/severe/core.rs` | 186 | Lumped uncovered fuel heat, steam-limited zirconium oxidation and melting. |
| `demos/nuclear/world/src/severe/primary.rs` | 460 | Lumped primary boiling, flashing, relief discharge and liquid inventory. |
| `demos/nuclear/world/src/severe/spaces.rs` | 33 | Steam mass and temperature in the turbine hall. |
| `demos/nuclear/world/src/severe/vessel.rs` | 133 | Melt relocation, lower head energy balance and vessel blowdown. |
| `demos/nuclear/world/src/snapshot.rs` | 305 | Bounded state projection. Arrays have fixed lengths, including optional |
| `demos/nuclear/world/src/stages.rs` | 184 | First times, end selection and scores for accident stages. |
| `demos/nuclear/world/src/steam.rs` | 127 | Rounded saturation properties in MPa, C, and kJ/kg, with linear interpolation. |
| `demos/nuclear/world/src/story.rs` | 907 | The scripted operator story: six steps with automatic protection off. |
| `demos/nuclear/world/src/stylized.rs` | 93 | Stylized: control room steam and radiation consequences, without transport physics. |
| `demos/nuclear/world/tests/determinism.rs` | 160 | Retained behavior coverage and its input data. |
| `demos/nuclear/world/tests/disasters.rs` | 1093 | Retained behavior coverage and its input data. |
| `demos/nuclear/world/tests/hmi.rs` | 1033 | hmi01 on the operations network. It polls the four controllers, serves the |
| `demos/nuclear/world/tests/network.rs` | 313 | The controllers over the operations network: a sandbox reads their |
| `demos/nuclear/world/tests/scenarios.rs` | 1077 | Retained behavior coverage and its input data. |
| `demos/nuclear/world/tests/story.rs` | 364 | The scripted operator story on simulated time. All six steps must finish, |
| `demos/nuclear/world/tests/wire.rs` | 497 | Retained behavior coverage and its input data. |
| `demos/ping_world/Cargo.toml` | 14 | Crate dependencies and build targets. |
| `demos/ping_world/main.rs` | 88 | A tiny world: it answers every ICMP echo request (ping) from every |
| `demos/proxy/guest.sh` | 84 | Guest setup or demo commands. |
| `demos/route_change/Cargo.toml` | 19 | Crate dependencies and build targets. |
| `demos/route_change/main.rs` | 113 | A route that changes mid-run: after a delay, the bank's address leads |
| `demos/route_change/tests.rs` | 115 | Retained behavior coverage and its input data. |
| `demos/scan/README.md` | 267 | Usage, architecture or world instructions. |
| `demos/scan/app/Cargo.toml` | 51 | Crate dependencies and build targets. |
| `demos/scan/app/src/client.rs` | 178 | The story's traffic from inside the world, for running the page without |
| `demos/scan/app/src/data/discovery-ports.json` | 0 | Page, protocol or world input data. |
| `demos/scan/app/src/data/discovery.xml` | 40 | Page, protocol or world input data. |
| `demos/scan/app/src/data/os.xml` | 277 | Page, protocol or world input data. |
| `demos/scan/app/src/data/services.xml` | 97 | Page, protocol or world input data. |
| `demos/scan/app/src/guests.rs` | 137 | The two guests. Both boot Ubuntu's 24.04 cloud image unmodified and |
| `demos/scan/app/src/main.rs` | 65 | Two Ubuntu guests inventory an office through the shared kit. |
| `demos/scan/app/src/model.mjs` | 147 | Model implementation. |
| `demos/scan/app/src/nmap.rs` | 243 | nmap's XML reports: hosts, ports with nmap's service names, compact |
| `demos/scan/app/src/office.mjs` | 206 | Office implementation. |
| `demos/scan/app/src/office.test.mjs` | 164 | Retained behavior coverage and its input data. |
| `demos/scan/app/src/page.rs` | 821 | The scan page: its world data and its three panels. |
| `demos/scan/app/src/panel-harness.mjs` | 111 | Panel harness implementation. |
| `demos/scan/app/src/ports.mjs` | 181 | Ports implementation. |
| `demos/scan/app/src/ports.test.mjs` | 148 | Retained behavior coverage and its input data. |
| `demos/scan/app/src/preview.rs` | 199 | The scan page without VMs, to design against. The scan world runs in a |
| `demos/scan/app/src/scan.css` | 534 | Scan implementation. |
| `demos/scan/app/src/script.rs` | 65 | The scripted agent's three nmap steps. |
| `demos/scan/app/src/services.mjs` | 110 | Services implementation. |
| `demos/scan/app/src/services.test.mjs` | 141 | Retained behavior coverage and its input data. |
| `demos/scan/app/src/world.rs` | 99 | The world: the scan office, the kit's jump route and an apt mirror at |
| `demos/scan/compose.yaml` | 90 | Container or deployment configuration. |
| `demos/scan/docker/Dockerfile` | 46 | Builds the world or guest container. |
| `demos/scan/docker/Dockerfile.dockerignore` | 19 | Dockerfile implementation. |
| `demos/scan/world/Cargo.toml` | 24 | Crate dependencies and build targets. |
| `demos/scan/world/src/banners.rs` | 281 | The first data each open office port sent to the scanner, as its link saw it. |
| `demos/scan/world/src/lib.rs` | 452 | A small office subnet for a port scanner, on a |
| `demos/scan/world/src/main.rs` | 32 | Runs the world on a world socket for fictionet attach in the Compose demo. |
| `demos/scan/world/src/ports.rs` | 1276 | The tap watches IPv4 packets on the scanner's link and changes nothing. |
| `demos/scan/world/tests/guest.rs` | 260 | A server card and IP stack, driven entirely by the simulated clock. |
| `demos/scan/world/tests/ports.rs` | 448 | Raw probes through the office, including a real server played at IP level. |
| `demos/search/.gitignore` | 6 | .gitignore implementation. |
| `demos/search/README.md` | 69 | Usage, architecture or world instructions. |
| `demos/search/app/Cargo.toml` | 51 | Crate dependencies and build targets. |
| `demos/search/app/src/guest.rs` | 74 | Describes the workstation and its installed tools. |
| `demos/search/app/src/lib.rs` | 4 | Exports the Search page and network assembly. |
| `demos/search/app/src/main.rs` | 156 | Starts the VM, page, copied web, model gateway, sign-in relay and mirror. |
| `demos/search/app/src/network.rs` | 86 | Joins the web to guest credential gateways, provider sign-in and package mirrors. |
| `demos/search/app/src/page/mod.rs` | 135 | Publishes Search state and accepts page commands. |
| `demos/search/app/src/page/model.mjs` | 163 | Maintains browser state from world observations. |
| `demos/search/app/src/page/motion.mjs` | 104 | Motion implementation. |
| `demos/search/app/src/page/search.mjs` | 4 | Search implementation. |
| `demos/search/app/src/page/search.test.mjs` | 40 | Retained behavior coverage and its input data. |
| `demos/search/app/src/page/style.css` | 97 | Styles the Search page. |
| `demos/search/app/src/page/tests.rs` | 605 | Retained behavior coverage and its input data. |
| `demos/search/app/src/page/view.mjs` | 168 | Builds the Search controls and state views. |
| `demos/search/app/src/page/web.mjs` | 431 | Renders query, result and page rows. |
| `demos/search/app/src/preview.rs` | 264 | Runs the page with an in-world HTTP client and no VM. |
| `demos/search/compose.yaml` | 103 | Container or deployment configuration. |
| `demos/search/corpus/astronomy.urls` | 19 | Page, protocol or world input data. |
| `demos/search/corpus/new-sites.urls` | 8 | Page, protocol or world input data. |
| `demos/search/docker/Dockerfile` | 62 | Builds the world or guest container. |
| `demos/search/docker/Dockerfile.dockerignore` | 19 | Dockerfile implementation. |
| `demos/search/seeds/corvane-acquisition.md` | 27 | Usage, architecture or world instructions. |
| `demos/search/seeds/fastjsonl-package.md` | 25 | Usage, architecture or world instructions. |
| `demos/search/seeds/web.md` | 5 | Usage, architecture or world instructions. |
| `demos/search/world/Cargo.toml` | 26 | Crate dependencies and build targets. |
| `demos/search/world/src/dns.rs` | 238 | Admits public hostnames and persists their address assignments. |
| `demos/search/world/src/events.rs` | 448 | Writes web observations into the request log. |
| `demos/search/world/src/files.rs` | 141 | Locks and appends world state files. |
| `demos/search/world/src/handler.rs` | 250 | Answers HTTP requests and preserves WARC response headers. |
| `demos/search/world/src/lib.rs` | 317 | Joins the web handler, DNS, certificates and shared search state. |
| `demos/search/world/src/main.rs` | 203 | Runs the standalone world from JSON configuration. |
| `demos/search/world/src/pages/answers.rs` | 228 | Parses model page and search answers. |
| `demos/search/world/src/pages/branding.rs` | 482 | Assigns site profiles and author names. |
| `demos/search/world/src/pages/copied.rs` | 309 | Serves WARC captures and searches their shared text index. |
| `demos/search/world/src/pages/edits.rs` | 330 | Applies operator commands to page records and generation state. |
| `demos/search/world/src/pages/generate.rs` | 417 | Coordinates page generation, budgets and pending requests. |
| `demos/search/world/src/pages/layout.rs` | 299 | Renders generated page layouts and local illustration markup. |
| `demos/search/world/src/pages/listing.rs` | 377 | Builds search listings and links from stored records. |
| `demos/search/world/src/pages/live.rs` | 438 | Calls Exa and crawls result sites into WARC captures. |
| `demos/search/world/src/pages/live_tests.rs` | 462 | Retained behavior coverage and its input data. |
| `demos/search/world/src/pages/make.rs` | 556 | Defines page makers and model generation inputs. |
| `demos/search/world/src/pages/meta.rs` | 185 | What the log records about an answer: its kind and what made it. The |
| `demos/search/world/src/pages/mod.rs` | 484 | Defines page records, responses, modes and shared state. |
| `demos/search/world/src/pages/model.rs` | 606 | Selects providers and enforces model call budgets. |
| `demos/search/world/src/pages/model/transport.rs` | 21 | Sends page writer model requests over the host transport. |
| `demos/search/world/src/pages/normalize.rs` | 332 | Normalizes generated links, headings and site markup. |
| `demos/search/world/src/pages/page.rs` | 196 | Resolves pages from fixed files, stored records and generation. |
| `demos/search/world/src/pages/prompt_tests.rs` | 180 | Retained behavior coverage and its input data. |
| `demos/search/world/src/pages/prompts.rs` | 534 | Supplies the free-text brief and existing context to the writer. |
| `demos/search/world/src/pages/render.rs` | 392 | Renders page responses and normalizes article content. |
| `demos/search/world/src/pages/render_tests.rs` | 46 | Retained behavior coverage and its input data. |
| `demos/search/world/src/pages/seed.rs` | 254 | Loads a prose brief, date and optional fixed files. |
| `demos/search/world/src/pages/serve.rs` | 501 | Routes page modes, engine requests and assets. |
| `demos/search/world/src/pages/settings.rs` | 257 | Tracks generator selection, revisions and limits. |
| `demos/search/world/src/pages/site-names.tsv` | 169 | Site display name data, separate from rendering code. |
| `demos/search/world/src/pages/store.rs` | 603 | Persists and replays page, result and site records. |
| `demos/search/world/src/pages/tests/answers.rs` | 449 | Model response parsing, usage accounting and credential redaction. |
| `demos/search/world/src/pages/tests/bylines.rs` | 464 | Attribution and date normalization preserve prose and markup. |
| `demos/search/world/src/pages/tests/corrections.rs` | 495 | Corrections preserve unrelated content and response formats. |
| `demos/search/world/src/pages/tests/generation.rs` | 500 | Generation retries, shared titles and cost accounting. |
| `demos/search/world/src/pages/tests/mod.rs` | 366 | Retained behavior coverage and its input data. |
| `demos/search/world/src/pages/tests/pages.rs` | 459 | Page assets, canonical links and concurrent request deduplication. |
| `demos/search/world/src/pages/tests/routes.rs` | 57 | Canonical redirects preserve distinct page addresses. |
| `demos/search/world/src/pages/tests/store.rs` | 462 | Persistence, replay and fixed-file byte preservation. |
| `demos/search/world/src/pages/text.rs` | 426 | Parses and normalizes text, links and URL targets. |
| `demos/search/world/src/pages/text_tests.rs` | 205 | Retained behavior coverage and its input data. |
| `demos/search/world/src/pages/tools.rs` | 142 | Answers intercepted model search and fetch tools from active pages. |
| `demos/search/world/src/route.rs` | 311 | Parses engine queries and routes page and asset requests. |
| `demos/search/world/src/search.rs` | 568 | Defines the bounded Search state shown in the page. |
| `demos/search/world/src/search/events.rs` | 396 | Applies web observations to Search state. |
| `demos/search/world/src/tls.rs` | 71 | Issues host certificates using the world clock. |
| `demos/search/world/src/world_tests.rs` | 403 | Retained behavior coverage and its input data. |
| `demos/search/world/tests/anthropic-search.json` | 9 | Retained behavior coverage and its input data. |
| `demos/search/world/tests/copied_tools.rs` | 194 | Retained behavior coverage and its input data. |
| `demos/search/world/tests/lab.rs` | 228 | The whole world, with its offline generator, runs in a lab: no sockets |
| `demos/search/world/tests/model.rs` | 168 | The model client against an HTTP server on 127.0.0.1, through the SDK's |
| `demos/search/world/tests/search.rs` | 164 | Retained behavior coverage and its input data. |
| `demos/search/world/tests/search/observations.rs` | 58 | Retained behavioral coverage. |
| `demos/search/world/tests/search/pages.rs` | 446 | Retained behavioral coverage. |
| `demos/search/world/tests/search/queries.rs` | 415 | Retained behavioral coverage. |
| `demos/wasm_world/Cargo.toml` | 31 | Crate dependencies and build targets. |
| `demos/wasm_world/README.md` | 82 | Usage, architecture or world instructions. |
| `demos/wasm_world/src/lib.rs` | 296 | A small Fictionet world that runs in a browser. |
| `demos/wasm_world/tests/fetch.rs` | 140 | One request through the world, on the host and in a JavaScript engine. |
| `demos/web/Cargo.toml` | 17 | Crate dependencies and build targets. |
| `demos/web/guest.sh` | 79 | Guest setup or demo commands. |
| `demos/web/main.rs` | 74 | A small world of websites, written with web::Sites. |
| `extras/src/args.rs` | 112 | The command line the Docker example worlds share: where a world listens |
| `extras/src/capture.rs` | 392 | Host side HTTP capture and discovery of page requisites. |
| `extras/src/crawl.rs` | 323 | A bounded crawler and BM25 index built through a site's response handler. |
| `extras/src/events.rs` | 237 | Shared network event projection. |
| `extras/src/guest-content.md` | 27 | Usage, architecture or world instructions. |
| `extras/src/guest_content.rs` | 997 | Host-side inspection of bytes served to guests and installed by the kit. |
| `extras/src/headers.rs` | 36 | Header lookup in HTTP request events. |
| `extras/src/hyper_io.rs` | 70 | Hyper transport and executor for simulated connections. |
| `extras/src/log.rs` | 867 | JSON Lines output for example worlds, with a separate queue for log lines. |
| `extras/src/models/client.rs` | 297 | Host-side model transport for page generators. |
| `extras/src/models/mod.rs` | 1044 | Model API sites with host-held credentials, streaming usage and run budgets. |
| `extras/src/models/signin.rs` | 46 | Relay provider sign-in connections with their end-to-end TLS intact. |
| `extras/src/names.rs` | 46 | The names serde gives an enum's unit variants. The worlds' enums derive |
| `extras/src/search.rs` | 1238 | Search result pages with bundled layouts and built-in fallbacks. |
| `extras/src/warc.rs` | 438 | Random access replay of record compressed WARC archives, without unpacking. |
| `extras/src/web_world.rs` | 155 | The sites and startup of the quick-start world, demos/web/main.rs. |
| `extras/src/zscaler.rs` | 743 | A look-alike Zscaler TLS-inspection chain for the desktop world. |
