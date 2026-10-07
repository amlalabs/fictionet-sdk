//! Attaching sandboxes: how to connect a sandbox to a world, wherever the
//! sandbox runs.
//!
//! Read this page when you have a world running and want an agent's
//! sandbox to use it as its network. Start with the table below to pick a
//! setup, then read that setup's section. The sections at the end
//! ([Addresses](#addresses), [DNS and `resolv.conf`](#dns-and-resolvconf)
//! and [Checking that it works](#checking-that-it-works)) apply to every
//! `tun` setup, and [Every flag](#every-flag) lists the flags of
//! `fictionet attach` with a link to where each is explained. If you have
//! not attached a sandbox before, walk through
//! [`getting_started`](crate::getting_started) first.
//!
//! `fictionet attach` is a relay. You run one next to each sandbox,
//! wherever it can get at the sandbox's packets. It connects to the world's
//! socket, tells the world the sandbox's name (`--name`), and then moves
//! packets both ways until one side stops. The world gets each sandbox as
//! an [`Attachment`](crate::Attachment), an
//! [`Interface`](crate::Interface) like any other. Whatever the setup, the
//! world only ever sees IP packets.
//! [`lowering`](crate::lowering) shows how each attach type turns its
//! sandbox's traffic into those packets, step by step.
//!
//! # Choose your setup
//!
//! | Setup | Choose it when | Attach type |
//! |---|---|---|
//! | [A namespace on the host](#on-a-host-with-ip-netns) | you run the agent on a Linux machine you control, with no containers, as a test harness often does | `tun` |
//! | [Docker Compose](#in-docker-compose) | the agent runs in a container | `tun` |
//! | [Kubernetes](#on-kubernetes) | the agent runs in a pod, for example through Inspect's k8s sandbox, and the cluster lets one container have `NET_ADMIN` | `tun` |
//! | [Hosted: Daytona and E2B](#hosted-sandboxes) | the agent runs in a provider's sandbox that can run Docker inside it | `tun`, through Docker Compose |
//! | [No privileges: a proxy](#behind-a-proxy-http_proxy-and-socks5) | the sandbox may not have `NET_ADMIN` or `/dev/net/tun` (for example, under Kubernetes Pod Security "restricted"), and the agent's traffic is HTTP, HTTPS or other TCP | `http_proxy` or `socks5` |
//! | [A virtual machine](#a-virtual-machine-with-tap) | the agent runs in a VM of your own, under QEMU, Firecracker or Cloud Hypervisor | `tap` |
//!
//! Attaching remote sandboxes and tailnets is on the
//! [roadmap](crate::roadmap).
//!
//! The kinds of attach type work differently:
//!
//! - **`tun`** gives the sandbox a network device, `tun0`, and routes its
//!   traffic through it. In a namespace with no other way out, every
//!   packet the sandbox's kernel sends goes to the world, so every program
//!   works without any settings: `curl`, `dig`, `ping`, `traceroute`, raw
//!   sockets. Attach needs `NET_ADMIN` in the sandbox's network namespace
//!   to make the device. The agent needs no privileges, and runs without
//!   `NET_ADMIN`, so it cannot change its own network.
//! - **`http_proxy` and `socks5`** give the sandbox nothing new. Attach
//!   runs outside the sandbox as a proxy, and the agent's programs connect
//!   through it. Attach turns each proxied connection into IP packets from
//!   the sandbox's address, made by its own TCP/IP stack. This needs no
//!   privileges anywhere, but it only carries TCP over IPv4 from programs
//!   that use the proxy.
//! - **`tap`** is for a virtual machine. Attach sits on the host side of
//!   the VM's network card and takes its Ethernet frames. Attach answers
//!   ARP and neighbor discovery itself, and passes the VM's IP packets
//!   from its own addresses to the world. The agent may even be root
//!   inside the VM.
//!
//! The [relay protocol](crate::proto) describes what attach and the world
//! say to each other.
//!
//! # How `tun` works
//!
//! The first four setups use `--type tun`. This section says what attach
//! needs and what it does, so that the setups that follow make sense.
//!
//! Attach needs these privileges:
//!
//! - **`CAP_NET_ADMIN`** in the network namespace where it makes the
//!   device, and access to `/dev/net/tun`. If the device node is missing,
//!   as in a Kubernetes container, attach makes it, which also needs
//!   `CAP_MKNOD`.
//! - **`CAP_SYS_ADMIN` as well, if you give `--netns`.** To enter another
//!   network namespace, attach calls `setns(fd, CLONE_NEWNET)`. Linux allows
//!   that only with `CAP_SYS_ADMIN`, both in attach's own user namespace and
//!   in the user namespace that owns the target. Attach also opens the
//!   `--netns` path, so it needs read access to that file. Root on the host
//!   has all of this.
//!
//! Without `--netns`, attach makes the device in the namespace it already
//! runs in, and `CAP_NET_ADMIN` is enough. The Docker Compose and
//! Kubernetes setups work this way. The sandbox needs none of these
//! privileges.
//!
//! When it starts, attach does these steps in order:
//!
//! 1. It enters the network namespace given with `--netns`, if any.
//! 2. It takes down each link given with `--down-link`, such as a pod's
//!    `eth0`. It deletes the link's IPv4 and IPv6 routes and addresses, and
//!    sets the link down. See [On Kubernetes](#on-kubernetes).
//! 3. It makes a TUN device. The kernel picks the name, usually `tun0`. If
//!    `/dev/net/tun` is missing, attach makes it first.
//! 4. It sets the device's MTU (`--mtu`, 1500 by default), its addresses
//!    and its default routes ([Addresses](#addresses)), and brings it up.
//! 5. It connects to the world's socket (`--world`), sends a `hello` with
//!    the sandbox's name, and waits for the world to accept it (the
//!    [relay protocol](crate::proto) has the messages). If the world
//!    refuses, for example because that name is already attached, attach
//!    exits with status 3. With
//!    `--world-wait <seconds>`, attach keeps trying for that long while the
//!    socket is missing or nothing listens on it yet.
//! 6. It writes the DNS servers to a `resolv.conf`, unless you give
//!    `--no-resolv-conf`. [DNS and `resolv.conf`](#dns-and-resolvconf) says
//!    which file.
//! 7. It creates the file named with `--ready-file <path>`, if you give
//!    one, so that a harness knows when to start the agent. Attach removes
//!    the file when it exits. `fictionet ready <path>` exits with status 0
//!    if that file exists, and 1 if not. It is meant for a readiness probe
//!    in an image that has no shell.
//! 8. It moves packets until the world closes the connection, and then
//!    exits with status 0. SIGTERM, SIGINT or SIGHUP also stop it. Either
//!    way, the device goes away and the world sees the sandbox detach.
//!
//! **`tun0` is the only way out when nothing else is.** Attach adds the
//! default routes through `tun0` and takes down the links named with
//! `--down-link`. It changes nothing else in the namespace. Any other
//! interface that is up keeps its addresses and routes, and traffic to
//! those addresses bypasses the world. So the harness must give the sandbox
//! a namespace with no other path out. Each setup below does this: a new
//! namespace from `ip netns add` has only `lo`, the Compose file gives
//! attach `network_mode: none`, and in a pod attach takes down `eth0` with
//! `--down-link`. The agent must also run without `NET_ADMIN`, so that it
//! cannot bring a link back up or add a route of its own.
//!
//! # On a host, with `ip netns`
//!
//! The simplest setup needs no containers at all. The sandbox is a Linux
//! network namespace. `fictionet attach` runs on the host and puts a `tun0`
//! device inside that namespace. Then you start the agent inside the
//! namespace with `ip netns exec`. [`getting_started`](crate::getting_started)
//! walks through this by hand.
//!
//! A network namespace isolates networking only. Inside it, the only
//! interfaces are loopback and `tun0`, but the agent still shares the host's filesystem,
//! users and processes. The script below runs the agent as a user of its
//! own for that reason. When the agent needs more isolation than that, run
//! it in a container, a Kubernetes pod or a VM, as the setups after this
//! one do. Fictionet supplies the sandbox's network. The harness supplies
//! the rest of the sandbox, and decides what the agent may do.
//!
//! The script `examples/attach/netns.sh` does what
//! [`getting_started`](crate::getting_started) does, in one go, the way a
//! test harness would. It makes the namespace and gives it its own
//! `nsswitch.conf` (see
//! [why](crate::getting_started#when-dig-works-but-programs-cannot-resolve-names)),
//! starts attach, waits until attach is ready, and runs one command as the agent. When the command
//! ends, or the script is stopped, it stops attach and removes the
//! namespace. This is the whole file:
//!
#![cfg_attr(doc, doc = concat!("```sh\n", include_str!("../examples/attach/netns.sh"), "```"))]
//!
//! The loop in the middle waits for attach's ready file, so the agent never
//! starts without a network. `--world-wait 5` lets attach wait up to 5
//! seconds for a world that is still starting. The script stops early in
//! each case where the agent would get no network:
//!
//! - **A ready file is left from an earlier run.** The script removes it
//!   before attach starts, so only this attach can write it. (Attach
//!   removes it too, but the loop could look before attach gets that far.)
//! - **Attach exits.** If the world socket is still missing after 5
//!   seconds, or the world refuses the name, attach exits, and the loop
//!   reports its exit status. For example:
//!   `fictionet attach: connecting to the world at /run/fictionet/world.sock: No such file or directory (os error 2), after waiting 5 s`,
//!   then `attach exited with status 1 before it was ready`.
//! - **Attach hangs.** The loop gives up after 10 seconds. A world that
//!   never answers `hello` is one cause.
//!
//! The last lines start the agent with `setsid`, in a session of its own.
//! The terminal is then not the agent's controlling terminal, so the agent
//! cannot push keystrokes into the root shell that ran the script (with the
//! `TIOCSTI` ioctl, on kernels that still allow it). The agent runs in the
//! background while the script waits for it. So when the script gets
//! SIGTERM or Ctrl-C, `cleanup` runs immediately: it sends SIGTERM to the
//! agent's whole process group, then stops attach and removes the
//! namespace. `runuser` gives the agent 2 seconds before it kills it.
//!
//! ## Run it on a host
//!
//! You need Linux, a root shell, iproute2, curl, and Rust 1.91 or later.
//! Run these from the top directory of the repository.
//!
//! **1. Build** `fictionet` and the `web_world` example, and put both on
//! root's `PATH`:
//!
//! ```sh
//! cargo build --release --bin fictionet --example web_world
//! install target/release/fictionet target/release/examples/web_world /usr/local/bin/
//! ```
//!
//! **2. Start the world,** and add the user the agent runs as.
//! `web_world` listens on the socket, and writes its CA certificate to the
//! second path:
//!
//! ```sh
//! mkdir -p /run/fictionet
//! web_world /run/fictionet/world.sock /run/fictionet/ca.pem &
//! world=$!
//! useradd --system agent
//! ```
//!
//! **3 and 4. Run the agent, and check that it works.** Each run of the
//! script attaches a new namespace, runs one command in it, and removes
//! it again:
//!
//! ```text
//! # examples/attach/netns.sh curl -sS --cacert /run/fictionet/ca.pem https://example.test/
//! fictionet attach: agent attached as tun0
//! lookup example.test
//! hello from https example.test 443 over HTTP/2.0
//! # examples/attach/netns.sh ip -br addr
//! fictionet attach: agent attached as tun0
//! lo               UNKNOWN        127.0.0.1/8 ::1/128
//! tun0             UNKNOWN        10.0.0.2/24 2001:db8::2/64 fe80::9f59:abb7:ab11:68f8/64
//! # examples/attach/netns.sh id
//! fictionet attach: agent attached as tun0
//! uid=999(agent) gid=999(agent) groups=999(agent)
//! # examples/attach/netns.sh curl -sS -m 5 https://1.1.1.1/
//! fictionet attach: agent attached as tun0
//! curl: (7) Failed to connect to 1.1.1.1 port 443 after 0 ms: Couldn't connect to server
//! ```
//!
//! The first line of each run is attach's. `lookup example.test` is the
//! world's log, from the background job. The world has no machine at
//! `1.1.1.1`, so that connection fails immediately.
//!
//! **5. Clean up:**
//!
//! ```sh
//! kill "$world"
//! userdel agent
//! rm -rf /run/fictionet /usr/local/bin/fictionet /usr/local/bin/web_world
//! ```
//!
//! This was run in a root shell on Debian 12, with iproute2 6.1. The build
//! took 64 s from a clean checkout, and each run of the script, from
//! `ip netns add` to the namespace being removed, took about 0.13 s.
//!
//! ## What the script relies on
//!
#![doc = include_str!("../docs/diagrams/attach-tun-netns.svg")]
//!
//! **Attach sets the address.** It enters `/run/netns/agent` before it
//! makes `tun0`, so the device and its addresses are in that namespace.
//!
//! **Attach writes `/etc/netns/agent/resolv.conf` on the host.** It takes
//! the name, `agent`, from the last part of the `--netns` path, so give a
//! path under `/run/netns/`, where `ip netns add` puts namespaces. Attach
//! mounts nothing, and it leaves the host's own `/etc/resolv.conf` alone.
//!
//! **`ip netns exec agent <command>` puts that file in place.** It makes a
//! new mount namespace for the command, and bind-mounts each file in
//! `/etc/netns/agent/` over the file of the same name in `/etc`. So the
//! command and its children see `/etc/netns/agent/resolv.conf` at
//! `/etc/resolv.conf`. Every other process, including the host and attach,
//! still sees the host's file. (`man ip-netns` describes this. It was
//! checked with iproute2 7.2.)
//!
//! This has two consequences:
//!
//! - **Start the agent after attach is ready.** `ip netns exec` only mounts
//!   files that exist when it starts. Attach writes the file once the world
//!   has accepted it, and writes the ready file after that.
//! - **Only `ip netns exec` does this.** A process that enters the
//!   namespace another way, such as with `nsenter --net=/run/netns/agent`,
//!   runc, or a container runtime with its own mounts, keeps the
//!   `resolv.conf` it had. Its harness must set DNS itself, or tell attach
//!   where that process reads it, with
//!   [`--resolv-conf`](#--resolv-conf-and---no-resolv-conf).
//!
//! **Give the agent the world's CA without changing the host.** The agent
//! shares the host's filesystem, so don't run `update-ca-certificates`
//! here: it would change the host's trust store. Point the agent's
//! programs at the CA file instead, with `SSL_CERT_FILE` for programs that
//! read it, or a flag such as curl's `--cacert`. A sandbox-wide trust store
//! belongs in the sandbox's own image, as in the container setups below.
//!
//! # In Docker Compose
//!
//! Use this setup when the agent runs in a container. It has three
//! containers: the world, attach, and the agent. Attach makes `tun0` in its
//! own network namespace, and the agent joins that namespace with
//! `network_mode: "service:attach"`. So the agent's only interface,
//! besides loopback, is `tun0`, and it has no privileges of its own. The world and attach share
//! the world socket through a volume. The agent gets the world's CA
//! certificate through another volume, and nothing else of the world.
//!
//! The file is `examples/attach/compose-tun.yaml` in the crate's
//! repository, shown here whole. Notice the start order. The world starts
//! first. Attach waits up to 30 seconds for the world's socket
//! (`--world-wait`), and its healthcheck passes once the world has
//! accepted it. The agent starts only after that healthcheck passes
//! (`depends_on` with `service_healthy`), so it never runs without a
//! network.
//!
#![cfg_attr(doc, doc = concat!("```yaml\n", include_str!("../examples/attach/compose-tun.yaml"), "```"))]
//!
//! ## The images
//!
//! `deploy/Dockerfile` builds the three images that both Compose files and
//! the Kubernetes chart use. Compose builds them for you from the `build`
//! entries above. To build them by hand, as for Kubernetes, run these from
//! the top directory of the repository:
//!
//! ```sh
//! docker build -f deploy/Dockerfile --target attach -t fictionet-attach:dev .
//! docker build -f deploy/Dockerfile --target web-world -t fictionet-web-world:dev .
//! docker build -f deploy/Dockerfile --target agent -t fictionet-agent:dev .
//! ```
//!
//! - `fictionet-attach` holds one static binary, `/fictionet`, linked with
//!   musl, on `scratch`. It runs `fictionet attach`, and `fictionet ready`
//!   for the healthcheck, since the image has no shell.
//! - `fictionet-web-world` holds the `web_world` example the same way, run
//!   as uid 65532. A world of your own needs an image like it.
//! - `fictionet-agent` is Debian with curl, dig, ip and ping, and a user
//!   `agent` (uid 1000). It has nothing of Fictionet, and stands in for the
//!   agent's sandbox. Any image works there.
//!
//! `docker images` listed them at 3.5 MB, 10 MB and 203 MB.
//!
//! ## Run it with Compose
//!
//! You need Linux with `/dev/net/tun`, and Docker Engine with Compose v2.
//! Run these from the top directory of the repository. The first build compiles the crate in
//! Docker, and took 3.5 minutes. With the images built, starting took 3 to
//! 6 s, and removing it all took 0.7 to 1.1 s.
//!
//! ```text
//! $ docker compose -f examples/attach/compose-tun.yaml build
//! $ docker compose -f examples/attach/compose-tun.yaml up -d --wait
//! $ docker compose -f examples/attach/compose-tun.yaml exec agent curl -sS --cacert /run/ca/ca.pem https://example.test/
//! hello from https example.test 443 over HTTP/2.0
//! $ docker compose -f examples/attach/compose-tun.yaml down -v
//! ```
//!
#![doc = include_str!("../docs/diagrams/attach-tun-compose.svg")]
//!
//! From inside the agent's container
//! (`docker compose -f examples/attach/compose-tun.yaml exec agent ...`),
//! the network looks like this:
//!
//! ```text
//! $ ip addr show tun0
//! 2: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 500
//!     link/none
//!     inet 10.0.0.2/24 scope global tun0
//!        valid_lft forever preferred_lft forever
//!     inet6 2001:db8::2/64 scope global nodad
//!        valid_lft forever preferred_lft forever
//!     inet6 fe80::7533:5b3d:12c5:753d/64 scope link stable-privacy
//!        valid_lft forever preferred_lft forever
//! $ ip route
//! default via 10.0.0.1 dev tun0 proto static onlink
//! 10.0.0.0/24 dev tun0 proto kernel scope link src 10.0.0.2
//! $ ip -6 route
//! 2001:db8::/64 dev tun0 proto kernel metric 256 pref medium
//! fe80::/64 dev tun0 proto kernel metric 256 pref medium
//! default via 2001:db8::1 dev tun0 proto static metric 1024 onlink pref medium
//! $ cat /etc/resolv.conf
//! # Written by fictionet attach.
//! nameserver 10.0.0.1
//! nameserver 2001:db8::1
//! $ ls /sys/class/net
//! lo
//! tun0
//! ```
//!
//! **Attach sets the address,** in the network namespace the two containers
//! share.
//!
//! **Attach writes `resolv.conf`, and the agent reads the same file.** The
//! two containers share a network namespace, but not a mount namespace, so
//! each has its own `/etc`. They still share `resolv.conf` because of how
//! Docker sets it up. Docker keeps each container's `resolv.conf` as a file
//! on the host, under `/var/lib/docker/containers/<id>/`, and bind-mounts
//! it at `/etc/resolv.conf`. A container started with
//! `network_mode: "service:attach"` (`docker run --network container:...`)
//! is given the file of the container it joins, not one of its own. So
//! attach and the agent have one host file mounted in two places.
//! `docker inspect -f '{{.ResolvConfPath}}'` prints the same path for both.
//!
//! Attach rewrites that file in place, so the change shows through both
//! mounts. (Renaming a new file over `/etc/resolv.conf` would fail, because
//! the path is a mount point.) The agent must start after attach is ready,
//! which is what the `--ready-file` healthcheck is for. Programs read the
//! file again when it changes, but a program that started earlier may have
//! cached the old servers.
//!
//! # On Kubernetes
//!
//! Use this setup when the agent runs in a pod, for example through
//! Inspect's k8s sandbox. The Helm chart `charts/fictionet-sandbox` runs
//! sandboxes on Kubernetes 1.29 or later. Inspect's k8s sandbox takes it as
//! a custom chart, and any other harness can install it with `helm`. Each
//! entry under `services` becomes one pod with three containers. All the
//! containers of a pod share one network namespace, so attach makes `tun0`
//! in the agent's namespace without `--netns`.
//!
//! - **The agent's container** is the first entry in `containers`, so
//!   Inspect runs its commands there. Every capability is dropped,
//!   including `NET_RAW` and `NET_ADMIN`.
//! - **`world`** is a native sidecar: an init container with
//!   `restartPolicy: Always`, which keeps running beside the agent. It
//!   listens on `/run/relay/relay.sock`, in an `emptyDir` that only it
//!   and attach mount.
//! - **`attach`** is a native sidecar too, started after the world. It is
//!   the only container with `NET_ADMIN`.
//!
//! This section covers `attach.type: tun`, the default. If your cluster
//! enforces Pod Security "baseline" or "restricted", use `http_proxy` or
//! `socks5` instead: no container then needs a privilege. See
//! [The proxy on Kubernetes](#the-proxy-on-kubernetes).
//!
#![doc = include_str!("../docs/diagrams/attach-tun-pod.svg")]
//!
//! A pod is not an empty namespace, and Kubernetes gives a container no
//! tun device node, so attach needs more there than in Docker Compose.
//! The chart sets all of it up:
//!
//! - **`--down-link eth0`.** The CNI gives every pod an `eth0`, with an
//!   address and a default route. Without this flag, attach fails when it
//!   adds its own default route:
//!
//!   ```text
//!   fictionet attach: configuring tun0: adding the IPv4 default route: another link already has one (File exists (os error 17)). Give --down-link <ifname> for that link (in a Kubernetes pod, --down-link eth0), or remove its default route first
//!   ```
//!
//!   With the flag, attach first deletes every route through `eth0`, in
//!   every routing table, then deletes `eth0`'s IPv4 and IPv6 addresses,
//!   and sets the link down. It deletes the routes itself rather than rely
//!   on the link going down, so the result does not depend on the kernel.
//!   (gVisor has its own network stack, and it ignores the request to set
//!   the link down: see [gVisor](#gvisor).) You can give the flag more than
//!   once.
//! - **`/dev/net/tun`.** Kubernetes gives a container no tun device node.
//!   Attach makes it (`mknod`, character device 10:200) with `CAP_MKNOD`,
//!   and logs `made /dev/net/tun (char 10:200)`. The node alone is not
//!   enough: the runtime's device rules must also allow the device. runc's
//!   built-in rules do, except in runc 1.2.0 to 1.2.3.
//! - **`--world-wait 60`.** The world may not be listening yet when attach
//!   starts. Attach tries the socket again every 100 ms, for up to 60
//!   seconds.
//! - **`--no-resolv-conf`.** The chart sets the pod's DNS instead, with
//!   `dnsPolicy: None` and a `dnsConfig` that has the world's DNS server
//!   (`--dns`) as the only nameserver, no search domains and `ndots:1`. The
//!   kubelet writes that `resolv.conf` before any container starts. This
//!   works with a read-only root file system. It also keeps the cluster's
//!   search domains, which name the Kubernetes namespace, out of the
//!   sandbox.
//!
//! **The agent starts last.** Attach writes `--ready-file
//! /run/relay/attach.ready` once the world has accepted it. Attach's
//! startup probe runs `fictionet ready /run/relay/attach.ready`, which
//! exits with status 0 once the file exists. (The attach image has no
//! shell, so it cannot run `test -f`.) Kubernetes starts the next container
//! only after a native sidecar's startup probe passes. So by the time the
//! agent's container starts, `eth0` is down and `tun0` is up. The chart
//! also adds a deny-all `NetworkPolicy`, as a second layer, if the
//! cluster's CNI enforces policies. It cannot be the first layer, because a
//! CNI may apply a policy a few seconds after the pod starts, as kind's
//! `kindnet` did in our test.
//!
//! ## Values
//!
//! The chart takes its settings from a values file.
//! `examples/attach/k8s-tun.yaml` is the one the crate's own test
//! installs, shown here whole. The world is `web_world`, and the agent is
//! the Debian image from [The images](#the-images), run as uid 1000:
//!
#![cfg_attr(doc, doc = concat!("```yaml\n", include_str!("../examples/attach/k8s-tun.yaml"), "```"))]
//!
//! The world's socket must be `/run/relay/relay.sock`. The agent shares
//! the pod's network namespace, so it can list that socket in
//! `/proc/net/unix`, and the path names nothing. The `attach`
//! value sets attach's flags for every service. `ipAddr`, `gateway` and
//! `dns` default to `10.0.0.2/24`, `10.0.0.1` and `10.0.0.1`, and an empty
//! value means the flag's `--no-` form. `ipAddrV6`, `gatewayV6` and
//! `dnsV6` are empty by default, so pods get IPv4 only. Set them to
//! `2001:db8::2/64`, `2001:db8::1` and `2001:db8::1` to give a pod IPv6 in
//! a world built on [`Sites`](crate::stdlib::web::Sites). A service's own `attach` value
//! overrides them for that service. Each service starts from
//! `serviceDefaults`, and `values.yaml` in the chart describes every value.
//! `runtimeClassName` sets the pods' runtime class, such as `gvisor`. If it
//! is empty, the pods get the cluster's default.
//!
//! Every container has a memory limit, so an agent that allocates without
//! end is killed in its own container, not the node's other pods. The
//! agent may use 2 GiB and one CPU, as in Inspect's own chart, the world
//! 2 GiB, and attach 512 MiB. The requests, which the scheduler goes by,
//! are much smaller (256 MiB and 0.1 CPU for the agent, 64 MiB for the
//! world, 32 MiB for attach), so many sandboxes fit on one node. Set a
//! service's `resources`, or its world's, to change them: the value
//! replaces the default whole, and `{}` means no limits. Kubernetes has no process limit per
//! container, so set the kubelet's `podPidsLimit` on the nodes that run
//! sandboxes, to stop a fork bomb.
//!
//! `imagePullPolicy: Never` is there because the images are loaded into
//! kind's node by hand, below. On a cluster that pulls from a registry,
//! push the three images there, set the `image` values to their names,
//! and drop that line.
//!
//! ## Run it on kind
//!
//! You need Docker, [kind](https://kind.sigs.k8s.io/), kubectl and Helm.
//! Run these from the top directory of the repository. They build the images, make a cluster,
//! install one sandbox, fetch a page from inside it, and remove it all:
//!
//! ```text
//! $ docker build -f deploy/Dockerfile --target attach -t fictionet-attach:dev .
//! $ docker build -f deploy/Dockerfile --target web-world -t fictionet-web-world:dev .
//! $ docker build -f deploy/Dockerfile --target agent -t fictionet-agent:dev .
//! $ kind create cluster --name fictionet
//! $ kind load docker-image --name fictionet fictionet-attach:dev fictionet-web-world:dev fictionet-agent:dev
//! $ helm install demo charts/fictionet-sandbox -f examples/attach/k8s-tun.yaml --wait
//! $ kubectl exec fictionet-sandbox-demo-default-0 -c default -- curl -sS --cacert /run/ca/ca.pem https://example.test/
//! hello from https example.test 443 over HTTP/2.0
//! $ kubectl exec fictionet-sandbox-demo-default-0 -c default -- ip -br addr
//! lo               UNKNOWN        127.0.0.1/8 ::1/128
//! eth0@if5         DOWN
//! tun0             UNKNOWN        10.0.0.2/24
//! $ kubectl logs fictionet-sandbox-demo-default-0 -c attach
//! fictionet attach: eth0 is down, with no routes or addresses
//! fictionet attach: made /dev/net/tun (char 10:200)
//! fictionet attach: default attached as tun0
//! $ helm uninstall demo --wait
//! $ kind delete cluster --name fictionet
//! ```
//!
//! Each service's pod is named `fictionet-sandbox-<release>-<service>-0`,
//! and the agent's container is named after the service. Attach gives the
//! world the service's name, `default`, unless you set `attach.name`. The
//! builds are the ones Compose runs, so they take no time if you built for
//! Compose first. Making the cluster took 16 s, loading the images 4 s,
//! `helm install` 2.5 s once the images were on the node, and deleting
//! the cluster 1.3 s.
//!
//! Inspect's k8s sandbox installs the same chart and values:
//!
//! ```python
//! from pathlib import Path
//! from k8s_sandbox import K8sSandboxEnvironmentConfig
//!
//! Task(
//!     ...,
//!     sandbox=("k8s", K8sSandboxEnvironmentConfig(
//!         chart="charts/fictionet-sandbox",
//!         values=Path("examples/attach/k8s-tun.yaml"))),
//! )
//! ```
//!
//! Inspect adds its own annotations and labels when it installs the chart,
//! and the chart passes them on to the pods. Each Inspect service is its own
//! pod, so each one gets its own world. Inspect's built-in chart,
//! `agent-env`, has no place for the two sidecars, so a Fictionet sandbox
//! needs this chart.
//!
//! ## What the agent sees
//!
//! This is from `tests/k8s/run.sh`, on a kind cluster (Kubernetes 1.37,
//! containerd 2.3, runc 1.4), run in the agent's container. `eth0` is down,
//! the only route is through `tun0`, the world's site answers, and every way
//! around the world fails:
//!
//! ```text
//! $ ip -br link
//! lo               UNKNOWN        00:00:00:00:00:00 <LOOPBACK,UP,LOWER_UP>
//! eth0@if6         DOWN           92:d4:3f:65:b0:5f <BROADCAST,MULTICAST>
//! tun0             UNKNOWN        <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP>
//! $ ip route
//! default via 10.0.0.1 dev tun0 proto static onlink
//! 10.0.0.0/24 dev tun0 proto kernel scope link src 10.0.0.2
//! $ cat /etc/resolv.conf
//! nameserver 10.0.0.1
//! options ndots:1
//! $ curl -sS --cacert /run/ca/ca.pem https://example.test/
//! hello from https example.test 443 over HTTP/2.0
//! $ curl -sS -m 5 http://1.1.1.1/
//! curl: (7) Failed to connect to 1.1.1.1 port 80 after 0 ms: Couldn't connect to server
//! $ dig +time=2 +tries=1 @10.96.0.10 kubernetes.default.svc.cluster.local
//! ;; communications error to 10.96.0.10#53: timed out
//! $ ip link set eth0 up
//! RTNETLINK answers: Operation not permitted
//! $ ls /run/relay
//! ls: cannot access '/run/relay': No such file or directory
//! ```
//!
//! `10.96.0.10` is the cluster's DNS service. `ping` fails too, with
//! `exec /usr/bin/ping: operation not permitted`, because Debian's `ping`
//! needs `NET_RAW`, which the container dropped.
//!
//! **If attach stops,** `tun0` goes with it and `eth0` stays down, so the
//! agent has no network at all. Kubernetes restarts attach, which attaches
//! again under the same name, and the world sees a detach and then a new
//! attach. The test stops attach this way and checks both.
//!
//! ## Pod Security
//!
//! The Pod Security Standards' "baseline" and "restricted" levels reject
//! `NET_ADMIN`. In a Kubernetes namespace that enforces "baseline", the
//! chart's StatefulSet is created but its pod is not:
//!
//! ```text
//! pods "fictionet-sandbox-fn3-default-0" is forbidden: violates PodSecurity "baseline:latest": non-default capabilities (container "attach" must not include "NET_ADMIN" in securityContext.capabilities.add)
//! ```
//!
//! Only attach needs `NET_ADMIN`. Attach's other two capabilities, `MKNOD`
//! and `DAC_OVERRIDE` (to connect to a socket the world's user owns), are
//! both allowed by "baseline". The agent's container can meet "restricted"
//! on its own: no capabilities, no privilege escalation, `RuntimeDefault`
//! seccomp, and a non-root user where its image allows. So the Kubernetes
//! namespace needs `pod-security.kubernetes.io/enforce: privileged`, or an
//! exception for the attach container from a policy engine (Kyverno,
//! Gatekeeper or a ValidatingAdmissionPolicy). The built-in Pod Security
//! admission can exempt only whole namespaces, users or runtime classes, in
//! the API server's own config, which managed clusters (GKE, EKS, AKS) do
//! not let you edit.
//!
//! Where none of that is possible, use `attach.type: http_proxy` or
//! `socks5`. No container then needs a capability, and the pod passes
//! "restricted". See [The proxy on Kubernetes](#the-proxy-on-kubernetes).
//!
//! ## gVisor
//!
//! Inspect's clusters run sandboxes under gVisor (`runtimeClassName:
//! gvisor`), and the chart works there too. It was run on the kind cluster
//! above with gVisor's `runsc` (release 20260928.0) as a containerd
//! runtime, and every check of the test passed. Four things differ from
//! runc:
//!
//! - **The world's socket needs pod annotations.** Under gVisor, an
//!   `emptyDir` is not shared between a pod's containers unless the pod
//!   says so. The chart adds the pod annotations
//!   `dev.gvisor.spec.mount.fictionet.share: pod`, `.type: tmpfs` and
//!   `.options: rw` for the volume that holds the socket. containerd passes
//!   them to `runsc` only if the runtime's config lists them:
//!   `pod_annotations = ["dev.gvisor.*"]`. Without that, attach waits for a
//!   socket it never sees, and gives up after `--world-wait`.
//! - **`eth0` stays up.** gVisor deletes `eth0`'s addresses and routes but
//!   ignores the request to set it down, so `ip -br link` shows it `UP`.
//!   With no address and no route it carries nothing, and the agent cannot
//!   add either. The only default route is `tun0`'s.
//! - **`--down-link` matters more.** Without it, gVisor adds `tun0`'s
//!   default route next to the pod's own, with no error, and the pod's
//!   route wins for TCP. In the test, connections to the world's sites left
//!   through `eth0` and timed out, and only DNS reached the world.
//! - **The device's name** is chosen by gVisor: `tun0`, or another such as
//!   `tun3`. `/dev/net/tun` is already there, so attach makes no node.
//!
//! Each packet crosses the gVisor kernel twice, once into attach and once
//! into the world. A 16 MiB download over HTTPS from `web_world` took 0.33
//! to 0.41 s under gVisor (41 to 51 MB/s), and 0.021 to 0.024 s under runc
//! (690 to 790 MB/s).
//!
//! # Hosted sandboxes
//!
//! Use this setup when the agent runs in a hosted sandbox from Daytona or
//! E2B. Both can run Docker inside the sandbox, so the whole
//! [Docker Compose](#in-docker-compose) setup runs in one sandbox: the
//! world, attach with `--type tun`, and the agent in attach's network
//! namespace. Nothing about Fictionet changes. The agent's only interface,
//! besides loopback, is still `tun0`, and it still has no `NET_ADMIN`. The sandbox itself can
//! reach the provider's network, but the agent cannot.
//!
//! `examples/hosted` in the crate's repository has a tested copy: two small
//! Dockerfiles, a compose file, a `check.sh`, a script that runs it on
//! either provider, a tiny Inspect eval and a Harbor task. Run
//! `examples/hosted/build.sh` first. It builds `fictionet` and `web_world`
//! for Debian, so nothing is compiled in the sandbox.
//!
//! This is what the Docker inside each provider's sandbox gave attach, as
//! tested on 2 October 2026:
//!
//! | | Daytona | E2B |
//! |---|---|---|
//! | Sandbox | a container from `docker:28.3.3-dind`, root, every capability | a VM, kernel 6.1, user `user` with sudo |
//! | `/dev/net/tun`, `cap_add: [NET_ADMIN]` | work | work |
//! | Docker | started by hand: `dockerd-entrypoint.sh dockerd &` | from the template, run with `sudo` |
//! | Sandbox to healthy, with images built in it | 17 s | 28 s, after a one-time 26 s template build |
//!
//! ## Run it locally first
//!
//! The same files run on any machine with Docker, which is the quickest way
//! to check a change before you pay for a sandbox. You need Linux with
//! `/dev/net/tun`, and Docker Engine with Compose v2. Run these from the
//! repository's top directory. `build.sh` builds `fictionet` and `web_world` in Docker
//! and copies them into `examples/hosted/bin`. Then Compose starts the
//! three containers, `check.sh` runs 19 checks from outside them, and
//! Compose removes them:
//!
//! ```text
//! $ examples/hosted/build.sh
//! $ cd examples/hosted
//! $ docker compose up -d --build --wait
//! $ ./check.sh
//! outer address 172.17.0.5, gateway 172.17.0.1, docker0 172.18.0.1
//! PASS: the agent has only lo and tun0
//! ...
//! PASS: the sandbox's own network (172.18.0.1) fails
//! ALL PASSED
//! $ docker compose down -v
//! ```
//!
//! `build.sh` took 56 s, `up` took 40 to 100 s (most of it `apt-get` in the
//! agent's image), `check.sh` 6 to 7 s, and `down` 0.7 s.
//!
//! ## Directly, with each provider's SDK
//!
//! You need Python 3, the providers' SDKs, an API key for the provider,
//! and the binaries from `build.sh` above:
//!
//! ```sh
//! examples/hosted/build.sh
//! pip install daytona e2b
//! DAYTONA_API_KEY=... python examples/hosted/run_hosted.py daytona
//! E2B_API_KEY=... python examples/hosted/run_hosted.py e2b
//! ```
//!
//! The script does every other step itself. It makes one sandbox, uploads
//! the example, runs `docker compose up -d --build --wait` and `check.sh`
//! inside it, and deletes the sandbox, even when a check fails. On Daytona it makes the sandbox from
//! `docker:28.3.3-dind` with 2 vCPU and 4 GiB, and starts dockerd. On E2B
//! it first builds a template, `fictionet-dind`: Ubuntu 24.04 with
//! `docker.io` and `docker-compose-v2`. `check.sh` printed the same on both
//! providers:
//!
//! ```text
//! PASS: the agent has only lo and tun0
//! PASS: tun0 has 10.0.0.2/24
//! PASS: the default route is tun0
//! PASS: resolv.conf points at the world
//! PASS: the world's DNS answers
//! PASS: HTTPS with the world's CA
//! PASS: ping the gateway
//! PASS: the agent has no NET_ADMIN
//! PASS: the agent cannot delete its route
//! PASS: the agent cannot add a link
//! PASS: the agent cannot see the world socket
//! PASS: DNS to 1.1.1.1 fails
//! PASS: DNS to 8.8.8.8 fails
//! PASS: HTTPS to 1.1.1.1 fails
//! PASS: a real name does not resolve
//! PASS: the metadata address fails
//! PASS: the sandbox's own network (172.20.0.53) fails
//! PASS: the sandbox's own network (172.20.0.1) fails
//! PASS: the sandbox's own network (172.17.0.1) fails
//! ALL PASSED
//! ```
//!
//! The last three addresses are the sandbox's own address, its gateway and
//! the inner Docker's bridge. On E2B the first two were `169.254.0.21` and
//! `169.254.0.22`.
//!
//! Two things to know when you write your own:
//!
//! - Both providers' upload APIs write files without the execute bit. Copy
//!   binaries into an image with `COPY --chmod=0755`.
//! - `docker:dind` is Alpine and has no bash.
//!
//! ## Through Inspect
//!
//! [inspect-sandboxes](https://github.com/meridianlabs-ai/inspect_sandboxes)
//! runs a compose file with more than one service inside one Daytona or E2B
//! sandbox. Inspect runs the agent's tools in the service named `default`.
//!
//! ```sh
//! pip install inspect-ai inspect-sandboxes
//! inspect eval examples/hosted/eval.py --model mockllm/model -T provider=daytona
//! inspect eval examples/hosted/eval.py --model mockllm/model -T provider=e2b --max-samples 1
//! ```
//!
//! The eval needs no model: a scripted solver runs five commands in the
//! agent's container, and the scorer checks the output. Both providers
//! scored 5 of 5. Sample setup took 20 to 42 s on Daytona, with five
//! samples at once, and 30 to 38 s on E2B, one at a time.
//!
//! - inspect-sandboxes 0.6.0 refuses a compose file with a top-level
//!   `name:` or a `build.target`. Use one Dockerfile per image.
//! - On E2B, run one sample at a time with `--max-samples 1`. With several
//!   at once, each one rebuilds the same template, and all but one fail
//!   with `400: build is not in waiting state`.
//!
//! ## Through Harbor
//!
//! Harbor runs a task's `environment/docker-compose.yaml` inside one
//! Daytona sandbox. The agent is the service `main`, built from
//! `environment/Dockerfile`. The task's compose file adds the world and
//! attach, and puts `main` in attach's network namespace.
//!
//! ```sh
//! pip install 'harbor[daytona]'
//! harbor run -p examples/hosted/harbor/fictionet-web -a oracle -e daytona
//! ```
//!
//! The `oracle` agent runs the task's `solution/solve.sh`, so no model is
//! needed. It scored 1.0, after 24 s of setup. Harbor's E2B backend does
//! not run Compose, so it cannot run this task.
//!
//! ## The provider's network
//!
//! The agent cannot reach the sandbox's network, whatever the provider
//! allows. Docker inside the sandbox can, and it needs that network to pull
//! images. What each provider lets the sandbox reach:
//!
//! - **Daytona, tiers 1 and 2.** The sandbox reaches only Daytona's list of
//!   essential services, such as PyPI, Debian and Docker Hub.
//!   `network_block_all` at creation is honored, but then nothing can be
//!   pulled. Changing it on a running sandbox is refused: "Network access
//!   is restricted and cannot be overridden at the sandbox level." Allow
//!   lists are ignored.
//! - **E2B.** Egress is open by default. `allow_internet_access=False`
//!   blocked HTTPS and UDP DNS to 8.8.8.8 and 1.1.1.1. `deny_out` and
//!   `allow_out` by IP address worked.
//!
//! # Behind a proxy: `http_proxy` and `socks5`
//!
//! Use this setup when the sandbox gets no privileges at all: no
//! `NET_ADMIN`, no `/dev/net/tun`, no root. Examples are a pod under Pod
//! Security "restricted", a gVisor sandbox, or a hosted sandbox that may
//! reach only one address. The sandbox gets no new interface. Instead,
//! attach runs next to the world, outside the sandbox, and listens on a TCP
//! port as a proxy. The agent's programs reach the world through that proxy.
//!
//! There are two proxy types:
//!
//! - **`--type http_proxy`** is an HTTP proxy. It serves
//!   `CONNECT host:port`, which clients send for `https://` URLs, and
//!   plain-HTTP requests in absolute form (`GET http://host/path`), which
//!   they send for `http://` URLs.
//! - **`--type socks5`** is a SOCKS5 proxy. It serves `CONNECT`, and looks
//!   names up in the world. It does not serve `BIND` or `UDP ASSOCIATE`.
//!
//! Both types share one engine. Attach acts as the sandbox's kernel: it
//! turns each proxied connection into IP packets from `--ip-addr`, made by
//! the same TCP/IP stack that worlds use from [`stdlib`](crate::stdlib).
//! It looks a name up by sending a DNS query from `--ip-addr` to `--dns`, a
//! UDP packet into the world. The world sees ordinary TCP and DNS traffic
//! from that address, but not exactly what a `tun` sandbox would send:
//! the TCP options are attach's, lookups ask only for `A` records, and
//! there is no IPv6. [`lowering`](crate::lowering) compares the types
//! packet by packet.
//!
#![doc = include_str!("../docs/diagrams/attach-proxy.svg")]
//!
//! When it starts, attach does these steps in order:
//!
//! 1. It reads the sandbox's token from `--token-file`.
//! 2. It listens on `--listen`. If the port is taken, attach stops here.
//! 3. It connects to the world, sends `hello` with the type `http_proxy`
//!    or `socks5`, and waits for `accept`, as `tun` does. `--world-wait`
//!    works the same way.
//! 4. It writes the `--ready-file`, if you give one.
//! 5. It serves clients until the world closes the connection. Then it
//!    closes the port, and gives the clients it is still serving up to 1
//!    second to finish, so that a client waiting for a connection hears
//!    why it failed (see [Errors](#errors)). Then it exits with status 0.
//!    SIGTERM, SIGINT or SIGHUP stop it immediately, and the port closes too.
//!    Either way, the sandbox then has no way out at all, as long as the
//!    platform blocks its other egress (see
//!    [What keeps the agent in](#what-keeps-the-agent-in)).
//!
//! ## Running the proxy
//!
//! This makes a random token and starts an HTTP proxy for the sandbox
//! `agent`, on port 8080:
//!
//! ```sh
//! od -An -tx1 -N24 /dev/urandom | tr -d ' \n' > /run/fictionet/token
//! fictionet attach --world unix:/run/fictionet/world.sock --name agent \
//!     --type http_proxy --listen 0.0.0.0:8080 --token-file /run/fictionet/token \
//!     --ip-addr 10.0.0.2 --dns 10.0.0.1 --ready-file /run/fictionet/attach.ready
//! ```
//!
//! `--type socks5` takes the same flags. Attach prints one line when it is
//! ready, and one line per request:
//!
//! ```text
//! fictionet attach: agent attached; HTTP proxy on 0.0.0.0:8080, as 10.0.0.2 with DNS at 10.0.0.1
//! fictionet attach: CONNECT example.test:443 (203.0.113.10) 200, 1927 bytes up, 1190 down, 0.002 s
//! fictionet attach: GET http://plain.test:80/x (198.18.0.1) 200, 0 bytes up, 30 down, 0.000 s
//! fictionet attach: CONNECT nope.test:443 502 no such name in the world
//! fictionet attach: CONNECT example.test:443 407 no token
//! ```
//!
//! Attach writes one line for each request it reads, when that request
//! ends. A `CONNECT` tunnel ends when the client or the site closes it, so
//! a long download, or a connection the client keeps open, shows up only
//! after it closes. Once a program's connections have closed, the log is a
//! quick check: a program that never shows up in it did not use the proxy.
//!
//! The flags:
//!
//! - **`--listen <ip:port>`** is where the proxy listens. In a pod, use
//!   `127.0.0.1:8080`. In Docker Compose, use an address on the network the
//!   sandbox shares with attach. For a sandbox elsewhere, use a public
//!   address.
//! - **`--token-file <path>`** holds the sandbox's token, described below.
//! - **`--ip-addr <ip>`** is the sandbox's address in the world, with no
//!   prefix length. Give each sandbox its own.
//! - **`--dns <ip>`** is the world's DNS server.
//! - **`--ready-file` and `--world-wait`** work as they do for `tun`.
//!
//! The `tun` flags that set up a device, routes or `resolv.conf` mean
//! nothing here, so attach refuses them rather than ignore them:
//! `--gateway`, `--netns`, `--mtu`, `--down-link`, `--resolv-conf`, and the
//! IPv6 flags. The proxy types are IPv4 only. For example:
//!
//! ```text
//! fictionet attach: --type http_proxy takes no --gateway: attach makes the packets itself, and there are no routes to set
//! ```
//!
//! **The token** stops other clients from using this sandbox's proxy. One
//! attach serves one sandbox, so it has one token. A client gives it as the
//! password in the proxy URL: `http://fictionet:TOKEN@attach:8080`, or
//! `socks5h://fictionet:TOKEN@attach:1080`. Attach does not check the
//! username. The HTTP proxy also accepts
//! `Proxy-Authorization: Bearer TOKEN`, and both proxies accept the token
//! as the username with no password, for clients that put only one value
//! in the URL. The token is 1 to 255 printable ASCII characters with no
//! spaces, and attach compares it exactly, in constant time. A request
//! without the token, or with another one, gets
//! `407 Proxy Authentication Required` from the HTTP proxy. The SOCKS5
//! proxy answers a wrong or empty token with status 1. A SOCKS5 client
//! that does not offer the username/password method at all, such as curl
//! with no credentials in its proxy URL, gets method `0xff`, "no
//! acceptable methods", instead. Either way, the SOCKS5 proxy then closes
//! the connection. The agent can read its
//! own token, and that gets it nothing it does not already have: the token
//! opens only its own attachment. Both proxy protocols send the token in
//! clear text, so on a network others can watch, give each sandbox its own
//! short-lived token.
//!
//! ## In the sandbox: which programs use it
//!
//! Programs find a proxy through environment variables. Set them before the
//! agent starts. Here `$TOKEN` holds the sandbox's token, the contents of
//! attach's `--token-file`:
//!
//! ```sh
//! export HTTPS_PROXY=http://fictionet:$TOKEN@attach:8080 https_proxy=http://fictionet:$TOKEN@attach:8080
//! export HTTP_PROXY=http://fictionet:$TOKEN@attach:8080 http_proxy=http://fictionet:$TOKEN@attach:8080
//! export NO_PROXY= no_proxy= NODE_USE_ENV_PROXY=1
//! # or, for socks5:
//! export ALL_PROXY=socks5h://fictionet:$TOKEN@attach:1080
//! ```
//!
//! Set both the uppercase and lowercase forms, because curl reads only the
//! lowercase `http_proxy`. The `h` in `socks5h` makes the client send the
//! name to the proxy instead of looking it up itself. The sandbox must
//! also trust the world's CA, as with `tun`, because `CONNECT` keeps TLS
//! end to end, between the client and the world's site. Some runtimes keep
//! their own trust store: `REQUESTS_CA_BUNDLE` for Python requests,
//! `NODE_EXTRA_CA_CERTS` for Node, `GIT_SSL_CAINFO` for git, and
//! `SSL_CERT_FILE` for Go and Python's `ssl`.
//!
//! These programs were run through both proxy types with the `web_world`
//! example (the Docker test in `tests/docker/proxy`):
//!
//! | Program | `http_proxy` | `socks5` |
//! |---|---|---|
//! | curl 7.88 | yes: `https_proxy`, `http_proxy` | yes: `ALL_PROXY=socks5h://` |
//! | wget 1.21 | yes: `https_proxy`, `http_proxy` | no: wget has no SOCKS support |
//! | git 2.39, over HTTPS | yes, through libcurl | yes: `ALL_PROXY` or `-c http.proxy=socks5h://` |
//! | Python 3.13, requests 2.34 | yes: `HTTPS_PROXY`, `HTTP_PROXY` | with PySocks (`requests[socks]`) |
//! | Go 1.27, `net/http` | yes: `HTTPS_PROXY`, `HTTP_PROXY` | as `HTTPS_PROXY=socks5://`; Go ignores `ALL_PROXY` |
//! | Node 24.21, `fetch` | only with `NODE_USE_ENV_PROXY=1` | no |
//!
//! Without `NODE_USE_ENV_PROXY=1`, Node looks the name up itself and fails
//! with `ENOTFOUND`. Python's `urllib` also worked through the HTTP proxy,
//! on Python 3.14. pip, uv and npm read the same variables, or their own
//! settings, but they were not run in this test.
//!
//! ## What cannot go through
//!
//! The proxy carries only TCP connections that a program opens through it.
//! If the agent's task needs any of the following, use `tun` instead. Cyber
//! evals usually do.
//!
//! - **ICMP, raw sockets and UDP.** `ping`, `traceroute`, `nmap`, DNS
//!   queries from the sandbox, QUIC and HTTP/3 all fail.
//! - **Name lookups in the sandbox.** `dig`, `nslookup` and `getent hosts`
//!   fail. Names reach attach inside the proxy request instead. A program
//!   that looks a name up before it connects (`socks5://` without the `h`,
//!   or Node without `NODE_USE_ENV_PROXY`) fails.
//! - **Programs that ignore the proxy variables.** These include `ssh` and
//!   git over SSH, database clients, Python's aiohttp (unless
//!   `trust_env=True`), Go programs with their own `Transport` and no
//!   `Proxy`, and browsers that are not told about the proxy.
//! - **Connections into the sandbox.** A machine in the world cannot
//!   connect back to the sandbox: attach's stack answers a SYN to
//!   `--ip-addr` with a RST. Reverse shells and callbacks do not work.
//! - **The sandbox's own TCP behavior.** The world sees attach's TCP, from
//!   the SDK, not the sandbox kernel's. A reset, a dropped SYN or an ICMP
//!   error from the world reaches the client as a proxy answer (see
//!   [Errors](#errors)), not as the same TCP event.
//!
//! ## Errors
//!
//! When a connection cannot be made, attach answers the client as soon as
//! it knows. The HTTP proxy puts the reason in an `X-Fictionet-Error`
//! header and in the body. The SOCKS5 proxy answers with a reply code:
//!
//! | In the world | `http_proxy` | `socks5` reply |
//! |---|---|---|
//! | the name does not exist (NXDOMAIN), or has no IPv4 address | 502 | 4, host unreachable |
//! | the DNS server fails, or does not answer in 7 s | 502 | 4 |
//! | the port is closed (a RST) | 502 | 5, connection refused |
//! | no machine at the address (ICMP host unreachable) | 502 | 4 (3 for network unreachable) |
//! | no answer to the SYN within 10 s | 504 | 6, TTL expired |
//! | the world is gone | 503, then the port closes | 1, general failure |
//! | an IPv6 target | 502 | 8, address type not supported |
//! | `BIND` or `UDP ASSOCIATE` | | 7, command not supported |
//! | more than 1,024 clients at once | 503 | the connection closes |
//!
//! ```text
//! $ curl -sS https://nope.test/
//! curl: (7) CONNECT tunnel failed, response 502
//! $ curl -sS -i http://nope.test/
//! HTTP/1.1 502 Bad Gateway
//! X-Fictionet-Error: no such name in the world
//! Content-Type: text/plain
//! Content-Length: 26
//! Connection: close
//!
//! no such name in the world
//! $ curl -sS -x socks5h://fictionet:$TOKEN@attach:1080 https://plain.test/
//! curl: (97) cannot complete SOCKS5 connection to plain.test. (5)
//! ```
//!
//! Attach forwards a plain-HTTP request in origin form (`GET /path`). It
//! removes the proxy's own header fields and the hop-by-hop ones, and adds
//! `Connection: close`, so the client opens a new connection for its next
//! request. Attach also limits what a client can make it hold: 64 KiB for a
//! request head, 30 seconds to send it, 10 seconds for the SOCKS5
//! handshake, and 1,024 clients at once.
//!
//! ## What keeps the agent in
//!
//! Fictionet treats only the agent as adversarial. Attach runs outside the
//! sandbox, and nothing in attach opens a socket on the host toward an
//! address a client names. Every connection becomes packets on the world's
//! [`Attachment`](crate::Attachment). So through the proxy, the agent
//! reaches the world and nothing else. A real address, such as `1.1.1.1`,
//! is just one more address in the world. In `web_world` it has no
//! machine, so the client gets `502 host unreachable`.
//!
//! The proxy does not contain the sandbox by itself. The sandbox must have
//! no other way out, and that is the platform's job: the sandbox may reach
//! attach's port, and nothing else, not even a DNS server.
//!
//! - **Docker.** The sandbox's only network is an `internal: true` network
//!   shared with attach, so it has no route out. Give that network the
//!   `isolated` gateway modes as well, as `examples/attach/compose-proxy.yaml`
//!   does. Without them, the host has an address on the network, and the
//!   agent can connect to any service on the host that listens on all
//!   addresses. (In a test with Docker Engine 29.8, the agent reached the
//!   Docker daemon's own TLS port that way.) Docker's DNS on that network
//!   answers only for container names. Attach reaches the world through the socket volume,
//!   so it needs no other network either, and the world needs none at all.
//! - **Kubernetes.** A NetworkPolicy denies all egress from the pod. Attach
//!   runs in the same pod and listens on `127.0.0.1`, which the policy does
//!   not touch. This needs a CNI that enforces policies, and no other
//!   policy that allows the pod's traffic. Do not allow the cluster's DNS,
//!   because it answers for real names. The chart also makes the agent
//!   wait until the policy holds: see
//!   [The proxy on Kubernetes](#the-proxy-on-kubernetes).
//! - **Hosted sandboxes.** Block all egress, then allow attach's address as
//!   a `/32`. Use rules on addresses, not on names. A rule on names matches
//!   the world's names, which the proxy request carries, and some providers
//!   then let DNS out to a public server. This setup has not been run on a
//!   provider. The [roadmap](crate::roadmap#hosted-sandboxes-without-docker)
//!   lists what to check first.
//!
//! An agent that tries to get around the proxy has these options, and none
//! of them gets it out:
//!
//! - **Unset the variables, or use a program that ignores them.** Its
//!   connections fail, because nothing else is routed.
//! - **Be root in its sandbox.** It can change its own interfaces and
//!   firewall, but the rule that holds it is outside the sandbox.
//! - **Read its token.** The token is the agent's own, for the attachment
//!   it already has.
//! - **Send attach anything.** Attach's parsers are bounded, as above.
//!
//! Getting out is one thing, and slowing others down is another. A flood
//! through the proxy keeps this sandbox's attach busy, and every connection
//! it opens reaches the world as packets. All the sandboxes of one world
//! share its tasks, and those tasks share one thread, so a flood of new
//! connections or DNS names slows the world for every sandbox in it. When
//! one agent must not slow down another, give each its own world process,
//! and limit each process's CPU and memory, for example with a container
//! or a systemd unit.
//!
//! ## The proxy in Docker Compose
//!
//! The file is `examples/attach/compose-proxy.yaml` in the crate's
//! repository, shown here whole. It uses the images from
//! [The images](#the-images). The world has no network at all. The
//! sandbox's only network, `sandbox`, is internal, and attach is the only
//! other container on it. The start order works as in the `tun` file:
//! attach waits for the world's socket with `--world-wait`, and the agent
//! starts once attach's healthcheck passes. The token comes from the
//! environment variable `FICTIONET_TOKEN`. Compose gives it to attach as a
//! file, `/run/secrets/token`, and puts it in the agent's proxy URLs.
//!
#![cfg_attr(doc, doc = concat!("```yaml\n", include_str!("../examples/attach/compose-proxy.yaml"), "```"))]
//!
//! For `socks5`, change attach's `--type` and port, and give the agent
//! `ALL_PROXY=socks5h://fictionet:${FICTIONET_TOKEN}@attach:1080` instead
//! of the HTTP variables.
//!
//! ### Run it with Compose
//!
//! You need Docker Engine with Compose v2. Run these from the top directory of the repository,
//! in one shell, since every command reads `FICTIONET_TOKEN`. The site
//! answers through the proxy. Around the proxy, the agent can neither
//! look a name up nor reach an address. A real name, sent through the
//! proxy, does not exist in the world:
//!
//! ```text
//! $ export FICTIONET_TOKEN=$(od -An -tx1 -N24 /dev/urandom | tr -d ' \n')
//! $ docker compose -f examples/attach/compose-proxy.yaml build
//! $ docker compose -f examples/attach/compose-proxy.yaml up -d --wait
//! $ docker compose -f examples/attach/compose-proxy.yaml exec agent curl -sS https://example.test/
//! hello from https example.test 443 over HTTP/2.0
//! $ docker compose -f examples/attach/compose-proxy.yaml exec agent curl -sS --noproxy '*' -m 5 https://example.test/
//! curl: (6) Could not resolve host: example.test
//! $ docker compose -f examples/attach/compose-proxy.yaml exec agent curl -sS --noproxy '*' -m 5 https://1.1.1.1/
//! curl: (7) Failed to connect to 1.1.1.1 port 443 after 0 ms: Couldn't connect to server
//! $ docker compose -f examples/attach/compose-proxy.yaml exec agent curl -sS https://example.com/
//! curl: (56) CONNECT tunnel failed, response 502
//! $ docker compose -f examples/attach/compose-proxy.yaml logs attach
//! attach-1  | fictionet attach: agent attached; HTTP proxy on 0.0.0.0:8080, as 10.0.0.2 with DNS at 10.0.0.1
//! attach-1  | fictionet attach: CONNECT example.test:443 (203.0.113.10) 200, 774 bytes up, 1218 down, 0.003 s
//! attach-1  | fictionet attach: CONNECT example.com:443 502 no such name in the world
//! $ docker compose -f examples/attach/compose-proxy.yaml down -v
//! ```
//!
//! With the images already built, starting took 2.8 s and removing it all
//! took 0.6 s.
//!
//! The crate's larger proxy test, `tests/docker/proxy/run.sh`, runs both
//! proxy types side by side with more clients, and makes a new token each
//! time. Some of what it printed:
//!
//! ```text
//! PASS: curl https, HTTP/2
//! PASS: python requests https and http (Python 3.13)
//! PASS: go net/http https and http
//! PASS: node fetch, with NODE_USE_ENV_PROXY=1
//! PASS: git over https through socks5h
//! PASS: a wrong token: 407
//! PASS: socks5 with a wrong token is rejected
//! PASS: an address with no machine: 502 host unreachable
//! PASS: a real name through the proxy does not exist in the world: 502
//! PASS: around the proxy, TCP to 1.1.1.1 fails
//! PASS: around the proxy, UDP DNS to 8.8.8.8 fails
//! PASS: the sandbox resolves no real names
//! PASS: the sandbox has no capabilities
//! PASS: 10 downloads of 16 MiB at once through the http door, none stalled (0.193847 s to 0.194936 s)
//! PASS: a 64 MiB upload through the socks door, in 0.078196 s
//! PASS: 1,000 HTTPS requests, 200 at a time, all 200
//! PASS: when the world stops, attach exits 0
//! PASS: and the sandbox has no way out at all
//! ALL PASSED
//! ```
//!
//! ## The proxy on Kubernetes
//!
//! The `fictionet-sandbox` chart takes `attach.type: http_proxy` or
//! `socks5`, for every service or per service. The pod has the same three
//! containers as with `tun`, and one more, with these changes:
//!
//! - **Attach has no privileges.** It runs as the world's user
//!   (`attach.runAsUser`, 65532 in the images from `deploy/Dockerfile`), so
//!   it may open the world's socket, with every capability dropped. It
//!   listens on `127.0.0.1:8080` (1080 for `socks5`, or set
//!   `attach.port`), and `eth0` stays as the CNI made it.
//! - **Each service gets a token.** The chart makes a Secret with a random
//!   token, and keeps it across upgrades. Attach reads it from a file. The
//!   agent gets it in its proxy variables, which the chart sets:
//!   `HTTPS_PROXY`, `HTTP_PROXY` and their lowercase forms (or `ALL_PROXY`
//!   for `socks5`), with `NO_PROXY` empty and `NODE_USE_ENV_PROXY=1`.
//! - **The pod's resolver is `127.0.0.1`,** where nothing listens. A
//!   program that looks a name up in the pod fails immediately.
//! - **The deny-all NetworkPolicy is what keeps the agent in.** A fourth
//!   container, `wait-blocked`, starts the agent only once the policy
//!   holds: see [Waiting until the policy holds](#waiting-until-the-policy-holds)
//!   below.
//!
//! `examples/attach/k8s-proxy.yaml` has two sandboxes, one with each proxy
//! type. The crate's test installs it, and it is shown here whole:
//!
#![cfg_attr(doc, doc = concat!("```yaml\n", include_str!("../examples/attach/k8s-proxy.yaml"), "```"))]
//!
//! ### Run it on kind
//!
//! You need what [Run it on kind](#run-it-on-kind) needs, and the same
//! three images. These commands make a cluster, load the images, and
//! install both sandboxes in a Kubernetes namespace that enforces Pod
//! Security "restricted". Each agent fetches the page through its own
//! proxy type, and fails without the proxy. Then they remove it all:
//!
//! ```text
//! $ kind create cluster --name fictionet
//! $ kind load docker-image --name fictionet fictionet-attach:dev fictionet-web-world:dev fictionet-agent:dev
//! $ kubectl create namespace sandboxes
//! $ kubectl label namespace sandboxes pod-security.kubernetes.io/enforce=restricted
//! $ helm install demo charts/fictionet-sandbox -n sandboxes -f examples/attach/k8s-proxy.yaml --wait
//! $ kubectl -n sandboxes exec fictionet-sandbox-demo-default-0 -c default -- curl -sS https://example.test/
//! hello from https example.test 443 over HTTP/2.0
//! $ kubectl -n sandboxes exec fictionet-sandbox-demo-socks-0 -c socks -- curl -sS https://example.test/
//! hello from https example.test 443 over HTTP/2.0
//! $ kubectl -n sandboxes exec fictionet-sandbox-demo-default-0 -c default -- curl -sS --noproxy '*' -m 5 https://example.test/
//! curl: (6) Could not resolve host: example.test
//! command terminated with exit code 6
//! $ kubectl -n sandboxes logs fictionet-sandbox-demo-default-0 -c attach
//! fictionet attach: default attached; HTTP proxy on 127.0.0.1:8080, as 10.0.0.2 with DNS at 10.0.0.1
//! fictionet attach: CONNECT example.test:443 (203.0.113.10) 200, 774 bytes up, 1218 down, 0.017 s
//! $ kubectl delete namespace sandboxes
//! $ kind delete cluster --name fictionet
//! ```
//!
//! `helm install` took 15 s, with the images loaded but not yet started,
//! and deleting the namespace took 11 s.
//!
//! **The pod passes Pod Security "restricted".** `tests/k8s/proxy.sh`
//! installs these values in a Kubernetes namespace that enforces
//! "restricted", on kind (Kubernetes 1.37, kindnet). Helm printed no Pod
//! Security warning, both pods ran, and no container added a capability or
//! ran as root. A `tun` release in the same namespace was refused:
//!
//! ```text
//! pods "fictionet-sandbox-fntun-default-0" is forbidden: violates PodSecurity "restricted:latest": unrestricted capabilities (container "attach" must not include "DAC_OVERRIDE", "MKNOD", "NET_ADMIN" in securityContext.capabilities.add), runAsNonRoot != true (container "attach" must not set securityContext.runAsNonRoot=false), runAsUser=0 (container "attach" must not set runAsUser=0)
//! ```
//!
//! To pass it yourself, set `podSecurityContext` as above, and run the
//! agent's image as a user other than root.
//!
//! In the agent's container, the world's site answers through the proxy,
//! and everything else fails:
//!
//! ```text
//! $ ip -br addr
//! lo               UNKNOWN        127.0.0.1/8 ::1/128
//! eth0@if11        UP             10.244.0.10/24 fe80::b400:4cff:fe26:c74/64
//! $ cat /etc/resolv.conf
//! nameserver 127.0.0.1
//! options ndots:1
//! $ env | grep -i proxy
//! HTTPS_PROXY=http://fictionet:***@127.0.0.1:8080
//! ...
//! $ curl -sS https://example.test/
//! hello from https example.test 443 over HTTP/2.0
//! $ curl -sS -x http://fictionet:wrong@127.0.0.1:8080 https://example.test/
//! curl: (56) CONNECT tunnel failed, response 407
//! $ curl -sS --noproxy '*' https://example.test/
//! curl: (6) Could not resolve host: example.test
//! $ curl -sS --noproxy '*' -m 5 -k https://10.96.0.1/version
//! curl: (28) Connection timed out after 5001 milliseconds
//! $ dig +time=2 +tries=1 @10.96.0.10 kubernetes.default.svc.cluster.local
//! ;; communications error to 10.96.0.10#53: timed out
//! ;; no servers could be reached
//! ```
//!
//! The token is masked here. `10.96.0.1` is the API server, and
//! `10.96.0.10` is the cluster's DNS. `1.1.1.1` did not answer either. With
//! `networkPolicy.enabled: false` (and `networkPolicy.waitForEnforcement:
//! false`), the same agent reached the API server (`200`) and the
//! cluster's DNS answered, so the policy is what holds the agent in.
//!
//! ### Waiting until the policy holds
//!
//! With a proxy type, `eth0` stays up, so the agent is held in by the
//! chart's deny-all NetworkPolicy alone. Kubernetes does not promise that a
//! new policy is enforced when the pod starts. A CNI may apply it a few
//! seconds later, and a connection opened before then may stay open. So
//! the chart does not start the agent until the policy holds.
//!
//! The pod has one more container for this, `wait-blocked`. It is a
//! regular init container, after the world and attach, so Kubernetes
//! starts the agent's container only after it exits with status 0. It runs
//! `fictionet wait-blocked --api-server` from the attach image, as attach's
//! user, with no capabilities, so the pod still passes Pod Security
//! "restricted". Every half second it tries a TCP connection from the pod
//! to the API server (the address in `KUBERNETES_SERVICE_HOST`, which every
//! pod can reach unless a policy blocks it), and to each address in
//! `networkPolicy.waitAddresses`. It exits 0 once every attempt has failed
//! three rounds in a row, by timing out after a second, being refused, or
//! finding the host or network unreachable: what a policy that drops or
//! rejects packets does. A connection that succeeds starts the count
//! again, and so does any other failure, such as no socket being
//! available, because that says nothing about the network. If an address still answers after `networkPolicy.waitTimeout`
//! seconds (120 by default), it exits 1, and Kubernetes keeps the agent's
//! container from starting and tries `wait-blocked` again.
//!
//! On kind, kindnet enforced the policy before `wait-blocked` started, and
//! it exited after the three rounds:
//!
//! ```text
//! $ kubectl -n sandboxes logs fictionet-sandbox-demo-default-0 -c wait-blocked
//! fictionet wait-blocked: 10.96.0.1:443 unreachable 3 times in a row, after 4.0 s
//! ```
//!
//! With `networkPolicy.enabled: false`, nothing blocks the pod, and the
//! agent's container did not start. Then `deny-all.yaml`, a NetworkPolicy
//! with an empty `podSelector` and `policyTypes: [Ingress, Egress]`, was
//! applied by hand, and the agent started:
//!
//! ```text
//! $ helm install demo charts/fictionet-sandbox -n sandboxes -f examples/attach/k8s-proxy.yaml --set networkPolicy.enabled=false
//! ...
//! $ kubectl -n sandboxes get pod fictionet-sandbox-demo-default-0
//! NAME                               READY   STATUS     RESTARTS   AGE
//! fictionet-sandbox-demo-default-0   2/3     Init:2/3   0          15s
//! $ kubectl -n sandboxes logs fictionet-sandbox-demo-default-0 -c wait-blocked
//! fictionet wait-blocked: 10.96.0.1:443 still reachable; waiting
//! $ kubectl -n sandboxes apply -f deny-all.yaml
//! networkpolicy.networking.k8s.io/deny-all created
//! $ kubectl -n sandboxes logs fictionet-sandbox-demo-default-0 -c wait-blocked
//! fictionet wait-blocked: 10.96.0.1:443 still reachable; waiting
//! fictionet wait-blocked: 10.96.0.1:443 unreachable 3 times in a row, after 14.5 s
//! $ kubectl -n sandboxes get pod fictionet-sandbox-demo-default-0
//! NAME                               READY   STATUS    RESTARTS   AGE
//! fictionet-sandbox-demo-default-0   3/3     Running   0          27s
//! ```
//!
//! This is what the chart guarantees: the agent's first process runs only
//! after the pod's direct connections to the API server, and to every
//! address in `networkPolicy.waitAddresses`, have failed three rounds in a
//! row. A failed connection is how an enforced policy looks, but an
//! address that is down looks the same. If the API server were down at
//! the moment the CNI was still applying the policy, `wait-blocked` could
//! not tell the two apart. Each address in `networkPolicy.waitAddresses`
//! must then be down at the same time too, so add one or two that are
//! always up. The cluster must provide the rest:
//!
//! - **A CNI that enforces NetworkPolicy,** for egress and ingress, on
//!   all of a pod's traffic at once, so that a blocked API server means
//!   every other destination is blocked too.
//! - **No way to the pod's own node.** Kubernetes lets a CNI allow traffic
//!   between a pod and the node it runs on whatever the policies say, and
//!   some CNIs do. On such a cluster, the agent can reach services on its
//!   node, such as the kubelet, around the proxy. kindnet blocks it: from
//!   the agent's container, the kubelet's port on the node's address
//!   (`172.19.0.2:10250`) and on the pod's gateway (`10.244.0.1:10250`)
//!   timed out. Check your CNI the same way, use its own host policies to
//!   block this traffic, or use `tun`, which takes `eth0` down.
//! - **No other NetworkPolicy that selects the pod.** Policies add up:
//!   one that allows egress to some addresses, or ingress from some
//!   peers, opens those paths beside the proxy, and the chart's policy
//!   cannot take them away. If a namespace-wide policy might allow egress
//!   outside the cluster, add an outside address that the cluster can
//!   reach, such as `1.1.1.1:443`, to `networkPolicy.waitAddresses`, so
//!   the agent does not start while it answers.
//!
//! ## Speed
//!
//! These numbers are from one Ryzen 9 9900X (12 cores, 24 threads), with
//! release builds and the `web_world` example, through the HTTP proxy. The
//! SOCKS5 proxy was about the same. The machine was shared with other work,
//! so the numbers moved from run to run. The table shows the ranges seen.
//!
//! | | on the host | Docker Compose | kind |
//! |---|---|---|---|
//! | one HTTPS download of 16 MiB | 0.018 to 0.024 s (6 to 7 Gbit/s) | 1.8 to 6.9 Gbit/s | 1.8 to 3.5 Gbit/s |
//! | 10 of them at once | 0.20 to 0.24 s | 0.19 to 0.62 s | 0.51 to 0.88 s |
//! | 50 of them at once (800 MiB) | 1.6 to 2.0 s | | |
//! | a 64 MiB HTTPS upload | 0.06 to 0.09 s | 0.08 to 0.24 s | |
//! | 1,000 HTTPS requests, 200 at a time | 0.38 to 0.40 s | 0.46 to 2.0 s, with `docker exec` | |
//! | one new HTTPS request (CONNECT, DNS, TCP, TLS, answer) | 1.3 to 1.8 ms | | |
//!
//! None of the parallel downloads stalled in any run. A packet lost on the
//! way would cost a retransmit of a second or more, which would show.
//! Attach used 5 to 12 MB of memory after these runs. It runs client
//! connections on two worker threads, and its TCP/IP stack on a third.
//!
//! # A virtual machine, with `tap`
//!
//! Use this setup when the agent runs in a virtual machine of your own,
//! under QEMU, Firecracker or Cloud Hypervisor. The VM gets an ordinary
//! Ethernet card. Attach sits on the host side of that card: it takes the
//! card's Ethernet frames, answers the questions that never leave a real
//! Ethernet link (ARP, IPv6 neighbor discovery and, if you give it
//! addresses, DHCP), and moves the IP packets inside the frames to and
//! from the world. The world sees the same IP packets it would see from a
//! `tun` sandbox. Inside the VM, the agent can be root and nothing
//! changes: its kernel has one network card, and every packet through it
//! goes to the world.
//!
//! The frames reach attach in one of two ways, chosen with `--vm`:
//!
//! - **`--vm qemu:<path>`** is for QEMU. QEMU's `-netdev stream` backend
//!   sends the card's frames over a Unix socket instead of a TAP device,
//!   and attach listens on that socket. This needs no root, no TAP device
//!   and no network namespace.
//! - **`--vm tap:<name>`** is for VM programs that only take a TAP device:
//!   Firecracker, Cloud Hypervisor, and QEMU with `-netdev tap`. The VM
//!   program holds the TAP device's file side, and a TAP device has only
//!   one, so attach makes a second TAP device and has the kernel pass
//!   every frame between the two. This needs `CAP_NET_ADMIN` in the TAP
//!   device's network namespace.
//!
#![doc = include_str!("../docs/diagrams/attach-tap.svg")]
//!
//! ## With QEMU, over a socket
//!
//! This starts attach for the sandbox `agent` on the socket
//! `/run/fictionet/agent.sock`, with the world from
//! [`getting_started`](crate::getting_started) already listening:
//!
//! ```sh
//! fictionet attach --world unix:/run/fictionet/world.sock --name agent \
//!     --type tap --vm qemu:/run/fictionet/agent.sock \
//!     --ip-addr 10.0.0.2/24 --gateway 10.0.0.1 --dns 10.0.0.1 --no-ip-addr-v6 \
//!     --ready-file /run/fictionet/agent.ready &
//! ```
//!
//! Attach listens on the socket first, then connects to the world, then
//! writes the ready file. Start QEMU once the ready file exists. The socket
//! has mode 0600, so QEMU must run as attach's user:
//!
//! ```sh
//! qemu-system-x86_64 -enable-kvm -cpu host -m 1G -display none \
//!     -drive file=agent.qcow2,if=virtio -drive file=seed.iso,if=virtio,media=cdrom \
//!     -netdev stream,id=n0,server=off,addr.type=unix,addr.path=/run/fictionet/agent.sock \
//!     -device virtio-net-pci,netdev=n0
//! ```
//!
//! `agent.qcow2` is the VM's disk: here, a Debian 13 cloud image with `dig`
//! installed. `seed.iso` is a cloud-init seed that copies in the world's CA
//! certificate. QEMU adds its default user-mode network card, which reaches
//! the real internet, only when no `-netdev` or `-nic` is given, so this
//! VM has the one card. Attach prints:
//!
//! ```text
//! fictionet attach: agent attached; waiting for QEMU at /run/fictionet/agent.sock
//! fictionet attach: QEMU connected
//! fictionet attach: the VM's MAC is 52:54:00:12:34:56
//! ```
//!
//! The VM's own DHCP client, systemd-networkd here, gets its address,
//! gateway and DNS server from attach while it boots. Inside the VM:
//!
//! ```text
//! $ ip -br link
//! lo               UNKNOWN        00:00:00:00:00:00 <LOOPBACK,UP,LOWER_UP>
//! ens3             UP             52:54:00:12:34:56 <BROADCAST,MULTICAST,UP,LOWER_UP>
//! $ ip -br addr show ens3
//! ens3             UP             10.0.0.2/24 metric 100 fe80::5054:ff:fe12:3456/64
//! $ ip route
//! default via 10.0.0.1 dev ens3 proto dhcp src 10.0.0.2 metric 100
//! 10.0.0.0/24 dev ens3 proto kernel scope link src 10.0.0.2 metric 100
//! 10.0.0.1 dev ens3 proto dhcp scope link src 10.0.0.2 metric 100
//! $ resolvectl dns ens3
//! Link 2 (ens3): 10.0.0.1
//! $ dig +short example.test
//! 203.0.113.10
//! $ curl -sS --cacert /root/ca.pem https://example.test/
//! hello from https example.test 443 over HTTP/2.0
//! $ ping -c 2 10.0.0.1
//! PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.
//! 64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.206 ms
//! 64 bytes from 10.0.0.1: icmp_seq=2 ttl=64 time=0.334 ms
//! ...
//! $ curl -sS http://nowhere.test/
//! curl: (6) Could not resolve host: nowhere.test
//! $ curl -sS http://192.0.2.1/
//! curl: (7) Failed to connect to 192.0.2.1 port 80 after 2 ms: Could not connect to server
//! ```
//!
//! The last two fail immediately: the world's DNS answers NXDOMAIN for a name
//! it does not serve, and it answers a connection to an address it does
//! not serve with ICMP "host unreachable".
//!
//! Attach serves one connection. Once QEMU has connected, attach removes
//! the socket file, so a second VM cannot connect. One attach at a time
//! owns a socket path: attach holds a lock on `<path>.lock`
//! (`/run/fictionet/agent.sock.lock` here) for as long as it runs. A
//! second attach given the same path, by any spelling, exits with status 1
//! and leaves the first one's socket and ready file alone. The lock file
//! stays after attach exits, and the kernel releases the lock however
//! attach ends. When QEMU exits, attach closes its connection to the
//! world, which reads a detach, and exits with status 0:
//!
//! ```text
//! fictionet attach: QEMU closed the connection; agent detached
//! ```
//!
//! **Restarting attach under a running VM.** A new attach is a new
//! attachment: the world sees a detach and then a new attach under the
//! same name. The VM keeps its address, since attach hands out the same
//! one every time, and a world built on
//! [`Sites`](crate::stdlib::web::Sites) binds it again from the VM's next
//! packet. For QEMU to find the new attach, give its netdev
//! `reconnect-ms=500`: QEMU then tries the socket path again every half
//! second. In a test, attach was stopped with SIGTERM while the VM ran,
//! and started again a second later. The VM's next pings and HTTPS
//! requests worked, with no change inside the VM.
//!
//! ## With a TAP device: Firecracker and Cloud Hypervisor
//!
//! Firecracker and Cloud Hypervisor have no socket backend. They open a
//! TAP device by name and hold its file side, which carries the VM's
//! frames. A second program that opens the same TAP device gets `EBUSY`.
//! So attach makes a TAP device of its own, named after the VM's with
//! `-fn` added (`tap0-fn`), and adds a traffic-control redirect on each
//! device: every frame that arrives on `tap0` leaves through `tap0-fn`,
//! and the other way round.
//!
//! Attach's device has no offloads. A VM program such as Firecracker
//! offers the VM checksum and segmentation offloads, so the VM hands it
//! TCP segments of up to 64 KiB with their checksums left unfinished.
//! On the way into `tap0-fn`, the kernel finishes the checksums and splits
//! the segments into frames that fit the MTU, so attach reads the same
//! complete frames it reads from QEMU's socket. The redirect also takes
//! each frame before the namespace's own IP stack sees it.
//!
//! While attach sets this up, `tap0` is down, and the kernel refuses every
//! frame the VM program writes to it. Attach sets `tap0` down first, puts
//! both redirects in place, and only then brings `tap0` up. So no frame
//! from the VM reaches the namespace's IP stack, even when attach is
//! restarted under a running VM. One attach at a time owns a TAP device:
//! a second attach given the same device exits with status 1 before it
//! changes anything.
//!
//! Put the TAP device in a network namespace of its own, with nothing
//! else in it, and create it before the VM program starts. Run attach as
//! root, or with `CAP_NET_ADMIN` in that namespace. The kernel needs the
//! traffic-control modules `sch_ingress`, `cls_matchall` and
//! `act_mirred`, which common distribution kernels ship:
//!
//! ```sh
//! ip netns add vm1
//! ip -n vm1 tuntap add dev tap0 mode tap
//! fictionet attach --world unix:/run/fictionet/world.sock --name agent \
//!     --type tap --vm tap:tap0 --netns /run/netns/vm1 \
//!     --ip-addr 10.0.0.2/24 --gateway 10.0.0.1 --dns 10.0.0.1 --no-ip-addr-v6 \
//!     --ready-file /run/fictionet/agent.ready &
//! ```
//!
//! Once the ready file exists, the namespace holds both devices and the
//! redirect:
//!
//! ```text
//! $ ip -n vm1 -br link
//! lo               DOWN           00:00:00:00:00:00 <LOOPBACK>
//! tap0             DOWN           2e:50:03:59:90:26 <NO-CARRIER,BROADCAST,MULTICAST,UP>
//! tap0-fn          UNKNOWN        32:99:88:69:0c:34 <BROADCAST,MULTICAST,UP,LOWER_UP>
//! $ tc -n vm1 filter show dev tap0 ingress
//! filter parent ffff: protocol all pref 1 matchall chain 0
//! filter parent ffff: protocol all pref 1 matchall chain 0 handle 0x1
//!   not_in_hw
//!         action order 1: mirred (Egress Redirect to device tap0-fn) stolen
//!         index 1 ref 1 bind 1
//! ```
//!
//! Then start the VM program in the namespace, on `tap0`. For Firecracker,
//! the config names the device in `network-interfaces`. This is the nested
//! test's config, with shorter paths:
//!
//! ```text
//! $ ip netns exec vm1 firecracker --no-api --config-file vm1.json
//! ```
//!
//! ```json
//! {
//!   "boot-source": {"kernel_image_path": "vmlinux", "boot_args": "console=ttyS0 reboot=k panic=1"},
//!   "drives": [{"drive_id": "root", "path_on_host": "agent.ext4", "is_root_device": true, "is_read_only": false}],
//!   "network-interfaces": [{"iface_id": "eth0", "host_dev_name": "tap0", "guest_mac": "52:54:00:12:34:56"}],
//!   "machine-config": {"vcpu_count": 1, "mem_size_mib": 512}
//! }
//! ```
//!
//! For Cloud Hypervisor it is `--net tap=tap0`, and for QEMU
//! `-netdev tap,id=n0,ifname=tap0,script=no,downscript=no`.
//!
//! The VM's frames take the same path through attach as QEMU's, so the
//! VM sees the same answers as in [the QEMU section](#with-qemu-over-a-socket).
//! A TAP device stays when the VM program exits, so attach watches for
//! its removal instead: delete `tap0` (`ip -n vm1 link del tap0`), and
//! attach exits with status 0. When attach exits for any other reason,
//! including SIGTERM, SIGINT or SIGHUP, it sets `tap0` down and removes
//! the redirect, and its own device goes with it. A VM that is still
//! running then has no network at all: the kernel drops what it sends,
//! and the namespace's IP stack never sees it. Start attach again to
//! bring the link back.
//!
//! ```text
//! fictionet attach: frames from tap0 go to tap0-fn, and back
//! fictionet attach: agent attached through tap0
//! fictionet attach: the VM's MAC is 52:54:00:12:34:56
//! fictionet attach: tap0 was removed; agent detached
//! ```
//!
//! ## The VM's addresses
//!
//! Attach cannot reach inside a VM to set its address. The VM's own
//! operating system does that, usually with a DHCP client, and writes its
//! own `resolv.conf` from the answer. So for `tap`, the address flags say
//! what attach hands out, one family at a time:
//!
//! - **`--ip-addr` given:** attach answers the VM's DHCP itself, with that
//!   address and prefix, the `--gateway` as the router and the `--dns` as
//!   the DNS server. Give each of `--gateway` and `--dns` a value or its
//!   `--no-` form. The lease also carries the MTU (`--mtu`, 1500 by
//!   default). Attach then passes only IPv4 packets from that address to
//!   the world, and drops the rest.
//! - **All three left out:** attach passes the VM's DHCP to the world like
//!   any other packet. A world built on
//!   [`Sites`](crate::stdlib::web::Sites) answers it. Packets from
//!   `0.0.0.0` reach the world too, since a VM sends its first DHCP
//!   requests before it has an address.
//! - **`--no-ip-addr`:** attach hands out nothing, and drops the VM's
//!   DHCP. Use it for a VM whose address is set inside the image or on the
//!   kernel command line (`ip=10.0.0.2::10.0.0.1:255.255.255.0::eth0:off`).
//!
//! IPv6 has the same three flags, `--ip-addr-v6`, `--gateway-v6` and
//! `--dns-v6`, and the same three choices. Left out, they pass the VM's
//! router solicitations and DHCPv6 requests to the world, along with the
//! rest of its packets from `::` and link-local addresses. But
//! [`Sites`](crate::stdlib::web::Sites) sends no router advertisements and
//! runs no DHCPv6, so with `Sites` a VM gets no IPv6 address that way.
//! Give attach the IPv6 flags, or give it `--no-ip-addr-v6` and set the
//! VM's IPv6 address inside the VM, or write a world that answers both.
//!
//! Given an address, attach answers the VM's router
//! solicitations with a router advertisement and its DHCPv6 requests with
//! the address. The advertisement says to take the address from DHCPv6,
//! puts the address's prefix on the link, and names the DNS server. It
//! makes attach's own link-local address the VM's default router, unless
//! `--no-gateway-v6` is given. A Debian VM with DHCPv6 turned on, attached
//! with `--ip-addr-v6 fd00::2/64 --gateway-v6 fd00::1 --dns-v6 fd00::1`,
//! showed:
//!
//! ```text
//! $ ip -br addr show dev ens3
//! ens3             UP             10.0.0.2/24 metric 100 fd00::2/128 fe80::5054:ff:fe12:3456/64
//! $ ip -6 route
//! fd00::/64 dev ens3 proto ra metric 100 pref medium
//! fe80::/64 dev ens3 proto kernel metric 256 pref medium
//! default nhid 4117034846 via fe80::66:6eff:fe00:1 dev ens3 proto ra metric 100 expires 1799sec pref medium
//! ```
//!
//! Attach answers every ARP request and neighbor solicitation with its own
//! MAC address, `02:66:6e:00:00:01`, whatever address is asked for. So
//! every IP packet the VM sends reaches attach. Attach passes on the ones
//! from the VM's own addresses, and the world decides what is there, as
//! it does for `tun`. A VM's kernel checks that its address is free with
//! duplicate address detection, ARP probes and gratuitous ARP, and attach
//! stays quiet for all three, so the VM never sees its address as taken.
//! Attach also stays quiet when asked for the address it handed out. When
//! the address flags are left out or turned off, attach does not know the
//! VM's address, so it answers for that one too, if the VM ever asks for
//! it from another of its addresses.
//!
//! When attach hands out an IPv6 address, its DHCPv6 server agrees only to
//! that address. A VM that comes back with another one, such as a cached
//! lease from before a snapshot was restored, is told it is not on the
//! link (NotOnLink), and a renewal of it gets lifetimes of 0. Either way,
//! RFC 8415 has the VM's DHCPv6 client drop that address, and ask again
//! for the address attach passes packets from.
//!
//! **MTU.** Frames carry at most `--mtu` bytes of IP packet. Longer ones
//! are dropped both ways. To use a larger MTU, give the VM's card the same
//! one: with QEMU, `-device virtio-net-pci,netdev=n0,host_mtu=9000` and
//! `--mtu 9000`. The VM's DHCP client then sets the MTU from the lease. A
//! test VM showed `mtu 9000` on its card and passed 8,000-byte pings with
//! fragmentation turned off.
//!
//! ## What the agent can do in a VM
//!
//! The agent may be root in the VM, so it can send any frame, change its
//! MAC and addresses, and flood. Attach learns the VM's MAC from its first
//! frame and drops frames from any other MAC, frames to a MAC other than
//! its own or a broadcast or multicast one, VLAN-tagged frames, and every
//! type other than ARP, IPv4 and IPv6. Neighbor discovery always stays on
//! the link: router and neighbor solicitations and advertisements, and
//! redirects, behind any IPv6 extension headers. The one exception is a
//! router solicitation when the IPv6 address flags are left out, which
//! goes to the world. Packets from `0.0.0.0` or a link-local IPv6 address
//! stay on the link too, unless that family's address flags are left out,
//! as [the VM's addresses](#the-vms-addresses) explains. When attach hands
//! out the address, packets from any other source are dropped. The world
//! then applies its own rules, as for `tun`.
//!
//! Attach reads IPv6 extension headers and fragments with the same parser
//! as the stdlib's IP stack in the world, so the agent cannot hide a
//! message from attach that the world's stack would still read. Attach does not put fragments back
//! together. It drops a packet whose headers it cannot read, neighbor
//! discovery in a fragment (which the standard forbids), and the first
//! fragment of a DHCP or DHCPv6 request, unless that family's flags are
//! left out. Without its first fragment, a request cannot be put back
//! together in the world. So a fragmented request never gets an answer
//! from attach, and reaches the world only when the world was left to
//! answer DHCP.
//!
//! With `--vm qemu:`, the host's kernel never sees the VM's frames as
//! network traffic. They go from the virtio queue to QEMU, over a Unix
//! socket, to attach. With `--vm tap:`, the frames pass through the TAP
//! devices and the redirect in the VM's namespace, which has no address,
//! route or other link to reach. Either way, give QEMU or the VM program
//! no other network card.
//!
//! ## Tested with
//!
//! `tests/vm/run.sh` boots the Debian 13 cloud image under QEMU with KVM,
//! with no root, and checks DHCP, `dig`, `curl --cacert`, `ping`, the two
//! fast failures, and IPv6 by router advertisement and DHCPv6.
//! `tests/vm/nested.sh` checks `--vm tap:` with real TAP devices: it boots
//! an outer VM with nested KVM and runs QEMU, Firecracker 1.17 and Cloud
//! Hypervisor 53 inside it, one at a time, each with the same checks.
//! Each needs one command, and skips when KVM, nesting or its images are
//! missing (`--fetch` downloads them once).
//!
//! These numbers are from one Ryzen 9 9900X, with release builds and
//! `web_world`. The nested VMs ran inside the outer VM, so they show the
//! cost of nesting as well. The machine was shared with other work, so
//! the table shows the range over two runs of each test.
//!
//! | | QEMU, `--vm qemu:` | QEMU, `--vm tap:`, nested | Firecracker, nested | Cloud Hypervisor, nested |
//! |---|---|---|---|---|
//! | one HTTPS download of 16 MiB | 0.024 to 0.030 s | 0.086 to 0.56 s | 0.069 to 0.070 s | 0.12 to 0.21 s |
//! | network online, from kernel start | | 7.6 to 7.8 s | 5.9 to 6.4 s | 8.1 to 10.0 s |
//! | VM program start to exit, with the checks | | 18 to 24 s | 12 to 13 s | 20 s |
//!
//! # Addresses
//!
//! This section and the next two apply to `tun`. A VM attached with `tap`
//! gets its addresses as [The VM's addresses](#the-vms-addresses) says.
//!
//! Attach does not run DHCP or listen for router advertisements, so you give
//! it the sandbox's addresses with flags. Six flags set them: `--ip-addr`,
//! `--gateway` and `--dns` for IPv4, and `--ip-addr-v6`, `--gateway-v6` and
//! `--dns-v6` for IPv6. Give each one either a value, or its `--no-` form
//! to turn that setting off:
//!
//! - **A value**, such as `--ip-addr 10.0.0.2/24`. Attach sets it.
//! - **The `--no-` form**, such as `--no-ip-addr-v6`. That setting is off:
//!   for example, no IPv6 address.
//!
//! Attach refuses to start if one of the six is left out, and it refuses
//! both forms of the same flag. Getting addresses from the world instead is
//! on the [roadmap](crate::roadmap#dhcp-and-router-advertisements-in-attach).
//!
//! For example, these are the flags for a world built on
//! [`Sites`](crate::stdlib::web::Sites), whose network is dual-stack. Its
//! gateway and DNS server are at `10.0.0.1` and `2001:db8::1`:
//!
//! ```text
//! --ip-addr 10.0.0.2/24        tun0 gets 10.0.0.2, and 10.0.0.0/24 is on the link
//! --gateway 10.0.0.1           default route via 10.0.0.1
//! --dns 10.0.0.1               "nameserver 10.0.0.1" in resolv.conf
//! --ip-addr-v6 2001:db8::2/64  tun0 gets 2001:db8::2, and 2001:db8::/64 is on the link
//! --gateway-v6 2001:db8::1     IPv6 default route via 2001:db8::1
//! --dns-v6 2001:db8::1         "nameserver 2001:db8::1" in resolv.conf
//! ```
//!
//! A sandbox with IPv6 needs IPv6 turned on in its network namespace.
//! Docker turns it off in a container without an IPv6 network, so the
//! Compose setup above turns it back on with `sysctls`. If it is off,
//! attach fails and its message names the sysctl to set.
//!
//! For a sandbox with IPv4 only, give the `--no-` forms instead of the
//! three IPv6 flags:
//!
//! ```text
//! --no-ip-addr-v6              no IPv6 address
//! --no-gateway-v6              no IPv6 default route
//! --no-dns-v6                  no IPv6 nameserver line
//! ```
//!
//! With both `--no-ip-addr-v6` and `--no-gateway-v6`, attach also turns off
//! automatic IPv6 addresses on its device. Then `tun0` has no IPv6
//! link-local address, and the sandbox's kernel sends no IPv6 packets of its
//! own through it. Other interfaces in the namespace, if there are any, do
//! not change. Such a sandbox still works in a dual-stack world. Programs
//! that look names up with glibc's `getaddrinfo` in the usual way, such as
//! curl, get only IPv4 addresses when the sandbox has no IPv6 address. A
//! connection to an IPv6 address fails immediately with "Network is
//! unreachable". A world that models an IPv4-only network can
//! also turn IPv6 off on its side, with
//! [`Sites::ipv4_only`](crate::stdlib::web::Sites::ipv4_only).
//!
//! The world is never told the sandbox's addresses. It sees them in the
//! packets. `Sites` takes a sandbox's IPv4 and IPv6 addresses from the
//! source of its first packet of each family, and from then on drops
//! packets from that sandbox with any other source address. So give each
//! sandbox of a world its own addresses.
//!
//! # DNS and `resolv.conf`
//!
//! A program finds its DNS server in `/etc/resolv.conf`, which is a file.
//! The file is not part of the network namespace, so setting up the network
//! does not set up DNS. Some process has to write a file that the sandbox's
//! programs read. The DNS server it names, such as `10.0.0.1`, is world
//! code: in a world built on `Sites`, the gateway answers DNS.
//!
//! This table says who writes the sandbox's `resolv.conf` in each setup:
//!
//! | Where the sandbox runs | Who writes its `resolv.conf` |
//! |---|---|
//! | host, `ip netns exec` | attach writes `/etc/netns/<name>/resolv.conf`, and `ip netns exec` mounts it |
//! | host, `nsenter`, runc or another runtime | the harness, or attach with `--resolv-conf <path>` |
//! | Docker, `network_mode: "service:attach"` | attach, in place, in the host file both containers mount |
//! | Kubernetes, the `fictionet-sandbox` chart | the kubelet, from the pod's `dnsConfig`; attach has `--no-resolv-conf` |
//! | any `tun` setup with `--no-resolv-conf` | the harness |
//! | a VM on `tap` | the VM, from DHCP, DHCPv6 and router advertisements: sent by attach with `--dns` and `--dns-v6`, or by the world when a family has none of its address flags |
//! | behind a proxy (`http_proxy`, `socks5`) | no file: attach looks names up at `--dns` |
//!
//! ## `--resolv-conf` and `--no-resolv-conf`
//!
//! By default, attach writes `/etc/resolv.conf` as attach itself sees it,
//! or `/etc/netns/<name>/resolv.conf` with `--netns`. Use these two flags
//! when the agent reads its DNS settings from somewhere else:
//!
//! - **`--resolv-conf <path>`** writes the file at `<path>` instead, and
//!   makes its directory if needed.
//! - **`--no-resolv-conf`** writes no file. DNS is then up to the harness.
//!
//! Attach runs as root, so it never writes through a link: a `resolv.conf`
//! path that is a symlink, or a file with other hard links, is an error.
//! The `--ready-file` is always made new, replacing whatever was at its
//! path.
//!
//! For example, a harness might start the agent with runc, in the namespace
//! `/run/netns/agent`, and give it the host directory `/srv/agent/etc` as
//! its `/etc`. Then attach should write the file there:
//!
//! ```sh
//! fictionet attach --world unix:/run/fictionet/world.sock --name agent --type tun \
//!     --netns /run/netns/agent --resolv-conf /srv/agent/etc/resolv.conf \
//!     --ip-addr 10.0.0.2/24 --gateway 10.0.0.1 --dns 10.0.0.1 \
//!     --ip-addr-v6 2001:db8::2/64 --gateway-v6 2001:db8::1 --dns-v6 2001:db8::1
//! ```
//!
//! Attach rewrites the file in place there too. If it cannot write the
//! file, attach exits with status 1, and the message names the path and
//! these two flags. It never carries on with the wrong DNS.
//!
//! # Checking that it works
//!
//! Run these commands inside the sandbox: with `ip netns exec agent` or
//! `examples/attach/netns.sh` on a host, or with
//! `docker compose -f examples/attach/compose-tun.yaml exec agent` in the
//! Compose setup. The outputs are from
//! [`getting_started`](crate::getting_started), with the `web_world`
//! example as the world.
//!
//! 1. **The device and its addresses.** `ip addr show tun0` shows
//!    `inet 10.0.0.2/24` and `inet6 2001:db8::2/64`. `ip route` shows
//!    `default via 10.0.0.1 dev tun0`, and `ip -6 route` shows
//!    `default via 2001:db8::1 dev tun0`.
//! 2. **DNS.** `cat /etc/resolv.conf` shows `nameserver 10.0.0.1` and
//!    `nameserver 2001:db8::1`. `dig +short example.test` prints
//!    `203.0.113.10`, and `dig +short AAAA example.test` prints
//!    `2001:db8:113::10`: answers from the world.
//! 3. **The gateway.** `ping -c 1 10.0.0.1` and `ping -6 -c 1 2001:db8::1`
//!    get replies from the world.
//! 4. **HTTPS.** `curl -sS --cacert <the world's CA> https://example.test/`
//!    prints `hello from https example.test 443 over HTTP/2.0`. Without
//!    `--cacert`, it fails with curl's error 60, because the sandbox does
//!    not trust the world's CA.
//!
//! If step 1 fails, read attach's messages. If step 1 works but step 2
//! fails, the sandbox reads a different `resolv.conf`: see
//! [DNS and `resolv.conf`](#dns-and-resolvconf).
//!
//! # Every flag
//!
//! `fictionet attach --help` prints the same list, with the flags each type
//! takes. A flag's value is the next argument, or follows `=`, as in
//! `--mtu=1400`. A next argument that starts with `--` is read as a flag,
//! so a value that starts with `--` must use `=`, as in
//! `--resolv-conf=--odd-name`.
//!
//! | Flag | Types | What it does |
//! |---|---|---|
//! | `--world unix:<path>` | all | the world's socket |
//! | `--name <name>` | all | the sandbox's name, which the world sees as [`Attachment::name`](crate::Attachment::name) |
//! | `--type <type>` | all | `tun`, `tap`, `http_proxy` or `socks5`: see [Choose your setup](#choose-your-setup) |
//! | `--world-wait <seconds>` | all | keep trying to connect for that long, for a world that is still starting; without it, attach tries once ([How `tun` works](#how-tun-works)) |
//! | `--ready-file <path>` | all | create this file once the world has accepted the sandbox ([How `tun` works](#how-tun-works)) |
//! | `--ip-addr`, `--gateway`, `--dns`, and the same with `-v6` | `tun`, `tap` | the sandbox's addresses, each given a value or turned off with its `--no-` form ([Addresses](#addresses), [The VM's addresses](#the-vms-addresses)) |
//! | `--ip-addr <ip>`, `--dns <ip>` | `http_proxy`, `socks5` | the address attach sends from, as the sandbox, and the world's DNS server ([Running the proxy](#running-the-proxy)) |
//! | `--netns <path>` | `tun`, and `tap` with `--vm tap:` | the network namespace to work in, instead of attach's own ([How `tun` works](#how-tun-works)) |
//! | `--mtu <n>` | `tun`, `tap` | the MTU, 1500 by default and at least 1280 |
//! | `--down-link <ifname>` | `tun` | take another link out of the way first: delete its routes and addresses, and set it down; give it once per link ([On Kubernetes](#on-kubernetes)) |
//! | `--resolv-conf <path>`, `--no-resolv-conf` | `tun` | where to write the DNS servers, or write nothing ([`--resolv-conf` and `--no-resolv-conf`](#--resolv-conf-and---no-resolv-conf)) |
//! | `--vm qemu:<path>`, `--vm tap:<ifname>` | `tap` | how the VM's frames reach attach ([A virtual machine](#a-virtual-machine-with-tap)) |
//! | `--listen <ip:port>`, `--token-file <path>` | `http_proxy`, `socks5` | where the proxy listens, and the file with the sandbox's token ([Running the proxy](#running-the-proxy)) |
