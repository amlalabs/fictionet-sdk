# The Fictionet VM

`vm/run` boots a small Debian VM under QEMU and KVM, and runs Fictionet's demos
and test suites inside it. Inside the VM they have root, so tun devices, network
namespaces, Docker Compose and kind all work. On your own machine, nothing needs
root, and Docker is not used at all.

You need Linux on x86-64 with:

- `qemu-system-x86_64` and `qemu-img`;
- `/dev/kvm` that your user can read and write (on most distributions, membership
  in the `kvm` group);
- `genisoimage`, `mkisofs` or `xorriso`, for the cloud-init seed, which is used
  only the first time;
- `curl`, `ssh`, `ssh-keygen`, `tar`, `flock`, `sha256sum`, `sha512sum` and `git`.
  `vm/run sync` copies tracked and unignored files from a git checkout.
  It excludes `fuzz/corpus`.
- A systemd user session, for the memory cap below. Without one, the VM runs
  uncapped, and `vm/run` says so.

You don't need Rust, Docker or `sudo`. The VM builds Fictionet itself.

## Using it

```console
$ vm/run up
The VM is up in 6.1 s: 4 vCPUs, 5G, SSH on 127.0.0.1:2222, port 7878 on 127.0.0.1:7878.
$ vm/run test netns
...
ALL PASSED

vm/run test netns: PASSED in 3.6 s (log in .vm/test-netns.log)
$ vm/run ssh
root@fictionet-vm:~#
$ vm/run down
The VM is down, and its overlay is deleted.
```

The first `vm/run up` downloads the Debian image and prepares it, which takes
about three minutes. After that, the VM boots in 5 to 10 seconds. One `vm/run`
command at a time changes the VM: a second one waits for the first.

| Command | What it does |
|---|---|
| `vm/run prepare` | Downloads and prepares the base image without leaving a VM running. |
| `vm/run up` | Boots the VM. The first time, it downloads and prepares the image. |
| `vm/run ssh [command]` | Opens a root shell in the VM, or runs one command there. |
| `vm/run sync` | Copies this working tree into the VM, at `/src`. |
| `vm/run build [sdk] [border] [fakewiki]` | Syncs, then builds the static binaries in the VM (see below). |
| `vm/run test <name>` | Runs one test suite in the VM. `vm/run test list` lists them. |
| `vm/run demo <name>` | What `demos/<name>` runs. |
| `vm/run status` | Says whether the VM is running, on which ports, and how much disk `.vm/` uses. |
| `vm/run down` | Shuts the VM down and deletes its disk overlay. |
| `vm/run clean` | Shuts down, and deletes everything under `.vm/`. |

`vm/run test` and the demos boot the VM if it is not running, and shut it down
again when they finish. If it was already running, they leave it running, so a
series of tests or demos pays for one boot. Set `VM_KEEP=1` to keep a VM that a
demo booted. `VM_CPUS` (default 4) and `VM_MEM` (default `5G`) size the VM. QEMU runs in a
systemd user scope capped at `VM_MEM` plus 1 GiB, so the VM cannot take more of
your memory than that. `VM_SCOPE=0` runs it without the scope.

## The test suites

Each suite runs unchanged, the way its own README says. `vm/guest/test.sh` only
starts it and decides whether it passed. The log of the last run of each suite is
in `.vm/test-<name>.log`.

| Name | What runs |
|---|---|
| `netns` | `vm/guest/tests/netns.sh`: the README's quick start, checked. A network namespace named `agent`, attached with `--type tun --netns`. |
| `docker-web` | `tests/docker/web/run.sh`: `web::Sites` under Docker Compose, attached with `--type tun`. |
| `docker-proxy` | `tests/docker/proxy/run.sh`: `--type http_proxy` and `--type socks5` under Docker Compose. |
| `docker-ping`, `docker-tcpudp` | `tests/docker/ping/run.sh` and `tests/docker/tcpudp/run.sh`. |
| `k8s` | `tests/k8s/run.sh`: the Helm chart on kind, attached with `--type tun`. |
| `k8s-proxy` | `tests/k8s/proxy.sh`: the Helm chart on kind with the proxy types, under Pod Security "restricted". |
| `border-world` | `cargo test` in `examples/border/world`. |
| `border-scripted` | Border's `border_scripted` task, lab and home settings, with Inspect's mock model. |
| `border-probes` | Border's `border_probes` task, lab and home settings. |
| `fakewiki-probes` | FakeWiki's `fakewiki_probes` task, and its leak checker's negative control. |
| `cargo` | `cargo test --features web-proxy`, then `tests/tun_linux.rs` with `--ignored`, since it needs root and a tun device. |

The Docker and Inspect suites build their images inside the VM, from the
examples' own Dockerfiles, the first time. Docker keeps those images and its
build cache on the cache disk, so later runs reuse them.

## How it works

**The image.** The base is Debian's official Debian 13 (trixie) `genericcloud`
image, a dated build pinned in `vm/versions.sh`. `vm/run` checks its SHA-512
against the `SHA512SUMS` file Debian publishes next to it. Preparing boots it once,
with a cloud-init seed ISO that holds only an SSH key, and runs
`vm/guest/provision.sh` over SSH. That installs Docker Engine with the Compose and
Buildx plugins (from Docker's apt repository, with its key's fingerprint
checked), kind, kubectl, helm and uv (each checked against its published
SHA-256), Rust with the musl target, and curl, dig, ping, traceroute, ip and
python3. Then it turns cloud-init off, so later boots skip it. The result is
`.vm/images/prepared-<key>.qcow2`, an overlay on the Debian image. Its key is a
hash of `vm/versions.sh`, `vm/guest/provision.sh` and the SSH public key,
so a change to any of them prepares a new image.

**Each run** boots from a fresh qcow2 overlay on the prepared image, which is
deleted by `vm/run down`. The prepared image is never written to.

**The cache disk.** A second disk, `.vm/cache.qcow2`, is mounted at `/cache` in
the VM and kept between runs. It holds Docker's images and build cache, cargo's
registry and build output, and uv's cache. So a demo after a small change to the
code rebuilds in seconds, and an image pulled once stays pulled. It grows up to
80 GB. `vm/run clean` deletes it.

**Network.** The VM uses QEMU's user-mode network (slirp), which needs no root.
`vm/run` forwards a free port on `127.0.0.1` to the VM's SSH (2222 when it is
free), and another to the VM's port 7878. The VM reaches the internet through it
to install packages and pull images. Fictionet's sandboxes inside the VM reach
only their world. In slirp, the address 10.0.2.2 is your machine's own
`127.0.0.1`. Nothing in the VM needs it, so a firewall rule in the VM drops new
connections to it, from the VM and from its containers.

**SSH.** `vm/run` connects with `ssh -F /dev/null` and its own key in `.vm/ssh/`,
so none of your SSH settings apply: no agent, X11 or port forwarding into your
machine. Everything under `.vm/` is readable by you alone.

**Code.** `vm/run sync` copies the working tree into `/src` over SSH with `tar`:
the tracked files, and untracked ones that are not ignored, so uncommitted
changes are included. File times are kept, so cargo rebuilds only what changed.
`vm/guest/build.sh` then builds static musl binaries of `fictionet`, `web_world`,
`web_fixture`, `border-world` and `fakewiki-world`, into `/opt/fictionet/bin`.
Static binaries run in the VM and in any container image, so the demos put them
straight into images, without a second build.

## Why it is built this way

- **Build inside the VM, not on your machine.** The VM already has Rust, so your
  machine needs none, and the binaries are the same wherever the VM runs. With
  build output on the cache disk, a rebuild after a change takes seconds. A
  first build takes about 30 seconds on 4 vCPUs.
- **Copy the code with `tar` over SSH, not share it with 9p.** QEMU's `-virtfs`
  needs the guest kernel's 9p modules, and builds that write into a shared
  folder are slow and can leave root-owned files in your tree. `tar` over the
  SSH connection that is already open takes a fraction of a second for this
  repository, and works the same on every host and in CI.
- **Debian's cloud image, not a custom one.** Debian publishes it with
  checksums, and it boots in seconds. Preparing it once and caching the result
  keeps every later boot fast.
- **Turn cloud-init off after preparing.** Each later boot would otherwise
  search for a data source. With the SSH key already in the image, there is
  nothing for it to do.

The VM differs from a stock Debian install in one way that matters for
Fictionet: `/etc/nsswitch.conf` looks names up with `files myhostname dns`.
Debian's cloud image uses systemd-resolved's NSS module, which asks resolved over
a socket. Resolved runs in the VM's own network namespace, so a program in a
sandbox namespace would get the VM's real DNS, whatever
`/etc/netns/agent/resolv.conf` says. The same holds on any host that uses
`nss-resolve`.

## Troubleshooting

- **`/dev/kvm is not usable`**: add yourself to the `kvm` group
  (`sudo usermod -aG kvm $USER`, then log in again).
- **The VM does not answer SSH**: `.vm/run/console.log` has its serial console.
- **Preparing failed**: `.vm/prepare.log` has the whole log. Run `vm/run up`
  again to retry. A partly prepared image is never used.
- **The Debian build in `vm/versions.sh` is gone**: Debian removes old dated
  builds after some months. Pick a newer one from
  <https://cloud.debian.org/images/cloud/trixie/> and update `DEBIAN_BUILD`.
- **Start over**: `vm/run clean` deletes `.vm/`, images and cache included.
