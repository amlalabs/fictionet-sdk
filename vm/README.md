# The Fictionet VM

`cargo xtask vm up` boots a small Debian VM under QEMU and KVM, and runs Fictionet's demos
and test suites inside it. Inside the VM they have root, so tun devices, network
namespaces, Docker Compose and kind all work. On your own machine, nothing needs
root, and Docker is not used at all.

This directory owns the development appliance and its host commands. To
attach an agent VM's network to a world, follow
[the attachment guide](../src/guide/attaching.rs), section "A virtual machine, with `tap`".
`cargo xtask vm` and `cargo xtask vm nested` exercise that attachment path.

You need Linux on x86-64 with:

- Rust and Cargo, using the repository's `rust-toolchain.toml`;
- `qemu-system-x86_64` and `qemu-img`;
- `/dev/kvm` that your user can read and write (on most distributions, membership
  in the `kvm` group);
- `genisoimage`, for the cloud-init seed, which is used only the first time;
- `curl`, `ssh`, `ssh-keygen`, `tar`, `sha256sum`, `sha512sum` and `git`.
  `cargo xtask vm sync` copies tracked and unignored files from a git checkout.
  It excludes `fuzz/corpus`.
- A systemd user session, for the memory cap below. Without one, the VM runs
  uncapped, and `cargo xtask vm` says so.

You don't need Docker or `sudo`. The VM builds Fictionet itself.

## Using it

```console
$ cargo xtask vm up
The VM is up in 6.1 s: 4 vCPUs, 5G, SSH on 127.0.0.1:2222, port 7878 on 127.0.0.1:7878.
$ cargo xtask vm test netns
...
ALL PASSED

cargo xtask vm test netns: PASSED in 3.6 s (log in .vm/test-netns.log)
$ cargo xtask vm ssh
root@fictionet-vm:~#
$ cargo xtask vm down
The VM is down, and its overlay is deleted.
```

The first `cargo xtask vm up` downloads the Debian image and prepares it, which takes
about three minutes. After that, the VM boots in 5 to 10 seconds. One `cargo xtask vm`
command at a time changes the VM: a second one waits for the first.

| Command | What it does |
|---|---|
| `cargo xtask vm prepare` | Downloads and prepares the base image without leaving a VM running. |
| `cargo xtask vm up` | Boots the VM. The first time, it downloads and prepares the image. |
| `cargo xtask vm ssh [command]` | Opens a root shell in the VM, or runs one command there. |
| `cargo xtask vm sync` | Copies this working tree into the VM, at `/src`. |
| `cargo xtask vm build [sdk]` | Syncs, then builds the static binaries in the VM (see below). |
| `cargo xtask vm test <name>` | Runs one test suite in the VM. The table below lists them. |
| `cargo xtask demo <name>` | Runs a [demo](../demos/README.md). |
| `cargo xtask vm status` | Says whether the VM is running, on which ports, and how much disk `.vm/` uses. |
| `cargo xtask vm down` | Shuts the VM down and deletes its disk overlay. |
| `cargo xtask vm clean` | Shuts down, and deletes everything under `.vm/`. |

`cargo xtask vm test` and the demos boot the VM if it is not running, and shut it down
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
| `netns` | `vm/guest/tests/netns.sh`: [the getting-started tutorial](../src/guide/getting_started.rs), checked. A network namespace named `agent`, attached with `--type tun --netns`. |
| `docker-web` | `cargo xtask docker web`: `web::Sites` under Docker Compose, attached with `--type tun`. |
| `docker-proxy` | `cargo xtask docker proxy`: `--type http_proxy` and `--type socks5` under Docker Compose. |
| `docker-ping`, `docker-tcpudp` | `cargo xtask docker ping` and `cargo xtask docker tcpudp`. |
| `k8s` | `cargo xtask k8s tun`: the Helm chart on kind, attached with `--type tun`. |
| `k8s-proxy` | `cargo xtask k8s proxy`: the Helm chart on kind with the proxy types, under Pod Security "restricted". |
| `border-world` | `cargo test` in `examples/border/world`. |
| `border-scripted` | Border's `border_scripted` task, lab and home settings, with Inspect's mock model. |
| `border-probes` | Border's `border_probes` task, lab and home settings. |
| `fakewiki-probes` | FakeWiki's `fakewiki_probes` task, and its leak checker's negative control. |
| `cargo` | `cargo test --features web-proxy,tokio`, then `cargo test --test host`, the tests that need user namespaces, root and a tun device. |

The Docker and Inspect suites build their images inside the VM, from the
examples' own Dockerfiles, the first time. Docker keeps those images and its
build cache on the cache disk, so later runs reuse them.

## How it works

**The image.** The base is Debian's official Debian 13 (trixie) `genericcloud`
image, a dated build pinned in `xtask/src/vm.rs`. `cargo xtask vm` checks its SHA-512
against the pinned checksum from Debian's `SHA512SUMS`. Preparing boots it once,
with a cloud-init seed ISO that holds only an SSH key, and runs
`vm/guest/provision.sh` over SSH. That installs Docker Engine with the Compose and
Buildx plugins (from Docker's apt repository, with its key's fingerprint
checked), kind, kubectl, helm and uv (each checked against its published
SHA-256), Rust with the musl target, and curl, dig, ping, traceroute, ip and
python3. Then it turns cloud-init off, so later boots skip it. The result is
`.vm/images/prepared-<key>.qcow2`, an overlay on the Debian image. Its key is a
hash of the image and tool versions in `xtask/src/vm.rs`, `vm/guest/provision.sh`,
`rust-toolchain.toml` and the SSH public key, so a change to any of them prepares
a new image.

The TAP tests in `cargo xtask vm` use the same image constants, including the pinned
SHA-512. Their base and prepared disks stay directly under `.vm/` (or
`FICTIONET_VM_DIR`), separate from the appliance's `.vm/images/` disks. Their
provisioning and network lifecycles stay separate too. Both workflow cache keys
include `xtask/src/vm.rs`.

The VM follows the checkout's `rust-toolchain.toml`. Provisioning bundles that
file, installs its compiler and components, and adds `x86_64-unknown-linux-musl`
to that compiler. It also makes that compiler the VM's default. Builds in `/src`
select it through the same descriptor after sync. If you change the descriptor
while a VM is running, run `cargo xtask vm down` and `cargo xtask vm up` to prepare a new image.
Docker builds keep the compiler versions in their own Dockerfiles.

**Each run** boots from a fresh qcow2 overlay on the prepared image, which is
deleted by `cargo xtask vm down`. The prepared image is never written to.

**The cache disk.** A second disk, `.vm/cache.qcow2`, is mounted at `/cache` in
the VM and kept between runs. It holds Docker's images and build cache, cargo's
registry and build output, and uv's cache. So a demo after a small change to the
code rebuilds in seconds, and an image pulled once stays pulled. It grows up to
80 GB. `cargo xtask vm clean` deletes it.

**Network.** The VM uses QEMU's user-mode network (slirp), which needs no root.
`cargo xtask vm` forwards a free port on `127.0.0.1` to the VM's SSH (2222 when it is
free), and another to the VM's port 7878. The VM reaches the internet through it
to install packages and pull images. Fictionet's sandboxes inside the VM reach
only their world. In slirp, the address 10.0.2.2 is your machine's own
`127.0.0.1`. Nothing in the VM needs it, so a firewall rule in the VM drops new
connections to it, from the VM and from its containers.

**SSH.** `cargo xtask vm` connects with `ssh -F /dev/null` and its own key in `.vm/ssh/`,
so none of your SSH settings apply: no agent, X11 or port forwarding into your
machine. Everything under `.vm/` is readable by you alone.

**Code.** `cargo xtask vm sync` copies the working tree into `/src` over SSH with `tar`:
the tracked files, and untracked ones that are not ignored, so uncommitted
changes are included. File times are kept, so cargo rebuilds only what changed.
`vm/guest/build.sh` then builds static musl binaries of `fictionet` and the crate's
examples into `/opt/fictionet/bin`.
Static binaries run in the VM and in any container image, so the demos put them
straight into images, without a second build.

## Why it is built this way

- **Build inside the VM, not on your machine.** The VM already has Rust, and
  the binaries are the same wherever the VM runs. With
  build output on the cache disk, a rebuild after a change takes seconds. A
  first build takes about two minutes on 4 vCPUs.
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

Provisioning changes Debian's DNS setup in two ways. First,
`/etc/nsswitch.conf` looks names up with `files myhostname dns`. With plain
`dns`, glibc reads `/etc/resolv.conf`, which `ip netns exec` swaps per namespace.
Second, provisioning stops and masks systemd-resolved so sandbox workloads
cannot ask the VM's resolver through local sockets. It writes a plain
`/etc/resolv.conf` with `nameserver 10.0.2.3`, QEMU's user-net DNS, so the VM
keeps DNS access.

## Troubleshooting

- **`/dev/kvm is not usable`**: add yourself to the `kvm` group
  (`sudo usermod -aG kvm $USER`, then log in again).
- **The VM does not answer SSH**: `.vm/run/console.log` has its serial console.
- **Preparing failed**: `.vm/prepare.log` has the whole log. Run `cargo xtask vm up`
  again to retry. A partly prepared image is never used.
- **The Debian build in `xtask/src/vm.rs` is gone**: Debian removes old dated
  builds after some months. Pick a newer one from
  <https://cloud.debian.org/images/cloud/trixie/> and update `DEBIAN_BUILD` and
  `DEBIAN_SHA512` from that build's `SHA512SUMS`. The filename and URL are
  derived from the build in the same module.
- **Start over**: `cargo xtask vm clean` deletes `.vm/`, images and cache included.
