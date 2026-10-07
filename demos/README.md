# Demos

Each demo is one command. It boots the Fictionet VM if it is not running
([vm/README.md](../vm/README.md)), builds Fictionet inside it, runs the demo, and
cleans up. Each step says in plain words what happens next, then shows the
commands and their real output. Nothing needs root or Docker on your machine:
only QEMU and KVM.

```console
$ demos/web
```

The first demo on a machine downloads and prepares the VM image, which takes a few
minutes. After that a demo boots the VM in seconds. A demo that booted the VM shuts
it down at the end. Run `vm/run up` first to keep one VM for several demos, and
`vm/run down` when you are done.

| Demo | What it shows |
|---|---|
| [`demos/web`](web) | The sandbox is a network namespace named `agent`, and `fictionet attach --type tun` puts `tun0` in it. From inside: `dig` answers the world's names and NXDOMAIN for the rest, `curl` reaches `https://example.test/` with the world's CA and fails without it, `ping` reaches the gateway, an address with no machine fails at once, and `example.com` and `1.1.1.1` are not there. |
| [`demos/proxy`](proxy) | A sandbox with only a loopback interface, whose commands run as an unprivileged user with no capabilities. Two attaches inside its namespace serve `--type http_proxy` and `--type socks5`. `curl` and Python reach the world through `http_proxy`, and `curl` through SOCKS5. A wrong token gets 407, an unknown name gets 502 with the reason, and around the proxy there is no network. |
| [`demos/k8s`](k8s) | A kind cluster in the VM, the Helm chart in `charts/fictionet-sandbox` with `examples/attach/k8s-tun.yaml`, and the agent's pod. Its `eth0` is down, `tun0` is its only route, it reaches `https://example.test/`, and the internet, the cluster's DNS and the API server are out of reach. |
| [`demos/border`](border) | [Border](../examples/border)'s world under Docker Compose, with a scripted agent and no model. First the real bank: sign-in, balance, three hops, one BGP route. Then the hijack: a fourth hop and a more specific route from AS 65002, an impostor certificate that `curl` refuses, and with `curl -k`, the password sent to the impostor, as the world's log shows. |
| [`demos/dashboard`](dashboard) | The world and sandbox of `demos/web`, with `fictionet dashboard` serving the live view on the VM's port 7878, which `vm/run` forwards to `127.0.0.1` on your machine. It prints the address to open, and `fictionet observe` shows the same API from a shell: the graph, and the world's custom events as they happen. A loop in the sandbox makes requests until you press Enter (or for `DASHBOARD_SECONDS`). |

The scripts that run inside the VM are in [`guest/`](guest). Each starts with a
`# needs:` line that says which binaries `vm/guest/build.sh` builds for it.

## How long they take

Measured on a 24-core machine with other work running, with the VM's default 4
vCPUs and 5 GB. "In all" is the whole command: the VM's boot, the build and the
demo, and the shutdown.

| Run | In all | Of which |
|---|---|---|
| The first `demos/web` on a machine | 229 s | download and check the Debian image about 10 s, prepare it 160 s, boot 7.5 s, first build 45 s, demo 3.5 s |
| `demos/web` after that | 10 s | boot 5.2 s, build 0.2 s, demo 3.5 s |
| `demos/proxy` | 8 s | demo 0.5 s |
| `demos/k8s`, first | 77 s | includes pulling kind's node image |
| `demos/k8s` after that | 55 s | the cluster's start is most of it |
| `demos/border`, first | 175 s | builds `border-world` and Border's three images |
| `demos/border` after that | 39 s | demo 27 s |
| `demos/dashboard`, with `DASHBOARD_SECONDS=5` | 20 s | |

Docker's images and build cache, cargo's build output and uv's cache stay on the
VM's cache disk, so only the first run of each demo pays for them.
