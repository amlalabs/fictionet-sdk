# Demos

Each demo is one command. It boots the Fictionet VM if it is not running
([vm/README.md](../vm/README.md)), builds Fictionet inside it, runs the demo, and
cleans up. Each step says in plain words what happens next, then shows the
commands and their real output. Nothing needs root or Docker on your machine:
QEMU, KVM and [the other host tools](../vm/README.md#the-fictionet-vm) are required.

```console
$ demos/dashboard
```

Start with the dashboard to see requests in the world's live log, or run
[`demos/border`](border) to see the log label a password sent to the impostor.
Both use scripted traffic and need no model key.

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
The web, proxy and dashboard demos wait for the world's socket and a complete,
readable CA certificate before continuing. If the world exits or startup times
out, they stop and print the world log.

Refusal steps require the expected exit status and diagnostic. An unexpected
timeout, missing command, or failed runner stops the demo. The scripts capture
status and output before formatting them for display. Output checks show only
matching lines on success and the full capture on failure. The direct TCP refusal
in `demos/web` must finish within three seconds. The proxy's unknown-name check
requires both HTTP 502 and `X-Proxy-Error: no such name in the world`.

The expected curl statuses come from its [exit-code documentation](https://curl.se/docs/manpage.html#exit-codes)
and the world's DNS, TLS and routing behavior. `tests/k8s/run.sh` also checks
`Could not resolve host`, `Couldn't connect`, `no servers could be reached` and
`Operation not permitted`. `tests/docker/proxy/run.sh` checks `response 407`,
`connection to nope.test. (4)`, `Network is unreachable|Couldn't connect` and
`X-Proxy-Error: no such name in the world`. `No route to host` is checked in
`tests/docker/web/run.sh` and `vm/guest/tests/netns.sh`.

Two expectations come only from the tools' documented behavior. Curl's certificate
refusal is exit 60 with `SSL certificate problem`. GNU `ls` on a mode-0700 directory
as another user exits 2 with `Permission denied`. Run the refusal and launcher
fixtures without a VM with `python3 -m unittest discover -s demos/tests -p 'test_*.py'`.

## How long they take

Historical measurements on a 24-core machine with other work running, with the
VM's default 4 vCPUs and 5 GB. "In all" is the whole command: the VM's boot, the
build and the demo, and the shutdown.

| Cold setup or warm run | In all | Of which |
|---|---|---|
| The first `demos/web` on a machine | 229 s | download and check the Debian image about 10 s, prepare it 160 s, boot 7.5 s, first build 45 s, demo 3.5 s |
| Warm `demos/web` | 10 s | boot 5.2 s, build 0.2 s, demo 3.5 s |
| `demos/proxy` | 8 s | demo 0.5 s |
| `demos/k8s`, first | 77 s | includes pulling kind's node image |
| `demos/k8s` after that | 55 s | the cluster's start is most of it |
| `demos/border`, first | 175 s | builds `border-world` and Border's three images |
| Warm `demos/border` | 39 s | demo 27 s |
| `demos/dashboard`, with `DASHBOARD_SECONDS=5` | 20 s | |

Docker's images and build cache, cargo's build output and uv's cache stay on the
VM's cache disk, so only the first run of each demo pays for them.
