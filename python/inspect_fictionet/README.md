# inspect_fictionet

`inspect_fictionet` puts an [Inspect](https://inspect.aisi.org.uk) eval's agent
inside a Fictionet world with one function call. You name the world's image
and the agent's image. The package writes the compose file that runs the
world, `fictionet attach` and the agent in the right order, and hands it to
Inspect's docker sandbox. On Kubernetes, it writes values for the
`fictionet-sandbox` Helm chart instead, and hands them to
[inspect_k8s_sandbox](https://k8s-sandbox.aisi.org.uk).

Without the package, each eval carries a compose file like
[`examples/hosted/compose.yaml`](../../examples/hosted/compose.yaml): about 70
lines of services, volumes, healthchecks and attach flags. With it, the
sandbox is one argument.

## Install

The package is not on PyPI. Install it from the repository:

```sh
pip install "git+https://github.com/amlalabs/fictionet-sdk#subdirectory=python/inspect_fictionet"
# with the Kubernetes backend:
pip install "inspect-fictionet[k8s] @ git+https://github.com/amlalabs/fictionet-sdk#subdirectory=python/inspect_fictionet"
```

It needs Python 3.12 or later and inspect-ai 0.3.276 or later. The docker
backend needs a Linux host with `/dev/net/tun`, and Docker Compose 2.23.1 or
later for the proxy types, which pass the token as an inline `configs`
entry.

## An example

In this task the agent is asked to fetch a page from the world. The world is
the `web_world` example, published as an image. It writes its CA certificate
to `/run/ca/ca.pem`, and `world_ca` shares that file with the agent.

```python
from inspect_ai import Task, task
from inspect_ai.dataset import Sample
from inspect_ai.scorer import includes
from inspect_ai.solver import generate, use_tools
from inspect_ai.tool import bash
from inspect_fictionet import WEB_WORLD_IMAGE, fictionet_sandbox

@task
def fetch():
    return Task(
        dataset=[Sample(input="What does https://example.test/ say?", target="hello from https")],
        solver=[use_tools(bash()), generate()],
        scorer=includes(),
        sandbox=fictionet_sandbox(
            WEB_WORLD_IMAGE,
            world_args=["/run/relay/relay.sock", "/run/ca/ca.pem"],
            world_ca="/run/ca/ca.pem",
        ),
    )
```

The agent's sandbox is Inspect's `default` sandbox, as always, here from the
default image, `python:3.12-slim`. Its only network interface is `tun0`, and
every packet it sends goes to the world. Python's `urllib` fetches
`https://example.test/` from the world, and trusts it, because the agent's
`SSL_CERT_FILE` names the world's CA:

```console
$ python3 -c "import urllib.request; print(urllib.request.urlopen('https://example.test/').read().decode())"
hello from https example.test 443 over HTTP/1.1
```

Anything outside the world, such as `1.1.1.1` or `example.com`, does not
exist for the agent.

[`examples/web_eval.py`](examples/web_eval.py) is a complete eval that needs
no model. It is [`examples/hosted/eval.py`](../../examples/hosted/eval.py)
ported to this package: the samples, the solver and the scorer are the same,
and the hand-written compose file is gone. A scripted solver runs `dig` and
`curl --cacert` in the agent's sandbox, and checks that real addresses stay
out of reach. Run it from this directory:

```console
$ uv run inspect eval examples/web_eval.py --model mockllm/model
web (6 samples): mockllm/model
dataset: (samples)

total time:                                   0:00:17
contains
accuracy  1.000
```

## Options

`fictionet_sandbox(world, **options)` returns an Inspect
`SandboxEnvironmentSpec`. Pass it as a `Task`'s `sandbox`, or as a
`Sample`'s.

**The world.**

| Option | Default | What it does |
|---|---|---|
| `world` | required | An image name, a `Build`, or a `CargoExample`. The world must listen on `/run/relay/relay.sock` (`WORLD_SOCKET`). |
| `world_args` | none | The world's arguments: its image's CMD. |
| `world_env` | none | The world's environment. |
| `world_ca` | none | Where the world writes its CA certificate, such as `/run/ca/ca.pem`. See [The world's CA](#the-worlds-ca). |
| `world_healthcheck` | none | A command that exits with status 0 once the world is up. It runs in the world's container. Without one, attach waits for the world's socket. |
| `world_wait` | `60` | How many seconds attach waits for the world's socket before it gives up. |

**The agent.**

| Option | Default | What it does |
|---|---|---|
| `agent_image` | `python:3.12-slim` | The agent's image, or a `Build`. |
| `agent_command` | `tail -f /dev/null` | The agent's command. It must keep running, because Inspect runs tools beside it. |
| `agent_env` | none | More environment for the agent. |
| `agent_user` | the image's | The user the agent runs as, such as `"1000:1000"`. |
| `agent_limits` | `AGENT_LIMITS`: 2 GiB, 1 CPU, 1024 processes | The agent's resource limits. See [Resource limits](#resource-limits). |
| `world_limits` | `WORLD_LIMITS`: 2 GiB, 1024 processes | The world's resource limits. |

**Attach.**

| Option | Default | What it does |
|---|---|---|
| `attach` | `"tun"` | `"tun"`, `"http_proxy"` or `"socks5"`. See [Proxy types](#proxy-types). |
| `name` | `"agent"` | The name attach gives the world for this sandbox. |
| `ip_addr`, `gateway`, `dns` | `10.0.0.2/24`, `10.0.0.1`, `10.0.0.1` | The sandbox's IPv4 settings. These fit a world built on `web::Sites`. `None` turns a setting off. |
| `ip_addr_v6`, `gateway_v6`, `dns_v6` | `None` | The sandbox's IPv6 settings, off by default. |
| `mtu` | 1500 | `tun0`'s MTU. |
| `proxy_port` | 8080 or 1080 | The proxy's port on 127.0.0.1, for the proxy types. |
| `attach_image` | `ATTACH_IMAGE` | The attach image. It must have the `fictionet` binary at `/fictionet`. |

**Where it runs.**

| Option | Default | What it does |
|---|---|---|
| `backend` | `"docker"` | `"docker"` for Inspect's docker sandbox, `"k8s"` for inspect_k8s_sandbox. |
| `image_pull_policy` | the cluster's | On Kubernetes, the pods' `imagePullPolicy`, such as `"Never"` for images loaded into kind. |
| `k8s_values` | none | On Kubernetes, more values for the chart, merged key by key over the ones the package writes. |
| `cache_dir` | the user cache directory | Where the generated files go: `~/.cache/inspect_fictionet` on Linux. A relative path is made absolute when `fictionet_sandbox` runs. |

Docker Compose interpolates `${...}` in the values you pass, so write `$$`
for a literal `$`. Inspect sets `SAMPLE_METADATA_<KEY>` for each key of a
sample's metadata, so a world can take a per-sample setting, as Border's
variant does: `world_env={"VARIANT": "${SAMPLE_METADATA_VARIANT}"}`.

`ATTACH_IMAGE` and `WEB_WORLD_IMAGE` are the images published from this
repository, `ghcr.io/amlalabs/fictionet-attach` and
`ghcr.io/amlalabs/fictionet-web-world`, pinned to the tag `4903de4`. Both are
built for amd64 and arm64.

### Resource limits

Docker puts no limit on a container unless it is given one, so an agent
could allocate memory or start processes until the host runs out, taking
the other samples and the evaluator with it. Each container therefore gets
limits, as a `Limits(memory=..., cpus=..., pids=...)`:

| Container | Default | Memory | CPUs | Processes |
|---|---|---|---|---|
| the agent | `AGENT_LIMITS` | 2 GiB | 1 | 1024 |
| the world | `WORLD_LIMITS` | 2 GiB | no limit | 1024 |
| attach | `ATTACH_LIMITS` | 512 MiB | no limit | 256 |

The memory limit includes swap. When a container goes over it, the kernel
kills a process in that container only. The agent's 2 GiB and one CPU are
what Inspect's own Kubernetes chart gives a sandbox.

Pass `agent_limits` or `world_limits` to change them. A field set to
`None` is not limited:

```python
from inspect_fictionet import Limits

fictionet_sandbox(..., agent_limits=Limits(memory="8g", cpus=4.0, pids=4096))
```

On Kubernetes, `memory` and `cpus` become each container's
`resources.limits`. The requests, which the scheduler goes by, are much
smaller: 256 MiB and 0.1 CPU for the agent, and 64 MiB for the world, or
the limit if it is lower. So many sandboxes fit on one node, and a sandbox
that uses more than its request may be the first to go when a node runs
short. Kubernetes has no process limit per container, so
`pids` does not apply there. Set the kubelet's `podPidsLimit` on the nodes
that run sandboxes instead.

### A world built from source

A world you are still writing need not be pushed anywhere. Pass a `Build` for
a Dockerfile, or a `CargoExample` for a cargo example. Inspect builds the
image before the first sample, and every sample of the task shares it.

```python
from pathlib import Path
from inspect_fictionet import Build, CargoExample, fictionet_sandbox

here = Path(__file__).parent

# A Dockerfile, with an optional context, target stage and build arguments:
fictionet_sandbox(Build(here / "world.Dockerfile", context=here), agent_image=...)

# A cargo example: built with musl on rust:1.92-alpine, and run alone on scratch.
fictionet_sandbox(CargoExample("web_world", crate=here / "..", features=["tokio"]),
                  world_args=["/run/relay/relay.sock", "/run/ca/ca.pem"], ...)
```

The agent's image can be a `Build` too. Give absolute paths, as above: the
generated compose file lives in the cache directory, and relative paths are
taken from the directory Inspect runs in. `CargoExample` leaves `target/` and
`.git/` out of the build context. The Kubernetes backend takes images only,
because the cluster has to pull them: build and push them first.

### The world's CA

A world that serves HTTPS signs its certificates with its own CA. The agent
must trust that CA, or every HTTPS request fails with curl's error 60. There
are two ways to give the agent the CA:

- **At run time, through a shared directory.** This is how `web_world` works.
  The world makes a new CA each time it starts and writes the certificate to
  the path it was given. With `world_ca="/run/ca/ca.pem"`, the directory
  `/run/ca` is shared between the world, which can write to it, and the
  agent, which sees it read-only at the same path. The agent's
  `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`,
  `NODE_EXTRA_CA_CERTS` and `GIT_SSL_CAINFO` name the file, so curl, Python,
  Node and git trust it without flags.
- **At build time, in the agent's image.** This is how Border works. Its
  Dockerfile makes the CA once, copies the certificate into the agent's
  image, and runs `update-ca-certificates`. Then leave `world_ca` out.

### Proxy types

With `attach="http_proxy"` or `attach="socks5"`, attach does not make a
`tun0` device. It listens as a proxy on 127.0.0.1 in the network namespace
the agent shares. On Docker, that namespace has only loopback, so the proxy
is the agent's only way out. The agent gets:

- the proxy variables: `HTTP_PROXY`, `HTTPS_PROXY` and their lowercase forms
  for `http_proxy`, or `ALL_PROXY` for `socks5`, with an empty `NO_PROXY`;
- the proxy token in those URLs, and in a file named by
  `FICTIONET_TOKEN_FILE` (`/run/fictionet-token/token`);
- no capabilities at all (`cap_drop: [ALL]`).

The token is made once per cache directory and reused, so the compose file
stays the same from run to run.

On Kubernetes the chart sets up the proxy types differently. The pod keeps
its `eth0`, and the chart's deny-all NetworkPolicy is what stops the agent
from using it. A CNI may enforce a new policy a few seconds after the pod
starts, so the pod has one more init container, `wait-blocked`, and the
agent's container starts only once it has seen the pod's own connections to
the API server fail three times in a row. That needs a CNI that enforces
NetworkPolicy, also on traffic to the pod's own node, and no other policy
that selects the pod: policies add up, so one that allows traffic opens a
way around the proxy. "What keeps the agent
in" in [`src/attaching.rs`](../../src/attaching.rs) says exactly what is
checked.

The agent gets the token in `FICTIONET_TOKEN` and in the proxy URLs, with no
token file. Attach runs as uid 65532, the published world image's user, so
it can open the world's socket. For a world that runs as another user, set
`k8s_values={"attach": {"runAsUser": <the world's uid>}}`. For a world that
runs as root, that is `0`: the chart then runs attach as root too, which Pod
Security "restricted" refuses.

The published attach image, tag `4903de4`, has `tun` only. For the proxy
types, build attach from this repository and pass it as `attach_image`:

```console
$ docker build -f deploy/Dockerfile --target attach -t fictionet-attach:dev .
```

```python
fictionet_sandbox(WEB_WORLD_IMAGE, attach="http_proxy", attach_image="fictionet-attach:dev",
                  agent_user="1000:1000", ...)
```

Programs that ignore the proxy variables cannot reach the world, and `dig`
gets no answer, because there is no DNS server to ask: attach looks names up
in the world itself. See "Behind a proxy" in
[`src/attaching.rs`](../../src/attaching.rs) for which programs use the
variables.

### Kubernetes

With `backend="k8s"`, the package writes Helm values and returns a spec for
inspect_k8s_sandbox with the `fictionet-sandbox` chart. A copy of the chart
ships inside the package, so this works wherever the package is installed.
`chart_path()` returns its directory.

```python
fictionet_sandbox(WEB_WORLD_IMAGE, world_args=[...], world_ca="/run/ca/ca.pem",
                  agent_image="registry.example/agent:1", backend="k8s")
```

Each sample is one pod. The world and attach run as native sidecars, and the
agent's container starts only once attach is ready. The chart needs
Kubernetes 1.29 or later. "On Kubernetes" in
[`src/attaching.rs`](../../src/attaching.rs) explains the pod, and the chart's
[`values.yaml`](../../charts/fictionet-sandbox/values.yaml) lists what else
can be set. Pass any of them with `k8s_values`. Two differ from Docker:

- The world's root file system is read-only, and the chart mounts no other
  writable directory for it. For a world that writes files, turn that
  setting off with `k8s_values={"services": {"default": {"world":
  {"securityContext": {"readOnlyRootFilesystem": False}}}}}`.
- The attach container is started with its image's entrypoint, so a custom
  attach image must have `ENTRYPOINT ["/fictionet"]`, as the published one
  does.

The agent's and the world's `resources` come from `agent_limits` and
`world_limits`, and replace the chart's defaults whole.

`examples/web_eval.py` passed on a kind cluster:

```console
$ uv run --extra k8s inspect eval examples/web_eval.py --model mockllm/model \
    -T backend=k8s -T agent_image=inspect-fictionet-test-agent:dev
web (5 samples): mockllm/model
backend: k8s, agent_image: inspect-fictionet-test-agent:dev, dataset: (samples)

total time:                                   0:00:11
contains
accuracy  1.000
```

The run on Kubernetes leaves out the sample that reads the world's CA from
the world's container, because on Kubernetes the world's container is not
an Inspect sandbox. See [Reading the world's log](#reading-the-worlds-log).

## How it works

Inspect's docker sandbox takes a compose file. `fictionet_sandbox` writes one
into the cache directory and returns its path. The same options always give
the same file. It has three services, and Docker Compose starts them in this
order:

```text
             +-----------------------+
             | world                 |  network_mode: none
             | listens on            |  volumes: sock (rw), ca (rw)
             | /run/relay/relay.sock |
             +-----------+-----------+
                         |  Unix socket, on the `sock` volume
                         |  (attach retries for --world-wait seconds)
             +-----------+-----------+
             | attach                |  network_mode: none, so it starts with lo only
             | fictionet attach      |  tun: NET_ADMIN, /dev/net/tun -> makes tun0
             | --type tun            |  proxy: no device, listens on 127.0.0.1
             | healthy once its      |
             | ready file exists     |
             +-----------+-----------+
                         |  one network namespace
                         |  (network_mode: "service:attach")
             +-----------+-----------+
             | default (the agent)   |  starts once attach is healthy
             | Inspect runs tools    |  sees lo and tun0, and nothing else
             | here                  |  volumes: ca (read-only); never sock
             +-----------------------+
```

1. **The world** starts first, with no network at all. Its only way in is
   the socket at `/run/relay/relay.sock`, on a volume that only attach
   also mounts.
2. **Attach** starts next and connects to the socket. It retries for up to
   `world_wait` seconds, because the world may still be starting. With
   `tun`, it makes `tun0` in its own network namespace, sets the addresses
   and route, and writes `resolv.conf`. Then it writes a ready file, and its
   healthcheck (`/fictionet ready <file>`) passes.
3. **The agent** starts only once attach is healthy. It joins attach's
   network namespace, so `tun0` is already its only way out when its first
   program runs. It has no `NET_ADMIN`, so it cannot change the network, and
   it does not mount the socket.

The two volumes are tmpfs, writable by any user, so a world may run as any
user. The published images run the world as uid 65532.

Inspect sees three sandboxes: `default`, `world` and `attach`.
`sandbox("world")` reaches the world's container, which the agent cannot.

## Reading the world's log

A world can write down what the agent did, as it happened: the requests it
made, the names it looked up, the form it filled in. That log is the ground
truth for a scorer. Write it to a file in the world's container, then read
it after the agent has finished:

```python
from inspect_fictionet import read_world_file

@scorer(metrics=[accuracy()])
def sent_password():
    async def score(state, target):
        log = await read_world_file("/var/log/world/requests.jsonl")
        ...
```

`read_world_file(path)` is `sandbox("world").read_file(path)`, with one
check first. When a sample has only one sandbox, Inspect's `sandbox("world")`
returns that one, which is the agent's, and the agent could have written the
file. So `read_world_file` raises `RuntimeError` unless the sample has a
sandbox named `world`. On Docker it does, and the file is copied out with
`docker compose cp`, so this works on images with no shell, such as the
published ones, and on files in the world's volumes. `examples/web_eval.py`
reads the CA certificate this way, and checks that the agent sees the same
file.

On Kubernetes, inspect_k8s_sandbox makes one sandbox per pod, the agent's
container, so the world's files cannot be read through Inspect, and
`read_world_file` raises. There, have the world write its log somewhere the
agent cannot reach, and read it from outside the pod.

## Troubleshooting

**`dependency failed to start: container ... attach-1 exited (2)`.** Attach
refused its flags. Run `docker compose -f <the compose file> logs attach`:
the first lines name the flag. The compose file's path is in the spec
(`spec.config`). One cause is a proxy type with an attach image that has
only `tun`.

**`dependency failed to start: container ... attach-1 exited (1)`.** The
world never listened on `/run/relay/relay.sock`, and attach gave up after
`world_wait` seconds. Attach's log says so:

```text
fictionet attach: connecting to the world at /run/relay/relay.sock: No such file or directory (os error 2), after waiting 5 s
```

Check the world's logs, and that `world_args` gives the world that path.

**`curl: (60) SSL certificate problem`.** The agent does not trust the
world's CA. Set `world_ca` to the path the world writes its certificate to,
and check that `world_args` gives the world the same path.

**`dig` times out with a proxy type.** That is how proxy types work: the
agent has no DNS server. Use a program that honors the proxy variables, such
as curl.

**`Failed to pull docker image`, for an image you built yourself.** Inspect
pulls every image that is not already present. Build or load the image first,
or pass a `Build`.

**On Kubernetes: `ValueError: 3.22.0+g144ca65 is not valid SemVer string`.**
inspect-k8s-sandbox 0.13.0 parses `helm version --short` together with its
trailing newline. A `helm` earlier on `PATH` that prints the version without
the newline works around it.

**On Kubernetes, with a proxy type: the pod stays at `Init:2/3`.** The
agent's container waits for `wait-blocked`, which waits for the pod's
NetworkPolicy to block it. Its log says which address still answers:

```text
fictionet wait-blocked: 10.96.0.1:443 still reachable; waiting
```

The cluster's CNI does not enforce NetworkPolicy, or another policy allows
the pod's traffic. The sandbox is not isolated on that cluster, so the agent
does not start.

**A command in the agent's sandbox is `Killed`, or exits with status 137.**
It went over the agent's memory limit, 2 GiB by default. Raise it with
`agent_limits` if the task needs more.

**On Kubernetes: `When a user parameter ('root') is provided to exec(), the
container must be running as root`.** Inspect logs this once per sample when
the agent's image runs as a user other than root. The samples still run.

**Old images after a change.** Inspect uses an image that is already present
and does not pull it again. Remove the old one with `docker image rm`.

## Development

```console
$ uv run --extra k8s pytest
```

The unit tests check the compose file and the Helm values, and build the
package to check that its wheel holds the chart. The package's
`chart/fictionet-sandbox` is a symbolic link to
[`charts/fictionet-sandbox`](../../charts/fictionet-sandbox), and the build
copies the files it points to into the package.
