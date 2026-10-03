# Fictionet on hosted sandboxes

The Docker Compose setup from `tests/docker/web`, run inside one hosted
sandbox that has Docker of its own: Daytona or E2B. Three containers run
inside the sandbox:

- `world`: the `web_world` example, with no network (`network_mode: none`).
  Its only door is the world socket on a volume.
- `attach`: `fictionet attach --type tun`, with `NET_ADMIN` and
  `/dev/net/tun`. It makes `tun0` in its own network namespace.
- `default` (`main` in the Harbor task): the agent. It joins attach's
  network namespace, so `tun0` is its only interface. It has no
  `NET_ADMIN` and does not see the world socket.

No new Fictionet code is needed. The images are built inside the sandbox
from two small Dockerfiles and the binaries in `bin/`.

On local Docker or Kubernetes, `python/inspect_fictionet` writes this compose
file for you: [`web_eval.py`](../../python/inspect_fictionet/examples/web_eval.py)
is `eval.py` with one call in place of `compose.yaml`.

## Files

| File | What it is |
|---|---|
| `build.sh` | Builds `fictionet` and `web_world` for Debian bookworm, into `bin/` and the Harbor task. Run it first. |
| `Dockerfile` | The world and attach image: Debian with the two binaries. |
| `agent.Dockerfile` | The agent image: Debian with curl, dig, ping, ip and python3. |
| `compose.yaml` | The three services. Works with `docker compose` and with inspect-sandboxes. |
| `check.sh` | 19 checks, run where Docker runs: the world works, and nothing else is reachable. POSIX sh. |
| `run_hosted.py` | Runs it all on one Daytona or E2B sandbox, then deletes the sandbox. |
| `eval.py` | A tiny Inspect eval: a scripted solver and the mock model, no LLM key. |
| `harbor/fictionet-web/` | The same as a Harbor task, run with Harbor's `oracle` agent. |

## Run it

```sh
examples/hosted/build.sh

# Local Docker
cd examples/hosted && docker compose up -d --build --wait && ./check.sh; docker compose down -v

# Daytona or E2B, directly (pip install daytona e2b)
DAYTONA_API_KEY=... python examples/hosted/run_hosted.py daytona
E2B_API_KEY=... python examples/hosted/run_hosted.py e2b

# Inspect, through inspect-sandboxes (pip install inspect-ai inspect-sandboxes)
inspect eval examples/hosted/eval.py --model mockllm/model -T provider=daytona
inspect eval examples/hosted/eval.py --model mockllm/model -T provider=e2b --max-samples 1

# Harbor (pip install 'harbor[daytona]')
harbor run -p examples/hosted/harbor/fictionet-web -a oracle -e daytona
```

## What was run, 2 October 2026

All on the same day, with inspect-ai 0.3.276, inspect-sandboxes 0.6.0,
harbor 0.23.0, daytona 0.220.0 and e2b 2.52.0.

| Path | Result | Startup per sample |
|---|---|---|
| Local Docker, `check.sh` | 19 of 19 pass | |
| Daytona, `run_hosted.py` | 19 of 19 pass | 16.6 s to healthy: sandbox 1.5 s, dockerd 0.8 s, `compose up --build` 14 s |
| E2B, `run_hosted.py` | 19 of 19 pass | 27.7 s to healthy: sandbox 0.6 s, dockerd 4 s, `compose up --build` 23 s. The template build took 26 s, once. |
| Inspect, `provider=daytona` | 5 of 5 samples correct | 20 to 42 s of sample init, five samples at once |
| Inspect, `provider=e2b` | 5 of 5 correct, with `--max-samples 1` | 30 to 38 s of sample init |
| Harbor, `-e docker` | reward 1.0 | |
| Harbor, `-e daytona` | reward 1.0 | 24 s of environment setup |
| Harbor, `-e e2b` | fails, see below | |

`check.sh` on Daytona:

```text
outer address 172.20.0.53, gateway 172.20.0.1, docker0 172.17.0.1
PASS: the agent has only lo and tun0
PASS: tun0 has 10.0.0.2/24
PASS: the default route is tun0
PASS: resolv.conf points at the world
PASS: the world's DNS answers
PASS: HTTPS with the world's CA
PASS: ping the gateway
PASS: the agent has no NET_ADMIN
PASS: the agent cannot delete its route
PASS: the agent cannot add a link
PASS: the agent cannot see the world socket
PASS: DNS to 1.1.1.1 fails
PASS: DNS to 8.8.8.8 fails
PASS: HTTPS to 1.1.1.1 fails
PASS: a real name does not resolve
PASS: the metadata address fails
PASS: the sandbox's own network (172.20.0.53) fails
PASS: the sandbox's own network (172.20.0.1) fails
PASS: the sandbox's own network (172.17.0.1) fails
ALL PASSED
```

E2B printed the same, with `outer address 169.254.0.21, gateway
169.254.0.22`.

## What the sandboxes gave Docker

- **Daytona.** A container (`class container`) from `docker:28.3.3-dind`,
  as root, with every capability (`CapEff: 000001ffffffffff`) and
  `/dev/net/tun` present. Host kernel 6.8.0 (Ubuntu). The inner dockerd
  uses overlay2 and cgroup v2. `cap_add: [NET_ADMIN]` and
  `devices: [/dev/net/tun]` work as on a laptop.
- **E2B.** A VM with its own kernel, 6.1.158, and user `user` with passwordless
  sudo. `/dev/net/tun` is present. Docker comes from the template (Ubuntu
  24.04 `docker.io`, or docker-ce 29.5.2 in inspect-sandboxes' template).
  Docker commands need `sudo`.

## Things that broke on the way

- **Uploads lose the execute bit.** Both providers' file APIs wrote the
  binaries as mode 0644. The Dockerfile uses `COPY --chmod=0755`.
- **The `docker:dind` image has no bash** (Alpine), and Daytona's tier 1
  and 2 egress blocks the Alpine package mirror. So `check.sh` is POSIX sh.
- **inspect-sandboxes rejects** a top-level `name:` and `build.target` in
  the compose file (`Unknown field`). Hence two Dockerfiles, not one with
  stages.
- **inspect-sandboxes on E2B, samples at once.** Every sample calls
  `Template.build` for the same template name, and all but one fail with
  `BuildException: 400: build is not in waiting state`. With
  `--max-samples 1` all samples pass. Daytona logs a warning for the same
  race on its snapshot, then goes on.
- **Harbor on E2B.** Harbor's E2B backend does not run Compose: it built a
  template from the agent's Dockerfile alone and ignored the world and
  attach. It then failed to create the sandbox with
  `400: Timeout cannot be greater than 1 hours`, the cap of E2B's Hobby
  tier.

## The sandbox's own network

The agent cannot reach it in any of the runs above, whatever the provider
allows: its only route is `tun0`. The provider's egress rules matter only
for the world and for dockerd, which pulls images.

- **Daytona**, this account: tier 1 or 2. From the sandbox itself,
  pypi.org and deb.debian.org answer, while example.com, 1.1.1.1 and the
  Alpine mirror are reset. That is the "essential services" list.
  `network_block_all=True` at create time is honored (no DNS, no HTTPS).
  A `network_allow_list` is ignored. Changing it on a running sandbox is
  refused: `Network access is restricted and cannot be overridden at the
  sandbox level`. So egress can't be cut after `docker compose up` on
  these tiers.
- **E2B**, this account: Hobby tier, judging by the one-hour cap.
  Sandboxes have open egress by default. `allow_internet_access=False`
  blocked HTTPS, and UDP DNS to 8.8.8.8 and 1.1.1.1. `deny_out:
  ["0.0.0.0/0"]` with `allow_out: ["1.1.1.1"]` let only 1.1.1.1 through,
  and UDP DNS to 8.8.8.8 failed.

## Still unknown

- Daytona tiers 3 and 4: whether an allow list can be set after
  `compose up`, so the sandbox itself has no egress while the agent runs.
- Startup with images from a registry, or a Daytona snapshot or E2B
  template with the images inside. Today each sample pulls Debian and runs
  `apt-get` (14 to 23 s of the startup above).
- Modal's VM runtime through Harbor, and Daytona VM sandboxes.
- Many samples at once: only five were run, on Daytona.
