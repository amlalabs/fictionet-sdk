# Fictionet on hosted sandboxes

This directory runs the Docker Compose setup inside a hosted sandbox with
its own Docker daemon. The [attachment guide](../../src/guide/attaching.rs)
owns the setup and run instructions. This README owns the dated provider
measurements and limitations below.

The world, attach and agent run in separate containers. The agent shares
attach's network namespace, where `tun0` is its only interface besides
loopback. See [Docker Compose](../../src/guide/attaching.rs)
for the isolation rules.

On local Docker or Kubernetes, [`python/inspect_fictionet`](../../python/inspect_fictionet)
writes the deployment for you. Its
[`web_eval.py`](../../python/inspect_fictionet/demos/search_eval.py) uses one call
in place of this example's `compose.yaml`.

## Files

| Command or file | What it is |
|---|---|
| `cargo xtask images hosted` | Builds `fictionet` and `web_world` for Debian bookworm, into `bin/` and the Harbor task, and generates the Harbor environment. Run it first. |
| `package_harbor.py` | Generates Harbor's Dockerfiles and Compose manifest from the hosted sources. |
| `Dockerfile` | The world and attach image: Debian with the two binaries. |
| `agent.Dockerfile` | The agent image: Debian with curl, dig, ping, ip and python3. |
| `compose.yaml` | The three services. Works with `docker compose` and with inspect-sandboxes. |
| `check.sh` | 19 checks, run where Docker runs: the world works, and nothing else is reachable. POSIX sh. |
| `run_hosted.py` | Runs it all on one Daytona or E2B sandbox, then deletes the sandbox. |
| `eval.py` | A tiny Inspect eval: a scripted solver and the mock model, no LLM key. |
| `harbor/fictionet-web/` | The same as a Harbor task, run with Harbor's `oracle` agent. |

`check.sh` requires all 19 checks. Missing or failed host-address discovery
counts as a failure. If `docker0` has no address, it tries the Docker `bridge`
network's gateway. Commands must exit successfully for positive checks and
with a refusal status for denial checks, as well as match the expected output.
Denial checks reject status 124 (timeout), 126/127 (execution errors), and
statuses above 128 (signals).
`eval.py` checks each sample's exit code, exact stdout and empty stderr for
world answers, or the expected denial message for blocked requests.

The Harbor task fetches `https://example.test/challenge`. The world draws a
32-byte nonce once at startup from its seeded random stream and serves it as
64 hex digits followed by a newline. The verifier fetches the same URL with
the world's CA and compares the complete body with `/app/answer.txt`.
The public greeting at `/` does not satisfy the task.

Reward also requires only `lo` and `tun0`, failed external DNS, and curl exit 7
for `1.1.1.1` with `No route to host`, `Could not connect` or `Failed to connect`
on stderr. Timeouts and TLS failures fail. The agent must have no NET_ADMIN
capability, and route deletion must return iproute2's error status 2 with
`Operation not permitted` on stderr. Missing tools and missing or malformed
output fail. The scripts use fixed paths when run by Harbor. Offline tests
source their functions and supply paths and command fixtures as arguments.

Harbor 0.23 runs the verifier inside `main`. These checks trust that container's
tools and files. An agent with root can replace tools or tamper with the
files the verifier reads. Before checking, the verifier removes reward files left
in the reward directory and starts a fresh `reward.txt` at 0. This task does
not provide a separate trusted verifier environment. The command fixtures
test the checks, not resistance to tool tampering inside the container.

The canonical deployment files are `Dockerfile`, `agent.Dockerfile` and
`compose.yaml` here. `cargo xtask images hosted` runs `package_harbor.py` to copy the Dockerfiles
and generate `harbor/fictionet-web/environment/docker-compose.yaml`. These three
files are ignored build output, like `environment/bin/`. Do not edit them;
edit the hosted sources and run `cargo xtask images hosted` instead.
The generated manifest uses JSON syntax, which Compose accepts as YAML,
and has no reference back to this directory. `cargo xtask images hosted` also supplies its `bin/`.

The generator keeps Harbor's differences explicit: `default` becomes `main`,
attach uses `--name main`, and world and attach build from `world.Dockerfile`.
Harbor owns the agent image and process, using `environment/Dockerfile`.
The Harbor world and agent still omit `init`; the hosted services retain it.
Project and volume names remain scoped to each Harbor run. The direct SDK,
Inspect and Harbor orchestration adapters stay separate.

To regenerate packaging without building images or binaries, run
`python3 demos/hosted/package_harbor.py`. It needs Python 3 and the Docker
Compose CLI, but no Docker daemon or network. Run the offline contract tests with
`python3 -m unittest discover -s demos/hosted/tests -p 'test_*.py'`.

## Run it

Run the commands from the repository root.
Follow these sections of the attachment guide:

- [Run it locally first](../../src/guide/attaching.rs): build the binaries and
  check the Compose setup.
- [Directly, with each provider's SDK](../../src/guide/attaching.rs): run on
  Daytona or E2B.
- [Through Inspect](../../src/guide/attaching.rs): run the scripted eval.
- [Through Harbor](../../src/guide/attaching.rs): run the oracle task.

## What was run, 2 October 2026

All on the same day, with inspect-ai 0.3.276, inspect-sandboxes 0.6.0,
harbor 0.23.0, daytona 0.220.0 and e2b 2.52.0. The capabilities, failures,
egress rules and unknowns below describe those versions and accounts on
that date.

| Path | Result | Startup per sample |
|---|---|---|
| Local Docker, `check.sh` | 19 of 19 pass | |
| Daytona, `run_hosted.py` | 19 of 19 pass | 16.6 s to healthy: sandbox 1.5 s, dockerd 0.8 s, `compose up --build` 14 s |
| E2B, `run_hosted.py` | 19 of 19 pass | 27.7 s to healthy: sandbox 0.6 s, dockerd 4 s, `compose up --build` 23 s. The template build took 26 s, once. |
| Inspect, `provider=daytona` | 5 of 5 samples correct | 20 to 42 s of sample init, five samples at once |
| Inspect, `provider=e2b` | 5 of 5 correct, with `--max-samples 1` | 30 to 38 s of sample init |
| Harbor, `-e docker` | reward 1.0 with the original greeting verifier | |
| Harbor, `-e daytona` | reward 1.0 with the original greeting verifier | 24 s of environment setup |
| Harbor, `-e e2b` | fails, see below | |

The 19-of-19 and 5-of-5 results above predate the exit-status and whole-output
checks and have not been rerun with them.

On 15 October 2026, the Docker oracle run with the challenge verifier earned
reward 1.0 using Harbor 0.23.0 and Docker 29.8.1: one trial, no exceptions,
42 s total job runtime. A run that only wrote the public greeting to
`/app/answer.txt` earned reward 0, and so did a run that only wrote
`{"reward": 1.0}` to `/logs/verifier/reward.json`. Daytona was not re-run
with the challenge task.

The stricter curl and route-error checks were run on 15 October 2026 with
the same Harbor and Docker versions. The world and attach binaries came from
the earlier challenge run's build image; neither changed in this update.

| Path | Result | Total job runtime |
|---|---|---|
| Harbor, `-a oracle -e docker`, strict failure classification | reward 1.0, one trial, no exceptions | 37 s |

In the local Docker run, image building took 56 s, `up` took 40 to 100 s
(most of it `apt-get` in the agent's image), `check.sh` 6 to 7 s, and
`down` 0.7 s. The outer address was `172.17.0.5`, the gateway
`172.17.0.1`, and the Docker bridge `172.18.0.1`.

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
  template with the images inside. In these runs each sample pulled Debian
  and ran `apt-get` (14 to 23 s of the startup above).
- Modal's VM runtime through Harbor, and Daytona VM sandboxes.
- Many samples at once: only five were run, on Daytona.
