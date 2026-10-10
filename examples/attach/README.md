# Attach recipes

These small recipes connect ordinary tools to the `web_world` example. Start
with [`demos/dashboard`](../../demos/README.md) for a scripted run and the
world's live request log, or choose a deployment recipe below.

| Recipe | Requirements and use |
|---|---|
| [Compose with tun](compose-tun.yaml) | Linux, Docker Compose, `/dev/net/tun`. The agent shares attach's network namespace. |
| [Compose with proxies](compose-proxy.yaml) | Docker Compose. HTTP and SOCKS clients connect through attach. |
| [Kubernetes with tun](k8s-tun.yaml) | Kubernetes and the [sandbox Helm chart](../../charts/fictionet-sandbox). The agent uses a tun interface. |
| [Kubernetes with proxies](k8s-proxy.yaml) | Kubernetes and the sandbox Helm chart. Clients use HTTP or SOCKS proxies. |
| [Local namespace](netns.sh) | Linux and root, with a world already running. This is a trusted connectivity recipe; a network namespace alone does not isolate files or processes. |

The [`fictionet::attaching` rustdoc](../../src/attaching.rs) gives the build,
start, check and cleanup commands. Cold image builds download base images
and packages.
