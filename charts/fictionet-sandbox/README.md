# Fictionet sandbox Helm chart

This chart runs one world, attach relay and agent per service on Kubernetes.
Use the [attachment guide](../../src/attaching.rs) for deployment instructions,
startup and restart behavior, and isolation requirements:

- **On Kubernetes** for TUN attachment.
- **The proxy on Kubernetes** for HTTP and SOCKS5 proxies.
- **Pod Security** and **gVisor** for runtime requirements.

[values.yaml](values.yaml) is the reference for settings and defaults;
[values.schema.json](values.schema.json) validates their shape. Runnable values
files are [k8s-tun.yaml](../../examples/attach/k8s-tun.yaml) and
[k8s-proxy.yaml](../../examples/attach/k8s-proxy.yaml). The guide includes both
files and gives the build, install, check and cleanup commands.

[tests/k8s/run.sh](../../tests/k8s/run.sh) and
[tests/k8s/proxy.sh](../../tests/k8s/proxy.sh) check these deployments.
For an Inspect eval, see [inspect_fictionet](../../python/inspect_fictionet).
