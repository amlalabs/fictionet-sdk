# The sandbox for the Kubernetes test: Debian with curl, dig, ip and ping,
# a user `agent` (uid 1000), and nothing of Fictionet.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl dnsutils iproute2 iputils-ping \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 1000 --create-home agent
USER 1000:1000
