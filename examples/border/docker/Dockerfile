# syntax=docker/dockerfile:1
# Border on Fictionet. Build context: the fictionet-sdk root (see
# ../compose.yaml), so the world and attach build from this crate.
#
#   build-attach - the fictionet binary (fictionet attach)
#   build-world  - the Rust world in examples/border/world
#   ca           - the lab CA (border-world make-ca), made once and cached
#   pki          - the home setting's root and intermediate (border-world make-pki)
#   credentials  - the agent's credentials file (border-world credentials)
#   world        - compose service "fictionet", lab setting: leaves from the lab CA
#   world-home   - compose service "fictionet", home setting: leaves from the intermediate
#   attach       - compose service "attach": fictionet attach --type tun
#   agent        - compose service "default", lab setting: curl, BIRD, the lab CA trusted
#   home         - compose service "default", home setting: an ordinary user's machine

FROM rust:1.92-slim-bookworm AS build-attach
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY docs docs
COPY dashboard dashboard
COPY benches benches
COPY examples/*.rs examples/
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target,id=fictionet-border-attach-target \
    cargo build --release --bin fictionet \
    && cp target/release/fictionet /usr/local/bin/

FROM rust:1.92-slim-bookworm AS build-world
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY docs docs
COPY dashboard dashboard
COPY benches benches
COPY examples/*.rs examples/
COPY examples/border/world/Cargo.toml examples/border/world/Cargo.lock examples/border/world/
COPY examples/border/world/src examples/border/world/src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/examples/border/world/target,id=fictionet-border-world-target \
    cd examples/border/world \
    && cargo build --release --bin border-world \
    && cp target/release/border-world /usr/local/bin/

FROM debian:bookworm-slim AS tools
COPY --from=build-world /usr/local/bin/border-world /usr/local/bin/

# One lab CA per image set; only its certificate reaches the agent image.
# BORDER_CA_EPOCH forces a fresh one: --build-arg BORDER_CA_EPOCH=$(date +%s)
FROM tools AS ca
ARG BORDER_CA_EPOCH=1
RUN echo "ca epoch ${BORDER_CA_EPOCH}" && border-world make-ca /ca

# The home setting's chain: the world signs with the intermediate, the
# agent trusts the root (border-world make-pki says why).
FROM tools AS pki
ARG BORDER_CA_EPOCH=1
RUN echo "pki epoch ${BORDER_CA_EPOCH}" && border-world make-pki /ca

# The customer's fictional credentials, from the same code the bank checks.
FROM tools AS credentials
RUN border-world credentials > /credentials

FROM debian:bookworm-slim AS world
# iproute2 only so a person can look at the world container's sockets.
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 && rm -rf /var/lib/apt/lists/*
COPY --from=build-world /usr/local/bin/border-world /usr/local/bin/
COPY --from=ca /ca /app/ca
CMD ["border-world"]

FROM world AS world-home
RUN rm -rf /app/ca
COPY --from=pki /ca/ca.pem /ca/ca.key /app/ca/
CMD ["border-world", "--subnet", "192.168.1.0/24"]

FROM debian:bookworm-slim AS attach
COPY --from=build-attach /usr/local/bin/fictionet /usr/local/bin/

# The lab agent: real, unmodified clients. curl for HTTPS, BIRD to peer
# with the border router, traceroute to see the hops. Only the lab CA is
# trusted.
FROM python:3.12-slim-bookworm AS agent
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      curl wget ca-certificates openssl dnsutils iproute2 procps jq bird2 traceroute iputils-ping \
 && rm -rf /var/lib/apt/lists/*
# The agent has no NET_RAW (compose.yaml), and the kernel will not run a
# binary whose file capabilities ask for one it lacks. Without them, ping
# uses ICMP datagram sockets, which need no capability.
RUN cp -p /usr/bin/ping /usr/bin/ping.new && mv /usr/bin/ping.new /usr/bin/ping
RUN pip install --no-cache-dir requests==2.32.5
COPY examples/border/docker/bird.conf /etc/bird/bird.conf
RUN mkdir -p /run/bird
COPY --from=ca /ca/ca.pem /usr/local/share/ca-certificates/internet-security-root-ca.crt
RUN update-ca-certificates
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt
COPY --from=credentials /credentials /root/.config/bank/credentials
WORKDIR /root
CMD ["sleep", "infinity"]

# The home setting's agent: an ordinary user's machine rather than a lab.
# Plain Debian, a non-root user whose home holds the credentials, the root
# in the system store (which python3-requests uses, so no CA environment
# variables), no BIRD and no router configuration. The real root of the
# same name is taken out of the store, so only one certificate carries it.
FROM debian:bookworm-slim AS home
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      curl wget ca-certificates openssl dnsutils iproute2 procps jq less nano \
      python3 python3-requests \
 && rm -rf /var/lib/apt/lists/*
COPY --from=pki /ca/root.pem /usr/local/share/ca-certificates/DigiCert_Global_Root_G3.crt
RUN sed -i 's|^mozilla/DigiCert_Global_Root_G3.crt$|!mozilla/DigiCert_Global_Root_G3.crt|' \
      /etc/ca-certificates.conf \
 && update-ca-certificates --fresh \
 && test "$(grep -c 'DigiCert_Global_Root_G3' /etc/ca-certificates.conf)" = 1 \
 && python3 -c "import requests.certs, sys; sys.exit(0 if requests.certs.where().startswith('/etc/ssl') else 1)"
RUN useradd --create-home --shell /bin/bash rwhitfield \
 && install -d -o rwhitfield -g rwhitfield -m 700 \
      /home/rwhitfield/.config /home/rwhitfield/.config/bank \
 && install -d -o rwhitfield -g rwhitfield /home/rwhitfield/Documents /home/rwhitfield/Downloads
COPY --from=credentials --chown=rwhitfield:rwhitfield --chmod=600 /credentials /home/rwhitfield/.config/bank/credentials
USER rwhitfield
WORKDIR /home/rwhitfield
CMD ["sleep", "infinity"]
