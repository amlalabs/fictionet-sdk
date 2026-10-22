# syntax=docker/dockerfile:1
# Artifactory on Fictionet. Build context: the SDK root.
#
#   build-attach - the static fictionet binary
#   attach       - fictionet attach on scratch
#   build-world  - the Rust world without fictionet's tokio feature
#   world        - the package mirror, running as uid 65532
#   agent        - an ordinary workstation with pip and twine

FROM rust:1.99-alpine AS build-attach
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY cli cli
COPY observe observe
COPY docs docs
COPY dashboard dashboard
COPY benches benches
COPY codegen codegen
COPY xtask xtask
COPY smoltcp smoltcp
COPY demos demos
COPY tests tests
COPY extras extras
COPY host host
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target,id=fictionet-artifactory-attach-target \
    find src cli demos extras host observe -type f -exec touch {} + \
    && cargo build --release --locked -j 8 -p fictionet-cli --bin fictionet \
    && cp target/release/fictionet /fictionet

# musl makes this binary runnable without a shell or shared libraries.
FROM scratch AS attach
COPY --from=build-attach /fictionet /fictionet
ENTRYPOINT ["/fictionet"]

FROM rust:1.99-slim-bookworm AS build-world
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY cli cli
COPY observe observe
COPY docs docs
COPY dashboard dashboard
COPY benches benches
COPY codegen codegen
COPY xtask xtask
COPY smoltcp smoltcp
COPY demos demos
COPY tests tests
COPY extras extras
COPY host host
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target,id=fictionet-artifactory-world-target \
    find src cli demos extras host observe -type f -exec touch {} + \
    && cargo build --release --locked -j 8 -p artifactory-world --bin artifactory-world \
    && cp target/release/artifactory-world /usr/local/bin/

# The CA is made at startup. Only its certificate reaches the agent.
FROM debian:bookworm-slim AS world
COPY --from=build-world /usr/local/bin/artifactory-world /usr/local/bin/
RUN mkdir -p /var/lib/fictionet /run/fictionet /run/ca /run/relay \
    && chown 65532:65532 /var/lib/fictionet /run/fictionet /run/ca /run/relay
USER 65532:65532
CMD ["artifactory-world"]

# Real clients use the per-sample CA mounted at /run/ca/ca.pem.
FROM python:3.12-slim-bookworm AS agent
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       curl wget git ca-certificates dnsutils iproute2 procps jq \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir twine==6.1.0
COPY demos/artifactory/docker/agent/pip.conf /etc/pip.conf
COPY demos/artifactory/docker/agent/project /root/project
ENV PIP_CERT=/run/ca/ca.pem
WORKDIR /root/project
CMD ["sleep", "infinity"]
