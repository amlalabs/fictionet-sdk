# syntax=docker/dockerfile:1
# Artifactory on Fictionet. Build context: the SDK root.
#
#   build-attach - the static fictionet binary
#   attach       - fictionet attach on scratch
#   build-world  - the Rust world without fictionet's tokio feature
#   world        - the package mirror, running as uid 65532
#   agent        - an ordinary workstation with pip and twine

FROM rust:1.92-alpine AS build-attach
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY docs docs
COPY dashboard dashboard
COPY benches benches
# Cargo loads the workspace member and path dev-dependency for every build.
COPY codegen codegen
COPY tests/copy_and_own tests/copy_and_own
COPY examples/*.rs examples/
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target,id=fictionet-artifactory-attach-target \
    find src examples -type f -exec touch {} + \
    && cargo build --release --locked -j 8 --bin fictionet \
    && cp target/release/fictionet /fictionet

# musl makes this binary runnable without a shell or shared libraries.
FROM scratch AS attach
COPY --from=build-attach /fictionet /fictionet
ENTRYPOINT ["/fictionet"]

FROM rust:1.92-slim-bookworm AS build-world
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY docs docs
COPY dashboard dashboard
COPY benches benches
COPY codegen codegen
COPY tests/copy_and_own tests/copy_and_own
COPY examples/*.rs examples/
COPY examples/artifactory/world/Cargo.toml examples/artifactory/world/Cargo.lock examples/artifactory/world/
COPY examples/artifactory/world/src examples/artifactory/world/src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/examples/artifactory/world/target,id=fictionet-artifactory-world-target \
    find src examples -type f -exec touch {} + \
    && cd examples/artifactory/world \
    && cargo build --release --locked -j 8 --bin artifactory-world \
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
COPY examples/artifactory/docker/agent/pip.conf /etc/pip.conf
COPY examples/artifactory/docker/agent/project /root/project
ENV PIP_CERT=/run/ca/ca.pem
WORKDIR /root/project
CMD ["sleep", "infinity"]
