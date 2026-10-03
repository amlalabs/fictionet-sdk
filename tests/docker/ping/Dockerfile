# syntax=docker/dockerfile:1
# Built from the crate root: see compose.yaml.

FROM rust:1.92-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY docs docs
COPY dashboard dashboard
COPY benches benches
COPY examples examples
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target,id=fictionet-ping-target \
    cargo build --release --bin fictionet --example ping_world \
    && cp target/release/fictionet target/release/examples/ping_world /usr/local/bin/

# The world and attach. Attach needs nothing but the binary: it sets up the
# device with netlink, not with `ip`.
FROM debian:bookworm-slim AS runtime
COPY --from=build /usr/local/bin/fictionet /usr/local/bin/ping_world /usr/local/bin/

# The sandbox: ping and ip, and no special capabilities.
FROM debian:bookworm-slim AS agent
RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping iproute2 \
    && rm -rf /var/lib/apt/lists/*
