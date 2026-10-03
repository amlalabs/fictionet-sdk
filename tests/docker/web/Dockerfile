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
    --mount=type=cache,target=/src/target,id=fictionet-web-target \
    cargo build --release --features tokio --bin fictionet --example web_world \
    && cp target/release/fictionet target/release/examples/web_world /usr/local/bin/

# The world, the real upstream, and attach.
FROM debian:bookworm-slim AS runtime
COPY --from=build /usr/local/bin/fictionet /usr/local/bin/web_world /usr/local/bin/

# The sandbox: curl, dig, ping and python3, and no special capabilities.
FROM debian:bookworm-slim AS agent
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl dnsutils iputils-ping python3 \
    && rm -rf /var/lib/apt/lists/*
