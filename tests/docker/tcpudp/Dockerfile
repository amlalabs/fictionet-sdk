# syntax=docker/dockerfile:1
# Built from the crate root: see run.sh.
#
# The test binary is built in Docker, not on the host as a musl binary,
# because ring (rustls's crypto) needs a C compiler for its target.

FROM rust:1.92-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY docs docs
COPY dashboard dashboard
COPY benches benches
COPY tests/tun_linux.rs tests/tun_linux.rs
# Cargo.toml names web_world, and src/recipes.rs includes other examples.
COPY examples examples
ARG PROFILE=release
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target,id=fictionet-tcpudp-target \
    flag=""; [ "$PROFILE" = release ] && flag="--release"; \
    cargo test $flag --test tun_linux --no-run \
    && cp "$(ls -t target/$PROFILE/deps/tun_linux-* | grep -v '\.d$' | head -1)" /tun_linux

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 && rm -rf /var/lib/apt/lists/*
COPY --from=build /tun_linux /test
