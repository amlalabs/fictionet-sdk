# syntax=docker/dockerfile:1
# Built from the crate root: run cargo xtask docker tcpudp.
#
# The test binary is built in Docker, not on the host as a musl binary,
# because ring (rustls's crypto) needs a C compiler for its target.

FROM rust:1.99-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY cli cli
COPY docs docs
COPY dashboard dashboard
COPY benches benches
COPY codegen codegen
COPY xtask xtask
COPY demos demos
COPY tests tests
COPY examples examples
ARG PROFILE=release
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target,id=fictionet-tcpudp-target \
    flag=""; [ "$PROFILE" = release ] && flag="--release"; \
    cargo test --locked $flag -p fictionet --test host --no-run \
    && cp "$(ls -t target/$PROFILE/deps/host-* | grep -v '\.d$' | head -1)" /host

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 && rm -rf /var/lib/apt/lists/*
COPY --from=build /host /test
