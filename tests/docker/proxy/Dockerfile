# syntax=docker/dockerfile:1
# Built from the crate root: see compose.yaml.

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
COPY microvm microvm
COPY tests tests
COPY examples examples
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target,id=fictionet-proxy-target \
    find src cli examples tests/web_fixture -type f -exec touch {} + \
    && cargo build --release --locked --features web-proxy,tokio --bin fictionet --example web_fixture \
    && cp target/release/fictionet target/release/examples/web_fixture /usr/local/bin/

# A Go client tested and built with the standard library only.
FROM golang:1-bookworm AS go
WORKDIR /src
COPY tests/docker/proxy/goclient .
RUN go vet ./... && go test ./...
RUN CGO_ENABLED=0 go build -buildvcs=false -trimpath -o /goclient .

# The world and attach.
FROM debian:bookworm-slim AS runtime
COPY --from=build /usr/local/bin/fictionet /usr/local/bin/web_fixture /usr/local/bin/

# The sandbox: the clients an agent uses, as a user with no capabilities.
# Python 3.13, which checks certificates strictly. No ping, dig or ip.
FROM node:24-bookworm-slim AS node
FROM python:3.13-slim-bookworm AS agent
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git netcat-openbsd wget \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir 'requests[socks]' \
    && useradd --uid 1000 --create-home agent
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=go /goclient /usr/local/bin/goclient
USER 1000:1000
