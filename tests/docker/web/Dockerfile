# syntax=docker/dockerfile:1
# Built from the crate root: see compose.yaml.

FROM rust:1.99-slim-bookworm AS build
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
COPY examples examples
# The hosted example also copies web_world out of this image.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target,id=fictionet-web-target \
    cargo build --release --locked --features web-proxy,tokio --bin fictionet --example web_world --example web_fixture \
    && cp target/release/fictionet target/release/examples/web_world target/release/examples/web_fixture /usr/local/bin/

# The world, the real upstream, and attach.
FROM debian:bookworm-slim AS runtime
COPY --from=build /usr/local/bin/fictionet /usr/local/bin/web_world /usr/local/bin/web_fixture /usr/local/bin/

# The fixture as a non-root world for the Kubernetes proxy test.
FROM runtime AS fixture
USER 65532:65532
ENTRYPOINT ["web_fixture"]

# The sandbox: curl, dig, ping and python3, and no special capabilities.
FROM debian:bookworm-slim AS agent
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl dnsutils iputils-ping python3 \
    && rm -rf /var/lib/apt/lists/*
