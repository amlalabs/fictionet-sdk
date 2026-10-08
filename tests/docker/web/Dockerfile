# syntax=docker/dockerfile:1
# Built from the crate root: see compose.yaml.

FROM rust:1.92-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY docs docs
COPY dashboard dashboard
COPY benches benches
# The workspace member and the path dev-dependency, which Cargo loads for
# any build. Examples link dev-dependencies, and tests/copy_and_own reads
# a file in codegen/tests.
COPY codegen codegen
COPY tests/copy_and_own tests/copy_and_own
COPY examples examples
COPY tests/web_fixture tests/web_fixture
# The hosted example also copies web_world out of this image.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target,id=fictionet-web-target \
    cargo build --release --features tokio --bin fictionet --example web_world --example web_fixture \
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
