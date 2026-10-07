# syntax=docker/dockerfile:1
# Static images of `fictionet attach` and of the web_world example, for
# Docker Compose (examples/compose), Kubernetes (charts/fictionet-sandbox)
# or anywhere else, and an agent image for the examples. Built from the
# crate root:
#
#   docker build -f deploy/Dockerfile --target attach -t fictionet-attach:dev .
#   docker build -f deploy/Dockerfile --target web-world -t fictionet-web-world:dev .
#   docker build -f deploy/Dockerfile --target agent -t fictionet-agent:dev .
#
# Both binaries are linked with musl, statically, so their images hold
# nothing else: no shell, no libc, no package manager.

FROM rust:1.92-alpine AS build
RUN apk add --no-cache musl-dev
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
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target,id=fictionet-musl-target \
    # Copied files may keep old times, and cargo would then take the
    # cached build for current. Touch them so it compares contents anew.
    find src examples -type f -exec touch {} + \
    && cargo build --release --locked --features tokio --bin fictionet --example web_world \
    && mkdir /out \
    && cp target/release/fictionet target/release/examples/web_world /out/

# `fictionet attach`, and `fictionet ready` for its probe. Attach runs as
# root in its container, with only the capabilities it is given: in the
# chart, NET_ADMIN and MKNOD.
FROM scratch AS attach
COPY --from=build /out/fictionet /fictionet
ENTRYPOINT ["/fictionet"]

# The web_world example: a world of websites. It needs no capabilities
# and no root.
FROM scratch AS web-world
COPY --from=build /out/web_world /web_world
USER 65532:65532
ENTRYPOINT ["/web_world"]

# A stand-in for the agent's sandbox, for the examples: Debian with curl,
# dig, ip and ping, a user `agent` (uid 1000), and nothing of Fictionet.
# Any image works in its place.
FROM debian:bookworm-slim AS agent
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl dnsutils iproute2 iputils-ping \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 1000 --create-home agent
USER 1000:1000
