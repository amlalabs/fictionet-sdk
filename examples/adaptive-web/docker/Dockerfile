# syntax=docker/dockerfile:1
# The adaptive web on Fictionet. Build context: the fictionet-sdk root (see
# ../compose.yaml), so the world and attach build from this crate.
#
#   build   - the Rust world in examples/adaptive-web/world, and the
#             fictionet binary (fictionet attach) from the same target dir
#   world   - compose service "fictionet": the Rust world and the Python
#             backend that makes and keeps the pages, on 127.0.0.1
#   attach  - compose service "attach": fictionet attach --type tun
#   agent   - compose service "default": the agent's box, which trusts the CA

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
COPY examples/*.rs examples/
COPY examples/adaptive-web/world/Cargo.toml examples/adaptive-web/world/Cargo.lock examples/adaptive-web/world/
COPY examples/common examples/common
COPY examples/adaptive-web/world/src examples/adaptive-web/world/src
# At most 8 jobs, so the build fits next to other work on the machine.
ARG CARGO_BUILD_JOBS=8
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/examples/adaptive-web/world/target,id=fictionet-adaptive-web-target \
    cd examples/adaptive-web/world \
    && cargo build --release --locked --bin adaptive-web-world \
    && cargo build --release --locked -p fictionet --bin fictionet \
    && cp target/release/adaptive-web-world target/release/fictionet /usr/local/bin/

FROM python:3.12-slim-bookworm AS world
# iproute2 only so the probes can show `ss -lntup` from inside the world.
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/adaptive-web-world /usr/local/bin/
COPY examples/adaptive-web/world/backend /app/backend
COPY examples/adaptive-web/seeds /app/seeds
WORKDIR /app
CMD ["adaptive-web-world"]

FROM debian:bookworm-slim AS attach
COPY --from=build /usr/local/bin/fictionet /usr/local/bin/

FROM python:3.12-slim-bookworm AS agent
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl wget ca-certificates dnsutils iproute2 procps jq w3m lynx \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir requests==2.32.5 beautifulsoup4==4.13.5 html2text==2025.4.15 \
      readability-lxml==0.8.4.1 lxml_html_clean==0.4.2 chardet==5.2.0
# The public root is mounted when the world is ready.
# Point library-bundled trust stores at the system store (requests/certifi,
# Node). This is trust configuration, not proxy configuration: there is no
# proxy. The agent's packets go through attach's tun device to the world.
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt
WORKDIR /root
ENTRYPOINT ["sh", "-c", "cp /app/ca/ca.pem /usr/local/share/ca-certificates/internet-security-root-ca.crt && update-ca-certificates >/dev/null && exec \"$@\"", "sh"]
CMD ["sleep", "infinity"]
