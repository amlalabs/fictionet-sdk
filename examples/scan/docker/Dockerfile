# syntax=docker/dockerfile:1
# The nmap demo. Build context: the fictionet-sdk root (see ../compose.yaml).
#
#   build     - the fictionet binary and the scan example world
#   fictionet - compose services "world", "*-attach" and "dashboard"
#   container - compose service "container": a real nginx and OpenSSH
#   scanner   - compose service "scanner": the agent, with nmap

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
COPY examples/scan/main.rs examples/scan/main.rs
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target,id=fictionet-scan-target \
    CARGO_BUILD_JOBS=4 cargo build --release --bin fictionet --example scan \
    && cp target/release/fictionet target/release/examples/scan /usr/local/bin/

FROM debian:bookworm-slim AS fictionet
COPY --from=build /usr/local/bin/fictionet /usr/local/bin/scan /usr/local/bin/

# A real machine for the subnet: nginx on port 80 and OpenSSH on port 22.
FROM alpine:3.20 AS container
RUN apk add --no-cache nginx openssh-server \
    && ssh-keygen -A \
    && sed -i 's/server_tokens off;/server_tokens on;/' /etc/nginx/nginx.conf \
    && printf 'server {\n  listen 80 default_server;\n  root /srv;\n}\n' > /etc/nginx/http.d/default.conf \
    && mkdir -p /srv && echo '<h1>A real container</h1>' > /srv/index.html
CMD ["sh", "-c", "/usr/sbin/sshd && exec nginx -g 'daemon off;'"]

# The agent: nmap and nothing else.
FROM debian:bookworm-slim AS scanner
RUN apt-get update && apt-get install -y --no-install-recommends nmap iproute2 \
    && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
