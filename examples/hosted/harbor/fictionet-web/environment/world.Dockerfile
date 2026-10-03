# The world (web_world) and attach (fictionet), from binaries built
# beforehand by ./build.sh, so nothing is compiled inside the hosted sandbox.
FROM debian:bookworm-slim
COPY --chmod=0755 bin/fictionet bin/web_world /usr/local/bin/
