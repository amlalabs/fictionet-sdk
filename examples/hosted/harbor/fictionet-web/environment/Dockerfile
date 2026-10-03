# The agent: curl, dig, ping, ip and python3, and nothing of Fictionet.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl dnsutils iputils-ping iproute2 python3 \
    && rm -rf /var/lib/apt/lists/*
