# Shared setup for the web and proxy demos. start_web passes its optional
# argument as web_world's third path, which opens the observation socket.
# shellcheck shell=bash

cleanup_web() {
    stop_pid "${attach_pid:-}"
    stop_pid "${world_pid:-}"
    ip netns del agent 2>/dev/null || true
    rm -rf /etc/netns/agent /run/fictionet /run/attach.ready /run/agent-ca.pem
}

start_web() {
    mkdir -p /run/fictionet
    chmod 700 /run/fictionet
    web_world /run/fictionet/world.sock /run/fictionet/ca.pem "$@" >/run/world.log 2>&1 &
    world_pid=$!
    local i
    for ((i = 0; i < 100; i++)); do
        if ! kill -0 "$world_pid" 2>/dev/null; then
            echo "demo: web_world exited before its socket and CA were ready" >&2
            sed 's/^/    /' /run/world.log >&2
            return 1
        fi
        if [[ -S /run/fictionet/world.sock && -s /run/fictionet/ca.pem ]] &&
            python3 -c 'import ssl, sys; ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(sys.argv[1])' \
                /run/fictionet/ca.pem 2>/dev/null; then
            sed 's/^/    /' /run/world.log
            return 0
        fi
        sleep 0.1
    done
    echo "demo: timed out waiting for /run/fictionet/world.sock and a complete /run/fictionet/ca.pem" >&2
    sed 's/^/    /' /run/world.log >&2
    return 1
}

attach_web() {
    vm 'ip netns add agent && ip -n agent link set lo up'
    # An ordinary user pings with ICMP datagram sockets, which the kernel
    # allows only for the groups in ping_group_range. A new namespace allows
    # none; Debian's own default allows all.
    ip netns exec agent sysctl -q -w net.ipv4.ping_group_range="0 2147483647"
    fictionet attach --world unix:/run/fictionet/world.sock --name agent --type tun \
        --netns /run/netns/agent --ip-addr 10.0.0.2/24 --gateway 10.0.0.1 --dns 10.0.0.1 \
        --no-ip-addr-v6 --no-gateway-v6 --no-dns-v6 --ready-file /run/attach.ready >/run/attach.log 2>&1 &
    attach_pid=$!
    wait_for /run/attach.ready 10
    sed 's/^/    /' /run/attach.log
    id agent >/dev/null 2>&1 || useradd --uid 2000 --no-create-home --shell /bin/bash agent
}
