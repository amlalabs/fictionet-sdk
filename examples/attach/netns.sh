#!/bin/sh
# Runs one command as the agent, in a network namespace attached to the
# world with `fictionet attach --type tun`, and removes the namespace when
# the command ends. Run it as root, with the world started at
# /run/fictionet/world.sock. The fictionet::attaching docs explain it.
#
#   examples/attach/netns.sh curl -sS --cacert /run/fictionet/ca.pem https://example.test/

ip netns add agent || exit 1           # makes /run/netns/agent
ip -n agent link set lo up
mkdir -p /etc/netns/agent
# Programs in the namespace look names up in the world, not in the
# host's systemd-resolved. ip netns exec mounts this over /etc/nsswitch.conf.
echo "hosts: files dns" > /etc/netns/agent/nsswitch.conf

ready=/run/fictionet/agent.ready
rm -f "$ready"                         # a file left from an earlier run
fictionet attach --world unix:/run/fictionet/world.sock --world-wait 5 \
    --name agent --type tun --netns /run/netns/agent \
    --ip-addr 10.0.0.2/24 --gateway 10.0.0.1 --dns 10.0.0.1 \
    --ip-addr-v6 2001:db8::2/64 --gateway-v6 2001:db8::1 --dns-v6 2001:db8::1 \
    --ready-file "$ready" &
attach=$!
agent=

cleanup() {
    if [ -n "$agent" ]; then
        kill -TERM "-$agent" 2>/dev/null      # the agent and everything it started
        wait "$agent" 2>/dev/null
    fi
    kill "$attach" 2>/dev/null         # attach removes tun0 and the ready file
    wait "$attach" 2>/dev/null
    ip netns del agent
    rm -rf /etc/netns/agent            # nsswitch.conf, and the resolv.conf attach wrote
}
trap cleanup EXIT
trap 'exit 1' INT TERM

waited=0
until [ -e "$ready" ]; do
    if ! kill -0 "$attach" 2>/dev/null; then
        wait "$attach"
        echo "attach exited with status $? before it was ready" >&2
        exit 1
    fi
    if [ "$waited" -ge 100 ]; then     # 100 tries of 0.1 s: 10 s
        echo "attach was not ready after 10 s" >&2
        exit 1
    fi
    sleep 0.1
    waited=$((waited + 1))
done

# The agent runs in a session of its own, so the terminal is not its
# controlling terminal, and it cannot type into the root shell that ran
# this script. It runs in the background, so a signal to this script runs
# cleanup at once. Its stdin is this script's.
exec 3<&0
setsid ip netns exec agent runuser -u agent -- "$@" <&3 3<&- &
agent=$!
wait "$agent"
