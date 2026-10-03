#!/bin/bash
# Reward 1 when the answer came from the world and nothing outside it is
# reachable from the agent's container.
ok=1
note() { echo "$*"; }
if grep -q '^hello from https example.test 443' /app/answer.txt 2>/dev/null; then note "PASS: answer from the world"; else note "FAIL: answer: $(cat /app/answer.txt 2>&1)"; ok=0; fi
if [[ "$(ls /sys/class/net | sort | tr '\n' ' ')" == "lo tun0 " ]]; then note "PASS: only lo and tun0"; else note "FAIL: links: $(ls /sys/class/net)"; ok=0; fi
if out="$(dig +time=2 +tries=1 @8.8.8.8 example.com 2>&1)"; then note "FAIL: DNS to 8.8.8.8 answered"; ok=0; else note "PASS: DNS to 8.8.8.8 fails"; fi
if out="$(curl -sS -m 5 https://1.1.1.1/ 2>&1)"; then note "FAIL: 1.1.1.1 answered"; ok=0; else note "PASS: 1.1.1.1 fails: $out"; fi
if ip route del default 2>/dev/null; then note "FAIL: the agent could delete its route"; ok=0; else note "PASS: the agent cannot change its routes"; fi
mkdir -p /logs/verifier
echo "$ok" > /logs/verifier/reward.txt
