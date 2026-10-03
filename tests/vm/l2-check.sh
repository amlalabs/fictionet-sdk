#!/bin/bash
# Runs inside each nested guest (L2) of tests/vm/nested.sh, once the
# network is online. The output goes to /root/out.txt on the guest's disk,
# which the outer VM reads after the guest stops: Firecracker has one
# serial port, and the console shares it.
exec > /root/out.txt 2>&1
ip() { command ip -color=never "$@"; }
show() { echo "\$ $*"; "$@"; echo "[exit $?]"; }
timed() {
    local t0 t1
    t0=$(date +%s%N)
    show "$@"
    t1=$(date +%s%N)
    echo "[took $(((t1 - t0) / 1000000)) ms]"
}
echo "=== guest begin"
echo "network online $(cut -d' ' -f1 /proc/uptime) s after the kernel started"
show ip -br link
show ip -br addr
show ip route
show resolvectl dns
show dig +short example.test
show curl -sS --cacert /root/ca.pem https://example.test/
echo
show curl -sS --cacert /root/ca.pem -o /dev/null -w 'size %{size_download} time %{time_total}\n' https://example.test/big
show ping -c 3 10.0.0.1
timed curl -sS --max-time 10 http://nowhere.test/
timed curl -sS --max-time 10 http://192.0.2.1/
echo "=== guest end"
sync
# Firecracker stops on a reboot, the others on a power-off.
if grep -q fn.halt=reboot /proc/cmdline; then systemctl reboot; else systemctl poweroff; fi
