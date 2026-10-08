#!/bin/bash
# Runs as root inside the outer VM (L1) of tests/vm/nested.sh. For each of
# QEMU (-netdev tap), Firecracker and Cloud Hypervisor, it:
#
#   1. makes a network namespace with a TAP device, tap0, in it;
#   2. starts `fictionet attach --type tap --vm tap:tap0` there, which makes
#      its own TAP device and redirects frames between the two;
#   3. boots a nested guest (L2) on tap0, which runs l2-check.sh;
#   4. prints the guest's output, and checks it;
#   5. removes tap0, and checks that attach exits and removes its redirect.
#
# It prints PASS and FAIL lines, which nested.sh counts.

set -u
assets=/mnt/assets
run=/mnt/run
work=/var/lib/fictionet-test
# The world and attach use the paths of the docs (attaching.rs).
mkdir -p "$work" /run/fictionet
cd "$work" || exit 1

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; }

echo "=== L1: $(uname -r), $(nproc) CPUs, $(grep -c -E 'svm|vmx' /proc/cpuinfo) with hardware virtualization"
modprobe kvm_amd 2>/dev/null || modprobe kvm_intel 2>/dev/null
for m in tun sch_ingress cls_matchall act_mirred; do modprobe "$m"; done
if [ ! -c /dev/kvm ]; then
    fail "L1 has no /dev/kvm: nested virtualization is off"
    exit 0
fi

"$run/web_fixture" /run/fictionet/world.sock /run/fictionet/ca.pem > "$work/world.log" 2>&1 &
world_pid=$!
for _ in $(seq 100); do [ -S /run/fictionet/world.sock ] && break; sleep 0.1; done

# The nested guests' root filesystem: the Debian image's root partition,
# set up to run l2-check.sh once the network is online.
echo "=== preparing the nested guests' root filesystem"
qemu-img convert -O raw "$assets/l2-root.qcow2" template.ext4
mkdir -p /mnt/l2
mount -o loop template.ext4 /mnt/l2
# No cloud-init: there is no data source. No netplan: the file cloud-init
# wrote names the first boot's interface.
touch /mnt/l2/etc/cloud/cloud-init.disabled
rm -f /mnt/l2/etc/netplan/*.yaml
echo '/dev/vda / ext4 rw,discard,errors=remount-ro 0 1' > /mnt/l2/etc/fstab
cat > /mnt/l2/etc/systemd/network/10-fictionet.network <<'EOF'
[Match]
Type=ether

[Network]
DHCP=ipv4
IPv6AcceptRA=no
EOF
cp "$run/l2-check.sh" /mnt/l2/root/check.sh
chmod 755 /mnt/l2/root/check.sh
cp /run/fictionet/ca.pem /mnt/l2/root/ca.pem
cat > /mnt/l2/etc/systemd/system/fictionet-check.service <<'EOF'
[Unit]
Description=Fictionet checks
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/root/check.sh

[Install]
WantedBy=multi-user.target
EOF
ln -sf /etc/systemd/system/fictionet-check.service /mnt/l2/etc/systemd/system/multi-user.target.wants/
umount /mnt/l2

kernel="$assets/vmlinux"
cmdline="console=ttyS0 reboot=k panic=1"

# The VM program's command for $1, with root filesystem $2 and MAC $3.
vmm_command() {
    local vmm="$1" disk="$2" mac="$3"
    case "$vmm" in
        qemu)
            echo qemu-system-x86_64 -enable-kvm -cpu host -m 512M -smp 1 -nodefaults -display none -no-reboot \
                -kernel "$kernel" -append "\"$cmdline root=/dev/vda rw\"" \
                -drive "file=$disk,if=virtio,format=raw" \
                -netdev tap,id=n0,ifname=tap0,script=no,downscript=no \
                -device "virtio-net-pci,netdev=n0,mac=$mac" \
                -serial "file:$work/$vmm-console.log"
            ;;
        firecracker)
            cat > "$work/vm1.json" <<EOF
{
  "boot-source": {"kernel_image_path": "$kernel", "boot_args": "$cmdline fn.halt=reboot"},
  "drives": [{"drive_id": "root", "path_on_host": "$disk", "is_root_device": true, "is_read_only": false}],
  "network-interfaces": [{"iface_id": "eth0", "host_dev_name": "tap0", "guest_mac": "$mac"}],
  "machine-config": {"vcpu_count": 1, "mem_size_mib": 512}
}
EOF
            echo "$assets/firecracker --no-api --config-file $work/vm1.json --log-path /dev/null"
            ;;
        cloud-hypervisor)
            echo "$assets/cloud-hypervisor" --kernel "$kernel" --cmdline "\"$cmdline root=/dev/vda rw\"" \
                --disk "path=$disk" --net "tap=tap0,mac=$mac" --cpus boot=1 --memory size=512M \
                --serial "file=$work/$vmm-console.log" --console off
            ;;
    esac
}

# One VM at a time, each as the sandbox "agent" at 10.0.0.2, in the
# namespace vm1: the world frees the name and the address when attach
# detaches.
addr=10.0.0.2
mac=52:54:00:12:34:56
for vmm in qemu firecracker cloud-hypervisor; do
    echo
    echo "=== $vmm: attach --vm tap:tap0, guest at $addr"
    ip netns add vm1
    ip -n vm1 tuntap add dev tap0 mode tap
    cp --sparse=always template.ext4 "$vmm.ext4"
    rm -f /run/fictionet/agent.ready
    /mnt/run/fictionet attach --world unix:/run/fictionet/world.sock --name agent \
        --type tap --vm tap:tap0 --netns /run/netns/vm1 \
        --ip-addr 10.0.0.2/24 --gateway 10.0.0.1 --dns 10.0.0.1 --no-ip-addr-v6 \
        --ready-file /run/fictionet/agent.ready 2> "$work/$vmm-attach.log" &
    attach_pid=$!
    for _ in $(seq 100); do [ -f /run/fictionet/agent.ready ] && break; sleep 0.1; done
    echo "--- the devices and the redirect in vm1"
    ip -n vm1 -br link
    tc -n vm1 filter show dev tap0 ingress

    # A second attach on the same device stops before it changes anything.
    status=0
    timeout 10 /mnt/run/fictionet attach --world unix:/run/fictionet/world.sock --name agent2 \
        --type tap --vm tap:tap0 --netns /run/netns/vm1 --no-ip-addr --no-ip-addr-v6 \
        --ready-file /run/fictionet/agent.ready 2> "$work/$vmm-second.log" || status=$?
    if [ "$status" = 1 ] && grep -q "another attach is using tap0" "$work/$vmm-second.log" \
        && [ -f /run/fictionet/agent.ready ] && tc -n vm1 filter show dev tap0 ingress | grep -q mirred; then
        pass "$vmm: a second attach on tap0 was refused, and left the first alone"
    else
        fail "$vmm: a second attach on tap0 (status $status): $(cat "$work/$vmm-second.log")"
    fi

    command=$(vmm_command "$vmm" "$work/$vmm.ext4" "$mac")
    echo "\$ ip netns exec vm1 $command"
    [ "$vmm" = firecracker ] && cat "$work/vm1.json"
    t0=$(date +%s%N)
    eval "timeout 300 ip netns exec vm1 $command" \
        > "$work/$vmm-vmm.log" 2>&1
    status=$?
    t1=$(date +%s%N)
    echo "$vmm exited with status $status after $(((t1 - t0) / 1000000)) ms"

    mount -o loop,ro "$vmm.ext4" /mnt/l2
    cp /mnt/l2/root/out.txt "$work/$vmm-out.txt" 2>/dev/null || echo "(no output from the guest)" > "$work/$vmm-out.txt"
    umount /mnt/l2
    echo "--- $vmm: in the guest"
    cat "$work/$vmm-out.txt"
    out="$work/$vmm-out.txt"
    says() { grep -Eq -- "$1" "$out"; }
    took() { grep -A20 -F -- "$1" "$out" | grep -m1 -o 'took [0-9]*' | grep -o '[0-9]*'; }
    says "UP +$addr/24" && pass "$vmm: the guest got $addr/24 by DHCP" || fail "$vmm: the guest has no $addr/24"
    says '^203\.0\.113\.10$' && pass "$vmm: dig resolved example.test" || fail "$vmm: dig did not resolve example.test"
    says '^hello from https example\.test 443' && pass "$vmm: curl --cacert fetched https://example.test/" \
        || fail "$vmm: curl did not fetch https://example.test/"
    says '^size 16777216 ' && pass "$vmm: curl fetched 16 MiB over HTTPS" || fail "$vmm: the 16 MiB download did not complete"
    says '3 packets transmitted, 3 received' && pass "$vmm: ping reached the gateway" || fail "$vmm: ping did not reach the gateway"
    t=$(took 'http://nowhere.test/' || echo 99999)
    says 'Could not resolve host: nowhere.test' && [ "$t" -lt 2000 ] \
        && pass "$vmm: an unknown name failed in $t ms" || fail "$vmm: an unknown name did not fail fast ($t ms)"
    t=$(took 'http://192.0.2.1/' || echo 99999)
    says 'Failed to connect to 192\.0\.2\.1' && [ "$t" -lt 2000 ] \
        && pass "$vmm: an unknown address failed in $t ms" || fail "$vmm: an unknown address did not fail fast ($t ms)"
    if ! grep -q "=== guest end" "$out"; then
        echo "--- $vmm: its output"
        tail -20 "$work/$vmm-vmm.log"
        tail -40 "$work/$vmm-console.log" 2>/dev/null
    fi

    # The VM is gone, but tap0 stays until it is removed. Then attach exits.
    ip -n vm1 link del tap0
    status=0
    for _ in $(seq 50); do kill -0 "$attach_pid" 2>/dev/null || break; sleep 0.1; done
    # Still running after 5 s: a failure, not a hang.
    if kill -0 "$attach_pid" 2>/dev/null; then
        kill -9 "$attach_pid"
        wait "$attach_pid" 2>/dev/null || true
        status=still-running
    else
        wait "$attach_pid" || status=$?
    fi
    echo "--- attach's messages"
    cat "$work/$vmm-attach.log"
    if [ "$status" = 0 ] && grep -q "tap0 was removed; agent detached" "$work/$vmm-attach.log"; then
        pass "$vmm: attach exited 0 when tap0 was removed"
    else
        fail "$vmm: attach did not exit 0 when tap0 was removed (status $status)"
    fi
    if [ -z "$(ip -n vm1 -o link show type tun)" ]; then
        pass "$vmm: attach's own TAP device is gone"
    else
        fail "$vmm: a TAP device is left: $(ip -n vm1 -o link show type tun)"
    fi
    ip netns del vm1
    rm -f "$vmm.ext4"
done

kill "$world_pid"
echo "=== L1 done"
