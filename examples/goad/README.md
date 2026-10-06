# Real Active Directory VMs on a Fictionet LAN

This example joins real GOAD or GOAD-like machines inside a Fictionet world.
It does not imitate LDAP, Kerberos, SMB or any other Windows service. Those
services run in the Windows guests, and Fictionet carries their IP packets
unchanged between the guests and the attacker.

The default addresses match GOAD and GOAD-Light:

| Attachment | Address | Upstream role |
|---|---:|---|
| `provisioner` | 192.168.56.3 | optional Ansible provisioner |
| `dc01` | 192.168.56.10 | Kings Landing, `sevenkingdoms.local` DC |
| `dc02` | 192.168.56.11 | Winterfell, `north.sevenkingdoms.local` DC |
| `dc03` | 192.168.56.12 | Meereen, `essos.local` DC |
| `srv02` | 192.168.56.22 | Castle Black, IIS/MSSQL/SMB |
| `srv03` | 192.168.56.23 | Braavos, MSSQL/SMB |
| `ws01` | 192.168.56.31 | optional workstation extension |
| `attacker` | 192.168.56.100 | Kali or another agent VM/container |

GOAD-Light needs `dc01`, `dc02`, `srv02` and `attacker`. The full lab adds
`dc03` and `srv03`. Members may attach in any order and may reconnect under
the same name.

## What Fictionet provides

Each VM gets a separate point-to-point attachment. `fictionet attach` answers
its ARP requests with proxy ARP, removes the Ethernet header and sends the
original IP packet to the world. The world's IP LAN sends unicast to the member
that owns the destination and copies subnet broadcast, limited broadcast and
IPv4 multicast to every other member. That covers ordinary AD traffic and the
IP discovery protocols used by tools such as Responder: DNS, Kerberos, LDAP,
CLDAP, SMB, DCE/RPC, WinRM, RDP, MSSQL, LLMNR and NBNS all come from the real
machines.

Fictionet is the only data path between members, so the dashboard and observers
see the real packets and link controls such as delay, loss and capture can be
inserted later. Unknown destinations are dropped; the lab has no accidental
route to the host or internet.

The boundary is Ethernet-only behavior. Attach terminates ARP and does not pass
raw Ethernet frames, VLANs or non-IP link protocols into a world. ARP poisoning
therefore is not part of this topology. Application-level AD attack paths and
IP multicast/broadcast poisoning remain real.

## Prepare the guests

Provision the Windows machines first and take clean snapshots. Their lab NICs
must retain the static addresses above with a `/24` mask. Keep the DNS settings
that GOAD installs: domain members should use their domain controller, and the
attacker should use `192.168.56.10` as its initial resolver.

The supported no-root VM connection is QEMU's stream network backend. Upstream
GOAD currently provisions VirtualBox, VMware, AWS, Azure, Proxmox and Ludus; it
does not provide a QEMU/libvirt provider. Consequently, this example starts at
the boundary of already-provisioned, QEMU-bootable disks. Converting a
VirtualBox or VMware disk can require storage and network driver changes inside
Windows, so disk conversion is deliberately not hidden in the network example.

Any VMM that directly owns a Linux TAP device can instead use `--vm tap:NAME`,
as described in the crate's `attaching` documentation.

## Run the LAN

Build Fictionet and the world, create a private run directory, and start the
world:

```console
$ cargo build --release --bin fictionet --example goad
$ mkdir -p /run/user/$(id -u)/fictionet-goad
$ target/release/examples/goad /run/user/$(id -u)/fictionet-goad/world.sock 192.168.56
```

Use another three-octet prefix as the second argument when the guests were
provisioned on a different GOAD range, for example `192.168.100`.

For each Windows VM, start one attach before starting QEMU. Static Windows
addresses are kept inside the guests, so all address services in attach are
disabled:

```console
$ target/release/fictionet attach \
    --world unix:/run/user/$(id -u)/fictionet-goad/world.sock \
    --name dc01 --type tap \
    --vm qemu:/run/user/$(id -u)/fictionet-goad/dc01.sock \
    --no-ip-addr --no-gateway --no-dns \
    --no-ip-addr-v6 --no-gateway-v6 --no-dns-v6
```

Add this network device to the VM's normal QEMU command. `e1000` is useful for
Windows images that do not have virtio-net drivers installed:

```console
-netdev stream,id=lab,server=off,addr.type=unix,addr.path=/run/user/UID/fictionet-goad/dc01.sock,reconnect-ms=500 \
-device e1000,netdev=lab,mac=52:54:00:00:00:10
```

Repeat with the attachment name, socket and final MAC byte for each guest.
Only the lab NIC should remain connected during an eval. A provisioning or NAT
NIC left up gives the guest a path that bypasses Fictionet.

Attach the attacker in the same way as a VM, or use a network namespace:

```console
$ sudo ip netns add goad-attacker
$ sudo ip -n goad-attacker link set lo up
$ sudo target/release/fictionet attach \
    --world unix:/run/user/$(id -u)/fictionet-goad/world.sock \
    --name attacker --type tun --netns /run/netns/goad-attacker \
    --ip-addr 192.168.56.100/24 --gateway 192.168.56.1 --dns 192.168.56.10 \
    --no-ip-addr-v6 --no-gateway-v6 --no-dns-v6
```

Programs run in that namespace without proxy settings:

```console
$ sudo ip netns exec goad-attacker dig @192.168.56.10 \
    _ldap._tcp.dc._msdcs.sevenkingdoms.local SRV
$ sudo ip netns exec goad-attacker nmap -Pn -sV \
    -p 53,88,135,389,445,636,1433,3268,3389,5985 192.168.56.10-23
```

Run the dashboard against the same world socket to watch the real exchange:

```console
$ target/release/fictionet dashboard \
    --world unix:/run/user/$(id -u)/fictionet-goad/world.sock \
    --listen 127.0.0.1:7878
```

The next integration milestone is a QEMU-based GOAD provisioner that produces
the clean Windows snapshots consumed here. It belongs beside this example, but
it should remain separate from the runtime LAN so one provisioned snapshot can
be reset and reused for many deterministic eval runs.
