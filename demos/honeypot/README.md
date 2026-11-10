# Honeypot

One executable serves a Fictionet Linux host, collects MPTCP and IPv4-option
observations, terminates encrypted SSH sessions, and observes literal TCP and
UDP port zero. Client input never becomes a host command. SSH shows a simulated
prompt and disconnects before executing the first nonempty command; exec and
subsystem requests also disconnect.

This milestone unifies world sockets, direct TUN attachment, and the existing
QEMU VFIO virtio-net path. XDP, AF_XDP and direct ENA ownership are unavailable
and are rejected explicitly. TUN and VFIO need prepared guests. Opening a backend
establishes local readiness, not public reachability or preservation of probes
by upstream filtering and NAT.

## Build and configuration

The default Linux build includes world, TUN and VFIO virtio-net:

```sh
cargo build --release -p honeypot-world --bin honeypot
```

Copy the release executable to the prepared VM. It needs no Rust toolchain,
`fictionet` CLI or helper process there. Dynamic system library dependencies
still follow the chosen build target. `--version` lists compiled backends.
Build with `--no-default-features` for a world/TUN executable without VFIO.
Never run VFIO, XDP or AF_XDP binaries or change network settings on the
project development host. Device validation belongs in disposable guests.

The primary command is `honeypot run`. `--help` lists options. One protected
`--state-dir` owns a persistent sensor identity, a private Ed25519 SSH host key,
a process lock and separate evidence files for each run. It is created with
mode 0700. An existing state directory must have the same owner and exclude
access by other users. Key and evidence files use mode 0600. A second process
cannot use the same state directory concurrently. Keep this directory across
restarts to preserve the SSH host key. A damaged key is rejected rather than
silently replaced.

All command settings also work in a JSON configuration file. Keys are option
names without `--`; repeated service and internet-prefix settings use arrays.
CLI settings replace the corresponding file settings. Unknown options and
mixed backend options fail before opening devices. For example:

```json
{
  "backend": "tun",
  "tun": "hp0",
  "tun-mode": "existing",
  "address": "203.0.113.10",
  "state-dir": "/var/lib/honeypot",
  "metrics": "127.0.0.1:9108"
}
```

```sh
honeypot run --config sensor.json --dry-run
```

Dry run prints resolved settings and prerequisites as JSON. It does not create
state, open a device, bind listeners, or change networking. It does not certify
that the prerequisites are satisfied. Configured passwords and the host key
are excluded from this output.

## Packet backends

For development, attach clients to the world socket:

```sh
honeypot run --backend world --world unix:/tmp/honeypot.sock \
  --address 203.0.113.10 --state-dir /tmp/honeypot-state
```

Clients use the existing Fictionet attachment protocol. A prepared connector
can speak SSH without any host network changes:

```sh
ssh -o 'ProxyCommand=xtask ssh-connect /tmp/honeypot.sock %h %p' ubuntu@203.0.113.10
```

For TUN, run the following only in a prepared guest:

```sh
honeypot run --backend tun --tun hp0 --tun-mode existing \
  --address 203.0.113.10 --state-dir /var/lib/honeypot
```

Existing mode requires a persistent TUN in the current network namespace,
already up, with MTU 1500, a single queue, and no packet-info or virtio headers.
The process needs ownership or the applicable privileges to attach it, access
to `/dev/net/tun`, and sysfs for validating its format. The device remains
externally owned. Its addresses, routes, persistence, link state and DNS are
not changed. Existing nonpersistent devices are deliberately unsupported in
this first integration. Provision the device for an unprivileged owner when
possible; the executable does not automatically drop privileges.

`--tun-mode create` refuses an occupied name, creates a nonpersistent TUN with
MTU 1500, and brings only that interface up. Before link-up it sets that device's
IPv6 `addr_gen_mode=1`, `autoconf=0`, and `accept_ra=0`. These suppress kernel
link-local address generation, address autoconfiguration and router
solicitations on the decoy path; IPv6 packet handling and forwarding settings
remain intact. The values follow the [Linux IP sysctl documentation](https://docs.kernel.org/networking/ip-sysctl.html).
Existing mode leaves these settings unchanged. Closing the ephemeral device's
last descriptor removes it, including after a failed startup. Creation requires
`CAP_NET_ADMIN` and write access to the three files under
`/proc/sys/net/ipv6/conf/NAME/`. Missing or read-only sysctls fail creation.

Both TUN modes leave routes and forwarding to guest provisioning. The intended
path is guest NIC → guest kernel forwarding → TUN → Fictionet, with the return
path reversed. Route the decoy destination behind the TUN. Assigning it as a
normal local kernel address can consume traffic before Fictionet receives it.
Never replace the management default route. IPv6 and cloud public-to-private
address mappings need equivalent deliberate provisioning. Use the address
actually delivered inside the guest. TUN capture occurs after guest kernel
processing; it does not claim to preserve every malformed packet or IP option.

For direct device ownership, run only in a prepared QEMU guest:

```sh
honeypot run --backend vfio --device 0000:00:03.0 \
  --address 203.0.113.10 --gateway 203.0.113.1 \
  --address-v6 2001:db8:113::10 --gateway-v6 fe80::1 \
  --state-dir /var/lib/honeypot
```

The existing [VFIO guest prerequisites](../../host/README.md) apply: x86-64,
modern virtio-net, a real IOMMU, a suitable VFIO group, QEMU DMI and the explicit
`fictionet.rawnic=1` guest boot token. Bind the dedicated data device to
`vfio-pci` during provisioning. The executable never unbinds a kernel NIC or
sets host routes. Keep a separate management interface. ENA and Cloud
Hypervisor are not qualified by this path.

The shared Ethernet host handles ARP, IPv6 discovery and duplicate address
detection. IPv6 gateway discovery uses router advertisements when
`--gateway-v6` is absent. Replies use the configured or learned gateway; they
are dropped while it is unresolved. Untagged IP reaches the simulated host;
VLAN, malformed and unknown-EtherType frames remain in original Ethernet
capture. The adapter supports a 1500-byte IP MTU and does not fragment larger
replies. Raw pump queues hold at most 64 frames per direction; device-level
loss remains unknown.

## Observations and service behavior

All observation families are enabled together, independently of listener
selection. Defaults are SSH on 22 and Caddy HTTP with MPTCP on 80. `--ssh` and
`--http` select explicit ports; supplying either replaces the default listener
list. Port zero remains closed and cannot be configured as a listener.
`--http-profile nginx` selects ordinary TCP and the nginx response profile.

MPTCP records retain ordered options, malformed option details, keys, tokens,
handshake observations and payload presence. `ip_options_retransmit` correlates
option-bearing SYNs using the attachment, tuple and initial sequence number.
`mptcp_no_data` means no inbound payload was observed before close or the
63-second observation deadline. Neither event proves exploitation or complete
MPTCP negotiation. Joined subflows are accepted and logged but do not form a
complete multipath application data path. Bursts remain configurable heuristics.

SSH implements real encrypted negotiation, authentication, channel requests,
a simulated prompt and first-command disconnect. The default accepts supplied
passwords and correctly signed public keys; `none` is refused. `--ssh-auth
reject` rejects credentials, and `password:VALUE` requires that password or a
correctly signed public key. An actual authenticated transition is distinct
from policy acceptance or an unsigned public-key probe. Successful simulated
login is not evidence of an authentication bypass. This is the Ubuntu collector,
not an advisory-specific musl persona or classifier.

Port-zero observations cover TCP and UDP, IPv4 and IPv6, and zero in source,
destination or both fields. They include ACK-only TCP and readable header
facts from packets with invalid checksums. Non-first fragments and truncated
transport headers do not invent ports. Reassembled observations are marked as
derived. Source-zero probes to a listener differ from probes to closed port
zero, and a zero UDP source field alone does not prove malicious intent.

The persona targets Ubuntu 24.04/Linux 6.8; exact closed-port behavior and cloud
probe preservation still need matching guest and remote qualification. The
listener implementation and algorithm set are a subset of OpenSSH, not an
assertion of indistinguishability.

## Evidence and metrics

Files are named by stream, run and rotation index. `events-*.jsonl` contains
versioned JSON objects with sensor/run identity, monotonic event sequence,
writer timing, backend, persona, and the nested observation. The original
observation timestamp remains in the nested record. IP observations and IP
capture timestamps currently come from world processing.
Original Ethernet ingress additionally carries the raw backend receipt wall time
and uses it for capture; that is a software receipt timestamp, not hardware time.
`ip-*.pcapng` contains the IP boundary; VFIO additionally writes
`ethernet-*.pcapng` with original frames and Ethernet link type. The VFIO IP
view is derived. Capture references include file, section, interface and byte
offset where a persisted record can be correlated. Missing references stay
unavailable; derived fragment observations do not claim one original packet.
Linking every contributing fragment remains future work.

Default SSH analytics retain methods, outcomes and byte lengths while removing
passwords and exact decrypted command/input/output bytes. Packet capture still
contains original traffic, including unencrypted protocol payloads.
`--restricted-evidence` explicitly retains exact decrypted SSH records in the
protected state directory. Keep retention and exported destinations appropriate
for that choice. SSH `wire_payload` is reconstructed protocol data, never the
original encrypted network packet.

Evidence admission is bounded by record count and bytes. A worker performs file
writes and envelopes outside the world; admission does not wait for disk.
Observation-to-JSON serialization still occurs in the world before admission.
Overflow and storage
failure increment separate event/capture loss and write-failure counters. A
small independent queue reserves lifecycle capacity. Rotation defaults to
64 MiB or one hour, with 32 files retained **per stream** across runs. Change
`--rotate-bytes`, `--retain-files`, `--queue-bytes` and `--max-record-bytes` to
bound the intended budget. Retention runs at startup and rotation. Queued does not mean written,
and written does not mean synchronized. The worker aims to synchronize once a
second when scheduled and storage responds; a stalled filesystem can exceed
that interval.

SIGINT/SIGTERM cancel the world, close the backend and request a five-second
writer drain. A stalled worker causes a shutdown error after that deadline.
Abrupt exits can leave incomplete final records; restart preserves those files
and starts new ones instead of appending into damaged tails. No automatic
repair of old files is attempted.

Enable a real management HTTP listener explicitly:

```sh
honeypot run --config sensor.json --metrics 127.0.0.1:9108
```

Prometheus scrapes `/metrics`; Grafana can display it. JSONL can be shipped by
an external agent to Loki or another analytics store. No log shipper is required
for local collection. Metrics have bounded labels and remain readable during
writer failure. They include queue occupancy, capture/event loss, write and sync
failures, last persistence, port-zero observations and SSH authentication
completions, MPTCP signals, and backend readiness. These observation counters
describe records processed by the
writer, not lossless ingress totals. Written event totals include Ethernet
sidecars generated after queue admission. Software queue loss never substitutes
for unknown NIC loss.

Observer maps each have a hard limit of 4096 entries and emit capacity loss
records. Established service connections share a 256-connection guard.
Reassembly and preauthentication also retain their existing limits. These
limits are the first operating bounds, not a completed CPU/memory qualification
under Internet floods. QEMU validation covers TUN lifecycle and VFIO teardown;
cloud reachability, driver coverage, and sustained load still need deployment
qualification.

## Validation and next work

Use Cargo tests, benches, clippy, rustfmt and documentation checks. Host-safe
world checks use a build with `--no-default-features`; all device execution
and network-changing tests run only inside disposable guests:

```sh
cargo test -p honeypot-world --no-default-features
cargo xtask-host rawnic /tmp/honeypot-qemu
```

The existing `cargo xtask-host rawnic` harness packages and exercises the unified executable
in QEMU, including original Ethernet capture and graceful shutdown. Guest
checks cover ephemeral and persistent TUN ownership and bidirectional IP traffic
without adding routes. The harness also retains the in-memory and driver-level protocol checks.

To exercise the deployed executable against a real Linux kernel client in a
second VM, use an empty artifact directory:

```sh
systemd-run --user --scope -q --slice=fictionet-work.slice \
  -p MemoryMax=10G -p MemorySwapMax=0 \
  env CARGO_TARGET_DIR=/home/souvik/Projects/amlalabs/.fictionet-comp-work/target-honeypot-vm \
  cargo xtask-host honeypot-vm \
  /home/souvik/Projects/amlalabs/.fictionet-comp-work/honeypot-vm-run
```

The task builds the executables and two initramfs images, then boots two QEMU
guests with 2 GiB each. The sensor runs the actual
`honeypot run --backend vfio --device 0000:00:03.0` executable. The attacker
uses an `IPPROTO_MPTCP` socket to fetch the complete HTTP page, OpenSSH over
ordinary TCP to authenticate with a fresh Ed25519 key and send its first command,
and an ordinary kernel TCP connect to literal destination port zero. No packet
fixtures implement those connections. The first SSH command is observed and
disconnected without execution. MP_JOIN is outside this task's coverage.

The only data connection is QEMU's Unix stream netdev between the two virtual
cards. There is no slirp, TAP, bridge, host interface, management NIC, external
route or public deployment. Each guest checks its network devices and routes,
and requires external IPv4 and IPv6 TCP attempts to fail with `ENETUNREACH`.
Only guest init loads modules, binds the VFIO device, or sets the attacker's
interface address. The host only reads its kernel/module files and runs QEMU.
All subprocesses inherit the command's memory scope. This task runs no full
test suite and requires the existing raw NIC prerequisites, an MPTCP-enabled
guest kernel, 9p modules, and host `ssh` and `ssh-keygen` binaries for packaging.

Separate 9p shares export the sensor's actual `events-*.jsonl`, original
`ethernet-*.pcapng`, derived `ip-*.pcapng`, and shutdown log under `sensor/`;
the attacker's HTTP response, kernel MPTCP report and SSH log are under
`attacker/`. Both directories contain `isolation.json`; QEMU commands and serial
logs are at the artifact root. Keep the artifact directory private: it also
contains the sensor's persistent identity and SSH host key.

Success requires both guest exit devices to report success and a semantic check
of the exported evidence. The checker correlates the client's kernel MPTCP
token with the captured client key, validates the SYN, SYN-ACK and third ACK
sequence numbers and both keys against JSON observations, checks DSS-bearing
HTTP data against the bytes received by the kernel, resolves capture references,
checks plain TCP SSH and its authenticated session, and matches the port-zero
SYN and reset. Evidence admission, writing, synchronization and raw queue loss
counters must remain zero; the final writer queue must drain. This validates
the local two-guest path, not cloud filtering, Internet reachability, load
capacity, or the unfinished XDP/AF_XDP backend.

AF_XDP needs its own embedded redirector, correct queue coverage, bounded
copy-mode transport, ownership and crash guards, and qualification on the
actual guest NIC/driver/kernel combination. Native/generic and copy/zero-copy
are separate capabilities. No current startup message claims those capabilities,
a direct ENA driver, or a validated advisory-specific SSH classifier.

## Initiated traffic spike

An embedding application can call `Honeypot::program` with a Fictionet
`Program`. It receives the existing server machine's TCP and UDP endpoints;
`machine.tcp.connect` and a bound UDP socket's `send_to` initiate traffic
through the same `internet` attachment used for incoming traffic and replies.
The backend's routes and, for Ethernet, gateway resolution still apply. This
hook runs trusted application code; SSH input is never used to initiate traffic.
The deployed CLI does not start an outbound program.

`cargo xtask-host egress /path/to/guest-artifacts` builds and boots a disposable QEMU
guest. It checks IPv4 TCP and UDP request/response exchanges through the
in-process world attachment, TUN with a guest Linux peer, and two VFIO
virtio-net devices connected by an internal QEMU hub. All peers run inside the
guest. There is no host networking backend or external network connection.
The guest verifies randomized payload responses, capture directions and
checksums, and that the existing incoming HTTP service still works. Its result
reaches the harness through QEMU's exit device, independently of printed text.

Run this task only where QEMU and the existing raw NIC guest prerequisites are
available. Choose an artifact directory outside temporary storage. This spike
does not qualify the Unix world socket transport, IPv6, performance, cloud NICs,
or the planned XDP/AF_XDP backend.
