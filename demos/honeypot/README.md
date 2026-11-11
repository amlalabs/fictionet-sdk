# Honeypot

One executable serves a Fictionet Linux host, collects MPTCP and IPv4-option
observations, terminates encrypted SSH sessions, and observes literal TCP and
UDP port zero. Client input never becomes a host command. SSH shows a simulated
prompt and disconnects before executing the first nonempty command; exec and
subsystem requests also disconnect.

## Packet path

The world runs behind `start_raw`, which takes whole Ethernet frames from a
`fictionet_host::raw::RawAttachment`. A network card's driver holds the other
side. This build has no driver yet: `honeypot run` checks its options, then
refuses to start before it opens its state directory. `--help` says so.

The Ethernet host in `start_raw` handles ARP, IPv6 discovery and duplicate
address detection. IPv6 gateway discovery uses router advertisements when
`--gateway-v6` is absent. Replies use the configured or learned gateway; they
are dropped while it is unresolved. Untagged IP reaches the simulated host;
VLAN, malformed and unknown-EtherType frames stay in the original Ethernet
capture. The adapter supports a 1500-byte IP MTU and does not fragment larger
replies. The attachment's queues hold at most 64 frames per direction and
count the frames a full queue discards; device-level loss is unknown.

## Northbank deployment services

The same executable can serve a small company's deployment network. SSH's
application and authentication behavior are unchanged. Enable the services
with `--mcp 8081 --a2a 8082 --fleet 8083`. These entry ports share application
state with the private hosts:

| Host | Address | Application |
| --- | --- | --- |
| deploy.northbank.internal | 10.44.0.11 | MCP deployment approvals |
| change.northbank.internal | 10.44.0.12 | A2A change review |
| fleet.northbank.internal | 10.44.0.13 | Rollout portal and API |

Each enabled host serves HTTP on 80 and HTTPS on 443 with a world-issued
Northbank internal certificate. The primary honeypot address serves authoritative
DNS on UDP and TCP 53. Only enabled applications have DNS records. The primary
HTTP page stays unchanged. On the Ethernet link, separate simulated hosts
answer ARP for the company addresses. The private address range must be routed
to the sensor by the client.

MCP initialization requires the client's routed model identifier and client
name/version, refuses the first attempt, and rejects placeholder and retired
model declarations without providing a valid example. `deploy_bundle` starts a
three-section approval: operator log, risk assessment and rollback note.
`complete_sampling` must supply the current request identifier and original
prose of at least 80 characters. A2A exposes its agent card and a four-section
change review over `message/send`, with model/runtime metadata and a context
identifier. The writing gates return synthetic deployment material after the
required sections. These values confer no access outside the world.

The mandatory sampling model field and initial negotiation refusal are deliberate
trap extensions, as in the paper. A client must retain the returned session ID
and retry; a generic MCP SDK that aborts on the first initialization error will
not complete the gate. The server exposes a JSON response subset of
[MCP Streamable HTTP](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports)
and an A2A 0.3 message interface; it is not a full implementation of every
operation or streaming mode in either protocol.

The fleet portal's rollout log exposes a URL password, a two-part signed-token
shape and a three-part signed-token shape. Later credential submissions record
whether the value arrived whole, masked or otherwise changed. A retry holds
its response for 150 seconds; the log stream sends progress every 45 seconds;
four host checks each take two seconds. Their request intervals and socket
outcomes show timing and concurrency. A successful HTTP connection alone does
not show that the agent completed these gates.

Every gate goes through `Observation::Trap` and the bounded evidence writer.
Records retain declarations, accepted/refused prose, request bodies,
credential submissions, request connection identifiers and ordinals, HTTP
versions, probe outcomes and payout events. Application inputs are untrusted;
the server never executes them.

`Observation::Network` adds both-direction TCP sequence/acknowledgment numbers,
flags, advertised windows and payload lengths (including pure ACKs), DNS
questions over UDP/TCP, and exact TLS ClientHello handshake bytes. The latter
preserve cipher and extension ordering, SNI, ALPN and GREASE without choosing a
fingerprint algorithm. A bounded first-flight reader handles split records and
retransmitted prefixes; gaps, limits and incomplete closes are explicit. It
does not guess through an out-of-order gap. The original packet captures remain
available for a fuller offline reconstruction. HTTP/2 and HTTP/3 serving are
not implemented by these applications; TLS advertises HTTP/1.1 only.

Inference is offline; see [INFERENCE.md](INFERENCE.md) for fitting a character
n-gram vocabulary, enrolling trace templates and applying declaration and
harness probe rules. Synthetic scripted-client prose checks plumbing, not
fingerprinting accuracy. Use separate labeled agent traces for enrollment and
evaluation; no paper accuracy claim carries over automatically.

## Build and options

```sh
cargo build --release -p honeypot-world --bin honeypot
```

The executable needs no Rust toolchain, `fictionet` CLI or helper process
where it runs. Dynamic system library dependencies still follow the chosen
build target. `--version` prints the build version.

The primary command is `honeypot run`, configured on the command line only.
`--help` lists options; unknown options fail. `--address`, `--address-v6`,
`--gateway` and `--gateway-v6` set the server's addresses and the link's
gateways. One protected `--state-dir` owns a persistent sensor identity, a
private Ed25519 SSH host key, a process lock and separate evidence files for
each run. It is created with mode 0700. An existing state directory must have
the same owner and exclude access by other users. Key and evidence files use
mode 0600. A second process cannot use the same state directory concurrently.
Keep this directory across restarts to preserve the SSH host key. A damaged
key is rejected rather than silently replaced.

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
from policy acceptance or an unsigned public-key probe. A successful simulated
login does not show an authentication bypass. This is the Ubuntu collector,
not an advisory-specific musl persona or classifier.

Port-zero observations cover TCP and UDP, IPv4 and IPv6, and zero in source,
destination or both fields. They include ACK-only TCP and readable header
facts from packets with invalid checksums. Non-first fragments and truncated
transport headers do not invent ports. Reassembled observations are marked as
derived. Source-zero probes to a listener differ from probes to closed port
zero, and a zero UDP source field alone does not prove malicious intent.

The persona targets Ubuntu 24.04/Linux 6.8; exact closed-port behavior and cloud
probe preservation still need matching remote qualification. The listener
implementation and algorithm set are a subset of OpenSSH, not an assertion of
indistinguishability.

`Honeypot::program` runs trusted application code on the server machine. It
receives the server's TCP and UDP endpoints; `tcp.connect` and a bound UDP
socket's `send_to` start traffic through the same `internet` attachment used
for incoming traffic and replies, and on the Ethernet link through the same
gateway. SSH input never starts traffic, and the executable runs no program.

## Evidence

The world emits typed records (`record::Record`): observations, Ethernet
frames and the executable's lifecycle. It hands them, and each captured IP
packet, to an `EventSink`, and never turns them into JSON itself. One writer
thread serializes each record into a line of the log, writes packets and
frames to pcapng, and then passes the line, as typed values, to each
`RecordConsumer` the executable gives `Writer::open`. Live attribution and
the dashboard are consumers. Every line reads back into the same types, so a
stored log replays as the same records.

Files are named by stream, run and rotation index. `events-*.jsonl` contains
versioned JSON objects with sensor/run identity, monotonic event sequence,
writer timing, backend, persona, and the nested observation. The original
observation timestamp remains in the nested record. IP observations and IP
capture timestamps come from world processing. Original Ethernet ingress
additionally carries the attachment's receipt wall time and uses it for
capture; that is a software receipt timestamp, not hardware time.
`ethernet-*.pcapng` holds the original frames with the Ethernet link type, and
`ip-*.pcapng` the IP packets derived from them. Capture references include
file, section, interface and byte offset where a persisted record can be
correlated. Missing references stay unavailable; derived fragment observations
do not claim one original packet.

By default, SSH records keep methods, outcomes and byte lengths, without
passwords and exact decrypted command/input/output bytes, and TCP segment
records keep a payload's length (`payload_bytes`), not its bytes. The world
makes the records that way, so consumers see the same. Packet capture still
contains original traffic, including unencrypted protocol payloads.
`--restricted-evidence` explicitly retains exact decrypted SSH records and
segment payloads in the protected state directory. Keep retention and exported destinations appropriate
for that choice. SSH `wire_payload` is reconstructed protocol data, never the
original encrypted network packet.

Evidence admission is bounded by record count and by bytes. A record's bytes
are estimated at admission from its string and byte lengths, without
formatting it; the writer drops a line that is over `--max-record-bytes`
once written. The worker performs serialization, file writes and envelopes
outside the world; admission does not wait for disk. Overflow and storage
failure increment separate event/capture loss and write-failure counters. A small independent queue reserves lifecycle capacity.
Rotation defaults to 64 MiB or one hour, with 32 files retained **per stream**
across runs. Change `--rotate-bytes`, `--retain-files`, `--queue-bytes` and
`--max-record-bytes` to bound the intended budget. Retention runs at startup
and rotation. Queued does not mean written, and written does not mean
synchronized. The worker aims to synchronize once a second when scheduled and
storage responds; a stalled filesystem can exceed that interval.

SIGINT/SIGTERM cancel the world and request a five-second writer drain. A
stalled worker causes a shutdown error after that deadline. Abrupt exits can
leave incomplete final records; restart preserves those files and starts new
ones instead of appending into damaged tails. No automatic repair of old files
is attempted.

The writer keeps health counters that stay readable during writer failure:
queue occupancy, capture/event loss, write and sync failures, last
persistence, port-zero observations and SSH authentication completions, MPTCP
signals, and backend readiness. It counts by record type. The observation
counters describe records processed by the writer, not lossless ingress
totals. The executable prints them to standard error when it stops. Software
queue loss never substitutes for unknown NIC loss.

Observer maps each have a hard limit of 4096 entries and emit capacity loss
records. Established service connections share a 256-connection guard.
Reassembly and preauthentication also retain their limits. These limits are
the first operating bounds, not a completed CPU/memory qualification under
Internet floods.

## Running on EC2

`cargo xtask-host honeypot-aws` runs one honeypot instance in eu-west-2 with
the AWS CLI. Every command first checks the AWS session; when it has expired,
it stops and says to run `aws login`.

| Command | What it does |
| --- | --- |
| `launch` | Creates an m8i.large on Amazon Linux 2023 with two network interfaces. The management interface gets its own Elastic IP and a security group that admits SSH only from the address this workstation has when it launches. The data interface gets no public address and a security group with no rules. The SSH key pair is made here, kept under `~/.ssh`, and its public half imported. |
| `deploy` | Builds `honeypot` as a static `x86_64-unknown-linux-musl` executable, copies it over SSH, writes its systemd unit and restarts the service. The unit restarts the honeypot whenever it exits and limits its memory to 4 GiB. The commit it was built from is kept on the instance. |
| `status` | The instance's state and addresses, the data interface as Linux sees it, the service state, the deployed commit and the service's last log lines. |
| `dashboard` | Forwards `127.0.0.1:8700` here to the same port on the instance over SSH, until Ctrl-C. |
| `stop`, `start` | Stops or starts the instance. Both addresses stay. |
| `terminate` | Terminates the instance and deletes the data interface, both security groups, the key pair (in AWS and here) and the Elastic IP. |

`launch` records the ID of each resource it creates in
`~/.local/state/fictionet/honeypot-aws/state.json` (or under
`$XDG_STATE_HOME`), and tags each one `fictionet-honeypot=<launch ID>`. The
other commands act only on the resources in that file, and only after AWS
reports the same tag on them. A `launch` that stops partway can be cleaned up
with `terminate`. `launch` refuses to run while a launch is recorded.

The first boot leaves the data interface to the honeypot. A systemd-networkd
file marks it unmanaged, matched by its MAC address, and a udev rule turns off
IPv6 router advertisements, link-local addresses and IPv6 itself when it
appears. `launch` attaches the data interface only after the first boot has
finished, then reports its addresses, which should be none.

The musl build compiles the crates with C in them (aws-lc, ring, OpenSSL, xz
and zstd) with `zig cc`, which carries musl's headers and C library. The xtask
executable stands in for the C compiler and passes each call to `zig cc` with
zig's name for the target. OpenSSL is built from source for musl builds.

## Tests

The tests run in process, with no device and no host networking:

```sh
systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=8G -p MemorySwapMax=0 cargo test -p honeypot-world
```

| Test | What it checks |
| --- | --- |
| `tests/port_zero.rs` | Sixteen probes, eleven with a literal zero port: the resets, the source-zero handshake and close, UDP delivery with the source kept, port unreachable quoting the probe, and one `port_zero` line per zero-port probe pointing at its packet in the IP capture |
| `tests/initiated.rs` | TCP and UDP exchanges started through `Honeypot::program` between two honeypots, then inbound HTTP on the same attachment, and the capture of both directions |
| `tests/ethernet.rs` | The same probes and exchanges through `start_raw`, over two in-memory raw attachments joined by a task that copies frames: ARP and gateway resolution, the Ethernet capture and its log lines, and the queue counters |
| `tests/traps.rs` | The MCP, A2A and fleet gates, the 150-second retry hold, and the gate records read back from the log as typed values |

Each test writes its evidence with the real writer into a temporary state
directory and checks the files it leaves.
