# Honeypot reuse

The honeypot already uses the SDK's IP, TCP, MPTCP, Ethernet, ARP, neighbor
discovery, HTTP and SSH codecs. Reuse should remove a second implementation
of a rule, without making different network roles pretend to be the same.

## Frame queues and losses

The raw NIC pump and its in-memory wire now use the same attachment
constructor. Receive and transmit queues use the same `QueueStats` enqueue
operation. A full queue discards and counts; closure remains an error, and
an invalid frame never enters the queue. Async sends still wait for space.
The driver still publishes failures before closing its channels and still
owns completion of flush requests.

The raw frame log includes `tx_queue_dropped` beside `rx_queue_dropped`.
Both are deltas since the last accepted record. An outgoing frame is logged
after its enqueue attempt, so that very record includes its rejection.
Failed log writes retain the unreported counts. Device/backend loss stays
unknown (`nic_rx_dropped: null`). The README now describes the actual
receive behavior: keep reading and count discarded frames.

## Separate roles

`ethernet::Link` is the gateway of one VM. Its ARP reply policy is proxy
ARP for addresses other than a probe/announcement, subject to its configured
family and guest checks. Putting it on a shared cloud segment would claim
addresses it does not own, including a real gateway's. `ethernet::Host`
answers only for its own addresses and performs neighbor reachability,
IPv6 duplicate-address detection and multicast membership. They already
share frame construction and the ARP/NDP/MLD codecs. Keep both state machines.

Keep the transport execution models separate too. VFIO polls device
completion and owns DMA memory; vhost-user consumes guest descriptors from
callbacks and wakes through eventfd; the CLI multiplexes nonblocking file
descriptors and relay messages. A single polling pump would add adapters
and change readiness, flush and shutdown semantics. Their bounded queues
are real device/transport contracts, not a reason to merge those loops.

## Linux behavior and protocol evidence

The reusable MPTCP listener now lives at `fictionet_extras::linux::mptcp`.
Its timestamp input is a callback in milliseconds since midnight UTC;
it no longer depends on the demo's wall-clock type. Plain TCP and MPTCP
share the IPv4 SYN-reply address classification and retransmission policy
inside `linux`. JOIN cookies still retain the IPv4 options selected for
the SYN-ACK. Simply wrapping the listener and deleting its internal hook
would have lost those retained options, so that approach was rejected.

Generic MPTCP codecs and `DataLevel` stay in core. Linux option acceptance,
last-option preference, JOIN limits, cookie slots and reset reasons stay
in extras. This listener still delivers application data through its
primary connection and drains joined subflows; moving it does not turn it
into a complete multipath application endpoint.

TCP option walking now delegates to the same smoltcp parser in the endpoint,
dissector and differential probe. Core's lossless iterator retains each
option's original bytes, end-of-list padding and a malformed suffix. The
probe keeps its raw evidence and presentation. The dissector no longer
inventories malformed-size SACK options as valid blocks. The observer
already used the shared TCP/MPTCP codecs; its JSON enums remain application
presentation, not another protocol implementation. Hex serialization uses
the existing dissector helper.

The differential HTTP probe uses core's whole-response decoder instead of
its own Content-Length parser and header/body caps. It records the decoder's
original wire bytes, including header order and body framing. Unconsumed
read-ahead stays in its BufReader for the next response or idle observation.

## Guest harnesses

`honeypot_diff::forward` now uses `ethernet::Host`, the same link layer as
raw mode. It resolves the probe guest as its gateway, validates destination
frames and strips IP padding through the shared implementation. Fixed-offset
ARP rewriting and a hard-coded destination MAC are gone. The comparison's
configured network remains IPv4; the raw guest exercise covers IPv6.

The differential harness and raw peer use `ethernet::stream::Decoder`, as
the CLI's QEMU frontend does. Raw echo and honeypot phases share one peer,
so decoder read-ahead survives their transition. Keep the blocking writer's
two-line length prefix and `write_all`: introducing the CLI's bounded Outbox
there would add buffering without helping a synchronous write. The CLI
still needs Outbox to retain partial nonblocking writes.

The raw HTTP peer now uses `http1::ResponseEvents`, replacing its independent
header scan and arbitrary 8 KiB response cap. It sends cumulative TCP and
DSS acknowledgments, with timestamp echoes, so a response can progress past
the sender's initial window. All existing transport checks remain; the
complete decoded body must match the existing Caddy fixture. This fixes the
client, rather than shortening the page or increasing the old cap.

The existing rawnic exercise also packages and launches the actual
`raw_honeypot` example inside its marked QEMU guest and repeats link setup,
IPv6 SSH and the complete MPTCP HTTP exchange. A guest FIFO carries frame
records to the parent until the existing completion frame arrives. Cleanup
kills and reaps only that example child. No extra polling wait or timeout
was introduced. The original malformed-frame, byte-preservation, oversized
ping, queue and driver exercises still run.

Running the whole differential harness through `start_raw` was considered.
It would require a new stream transport/launcher API and change the external
binary comparison boundary. Sharing Host directly removes the duplicated
protocol logic; the separate guest run exercises `start_raw` and the actual
example. Keep that split until a production stream transport is needed.

## Other decisions

| Area | Decision and reason |
| --- | --- |
| Frame capture and pcapng | Keep raw JSON and IP pcapng. `observe::Sink` already handles both and is reused by raw capture, including partial-write recovery. There is only one core pcap writer, not competing implementations. Adding Ethernet link types would be a new feature and replacing JSON would lose typed queue-loss/unknown-device-loss fields. |
| Observation schemas | Keep `Observation`, `Opt`, `Ipv4Opt`, and MPTCP JSON representations in the demo. They annotate protocol values with log-specific meaning and serialization. The differential probe records wire evidence, not honeypot attack observations. Share parsing, not application schemas. |
| Probe header fields | Keep its field-level IP/TCP presentation and original hex. Strict endpoint validation is not a substitute for describing imperfect captured input. IPv4 options, ARP, SSH packets and MPTCP already use their core codecs. |
| Raw peer protocol oracle | Keep its independent ARP/NDP/MLD expectation state and deliberately malformed frame construction. Replacing the peer with Host would test the implementation against itself. Share stream framing, not expected behavior. The probe's PacketLink already uses typed ARP packets and replies. |
| Linux TCP settings and cookies | Keep the Linux cookie layout, hashes, windows, option ordering and timestamps in extras, distinct from generic endpoint defaults. These imitate an OS; similar arithmetic does not imply identical wire behavior. |
| MPTCP offer interpretation | Keep Linux acceptance/duplicate-option policy separate from the observer's exhaustive decoding of valid, unknown and malformed options. They already share the RFC codec. |
| Virtio queues | Keep the raw driver and kit backend separate. The former produces available DMA descriptors and consumes used completions; the latter consumes guest descriptors and produces used entries through `virtio_queue`. Their small shared header constants do not justify another codec or queue framework. |
| Transport statistics | Raw receive/transmit now share queue accounting. The CLI's protocol-drop reasons and relay-buffer loss differ from raw queue loss. Kit still has no loss counters. Do not describe missing kit/device counters as zero or hide protocol and queue losses behind one count. A universal counter object would not remove those distinct observation points. |
| Shared world adapter | Keep raw mode's timed Host tasks and the kit's gateway bridge separate. Host requires deadlines, logging and neighbor state; kit learns DHCP leases for its dashboard. A trait spanning both would mostly forward methods without deleting their work. Core stays sans-I/O. |
| Other logging | Do not replace `Sink` with `extras::log`: wall time, record folding, async buffering and finalization differ from deterministic packet timestamps and recovery from partial records. |
| Configuration | Keep the demo's typed Args/Config. `extras::args` is oriented to Docker paths and string errors. The xtask's Caddy/nginx selector also owns provisioning and observation duration, not the world's full configuration. No shared registry is needed. |
| HTTP and SSH personas | Keep application responses local for now. HTTP framing/date and SSH events/packets/KEXINIT already reuse SDK codecs. Generic HTTP serving would change measured header ordering and connection behavior. There is no second copy of these personas to remove. |
| Child and guest packaging helpers | Keep local cleanup and packaging glue. The two short kill/wait guards have little code to save; the kit's Tokio child setup also changes process groups. Initramfs entries and a shared library directory have different lifecycles. A common packaging framework would add more than it removes. |
| Guest images | Keep the comparison's three-file NoCloud ISO setup. The kit's single-file FAT seed is not interchangeable. Replacing qemu-img overlay creation with another library is tooling work, not a honeypot protocol unification. |

## Architecture page corrections and production transport

The page correctly identifies shared Ethernet codecs, distinct gateway/host
roles, the raw transmit-loss omission, kit's missing counters and the stale
host README. Several details were already out of date: the probe uses typed
ARP, the raw HTTP peer has no nginx-string assertion, and the deleted
honeypot tests are not present in this checkout. Raw Host sends multicast
and broadcast directly to group MACs; only ordinary unicast uses its gateway.
The page's historical fidelity results and package/kernel claims are not
substitutes for the new run's artifacts.

`cli/src/tap/device.rs::Mirror` really orders device-down before installing
both tc redirects and device-up after them, and registers cleanup before
mutating them. `cli/src/netlink.rs` selects redirect/stolen semantics. That
establishes setup ordering for the existing TAP frontend, not a guarantee
for an arbitrary physical cloud NIC. The device can already be active before
setup starts; offloads, management agents, driver behavior and SIGKILL
cleanup are outside that proof. Extracting Mirror into a production raw
transport would expand scope without removing an existing transport copy.
Leave that proposal unimplemented until its physical-NIC behavior is tested
inside an isolated guest. No VFIO guard was relaxed, and no host interface,
network setting, driver binding or module was changed here.

## Verification

All cargo invocations used this worktree's `target` directory and a user
systemd scope with `MemoryMax=32G`. No new output-assertion tests, scripts,
checkers, registries or generated tracked metadata were added.

- `cargo test -p fictionet -p fictionet-extras -p smoltcp --lib` passed.
- `cargo test -p fictionet-extras --test linux --test tcp_options` passed
  all nineteen existing integration cases.
- `cargo xtask honeypot-diff prepare caddy` prepared fresh guests, then
  `cargo xtask honeypot-diff run caddy reuse` completed with probe status
  zero. Artifacts are in `target/honeypot-diff/share/reuse`.
- That run used Ubuntu kernel 6.8.0-147-generic and Caddy 2.11.9. Both
  ordinary and MPTCP HTTP completed two requests on one connection; their
  responses matched byte-for-byte except Date. Both MPTCP sockets negotiated
  without fallback. Both sides answered every IPv4-option retransmission
  case, closed HTTP at approximately 300 seconds, and received nmap's same
  Linux 4.15–5.8 classification. The known SSH difference remains: the
  imitation stops after KEXINIT, while the reference completes key exchange.
  This is a comparison result, not a claim of complete Linux fidelity.
- `cargo xtask rawnic target/rawnic-qemu` passed. Its serial log contains
  both `RAW EXAMPLE PASS` and `RAWNIC PASS`. The guest ran the existing host
  transport/queue tests, preserved all six raw fixtures, exercised oversized
  reply handling and IPv6, and served the entire Caddy page through MPTCP
  from both the in-process world and the actual example binary.
- `cargo bench -p fictionet --bench network -- tcp` completed the TCP bulk
  and round-trip benchmarks. No performance comparison to a baseline is
  claimed.
- `cargo doc` for core, extras, host and honeypot passed with warnings denied.
  This caught and corrected the old links to the moved MPTCP module.
- `cargo fmt --all --check` and clippy with `-D warnings`, all targets and
  the raw features, passed for the changed crates before their commits.

All raw NIC access, module loading and driver binding occurred inside the
marked QEMU guest. Guest networking used userspace networking and loopback
socket backends. The VFIO driver itself and its guest-only guard are unchanged.
