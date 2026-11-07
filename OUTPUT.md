Three applications are implemented and exercised as packet-level Fictionet worlds.

The starting point was [The Port That Does Not Exist](https://acid.vegas/blog/the-port-that-does-not-exist/), published November 6, 2026. Its useful distinctions are between a wire port and a socket API convention, a completed TCP handshake and an application response, and the initiator of a TCP connection and the client of the application protocol. The work below develops those distinctions into controlled environments. It does not reproduce the article's internet scan or contact any of its listed systems.

**Port coverage and exposure assessment.** A maintenance HTTP service is reachable on both TCP zero and 8080. This gives agent evaluations a concrete way to test whether discovery depends on conventional port lists, while holding application behavior constant. An omitted port can hide a working service from the agent without changing what that service does.

Fictionet's TCP listener, connector, host builder and embedded TCP decoder now accept literal port zero. The embedded socket previously used zero to mean that it had no passive listener; that state is now an `Option`, so a reset during a handshake can correctly return a zero-port listener to listening. TCP's local ephemeral-port selection is unchanged. UDP's existing `bind(0)` still requests an ephemeral port.

Validation exercises IPv4 and IPv6 conversations at zero, one and the largest port, bidirectional data, address identity, close/refusal/rebind behavior, passive resets, simultaneous opens and atomic rejection of duplicate host listeners. The maintenance prototype compares successful decoded HTTP responses across the two ports and checks observations against the actual connection endpoints. It does not pin a page or banner to a golden string.

**Evidence-aware reconnaissance.** A second machine accepts TCP zero, consumes input and sends no application bytes. An adjacent port is closed. Together with the maintenance service, this provides three distinct outcomes for discovery agents: refusal, transport connectivity without an application response, and a parsed application response. World-side typed observations distinguish accepted connections, consumed bytes and handled HTTP requests.

The prototype validates a complete silent exchange through client half-close and server EOF, relates the world's consumed-byte count to the request sent, and contrasts it with a refused connection. This is a finite observed interaction, not proof that an arbitrary remote service can never answer. The component does not imitate a particular load balancer, emit vendor reset banners or infer deployed-device counts from addresses.

**Protocol roles independent of connection direction.** `fictionet_extras::reverse_modbus::Reader` is a reusable `PortServer` that accepts TCP but speaks first as the Modbus client. It asks the connecting peer for input or holding registers, validates the reply and reports a typed result to world code. This supplies an industrial gateway scenario in which an agent must read before sending and then serve the requested data, rather than assuming every listening port is an application server.

The reader uses the existing Modbus codec. It checks transaction identity, unit, function and register count, distinguishes protocol exceptions and malformed or truncated replies, and rejects invalid read ranges before serving. Tests cover both register banks, IPv4 and IPv6, zero and a nonstandard high port, runtime-derived register values, each mismatch kind, exceptions, malformed PDUs, EOF, truncation and invalid configuration. The application tests do not force fragmented reads or exercise transport failure and cancellation; incremental framing comes from the existing codec. This is one Modbus/TCP transaction per connection, not a vendor emulator or Modbus RTU serial bridge. No application timeout or new policy limit is added; a silent peer remains pending until transport closure or world cancellation.

The integrated world is [extras/examples/port_world.rs](extras/examples/port_world.rs):

| Host | IPv4 | IPv6 | TCP ports |
| --- | --- | --- | --- |
| maintenance.south.internal | 10.20.0.10 | fd20::10 | 0, 8080 |
| edge.south.internal | 10.20.0.11 | fd20::11 | 0 |
| collector.south.internal | 10.20.0.12 | fd20::12 | 0 |

Each machine uses ordinary protocol bytes. Observations stay in the world process; the guest receives no evaluation labels. The example uses Fictionet's Unix attachment socket and requires no host network interface or route changes. The existing `ssh-connect` stdio connector now accepts zero too, so a client can reach the maintenance service through the relay without asking the host kernel to connect to port zero.

Build and run from this directory:

```sh
export CARGO_TARGET_DIR=/home/souvik/Projects/amlalabs/.port-ideas-target
export CARGO_BUILD_JOBS=6
systemd-run --user --scope -p MemoryMax=16G cargo build --locked --profile test -p fictionet-extras --example port_world -p xtask --bin xtask
"$CARGO_TARGET_DIR/debug/examples/port_world" /tmp/port-world.sock
```

In another terminal, use the built connector with the same target directory:

```sh
printf 'GET /status HTTP/1.1\r\nHost: maintenance.south.internal\r\nConnection: close\r\n\r\n' | "$CARGO_TARGET_DIR/debug/xtask" ssh-connect /tmp/port-world.sock 10.20.0.10 0
```

The world runs until its owner stops it. Use a socket path owned by that run. This connector exercises simulated TCP; it does not validate Linux `getpeername`, browser unsafe-port policy, actual NAT rules or third-party scanner behavior. No claim is made that those clients now support zero. Application evaluation policies and scoring remain with the caller.

Validation used the prescribed target directory, six build jobs and a 16 GiB systemd scope. All checks completed successfully:

| Check | Result |
| --- | --- |
| Fictionet TCP/UDP and Net composition modules | 60 tests passed |
| Embedded TCP socket and wire modules | 287 tests passed |
| Integrated world example | 2 tests passed, each over IPv4 and IPv6 |
| Reverse Modbus integration tests | 4 tests passed |
| Reverse Modbus doctest | 1 passed |
| Scoped rustfmt and clippy | Passed; clippy denied warnings |
| Documentation for fictionet, extras, smoltcp and xtask | Built with rustdoc warnings denied |
| Existing TCP transfer and round-trip benchmark | Completed with `cargo bench --locked --profile test -p fictionet --bench network -- tcp` |
| Runnable world and existing stdio connector | Built and exercised through a temporary Unix socket |

The benchmark used Cargo's optimized test profile; it is an execution check without a before/after performance claim. The live run returned a complete HTTP response from TCP zero, consumed an HTTP request at the silent edge without returning application bytes, and completed a Modbus register exchange in which the listening controller sent the request first. Its world-side callback reported a successful sample. Only that run's own process was stopped, by its process identifier, and its temporary socket directory was removed.

An independent agent reviewed the implementation and validation claims. It found no concrete runtime defect. The report was narrowed where application tests did not establish fragmented reads or transport-error coverage, and an ineffective chunked-write loop was removed. No test assertion was loosened and no wait was added to make a test pass.

No XDP, AF_XDP or VFIO program was run on the host. All application traffic stayed in userspace simulation and Unix relay connections. No guest or host network configuration was modified, and nothing was pushed.
