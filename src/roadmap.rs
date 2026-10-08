//! Roadmap: what is planned for Fictionet, and how it is meant to work.
//!
//! Everything on the other pages works now. This page collects what is
//! planned: more ways to attach a sandbox, a remote transport between
//! attach and a world, and new ways to run a world. Read it when
//! you want to know whether something you need is coming, or to see the
//! design before it is built.
//!
//! # Attach types for remote sandboxes and tailnets
//!
//! `fictionet attach` has four types now: `tun`, `tap`, `http_proxy` and
//! `socks5` (see [`attaching`](crate::attaching)). Two more are planned.
//! Each still hands the world plain IP packets, so world code does not
//! change.
//!
//! ## `wireguard`: a remote sandbox
//!
//! This type is for remote sandboxes that cannot run Docker inside them, on
//! machines you do not control. (Daytona and E2B sandboxes can run Docker,
//! and work now: see [Hosted sandboxes](crate::attaching#hosted-sandboxes).)
//! Attach runs next to the world, on a machine the sandbox can reach over
//! UDP, and acts as a WireGuard server:
//!
//! ```sh
//! fictionet attach --world unix:/run/fictionet/world.sock --name e2b-7 \
//!     --type wireguard --listen 0.0.0.0:51820 \
//!     --ip-addr 10.0.0.2/24 --gateway 10.0.0.1 --dns 10.0.0.1 \
//!     --no-ip-addr-v6 --no-gateway-v6 --no-dns-v6
//! ```
//!
//! From its flags, attach generates a WireGuard config for the sandbox:
//!
//! ```ini
//! [Interface]
//! PrivateKey = <made by attach>
//! Address = 10.0.0.2/24
//! DNS = 10.0.0.1
//!
//! [Peer]
//! PublicKey = <attach's key>
//! Endpoint = attach.example.com:51820
//! AllowedIPs = 0.0.0.0/0
//! ```
//!
//! The harness copies the config into the sandbox, which runs
//! `wg-quick up ./fictionet.conf`. The sandbox then has a WireGuard
//! interface named `fictionet`, after the config file, and a default route
//! through it. `wg-quick` sets the address from the `Address =` line. It
//! hands the `DNS =` servers to the sandbox's `resolvconf` program, which
//! writes `resolv.conf`, so a sandbox image without `resolvconf` needs it
//! installed.
//!
#![doc = include_str!("../docs/diagrams/attach-wireguard.svg")]
//!
//! ## `tailscale`: a sandbox on a tailnet
//!
//! For a sandbox that is already on a tailnet, a private network run by
//! [Tailscale](https://tailscale.com/). The tailnet assigns the
//! sandbox its address. Its DNS depends on how Tailscale and the sandbox's
//! operating system are set up: `tailscaled` may write `resolv.conf`
//! itself, hand the servers to `systemd-resolved` or NetworkManager, or
//! leave DNS alone when the sandbox does not accept the tailnet's DNS
//! settings. Attach sets neither, so this type will not take the address
//! and DNS flags. How the sandbox's packets reach attach is still to be
//! designed.
//!
//! # Remote attach: a TLS transport
//!
//! Attach and the world talk over a Unix socket on one machine (see
//! [`proto`](crate::proto)). A TLS transport will let one world serve
//! sandboxes on other machines, and let several Inspect services on
//! Kubernetes share one world. `fictionet attach --world tls:...` is the
//! planned form.
//!
//! **Framing.** A TLS stream has no message boundaries, so each message goes
//! on it as a 4-byte length, then the message. The length counts the whole
//! message, kind byte included. A length over 65,536, the limit for every
//! message, closes the connection.
//!
//! ```text
//! ┌──────────┬──────┬───────────────────────┐
//! │ length   │ kind │ body                  │
//! └──────────┴──────┴───────────────────────┘
//!   4 bytes  └─── the message, at most ─────┘
//!                 65,536 bytes
//! ```
//!
//! **A token, sent first.** The side that dialed sends an `auth` message
//! (kind 0) with a token, before `hello`. The other side closes the
//! connection if the token is wrong. Each token grants one name, so the
//! world refuses a `hello` for any other name. One token per attachment is
//! best: then a token only lets its holder attach under one name, even if
//! the agent reads it.
//!
//! ```text
//! attach                                    world
//!    │                                        │
//! 1  │ ── auth: the token ──────────────────▶ │  when attach dialed
//!    │ ◀────────────────── auth: the token ── │  when the world dialed
//! 2  │ ── hello ────────────────────────────▶ │  as on the Unix socket
//!    │ ◀─────────────────────────── accept ── │  (1 and 2 within 10 seconds)
//! 3  │ ◀══════════════ packet ══════════════▶ │
//! ```
//!
//! **Either side can dial.**
//!
//! - *The sandbox dials the world.* The sandbox, or a sidecar next to it,
//!   needs to reach the world's address. Attach checks the world's
//!   certificate, then sends the token:
//!
//!   ```text
//!   fictionet attach --world tls:world.example.com:7000 \
//!       --token-file /run/secrets/fictionet-agent --name agent --type tun
//!   ```
//!
//! - *The world dials the sandbox.* This is for a sandbox that cannot reach
//!   out at all. Attach listens on a port, and the provider's tunnel
//!   carries the connection to it. Behind a provider that ends TLS itself,
//!   such as Modal's `encrypted_ports`, attach gets a plain stream and
//!   listens with `tcp:`. Otherwise it listens with `tls:` and its own
//!   certificate. The world sends the token, so a stranger who finds the
//!   tunnel cannot pose as the world. When the world dialed, it also
//!   refuses a name other than the one it dialed for.
//!
//!   ```text
//!   fictionet attach --accept tcp:0.0.0.0:9000 \
//!       --token-file /run/secrets/fictionet-agent --name agent --type tun
//!   ```
//!
//! **Attach must run outside the namespace it captures.** Inside, its own
//! connection to the world would be routed into the `tun` device it feeds,
//! a loop. So it runs on the host, or in a container with a network
//! namespace of its own. With `--netns`, attach opens its connection to the
//! world before it enters the sandbox's namespace, because a socket stays
//! in the namespace it was made in. A Kubernetes sidecar is not outside:
//! every container of a pod shares the pod's network namespace. There, and
//! wherever attach must run inside, it has to keep one route to the world
//! off `tun0`. That is either a host route to the world's address through
//! the pod's own link, or a mark on its socket and a policy route for that
//! mark, as WireGuard does. (The Unix socket has no such loop, because it
//! is a file, not a network address.)
//!
//! **Dead links.** A remote connection uses TCP keepalive, so a link that
//! dies without closing is noticed within a minute. The attachment then
//! reads [`RecvError::Closed`](crate::RecvError::Closed) and its name is
//! free again. Until then, a new `hello` for that name is refused.
//!
//! **Observers.** [Observer sessions](crate::proto#observer-sessions) are
//! messages like any other, so a remote connection will carry them too,
//! and `fictionet dashboard` will be able to watch a world on another
//! machine.
//!
//! ## Writing to a stream
//!
//! On the Unix socket, each message is one datagram. The socket takes all
//! of it or none of it, so a full socket can only drop whole packets.
//!
//! A TCP stream is different: it is one long run of bytes, with no edges
//! between messages. That is why each message carries its length. The
//! receiver reads 4 bytes as a length, then that many bytes as the message,
//! then the next length, and so on. This only works if every byte of every
//! message arrives.
//!
//! A stream can take part of a message and then be full. Say a 1,500-byte
//! packet is being written. Its message is 1,501 bytes (the kind byte and
//! the packet), so its length says 1,501. The stream has room for the
//! length and 750 bytes of the message. If the writer gave up on the other
//! 751, the receiver would still expect them. It would take the first 751
//! bytes of whatever came next as the end of this message, and then read
//! bytes from the middle of a packet as a length. Every message after that
//! would be misread.
//!
#![doc = include_str!("../docs/diagrams/stream-writer.svg")]
//!
//! So each side keeps one writer per remote connection, with three rules:
//!
//! 1. **Finish what was started.** A message that went out in part is
//!    finished first, as soon as the stream has room, even if nothing new
//!    is sent.
//! 2. **Keep a short queue of whole packets** behind it, to send when the
//!    stream has room.
//! 3. **When the queue is full, drop the new packet.** None of its bytes
//!    went out, so the receiver never knows it existed. The sandbox's TCP
//!    sees a lost packet, as on any real network, and sends the data again.
//!
//! The queue is short because every packet in it waits for all the packets
//! ahead of it. On a slow link, a long queue would add seconds of delay to
//! every packet, including the world's own deliberate delays. A short queue
//! keeps the added delay small and turns overload into loss, which TCP
//! handles.
//!
//! A TLS stream runs over TCP, so the sandbox's TCP runs inside another
//! TCP. One lost segment on the outer link holds up every packet behind it
//! until it is sent again. The writer cannot remove delay that is already
//! in the TCP and TLS buffers below it.
//!
//! # DHCP and router advertisements in attach
//!
//! With `tun`, attach needs every address setting as a flag (see
//! [Addresses](crate::attaching#addresses)). The plan is that a setting
//! left out comes from the world: IPv4 by DHCP, IPv6 by router
//! advertisements. (A VM attached with `tap` runs its own DHCP client
//! already. See [its addresses](crate::attaching#the-vms-addresses).)
//! Attach will send a DHCP request or an IPv6 router
//! solicitation into the world as ordinary packets, and the world will
//! answer with stdlib code, like any other packets.
//! [`Sites`](crate::stdlib::web::Sites) already answers DHCP. Attach will
//! wait for the answers before it writes its ready file, and renew the
//! lease while it runs.
//!
//! Attach's DHCP client will share code with the stdlib's DHCP server. That
//! code is "sans-io": it works out what to send and what an answer means,
//! and leaves the sending and receiving to its caller.
//!
//! # Hosted sandboxes without Docker
//!
//! Where a provider can block all egress but one address (E2B's
//! `allow_out`, Modal's `outbound_cidr_allowlist`, Daytona's
//! `networkAllowList` from tier 3), the proxy types need no Docker in the
//! sandbox. The world and attach run on a host of your own, attach listens
//! on a public address, and the sandbox gets the proxy variables and the
//! world's CA (see [What keeps the agent in](crate::attaching#what-keeps-the-agent-in)).
//! This has not been run on a provider. Two things to check for each one:
//! whether the sandbox can still reach the provider's own DNS server with
//! egress blocked, and whether it has a metadata address.
//!
//! Other things to measure on hosted sandboxes:
//!
//! - whether a Daytona tier 3 or 4 sandbox can cut its own egress after
//!   `docker compose up`;
//! - how much faster startup is with images in a registry, or baked into a
//!   Daytona snapshot or an E2B template (each sample now pulls Debian and
//!   runs `apt-get`);
//! - Daytona's VM sandboxes, and Modal's VM runtime through Harbor;
//! - many samples at once (five have been run).
//!
//! # `fictionet --world`
//!
//! A world is its own program (see [`running`](crate::running)). The
//! `fictionet` binary attaches sandboxes and observes worlds, with the
//! commands `attach`, `ready`, `wait-blocked`, `observe` and `dashboard`,
//! but does not run one. `fictionet --world` will start a world, written in Rust or Python,
//! and pass it its arguments:
//!
//! ```text
//! fictionet --world <world> --listen unix:/run/fictionet/world.sock \
//!     --args --ca /etc/fictionet/ca.pem --date 2019-03-14
//! ```
//!
//! Everything after `--args` reaches the world as `args`. This is how a
//! world gets its configuration: paths to certificates, data files, the
//! date, or anything else it needs. On Ctrl-C it drops the `run` future,
//! which stops every task immediately.
//!
//! # Python worlds
//!
//! A Python world will also run in one process. Fictionet will be embedded
//! in Python, and asyncio's ordinary event loop will poll
//! [`run`](crate::run), with the helper threads waking it through
//! `call_soon_threadsafe`. Any asyncio library will then work inside a
//! world.
//!
//! # The lab
//!
//! The lab will be a second way to run a world, next to
//! [`run`](crate::run): `fictionet::lab(seed, |fcx| world(..))`. The world
//! code stays the same. Only what stands behind [`Cx`](crate::Cx) changes.
//! Its design is still open, but these are its goals:
//!
//! - **Time is a number.** When every task is waiting, time jumps to the
//!   earliest deadline. A test of a minute of traffic then takes
//!   microseconds and gives the same answer every time.
//! - **Randomness comes from the seed.**
//! - **A lab run is closed.** The test plays the sandboxes, through
//!   [`attachments`](crate::attachments), and fakes play other services.
//!   Fictionet's own I/O, such as [`listen`](crate::listen), refuses to run
//!   in the lab. Fictionet cannot stop world code from using `std::net` or
//!   other real I/O, so keeping the rest of a lab world closed is up to its
//!   author.
//! - **The test runs inside the lab too.** The code that plays the
//!   sandboxes is scheduled with the world. Otherwise time could jump past
//!   a timeout before the test had its turn.
//!
//! The stdlib's own tests need the lab. "A 1 Mbit/s link with a 10-packet
//! queue drops the 11th packet of a burst" is exact in the lab, and flaky
//! in real time.
//!
//! ## Repeatability
//!
//! A lab run with the same seed, the same world and the same inputs will
//! make the same decisions at the same times. The same packets will be
//! delayed, dropped or answered, in the same order, at the same lab
//! instants, and every `fcx.random_*` call will return the same number.
//!
//! It will not promise the same bytes. Anything that draws randomness from
//! the operating system instead of `fcx` differs from run to run. The main
//! case is TLS key exchange: see
//! [`tls::config_builder`](crate::stdlib::tls::config_builder).
