//! How each attach type becomes IP packets.
//!
//! A world only ever sees IP packets. Each sandbox reaches it as an
//! [`Attachment`](crate::Attachment), an [`Interface`](crate::Interface)
//! that carries IPv4 and IPv6 packets and nothing else. But a sandbox does
//! not always speak in IP packets. A network namespace does, through a TUN
//! device. A virtual machine sends Ethernet frames. A program behind a
//! proxy sends a `CONNECT` request and then a stream of bytes. Each
//! `fictionet attach` type turns what its sandbox sends into IP packets for
//! the world, and turns the world's packets back into what the sandbox
//! expects. This page calls that step *lowering*.
//!
//! Read this page when you want to know exactly what the world receives
//! from a sandbox, and what it does not: which TCP options a world's site
//! sees, whether ARP or DHCP ever reach world code, why `ping` works with
//! one type and not another. [`attaching`](crate::attaching) says how to
//! set each type up. The [relay protocol](crate::proto) describes the
//! messages on the world socket. This page sits between the two.
//!
#![doc = include_str!("../docs/diagrams/lowering.svg")]
//!
//! The function names on this page are those in the `fictionet` binary's
//! source, under `src/bin/fictionet/`, so you can follow each step in the
//! code.
//!
//! # The last hop is the same for every type
//!
//! Whatever the type, attach ends up with IP packets, and every IP packet
//! crosses the world socket the same way. Attach sends each one as one
//! `packet` message of the [relay protocol](crate::proto): a byte that
//! says the message is a packet, then the packet's bytes, as one datagram
//! on the Unix `SOCK_SEQPACKET` socket (`relay::unix::send_parts`
//! in the crate's source). On the world's side, the sandbox's
//! `Attachment` reads each datagram from the connection that
//! [`listen`](crate::listen) accepted, and returns the packet from
//! [`recv`](crate::InterfaceExt::recv). Packets from the world go back the same
//! way, one message each. There is no other kind of message after the
//! handshake, so DHCP, neighbor discovery and DNS travel as ordinary
//! packets when they travel at all.
//!
//! A message is at most 65,536 bytes, so a packet is at most 65,535
//! bytes. Attach's `hello`, the first message it sends, carries an MTU, which the world reads with
//! [`Attachment::mtu`](crate::Attachment::mtu). It is advice for UDP and
//! raw packet code in the world: neither attach nor the world socket
//! splits packets to fit it. Each type sets the MTU its own way:
//!
//! | Type | MTU in `hello` | What attach does with it |
//! |---|---|---|
//! | `tun` | `--mtu`, 1500 by default, at least 1280 | sets it as `tun0`'s MTU, so the sandbox's kernel sends no larger packet. Attach writes packets from the world to `tun0` without checking their size. |
//! | `tap` | `--mtu`, 1500 by default, at least 1280 | tells the VM in the DHCP lease (option 26) and the router advertisement, when attach hands out that family's address, and with `--vm tap:` sets it on attach's own TAP device. Attach drops frames from the VM longer than the MTU plus the 14-byte Ethernet header, and packets from the world longer than the MTU. |
//! | `http_proxy`, `socks5` | always 1500 | nothing to set: attach's own TCP sends packets of at most 1,500 bytes. `--mtu` is refused. |
//!
//! When the socket is full, the types differ in one way. Packets from the
//! world wait in a queue inside the world, with a budget of 32 MiB (see
//! [`Interface::send`](crate::Interface::send)). Packets toward the world
//! from `tun` and `tap` are dropped when the socket is full, as a full
//! network card queue drops them, and attach counts them and prints the
//! count when it ends normally. The proxy types queue them instead,
//! because a packet lost inside attach's own TCP can cost a retransmit
//! timeout of a second or more. Both queues count each packet's length
//! plus 64 bytes against their 32 MiB budget, and drop new packets past
//! it.
//!
//! [`listen`](crate::listen) reads the attach type from `hello` only to
//! tell an [observer](crate::observe), such as the dashboard, from a
//! sandbox. World code is never told the type. It
//! can only guess it from [`Attachment::mtu`](crate::Attachment::mtu),
//! which is always 1500 for the proxy types, and from what the packets
//! look like, which the sections below describe.
//!
//! # `tun`: the kernel's packets, as they are
//!
//! **What the sandbox sends.** A `tun` sandbox is a network namespace in
//! which attach makes a TUN device, usually `tun0`, with the default
//! routes through it. (Attach can also take other links down first, with
//! `--down-link`: see [How `tun` works](crate::attaching#how-tun-works).)
//! Programs in the sandbox use ordinary sockets. The sandbox's own kernel
//! runs TCP, UDP and ICMP, the C library's resolver sends DNS queries
//! over UDP, and the kernel routes every packet bound off the machine out
//! of `tun0`, as long as the namespace has no other way out (see
//! [How `tun` works](crate::attaching#how-tun-works)).
//!
//! **Where attach picks it up.** `open_tun` opens `/dev/net/tun` and makes
//! the device with `TUNSETIFF`, with the flags `IFF_TUN` and `IFF_NO_PI`.
//! `IFF_TUN` makes it a layer-3 device: it carries IP packets with no
//! Ethernet header, so there are no MAC addresses, no ARP, and no neighbor
//! solicitations to find the gateway's MAC. `IFF_NO_PI` leaves out the 4-byte header Linux would
//! otherwise put in front of each packet. Attach turns on no offloads, so
//! the kernel finishes every checksum and splits large TCP segments before
//! it hands a packet over. `configure` then sets the MTU, addresses and
//! default routes over netlink.
//!
//! **The lowering.** There is none. `relay_packets` waits on the tun file
//! descriptor and the world socket with `poll`. Each `read` from the tun
//! descriptor returns exactly one IP packet, and attach sends it as one
//! `packet` message, byte for byte. It moves at most 64 packets one way
//! before it gives the other way a turn.
//!
//! **The way back.** Each `packet` message from the world is one `write`
//! to the tun descriptor. The kernel takes it as a packet that arrived on
//! `tun0`, and delivers it to the program's socket, answers it, or drops
//! it, as it would for any network card. The kernel refuses a write that
//! is not IPv4 or IPv6, and attach counts that packet as dropped.
//!
//! **What the world sees.** Exactly what the sandbox's kernel sent: its
//! TCP options and window, its DNS queries (both A and AAAA, from the
//! resolver's own ports), its ICMP, its UDP, its IPv6 router solicitations
//! and multicast listener reports, and anything a program with raw sockets
//! builds. The world's answers reach the kernel unchanged, so a TCP reset,
//! an ICMP "host unreachable" or a dropped packet has the same effect as
//! on a real network.
//!
//! # `tap`: Ethernet frames, with the Ethernet taken off
//!
//! The address flags (`--ip-addr`, `--gateway`, `--dns` and their IPv6
//! forms) decide some of what happens below. [The VM's
//! addresses](crate::attaching#the-vms-addresses) explains them.
//!
//! **What the sandbox sends.** A VM's kernel has an Ethernet card, such as
//! a virtio-net card under QEMU. It sends Ethernet frames: IP packets with
//! a 14-byte header of destination MAC, source MAC and EtherType in front,
//! and link-local protocols that exist only on an Ethernet link, such as
//! ARP.
//!
//! **Where attach picks it up.** There are two ways, picked with `--vm`.
//!
//! - **`--vm qemu:<path>`.** QEMU's `-netdev stream` backend writes the
//!   card's frames to a Unix stream socket. Attach first takes an exclusive
//!   `flock` on `<path>.lock` (`lock_path`), so one attach at a time owns
//!   the path, then listens on the socket (`listen` in `tap.rs`, mode
//!   0600) and accepts one connection. A stream
//!   has no message boundaries, so QEMU puts a 4-byte big-endian length in
//!   front of each frame. `Decoder` splits the stream back into frames,
//!   and treats a length over 69,632 bytes as a broken stream, which ends
//!   attach with an error. Frames to the VM go through an `Outbox` that adds the same
//!   length, holds at most 4 MiB, and drops a frame that does not fit.
//! - **`--vm tap:<name>`.** Firecracker, Cloud Hypervisor and QEMU's
//!   `-netdev tap` hold the file side of a TAP device, and a second
//!   program that opens it gets `EBUSY`. Attach first binds an abstract
//!   Unix socket named after the VM device's index (`lock_device`), so one
//!   attach at a time owns the device. Then `open_tap` makes a second TAP
//!   device for attach, named `<name>-fn` (or `fntap0` and so on, when
//!   that name would be longer than 15 bytes), with `IFF_TAP` and
//!   `IFF_NO_PI` and no offloads. `Mirror::set_up` sets the VM's device down,
//!   turns IPv6 off on both devices, so the namespace adds no link-local
//!   address of its own, and brings attach's device up. It adds an ingress
//!   qdisc to each with a `matchall` filter and a `mirred` action that
//!   redirects every frame out of the other device, and brings the VM's
//!   device up last. While it is down, the kernel refuses the VM program's
//!   writes with `EIO`, so no frame reaches the namespace's IP stack before
//!   the redirect is in place. A frame
//!   the VM writes arrives on `<name>`, leaves through attach's device,
//!   and attach reads it there, one frame per `read`. On the way, the kernel
//!   finishes any checksums the VM program left to an offload, and splits
//!   large segments into frames that fit the MTU.
//!
//! **The lowering.** `Link::frame_from_vm` decides what happens to each
//! frame, with no I/O of its own. It reads the header, and drops a frame
//! that is shorter than one, longer than the header plus `--mtu`, sent
//! from a broadcast, multicast or zero MAC, or addressed to a unicast MAC
//! other than attach's. It learns the VM's MAC from the first frame, and
//! drops frames from any other MAC after that. Then it looks at the
//! EtherType:
//!
//! - **ARP.** `ether::arp_reply` answers every request with attach's own
//!   MAC, `02:66:6e:00:00:01`, whatever address is asked for, as a proxy
//!   ARP router does. It stays quiet for ARP probes, gratuitous ARP, and
//!   the address attach handed the VM, so the VM never sees its own
//!   address as taken. ARP never reaches the world.
//! - **IPv4.** `ether::ip_packet` takes the IP packet out of the frame,
//!   without the padding Ethernet adds to short frames. It checks the
//!   version and that the lengths in the header fit the frame, but not
//!   the checksum. `ether::upper` then reads the transport, as described
//!   below, and drops a packet it cannot read. A DHCP request (UDP to port 67) is answered,
//!   passed on or dropped, as the table below says. Other packets from
//!   `0.0.0.0` stay on the link, unless the IPv4 address flags were left
//!   out. When attach handed out the address, packets from any other
//!   source address are dropped. The rest go to the world.
//! - **IPv6.** `ether::upper` reads the transport past any extension
//!   headers, and drops a packet it cannot read. A neighbor solicitation gets a neighbor advertisement from
//!   `ether::neighbor_advert`, with attach's MAC and the router flag set,
//!   for the same reason ARP does. It stays quiet for duplicate address
//!   detection (source `::`), for a multicast target or the address attach
//!   handed the VM, and for a solicitation that is not valid. No neighbor
//!   solicitation reaches the world. Router advertisements, neighbor
//!   advertisements and redirects from the VM are dropped. Router
//!   solicitations and DHCPv6 requests (UDP to port 547) are handled as
//!   the table below says. Packets from `::` or a link-local address stay
//!   on the link, unless the IPv6 address flags were left out. When attach
//!   handed out the address, packets from any other source are dropped.
//!   The rest go to the world.
//! - **Anything else,** such as VLAN-tagged frames or LLDP, is dropped.
//!
//! `ether::upper` finds the transport with
//! [`ip::Header::check`](crate::stdlib::ip::Header::check), the parser that
//! [`ip::split_protocols`](crate::stdlib::ip::split_protocols) uses. So
//! attach walks the same IPv6 extension headers as the world's stack
//! (hop-by-hop, routing, destination options, authentication and
//! fragment), with no limit on how many. A packet whose
//! headers run past its end, whose UDP header is cut short or whose UDP
//! length does not fit, or whose ICMPv6 header is cut short, is dropped.
//! Attach does not put fragments back together. The transport header is
//! in the first fragment, so attach reads it there. It drops neighbor
//! discovery in a fragment, which RFC 6980 forbids, and never answers a
//! fragmented DHCP or DHCPv6 request. When attach answers or drops DHCP,
//! it drops the request's first fragment too, so the world cannot put the
//! request back together. Every other fragment is checked by its source
//! address like any other packet, and goes to the world.
//!
//! What happens to DHCP and router solicitations depends on the address
//! flags, one family at a time:
//!
//! | Flags | DHCP (IPv4), router solicitations and DHCPv6 (IPv6) | Other packets |
//! |---|---|---|
//! | `--ip-addr` (or `--ip-addr-v6`) given | attach answers: `addresses::dhcp4`, or `addresses::router_advert` and `addresses::dhcp6`, with the address, gateway, DNS server and MTU from the flags | passed to the world only from the address attach handed out |
//! | all three of the family left out | passed to the world as ordinary packets; DHCP and DHCPv6 fragmented or not, router solicitations only whole | passed to the world, including those from `0.0.0.0`, `::` and link-local addresses |
//! | `--no-ip-addr` (or `--no-ip-addr-v6`) | dropped | passed to the world, except those from `0.0.0.0`, `::` and link-local addresses |
//!
//! When attach hands out IPv6, it also sends router advertisements without
//! being asked: one as soon as it starts relaying, and then one every 10
//! minutes. With a gateway, they make attach's link-local address the VM's
//! default router for 30 minutes, so the VM never loses its route. With
//! `--no-gateway-v6`, the router lifetime is 0.
//!
//! **Why attach answers some questions itself.** An `Attachment` carries IP
//! packets, so the Ethernet link ends at attach. ARP and neighbor
//! discovery ask "which MAC has this address?", a question about that
//! link, so only attach can answer it. It answers for every address other
//! than the VM's own, so
//! every packet the VM sends reaches attach, and the world decides what is
//! really there, as it does for `tun`. DHCP is different: it runs over UDP
//! and IP, so it can cross into the world. Attach answers it locally when
//! you give it the addresses, so that a world needs no DHCP server and the
//! flags mean the same as for `tun`. Leave a family's flags out, and the
//! VM's DHCP goes to the world instead.
//! [`Sites`](crate::stdlib::web::Sites) runs a DHCP server for IPv4, but
//! sends no router advertisements and runs no DHCPv6. With `Sites`, a VM
//! gets an IPv6 address from attach's flags, or sets one itself.
//!
//! **The way back.** `Link::to_vm` drops a packet from the world that is
//! longer than `--mtu` or is not IPv4 or IPv6. For the rest, it builds an
//! Ethernet header. The source is attach's MAC. The destination is the
//! VM's MAC, or broadcast for `255.255.255.255` or while the VM's MAC is
//! not known yet, or the matching multicast MAC (`01:00:5e:...` or
//! `33:33:...`) for a multicast address (`ether::destination`). The
//! EtherType comes from the packet's version. The header and the packet
//! go to the VM as one frame: through the `Outbox` to QEMU's socket, or
//! with one `writev` to attach's TAP device, which the redirect passes to
//! the VM's.
//!
//! **What the world sees.** The VM kernel's own IP packets, byte for byte,
//! without the Ethernet header or padding: its TCP options and window, its
//! DNS queries, its ICMP and UDP. Ethernet headers never reach the world,
//! and neither do ARP, neighbor solicitations and advertisements, VLAN
//! tags or any other link-layer protocol. DHCP and router solicitations
//! reach the world only when the family's address flags are left out, and
//! then a DHCP request carries the VM's MAC inside it, as DHCP always
//! does.
//!
//! # `http_proxy` and `socks5`: a TCP/IP stack inside attach
//!
//! **What the sandbox sends.** Nothing at the IP level. The sandbox has no
//! device of Fictionet's. A program in it, told by `HTTPS_PROXY` or
//! `ALL_PROXY`, opens a TCP connection to attach's `--listen` port, over
//! whatever network joins the two, and asks for a destination by name:
//! `CONNECT example.test:443` for the HTTP proxy, or a SOCKS5 `CONNECT`
//! request for the SOCKS5 proxy. Then it sends the bytes it wants carried,
//! such as a TLS handshake. That TCP connection belongs to the host's
//! kernel and the sandbox's, not to the world.
//!
//! **Where attach picks it up.** Attach accepts the connection on tokio,
//! reads the request and checks the token: `http::serve` does this for
//! `http_proxy`, and `socks5::serve` for `socks5`. Each gives a host, as a
//! name or an IPv4 address, and a port.
//!
//! **The lowering.** Attach runs a TCP/IP stack of its own, the same one
//! worlds use. `Stack::new` takes the world socket as an `Interface`
//! (`proxy/link.rs`), splits it with
//! [`ip::split_protocols`](crate::stdlib::ip::split_protocols), and starts
//! [`tcp::endpoint`](crate::stdlib::tcp::endpoint) and
//! [`udp::endpoint`](crate::stdlib::udp::endpoint) at `--ip-addr`. To the
//! world, that address is the sandbox. For each request,
//! `Stack::connect` makes two kinds of packets:
//!
//! 1. **A DNS lookup in the world.** A name is looked up with an `A` query
//!    to `--dns` on port 53, from `--ip-addr` and a random UDP port from
//!    49152 up (`Stack::lookup`). The query goes out immediately, again 1
//!    second later and again 2 seconds after that, and attach gives up 7
//!    seconds after the first. The first `A` record of the answer is used,
//!    and cached for its TTL, at most 60 seconds, so a name in the cache
//!    sends no query. A name the world does not know is remembered for 5
//!    seconds. While a lookup is on its way, other requests for the same
//!    name wait for its answer instead of sending their own query. An IPv4
//!    address in the request skips the lookup. There is no `AAAA` query,
//!    and an IPv6 address is refused: attach's stack is IPv4 only. A name the world does not know never becomes a
//!    connection. The client gets `502` or SOCKS5 reply 4.
//! 2. **A TCP connection into the world.** `tcp::Endpoint::connect` opens
//!    a connection from `--ip-addr` and an ephemeral port to the address
//!    and port. If no answer comes in 10 seconds, the client is told it
//!    timed out. An ICMP "destination unreachable" about the connection
//!    ends the wait immediately: the TCP endpoint ignores ICMP, so a small
//!    wrapper in front of it, `Watch`, picks those messages out.
//!
//! Once the connection is open, the HTTP proxy answers
//! `200 Connection established` and the SOCKS5 proxy answers reply 0.
//! Then `pump::tunnel` copies bytes both ways, in pieces of up to 64 KiB,
//! between the client's socket and the
//! [`TcpConnection`](crate::stdlib::tcp::TcpConnection). A side that
//! closes its sending half closes the other's too. Attach's stack decides
//! how those bytes become segments: up to 1,460 bytes each, with a 256 KiB
//! window (a window scale shift of 3, which Wireshark and the observer
//! show as `WS=8`), as [`tcp::endpoint`](crate::stdlib::tcp::endpoint)
//! describes.
//!
//! The HTTP proxy also takes plain-HTTP requests in absolute form
//! (`GET http://host/path`). It opens the connection the same way, then
//! sends the request in origin form (`GET /path`), and with
//! `Connection: close` (`http::forward_head`). It leaves out
//! `Proxy-Authorization` and the other proxy fields, the hop-by-hop fields
//! (`Connection`, `Keep-Alive`, `TE`, `Trailer`, `Upgrade`), and any field
//! that `Connection` names. It rewrites the answer's head the same way,
//! and passes `1xx` answers other than `101` on as they are.
//!
//! **The way back.** Packets from the world come out of the link's
//! `poll_recv`, one per `packet` message. The split sends TCP to the TCP
//! endpoint, which puts the bytes in order and acknowledges them, and the
//! tunnel writes them to the client's socket. The client reads them as an
//! ordinary byte stream. It never sees the world's packets, only their
//! data.
//!
//! **What the world sees.** Attach's packets, not the sandbox's. The TCP
//! handshake, options, window and retransmits are attach's: the stdlib's
//! TCP, on smoltcp. The bytes inside the connection are the client's own:
//! a TLS `ClientHello` is the one curl sent, byte for byte, and TLS stays
//! end to end between the client and the world's site. A plain-HTTP
//! request through the HTTP proxy is rewritten, as above. The world sees
//! an `A` query for each name that is not in attach's cache, and no other
//! UDP or ICMP from the sandbox.
//! In the other direction:
//!
//! - a reset or an ICMP "destination unreachable" that answers the SYN
//!   becomes a proxy answer (an HTTP status or a SOCKS5 reply), not the
//!   same TCP event. A reset after that ends the tunnel, and the client's
//!   connection closes;
//! - a world machine that connects to `--ip-addr` gets a RST from attach's
//!   TCP endpoint, because nothing listens there;
//! - UDP to `--ip-addr` gets ICMP "port unreachable" from attach's UDP
//!   endpoint, unless it goes to the port of a DNS query that is waiting.
//!   There it is read, and ignored unless it is that query's answer;
//! - a ping to `--ip-addr` gets no answer: the stack drops ICMP.
//!
//! # One request, traced through each type
//!
//! These traces follow `curl https://example.test/` from the agent's
//! program to [`Sites`](crate::stdlib::web::Sites) and back, once for
//! each type. The world is the `web_world` example from
//! [`getting_started`](crate::getting_started). The packet lists are what
//! the world saw on the sandbox's `Attachment`, from
//! `fictionet observe ... packets <link>` (see [`observe`](crate::observe)),
//! cut to their source, destination and summary. TLS 1.3 is shown
//! decrypted, because the observer had the world's keys.
//!
//! ## `tun`
//!
//! The sandbox is the network namespace from
//! [`getting_started`](crate::getting_started), with IPv4 and IPv6:
//!
//! ```text
//! $ sudo ip netns exec agent curl -sS --cacert /run/fictionet/ca.pem https://example.test/
//! hello from https example.test 443 over HTTP/2.0
//! ```
//!
//! 1. curl asks glibc for the name. glibc reads the `resolv.conf` that
//!    attach wrote and sends an `A` and an `AAAA` query to `10.0.0.1`. The
//!    sandbox's kernel routes both out of `tun0`.
//! 2. `relay_packets` reads each query from the tun descriptor and sends
//!    it to the world unchanged. `Sites` answers both, and attach writes
//!    the answers to the tun descriptor.
//! 3. curl prefers IPv6 and connects to `2001:db8:113::10`. The SYN carries
//!    the sandbox kernel's options: MSS 1440, timestamps, `WS=1024`.
//! 4. The TLS handshake and the HTTP/2 request go over that connection,
//!    and the answer comes back the same way. curl closes the connection.
//!
//! The world saw 24 packets:
//!
//! ```text
//! 10.0.0.2:39109 → 10.0.0.1:53                  DNS Standard query A example.test
//! 10.0.0.2:40420 → 10.0.0.1:53                  DNS Standard query AAAA example.test
//! 10.0.0.1:53 → 10.0.0.2:39109                  DNS Standard query response A 203.0.113.10
//! 10.0.0.1:53 → 10.0.0.2:40420                  DNS Standard query response AAAA 2001:db8:113::10
//! [2001:db8::2]:40512 → [2001:db8:113::10]:443  TCP [SYN] Win=64800 MSS=1440 SACK_PERM TSval=1058637221 TSecr=0 WS=1024
//! [2001:db8:113::10]:443 → [2001:db8::2]:40512  TCP [SYN, ACK] Win=65535 MSS=1440 WS=8 SACK_PERM
//! [2001:db8::2]:40512 → [2001:db8:113::10]:443  TCP [ACK]
//! [2001:db8::2]:40512 → [2001:db8:113::10]:443  TCP [ACK] Len=1440, the first part of the Client Hello
//! [2001:db8::2]:40512 → [2001:db8:113::10]:443  TLS Client Hello (example.test)
//! [2001:db8:113::10]:443 → [2001:db8::2]:40512  TCP [ACK]
//! [2001:db8:113::10]:443 → [2001:db8::2]:40512  TLSv1.3 Server Hello, ..., Finished
//! ...                                           10 more: the client's Finished, HTTP/2 SETTINGS,
//!                                               HEADERS GET / and 200, GOAWAY, the TLS alert
//! [2001:db8::2]:40512 → [2001:db8:113::10]:443  TCP [FIN, ACK]
//! [2001:db8::2]:40512 → [2001:db8:113::10]:443  TCP [FIN, ACK]
//! [2001:db8:113::10]:443 → [2001:db8::2]:40512  TCP [ACK]
//! ```
//!
//! ## `tap`
//!
//! The sandbox is a Debian 13 VM under QEMU, attached with
//! `--vm qemu:<path> --ip-addr 10.0.0.2/24 --gateway 10.0.0.1 --dns
//! 10.0.0.1 --no-ip-addr-v6`, as in
//! [`attaching`](crate::attaching#with-qemu-over-a-socket). The capture
//! ran from before QEMU started until it exited.
//!
//! 1. While the VM boots, its DHCP client broadcasts a DISCOVER.
//!    `frame_from_vm` answers it, and the REQUEST after it, with
//!    `addresses::dhcp4`. The world sees neither.
//! 2. Before it sends its first packet to `10.0.0.1`, the VM's kernel asks
//!    for the gateway's MAC with ARP. `ether::arp_reply` answers with
//!    `02:66:6e:00:00:01`. The world does not see this either. After the
//!    request, `ip neigh` in the VM showed `10.0.0.1 dev ens3 lladdr
//!    02:66:6e:00:00:01 REACHABLE`.
//! 3. curl's DNS queries leave the VM as Ethernet frames to that MAC.
//!    Attach takes the Ethernet header off and sends each IP packet to the
//!    world. The answers come back with a header added by `Link::to_vm`.
//! 4. The VM has no IPv6 route (attach was given `--no-ip-addr-v6`), so
//!    curl connects over IPv4. The SYN carries the VM kernel's options:
//!    MSS 1460, timestamps, `WS=128`.
//! 5. The rest is the same as for `tun`, one frame per packet.
//!
//! Attach printed:
//!
//! ```text
//! fictionet attach: agent attached; waiting for QEMU at .../vm.sock
//! fictionet attach: QEMU connected
//! fictionet attach: the VM's MAC is 52:54:00:12:34:56
//! fictionet attach: QEMU closed the connection; agent detached
//! ```
//!
//! The world saw 32 packets in the whole boot. Five came from the VM's
//! kernel on its own, before curl ran: two IGMP reports to `224.0.0.22`,
//! and three LLMNR announcements to `224.0.0.252`. They are ordinary
//! multicast IP packets, so they pass. Then came curl's request, 26
//! packets:
//!
//! ```text
//! 10.0.0.2:40799 → 10.0.0.1:53        DNS Standard query AAAA example.test
//! 10.0.0.2:55822 → 10.0.0.1:53        DNS Standard query A example.test
//! 10.0.0.1:53 → 10.0.0.2:40799        DNS Standard query response AAAA 2001:db8:113::10
//! 10.0.0.1:53 → 10.0.0.2:55822        DNS Standard query response A 203.0.113.10
//! 10.0.0.2:45062 → 203.0.113.10:443   TCP [SYN] Win=64240 MSS=1460 SACK_PERM TSval=2353440092 TSecr=0 WS=128
//! 203.0.113.10:443 → 10.0.0.2:45062   TCP [SYN, ACK] Win=65535 MSS=1460 WS=8 SACK_PERM
//! 10.0.0.2:45062 → 203.0.113.10:443   TCP [ACK]
//! 10.0.0.2:45062 → 203.0.113.10:443   TCP [ACK] Len=1460, the first part of the Client Hello
//! 10.0.0.2:45062 → 203.0.113.10:443   TLS Client Hello (example.test)
//! ...                                 17 more: TLS, HTTP/2, the close, and two RSTs from the VM
//! 10.0.0.2 → 224.0.0.22               IGMP, as the VM shut down
//! ```
//!
//! No ARP, no DHCP, no MAC address and no IPv6 packet appears. Whatever
//! IPv6 the VM sent came from its link-local address, which attach keeps
//! on the link.
//!
//! ## `http_proxy`
//!
//! Attach runs on the host as an HTTP proxy, as
//! [`attaching`](crate::attaching#running-the-proxy) shows, and curl uses
//! it. `$TOKEN` holds the contents of the token file:
//!
//! ```text
//! $ fictionet attach --world unix:/run/fictionet/world.sock --name agent --type http_proxy \
//!     --listen 127.0.0.1:8080 --token-file /run/fictionet/token --ip-addr 10.0.0.2 --dns 10.0.0.1
//! $ curl -sS --cacert /run/fictionet/ca.pem -x http://relay:$TOKEN@127.0.0.1:8080 https://example.test/
//! hello from https example.test 443 over HTTP/2.0
//! ```
//!
//! 1. curl does not look the name up. It connects to `127.0.0.1:8080` with
//!    the host's TCP, and sends `CONNECT example.test:443 HTTP/1.1` with
//!    the token in `Proxy-Authorization`.
//! 2. `http::serve` checks the token and calls `Stack::connect`. The stack
//!    sends one `A` query from `10.0.0.2` to `10.0.0.1`, and `Sites`
//!    answers `203.0.113.10`.
//! 3. The stack sends a SYN from `10.0.0.2` to `203.0.113.10:443`, with
//!    smoltcp's options: MSS 1460, `WS=8`, and no timestamps.
//!    `Sites` accepts.
//! 4. Attach answers curl `200 Connection established`. curl starts TLS
//!    inside the tunnel. `pump::tunnel` copies its bytes into the
//!    connection, and the stack cuts them into segments. The world's
//!    answers go back the same way.
//! 5. curl closes its connection to attach, and attach closes the one in
//!    the world.
//!
//! Attach printed one line for the request:
//!
//! ```text
//! fictionet attach: CONNECT example.test:443 (203.0.113.10) 200, 1905 bytes up, 1220 down, 0.002 s
//! ```
//!
//! The world saw 20 packets:
//!
//! ```text
//! 10.0.0.2:55599 → 10.0.0.1:53        DNS Standard query A example.test
//! 10.0.0.1:53 → 10.0.0.2:55599        DNS Standard query response A 203.0.113.10
//! 10.0.0.2:60748 → 203.0.113.10:443   TCP [SYN] Win=65535 MSS=1460 WS=8 SACK_PERM
//! 203.0.113.10:443 → 10.0.0.2:60748   TCP [SYN, ACK] Win=65535 MSS=1460 WS=8 SACK_PERM
//! 10.0.0.2:60748 → 203.0.113.10:443   TCP [ACK]
//! 10.0.0.2:60748 → 203.0.113.10:443   TCP [ACK] Len=1460, the first part of the Client Hello
//! 10.0.0.2:60748 → 203.0.113.10:443   TLS Client Hello (example.test)
//! ...                                 10 more: TLS, HTTP/2, GOAWAY, the TLS alert
//! 10.0.0.2:60748 → 203.0.113.10:443   TCP [ACK]
//! 10.0.0.2:60748 → 203.0.113.10:443   TCP [FIN, ACK]
//! 203.0.113.10:443 → 10.0.0.2:60748   TCP [ACK]
//! ```
//!
//! Compare it with the `tun` trace. There is one DNS query, not two. The
//! SYN has no timestamps and a different window. The `ClientHello` is
//! 1,572 bytes in both, because it is curl's own.
//!
//! ## `socks5`
//!
//! The same, with `--type socks5` and `curl -x socks5h://...`. The `h`
//! makes curl send the name to attach in the SOCKS5 request, so the
//! lookup happens in the world. `socks5::serve` reads the request and
//! calls the same `Stack::connect`, so the world saw the same packets: one
//! `A` query, then a TCP connection from `10.0.0.2` with the same options.
//! Attach printed:
//!
//! ```text
//! fictionet attach: socks5 CONNECT example.test:443 (203.0.113.10) reply 0, 1927 bytes up, 1219 down, 0.007 s
//! ```
//!
//! With `socks5://`, without the `h`, curl looks the name up itself, in
//! the sandbox, and sends attach an address. A proxy sandbox usually has
//! no DNS server that knows the world's names, so the request then fails
//! before it reaches attach.
//!
//! # What survives the lowering
//!
//! | | `tun` | `tap` | `http_proxy`, `socks5` |
//! |---|---|---|---|
//! | IP packets the world gets | the sandbox kernel's, byte for byte | the VM kernel's, byte for byte, without Ethernet | attach's, made by its own stack |
//! | TCP behavior the world sees | the sandbox kernel's | the VM kernel's | attach's (smoltcp): MSS 1460, `WS=8`, no timestamps |
//! | DNS the world sees | the sandbox's resolver: `A` and `AAAA` | the VM's resolver | attach's: `A` only, for names not in its cache |
//! | UDP and ICMP from the sandbox | yes | yes | no |
//! | IPv6 | with `--ip-addr-v6` | with `--ip-addr-v6`, or an address the VM sets itself | no |
//! | Ethernet headers, ARP, neighbor solicitations | none exist | answered or dropped by attach, never seen | none exist |
//! | DHCP | attach runs no DHCP client: it sets the addresses from flags | answered by attach, or passed to the world with the flags left out | none |
//! | Connections from the world into the sandbox | reach the sandbox's kernel | reach the VM's kernel | refused with a RST by attach |
//! | Bytes inside a TCP connection | the program's own | the program's own | the program's own, except that plain-HTTP request and answer heads are rewritten |
