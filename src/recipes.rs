//! Recipes: slow links, lost packets, packet captures and hijacked routes.
//!
//! Each recipe on this page is a complete world in the crate's
//! `examples/` directory, with the commands that run it and what they
//! printed when they were run. Read this page when you have a world of
//! websites running, as in [`getting_started`](crate::getting_started),
//! and want to change the network the agent sees.
//!
//! To change a protocol, copy its module file from `src/stdlib/` into your
//! crate, edit it, and plug it into [`Stream`](crate::stdlib::codec::Stream)
//! through the public codec traits. Keep its `fictionet::stdlib::...` imports.
//! `cargo run --example custom_protocol` reads a planted Modbus register
//! through a copied module. This example needs no network or root.
//!
//! # Putting something in front of every sandbox
//!
//! [`web::Sites::serve`](crate::stdlib::web::Sites::serve) takes the
//! world's [`Attachments`](crate::Attachments): every sandbox that attaches,
//! now or later. To slow down, limit or watch a sandbox's traffic, put a
//! piece of the network between each sandbox and `Sites`.
//! [`Attachments::map`](crate::Attachments::map) does this. It takes a
//! function, and returns a new `Attachments`. When the world takes a
//! sandbox from the new one, `map` calls the function with that sandbox,
//! and hands the world what the function returned:
//!
//! ```
//! # use fictionet::{Attachments, Cx, Result, stdlib::{self, web}, time::ms};
//! # fn site_for(_host: &str) -> Option<web::Site> { None }
//! # fn world(cx: Cx, attachments: Attachments) -> Result {
//! let far = attachments.map(&cx, |cx, sandbox| stdlib::delay(cx, ms(200), sandbox));
//! web::Sites::new(site_for).serve(&cx, far)?;
//! # Ok(())
//! # }
//! ```
//!
//! `Sites` then sees each sandbox through its delay. It does not know the
//! delay is there: each sandbox keeps its name, and `Sites` binds its
//! addresses and reports its events as usual.
//!
//! The function can return any [`Interface`](crate::Interface). The
//! stdlib has three that fit here:
//!
//! - [`stdlib::delay`](crate::stdlib::delay) holds every packet for a fixed
//!   time.
//! - [`stdlib::bottleneck`](crate::stdlib::bottleneck) limits the rate,
//!   with a queue that drops packets when it is full.
//! - [`stdlib::filter`](crate::stdlib::filter) calls your code with every
//!   packet. Your code can look at the packet, and can drop it.
//!
//! These nest: `bottleneck(cx, rate, queue, delay(cx, ms(40), sandbox))` is
//! a slow link that is also far away. `map` calls can be chained too, and
//! the first is closest to the sandbox. The function gets the sandbox
//! itself, so it can read [`name`](crate::Attachment::name) and give each
//! sandbox a different link.
//!
//! A world that needs more than one path per sandbox wires the network by
//! hand from [`pair`](crate::pair) and
//! [`route::router`](crate::stdlib::route::router). The last recipe does
//! that.
//!
//! # Running the recipes
//!
//! Each recipe runs like the world in
//! [`getting_started`](crate::getting_started), on one Linux machine, with
//! a network namespace named `agent` as the sandbox. Make the socket's
//! directory and the namespace once. The last two lines give the
//! namespace its own `nsswitch.conf`, which a host with `systemd-resolved`
//! needs, as [`getting_started`](crate::getting_started) explains:
//!
//! ```text
//! $ sudo mkdir -p /run/fictionet
//! $ sudo chown "$USER" /run/fictionet
//! $ sudo ip netns add agent
//! $ sudo ip -n agent link set lo up
//! $ sudo mkdir -p /etc/netns/agent
//! $ echo "hosts: files dns" | sudo tee /etc/netns/agent/nsswitch.conf
//! hosts: files dns
//! ```
//!
//! Start the recipe's world in one terminal, with the command the recipe
//! gives. Then attach the sandbox in a second terminal:
//!
//! ```text
//! $ cargo build --release --bin fictionet
//! $ sudo target/release/fictionet attach --world unix:/run/fictionet/world.sock --name agent --type tun \
//!     --netns /run/netns/agent \
//!     --ip-addr 10.0.0.2/24 --gateway 10.0.0.1 --dns 10.0.0.1 \
//!     --ip-addr-v6 2001:db8::2/64 --gateway-v6 2001:db8::1 --dns-v6 2001:db8::1
//! fictionet attach: agent attached as tun0
//! ```
//!
//! Run the recipe's commands in a third terminal. To move on to the next
//! recipe, stop attach and the world with Ctrl-C. When you are done,
//! remove the namespace with `sudo ip netns del agent && sudo rm -r
//! /etc/netns/agent`. The sites in these
//! worlds serve plain HTTP, so the commands need no certificates.
//!
//! # A delayed website
//!
//! This world puts a 200 ms delay in front of every sandbox, each way, so
//! every round trip takes 400 ms longer:
//!
#![doc = concat!("```rust,no_run\n", include_str!("../examples/delayed_sites.rs"), "```")]
//!
//! Start it:
//!
//! ```text
//! $ cargo run --release --example delayed_sites -- /run/fictionet/world.sock
//! listening on /run/fictionet/world.sock
//! ```
//!
//! curl's `-w` option prints its timings. Each one counts from the start
//! of the request:
//!
//! ```text
//! $ sudo ip netns exec agent curl -sS -w 'lookup %{time_namelookup}s, connected %{time_connect}s, done %{time_total}s\n' http://example.test/
//! hello from far away
//! lookup 0.409962s, connected 0.810479s, done 1.211329s
//! ```
//!
//! Each step took one round trip of 400 ms. The DNS lookup asked for the A
//! and AAAA records at the same time, so it took one round trip for both.
//! Then came the TCP handshake, then the request and its answer. `ping`
//! shows the same round trip to the gateway:
//!
//! ```text
//! $ sudo ip netns exec agent ping -c 2 10.0.0.1
//! PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.
//! 64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=400 ms
//! 64 bytes from 10.0.0.1: icmp_seq=2 ttl=64 time=403 ms
//!
//! --- 10.0.0.1 ping statistics ---
//! 2 packets transmitted, 2 received, 0% packet loss, time 1001ms
//! rtt min/avg/max/mdev = 400.403/401.647/402.891/1.244 ms
//! ```
//!
//! # A bandwidth-limited sandbox
//!
//! This world gives every sandbox a link of 8 Mbit/s, one megabyte a
//! second, each way. Each direction has a queue with room for 100 packets.
//! When packets arrive faster than the link sends them, they wait in the
//! queue, and when the queue is full, new packets are dropped.
//!
//! To show the drops, the world puts a [`filter`](crate::stdlib::filter)
//! on each side of the [`bottleneck`](crate::stdlib::bottleneck), and
//! counts the packets that pass each one. A packet that went in on one
//! side and never came out of the other was dropped by the queue. Once the
//! packets have stopped for a second, the world prints the counts:
//!
#![doc = concat!("```rust,no_run\n", include_str!("../examples/bottleneck_sites.rs"), "```")]
//!
//! Start it:
//!
//! ```text
//! $ cargo run --release --example bottleneck_sites -- /run/fictionet/world.sock
//! listening on /run/fictionet/world.sock
//! ```
//!
//! Download 4 MiB, and then upload 4 MiB:
//!
//! ```text
//! $ sudo ip netns exec agent curl -sS -o /dev/null -w 'down: %{size_download} bytes in %{time_total}s, %{speed_download} bytes/s\n' http://example.test/4mb
//! down: 4194304 bytes in 9.861790s, 425308 bytes/s
//! $ head -c 4194304 /dev/zero > 4mb.bin
//! $ sudo ip netns exec agent curl -sS --data-binary @4mb.bin -w 'up: %{size_upload} bytes in %{time_total}s, %{speed_upload} bytes/s\n' http://example.test/upload
//! got 4194304 bytes
//! up: 4194304 bytes in 4.402541s, 952701 bytes/s
//! ```
//!
//! The world printed one line after each transfer, with its totals since
//! the sandbox attached:
//!
//! ```text
//! agent: toward it 5428 packets, 156 dropped; from it 4563 packets, 0 dropped
//! agent: toward it 6971 packets, 156 dropped; from it 7512 packets, 6 dropped
//! ```
//!
//! The upload ran at 950 kB/s: the link's megabyte a second, less the
//! space that IP and TCP headers take. The sandbox's Linux TCP filled the
//! queue, lost 6 packets, and sent them again.
//!
//! The download lost 156 packets and ran at 425 kB/s. In this direction
//! the sender is the world's own TCP ([`tcp`](crate::stdlib::tcp)), which
//! uses Reno congestion control and recovers from a burst of drops more
//! slowly than Linux does.
//!
//! # Lost packets
//!
//! This world drops 5% of the packets in each direction, at random. The
//! [`filter`](crate::stdlib::filter) decides for each packet with
//! [`Cx::random_f64`](crate::Cx::random_f64):
//!
#![doc = concat!("```rust,no_run\n", include_str!("../examples/lossy_sites.rs"), "```")]
//!
//! Start it:
//!
//! ```text
//! $ cargo run --release --example lossy_sites -- /run/fictionet/world.sock
//! listening on /run/fictionet/world.sock
//! ```
//!
//! A ping and its reply each cross the link once, so about 1 ping in 10 is
//! lost (1 - 0.95 × 0.95 = 9.75%). TCP sends lost packets again, so curl
//! still gets its answer:
//!
//! ```text
//! $ sudo ip netns exec agent ping -q -c 1000 -i 0.002 10.0.0.1
//! PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.
//!
//! --- 10.0.0.1 ping statistics ---
//! 1000 packets transmitted, 887 received, 11.3% packet loss, time 2914ms
//! rtt min/avg/max/mdev = 0.008/0.066/0.837/0.048 ms
//! $ sudo ip netns exec agent curl -sS http://example.test/
//! hello over a lossy link
//! ```
//!
//! # Packet capture
//!
//! This world writes the packets between the sandboxes and `Sites` to a
//! pcap file. The [`filter`](crate::stdlib::filter) sees each packet and
//! passes it on. The file is written on a thread of its own: all of a
//! world's tasks share one thread, and a write to a file can block, so the
//! filter only hands each packet to a channel that never waits. The file
//! uses the link type for raw IP packets, so tools read IPv4 and IPv6 from
//! it directly.
//!
//! The filter never waits for the file, so the capture gives up packets
//! instead of slowing the network:
//!
//! - **The channel is full.** It holds 100,000 packets. If the writer falls
//!   that far behind, the filter still passes each new packet on, but leaves
//!   it out of the file. When the writer catches up, the world prints how
//!   many packets it left out so far.
//! - **A write fails,** for example because the disk is full. The world
//!   prints the error, and stops capturing. The network keeps running.
//! - **The world stops.** Packets still in the channel are lost, and so is
//!   the count of packets left out since the last line the world printed.
//!   The writer flushes its buffer to the file each time it catches up, and
//!   only what it flushed is sure to be there.
//!
//! So a quiet world log does not prove the file is complete. A capture
//! that must hold every packet needs a world that, before it exits, closes
//! the channel, waits for the writer thread to finish, and prints the final
//! count.
//!
#![doc = concat!("```rust,no_run\n", include_str!("../examples/capture_sites.rs"), "```")]
//!
//! Start it, and make a request:
//!
//! ```text
//! $ cargo run --release --example capture_sites -- /run/fictionet/world.sock /run/fictionet/agent.pcap
//! listening on /run/fictionet/world.sock, writing packets to /run/fictionet/agent.pcap
//! ```
//!
//! ```text
//! $ sudo ip netns exec agent curl -sS http://example.test/
//! hello, captured
//! ```
//!
//! Then open the file in Wireshark, or read it with `tshark`:
//!
//! ```text
//! $ tshark -r /run/fictionet/agent.pcap
//!     1   0.000000 fe80::16b2:3fa9:a146:cf9c → ff02::2      ICMPv6 48 Router Solicitation
//!     2   0.104195     10.0.0.2 → 10.0.0.1     DNS 58 Standard query 0x15e0 A example.test
//!     3   0.104199     10.0.0.2 → 10.0.0.1     DNS 58 Standard query 0x095e AAAA example.test
//!     4   0.104775     10.0.0.1 → 10.0.0.2     DNS 74 Standard query response 0x15e0 A example.test A 198.18.0.1
//!     5   0.104778     10.0.0.1 → 10.0.0.2     DNS 86 Standard query response 0x095e AAAA example.test AAAA 2001:2::1
//!     6   0.104854  2001:db8::2 → 2001:2::1    TCP 80 46286 → 80 [SYN] Seq=0 Win=64800 Len=0 MSS=1440 SACK_PERM TSval=828074653 TSecr=0 WS=1024
//!     7   0.104977    2001:2::1 → 2001:db8::2  TCP 72 80 → 46286 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1440 WS=8 SACK_PERM
//!     8   0.105005  2001:db8::2 → 2001:2::1    TCP 60 46286 → 80 [ACK] Seq=1 Ack=1 Win=65536 Len=0
//!     9   0.105018  2001:db8::2 → 2001:2::1    HTTP 136 GET / HTTP/1.1
//!    10   0.105519    2001:2::1 → 2001:db8::2  HTTP 193 HTTP/1.1 200 OK  (text/plain)
//!    11   0.105532  2001:db8::2 → 2001:2::1    TCP 60 46286 → 80 [ACK] Seq=77 Ack=134 Win=65536 Len=0
//!    12   0.105568  2001:db8::2 → 2001:2::1    TCP 60 46286 → 80 [FIN, ACK] Seq=77 Ack=134 Win=65536 Len=0
//!    13   0.105579    2001:2::1 → 2001:db8::2  TCP 60 80 → 46286 [ACK] Seq=134 Ack=78 Win=262144 Len=0
//!    14   0.105581    2001:2::1 → 2001:db8::2  TCP 60 80 → 46286 [FIN, ACK] Seq=134 Ack=78 Win=262144 Len=0
//!    15   0.105597  2001:db8::2 → 2001:2::1    TCP 60 46286 → 80 [ACK] Seq=78 Ack=135 Win=65536 Len=0
//! ```
//!
//! The first packet is the sandbox's kernel looking for an IPv6 router as
//! `tun0` came up. Then curl looked up `example.test`, got an IPv4 and an
//! IPv6 address, and fetched the page over IPv6.
//!
//! The capture shows the packets as the sandbox sent and received them.
//! To see them as they cross a [`delay`](crate::stdlib::delay) or a
//! [`bottleneck`](crate::stdlib::bottleneck), chain a second `map` after
//! the link, or wrap the link in a `filter` inside the same function.
//!
//! # A route that changes mid-run
//!
//! In a BGP hijack, a network announces a more specific route to someone
//! else's addresses, and traffic for those addresses follows it. This
//! world plays out the core of one. A [router](crate::stdlib::route::router)
//! sends the sandbox's traffic for `203.0.113.0/24` to a bank. The command
//! line gives a number of seconds. That long after the sandbox attaches,
//! the world adds a route for `203.0.113.10/32`, the bank's own address,
//! that leads to an impostor
//! machine. The longest matching prefix wins, so from then on every packet
//! for the bank, and so every new connection, reaches the impostor.
//!
//! The world is wired by hand, without `Sites`: one [`pair`](crate::pair)
//! for each machine, one router, and the
//! [`Router`](crate::stdlib::route::Router) handle that adds the route
//! later. The two machines are TCP endpoints that answer every HTTP
//! request with one line. The agent controls how many connections it
//! opens and how slowly it sends, so each machine serves at most 64
//! connections at once, and gives each one 10 seconds. It ends every
//! connection with
//! [`TcpConnection::reset`](crate::stdlib::tcp::TcpConnection::reset), so
//! a client cannot keep sockets open past the count. The time limit races
//! the answer against [`Cx::sleep`](crate::Cx::sleep) with `tokio::select!`,
//! which needs tokio's `macros` feature in your `Cargo.toml`:
//!
#![doc = concat!("```rust,no_run\n", include_str!("../examples/route_change.rs"), "```")]
//!
//! The world has IPv4 only, so attach the sandbox with `--no-ip-addr-v6
//! --no-gateway-v6 --no-dns-v6` in place of the three IPv6 flags (see
//! [Addresses](crate::attaching#addresses)). It runs
//! no DNS server either, so the sandbox uses the bank's address. Start the
//! world with a 10-second delay:
//!
//! ```text
//! $ cargo run --release --example route_change -- /run/fictionet/world.sock 10
//! listening on /run/fictionet/world.sock
//! ```
//!
//! Ask the bank for a page every 3 seconds:
//!
//! ```text
//! $ for i in 1 2 3 4 5; do sudo ip netns exec agent curl -sS -m 5 http://203.0.113.10/; sleep 3; done
//! the real bank
//! the real bank
//! the real bank
//! an impostor
//! an impostor
//! ```
//!
//! The world builds its network when the sandbox attaches, and changes the
//! route 10 seconds after that. It printed a line at each step:
//!
//! ```text
//! agent attached: 203.0.113.0/24 leads to the bank
//! 10 s later: 203.0.113.10/32 leads to the impostor
//! ```
//!
//! The Border eval in `examples/border` builds a full hijack on the same
//! idea: a BGP speaker the agent can query, `traceroute` hops that show the
//! longer path, and an impostor bank with its own certificate authority.
//!
//! # A subnet for a port scanner
//!
//! `examples/scan` is a five-host subnet that `nmap` scans from a sandbox:
//! four simulated machines and one real container, wired with a router and
//! [grouped](crate::Cx#groups) for the dashboard. Its
//! [README](https://github.com/amlalabs/fictionet-sdk/blob/main/examples/scan/README.md)
//! runs it under Docker Compose and shows the scan.
