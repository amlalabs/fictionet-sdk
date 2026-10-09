//! Getting started: from `cargo build` to an HTTPS request from a sandbox.
//!
//! This page runs the crate's `web_world` example, a small world of
//! websites, and attaches one sandbox to it. Everything runs on one Linux
//! machine. Every command below was run as shown, and every output is
//! copied from that run.
//!
//! You need:
//!
//! - Linux, with Rust 1.91 or later.
//! - Root through `sudo`. Attach makes a network device, which needs
//!   `CAP_NET_ADMIN`.
//! - `ip` (iproute2) and `curl`. `dig` (in Debian's `dnsutils`) is
//!   optional.
//!
//! The sandbox here is a Linux network namespace named `agent`. It isolates
//! networking only. Inside it, the only interfaces are loopback and the
//! one attach makes, but programs still share the host's filesystem, users and processes.
//! That is enough to show a world working. A real sandbox, such as a
//! container (see [In Docker Compose](crate::attaching#in-docker-compose)),
//! a Kubernetes pod (see [On Kubernetes](crate::attaching#on-kubernetes))
//! or a VM, isolates the rest too. Fictionet supplies the sandbox's
//! network. The harness that runs the agent supplies the rest of the
//! sandbox, and decides what the agent may do.
//!
//! To try this without `sudo` on your own machine, run `demos/web` from the
//! repository. It boots a small Debian VM under QEMU, builds Fictionet
//! inside it, and runs the same world and sandbox as this page there, with
//! root inside the VM only. It needs QEMU, KVM and the host tools listed
//! in `vm/README.md`. It needs no Docker or Rust on the host.
//!
//! # 1. Build
//!
//! From the top directory of the repository:
//!
//! ```text
//! $ cargo build --release --bin fictionet --example web_world
//! ...
//!     Finished `release` profile [optimized] target(s) in 6.72s
//! ```
//!
//! This builds two programs:
//!
//! - `target/release/examples/web_world`, the world. It runs its local
//!   sites on a tokio runtime and makes no upstream requests.
//! - `target/release/fictionet`, which has the `fictionet attach` command.
//!
//! # 2. Make the socket's directory
//!
//! The world listens on a Unix socket, `/run/fictionet/world.sock`.
//! [`listen`](crate::listen) makes the socket, but not its directory, so
//! make the directory and give it to your user:
//!
//! ```text
//! $ sudo mkdir -p /run/fictionet
//! $ sudo chown "$USER" /run/fictionet
//! ```
//!
//! Now the world can run as you, without root. `/run` is emptied at every
//! boot, so do this again after a reboot.
//!
//! # 3. Start the world
//!
//! In a first terminal, start the world. Its two arguments are the socket
//! to listen on and the file to write its certificate authority to:
//!
//! ```text
//! $ target/release/examples/web_world /run/fictionet/world.sock /run/fictionet/ca.pem
//! listening on /run/fictionet/world.sock, CA in /run/fictionet/ca.pem
//! ```
//!
//! The world makes a certificate authority (CA) when it starts, and writes
//! the CA's certificate to `/run/fictionet/ca.pem`. It serves HTTPS for
//! `example.test` and `www.example.test`, with a certificate from that CA,
//! at two addresses: `203.0.113.10` for IPv4 and `2001:db8:113::10` for
//! IPv6. It also serves a few more sites, listed at the top of
//! `examples/web_world.rs`: `plain.test` and `shared.test` serve plain HTTP
//! only, and `v4only.test` and `v6only.test` have only one address family. It answers every other name with "no such name" (NXDOMAIN).
//!
//! Leave it running. It prints `lookup <name>` the first time a sandbox
//! asks for a name.
//!
//! # 4. Make a sandbox and attach it
//!
//! In a second terminal, make the network namespace `agent`, and bring up
//! its loopback interface:
//!
//! ```text
//! $ sudo ip netns add agent
//! $ sudo ip -n agent link set lo up
//! ```
//!
//! If your host runs `systemd-resolved`, as most desktop distributions do,
//! also give the namespace its own `nsswitch.conf`. Without it, programs in
//! the sandbox ask `systemd-resolved` for names, and it never asks the
//! world ([below](#when-dig-works-but-programs-cannot-resolve-names)
//! explains why):
//!
//! ```text
//! $ sudo mkdir -p /etc/netns/agent
//! $ echo "hosts: files dns" | sudo tee /etc/netns/agent/nsswitch.conf
//! hosts: files dns
//! ```
//!
//! Then attach it to the world. `--world` is the world's socket, `--name`
//! the sandbox's name, and `--type tun` asks for a network device in the
//! sandbox. `--netns` says where its namespace is. Attach runs no DHCP for
//! `tun`, so the last six flags give the sandbox an address, a gateway and
//! a DNS server for each of IPv4 and IPv6:
//!
//! ```text
//! $ sudo target/release/fictionet attach --world unix:/run/fictionet/world.sock --name agent --type tun \
//!     --netns /run/netns/agent \
//!     --ip-addr 10.0.0.2/24 --gateway 10.0.0.1 --dns 10.0.0.1 \
//!     --ip-addr-v6 2001:db8::2/64 --gateway-v6 2001:db8::1 --dns-v6 2001:db8::1
//! fictionet attach: agent attached as tun0
//! ```
//!
//! Attach entered the namespace and made the device `tun0` there. It gave
//! `tun0` the addresses `10.0.0.2/24` and `2001:db8::2/64`, with default
//! routes through `10.0.0.1` and `2001:db8::1`, the world's gateway. It
//! told the world the sandbox's name, `agent`. Then it wrote both DNS
//! servers to `/etc/netns/agent/resolv.conf`. The world is dual-stack, as
//! most of the real internet is, so the sandbox gets both families. For a
//! sandbox with IPv4 only, give `--no-ip-addr-v6 --no-gateway-v6
//! --no-dns-v6` instead of the three IPv6 flags (see
//! [Addresses](crate::attaching#addresses)).
//!
//! Leave it running. It moves packets between `tun0` and the world until
//! you stop it.
//!
//! # 5. Look around inside the sandbox
//!
//! Open a third terminal. `sudo ip netns exec agent <command>` runs a
//! command inside the sandbox. First, check the device, the routes and the
//! DNS settings that attach made:
//!
//! ```text
//! $ sudo ip netns exec agent ip addr show tun0
//! 2: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 500
//!     link/none
//!     inet 10.0.0.2/24 scope global tun0
//!        valid_lft forever preferred_lft forever
//!     inet6 2001:db8::2/64 scope global nodad
//!        valid_lft forever preferred_lft forever
//!     inet6 fe80::169f:caf7:470a:29dc/64 scope link stable-privacy proto kernel_ll
//!        valid_lft forever preferred_lft forever
//! $ sudo ip netns exec agent ip route
//! default via 10.0.0.1 dev tun0 proto static onlink
//! 10.0.0.0/24 dev tun0 proto kernel scope link src 10.0.0.2
//! $ sudo ip netns exec agent ip -6 route
//! 2001:db8::/64 dev tun0 proto kernel metric 256 pref medium
//! fe80::/64 dev tun0 proto kernel metric 256 pref medium
//! default via 2001:db8::1 dev tun0 proto static metric 1024 onlink pref medium
//! $ sudo ip netns exec agent cat /etc/resolv.conf
//! # Written by attach.
//! nameserver 10.0.0.1
//! nameserver 2001:db8::1
//! ```
//!
//! The `fe80::` address is the link-local address the kernel gives every
//! IPv6 interface. `ip netns exec` shows the command
//! `/etc/netns/agent/resolv.conf` as its `/etc/resolv.conf`, so programs in
//! the sandbox ask the world for names. Look up a name's IPv4 and IPv6
//! addresses, and ping the gateway over both:
//!
//! ```text
//! $ sudo ip netns exec agent dig +short example.test
//! 203.0.113.10
//! $ sudo ip netns exec agent dig +short AAAA example.test
//! 2001:db8:113::10
//! $ sudo ip netns exec agent ping -c 1 10.0.0.1
//! PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.
//! 64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=2.55 ms
//!
//! --- 10.0.0.1 ping statistics ---
//! 1 packets transmitted, 1 received, 0% packet loss, time 0ms
//! rtt min/avg/max/mdev = 2.546/2.546/2.546/0.000 ms
//! $ sudo ip netns exec agent ping -6 -c 1 2001:db8::1
//! PING 2001:db8::1 (2001:db8::1) 56 data bytes
//! 64 bytes from 2001:db8::1: icmp_seq=1 ttl=64 time=0.149 ms
//!
//! --- 2001:db8::1 ping statistics ---
//! 1 packets transmitted, 1 received, 0% packet loss, time 0ms
//! rtt min/avg/max/mdev = 0.149/0.149/0.149/0.000 ms
//! ```
//!
//! All of these answers came from world code: the DNS server and the
//! gateway of [`Sites`](crate::stdlib::web::Sites).
//!
//! # 6. Trust the world's CA, and make an HTTPS request
//!
//! The sandbox does not trust the world's CA yet, so HTTPS fails:
//!
//! ```text
//! $ sudo ip netns exec agent curl -sS https://example.test/
//! curl: (60) SSL certificate OpenSSL verify result: unable to get local issuer certificate (20)
//! More details here: https://curl.se/docs/sslcerts.html
//!
//! curl failed to verify the legitimacy of the server and therefore could not
//! establish a secure connection to it. To learn more about this situation and
//! how to fix it, please visit the webpage mentioned above.
//! ```
//!
//! Give curl the CA's certificate with `--cacert`:
//!
//! ```text
//! $ sudo ip netns exec agent curl -sS --cacert /run/fictionet/ca.pem https://example.test/
//! hello from https example.test 443 over HTTP/2.0
//! ```
//!
//! That answer came from the world's axum app, over HTTP/2, with TLS from
//! the world's CA.
//!
//! This demo isolates networking only, and shares the host's filesystem.
//! So use `--cacert` here, or the `SSL_CERT_FILE` variable for programs
//! that read it. Don't run `update-ca-certificates`: it would change the
//! host's trust store. When you need a sandbox-wide trust store, install
//! the CA in the sandbox's own image or container. On Debian, copy it into
//! `/usr/local/share/ca-certificates/` with a `.crt` name and run
//! `update-ca-certificates` when you build the image.
//!
//! curl asked for both addresses and connected over IPv6. `-w
//! '%{remote_ip}\n'` prints the address it used, and `-4` makes it use
//! IPv4:
//!
//! ```text
//! $ sudo ip netns exec agent curl -sS --cacert /run/fictionet/ca.pem -w '%{remote_ip}\n' https://example.test/
//! hello from https example.test 443 over HTTP/2.0
//! 2001:db8:113::10
//! $ sudo ip netns exec agent curl -sS --cacert /run/fictionet/ca.pem -4 --http1.1 -w '%{remote_ip}\n' https://example.test/
//! hello from https example.test 443 over HTTP/1.1
//! 203.0.113.10
//! ```
//!
//! The plain HTTP site redirects to HTTPS, and a name the world does not
//! know does not resolve:
//!
//! ```text
//! $ sudo ip netns exec agent curl -sS -i http://example.test/ | head -3
//! HTTP/1.1 301 Moved Permanently
//! content-type: text/plain; charset=utf-8
//! location: https://example.test/
//! $ sudo ip netns exec agent curl -sS --cacert /run/fictionet/ca.pem https://nope.test/
//! curl: (6) Could not resolve host: nope.test
//! ```
//!
//! A site can have just one family. `v4only.test` has no IPv6 address, so
//! its AAAA lookup comes back empty, and curl connects over IPv4 without
//! trying IPv6 first:
//!
//! ```text
//! $ sudo ip netns exec agent dig +short AAAA v4only.test
//! $ sudo ip netns exec agent curl -sS --cacert /run/fictionet/ca.pem -w '%{remote_ip}\n' https://v4only.test/
//! hello from https v4only.test 443 over HTTP/2.0
//! 198.18.0.1
//! ```
//!
//! A connection to an address where no site lives fails immediately. The
//! gateway answers with
//! ICMPv6 "address unreachable", which programs see as "No route to host":
//!
//! ```text
//! $ sudo ip netns exec agent curl -sS http://[2001:db8:99::1]/
//! curl: (7) Failed to connect to 2001:db8:99::1:80 after 0 ms: Could not connect to server
//! $ sudo ip netns exec agent bash -c 'exec 3<>/dev/tcp/2001:db8:99::1/80'
//! bash: connect: No route to host
//! bash: line 1: /dev/tcp/2001:db8:99::1/80: No route to host
//! $ sudo ip netns exec agent ping -6 -c 1 2001:db8:99::1
//! PING 2001:db8:99::1 (2001:db8:99::1) 56 data bytes
//! From 2001:db8::1 icmp_seq=1 Destination unreachable: Address unreachable
//!
//! --- 2001:db8:99::1 ping statistics ---
//! 1 packets transmitted, 0 received, +1 errors, 100% packet loss, time 0ms
//! ```
//!
//! The world exists only inside the sandbox. The host itself does not know
//! these names:
//!
//! ```text
//! $ curl -sS --cacert /run/fictionet/ca.pem https://example.test/
//! curl: (6) Could not resolve host: example.test
//! ```
//!
//! # 7. Stop
//!
//! Press Ctrl-C in the attach terminal. Attach exits, and removes `tun0` as
//! it goes:
//!
//! ```text
//! $ sudo ip netns exec agent ip link show tun0
//! Device "tun0" does not exist.
//! ```
//!
//! Press Ctrl-C in the world's terminal. Then remove the namespace, and
//! `/etc/netns/agent`, which holds the `resolv.conf` that attach wrote for
//! it:
//!
//! ```text
//! $ sudo ip netns del agent
//! $ sudo rm -r /etc/netns/agent
//! ```
//!
//! # If something goes wrong
//!
//! Find the message or the symptom in the left column. The middle column
//! says how to confirm the cause, and the right column how to fix it. Every
//! message here comes from a real run of the setup on this page.
//!
//! | Symptom | Check | Fix |
//! |---|---|---|
//! | `fictionet attach: connecting to the world at /run/fictionet/world.sock: No such file or directory (os error 2)` | `ls -l /run/fictionet/world.sock` finds no socket. | The world is not running, or it listens on another path. Start the world first, or give attach `--world-wait 30` so it keeps trying while the world starts. |
//! | `fictionet attach: connecting to the world at /run/fictionet/world.sock: Connection refused (os error 111)` | The socket file exists, but no world listens on it. A world that was killed can leave it behind. | Start the world. It removes the old socket file when it starts. |
//! | `fictionet attach: connecting to the world at /run/fictionet/world.sock: Permission denied (os error 13). The socket belongs to the world's user, and attach may not write to it: run both as the same user, or give attach CAP_DAC_OVERRIDE` | `ls -l /run/fictionet/world.sock` shows another owner, such as `root` when the world was started with `sudo`. This happens to an attach that runs without root, such as one of the [proxy types](crate::attaching#behind-a-proxy-http_proxy-and-socks5). | Run the world and attach as the same user, as the message says. |
//! | `fictionet attach: entering the network namespace /run/netns/agent: No such file or directory (os error 2)` | `ip netns list` does not list `agent`. | Make the namespace first: `sudo ip netns add agent`. Attach run without root fails at this step too, or at `creating the tun device`, with a permission error. Run it with `sudo`. |
//! | `fictionet attach: the world refused: agent is already attached`, with exit status 3 | Another attach with `--name agent` is still running: `pgrep -af 'name agent'`. | Stop the other attach, or give each sandbox its own `--name`. A name is free again as soon as its attach exits. |
//! | `fictionet attach: configuring tun1: adding the IPv4 default route: another link already has one (File exists (os error 17)). Give --down-link <ifname> for that link ...` | `sudo ip netns exec agent ip route` shows a default route on another link: a second attach in the same namespace, or a container's own `eth0`. | Attach once per namespace. For a container's link, give `--down-link eth0`, as the message says: attach then removes that link's routes and addresses and sets it down before it adds its own (see [How `tun` works](crate::attaching#how-tun-works)). |
//! | `dig` answers, but `curl` says `Could not resolve host: example.test` | Ask for the name the way most programs do, through the C library: `getent hosts example.test` inside the sandbox. Then `cat /etc/resolv.conf` and `grep '^hosts' /etc/nsswitch.conf` inside the sandbox. | See [When `dig` works but programs cannot resolve names](#when-dig-works-but-programs-cannot-resolve-names) below. |
//! | `curl: (60) SSL certificate OpenSSL verify result: unable to get local issuer certificate (20)` | The client does not trust the world's CA. | Give it the CA: `curl --cacert /run/fictionet/ca.pem`, `SSL_CERT_FILE` for programs that read it, `NODE_EXTRA_CA_CERTS` for Node, or install the CA in the sandbox's image (see [step 6](#6-trust-the-worlds-ca-and-make-an-https-request)). |
//! | `curl: (35) TLS connect error: error:0A000458:SSL routines::tlsv1 unrecognized name` | The world has no HTTPS site under that name. Here, `https://shared.test/` (a plain HTTP site) and `https://203.0.113.10/` (an address, so curl sends no name) both fail this way. | Use a name that has an HTTPS site. [`Sites`](crate::stdlib::web::Sites) picks the certificate by the name the client sends, and refuses the handshake for a name with no TLS. A certificate that does not cover the name, from a world's own TLS setup, fails differently: `openssl s_client` reports `Verification error: hostname mismatch`. Add the name to the certificate. |
//! | `curl: (6) Could not resolve host: nope.test` | `sudo ip netns exec agent dig nope.test` shows `status: NXDOMAIN` from `SERVER: 10.0.0.1#53`: the world has no site with that name. | Fix the name, or add a site for it to the world. |
//! | `curl: (7) Failed to connect to plain.test:443 after 3 ms: Could not connect to server` | `dig +short plain.test` answers an address, such as `198.18.0.1`, and `curl http://plain.test/` works. The site exists, but has no TLS, so port 443 is closed. | Use `http://`, or give the site a certificate with [`Site::tls`](crate::stdlib::web::Site::tls). |
//! | With the [HTTP proxy type](crate::attaching#behind-a-proxy-http_proxy-and-socks5) (`--type http_proxy`), curl says `Could not resolve host: example.test`, or Node says `getaddrinfo ENOTFOUND example.test` | The client did not use the proxy, and looked the name up on the host. `curl -sv https://example.test/ 2>&1 \| grep -E 'proxy tunnel\|NO_PROXY'` prints `Establishing HTTP proxy tunnel to example.test:443` when curl uses it. | Set `https_proxy` (and `http_proxy`) to `http://relay:<token>@<host>:<port>`, with the host and port that attach listens on (`--listen`): `attach:8080` in the [Compose setup](crate::attaching#the-proxy-in-docker-compose), `127.0.0.1:8080` in a [pod](crate::attaching#the-proxy-on-kubernetes). Take the world's names out of `NO_PROXY`. Node's built-in `fetch` ignores these variables unless `NODE_USE_ENV_PROXY=1` is set. |
//! | The ready file exists, but requests fail or time out | The ready file does not mean the world serves requests yet. Make one end-to-end request. | See [Readiness](#readiness) below. |
//!
//! ## When `dig` works but programs cannot resolve names
//!
//! `dig` sends its query straight to a DNS server. Most programs, `curl`
//! included, ask the C library instead, which reads `/etc/nsswitch.conf`
//! and `/etc/resolv.conf`. Attach writes the sandbox's `resolv.conf` to
//! `/etc/netns/agent/resolv.conf`, and only `ip netns exec` puts that file
//! in place of `/etc/resolv.conf`. A program started with `nsenter`, or
//! by a tool that enters the namespace some other way, still reads the
//! host's file and asks the host's DNS servers, which it cannot reach from
//! the sandbox:
//!
//! ```text
//! $ sudo nsenter --net=/run/netns/agent dig +short @10.0.0.1 example.test
//! 203.0.113.10
//! $ sudo nsenter --net=/run/netns/agent curl -sS --cacert /run/fictionet/ca.pem https://example.test/
//! curl: (6) Could not resolve host: example.test
//! $ sudo nsenter --net=/run/netns/agent cat /etc/resolv.conf | grep nameserver
//! nameserver 100.100.100.100
//! nameserver fd7a:115c:a1e0::53
//! ```
//!
//! Use `ip netns exec`, or mount the sandbox's file over
//! `/etc/resolv.conf` in a private mount namespace, as `ip netns exec`
//! does:
//!
//! ```text
//! $ sudo nsenter --net=/run/netns/agent unshare --mount sh -c 'mount --bind /etc/netns/agent/resolv.conf /etc/resolv.conf && exec curl -sS --cacert /run/fictionet/ca.pem https://example.test/'
//! hello from https example.test 443 over HTTP/2.0
//! ```
//!
//! In a container, attach writes the container's own `/etc/resolv.conf`,
//! so this does not come up.
//!
//! The other cause is `/etc/nsswitch.conf`. On a host that runs
//! `systemd-resolved`, the `hosts` line usually names `resolve` before
//! `dns`. The C library then sends every lookup to `systemd-resolved`,
//! which asks the host's DNS servers on the host's network, and never sees
//! the sandbox's `resolv.conf`. Give the sandbox its own `nsswitch.conf`.
//! `ip netns exec` mounts every file in `/etc/netns/agent/` over the file
//! of the same name in `/etc`, so this works for the namespace in this
//! guide:
//!
//! ```text
//! $ grep '^hosts' /etc/nsswitch.conf
//! hosts: mymachines resolve [!UNAVAIL=return] files myhostname dns
//! $ echo "hosts: files dns" | sudo tee /etc/netns/agent/nsswitch.conf
//! hosts: files dns
//! $ sudo ip netns exec agent getent hosts example.test
//! 2001:db8:113::10 example.test
//! ```
//!
//! In a container, set the same `hosts` line in the image. Remove
//! `/etc/netns/agent` when you remove the namespace, as in [step 7](#7-stop).
//!
//! ## Readiness
//!
//! A harness needs to know when it may start the agent. Give attach
//! `--ready-file <path>`, and it creates that file at the end of its setup.
//! (The commands on this page leave the flag out.) By then, the
//! world has accepted the sandbox, and attach has made `tun0`, given it
//! its addresses and routes, and written `resolv.conf`. Attach removes the
//! file when it exits. The file says nothing about the world itself: a
//! world can accept a sandbox and still not answer it. For example, a
//! world that loads data or connects to a database before it takes its
//! sandboxes from [`Attachments`](crate::Attachments) does not answer the
//! sandbox until it does, and the sandbox's clients time out meanwhile.
//!
//! To show this, `web_world` was changed to wait 20 seconds before it
//! serves its sandboxes, and attach was given
//! `--ready-file /run/fictionet/agent.ready`. The ready file appears
//! immediately, but the first request times out:
//!
//! ```text
//! $ test -f /run/fictionet/agent.ready && echo ready
//! ready
//! $ sudo ip netns exec agent curl -sS --cacert /run/fictionet/ca.pem --max-time 5 https://example.test/
//! curl: (28) Resolving timed out after 5001 milliseconds
//! ```
//!
//! So a harness that needs the world to answer checks it end to end, with
//! the same kind of request the agent will make. This one retries every
//! two seconds, up to 10 times, and prints the HTTP status once a request
//! succeeds. `--fail` makes an HTTP error status, such as 404 or 503, count
//! as a failure too, so curl exits with status 0 only after an answer with
//! a status below 400:
//!
//! ```text
//! $ sudo ip netns exec agent curl -sS --cacert /run/fictionet/ca.pem --max-time 5 --retry 10 --retry-delay 2 --retry-all-errors --fail -o /dev/null -w '%{http_code}\n' https://example.test/
//! curl: (28) Resolving timed out after 5001 milliseconds
//! curl: (28) Resolving timed out after 5001 milliseconds
//! 200
//! ```
//!
//! Start the agent once this check passes. With the unchanged `web_world`,
//! the same command prints `200` on the first try.
//!
//! # Next
//!
//! - [A world in code](crate#a-world-in-code), on the crate's front page:
//!   what a world looks like in Rust.
//! - [`running`](crate::running): the program around a world, how it stops,
//!   and how to run one in a test.
//! - [`attaching`](crate::attaching): every way to attach a sandbox. Its
//!   [host namespace section](crate::attaching#on-a-host-with-ip-netns) has
//!   a script that attaches a namespace, starts the agent in it and cleans
//!   up afterwards, the way a test harness would.
//! - [`stdlib::web`](crate::stdlib::web): how `web_world` builds its
//!   websites.
