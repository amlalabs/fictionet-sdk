# Choosing the MPTCP reference server

Research checked on November 5, 2026. The recommended persona is an Ubuntu
24.04 host with an official Caddy package from the default-enabled generation
beginning at v2.10.0, serving its packaged HTTP site on port 80, alongside
ordinary OpenSSH on port 22. The official package measured here is Caddy
2.11.9, built with Go 1.27.3. It negotiated MPTCP on port 80 while SSH on 22
answered the same offer with ordinary TCP. [Measured comparison](DIFF.md#caddy-and-ipv4-options),
[MPTCP application support](https://www.mptcp.dev/apps.html),
[Caddy package configuration](https://raw.githubusercontent.com/caddyserver/dist/master/config/Caddyfile),
[existing Ubuntu comparison](DIFF.md).

This choice prioritizes a reproducible real application with no MPTCP-specific
application configuration. It does not assert that Caddy's welcome page is
common on production servers, that Caddy represents most public MPTCP
listeners, or that Caddy was the target in Anthropic's demonstration. The
demonstration identifies an MPTCP listener but does not name its application,
distribution, or exact kernel build.
[Anthropic's Linux account](https://www.anthropic.com/research/discovering-vulnerabilities-with-claude).

## Vulnerability scope and Ubuntu update status

CVE-2026-98432 concerns ownership and lifetime of IPv4 options during TCP
connection setup: another CPU can use options while a child socket frees
them. The upstream correction defers freeing through RCU. This is an
underlying TCP defect, not a defect confined to an application or to MPTCP.
[Linux kernel CNA description](https://kernel.googlesource.com/pub/scm/linux/security/vulns/+/refs/heads/master/cve/published/2026/CVE-2026-98432.mbox).

Anthropic describes remote command execution against a Linux MPTCP listener.
Red Hat explicitly states that MPTCP is not a prerequisite for the underlying
vulnerability and that absence of an MPTCP listener is not an exposure test.
Consequently, ordinary TCP responses from SSH or nginx do not establish
immunity; MPTCP matters here because of the demonstrated chain and the persona
we want to emulate.
[Anthropic](https://www.anthropic.com/research/discovering-vulnerabilities-with-claude),
[Red Hat advisory](https://access.redhat.com/security/vulnerabilities/RHSB-2026-016).

At this research cutoff, Canonical's tracker lists Noble's `linux` package as
vulnerable, with work in progress for `6.8.0-149.149`. Its November 2 notice
places that fix in `-proposed`; the normal `noble-updates` source package is
`6.8.0-147.147`. “All normal updates installed” therefore does not establish
that this particular fix is running.
[Canonical tracker](https://ubuntu.com/security/CVE-2026-98432),
[Canonical proposed-pocket notice](https://ubuntu.com/blog/fixes-available-in-proposed-pocket-for-cve-2026-98432),
[Noble updates package](https://packages.ubuntu.com/source/noble-updates/linux).

The Caddy reference guest ran `6.8.0-147-generic`, with `linux-generic 6.8.0-147.147`.
Combined with Canonical's status, that supports an affected-package inference
unless a separate backport or livepatch applies. It is not an exploit test.
[Guest observations](DIFF.md),
[Canonical tracker](https://ubuntu.com/security/CVE-2026-98432).

The deployment host must run a kernel containing the fix. Disabling MPTCP on
that host does not protect its ordinary IPv4 TCP listeners, and a userspace
honeypot does not repair the host kernel. Both vendors describe filtering
inbound IPv4 TCP packets with IP options as a mitigation; that is not a claim
that the kernel is fixed. No host networking changes or deployment were made
for this comparison. Recheck the running kernel's vendor status before any
deployment; the November 5 Noble status above is still vulnerable/work in
progress, rather than a released normal-update fix.
[Red Hat's mitigation and MPTCP distinction](https://access.redhat.com/security/vulnerabilities/RHSB-2026-016),
[Ubuntu's mitigation and package status](https://ubuntu.com/security/CVE-2026-98432).

## What enables the listener

Linux 6.8 defaults `net.mptcp.enabled` to `1` and `pm_type` to `0`, permitting
MPTCP sockets with the in-kernel path manager. The application still has to
request an MPTCP socket. An enabled kernel does not automatically convert
ordinary TCP listeners.
[Linux 6.8 sysctls](https://www.kernel.org/doc/html/v6.8/networking/mptcp-sysctl.html),
[MPTCP setup guide](https://www.mptcp.dev/setup.html).

Go 1.21 introduced opt-in MPTCP. Go 1.23.0 still defaults off; Go 1.24.0
enables it for `net.ListenConfig` listeners, while leaving dialers off.
`GODEBUG=multipathtcp=0`, `1`, `2`, and `3` select neither, both, listeners,
and dialers respectively; explicit `SetMultipathTCP` overrides the default.
[Go setting history](https://go.dev/doc/godebug),
[Go 1.23 implementation](https://raw.githubusercontent.com/golang/go/go1.23.0/src/net/dial.go),
[Go 1.24 implementation](https://raw.githubusercontent.com/golang/go/go1.24.0/src/net/dial.go).

Compiler version alone is insufficient. Go adjusts compatibility defaults to
the main module or workspace's Go version and explicit directives. The Go
1.24 settings table marks `multipathtcp` as changed in 1.24, with old value
`0`. A newer compiler can therefore preserve the old behavior for an older
main module. Go also falls back to ordinary TCP if MPTCP socket creation fails.
[Go compatibility rules](https://go.dev/doc/godebug#default),
[Go 1.24 settings table](https://raw.githubusercontent.com/golang/go/go1.24.0/src/internal/godebugs/table.go),
[Go Linux fallback](https://raw.githubusercontent.com/golang/go/go1.24.0/src/net/mptcpsock_linux.go).

Caddy v2.10.0 declares `go 1.24`; its release workflow requests the latest
patch matching `~1.24.1`, and its Unix listener calls `config.Listen`.
These facts explain the project's documented default MPTCP behavior. The
workflow does not establish the precise compiler patch in an arbitrary
downloaded binary; retain that binary's build information with the measurement.
[Caddy module](https://raw.githubusercontent.com/caddyserver/caddy/v2.10.0/go.mod),
[release workflow](https://raw.githubusercontent.com/caddyserver/caddy/v2.10.0/.github/workflows/release.yml),
[listener implementation](https://raw.githubusercontent.com/caddyserver/caddy/v2.10.0/listen_unix.go),
[Caddy build information command](https://caddyserver.com/docs/command-line#caddy-build-info).

The official Ubuntu installation uses Caddy's Cloudsmith repository and starts
the systemd service. Its packaged Caddyfile binds `:80` and serves
`/usr/share/caddy`. This is the initial reference configuration.
[Official installation](https://caddyserver.com/docs/install),
[packaged Caddyfile](https://raw.githubusercontent.com/caddyserver/dist/master/config/Caddyfile).

Ubuntu's own Noble archive instead lists Caddy `2.6.2-6ubuntu0.24.04.3` for
amd64; upstream v2.6.2 declares Go 1.18. Treat a bare distribution-package
installation as a different candidate, whose actual binary and overrides
require inspection, not as evidence of the v2.10.0 defaults.
[Ubuntu package](https://packages.ubuntu.com/noble/caddy),
[older Caddy module](https://raw.githubusercontent.com/caddyserver/caddy/v2.6.2/go.mod).

`mptcpd` performs path management. `mptcpize run` explicitly forces a target
program to use MPTCP; `mptcpize enable` changes a systemd unit to use its
launcher. Noble provides the latter in package `0.12-4`. Such wrapping could
make another service useful as a configured reference, but it would not
represent that service's untouched application defaults.
[mptcpd documentation](https://raw.githubusercontent.com/multipath-tcp/mptcpd/v0.12/README.md),
[Noble mptcpize manual](https://manpages.ubuntu.com/manpages/noble/man8/mptcpize.8.html).

## Other candidates and prevalence

The response column below describes documented configuration and kernel
semantics, not packets measured from each product. A Linux MPTCP listener
negotiates a compatible MP_CAPABLE offer and still accepts ordinary TCP.
Application data then follows the selected HTTP, TLS or proxy configuration;
there is no universal MPTCP application banner.
[Linux socket semantics](https://docs.kernel.org/networking/mptcp.html).

| Candidate | Enablement and expected open-port behavior | Evidence of prevalence and limits |
| --- | --- | --- |
| Official Caddy 2.10+ | Default MPTCP listener; packaged `:80` serves its static welcome page. A configured hostname normally enables HTTPS/443 and HTTP redirects. | Caddy is 1.2% of websites with an identified server in the November 5 survey. MPTCP-enabled share and default-page share are unverified. [Support](https://www.mptcp.dev/apps.html), [package site](https://raw.githubusercontent.com/caddyserver/dist/master/config/Caddyfile), [HTTPS](https://caddyserver.com/docs/automatic-https), [survey](https://w3techs.com/technologies/overview/web_server). |
| HAProxy 3.1+ | Explicit `mptcp@`, `mptcp4@` or `mptcp6@` bind; upstream example uses port 5000. Application response depends on its backend. | MPTCP listener deployment count unverified; native support is not default enablement. [Release](https://www.haproxy.com/blog/reviewing-every-new-feature-in-haproxy-3-1), [upstream example](https://github.com/haproxy/haproxy/blob/v3.1.0/examples/mptcp.cfg). |
| Envoy | Explicit listener `enable_mptcp`; configured listener accepts MPTCP and ordinary TCP, then runs its filter chain. | Envoy is 0.5% of identified web-server websites; MPTCP-enabled share unverified. [Listener API](https://www.envoyproxy.io/docs/envoy/v1.24.7/api-v3/config/listener/v3/listener.proto), [survey](https://w3techs.com/technologies/overview/web_server). |
| nginx 1.29.7+ | Upstream `listen ... multipath` explicitly requests IPPROTO_MPTCP on Linux 5.6+. HTTP/TLS depends on the site. The earlier patch-only description is outdated; Ubuntu's measured 1.24 predates this directive. | nginx is 30.0% of identified web-server websites; the new opt-in listener's share is unverified. [Directive](https://nginx.org/en/docs/http/ngx_http_core_module.html#listen), [survey](https://w3techs.com/technologies/overview/web_server), [Ubuntu package observation](DIFF.md). |
| Apache Traffic Server | Per-port `mptcp` configuration; the MPTCP project lists support from 9.2.4. Its documentation still mentions a custom kernel, so version compatibility needs a concrete build check. | Below 0.1% of identified web-server websites; MPTCP share unverified. [Configuration](https://docs.trafficserver.apache.org/en/latest/admin-guide/files/records.yaml.en.html), [support catalog](https://www.mptcp.dev/apps.html), [survey](https://w3techs.com/technologies/overview/web_server). |
| nginx or another program through mptcpize | Explicit wrapper changes socket creation; application banner/content stays that program's. Red Hat documents the nginx technique. | Supported deployment procedure, but no measured public deployment count and not an untouched nginx/SSH default. [Red Hat procedure](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/configuring_and_managing_networking/assembly_managing-the-mptcpd-service_configuring-and-managing-networking), [wrapper manual](https://manpages.ubuntu.com/manpages/noble/man8/mptcpize.8.html). |

The website percentages are measurements of websites, not IP addresses,
listeners, software versions, kernel versions or MPTCP. The survey excludes
default server pages, so it cannot establish how common our exact packaged
welcome site is. [Survey methodology](https://w3techs.com/technologies).

There are documented product deployments, but they are poor generic identities
for this fixture. Huawei's 2019 IETF presentation describes Honor V20 app
acceleration using direct application clouds and proxies through Wangsu CDN
or Huawei Cloud. Proximus described a nine-month MPTCP access-bonding pilot
qualified for countrywide deployment in 2017. These historical primary reports
do not establish today's public listener versions, banners or affected kernel
counts. [Huawei deployment presentation](https://datatracker.ietf.org/meeting/104/materials/slides-104-mptcp-multi-path-transport-deployment-on-smartphone-apps-00),
[Proximus announcement](https://www.proximus.com/news/2017/tessares-proximus%E2%80%99-access-bonding-offering-faster-internet-large-sparsely-populated-rural-areas.html).

The longitudinal scan authors reported about 16,500 IPv4 MPTCPv0 hosts on
80 and 13,500 on 443 at the end of 2021, with roughly a hundred v1-responsive
addresses per address-family/port series. Their v0 analysis found mirrored
sender keys in 81% of candidate IPv4/443 hosts and 96% on IPv4/80. Those historical
false-positive rates cannot be applied to a 2026 v1 scan. Address-owning
networks also do not identify the application serving a port.
[Authors' APNIC account](https://blog.apnic.net/2022/08/23/analyzing-mptcp-adoption-in-the-internet/),
[primary paper, pages 4–6](https://olivergasser.net/papers/shreedhar2022longitudinal.pdf).

Hutchins' attributed October 30, 2026 report gives 2,102,043 MPTCP-reachable
port-443 endpoints and 762,774 TLS completions. **Unverified primary record:**
the original post was inaccessible during research; a mirror supplied the
text. No accompanying dataset or sufficiently detailed method was found to
establish option-echo rejection, continued MPTCP through TLS rather than
fallback, application attribution, or affected kernel versions. These numbers
are not a measured Caddy population. A 443-only scan cannot compare port 80
and 443 prevalence. [Original post](https://x.com/MalwareTechBlog/status/2117508092321747077),
[accessible mirror](https://nitter.gq/MalwareTechBlog/status/2117508092321747077).

Caddy therefore wins on a documented default, an observed web presence, and
a small reproducible package configuration. HAProxy, Envoy, nginx and wrapped
applications are credible opt-in alternatives, but support alone does not
establish how frequently those configurations are exposed. We do not know
which application the team's attackers will target; this is a representative
MPTCP service, not an attribution of the published exploit or a claim of
majority market share. [Caddy defaults](https://www.mptcp.dev/apps.html),
[survey](https://w3techs.com/technologies/overview/web_server),
[original demonstration](https://www.anthropic.com/research/discovering-vulnerabilities-with-claude).

## Packet semantics and measured limits

For a compatible MPTCPv1 handshake, Linux 6.8 defines these MP_CAPABLE lengths.
The SYN-ACK writes the request socket's 64-bit local key in network byte order;
the final ACK carries both keys.
[Linux constants](https://raw.githubusercontent.com/torvalds/linux/v6.8/net/mptcp/protocol.h),
[Linux option generation](https://raw.githubusercontent.com/torvalds/linux/v6.8/net/mptcp/options.c),
[RFC 8684 connection setup](https://www.rfc-editor.org/rfc/rfc8684.html#section-3.1).

| Segment | MP_CAPABLE option length | Key material |
| --- | --- | --- |
| SYN | 4 bytes | None |
| SYN-ACK | 12 bytes | Server's 64-bit key |
| ACK without data | 20 bytes | Both 64-bit keys |

With the normal compatible offer and default checksum/join settings, the
source predicts a SYN-ACK option starting `1e 0c 01 01`, followed by the
server key. The Caddy reference returned that option after MSS 1460 for the
four-byte offer `1e 04 01 01`; the window was 64240, TTL 64, DF set, IP ID 0,
and total IP length 56. SSH returned MSS alone and length 44. This is one
specific offer, not a complete fingerprint or a test of every MPTCP variant.
[Measured wire records](../../logs/honeypot-diff/caddy-before/reference-raw.json),
[Linux option writer](https://raw.githubusercontent.com/torvalds/linux/v6.8/net/mptcp/options.c),
[Linux defaults](https://www.kernel.org/doc/html/v6.8/networking/mptcp-sysctl.html).

The earlier retained `ssh_mptcp_syn` probe offered MP_CAPABLE on port 22 and
received an ordinary SYN-ACK with MSS and no MPTCP option. That record does
not measure nginx's response to an MP_CAPABLE offer. The earlier harness
explicitly wrote `1` to the MPTCP sysctl, so its observed enabled setting is
not an independent measurement of the distribution's boot default.
[Retained wire record](../../logs/honeypot-diff/final/reference-raw.json),
[probe construction](../../xtask/src/honeypot_probe.rs),
[guest preparation](../../xtask/src/honeypot_diff.rs).

## Measured reference and imitation

The reference was installed from Caddy's official Cloudsmith repository in
the Ubuntu guest. Its packaged Caddyfile was unchanged: `:80`, root
`/usr/share/caddy`, and `file_server`. The guest's MPTCP setting was read as
`1`; this version of the harness does not write it. Caddy's admin listener
was bound only to loopback, and there was no listener on 443. The observed
backlog was 4096 for Caddy and systemd's SSH socket.
[Package origin](../../logs/honeypot-diff/caddy-before/caddy-package-policy.txt),
[build information](../../logs/honeypot-diff/caddy-before/caddy-build-info.txt),
[configuration](../../logs/honeypot-diff/caddy-before/Caddyfile),
[listeners](../../logs/honeypot-diff/caddy-before/listeners.txt),
[MPTCP setting](../../logs/honeypot-diff/caddy-before/mptcp-enabled.txt).

The guest probe used identical MP_CAPABLE offers on both ports, then a real
Linux `IPPROTO_MPTCP` client for HTTP. `MPTCP_INFO` reported negotiation with
a remote key and no fallback. Both the ordinary TCP and MPTCP clients got
the 18,753-byte welcome page for `/` and an empty 404 for `/missing` on the
same connection. The HTTP idle close was measured at about 300 seconds.
An additional wire capture observed empty ACK keepalive probes beginning
about 15 seconds after connection setup, with about 15.36 seconds between
the subsequent probes in that run.
[HTTP over TCP](../../logs/honeypot-diff/caddy-before/reference-http.json),
[HTTP over MPTCP](../../logs/honeypot-diff/caddy-before/reference-http-mptcp.json),
[idle wire observation](../../logs/honeypot-diff/keepalive-before/reference-http-idle.json).

The imitation now defaults to Caddy on 80 with MPTCP, with ordinary SSH on
22. It uses the measured package page and file metadata, Caddy's 300-second
idle timeout, Go's 15-second TCP keepalive setting, and backlog 4096. Caddy's
current defaults also specify 60-second request-header and rolling body-read
and response-write inactivity limits; there is no per-connection request
count cap. These settings come from the current measured generation, not
an assumption that every Caddy release has identical defaults.
[Caddy 2.11.9 server defaults](https://raw.githubusercontent.com/caddyserver/caddy/v2.11.9/modules/caddyhttp/app.go),
[Go keepalive defaults](https://raw.githubusercontent.com/golang/go/go1.27.3/src/net/dial.go),
[Go HTTP connection loop](https://raw.githubusercontent.com/golang/go/go1.27.3/src/net/http/server.go),
[implementation](src/services.rs), [comparison and remaining gaps](DIFF.md#caddy-and-ipv4-options).

The final guest comparison confirmed MPTCP only on HTTP, no MPTCP fallback
for the HTTP client, identical welcome and missing-page bodies, and matching
HTTP headers except Date. Idle close measured 299987 ms for Caddy and
300022 ms for the imitation. Differences remain in the established receive
window, keepalive cadence, SSH after its initial key-exchange proposal, and
Ethernet padding in this QEMU setup. These are recorded rather than counted
as matches. [Final measured table](DIFF.md#caddy-and-ipv4-options),
[reference idle capture](../../logs/honeypot-diff/caddy-final/reference-http-idle.json),
[imitation idle capture](../../logs/honeypot-diff/caddy-final/imitation-http-idle.json).

The observer records decoded IPv4 options and their complete header bytes
on SYNs. Repeated SYNs for the same option-bearing attempt carry the observed
handshake phase, first and previous SYN times, and time since completion.
These signals describe traffic consistent with a prerequisite of the flaw;
they do not establish intent or exploitation. The option comparison sends
only well-formed SYNs and ordinary retransmissions, without completing those
handshakes, racing CPUs or attempting request migration. The in-memory tests
cover correlation after completion separately.
[Observer](src/observe.rs), [benign comparison](DIFF.md#caddy-and-ipv4-options).

HTTPS on 443 is a separate deployment profile. Replacing the packaged `:80`
address with a qualifying domain activates Caddy's automatic HTTPS and its
normal HTTP-to-HTTPS redirects. The untouched package site does not justify
claiming an open HTTPS service. Certificate/TLS behavior and configured site
content need their own reference observations.
[Caddy package configuration](https://raw.githubusercontent.com/caddyserver/dist/master/config/Caddyfile),
[automatic HTTPS](https://caddyserver.com/docs/automatic-https).
