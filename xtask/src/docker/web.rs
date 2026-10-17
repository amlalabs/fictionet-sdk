use super::Compose;
use crate::process::{Checks, ChildGuard, Result, capture, cmd, combined, poll};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub fn run(compose: &Compose) -> Result {
    let mut checks = Checks::default();
    initial(compose, &mut checks)?;
    let start = Instant::now();
    unreachable(compose, &mut checks)?;
    checks.require(
        "an unreachable address fails fast",
        start.elapsed() < Duration::from_secs(3),
        format!("took {:?}", start.elapsed()),
    );
    let count = |url| -> Result<u64> {
        Ok(
            capture(&mut compose.agent(&["curl", "-sS", "--cacert", "/run/ca/ca.pem", url]))?
                .trim()
                .parse()?,
        )
    };
    let a = count("https://example.test/count")?;
    let b = count("https://www.example.test/count")?;
    checks.require(
        "the site keeps its state",
        a.checked_add(1) == Some(b),
        format!("{a} then {b}"),
    );
    for version in ["--http2", "--http1.1"] {
        checks.transfer(
            &format!("16 MiB over {version}"),
            16777216,
            &mut compose.agent(&[
                "curl",
                "-fsS",
                "--max-time",
                "30",
                "--cacert",
                "/run/ca/ca.pem",
                version,
                "-o",
                "/dev/null",
                "-w",
                "%{size_download} %{speed_download}",
                "https://example.test/big",
            ]),
        )?;
    }
    checks.downloads("10 sequential downloads of 16 MiB", 10, 16777216, &mut compose.agent(&["bash", "-c", "seq 10 | xargs -P 1 -I{} curl -fsS --max-time 30 --cacert /run/ca/ca.pem -o /dev/null -w '%{size_download} %{time_total}\\n' https://example.test/big"]))?;
    upstream(compose, &mut checks)?;
    checks.downloads("32 downloads of 4 MiB at once", 32, 4194304, &mut compose.agent(&["bash", "-c", "seq 32 | xargs -P 32 -I{} curl -fsS --max-time 60 --cacert /run/ca/ca.pem -o /dev/null -w '%{size_download} %{time_total}\\n' https://example.test/4mb"]))?;
    memory(compose, &mut checks)?;
    closing(compose, &mut checks)?;
    half_close(compose, &mut checks)?;
    ipv6(compose, &mut checks)?;
    let start = Instant::now();
    ipv6_unreachable(compose, &mut checks)?;
    checks.require(
        "an unreachable IPv6 address fails fast",
        start.elapsed() < Duration::from_secs(3),
        format!("took {:?}", start.elapsed()),
    );
    ipv6_ping(compose, &mut checks)?;
    checks.transfer(
        "16 MiB over IPv6",
        16777216,
        &mut compose.agent(&[
            "curl",
            "-fsS",
            "--max-time",
            "30",
            "--cacert",
            "/run/ca/ca.pem",
            "-6",
            "-o",
            "/dev/null",
            "-w",
            "%{size_download} %{speed_download}",
            "https://example.test/big",
        ]),
    )?;
    println!(
        "world log:\n{}\nupstream log:\n{}",
        compose.logs("world")?,
        compose.logs("upstream")?
    );
    checks.finish()
}

fn start_holder(command: &mut Command) -> Result<(ChildGuard, String)> {
    let mut child = ChildGuard(
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?,
    );
    let stdout = child.0.stdout.take().ok_or("missing holder stdout")?;
    let (send, recv) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
        if let Err(error) = send.send(result) {
            eprintln!("holder readiness receiver closed: {error}");
        }
    });
    let line = recv.recv_timeout(Duration::from_secs(120))??;
    if line.is_empty() {
        return Err("holder exited before reporting readiness".into());
    }
    Ok((child, line))
}

fn release_holder(mut child: ChildGuard) -> Result {
    child
        .0
        .stdin
        .take()
        .ok_or("missing holder stdin")?
        .write_all(b"release\n")?;
    let status = child.0.wait()?;
    if !status.success() {
        return Err(format!("holder exited with {status}").into());
    }
    Ok(())
}

fn memory(compose: &Compose, checks: &mut Checks) -> Result {
    let id = capture(&mut compose.command(&["ps", "-q", "world"]))?;
    let rss = || -> Result<i64> {
        let status = capture(&mut cmd(
            "docker",
            &["exec", id.trim(), "cat", "/proc/1/status"],
        ))?;
        let line = status
            .lines()
            .find(|line| line.starts_with("VmRSS:"))
            .ok_or("missing world VmRSS")?;
        Ok(line
            .split_whitespace()
            .nth(1)
            .ok_or("missing world memory")?
            .parse::<i64>()?
            / 1024)
    };
    let before = rss()?;
    let (holder, opened) =
        start_holder(&mut compose.agent(&["timeout", "120", "python3", "-c", MEMORY]))?;
    let mut held = rss()?;
    if opened.trim() == "250" {
        poll(Duration::from_secs(10), Duration::from_millis(100), || {
            held = rss()?;
            Ok(held - before < 50)
        })?;
    }
    let released = release_holder(holder);
    checks.require(
        "idle connection holder completed",
        released.is_ok(),
        format!("{released:?}"),
    );
    checks.ok(
        "250 idle connections finished closing",
        "",
        &mut compose.agent(&["bash", "-c", DRAIN]),
    )?;
    checks.require(
        "250 idle connections return their buffers",
        opened.trim() == "250" && held - before < 50,
        format!("{opened} opened, memory {before} MB then {held} MB"),
    );
    Ok(())
}

fn closing(compose: &Compose, checks: &mut Checks) -> Result {
    let plain_big = || {
        compose.agent(&[
            "curl",
            "-fsS",
            "--max-time",
            "30",
            "-4",
            "-o",
            "/dev/null",
            "-w",
            "%{size_download} %{time_total}",
            "http://plain.test/big",
        ])
    };
    let before = checks.transfer(
        "16 MiB before holding closing connections",
        16777216,
        &mut plain_big(),
    )?;
    let (holder, counts) =
        start_holder(&mut compose.agent(&["timeout", "120", "python3", "-c", CLOSING]))?;
    let held = compose
        .agent(&[
            "curl",
            "-sS",
            "--max-time",
            "30",
            "-4",
            "-o",
            "/dev/null",
            "http://plain.test/big",
        ])
        .output()?;
    let released = release_holder(holder);
    checks.require(
        "closing connection holder completed",
        released.is_ok(),
        format!("{released:?}"),
    );
    checks.ok(
        "CLOSE_WAIT connections finished closing",
        "",
        &mut compose.agent(&["bash", "-c", DRAIN]),
    )?;
    let after = checks.transfer(
        "16 MiB after releasing closing connections",
        16777216,
        &mut plain_big(),
    )?;
    checks.require(
        "2,000 connections left in CLOSE_WAIT: 256 served, 1744 reset",
        counts.trim() == "256 1744"
            && !held.status.success()
            && combined(&held).contains("reset by peer")
            && before.is_some()
            && after.is_some(),
        format!(
            "counts {counts}, while held {}: {}",
            held.status,
            combined(&held)
        ),
    );
    Ok(())
}

fn initial(compose: &Compose, checks: &mut Checks) -> Result {
    checks.ok(
        "dig A example.test (Site::at)",
        "^203\\.0\\.113\\.10 $",
        &mut compose.agent(&["dig", "+short", "example.test", "A"]),
    )?;
    checks.ok(
        "dig A example.test again, same answer",
        "^203\\.0\\.113\\.10 $",
        &mut compose.agent(&["dig", "+short", "example.test", "A"]),
    )?;
    checks.ok(
        "dig AAAA example.test (Site::at, IPv6)",
        "^2001:db8:113::10 $",
        &mut compose.agent(&["dig", "+short", "example.test", "AAAA"]),
    )?;
    checks.ok(
        "dig nope.test is NXDOMAIN",
        "status: NXDOMAIN",
        &mut compose.agent(&["dig", "nope.test", "A"]),
    )?;
    checks.ok(
        "dig +tcp plain.test (an address from 198.18.0.0/15)",
        "^198\\.18\\.0\\.1 $",
        &mut compose.agent(&["dig", "+tcp", "+short", "plain.test", "A"]),
    )?;
    checks.ok(
        "dig AAAA plain.test (an address from 2001:2::/48)",
        "^2001:2::1 $",
        &mut compose.agent(&["dig", "+tcp", "+short", "plain.test", "AAAA"]),
    )?;
    checks.ok(
        "dig AAAA v4only.test is NODATA",
        "status: NOERROR.*ANSWER: 0",
        &mut compose.agent(&["dig", "v4only.test", "AAAA"]),
    )?;
    checks.ok(
        "dig A v6only.test is NODATA",
        "status: NOERROR.*ANSWER: 0",
        &mut compose.agent(&["dig", "v6only.test", "A"]),
    )?;
    checks.ok(
        "resolv.conf points at the gateway",
        "nameserver 10\\.0\\.0\\.1 nameserver 2001:db8::1",
        &mut compose.agent(&["cat", "/etc/resolv.conf"]),
    )?;
    checks.ok(
        "https over HTTP/2",
        "^hello from https example.test 443 over HTTP/2.0 2 $",
        &mut compose.agent(&[
            "curl",
            "-sS",
            "--cacert",
            "/run/ca/ca.pem",
            "-w",
            "%{http_version}\\n",
            "https://example.test/",
        ]),
    )?;
    checks.ok(
        "https over HTTP/1.1",
        "^hello from https example.test 443 over HTTP/1.1 1.1 $",
        &mut compose.agent(&[
            "curl",
            "-sS",
            "--cacert",
            "/run/ca/ca.pem",
            "--http1.1",
            "-w",
            "%{http_version}\\n",
            "https://example.test/",
        ]),
    )?;
    checks.ok(
        "https for the second name",
        "^hello from https www.example.test 443 over HTTP/2.0 $",
        &mut compose.agent(&[
            "curl",
            "-sS",
            "--cacert",
            "/run/ca/ca.pem",
            "https://www.example.test/",
        ]),
    )?;
    checks.ok(
        "http redirects to https",
        "^301 https://example.test/a\\?b=c $",
        &mut compose.agent(&[
            "curl",
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code} %{redirect_url}\\n",
            "http://example.test/a?b=c",
        ]),
    )?;
    checks.ok(
        "curl -L follows the redirect",
        "^hello from https example.test 443",
        &mut compose.agent(&[
            "curl",
            "-sS",
            "--cacert",
            "/run/ca/ca.pem",
            "-L",
            "http://example.test/",
        ]),
    )?;
    checks.ok(
        "a plain HTTP site",
        "^plain site http plain.test 80 $",
        &mut compose.agent(&["curl", "-sS", "http://plain.test/x"]),
    )?;
    checks.ok(
        "a plain site sharing an address with TLS sites",
        "^plain site http shared.test 80 $",
        &mut compose.agent(&["curl", "-sS", "http://shared.test/"]),
    )?;
    checks.ok(
        "HTTP/2 with prior knowledge on port 80",
        "^plain site http plain.test 80 2 $",
        &mut compose.agent(&[
            "curl",
            "-sS",
            "--http2-prior-knowledge",
            "-w",
            "%{http_version}\\n",
            "http://plain.test/",
        ]),
    )?;
    checks.ok(
        "a Host that is not this site gets 421",
        "^421 $",
        &mut compose.agent(&[
            "curl",
            "-sS",
            "--cacert",
            "/run/ca/ca.pem",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}\\n",
            "-H",
            "Host: plain.test",
            "https://example.test/",
        ]),
    )?;
    checks.fails(
        "TLS for a site without TLS at a TLS address is rejected",
        "unrecognized name|unrecognised name|alert number 112",
        &mut compose.agent(&[
            "curl",
            "-sS",
            "--cacert",
            "/run/ca/ca.pem",
            "https://shared.test/",
        ]),
    )?;
    checks.fails(
        "port 443 is closed where no site has TLS",
        "Couldn't connect|Connection refused",
        &mut compose.agent(&[
            "curl",
            "-sS",
            "--cacert",
            "/run/ca/ca.pem",
            "https://plain.test/",
        ]),
    )?;
    Ok(())
}

fn unreachable(compose: &Compose, checks: &mut Checks) -> Result {
    checks.fails(
        "an address with no site is unreachable (ICMP host unreachable)",
        "No route to host",
        &mut compose.agent(&[
            "timeout",
            "10",
            "bash",
            "-c",
            "exec 3<>/dev/tcp/192.0.2.1/80",
        ]),
    )?;
    Ok(())
}

fn upstream(compose: &Compose, checks: &mut Checks) -> Result {
    checks.ok(
        "web::proxy(&fcx) reaches the real upstream",
        "^hello from the real upstream: GET /some/path\\?q=1 HTTP/1.1 $",
        &mut compose.agent(&["curl", "-sS", "http://upstream/some/path?q=1"]),
    )?;
    checks.ok("300 requests at once over HTTP/2", "^300 $", &mut compose.agent(&["bash", "-c", "curl -sS --no-progress-meter --cacert /run/ca/ca.pem --http2 --parallel --parallel-max 100 -o /dev/null -w '%{http_code}\\n'         $(for i in $(seq 300); do echo https://example.test/?$i; done) | grep -c '^200$'"]))?;
    checks.ok(
        "a 20,000-byte ping, in fragments both ways",
        " 2 received",
        &mut compose.agent(&["ping", "-c", "2", "-W", "2", "-s", "20000", "10.0.0.1"]),
    )?;
    checks.ok("300 open connections: 256 kept, the rest reset at once; idle ones closed after 10 s", "opened 300 established 256 HTTP/1.1 200 OK closed-before-8s 1 sampled at [89]\\.[0-9] s closed-by-30s 256 after (1[0-9]|2[0-9])\\.[0-9] s", &mut compose.agent(&["bash", "-c", "\n        fds=()\n        start=$(date +%s%N)\n        for i in $(seq 300); do exec {fd}<>/dev/tcp/198.18.0.1/80 || break; fds+=(\"$fd\"); done\n        # Tenths of a second since the first connection.\n        since() { echo $(( ($(date +%s%N) - start) / 100000000 )); }\n        # Connections to port 80 (0050) by state: ESTABLISHED (01), and\n        # CLOSE_WAIT (08) once the other side has closed. Reset ones are gone.\n        count() { awk \"\\$3 ~ /:0050\\$/ && \\$4 == \\\"$1\\\"\" /proc/net/tcp | wc -l; }\n        closed() { count 08; }\n        sleep 1\n        echo \"opened ${#fds[@]} established $(count 01)\"\n        printf \"GET / HTTP/1.1\\r\\nHost: plain.test\\r\\nConnection: close\\r\\n\\r\\n\" >&\"${fds[0]}\"\n        head -c 15 <&\"${fds[0]}\"; echo\n        while (( $(since) < 80 )); do sleep 0.1; done\n        c=$(closed) t=$(since)\n        echo \"closed-before-8s $c sampled at $((t / 10)).$((t % 10)) s\"\n        while (( $(closed) < 256 && $(since) < 300 )); do sleep 0.1; done\n        t=$(since)\n        echo \"closed-by-30s $(closed) after $((t / 10)).$((t % 10)) s\""]))?;
    Ok(())
}

fn half_close(compose: &Compose, checks: &mut Checks) -> Result {
    checks.ok("a client that half-closes after its request gets the response", "^200 OK 200 OK $", &mut compose.agent(&["python3", "-c", "\nimport socket\nfor req in [b\"GET / HTTP/1.1\\r\\nHost: plain.test\\r\\nConnection: close\\r\\n\\r\\n\",\n            b\"GET / HTTP/1.0\\r\\nHost: plain.test\\r\\n\\r\\n\"]:\n    s = socket.create_connection((\"198.18.0.1\", 80), timeout=5)\n    s.sendall(req)\n    s.shutdown(socket.SHUT_WR)\n    data = b\"\"\n    while True:\n        x = s.recv(4096)\n        if not x:\n            break\n        data += x\n    print(data.split(b\"\\r\\n\")[0].split(b\" \", 1)[1].decode())\n"]))?;
    Ok(())
}

fn ipv6(compose: &Compose, checks: &mut Checks) -> Result {
    checks.ok(
        "curl tries IPv6 first (Happy Eyeballs)",
        "^hello from https example.test 443 over HTTP/2.0 2001:db8:113::10 $",
        &mut compose.agent(&[
            "curl",
            "-sS",
            "--cacert",
            "/run/ca/ca.pem",
            "-w",
            "%{remote_ip}\\n",
            "https://example.test/",
        ]),
    )?;
    checks.ok(
        "curl -6 over HTTP/1.1",
        "^hello from https example.test 443 over HTTP/1.1 2001:db8:113::10 $",
        &mut compose.agent(&[
            "curl",
            "-sS",
            "--cacert",
            "/run/ca/ca.pem",
            "-6",
            "--http1.1",
            "-w",
            "%{remote_ip}\\n",
            "https://example.test/",
        ]),
    )?;
    checks.ok(
        "curl -4 still works",
        "^hello from https example.test 443 over HTTP/2.0 203\\.0\\.113\\.10 $",
        &mut compose.agent(&[
            "curl",
            "-sS",
            "--cacert",
            "/run/ca/ca.pem",
            "-4",
            "-w",
            "%{remote_ip}\\n",
            "https://example.test/",
        ]),
    )?;
    checks.ok(
        "an IPv4-only site is reached over IPv4",
        "^hello from https v4only.test 443 over HTTP/2.0 198\\.18\\.0\\.[0-9]+ $",
        &mut compose.agent(&[
            "curl",
            "-sS",
            "--cacert",
            "/run/ca/ca.pem",
            "-w",
            "%{remote_ip}\\n",
            "https://v4only.test/",
        ]),
    )?;
    checks.ok(
        "an IPv6-only site",
        "^hello from https v6only.test 443 over HTTP/2.0 2001:2::[0-9a-f]+ $",
        &mut compose.agent(&[
            "curl",
            "-sS",
            "--cacert",
            "/run/ca/ca.pem",
            "-w",
            "%{remote_ip}\\n",
            "https://v6only.test/",
        ]),
    )?;
    checks.ok(
        "plain HTTP over IPv6",
        "^plain site http plain.test 80 2001:2::1 $",
        &mut compose.agent(&["curl", "-sS", "-w", "%{remote_ip}\\n", "http://plain.test/"]),
    )?;
    checks.ok(
        "ping -6 the gateway",
        " 1 received",
        &mut compose.agent(&["ping", "-6", "-c", "1", "-W", "2", "2001:db8::1"]),
    )?;
    checks.ok(
        "a 20,000-byte ping -6, in fragments both ways",
        " 2 received",
        &mut compose.agent(&[
            "ping",
            "-6",
            "-c",
            "2",
            "-W",
            "2",
            "-s",
            "20000",
            "2001:db8::1",
        ]),
    )?;
    Ok(())
}

fn ipv6_unreachable(compose: &Compose, checks: &mut Checks) -> Result {
    checks.fails(
        "an IPv6 address with no site is unreachable (ICMPv6 address unreachable)",
        "No route to host",
        &mut compose.agent(&[
            "timeout",
            "10",
            "bash",
            "-c",
            "exec 3<>/dev/tcp/2001:db8:99::1/80",
        ]),
    )?;
    Ok(())
}

fn ipv6_ping(compose: &Compose, checks: &mut Checks) -> Result {
    checks.fails(
        "ping -6 an address with no site",
        "Address unreachable",
        &mut compose.agent(&["ping", "-6", "-c", "1", "-W", "2", "2001:db8:99::1"]),
    )?;
    Ok(())
}

const MEMORY: &str = r###"
import socket, sys
socks = []
for i in range(250):
    s = socket.create_connection(("198.18.0.1", 80), timeout=30)
    s.sendall(b"GET /mb HTTP/1.1\r\nHost: plain.test\r\n\r\n")
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(65536)
        if not chunk:
            raise RuntimeError("incomplete response headers")
        buf += chunk
    got = len(buf.split(b"\r\n\r\n", 1)[1])
    while got < 1 << 20:
        chunk = s.recv(1 << 20)
        if not chunk:
            raise RuntimeError("incomplete response body")
        got += len(chunk)
    socks.append(s)
print(len(socks), flush=True)
sys.stdin.readline()
"###;

const CLOSING: &str = r###"
import resource, socket, sys
resource.setrlimit(resource.RLIMIT_NOFILE, (4096, 4096))
served, reset, socks = 0, 0, []
for i in range(2000):
    # A connection past the limit is reset right after the handshake. The
    # reset can arrive before connect() returns, and then connect() fails.
    try:
        s = socket.create_connection(("198.18.0.1", 80), timeout=30)
    except ConnectionResetError:
        reset += 1
        continue
    try:
        s.sendall(b"GET / HTTP/1.0\r\nHost: plain.test\r\n\r\n")
        data = b""
        while True:
            x = s.recv(65536)
            if not x:
                break
            data += x
        if data.startswith(b"HTTP/1.0 200"):
            served += 1
    except (ConnectionResetError, BrokenPipeError):
        reset += 1
    socks.append(s)
print(served, reset, flush=True)
sys.stdin.readline()
"###;

const DRAIN: &str = r###"
        for ((i=0; i<100; i++)); do
            remaining=$(awk '$3 == "010012C6:0050" && $4 != "06" { n++ }
                END { print n+0 }' /proc/net/tcp) || exit 1
            [[ $remaining == 0 ]] && exit 0
            sleep 0.1
        done
        echo "$remaining connections to 198.18.0.1:80 did not close within 10 s" >&2
        exit 1"###;
