use super::Compose;
use crate::process::{Checks, Result, capture, cmd, poll, run as execute};
use std::time::{Duration, Instant};

pub fn run(compose: &Compose) -> Result {
    let mut checks = Checks::default();
    clients(compose, &mut checks)?;
    failures(compose, &mut checks)?;
    let start = Instant::now();
    unreachable(compose, &mut checks)?;
    checks.require(
        "an unreachable address fails at once",
        start.elapsed() < Duration::from_secs(3),
        format!("took {:?}", start.elapsed()),
    );
    isolation(compose, &mut checks)?;
    let network = capture(&mut cmd(
        "docker",
        &[
            "network",
            "inspect",
            "fictionet-proxy_sandbox",
            "-f",
            "{{.Id}}",
        ],
    ))?;
    let bridge = format!(
        "br-{}",
        network.get(..12).ok_or("invalid Docker network id")?
    );
    let addresses = capture(&mut cmd("ip", &["-o", "addr", "show", "dev", &bridge]))?;
    checks.require(
        "the host has no IPv4 address on the sandbox network",
        !addresses.contains(" inet "),
        &addresses,
    );
    sandbox(compose, &mut checks)?;
    for (door, proxy) in [("http", ""), ("socks", "-x \"$SOCKS\"")] {
        checks.transfer(&format!("16 MiB through the {door} door"), 16777216, &mut compose.agent(&["sh", "-c", &format!("curl -fsS --max-time 30 {proxy} -o /dev/null -w '%{{size_download}} %{{speed_download}}' https://example.test/big")]), false)?;
        checks.downloads(&format!("10 downloads of 16 MiB at once through the {door} door"), 10, 16777216, &mut compose.agent(&["sh", "-c", &format!("seq 10 | xargs -P 10 -I{{}} curl -fsS --max-time 30 {proxy} -o /dev/null -w '%{{size_download}} %{{time_total}}\\n' https://example.test/big")]))?;
        checks.transfer(&format!("64 MiB upload through the {door} door"), 67108864, &mut compose.agent(&["sh", "-c", &format!("head -c 67108864 /dev/zero | curl -fsS --max-time 30 {proxy} --data-binary @- -w '%{{time_total}}' https://example.test/upload")]), true)?;
    }
    plain_upload(compose, &mut checks)?;
    let start = Instant::now();
    requests(compose, &mut checks)?;
    println!("    took {:?}, including docker exec", start.elapsed());
    for service in ["attach-http", "attach-socks"] {
        let logs = compose.logs(service)?;
        let lines: Vec<_> = logs.lines().collect();
        println!(
            "{service} log:\n{}",
            lines[lines.len().saturating_sub(5)..].join("\n")
        );
    }
    let id = capture(&mut compose.command(&["ps", "-q", "attach-http"]))?;
    let memory = capture(&mut cmd(
        "docker",
        &["exec", id.trim(), "grep", "VmRSS", "/proc/1/status"],
    ))?;
    let kb: u64 = memory
        .split_whitespace()
        .nth(1)
        .ok_or("missing VmRSS")?
        .parse()?;
    println!("attach-http memory after all of this: {} MB", kb / 1024);
    execute(&mut compose.command(&["stop", "-t", "2", "world"]))?;
    let mut state = String::new();
    poll(Duration::from_secs(10), Duration::from_millis(200), || {
        let states = capture(&mut compose.command(&[
            "ps",
            "-a",
            "--format",
            "{{.Service}} {{.State}} {{.ExitCode}}",
        ]))?;
        state = states
            .lines()
            .find(|s| s.starts_with("attach-http "))
            .unwrap_or_default()
            .into();
        Ok(state.contains("exited"))
    })?;
    checks.require(
        "when the world stops, attach exits 0",
        state == "attach-http exited 0",
        &state,
    );
    checks.ok(
        "attach says why",
        "the world closed the connection; the proxy is closed",
        &mut compose.command(&["logs", "--no-log-prefix", "attach-http"]),
    )?;
    no_proxy(compose, &mut checks)?;
    checks.finish()
}

fn clients(compose: &Compose, checks: &mut Checks) -> Result {
    checks.ok(
        "curl https, HTTP/2",
        "^hello from https example.test 443 over HTTP/2.0 2 $",
        &mut compose.agent(&[
            "curl",
            "-sS",
            "-w",
            "%{http_version}\\n",
            "https://example.test/",
        ]),
    )?;
    checks.ok(
        "curl http (a plain-HTTP proxy request)",
        "^plain site http plain.test 80 $",
        &mut compose.agent(&["curl", "-sS", "http://plain.test/x"]),
    )?;
    checks.fails(
        "curl without the world's CA fails: TLS is end to end",
        "\\(60\\)",
        &mut compose.agent(&[
            "env",
            "-u",
            "CURL_CA_BUNDLE",
            "-u",
            "SSL_CERT_FILE",
            "curl",
            "-sS",
            "https://example.test/",
        ]),
    )?;
    checks.ok(
        "wget https",
        "^hello from https example.test 443 over HTTP/1.1 $",
        &mut compose.agent(&[
            "wget",
            "-q",
            "-O",
            "-",
            "--ca-certificate=/run/ca/ca.pem",
            "https://example.test/",
        ]),
    )?;
    checks.ok(
        "wget http",
        "^plain site http plain.test 80 $",
        &mut compose.agent(&["wget", "-q", "-O", "-", "http://plain.test/w"]),
    )?;
    checks.fails(
        "git over https reaches the site (which has no repository)",
        "repository 'https://example.test/repo.git/' not found",
        &mut compose.agent(&["git", "ls-remote", "https://example.test/repo.git"]),
    )?;
    checks.ok("python requests https and http (Python 3.13)", "^3\\.13 hello from https example.test 443 over HTTP/1.1 plain site http plain.test 80 $", &mut compose.agent(&["python3", "-c", "\nimport platform, requests\nprint(\".\".join(platform.python_version_tuple()[:2]))\nprint(requests.get(\"https://example.test/\").text.strip())\nprint(requests.get(\"http://plain.test/\").text.strip())"]))?;
    checks.ok(
        "go net/http https and http",
        "^200 hello from https example.test 443 over HTTP/2.0 200 plain site http plain.test 80 $",
        &mut compose.agent(&["goclient", "https://example.test/", "http://plain.test/"]),
    )?;
    checks.ok(
        "node fetch, with NODE_USE_ENV_PROXY=1",
        "^hello from https example.test 443 over HTTP/1.1 $",
        &mut compose.agent(&[
            "node",
            "-e",
            "fetch(\"https://example.test/\").then(r => r.text()).then(t => console.log(t.trim()))",
        ]),
    )?;
    checks.ok("node fetch without NODE_USE_ENV_PROXY ignores the proxy, and fails", "ENOTFOUND|EAI_AGAIN", &mut compose.agent(&["env", "-u", "NODE_USE_ENV_PROXY", "node", "-e", "fetch(\"https://example.test/\").then(r => console.log(r.status)).catch(e => console.log(String(e.cause)))"]))?;
    checks.ok(
        "curl https through socks5h",
        "^hello from https example.test 443 over HTTP/2.0 $",
        &mut compose.agent(&["sh", "-c", "curl -sS -x \"$SOCKS\" https://example.test/"]),
    )?;
    checks.ok(
        "curl http through socks5h (ALL_PROXY)",
        "^plain site http plain.test 80 $",
        &mut compose.agent(&[
            "sh",
            "-c",
            "env -u http_proxy -u HTTP_PROXY ALL_PROXY=\"$SOCKS\" curl -sS http://plain.test/s",
        ]),
    )?;
    checks.fails(
        "git over https through socks5h",
        "repository 'https://example.test/repo.git/' not found",
        &mut compose.agent(&[
            "sh",
            "-c",
            "git -c http.proxy=\"$SOCKS\" ls-remote https://example.test/repo.git",
        ]),
    )?;
    checks.ok("python requests through socks5h", "^hello from https example.test 443 over HTTP/1.1 $", &mut compose.agent(&["sh", "-c", "python3 -c \"import os, requests; print(requests.get(\\\"https://example.test/\\\", proxies={\\\"https\\\": os.environ[\\\"SOCKS\\\"]}).text.strip())\""]))?;
    checks.ok(
        "go net/http through socks5 (HTTPS_PROXY=socks5://)",
        "^200 hello from https example.test 443 over HTTP/2.0 $",
        &mut compose.agent(&[
            "sh",
            "-c",
            "HTTPS_PROXY=\"socks5://${SOCKS#socks5h://}\" goclient https://example.test/",
        ]),
    )?;
    checks.fails(
        "no token: 407",
        "response 407",
        &mut compose.agent(&[
            "curl",
            "-sS",
            "-x",
            "http://attach-http:8080",
            "https://example.test/",
        ]),
    )?;
    checks.fails(
        "a wrong token: 407",
        "response 407",
        &mut compose.agent(&[
            "curl",
            "-sS",
            "-x",
            "http://relay:wrong@attach-http:8080",
            "https://example.test/",
        ]),
    )?;
    checks.ok(
        "a wrong token, plain HTTP: 407",
        "^407 $",
        &mut compose.agent(&[
            "curl",
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}\\n",
            "-x",
            "http://relay:wrong@attach-http:8080",
            "http://plain.test/",
        ]),
    )?;
    checks.fails(
        "socks5 with a wrong token is rejected",
        "rejected by the SOCKS5 server",
        &mut compose.agent(&[
            "curl",
            "-sS",
            "-x",
            "socks5h://relay:wrong@attach-socks:1080",
            "https://example.test/",
        ]),
    )?;
    checks.fails(
        "socks5 with no login is refused",
        "No authentication method was acceptable",
        &mut compose.agent(&[
            "curl",
            "-sS",
            "-x",
            "socks5h://attach-socks:1080",
            "https://example.test/",
        ]),
    )?;
    Ok(())
}

fn failures(compose: &Compose, checks: &mut Checks) -> Result {
    let relay_token = &compose
        .env
        .iter()
        .find(|(key, _)| key == "RELAY_TOKEN")
        .ok_or("missing relay token")?
        .1;
    checks.fails(
        "no such name: 502",
        "response 502",
        &mut compose.agent(&["curl", "-sS", "https://nope.test/"]),
    )?;
    checks.ok(
        "the reason is in X-Proxy-Error",
        "X-Proxy-Error: no such name in the world",
        &mut compose.agent(&[
            "curl",
            "-sS",
            "-o",
            "/dev/null",
            "-D",
            "-",
            "-x",
            &format!("http://relay:{}@attach-http:8080", relay_token),
            "http://nope.test/",
        ]),
    )?;
    checks.fails(
        "a closed port: 502, connection refused",
        "< HTTP/1.1 502 Bad Gateway.*< X-Proxy-Error: connection refused",
        &mut compose.agent(&["curl", "-sS", "-v", "https://plain.test/"]),
    )?;
    checks.fails(
        "socks5: no such name is reply 4",
        "connection to nope.test. \\(4\\)",
        &mut compose.agent(&["sh", "-c", "curl -sS -x \"$SOCKS\" https://nope.test/"]),
    )?;
    checks.fails(
        "socks5: a closed port is reply 5",
        "connection to plain.test. \\(5\\)",
        &mut compose.agent(&["sh", "-c", "curl -sS -x \"$SOCKS\" https://plain.test/"]),
    )?;
    Ok(())
}

fn unreachable(compose: &Compose, checks: &mut Checks) -> Result {
    checks.fails(
        "an address with no machine: 502 host unreachable",
        "response 502",
        &mut compose.agent(&["curl", "-sS", "https://192.0.2.1/"]),
    )?;
    Ok(())
}

fn isolation(compose: &Compose, checks: &mut Checks) -> Result {
    checks.fails(
        "a real address through the proxy is just a world address: 502",
        "response 502",
        &mut compose.agent(&["curl", "-sS", "-m", "10", "https://1.1.1.1/"]),
    )?;
    checks.fails(
        "a real name through the proxy does not exist in the world: 502",
        "response 502",
        &mut compose.agent(&["curl", "-sS", "-m", "10", "https://example.com/"]),
    )?;
    checks.fails(
        "around the proxy, a real address is unreachable",
        "Network is unreachable|Couldn't connect",
        &mut compose.agent(&[
            "curl",
            "-sS",
            "-m",
            "5",
            "--noproxy",
            "*",
            "http://1.1.1.1/",
        ]),
    )?;
    checks.fails(
        "around the proxy, TCP to 1.1.1.1 fails",
        "Network is unreachable",
        &mut compose.agent(&[
            "python3",
            "-c",
            "import socket; socket.create_connection((\"1.1.1.1\", 443), timeout=5)",
        ]),
    )?;
    checks.fails("around the proxy, UDP DNS to 8.8.8.8 fails", "Network is unreachable", &mut compose.agent(&["python3", "-c", "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b\"x\", (\"8.8.8.8\", 53))"]))?;
    Ok(())
}

fn sandbox(compose: &Compose, checks: &mut Checks) -> Result {
    checks.ok("the sandbox has no IPv6 address on its network", "^none $", &mut compose.agent(&["sh", "-ec", "addresses=$(cat /proc/net/if_inet6); printf \"%s\\n\" \"$addresses\" | awk \"/eth0/ { found=1; print } END { if (!found) print \\\"none\\\" }\""]))?;
    checks.ok("the sandbox resolves no real names", "^no address $", &mut compose.agent(&["sh", "-c", "if getent hosts example.com; then exit 0; else status=$?; fi; if [ \"$status\" -eq 2 ]; then echo no address; else exit \"$status\"; fi"]))?;
    checks.fails(
        "the sandbox has no ping and no raw sockets",
        "Operation not permitted|PermissionError",
        &mut compose.agent(&[
            "python3",
            "-c",
            "import socket; socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)",
        ]),
    )?;
    checks.ok(
        "the sandbox has no capabilities",
        "^CapEff:\\s+0+ $",
        &mut compose.agent(&["grep", "CapEff", "/proc/self/status"]),
    )?;
    checks.fails(
        "the sandbox cannot see the world socket",
        "No such file or directory",
        &mut compose.agent(&["ls", "/run/fictionet"]),
    )?;
    Ok(())
}

fn plain_upload(compose: &Compose, checks: &mut Checks) -> Result {
    checks.ok("a 64 MiB upload as a plain-HTTP request", "^67108864 $", &mut compose.agent(&["sh", "-c", "head -c 67108864 /dev/zero | curl -fsS --max-time 30 --data-binary @- http://plain.test/upload"]))?;
    Ok(())
}

fn requests(compose: &Compose, checks: &mut Checks) -> Result {
    checks.ok("1,000 HTTPS requests, 200 at a time, all 200", "^1000 $", &mut compose.agent(&["sh", "-c", "seq 1000 | xargs -P 200 -I{} curl -sS -o /dev/null -w '%{http_code}\\n' 'https://example.test/?{}' | grep -c '^200$'"]))?;
    Ok(())
}

fn no_proxy(compose: &Compose, checks: &mut Checks) -> Result {
    checks.fails(
        "and the sandbox has no way out at all",
        "Could not resolve proxy|Failed to connect|Couldn't connect",
        &mut compose.agent(&["curl", "-sS", "-m", "5", "https://example.test/"]),
    )?;
    Ok(())
}
