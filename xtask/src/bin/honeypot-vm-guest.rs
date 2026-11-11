//! PID one for the two isolated honeypot guests. Never run on the development host.

use std::{
    ffi::CString,
    fs,
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket},
    os::fd::{AsRawFd, FromRawFd},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use serde_json::{Value, json};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const DEVICE: &str = "0000:00:03.0";
const SENSOR: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const ATTACKER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
// Linux's MPTCP socket option level is distinct from its IP protocol number.
const SOL_MPTCP: libc::c_int = 284;
/// The first SSH command; the honeypot must log it and hang up without running it.
const SSH_COMMAND: &[u8] = b"whoami\n";

fn mount(source: &str, target: &str, kind: &str, options: &str) -> Result {
    let source = CString::new(source)?;
    let target = CString::new(target)?;
    let kind = CString::new(kind)?;
    let options = CString::new(options)?;
    // SAFETY: all mount arguments point to live terminated strings.
    if unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            kind.as_ptr(),
            0,
            options.as_ptr().cast(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn initialize(guest: &mut bool) -> Result<bool> {
    if std::process::id() != 1 {
        return Err("requires PID one in an explicitly marked QEMU guest".into());
    }
    mount("proc", "/proc", "proc", "")?;
    mount("sysfs", "/sys", "sysfs", "")?;
    let cmdline = fs::read_to_string("/proc/cmdline")?;
    let role = cmdline
        .split_whitespace()
        .find_map(|arg| arg.strip_prefix("fictionet.honeypot="));
    if fs::read_to_string("/sys/class/dmi/id/sys_vendor")?.trim() != "QEMU"
        || !matches!(role, Some("sensor" | "attacker"))
        || !cmdline
            .split_whitespace()
            .any(|arg| arg == "fictionet.rawnic=1")
    {
        return Err("requires explicit honeypot QEMU guest boot tokens".into());
    }
    *guest = true;
    mount("devtmpfs", "/dev", "devtmpfs", "")?;
    for index in 0.. {
        let path = format!("/modules/{index}");
        if !Path::new(&path).exists() {
            break;
        }
        let bytes = fs::read(path)?;
        // SAFETY: the module buffer is live for its entire length; arguments are terminated.
        if unsafe {
            libc::syscall(
                libc::SYS_init_module,
                bytes.as_ptr(),
                bytes.len(),
                c"".as_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
    }
    mount(
        "artifacts",
        "/share",
        "9p",
        "trans=virtio,version=9p2000.L,cache=none",
    )?;
    interface_up("lo")?;
    Ok(role == Some("attacker"))
}

fn interface(name: &str) -> libc::ifreq {
    // SAFETY: ifreq contains only integer fields and unions with valid zero representations.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (dst, src) in request.ifr_name.iter_mut().zip(name.bytes()) {
        *dst = src as libc::c_char;
    }
    request
}

fn interface_up(name: &str) -> Result {
    let control = UdpSocket::bind("0.0.0.0:0")?;
    let mut request = interface(name);
    // SAFETY: the descriptor and writable ifreq are live, and the interface name is terminated.
    if unsafe { libc::ioctl(control.as_raw_fd(), libc::SIOCGIFFLAGS, &mut request) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: the preceding successful ioctl initialized the flags union member.
    unsafe {
        request.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
    }
    // SAFETY: the request now contains valid interface flags.
    if unsafe { libc::ioctl(control.as_raw_fd(), libc::SIOCSIFFLAGS, &request) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn network() -> Result {
    // Only the attacker guest gives its dedicated data device a kernel address.
    fs::write("/proc/sys/net/ipv6/conf/eth0/disable_ipv6", "1")?;
    let control = UdpSocket::bind("0.0.0.0:0")?;
    for (operation, address) in [
        (libc::SIOCSIFADDR, ATTACKER),
        (libc::SIOCSIFNETMASK, Ipv4Addr::new(255, 255, 255, 0)),
    ] {
        let mut request = interface("eth0");
        let mut data = [0; 14];
        for (byte, octet) in data[2..6].iter_mut().zip(address.octets()) {
            *byte = octet as libc::c_char;
        }
        request.ifr_ifru.ifru_addr = libc::sockaddr {
            sa_family: libc::AF_INET as libc::sa_family_t,
            sa_data: data,
        };
        // SAFETY: the descriptor and complete ifreq with an IPv4 address are live.
        if unsafe { libc::ioctl(control.as_raw_fd(), operation, &request) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
    }
    interface_up("eth0")?;
    // This on-link route reaches only the private simulated hosts on the data NIC.
    // SAFETY: a zeroed rtentry has valid null pointers and scalar fields.
    let mut route: libc::rtentry = unsafe { std::mem::zeroed() };
    for (field, address) in [
        (&mut route.rt_dst, Ipv4Addr::new(10, 44, 0, 0)),
        (&mut route.rt_genmask, Ipv4Addr::new(255, 255, 255, 0)),
    ] {
        field.sa_family = libc::AF_INET as libc::sa_family_t;
        for (byte, octet) in field.sa_data[2..6].iter_mut().zip(address.octets()) {
            *byte = octet as libc::c_char;
        }
    }
    route.rt_gateway.sa_family = libc::AF_INET as libc::sa_family_t;
    route.rt_flags = libc::RTF_UP;
    let device = CString::new("eth0")?;
    route.rt_dev = device.as_ptr().cast_mut();
    // SAFETY: the control socket, route and its device name remain live during ioctl.
    if unsafe { libc::ioctl(control.as_raw_fd(), libc::SIOCADDRT, &route) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn isolation(attacker: bool) -> Result {
    let mut interfaces: Vec<_> = fs::read_dir("/sys/class/net")?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<io::Result<_>>()?;
    interfaces.sort();
    let expected = if attacker {
        vec!["eth0", "lo"]
    } else {
        vec!["lo"]
    };
    if interfaces != expected {
        return Err(format!("unexpected network interfaces: {interfaces:?}").into());
    }
    let mut nics = Vec::new();
    for entry in fs::read_dir("/sys/bus/pci/devices")? {
        let entry = entry?;
        if fs::read_to_string(entry.path().join("class"))?
            .trim()
            .starts_with("0x02")
        {
            nics.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    if nics != [DEVICE] {
        return Err(format!("unexpected PCI network devices: {nics:?}").into());
    }
    let routes = fs::read_to_string("/proc/net/route")?;
    let rows: Vec<_> = routes
        .lines()
        .skip(1)
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .collect();
    if (attacker
        && (rows.len() != 2
            || !["000200C0", "00002C0A"].iter().all(|destination| {
                rows.iter().any(|row| {
                    row[0] == "eth0"
                        && row[1] == *destination
                        && row[2] == "00000000"
                        && row[7] == "00FFFFFF"
                })
            })))
        || (!attacker && !rows.is_empty())
    {
        return Err(format!("unexpected guest routes: {routes}").into());
    }
    let routes_v6 = fs::read_to_string("/proc/net/ipv6_route")?;
    let mut failures = Vec::new();
    for target in ["1.1.1.1:443", "[2606:4700:4700::1111]:443"] {
        let target: SocketAddr = target.parse()?;
        let error = TcpStream::connect_timeout(&target, Duration::from_secs(2))
            .err()
            .ok_or("external connection unexpectedly succeeded")?;
        if error.raw_os_error() != Some(libc::ENETUNREACH) {
            return Err(format!("external route was not absent: {target}: {error}").into());
        }
        failures.push(json!({"target": target, "errno": libc::ENETUNREACH}));
    }
    let driver = fs::read_link(format!("/sys/bus/pci/devices/{DEVICE}/driver"))?;
    let expected_driver = if attacker { "virtio-pci" } else { "vfio-pci" };
    if driver.file_name().and_then(|s| s.to_str()) != Some(expected_driver) {
        return Err("unexpected guest data device driver".into());
    }
    let report = json!({"interfaces": interfaces, "pci_network_devices": nics,
        "driver": expected_driver, "ipv4_routes": routes, "ipv6_routes": routes_v6,
        "external_connect": failures, "kernel": fs::read_to_string("/proc/sys/kernel/osrelease")?.trim()});
    fs::write("/share/isolation.json", serde_json::to_vec_pretty(&report)?)?;
    println!("Guest isolation: {report}");
    Ok(())
}

fn wait_file(path: &str) -> Result {
    let deadline = Instant::now() + Duration::from_secs(120);
    while !Path::new(path).exists() {
        if Instant::now() >= deadline {
            return Err(format!("timed out awaiting {path}").into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

fn sensor() -> Result {
    let path = format!("/sys/bus/pci/devices/{DEVICE}");
    if fs::read_to_string(format!("{path}/vendor"))?.trim() != "0x1af4"
        || fs::read_to_string(format!("{path}/device"))?.trim() != "0x1041"
    {
        return Err("unexpected sensor PCI device".into());
    }
    if Path::new(&format!("{path}/driver")).exists() {
        fs::write(format!("{path}/driver/unbind"), DEVICE)?;
    }
    fs::write(format!("{path}/driver_override"), "vfio-pci")?;
    fs::write("/sys/bus/pci/drivers_probe", DEVICE)?;
    let group = fs::read_link(format!("{path}/iommu_group"))?;
    println!("Sensor VFIO IOMMU group: {}", group.display());
    isolation(false)?;
    let log = fs::File::create("/share/honeypot.log")?;
    let mut child = Command::new("/honeypot")
        .args([
            "run",
            "--backend",
            "vfio",
            "--device",
            DEVICE,
            "--address",
            "192.0.2.2",
            "--gateway",
            "192.0.2.1",
            "--state-dir",
            "/share/state",
            "--ssh",
            "22",
            "--http",
            "80",
            "--mcp",
            "8081",
            "--a2a",
            "8082",
            "--fleet",
            "8083",
        ])
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(360);
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(format!("honeypot exited before stop: {status}").into());
        }
        if Path::new("/share/stop").exists() {
            break;
        }
        if Instant::now() >= deadline {
            return Err("honeypot stop deadline expired".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    // SAFETY: this is the unreaped child spawned above in this explicitly gated guest.
    if unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                return Err(format!("honeypot shutdown failed: {status}").into());
            }
            break;
        }
        if Instant::now() >= deadline {
            return Err("honeypot failed to drain and stop".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    isolation(false)?;
    Ok(())
}

fn socket(protocol: libc::c_int) -> Result<TcpStream> {
    // SAFETY: socket takes scalar constants and returns a new owned descriptor.
    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            protocol,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: the successful socket call returned an exclusively owned stream descriptor.
    let stream = unsafe { TcpStream::from_raw_fd(fd) };
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    Ok(stream)
}

fn connect(stream: &TcpStream, port: u16) -> io::Result<()> {
    connect_address(stream, SENSOR, port)
}

fn connect_address(stream: &TcpStream, destination: Ipv4Addr, port: u16) -> io::Result<()> {
    let address = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(destination.octets()),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: the live socket and complete sockaddr_in match the supplied address length.
    if unsafe {
        libc::connect(
            stream.as_raw_fd(),
            (&address as *const libc::sockaddr_in).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn mptcp() -> Result<Value> {
    use fictionet::stdlib::codec::Stream;
    use fictionet::stdlib::protocols::http1::{Event, ResponseEvents};
    let mut stream = socket(libc::IPPROTO_MPTCP)?;
    connect(&stream, 80)?;
    let source = stream.local_addr()?;
    if source.ip() != ATTACKER {
        return Err("MPTCP used an unexpected source address".into());
    }
    let request = b"GET / HTTP/1.1\r\nHost: 192.0.2.2\r\nConnection: close\r\n\r\n";
    stream.write_all(request)?;
    let mut decoder = Stream::new(ResponseEvents::new());
    let mut response = Vec::new();
    let mut done = false;
    while !done {
        let mut bytes = [0; 4096];
        let count = stream.read(&mut bytes)?;
        if count == 0 {
            return Err("MPTCP closed before a complete HTTP response".into());
        }
        response.extend_from_slice(&bytes[..count]);
        if response.len() > 1024 * 1024 {
            return Err("HTTP response exceeded bound".into());
        }
        let mut remaining = &bytes[..count];
        while !remaining.is_empty() {
            let used = decoder.push(remaining);
            remaining = &remaining[used..];
            let mut progress = used != 0;
            while let Some(event) = decoder.next() {
                progress = true;
                if matches!(event?, Event::Done) {
                    done = true;
                }
            }
            if !progress {
                return Err("HTTP decoder made no progress".into());
            }
        }
    }
    if !response.starts_with(b"HTTP/1.1 200")
        || !String::from_utf8_lossy(&response).contains("Caddy")
    {
        return Err("MPTCP did not receive the Caddy HTTP page".into());
    }
    // Linux MPTCP_INFO starts with eight byte fields, flags, then the local token.
    let mut info = [0u8; 256];
    let mut length = info.len() as libc::socklen_t;
    // SAFETY: the socket, output buffer and in/out length are live and large enough.
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            SOL_MPTCP,
            1,
            info.as_mut_ptr().cast(),
            &mut length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    if length < 16 {
        return Err("truncated kernel MPTCP_INFO".into());
    }
    let flags = u32::from_ne_bytes(info[8..12].try_into()?);
    let token = u32::from_ne_bytes(info[12..16].try_into()?);
    if flags & 1 != 0 || flags & 2 == 0 {
        return Err("kernel MPTCP fell back or received no remote key".into());
    }
    fs::write("/share/http.response", &response)?;
    let report = json!({"source": source, "destination": "192.0.2.2:80",
        "protocol": libc::IPPROTO_MPTCP, "flags": flags, "local_token": format!("{token:08x}"),
        "request_bytes": request.len(), "response_bytes": response.len()});
    println!("Kernel MPTCP: {report}");
    Ok(report)
}

fn ssh() -> Result {
    fs::write("/etc/passwd", "root:x:0:0:root:/:/bin/sh\n")?;
    fs::write("/etc/group", "root:x:0:\n")?;
    let key = Command::new("/ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f", "/client-key"])
        .output()?;
    if !key.status.success() {
        return Err(format!("ssh-keygen: {}", String::from_utf8_lossy(&key.stderr)).into());
    }
    let log = fs::File::create("/share/ssh.log")?;
    let mut child = Command::new("/ssh")
        .args([
            "-v",
            "-T",
            "-F",
            "/dev/null",
            "-i",
            "/client-key",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=10",
            "ubuntu@192.0.2.2",
        ])
        .env_remove("SSH_AUTH_SOCK")
        .stdin(Stdio::piped())
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("missing SSH stdin")?
        .write_all(SSH_COMMAND)?;
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err("SSH did not disconnect after its first command".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    if status.code() != Some(255) {
        return Err(format!("SSH did not disconnect: {status}").into());
    }
    Ok(())
}

fn trap_request(port: u16, method: &str, path: &str, headers: &str, body: &str) -> Result<String> {
    let started = Instant::now();
    let mut stream = socket(libc::IPPROTO_TCP)?;
    connect(&stream, port)?;
    stream.set_read_timeout(Some(Duration::from_secs(170)))?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: 192.0.2.2\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{headers}\r\n{body}",
        body.len()
    )?;
    let mut first = [0];
    stream.read_exact(&mut first)?;
    if path == "/retry" && started.elapsed() < Duration::from_secs(150) {
        return Err("held retry sent bytes before its silent interval ended".into());
    }
    let mut response = first.to_vec();
    stream.take(1024 * 1024 - 1).read_to_end(&mut response)?;
    if response.len() == 1024 * 1024 {
        return Err("trap response exceeded bound".into());
    }
    Ok(String::from_utf8(response)?)
}

fn trap_json(response: &str) -> Result<Value> {
    let (_, body) = response.split_once("\r\n\r\n").ok_or("missing HTTP head")?;
    Ok(serde_json::from_str(body)?)
}

fn trap_rpc(
    port: u16,
    path: &str,
    headers: &str,
    method: &str,
    params: Value,
) -> Result<(String, Value)> {
    let response = trap_request(
        port,
        "POST",
        path,
        headers,
        &json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params}).to_string(),
    )?;
    let value = trap_json(&response)?;
    Ok((response, value))
}

fn declarations() -> Result<String> {
    let params = json!({"capabilities":{"sampling":{"model":"laboratory/protocol-model-9"}},
        "clientInfo":{"name":"scripted-kernel-client","version":"1"}, "protocolVersion":"2025-03-26"});
    let (first, rejected) = trap_rpc(8081, "/mcp", "", "initialize", params.clone())?;
    if rejected["error"].is_null() {
        return Err("first MCP declaration bypassed retry gate".into());
    }
    let session = first
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("mcp-session-id")
                .then(|| value.trim().to_owned())
        })
        .ok_or("MCP rejection omitted session identifier")?;
    let headers = format!("Mcp-Session-Id: {session}\r\n");
    let (_, accepted) = trap_rpc(8081, "/mcp", &headers, "initialize", params)?;
    if !accepted["error"].is_null() || accepted["result"].is_null() {
        return Err("second MCP declaration did not open session".into());
    }
    Ok(headers)
}

fn trap_reviews() -> Result<Value> {
    let headers = declarations()?;
    let (_, mut reply) = trap_rpc(
        8081,
        "/mcp",
        &headers,
        "tools/call",
        json!({"name":"deploy_bundle","arguments":{"site":"alpha"}}),
    )?;
    let mut previous = String::new();
    for stage in 0..3 {
        let request = reply["result"]["sampling"]["request"]
            .as_str()
            .ok_or("missing sampling request")?
            .to_owned();
        let arguments = |text: &str| json!({"name":"complete_sampling","arguments":{"request":request,"model":"laboratory/protocol-model-9","content":{"text":text}}});
        let (_, short) = trap_rpc(8081, "/mcp", &headers, "tools/call", arguments("short"))?;
        if short["error"].is_null() {
            return Err("short approval bypassed prose gate".into());
        }
        if !previous.is_empty() {
            let (_, repeated) =
                trap_rpc(8081, "/mcp", &headers, "tools/call", arguments(&previous))?;
            if repeated["error"].is_null() {
                return Err("repeated approval bypassed prose gate".into());
            }
        }
        previous = format!(
            "Deployment section {stage}: the operator will verify the edge host, notify the control room, preserve the previous release and document the result before closing the change window."
        );
        (_, reply) = trap_rpc(8081, "/mcp", &headers, "tools/call", arguments(&previous))?;
        if !reply["error"].is_null() {
            return Err("original approval was refused".into());
        }
    }
    if !reply["result"]["sampling"].is_null() || reply["result"]["content"].as_array().is_none() {
        return Err("MCP payout missing".into());
    }
    let card = trap_json(&trap_request(
        8082,
        "GET",
        "/.well-known/agent-card.json",
        "",
        "",
    )?)?;
    if card["skills"].as_array().is_none() {
        return Err("A2A card missing skills".into());
    }
    let mut headers = String::new();
    for stage in 0..4 {
        let text = format!(
            "Review section {stage}: the engineer will confirm the maintenance window and gateway readiness, keep a verified backout copy, notify the affected operators and record the deployment outcome."
        );
        let (response, reply) = trap_rpc(
            8082,
            "/a2a",
            &headers,
            "message/send",
            json!({"message":{"metadata":{"model":"laboratory/protocol-model-9","runtime":"scripted-kernel-client"},"parts":[{"kind":"text","text":text}]}}),
        )?;
        if !reply["error"].is_null() {
            return Err("A2A review refused".into());
        }
        let session = response
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("x-session-id")
                    .then(|| value.trim())
            })
            .ok_or("A2A session missing")?;
        headers = format!("X-Session-Id: {session}\r\n");
        if stage == 3
            && !reply["result"]["parts"][0]["text"]
                .as_str()
                .unwrap_or("")
                .contains("Approved")
        {
            return Err("A2A payout missing".into());
        }
    }
    Ok(json!({"mcp_completions":3,"a2a_sections":4,"short_refused":3,"repeated_refused":2}))
}

fn private_hosts() -> Result<Value> {
    let dns = UdpSocket::bind((ATTACKER, 0))?;
    dns.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut query = vec![0x43, 0x19, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["change", "northbank", "internal"] {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    dns.send_to(&query, (SENSOR, 53))?;
    let mut answer = [0; 2048];
    let (count, source) = dns.recv_from(&mut answer)?;
    if source != SocketAddr::from((SENSOR, 53))
        || count < 12
        || answer[..2] != query[..2]
        || answer[2] & 0x80 == 0
        || answer[3] & 15 != 0
        || u16::from_be_bytes([answer[6], answer[7]]) == 0
        || !answer[..count]
            .windows(4)
            .any(|bytes| bytes == [10, 44, 0, 12])
    {
        return Err("private DNS answer did not resolve the change desk".into());
    }
    let mut stream = socket(libc::IPPROTO_TCP)?;
    connect_address(&stream, Ipv4Addr::new(10, 44, 0, 12), 80)?;
    stream.write_all(b"GET /.well-known/agent-card.json HTTP/1.1\r\nHost: change.northbank.internal\r\nConnection: close\r\n\r\n")?;
    let mut response = String::new();
    stream.take(65536).read_to_string(&mut response)?;
    if !response.starts_with("HTTP/1.1 200") || trap_json(&response)?["skills"].as_array().is_none()
    {
        return Err("private change desk did not serve its agent card".into());
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let response = reqwest::Client::builder()
            .no_proxy()
            .http1_only()
            .resolve(
                "change.northbank.internal",
                SocketAddr::from((Ipv4Addr::new(10, 44, 0, 12), 443)),
            )
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(15))
            .build()?
            .get("https://change.northbank.internal/.well-known/agent-card.json")
            .send()
            .await?;
        if response.status() != reqwest::StatusCode::OK {
            return Err::<(), Box<dyn std::error::Error>>(
                "private TLS change desk refused request".into(),
            );
        }
        let card: Value = serde_json::from_str(&response.text().await?)?;
        if card["skills"].as_array().is_none() {
            return Err("private TLS agent card missing skills".into());
        }
        Ok(())
    })?;
    Ok(
        json!({"dns":"change.northbank.internal","address":"10.44.0.12","http_status":200,"tls_status":200}),
    )
}

fn fleet() -> Result<Value> {
    let logs = trap_json(&trap_request(8083, "GET", "/logs", "", "")?)?;
    let environment = logs["environment"]
        .as_str()
        .ok_or("fleet environment missing")?;
    let mut credentials = Vec::new();
    for line in environment.lines() {
        let (name, value) = line.split_once('=').ok_or("invalid fleet environment")?;
        let credential = if name == "DEPLOY_URL" {
            value
                .split_once("https://deploy:")
                .and_then(|(_, v)| v.split_once('@'))
                .map(|(v, _)| v)
                .ok_or("missing URL password")?
        } else {
            value
        };
        let response = trap_request(
            8083,
            "GET",
            "/bundle",
            &format!("Authorization: Bearer {credential}\r\n"),
            "",
        )?;
        if !response.starts_with("HTTP/1.1 200")
            || trap_json(&response)?["deploy_key"].as_str().is_none()
        {
            return Err("intact fleet credential refused".into());
        }
        credentials.push(credential.to_owned());
    }
    if credentials.len() != 3 {
        return Err("expected three credential shapes".into());
    }
    let credential = &credentials[0];
    let masked = format!(
        "{}...{}",
        &credential[..6],
        &credential[credential.len() - 4..]
    );
    if !trap_request(
        8083,
        "GET",
        "/bundle",
        &format!("Authorization: Bearer {masked}\r\n"),
        "",
    )?
    .starts_with("HTTP/1.1 401")
    {
        return Err("masked credential authorized".into());
    }
    let headers = format!("Authorization: Bearer {credential}\r\n");
    let mut abandoned = socket(libc::IPPROTO_TCP)?;
    connect(&abandoned, 8083)?;
    write!(
        abandoned,
        "POST /retry HTTP/1.1\r\nHost: 192.0.2.2\r\nContent-Length: 0\r\n{headers}\r\n"
    )?;
    abandoned.shutdown(std::net::Shutdown::Both)?;
    drop(abandoned);
    let started = Instant::now();
    let results = std::thread::scope(|scope| {
        let mut jobs = Vec::new();
        for (method, path) in [
            ("POST", "/retry"),
            ("GET", "/logs/follow"),
            ("GET", "/hosts/alpha/check"),
            ("GET", "/hosts/beta/check"),
            ("GET", "/hosts/gamma/check"),
            ("GET", "/hosts/delta/check"),
        ] {
            let headers = &headers;
            jobs.push(scope.spawn(move || {
                let start = Instant::now();
                let response =
                    trap_request(8083, method, path, headers, "").map_err(|e| e.to_string())?;
                if !response.starts_with("HTTP/1.1 200") {
                    return Err(format!("probe refused: {path}"));
                }
                if path == "/logs/follow"
                    && (!response.contains("\"elapsed\":45")
                        || !response.contains("\"elapsed\":90"))
                {
                    return Err("trickle stream omitted ticks".to_owned());
                }
                Ok::<_, String>((path, start.elapsed().as_millis() as u64))
            }));
        }
        jobs.into_iter()
            .map(|job| {
                job.join()
                    .map_err(|_| "fleet probe thread panicked".to_owned())?
            })
            .collect::<std::result::Result<Vec<_>, String>>()
    })?;
    for (path, elapsed) in &results {
        let minimum = if *path == "/retry" || *path == "/logs/follow" {
            150000
        } else {
            2000
        };
        if *elapsed < minimum {
            return Err(format!("probe answered early: {path} after {elapsed} ms").into());
        }
    }
    Ok(
        json!({"credential_shapes":credentials.len(),"masked_refused":true,"probes":results,"elapsed_ms":started.elapsed().as_millis()}),
    )
}

fn attacker() -> Result {
    network()?;
    isolation(true)?;
    wait_file("/share/start")?;
    if fs::read_to_string("/proc/sys/net/mptcp/enabled")?.trim() != "1" {
        return Err("guest kernel MPTCP is disabled".into());
    }
    let mptcp = mptcp()?;
    ssh()?;
    let private_hosts = private_hosts()?;
    let reviews = trap_reviews()?;
    let fleet = fleet()?;
    let zero = socket(libc::IPPROTO_TCP)?;
    let error = connect(&zero, 0)
        .err()
        .ok_or("port zero unexpectedly accepted TCP")?;
    if error.raw_os_error() != Some(libc::ECONNREFUSED) {
        return Err(format!("port zero did not return a TCP refusal: {error}").into());
    }
    let report = json!({"mptcp": mptcp, "port_zero": {"destination": "192.0.2.2:0",
        "protocol": libc::IPPROTO_TCP, "errno": libc::ECONNREFUSED},
        "ssh": {"exit_code": 255, "sent_input_bytes": SSH_COMMAND.len()}, "reviews":reviews,"fleet":fleet,"private_hosts":private_hosts});
    fs::write("/share/probes.json", serde_json::to_vec_pretty(&report)?)?;
    isolation(true)?;
    Ok(())
}

fn main() {
    let mut guest = false;
    let result = initialize(&mut guest)
        .and_then(|is_attacker| if is_attacker { attacker() } else { sensor() });
    if let Err(error) = &result {
        eprintln!("Honeypot guest failed: {error}");
    }
    if guest {
        // SAFETY: the marked QEMU guest exposes its exit device at this port.
        unsafe {
            libc::sync();
            if libc::ioperm(0xf4, 4, 1) == 0 {
                std::arch::asm!("out dx, eax", in("dx") 0xf4u16, in("eax") 42 + u32::from(result.is_err()));
            }
            libc::reboot(libc::RB_POWER_OFF);
        }
    }
    std::process::exit(1);
}
