use super::*;

pub fn run() -> Result {
    let kube = Kube {
        namespace: "default",
        pod: "fictionet-sandbox-fntest-default-0",
        container: "default",
    };
    execute(&mut helm(&[
        "uninstall",
        "fntest",
        "--ignore-not-found",
        "--wait",
    ]))?;
    let mut cleanup = Cleanup::default();
    cleanup.push(helm(&[
        "uninstall",
        "fntest",
        "--ignore-not-found",
        "--wait",
    ]));
    let result = (|| {
        execute(&mut helm(&[
            "install",
            "fntest",
            "charts/fictionet-sandbox",
            "-f",
            "examples/attach/k8s-tun.yaml",
            "--wait",
            "--timeout",
            "180s",
        ]))?;
        let mut checks = Checks::default();
        initial(&kube, &mut checks)?;
        isolation(&kube, &mut checks)?;
        let attach = kube.field(
            "{.status.initContainerStatuses[?(@.name==\"attach\")].state.running.startedAt}",
        )?;
        let agent = kube
            .field("{.status.containerStatuses[?(@.name==\"default\")].state.running.startedAt}")?;
        checks.require(
            "the agent started no earlier than attach",
            !attach.is_empty() && !agent.is_empty() && agent >= attach,
            format!("attach {attach}, agent {agent}"),
        );
        ready(&kube, &mut checks)?;
        kube.stop_attach()?;
        stopped(&kube, &mut checks)?;
        kube.restart(&mut checks)?;
        restored(&kube, &mut checks)?;
        // Inspect's sandbox uses the current Kubernetes context.
        execute(&mut cmd("kubectl", &["config", "use-context", CONTEXT]))?;
        checks.ok(
            "the Inspect eval passes",
            r"accuracy +1\.0",
            &mut crate::eval::uv(&[
                "--extra",
                "k8s",
                "inspect",
                "eval",
                "tests/k8s/inspect_eval.py",
                "--model",
                "mockllm/model",
                "--display",
                "plain",
                "--log-dir",
                "target/inspect-logs",
            ]),
        )?;
        checks.finish()
    })();
    cleanup.finish(result)
}

fn initial(kube: &Kube, checks: &mut Checks) -> Result {
    checks.ok(
        "the agent is uid 1000",
        "^uid=1000",
        &mut kube.agent(&["id"]),
    )?;
    checks.ok(
        "the agent's process 1 is its own command",
        "^sleep infinity +$",
        &mut kube.agent(&["sh", "-c", "tr \"\\0\" \" \" < /proc/1/cmdline"]),
    )?;
    checks.ok("the agent sees no process of attach or the world", "^0 $", &mut kube.agent(&["bash", "-e", "-o", "pipefail", "-c", "cmdlines=$(cat /proc/[0-9]*/cmdline | tr \"\\0\" \" \"); printf \"%s\\n\" \"$cmdlines\" | awk \"/fictione[t]|web_worl[d]/ { n++ } END { print n+0 }\""]))?;
    checks.ok(
        "the agent's memory is limited to 2 GiB",
        "^2147483648 $",
        &mut kube.agent(&["cat", "/sys/fs/cgroup/memory.max"]),
    )?;
    checks.ok(
        "the agent's CPU is limited to 1",
        "^100000 100000 $",
        &mut kube.agent(&["cat", "/sys/fs/cgroup/cpu.max"]),
    )?;
    checks.ok(
        "with tun, there is no wait-blocked",
        "^world attach ?$",
        &mut kubectl(&[
            "get",
            "pod",
            kube.pod,
            "-o",
            "jsonpath={.spec.initContainers[*].name}",
        ]),
    )?;
    checks.ok(
        "eth0 is down",
        "eth0@[^ ]+ +DOWN",
        &mut kube.agent(&["ip", "-br", "link", "show", "eth0"]),
    )?;
    checks.ok(
        "eth0 has no address",
        "^eth0@[^ ]+ +DOWN +$",
        &mut kube.agent(&["ip", "-br", "addr", "show", "eth0"]),
    )?;
    checks.ok("the only default route is tun0's", "^default via 10\\.0\\.0\\.1 dev tun0 proto static onlink +$", &mut kube.agent(&["sh", "-ec", "v4=$(ip route show table all); v6=$(ip -6 route show table all); printf \"%s\\n\" \"$v4\" \"$v6\" | awk \"/^default|dev eth0/\""]))?;
    checks.ok(
        "resolv.conf names only the world",
        "^nameserver 10\\.0\\.0\\.1 options ndots:1 $",
        &mut kube.agent(&["cat", "/etc/resolv.conf"]),
    )?;
    checks.ok(
        "the world answers DNS",
        "^203\\.0\\.113\\.10 $",
        &mut kube.agent(&["dig", "+short", "example.test"]),
    )?;
    checks.ok(
        "https to the world's site",
        "^hello from https example.test 443 over HTTP/2.0 $",
        &mut kube.agent(&[
            "curl",
            "-sS",
            "--cacert",
            "/run/ca/ca.pem",
            "https://example.test/",
        ]),
    )?;
    Ok(())
}

fn isolation(kube: &Kube, checks: &mut Checks) -> Result {
    let kube_dns = capture(&mut kubectl(&[
        "-n",
        "kube-system",
        "get",
        "service",
        "kube-dns",
        "-o",
        "jsonpath={.spec.clusterIP}",
    ]))?;
    let api = capture(&mut kubectl(&[
        "get",
        "service",
        "kubernetes",
        "-o",
        "jsonpath={.spec.clusterIP}",
    ]))?;
    checks.fails(
        "1.1.1.1 is unreachable",
        "Couldn't connect to server",
        &mut kube.agent(&["curl", "-sS", "-m", "5", "http://1.1.1.1/"]),
    )?;
    checks.fails(
        "the cluster's DNS ($kube_dns) is unreachable",
        "no servers could be reached",
        &mut kube.agent(&[
            "dig",
            "+time=2",
            "+tries=1",
            &format!("@{kube_dns}"),
            "kubernetes.default.svc.cluster.local",
        ]),
    )?;
    checks.fails(
        "the API server ($api) is unreachable",
        "Couldn't connect to server",
        &mut kube.agent(&[
            "curl",
            "-sS",
            "-m",
            "5",
            "-k",
            &format!("https://{api}/version"),
        ]),
    )?;
    checks.fails(
        "ip link set eth0 up is refused",
        "Operation not permitted",
        &mut kube.agent(&["ip", "link", "set", "eth0", "up"]),
    )?;
    checks.fails(
        "ip route add is refused",
        "Operation not permitted",
        &mut kube.agent(&["ip", "route", "add", "1.1.1.1", "dev", "eth0"]),
    )?;
    checks.fails(
        "the world's socket is not in the agent's container",
        "No such file or directory",
        &mut kube.agent(&["ls", "/run/relay"]),
    )?;
    Ok(())
}

fn ready(kube: &Kube, checks: &mut Checks) -> Result {
    checks.ok(
        "attach is ready",
        "^true ?$",
        &mut kubectl(&[
            "get",
            "pod",
            kube.pod,
            "-o",
            "jsonpath={.status.initContainerStatuses[?(@.name==\"attach\")].ready}",
        ]),
    )?;
    checks.ok(
        "attach made /dev/net/tun and took eth0 down",
        "eth0 is down.*made /dev/net/tun.*attached as tun0",
        &mut kubectl(&["logs", kube.pod, "-c", "attach"]),
    )?;
    Ok(())
}

fn stopped(kube: &Kube, checks: &mut Checks) -> Result {
    checks.ok("with attach stopped, tun0 is gone", "^0 $", &mut kube.agent(&["sh", "-ec", "links=$(ip -br link); printf \"%s\\n\" \"$links\" | awk \"/tun0/ { n++ } END { print n+0 }\""]))?;
    checks.fails(
        "with attach stopped, nothing answers",
        "Could not resolve host",
        &mut kube.agent(&[
            "curl",
            "-sS",
            "-m",
            "3",
            "--cacert",
            "/run/ca/ca.pem",
            "https://example.test/",
        ]),
    )?;
    Ok(())
}

fn restored(kube: &Kube, checks: &mut Checks) -> Result {
    checks.ok(
        "after the restart, https works again",
        "^hello from https example.test 443",
        &mut kube.agent(&[
            "curl",
            "-sS",
            "--cacert",
            "/run/ca/ca.pem",
            "https://example.test/",
        ]),
    )?;
    Ok(())
}
