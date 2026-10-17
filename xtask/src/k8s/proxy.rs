use super::*;
use crate::process::{combined, input};
use regex::Regex;

pub fn run() -> Result {
    let kube = Kube {
        namespace: "fictionet-restricted",
        pod: "fictionet-sandbox-fnproxy-default-0",
        container: "default",
    };
    execute(&mut kubectl(&[
        "delete",
        "namespace",
        kube.namespace,
        "--ignore-not-found",
        "--wait",
    ]))?;
    execute(&mut kubectl(&["create", "namespace", kube.namespace]))?;
    let mut cleanup = Cleanup::default();
    cleanup.push(kubectl(&[
        "delete",
        "namespace",
        kube.namespace,
        "--ignore-not-found",
        "--wait=false",
    ]));
    let result = (|| {
        execute(&mut kubectl(&[
            "label",
            "namespace",
            kube.namespace,
            "pod-security.kubernetes.io/enforce=restricted",
            "pod-security.kubernetes.io/warn=restricted",
            "pod-security.kubernetes.io/audit=restricted",
        ]))?;
        let mut checks = Checks::default();
        let output = install("fnproxy", kube.namespace, true, true).output()?;
        let output_text = combined(&output);
        checks.require(
            "helm installed the proxy release",
            output.status.success(),
            &output_text,
        );
        checks.require(
            "the proxy release is admitted under restricted with no warning",
            !output_text.to_lowercase().contains("podsecurity"),
            &output_text,
        );
        checks.ok(
            "both sandboxes run",
            "^Running Running ?$",
            &mut kube.command(&[
                "get",
                "pod",
                kube.pod,
                "fictionet-sandbox-fnproxy-socks-0",
                "-o",
                "jsonpath={.items[*].status.phase}",
            ]),
        )?;
        let pod = capture(&mut kube.command(&["get", "pod", kube.pod, "-o", "json"]))?;
        checks.require(
            "no container adds a capability or runs as root",
            !Regex::new(r#""add"|"runAsUser": 0|"privileged": true"#)?.is_match(&pod),
            &pod,
        );
        checks.require(
            "attach runs as the world's user with no capabilities",
            kube.field("{.spec.initContainers[?(@.name==\"attach\")].securityContext.runAsUser}")?
                == "65532",
            "expected uid 65532",
        );
        execute(&mut install("fntun", kube.namespace, false, false))?;
        let refused = Regex::new("violates PodSecurity \"restricted:latest\".*NET_ADMIN")?;
        let mut events = String::new();
        let seen = poll(Duration::from_secs(60), Duration::from_secs(1), || {
            events = capture(&mut kube.command(&[
                "get",
                "events",
                "--field-selector",
                "reason=FailedCreate",
                "-o",
                "jsonpath={.items[*].message}",
            ]))?;
            Ok(refused.is_match(&events))
        })?;
        checks.require(
            "a tun release in the same namespace is refused",
            seen,
            &events,
        );
        execute(&mut helm(&["uninstall", "fntun", "-n", kube.namespace]))?;
        startup(&kube, &mut checks)?;
        limits(&kube, &mut checks)?;
        clients(&kube, &mut checks)?;
        isolation(&kube, &mut checks)?;
        tokens(&kube, &mut checks)?;
        checks.downloads("10 downloads of 16 MiB at once", 10, 16777216, &mut kube.agent(&["sh", "-c", "seq 10 | xargs -P 10 -I{} curl -fsS --max-time 30 -o /dev/null -w '%{size_download} %{time_total}\\n' https://example.test/big"]))?;
        checks.transfer(
            "16 MiB through the proxy",
            16777216,
            &mut kube.agent(&[
                "curl",
                "-fsS",
                "--max-time",
                "30",
                "-o",
                "/dev/null",
                "-w",
                "%{size_download} %{speed_download}",
                "https://example.test/big",
            ]),
            false,
        )?;
        logged(&kube, &mut checks)?;
        kube.stop_attach()?;
        stopped(&kube, &mut checks)?;
        kube.restart(&mut checks)?;
        restored(&kube, &mut checks)?;
        execute(&mut helm(&[
            "uninstall",
            "fnproxy",
            "-n",
            kube.namespace,
            "--wait",
        ]))?;
        checks.finish()
    })();
    cleanup.finish(result)
}

fn api() -> Result<String> {
    capture(&mut kubectl(&[
        "get",
        "service",
        "kubernetes",
        "-o",
        "jsonpath={.spec.clusterIP}",
    ]))
}

fn install(release: &str, namespace: &str, proxy: bool, wait: bool) -> Command {
    let mut command = helm(&[
        "install",
        release,
        "charts/fictionet-sandbox",
        "-n",
        namespace,
        "-f",
        if proxy {
            "examples/attach/k8s-proxy.yaml"
        } else {
            "examples/attach/k8s-tun.yaml"
        },
    ]);
    if proxy {
        command.args([
            "--set",
            "serviceDefaults.world.image=fictionet-web-fixture:dev",
        ]);
    }
    if wait {
        command.args(["--wait", "--timeout", "180s"]);
    }
    command
}

fn startup(kube: &Kube, checks: &mut Checks) -> Result {
    checks.ok(
        "wait-blocked exited 0 once the API server stopped answering",
        "unreachable 3 times in a row",
        &mut kube.logs("wait-blocked"),
    )?;
    let blocked = kube.field(
        "{.status.initContainerStatuses[?(@.name==\"wait-blocked\")].state.terminated.finishedAt}",
    )?;
    let agent =
        kube.field("{.status.containerStatuses[?(@.name==\"default\")].state.running.startedAt}")?;
    checks.require(
        "the agent started after wait-blocked exited",
        !blocked.is_empty() && !agent.is_empty() && agent >= blocked,
        format!("wait-blocked {blocked}, agent {agent}"),
    );
    let nopolicy = Kube {
        namespace: kube.namespace,
        pod: "fictionet-sandbox-fnnopolicy-default-0",
        container: "default",
    };
    execute(
        install("fnnopolicy", kube.namespace, true, false)
            .args(["--set", "networkPolicy.enabled=false"]),
    )?;
    let started = poll(Duration::from_secs(20), Duration::from_millis(200), || {
        let running = capture(&mut nopolicy.command(&["get", "pods", "--field-selector", &format!("metadata.name={}", nopolicy.pod), "-o", "jsonpath={.items[*].status.containerStatuses[0].state.running.startedAt}{.items[*].status.containerStatuses[0].state.terminated.startedAt}"]))?;
        Ok(!running.is_empty())
    })?;
    let logs = capture(&mut nopolicy.logs("wait-blocked"))?;
    checks.require(
        "with no NetworkPolicy, wait-blocked is still waiting",
        logs.contains("still reachable; waiting"),
        &logs,
    );
    checks.require(
        "with no NetworkPolicy, the agent has not started",
        !started
            && nopolicy.field("{.status.containerStatuses[0].state.waiting.reason}")?
                == "PodInitializing",
        "expected PodInitializing",
    );
    input(
        &mut kube.command(&["apply", "-f", "-"]),
        br#"apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: fnnopolicy-deny-all
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/instance: fnnopolicy
  policyTypes: [Ingress, Egress]
"#,
    )?;
    execute(&mut kube.command(&[
        "wait",
        "--for=condition=Ready",
        &format!("pod/{}", nopolicy.pod),
        "--timeout",
        "90s",
    ]))?;
    checks.require(
        "once a deny-all policy is applied, the agent starts",
        nopolicy.field("{.status.containerStatuses[0].ready}")? == "true",
        "expected ready",
    );
    checks.connect_fails(
        "its first try at the API server is blocked",
        "Couldn't connect|Connection timed out|Timeout was reached|Failed to connect",
        &mut nopolicy.agent(&[
            "curl",
            "-sS",
            "--noproxy",
            "*",
            "-m",
            "5",
            "-k",
            &format!("https://{}/version", api()?),
        ]),
    )?;
    execute(&mut helm(&[
        "uninstall",
        "fnnopolicy",
        "-n",
        kube.namespace,
    ]))?;
    execute(&mut kube.command(&["delete", "networkpolicy", "fnnopolicy-deny-all"]))?;
    Ok(())
}

fn limits(kube: &Kube, checks: &mut Checks) -> Result {
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
    Ok(())
}

fn clients(kube: &Kube, checks: &mut Checks) -> Result {
    let socks = Kube {
        namespace: kube.namespace,
        pod: "fictionet-sandbox-fnproxy-socks-0",
        container: "socks",
    };
    checks.ok(
        "the agent is uid 1000 with no capabilities",
        "^uid=1000.* CapEff:\\s+0+ $",
        &mut kube.agent(&["sh", "-c", "id; grep CapEff /proc/self/status"]),
    )?;
    checks.ok(
        "the chart set the proxy variables",
        "^https_proxy=http://relay:\\*\\*\\*@127\\.0\\.0\\.1:8080 $",
        &mut kube.agent(&[
            "sh",
            "-c",
            "echo \"https_proxy=$https_proxy\" | sed \"s/:[^:@]*@/:***@/\"",
        ]),
    )?;
    checks.ok(
        "https to the world's site through the HTTP door",
        "^hello from https example.test 443 over HTTP/2.0 $",
        &mut kube.agent(&["curl", "-sS", "https://example.test/"]),
    )?;
    checks.ok(
        "plain http through the HTTP door",
        "^plain site http plain.test 80 $",
        &mut kube.agent(&["curl", "-sS", "http://plain.test/k"]),
    )?;
    checks.ok(
        "https through the SOCKS5 door (ALL_PROXY)",
        "^hello from https example.test 443 over HTTP/2.0 $",
        &mut socks.agent(&["curl", "-sS", "https://example.test/"]),
    )?;
    Ok(())
}

fn isolation(kube: &Kube, checks: &mut Checks) -> Result {
    let api = api()?;
    let kube_dns = capture(&mut kubectl(&[
        "-n",
        "kube-system",
        "get",
        "service",
        "kube-dns",
        "-o",
        "jsonpath={.spec.clusterIP}",
    ]))?;
    let node_ip = capture(&mut kubectl(&[
        "get",
        "node",
        "fictionet-k8s-test-control-plane",
        "-o",
        "jsonpath={.status.addresses[?(@.type==\"InternalIP\")].address}",
    ]))?;
    let routes = capture(&mut kube.agent(&["ip", "-4", "route", "show", "default"]))?;
    let gateway = routes.split_whitespace().nth(2).ok_or("missing gateway")?;
    checks.ok(
        "the agent's eth0 is up, with the pod's address",
        "^eth0@[^ ]+ +UP +[0-9.]+/",
        &mut kube.agent(&["ip", "-br", "addr", "show", "eth0"]),
    )?;
    checks.fails(
        "names do not resolve in the pod",
        "Could not resolve host",
        &mut kube.agent(&[
            "curl",
            "-sS",
            "--noproxy",
            "*",
            "-m",
            "5",
            "https://example.test/",
        ]),
    )?;
    checks.connect_fails("1.1.1.1 is unreachable around the proxy", "Couldn't connect|Connection timed out|Timeout was reached|Connection refused|Failed to connect", &mut kube.agent(&["curl", "-sS", "--noproxy", "*", "-m", "5", "http://1.1.1.1/"]))?;
    checks.fails(
        "the cluster's DNS ($kube_dns) is unreachable",
        "no servers could be reached|timed out",
        &mut kube.agent(&[
            "dig",
            "+time=2",
            "+tries=1",
            &format!("@{kube_dns}"),
            "kubernetes.default.svc.cluster.local",
        ]),
    )?;
    checks.connect_fails(
        "the API server ($api) is unreachable around the proxy",
        "Couldn't connect|Connection timed out|Timeout was reached|Failed to connect",
        &mut kube.agent(&[
            "curl",
            "-sS",
            "--noproxy",
            "*",
            "-m",
            "5",
            "-k",
            &format!("https://{api}/version"),
        ]),
    )?;
    checks.connect_fails(
        "the kubelet on the pod's node ($node_ip) is unreachable",
        "Couldn't connect|Connection timed out|Timeout was reached|Failed to connect",
        &mut kube.agent(&[
            "curl",
            "-sS",
            "--noproxy",
            "*",
            "-m",
            "5",
            "-k",
            &format!("https://{node_ip}:10250/healthz"),
        ]),
    )?;
    checks.connect_fails(
        "the kubelet at the pod's gateway ($gateway) is unreachable",
        "Couldn't connect|Connection timed out|Timeout was reached|Failed to connect",
        &mut kube.agent(&[
            "curl",
            "-sS",
            "--noproxy",
            "*",
            "-m",
            "5",
            "-k",
            &format!("https://{gateway}:10250/healthz"),
        ]),
    )?;
    checks.fails(
        "the world's socket is not in the agent's container",
        "No such file or directory",
        &mut kube.agent(&["ls", "/run/relay"]),
    )?;
    Ok(())
}

fn tokens(kube: &Kube, checks: &mut Checks) -> Result {
    let api = api()?;
    checks.fails(
        "a wrong token gets 407",
        "response 407",
        &mut kube.agent(&[
            "curl",
            "-sS",
            "-x",
            "http://relay:wrong@127.0.0.1:8080",
            "https://example.test/",
        ]),
    )?;
    checks.fails(
        "the API server's address through the proxy is a world address with no machine: 502",
        "response 502",
        &mut kube.agent(&[
            "curl",
            "-sS",
            "-m",
            "10",
            "-k",
            &format!("https://{api}/version"),
        ]),
    )?;
    checks.fails(
        "a real name through the proxy does not exist in the world: 502",
        "response 502",
        &mut kube.agent(&["curl", "-sS", "-m", "10", "https://example.com/"]),
    )?;
    Ok(())
}

fn logged(kube: &Kube, checks: &mut Checks) -> Result {
    checks.ok(
        "attach logged the requests",
        "CONNECT example.test:443 \\(203\\.0\\.113\\.10\\) 200",
        &mut kube.command(&["logs", kube.pod, "-c", "attach"]),
    )?;
    checks.ok(
        "attach has not restarted under load",
        "^0 ?$",
        &mut kube.command(&[
            "get",
            "pod",
            kube.pod,
            "-o",
            "jsonpath={.status.initContainerStatuses[?(@.name==\"attach\")].restartCount}",
        ]),
    )?;
    Ok(())
}

fn stopped(kube: &Kube, checks: &mut Checks) -> Result {
    checks.fails(
        "with attach stopped, nothing answers",
        "Failed to connect|Connection refused",
        &mut kube.agent(&["curl", "-sS", "-m", "3", "https://example.test/"]),
    )?;
    Ok(())
}

fn restored(kube: &Kube, checks: &mut Checks) -> Result {
    checks.ok(
        "after the restart, https works again",
        "^hello from https example.test 443",
        &mut kube.agent(&["curl", "-sS", "https://example.test/"]),
    )?;
    Ok(())
}
