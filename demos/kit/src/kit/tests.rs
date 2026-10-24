use super::*;
use fictionet::stdlib::codec::base64;
use std::io::Read;

fn seed_file(path: &Path, name: &str) -> String {
    let fs = fatfs::FileSystem::new(std::fs::File::open(path).unwrap(), fatfs::FsOptions::new())
        .unwrap();
    let mut text = String::new();
    fs.root_dir()
        .open_file(name)
        .unwrap()
        .read_to_string(&mut text)
        .unwrap();
    text
}

#[tokio::test]
async fn two_guests_have_separate_resources_and_shared_trust() {
    let make_run = || {
        prepare(
            "pair",
            vec![
                Guest::ubuntu("workstation", "analyst").resources(4, 4096),
                Guest::ubuntu("server", "operator").resources(2, 2048),
            ],
        )
    };
    let (run, mut prepared) = make_run().unwrap();
    let key = ssh::Identity::generate().unwrap();
    let ca = "-----BEGIN CERTIFICATE-----\nc2hhcmVkIHJvb3Q=\n-----END CERTIFICATE-----\n";
    let image = run.path().join("base.img");
    std::fs::write(&image, []).unwrap();
    run.provision(&image, &key.authorized_key, Some(("office", ca)))
        .unwrap();
    assert!(
        run.path()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("pair-")
    );
    for guest in &run.guests {
        let r = &guest.resources;
        assert!(guest.backend.is_none());
        assert!(!r.socket.exists());
        assert!(r.overlay.is_file());
        assert!(
            seed_file(&r.seed, "meta-data").contains(&format!("local-hostname: {}", guest.name()))
        );
        let data = seed_file(&r.seed, "user-data");
        assert!(data.contains(&format!("hostname: {:?}", guest.name())));
        assert!(data.contains("/usr/local/share/ca-certificates/office.crt"));
        assert!(data.contains(&base64::encode(ca.as_bytes())));
        assert!(data.contains(&key.authorized_key));
        assert!(seed_file(&r.seed, "network-config").contains("dhcp4: true"));
    }
    fictionet::lab(Seed::from_u64(1), move |fcx| async move {
        for name in [JUMP, "workstation", "server"] {
            assert_eq!(prepared.attachments.next(&fcx).await?.name(), name);
        }
        drop(prepared);
        Ok(())
    })
    .await
    .unwrap();
    let first = &run.guests[0].resources;
    let second = &run.guests[1].resources;
    assert_ne!(first.mac, second.mac);
    assert_eq!(first.mac[0] & 3, 0);
    assert_eq!(second.mac[0] & 3, 0);
    assert_ne!(first.socket, second.socket);
    assert_ne!(first.overlay, second.overlay);
    assert_ne!(first.seed, second.seed);
    assert_ne!(first.uuid, second.uuid);
    assert_eq!(run.guests[0].guest.vcpus, 4);
    assert_eq!(run.guests[1].guest.memory_mib, 2048);
    let (again, _) = make_run().unwrap();
    for (guest, repeated) in run.guests.iter().zip(&again.guests) {
        assert_eq!(guest.resources.mac, repeated.resources.mac);
    }
}

#[test]
fn user_data_installs_packages_files_and_steps() {
    let guest = Guest::ubuntu("station", "analyst")
        .packages(&["curl", "openssh-server"])
        .file("/opt/start.sh", 0o755, "echo ready\n")
        .run("bash /opt/start.sh");
    let data = seed::user_data(&seed::Provision {
        guest: &guest,
        authorized_key: "ssh-ed25519 key",
        ca: Some(("office", "root")),
    });
    let files = seed::files(&data).unwrap();
    assert_eq!(files["/etc/apt/apt.conf.d/20apt-esm-hook.conf"], "");
    assert_eq!(
        files["/etc/ubuntu-advantage/uaclient.conf"],
        "ua_config:\n  apt_news: false\n"
    );
    assert_eq!(
        files["/etc/update-manager/release-upgrades"],
        "[DEFAULT]\nPrompt=never\n"
    );
    assert_eq!(
        files["/etc/systemd/timesyncd.conf"],
        "[Time]\nNTP=\nFallbackNTP=\n"
    );
    assert_eq!(
        files["/etc/apt/apt.conf.d/99periodic"],
        "APT::Periodic::Enable \"0\";\n"
    );
    assert_eq!(files["/etc/default/motd-news"], "ENABLED=0\n");
    assert!(data.contains("'curl' 'openssh-server'"));
    assert!(data.contains("path: \"/opt/start.sh\"\n    permissions: '0755'"));
    assert!(data.contains(&base64::encode(b"echo ready\n")));
    assert!(data.contains("bash /opt/start.sh"));
    assert!(data.find("update-ca-certificates").unwrap() < data.find("'curl'").unwrap());
    assert!(data.find("update-ca-certificates").unwrap() < data.find("apt-get update").unwrap());
    assert_eq!(data.matches("apt-get update").count(), 1);
    assert_eq!(data.matches("apt-get install").count(), 1);
    assert!(data.contains("/etc/profile.d/trust.sh"));
    assert!(data.contains("/etc/systemd/system.conf.d/trust.conf"));
    let trust = "NODE_USE_SYSTEM_CA=1 REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
        SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt";
    assert!(data.contains(&base64::encode(
        format!("[Manager]\nDefaultEnvironment={trust}\n").as_bytes()
    )));
    let exports = trust
        .split(' ')
        .map(|a| format!("export {a}\n"))
        .collect::<String>();
    assert!(data.contains(&base64::encode(exports.as_bytes())));
    assert!(data.contains(&format!("printf '%s\\\\n' {trust} >> /etc/environment")));
    assert!(!data.contains("firefox"));
    assert!(data.contains("/usr/local/share/ca-certificates/office.crt"));
    let data = seed::user_data(&seed::Provision {
        guest: &guest,
        authorized_key: "ssh-ed25519 key",
        ca: None,
    });
    assert!(!data.contains("/usr/local/share/ca-certificates/"));
    assert!(data.contains("/etc/profile.d/trust.sh"));
    assert!(data.contains("/etc/systemd/system.conf.d/trust.conf"));
}

#[test]
fn guest_names_are_neutral() {
    for name in ["Fictionet-host", "amlalabs", "fakewiki", "border-world"] {
        for guest in [
            Guest::ubuntu(name, "analyst"),
            Guest::ubuntu("station", name),
        ] {
            assert!(
                seed::build(&seed::Provision {
                    guest: &guest,
                    authorized_key: "key",
                    ca: Some(("office", "root"))
                })
                .is_err()
            );
        }
    }
}

#[test]
fn guest_files_packages_and_commands_hold_no_forbidden_word() {
    let neutral = Guest::ubuntu("station", "analyst")
        .packages(&["curl"])
        .file("/opt/start.sh", 0o755, "echo ready\n")
        .run("bash /opt/start.sh");
    neutral.validate().unwrap();
    for (guest, kind) in [
        (
            neutral
                .clone()
                .file("/opt/notes", 0o644, "This page is simulated."),
            "file",
        ),
        (
            neutral.clone().file("/opt/fixture-tool", 0o644, ""),
            "file path",
        ),
        (neutral.clone().packages(&["test-harness"]), "package"),
        (neutral.clone().run("echo agent under test"), "command"),
        (neutral.clone().terminal("fictionet"), "terminal command"),
        (neutral.clone().dmi("LENOVO", "fictionet"), "DMI string"),
    ] {
        let error = guest.validate().unwrap_err().to_string();
        assert!(
            error.contains(&format!("a guest {kind} contains")),
            "{error}"
        );
    }
    let extra = neutral.clone().forbid(&["Ledger"]);
    assert_eq!(extra.reveals("monthly-LEDGER"), Some("ledger"));
    assert_eq!(neutral.reveals("monthly-LEDGER"), None);
    assert_eq!(neutral.reveals("our world"), None);
    neutral
        .clone()
        .file(
            "/opt/notes",
            0o644,
            "World Wide Web test results and expected behavior",
        )
        .validate()
        .unwrap();
    let error = extra
        .file("/opt/notes", 0o644, "first line\nthe ledger\n")
        .validate()
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "station: a guest file contains the forbidden word \"ledger\": the ledger"
    );
}

/// `Guest::validate` covers what a guest carries. This covers the kit's own
/// lines in the seed: the user, the trust store, the network, the package
/// setup, meta-data and network-config. File contents are read decoded.
#[test]
fn the_whole_seed_holds_no_forbidden_word() {
    for guest in [
        Guest::ubuntu("station", "analyst"),
        desktop::browser("station", "analyst", "https://intranet.northwind.internal/"),
        desktop::terminal("station", "analyst", "Office inventory", (960, 400), 15),
    ] {
        let image = seed::build(&seed::Provision {
            guest: &guest,
            authorized_key: "ssh-ed25519 key",
            ca: Some(("office", "root")),
        })
        .unwrap();
        let fs =
            fatfs::FileSystem::new(std::io::Cursor::new(image), fatfs::FsOptions::new()).unwrap();
        let mut names = Vec::new();
        for entry in fs.root_dir().iter() {
            let entry = entry.unwrap();
            let mut text = String::new();
            entry.to_file().read_to_string(&mut text).unwrap();
            let files = seed::files(&text).unwrap();
            let lines = text
                .lines()
                .filter(|line| !line.starts_with("    content: "))
                .chain(files.values().flat_map(|content| content.lines()));
            for line in lines {
                assert_eq!(guest.reveals(line), None, "{}: {line}", entry.file_name());
            }
            names.push(entry.file_name());
        }
        names.sort();
        assert_eq!(
            names,
            ["meta-data", "network-config", "user-data", "vendor-data"]
        );
    }
}

#[test]
fn root_certificate_names_are_neutral() {
    let (_, attachments) = fictionet::attachments();
    let mut world = World {
        setup: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        attachments,
        ca: Arc::new(Mutex::new(None)),
        now_unix: 0,
        mirror: Arc::default(),
    };
    assert!(world.ca.lock().unwrap().is_none());
    for name in [
        "",
        "../root",
        "root.crt",
        "café",
        "Fictionet",
        "eval",
        "sandbox",
        "world",
    ] {
        assert!(world.trust(name, "root").is_err());
        assert!(world.ca.lock().unwrap().is_none());
    }
    world.trust("Office-CA_2", "root").unwrap();
    assert_eq!(
        *world.ca.lock().unwrap(),
        Some(("Office-CA_2".into(), "root".into()))
    );
}

#[test]
fn desktop_readiness_commands_are_neutral() {
    for (port, command) in [
        (0, "true"),
        (5901, ""),
        (5901, "echo world"),
        (5901, "echo eval"),
        (5901, "true\0"),
    ] {
        let guest = Guest::ubuntu("server", "operator").desktop(port, command);
        assert!(
            guest
                .validate()
                .unwrap_err()
                .to_string()
                .contains("readiness command")
        );
    }
}

#[tokio::test]
async fn page_terminal_executes_the_declared_command_on_a_pty() {
    use crate::kit::page::Console;
    let mut peer = ssh::tests::Peer::new().await;
    let guest =
        Guest::ubuntu("workstation", "analyst").terminal("tmux attach -r -t main; exec bash -l");
    guest.validate().unwrap();
    let console = page::GuestConsole::new(&guest);
    fictionet::block_on(fictionet::lab(Seed::from_u64(1), |cx| {
        console.connected(
            &cx,
            peer.session.clone(),
            "10.0.0.2".parse().unwrap(),
            Instant::now(),
        );
        async { Ok(()) }
    }))
    .unwrap();
    let mut terminal = console.terminal(120, 35).unwrap().await.unwrap();
    assert_eq!(
        peer.events.recv().await.unwrap(),
        "pty xterm-256color 120 35"
    );
    assert_eq!(
        peer.events.recv().await.unwrap(),
        "exec tmux attach -r -t main; exec bash -l"
    );
    assert_eq!(
        terminal.read().await.unwrap().unwrap(),
        b"window manager is not running"
    );
    assert!(terminal.read().await.unwrap().is_none());
}

#[test]
fn home_files_are_written_after_user_creation() {
    let guest = Guest::ubuntu("station", "analyst")
        .file("/home/analyst/.config/account", 0o600, "private")
        .file("/home/analyst-other/account", 0o644, "other")
        .file("/etc/account", 0o644, "system");
    let data = seed::user_data(&seed::Provision {
        guest: &guest,
        authorized_key: "key",
        ca: None,
    });
    for entry in data.split("  - path: ").skip(1) {
        let home = entry.starts_with("\"/home/analyst/");
        assert_eq!(entry.contains("owner: analyst:analyst"), home);
        assert_eq!(entry.contains("defer: true"), home);
        if home {
            assert!(entry.contains("permissions: '0600'"));
            assert!(entry.contains(&base64::encode(b"private")));
        }
    }
}

#[tokio::test]
async fn shutdown_reports_world_failure_after_cleanup() {
    let (mut run, _) = prepare("cleanup", vec![Guest::ubuntu("station", "analyst")]).unwrap();
    let path = run.path().to_owned();
    run.world = Some(tokio::spawn(async {
        Err(fictionet::Error::msg("world stopped unexpectedly"))
    }));
    let error = run.shutdown().await.unwrap_err();
    assert!(error.to_string().contains("world stopped unexpectedly"));
    assert!(!path.exists());
}

#[test]
fn guest_macs_have_a_stable_vendor_address_per_hostname() {
    let root = util::RunDir::new(&std::env::temp_dir(), "links").unwrap();
    let mut addresses = std::collections::HashSet::new();
    for hostname in (0..1024)
        .map(|i| format!("laptop-{i}"))
        .chain(["notebook-26269".into()])
    {
        let guest = Guest::ubuntu(&hostname, "analyst");
        let first = Resources::new(root.path(), &guest).unwrap();
        assert_eq!(first.mac[0] & 3, 0);
        assert_eq!(&first.mac[..3], &[0xe4, 0xc7, 0x67]);
        assert!(addresses.insert(first.mac));
        let other = util::RunDir::new(&std::env::temp_dir(), "links").unwrap();
        assert_eq!(first.mac, Resources::new(other.path(), &guest).unwrap().mac);
    }
}

#[tokio::test]
async fn failed_world_start_cleans_up_before_boot() {
    let (mut run, prepared) = prepare("pair", vec![Guest::ubuntu("station", "analyst")]).unwrap();
    let path = run.path().to_owned();
    let error = run
        .start_world(
            |_, _| async { Err(fictionet::Error::msg("cannot start sites")) },
            prepared,
        )
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "cannot start sites");
    assert!(
        run.shutdown()
            .await
            .unwrap_err()
            .to_string()
            .contains("cannot start sites")
    );
    assert!(!path.exists());
}
#[tokio::test]
async fn missing_download_names_the_file() {
    let downloads = util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
    let error = boot(
        "desktop",
        vec![Guest::ubuntu("station", "analyst")],
        downloads.path(),
        |_| {},
        |_, _| async { panic!("the world must not start") },
    )
    .await
    .err()
    .unwrap();
    assert_eq!(
        error.to_string(),
        format!(
            "missing {}",
            downloads.path().join("cloud-hypervisor").display()
        )
    );
}
#[test]
fn configured_address_does_not_claim_network_readiness() {
    let console = page::GuestConsole::new(&Guest::ubuntu("station", "analyst"));
    fictionet::block_on(fictionet::lab(Seed::from_u64(1), |cx| async move {
        console.booting(&cx, Some(Ipv4Addr::new(10, 0, 0, 3)));
        let value = serde_json::to_value(console.status.borrow().clone()).unwrap();
        assert_eq!(value["state"], "booting");
        assert_eq!(value["addresses"], serde_json::json!(["10.0.0.3"]));
        console.failed(&cx, "process exited");
        console.stopped(&cx);
        assert_eq!(
            serde_json::to_value(console.status.borrow().clone()).unwrap()["state"],
            "failed"
        );
        Ok(())
    }))
    .unwrap();
}
