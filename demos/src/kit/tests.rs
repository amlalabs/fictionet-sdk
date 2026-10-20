use super::*;
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
    let make_kit = || {
        Kit::new("pair")
            .guest(Guest::ubuntu("workstation", "analyst").resources(4, 4096))
            .guest(Guest::ubuntu("server", "operator").resources(2, 2048))
    };
    let (run, mut prepared) = make_kit().prepare().unwrap();
    let key = ssh::Identity::generate().unwrap();
    let ca = "-----BEGIN CERTIFICATE-----\nshared root\n-----END CERTIFICATE-----\n";
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
        assert!(data.contains(&base64(ca.as_bytes())));
        assert!(data.contains(&key.authorized_key));
        assert!(seed_file(&r.seed, "network-config").contains("dhcp4: true"));
    }
    fictionet::lab(RunOptions::new(Seed::from_u64(1)), move |fcx| async move {
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
    assert_eq!(first.mac[0] & 3, 2);
    assert_eq!(second.mac[0] & 3, 2);
    assert_ne!(first.socket, second.socket);
    assert_ne!(first.overlay, second.overlay);
    assert_ne!(first.seed, second.seed);
    assert_ne!(first.uuid, second.uuid);
    assert_eq!(run.guests[0].guest.vcpus, 4);
    assert_eq!(run.guests[1].guest.memory_mib, 2048);
    let (again, _) = make_kit().prepare().unwrap();
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
    assert!(data.contains("'curl' 'openssh-server'"));
    assert!(data.contains("path: \"/opt/start.sh\"\n    permissions: '0755'"));
    assert!(data.contains(&base64(b"echo ready\n")));
    assert!(data.contains("bash /opt/start.sh"));
    assert!(data.find("update-ca-certificates").unwrap() < data.find("'curl'").unwrap());
    assert!(data.contains("/etc/profile.d/trust.sh"));
    assert!(data.contains("/etc/systemd/system.conf.d/trust.conf"));
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
    for name in ["Fictionet-host", "preEval", "Sandbox", "WORLD-server"] {
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

#[tokio::test]
async fn failed_world_start_cleans_up_before_boot() {
    let downloads = util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
    for file in [
        "cloud-hypervisor",
        "ubuntu-24.04-server-cloudimg-amd64.img",
        "ubuntu-24.04-server-cloudimg-amd64-vmlinuz-generic",
        "ubuntu-24.04-server-cloudimg-amd64-initrd-generic",
    ] {
        std::fs::write(downloads.path().join(file), []).unwrap();
    }
    let parent = util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
    assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
    let mut kit = Kit::new("pair")
        .guest(Guest::ubuntu("workstation", "analyst"))
        .guest(Guest::ubuntu("server", "operator"))
        .world(|_, _| async { Err(fictionet::Error::msg("cannot start sites")) });
    kit.run_parent = parent.path().to_path_buf();
    let result = kit.boot(downloads.path()).await;
    assert_eq!(result.err().unwrap().to_string(), "cannot start sites");
    assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn missing_download_names_the_command() {
    let downloads = util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
    let error = Kit::new("desktop")
        .guest(Guest::ubuntu("station", "analyst"))
        .world(|_, _| async { panic!("the world must not start") })
        .boot(downloads.path())
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("run cargo xtask demo desktop"));
}

#[tokio::test]
async fn addresses_follow_each_guests_lease() {
    use fictionet::events::{ConnInfo, Event, Sandbox, Stream};
    use fictionet::stdlib::network::ethernet::{Cidr, Lease as CardLease};
    let dir = util::RunDir::new(&std::env::temp_dir(), "test").unwrap();
    let fixed = Ipv4Addr::new(10, 0, 0, 9);
    let guests = [
        Guest::ubuntu("station", "analyst"),
        Guest::ubuntu("server", "operator").card(Family::Serve(CardLease {
            addr: Cidr {
                addr: fixed,
                prefix: 24,
            },
            gateway: None,
            dns: None,
        })),
    ];
    let mut observers: Vec<Arc<dyn Observer>> = Vec::new();
    let mut handles = Vec::new();
    for (index, guest) in guests.into_iter().enumerate() {
        let (tx, addr) = watch::channel(guest.initial_addr());
        observers.push(Arc::new(Lease {
            name: guest.hostname.clone(),
            addr: tx,
        }));
        let resources = Resources::new(dir.path(), &guest, index).unwrap();
        handles.push(GuestHandle {
            console: page::GuestConsole::new(&guest),
            guest,
            resources,
            addr,
            vm: None,
            ssh: None,
            backend: None,
            boot: std::time::Instant::now(),
            ssh_ready: Duration::ZERO,
        });
    }
    assert_eq!(handles[0].addr(), None);
    assert_eq!(handles[1].wait_addr().await.unwrap(), fixed);
    let fanout = Fanout::new(observers);
    let leased = Ipv4Addr::new(10, 0, 0, 5);
    for (name, addr) in [("unrelated", fixed), ("station", leased)] {
        let event = Event::new("net", "bound")
            .field("by_dhcp", true)
            .conn(&ConnInfo {
                sandbox: Some(Sandbox {
                    id: 1,
                    name: name.into(),
                    addr: Some(addr),
                    addr_v6: None,
                }),
                ..Default::default()
            });
        fanout.observe(
            Stamp {
                stream: Stream::Events,
                seq: 1,
                at: fictionet::time::Instant::ZERO,
            },
            Observation::Event(&event),
        );
    }
    assert_eq!(handles[0].wait_addr().await.unwrap(), leased);
    assert_eq!(handles[1].addr(), Some(fixed));
}

#[test]
fn root_certificate_names_are_neutral() {
    let (_, attachments) = fictionet::attachments();
    let mut world = World {
        attachments,
        ca: Arc::new(Mutex::new(None)),
        now_unix: 0,
        mirror: None,
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

/// A real kit page and world clock over an in-process SSH guest.
/// Keep this helper available for browser tests of the shared screen condition.
pub(crate) struct PageFixture {
    pub run: Run,
    pub peer: ssh::tests::Peer,
    pub client: client::PageClient,
}
impl PageFixture {
    pub async fn new() -> Self {
        let mut kit = Kit::new("console")
            .guest(Guest::ubuntu("workstation", "analyst").desktop(5901, "desktop-ready"))
            .guest(Guest::ubuntu("server", "operator"))
            .page(|dashboard, hosts| {
                Page::new("Desktop", dashboard)
                    .host(hosts.take("workstation"))
                    .standard_panels()
            });
        let build = kit.page.take().unwrap();
        let (mut run, mut prepared) = kit.prepare().unwrap();
        run.bind_page("console", build, &mut prepared)
            .await
            .unwrap();
        run.start_world(hold_world, prepared).await.unwrap();
        let client = client::PageClient::from_url(run.page_url()).unwrap();
        client.bootstrap().await.unwrap();
        let peer = ssh::tests::Peer::new().await;
        Self { run, peer, client }
    }
    pub fn network(&self) {
        self.run.guests[0].console.network(
            self.run.fcx.lock().unwrap().as_ref().unwrap(),
            Ipv4Addr::new(10, 0, 0, 2),
        );
    }
    pub fn connect(&mut self) {
        // The fixed address is supplied by the guest declaration in a VM run.
        self.run.guests[0].addr = watch::channel(Some(Ipv4Addr::new(10, 0, 0, 2))).1;
        self.run.connected(0, self.peer.session.clone());
    }
    pub async fn state(&self, topic: &str) -> serde_json::Value {
        self.client
            .get_json(&format!("/api/state/{topic}"))
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn page_consoles_cross_ssh_without_claiming_input() {
    use client::Capability;
    use fictionet_observe::page::Console;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut fixture = PageFixture::new().await;
        let error = fixture.run.guests[0]
            .console
            .screen()
            .unwrap()
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("workstation is still booting"));
        let ticket = fixture
            .client
            .ticket("workstation", Capability::Screen)
            .await
            .unwrap();
        let mut socket = fixture
            .client
            .open("workstation", Capability::Screen, Some(&ticket.ticket))
            .await
            .unwrap();
        let error = socket.read_u8().await.unwrap_err().to_string();
        assert!(error.contains("1008"), "{error}");
        assert!(error.contains("workstation is still booting"), "{error}");
        let wrong_url = format!(
            "{}#token={}",
            fixture.run.page_url().split('#').next().unwrap(),
            "0".repeat(64)
        );
        let error = client::PageClient::from_url(wrong_url)
            .unwrap()
            .bootstrap()
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("HTTP/1.1 401"), "{error}");
        assert!(error.contains("error"), "{error}");
        let error = fixture
            .client
            .open("workstation", Capability::Screen, None)
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("HTTP/1.1 401"), "{error}");
        assert!(error.contains("error"), "{error}");
        fixture.network();
        fixture.connect();
        let before = fixture.state("leases").await;
        assert!(before["value"]["workstation"]["holder"].is_null());
        let out = fixture.run.path().join("screen.png");
        let capture = rfb::capture_page(fixture.run.page_url(), "workstation", &out)
            .await
            .unwrap();
        assert_eq!(
            (capture.width, capture.height, capture.colors),
            (64, 64, 256)
        );
        let png = std::fs::read(out).unwrap();
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
        assert_eq!(&png[16..24], &[0, 0, 0, 64, 0, 0, 0, 64]);
        let mut chunks = &png[8..];
        let mut compressed = Vec::new();
        while !chunks.is_empty() {
            let len = u32::from_be_bytes(chunks[..4].try_into().unwrap()) as usize;
            if &chunks[4..8] == b"IDAT" {
                compressed.extend_from_slice(&chunks[8..8 + len]);
            }
            chunks = &chunks[12 + len..];
        }
        let mut pixels = Vec::new();
        flate2::read::ZlibDecoder::new(compressed.as_slice())
            .read_to_end(&mut pixels)
            .unwrap();
        assert_eq!(pixels.len(), 64 * (64 * 3 + 1));
        for y in 0..64u8 {
            let row = &pixels[y as usize * 193..][..193];
            assert_eq!(row[0], 0);
            for x in 0..64u8 {
                assert_eq!(&row[1 + x as usize * 3..][..3], &[x ^ y, y * 4, x * 4]);
            }
        }
        assert_eq!(*fixture.peer.rfb.lock().unwrap(), vec![0, 2, 3]);
        assert_eq!(
            fixture.state("leases").await,
            before,
            "no lease publication during capture"
        );
        let ticket = fixture
            .client
            .ticket("workstation", Capability::Terminal)
            .await
            .unwrap();
        let mut socket = fixture
            .client
            .open("workstation", Capability::Terminal, Some(&ticket.ticket))
            .await
            .unwrap();
        let mut ready = [0; 5];
        socket.read_exact(&mut ready).await.unwrap();
        assert_eq!(&ready, b"ready");
        socket.write_all(b"hello\r").await.unwrap();
        let mut echo = [0; 6];
        socket.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"hello\r");
        fixture.run.stop_status();
        let error = fixture.run.guests[0]
            .console
            .terminal(80, 24)
            .unwrap()
            .await
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "workstation has stopped");
        fixture.run.shutdown().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn terminal_acknowledges_output_beyond_the_page_window() {
    use client::Capability;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut fixture = PageFixture::new().await;
        fixture.connect();
        let ticket = fixture
            .client
            .ticket("workstation", Capability::Terminal)
            .await
            .unwrap();
        let mut socket = fixture
            .client
            .open("workstation", Capability::Terminal, Some(&ticket.ticket))
            .await
            .unwrap();
        let mut ready = [0; 5];
        socket.read_exact(&mut ready).await.unwrap();
        assert_eq!(&ready, b"ready");
        socket.write_all(b"large-output\r").await.unwrap();
        let mut output = vec![0; 512 * 1024];
        socket.read_exact(&mut output).await.unwrap();
        let expected: Vec<u8> = (0..512 * 1024).map(|n| (n % 251) as u8).collect();
        assert_eq!(output, expected);
        fixture.run.shutdown().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn status_follows_network_ssh_readiness_and_shutdown() {
    use serde_json::json;
    let mut fixture = PageFixture::new().await;
    let check = |state: &str, addresses: serde_json::Value, screen: bool, terminal: bool| json!({"state":state,"addresses":addresses,"screen":screen,"terminal":terminal});
    assert_eq!(
        fixture.state("host-workstation").await["value"],
        check("booting", json!([]), false, false)
    );
    fixture.network();
    let network = fixture.state("host-workstation").await;
    assert_eq!(
        network["value"],
        check("network_up", json!(["10.0.0.2"]), false, false)
    );
    fixture.connect();
    let ssh = fixture.state("host-workstation").await;
    assert_eq!(
        ssh["value"],
        check("ssh_up", json!(["10.0.0.2"]), false, true)
    );
    let error = fixture
        .run
        .guest("workstation")
        .wait_desktop(Duration::from_millis(200))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    for text in [
        "workstation",
        "desktop-ready",
        "exit code 7",
        "window manager is not running",
    ] {
        assert!(error.to_string().contains(text), "{error}");
    }
    fixture
        .peer
        .ready
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let elapsed = fixture
        .run
        .guest("workstation")
        .wait_desktop(Duration::from_secs(5))
        .await
        .unwrap();
    assert!(elapsed >= fixture.run.guest("workstation").ssh_ready());
    let desktop = fixture.state("host-workstation").await;
    assert_eq!(
        desktop["value"],
        check("desktop_up", json!(["10.0.0.2"]), true, true)
    );
    assert!(desktop["at"].as_f64().unwrap() >= ssh["at"].as_f64().unwrap());
    assert!(ssh["at"].as_f64().unwrap() >= network["at"].as_f64().unwrap());
    fixture.run.stop_status();
    assert_eq!(
        fixture.state("host-workstation").await["value"],
        check("stopped", json!([]), false, false)
    );
    assert!(
        fixture
            .run
            .guest("workstation")
            .wait_desktop(Duration::from_secs(1))
            .await
            .unwrap_err()
            .to_string()
            .contains("stopped")
    );
    fixture.run.shutdown().await.unwrap();
}

#[tokio::test]
async fn desktop_readiness_does_not_require_a_page() {
    let mut kit = Kit::new("headless")
        .guest(Guest::ubuntu("workstation", "analyst").desktop(5901, "desktop-ready"));
    let (mut run, prepared) = kit.prepare().unwrap();
    run.start_world(hold_world, prepared).await.unwrap();
    let peer = ssh::tests::Peer::new().await;
    peer.ready.store(true, std::sync::atomic::Ordering::SeqCst);
    run.guests[0].addr = watch::channel(Some(Ipv4Addr::LOCALHOST)).1;
    run.connected(0, peer.session.clone());
    run.guest("workstation")
        .wait_desktop(Duration::from_secs(5))
        .await
        .unwrap();
    assert!(run.page.is_none());
    assert!(run.dashboard.is_none());
    assert!(run.labels.is_none());
    assert_eq!(run.containment.revision(), 0);
    run.shutdown().await.unwrap();
}

#[tokio::test]
async fn page_wires_containment_and_labels() {
    let mut fixture = PageFixture::new().await;
    let response = fixture
        .client
        .request("GET", "/api/page", None, true)
        .await
        .unwrap();
    let description: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    let panels = description["panels"].as_array().unwrap();
    let containment = panels.iter().find(|p| p["id"] == "containment").unwrap();
    assert_eq!(containment["state"], "/api/state/containment");
    let labels = panels.iter().find(|p| p["id"] == "labels").unwrap();
    assert_eq!(labels["command"], "/api/command/labels");
    let response = fixture.client.request("POST", "/api/command/labels", Some(&serde_json::json!({
        "request_id":"label", "command":{"action":"add","target":{"kind":"event","seq":1},"text":"Boot"}
    })), true).await.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(fixture.state("labels").await["value"][0]["text"], "Boot");
    assert!(fixture.run.guests[1].console.status.revision() > 0);
    fixture.connect();
    fixture.run.guests[1].addr = watch::channel(Some(Ipv4Addr::new(10, 0, 0, 3))).1;
    fixture.run.connected(1, fixture.peer.session.clone());
    tokio::time::timeout(Duration::from_secs(5), async {
        while fixture.run.containment.revision() < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let state = fixture.state("containment").await;
    let probes = state["value"]["probes"].as_array().unwrap();
    assert_eq!(probes.len(), 2 * containment::PROBES.len());
    for guest in ["workstation", "server"] {
        assert_eq!(
            probes.iter().filter(|p| p["guest"] == guest).count(),
            containment::PROBES.len()
        );
    }
    fixture.run.shutdown().await.unwrap();
}

#[tokio::test]
async fn duplicate_kit_panels_are_actionable_errors() {
    for labels in [false, true] {
        let mut kit = Kit::new("duplicate")
            .guest(Guest::ubuntu("workstation", "analyst"))
            .page(move |dashboard, _| {
                let page = Page::new("Duplicate", dashboard);
                if labels {
                    page.labels(Labels::default())
                } else {
                    page.containment(StateTopic::new(StateLimits::default()))
                }
            });
        let build = kit.page.take().unwrap();
        let (mut run, mut prepared) = kit.prepare().unwrap();
        let error = run
            .bind_page("duplicate", build, &mut prepared)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("Kit::page adds containment and labels"),
            "{error}"
        );
        assert!(error.contains("remove"), "{error}");
    }
}

#[tokio::test]
async fn invalid_page_host_has_no_kit_panel_hint() {
    let mut kit = Kit::new("invalid")
        .guest(Guest::ubuntu("workstation", "analyst"))
        .page(|dashboard, _| {
            Page::new("Invalid", dashboard).host(fictionet_observe::page::Host::new("bad host"))
        });
    let build = kit.page.take().unwrap();
    let (mut run, mut prepared) = kit.prepare().unwrap();
    let error = run
        .bind_page("invalid", build, &mut prepared)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("bad host"), "{error}");
    assert!(
        !error.contains("Kit::page adds containment and labels"),
        "{error}"
    );
}

async fn hold_world(cx: Cx, world: World) -> fictionet::Result {
    cx.spawn(move |cx| async move {
        let _world = world;
        cx.cancelled().await;
        Ok(())
    });
    Ok(())
}

#[tokio::test]
async fn chromium_paints_the_page_through_the_ssh_console() {
    let mut fixture = PageFixture::new().await;
    fixture
        .peer
        .ready
        .store(true, std::sync::atomic::Ordering::SeqCst);
    fixture.network();
    fixture.connect();
    fixture
        .run
        .guest("workstation")
        .wait_desktop(Duration::from_secs(5))
        .await
        .unwrap();
    let before = fixture.state("leases").await;
    let (screen, page) = (
        fixture.run.path().join("screen.png"),
        fixture.run.path().join("console.png"),
    );
    let shots = fixture
        .run
        .screenshots("workstation", &screen, &page)
        .await
        .unwrap();
    assert_eq!((shots.screen.width, shots.screen.colors), (64, 256));
    assert_eq!(shots.page, page);
    let captured = shots.page;
    let png = std::fs::read(&captured).unwrap();
    assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
    assert_eq!(u32::from_be_bytes(png[16..20].try_into().unwrap()), 1440);
    assert_eq!(u32::from_be_bytes(png[20..24].try_into().unwrap()), 900);
    assert_eq!(fixture.state("leases").await, before);
    fixture.run.shutdown().await.unwrap();
    assert!(!std::path::Path::new(&captured).exists());
}

#[test]
fn page_hosts_name_unknown_and_repeated_guests() {
    use fictionet_observe::page::Console;
    let console = page::GuestConsole::new(&Guest::ubuntu("server", "operator"));
    assert!(console.screen().is_none());
    let mut hosts = Hosts([(String::from("server"), Some(console))].into());
    hosts.take("server");
    for (name, fix) in [("server", "only once"), ("missing", "Kit::guest")] {
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hosts.take(name)))
            .err()
            .unwrap();
        let message = panic.downcast_ref::<String>().unwrap();
        assert!(message.contains(name));
        assert!(message.contains(fix));
    }
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
    use fictionet_observe::page::Console;
    let mut peer = ssh::tests::Peer::new().await;
    let guest =
        Guest::ubuntu("workstation", "analyst").terminal("tmux attach -r -t main; exec bash -l");
    guest.validate().unwrap();
    let console = page::GuestConsole::new(&guest);
    fictionet::block_on(fictionet::lab(RunOptions::new(Seed::from_u64(1)), |cx| {
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

#[tokio::test]
async fn rfb_pointer_update_waits_for_every_rectangle() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::time::timeout(Duration::from_secs(5), async {
        let (client, mut server) = tokio::io::duplex(64);
        let (sent, received) = tokio::sync::oneshot::channel();
        let (finish, finishing) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            server.write_all(b"RFB 003.008\n").await.unwrap();
            let mut banner = [0; 12];
            server.read_exact(&mut banner).await.unwrap();
            assert_eq!(&banner, b"RFB 003.008\n");
            server.write_all(&[1, 1]).await.unwrap();
            assert_eq!(server.read_u8().await.unwrap(), 1);
            server.write_all(&[0; 4]).await.unwrap();
            assert_eq!(server.read_u8().await.unwrap(), 1);
            let mut init = [0; 24];
            init[..4].copy_from_slice(&[0, 2, 0, 1]);
            server.write_all(&init).await.unwrap();
            let mut format = [0; 28];
            server.read_exact(&mut format).await.unwrap();
            assert_eq!(
                format,
                [
                    0, 0, 0, 0, 32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0, 2, 0, 0,
                    1, 0, 0, 0, 0
                ]
            );
            let mut pointer = [0; 6];
            server.read_exact(&mut pointer).await.unwrap();
            assert_eq!(pointer, [5, 0, 0, 1, 0, 0]);
            let mut request = [0; 10];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [3, 0, 0, 0, 0, 0, 0, 2, 0, 1]);
            // Send the first of two rectangles before allowing the reply to finish.
            server
                .write_all(&[0, 0, 0, 2, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 255, 0])
                .await
                .unwrap();
            sent.send(()).unwrap();
            finishing.await.unwrap();
            server
                .write_all(&[0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 255, 0, 0])
                .await
                .unwrap();
        });
        let mut viewer = rfb::Viewer::handshake(client).await.unwrap();
        assert_eq!(viewer.size(), (2, 1));
        viewer.pointer(1, 0, 0).await.unwrap();
        let update = viewer.update();
        tokio::pin!(update);
        tokio::select! {
            biased;
            result = &mut update => panic!("update completed before the reply: {result:?}"),
            result = received => result.unwrap(),
        }
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(
                update.as_mut().poll(cx).is_pending()
            ))
            .await
        );
        finish.send(()).unwrap();
        assert_eq!(update.await.unwrap(), vec![255, 0, 0, 0, 255, 0]);
        peer.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn page_capture_reports_websocket_failure() {
    use fictionet::stdlib::protocols::websocket;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let out = std::env::temp_dir().join(format!("{}.png", random_uuid()));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let url = format!(
        "http://{}/#token={}",
        listener.local_addr().unwrap(),
        "a".repeat(64)
    );
    let peer = tokio::spawn(async move {
        for path in [
            "/api/bootstrap",
            "/api/ticket",
            "/ws/screen/workstation?ticket=abcd",
        ] {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(stream.read_u8().await.unwrap());
            }
            let head = String::from_utf8(head).unwrap();
            assert_eq!(head.split_whitespace().nth(1), Some(path));
            let header = |name: &str| {
                head.lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(key, _)| key.eq_ignore_ascii_case(name))
                    .map(|(_, value)| value.trim())
            };
            let length = header("Content-Length").unwrap_or("0").parse().unwrap();
            stream.read_exact(&mut vec![0; length]).await.unwrap();
            match path {
                "/api/bootstrap" => stream
                    .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                    .await
                    .unwrap(),
                "/api/ticket" => {
                    let body = r#"{"ticket":"abcd","session":"ef01"}"#;
                    stream
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                                body.len()
                            )
                            .as_bytes(),
                        )
                        .await
                        .unwrap();
                }
                _ => {
                    let accept = websocket::accept_key(header("Sec-WebSocket-Key").unwrap());
                    stream.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").as_bytes()).await.unwrap();
                    stream.write_all(b"\x82\x0cRFB 003.008\n").await.unwrap();
                    let mut banner = [0; 18];
                    stream.read_exact(&mut banner).await.unwrap();
                    stream.write_all(b"\x88\x00").await.unwrap();
                }
            }
        }
    });
    let error = rfb::capture_page(&url, "workstation", &out)
        .await
        .err()
        .unwrap();
    assert_eq!(error.to_string(), "page WebSocket closed: None");
    peer.await.unwrap();
    assert!(!out.exists());
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
            assert!(entry.contains(&base64(b"private")));
        }
    }
}

#[tokio::test]
async fn attachment_names_are_independent_of_guest_identity() {
    let mut kit = Kit::new("storage")
        .guest(
            Guest::ubuntu("laptop", "alex")
                .attachment("client-link")
                .resources(3, 1536),
        )
        .guest(
            Guest::ubuntu("storage", "sam")
                .attachment("storage-link")
                .resources(2, 768)
                .card(Family::Serve(fictionet::stdlib::network::ethernet::Lease {
                    addr: fictionet::stdlib::network::ethernet::Cidr {
                        addr: Ipv4Addr::new(192, 0, 2, 20),
                        prefix: 24,
                    },
                    gateway: Some(Ipv4Addr::new(192, 0, 2, 1)),
                    dns: Some(Ipv4Addr::new(192, 0, 2, 53)),
                })),
        );
    let (mut run, mut prepared) = kit.prepare().unwrap();
    assert_eq!(run.guests[0].name(), "laptop");
    assert_eq!(run.guests[1].name(), "storage");
    assert_eq!(run.guests[0].guest.attachment, "client-link");
    assert_eq!(run.guests[1].guest.attachment, "storage-link");
    assert_eq!(run.guests[0].resources.mac, [2, 0, 0, 0, 0, 2]);
    assert_eq!(run.guests[1].resources.mac, [2, 0, 0, 0, 0, 3]);
    assert_eq!(
        (run.guests[0].guest.vcpus, run.guests[0].guest.memory_mib),
        (3, 1536)
    );
    assert_eq!(
        (run.guests[1].guest.vcpus, run.guests[1].guest.memory_mib),
        (2, 768)
    );
    assert!(matches!(prepared.bridges[0].family, Family::FromWorld));
    assert_eq!(run.guests[1].addr(), Some(Ipv4Addr::new(192, 0, 2, 20)));
    assert!(matches!(prepared.bridges[1].family, Family::Serve(_)));
    run.bind_page(
        "storage",
        Box::new(|dashboard, hosts| {
            Page::new("Example", dashboard)
                .host(hosts.take("laptop").pinned())
                .host(hosts.take("storage").pinned())
                .standard_panels()
        }),
        &mut prepared,
    )
    .await
    .unwrap();
    let client = client::PageClient::from_url(run.page_url()).unwrap();
    client.bootstrap().await.unwrap();
    let response = client
        .request("GET", "/api/page", None, true)
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    let description: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(description["hosts"][0]["sandbox"], "client-link");
    assert_eq!(description["hosts"][1]["sandbox"], "storage-link");
    assert_eq!(description["hosts"][0]["pinned"], true);
    assert_eq!(description["hosts"][1]["pinned"], true);
    run.shutdown().await.unwrap();
}

#[tokio::test]
async fn page_client_reads_state_posts_commands_and_waits() {
    let fixture = PageFixture::new().await;
    let client = &fixture.client;
    let page = client.get_json("/api/page").await.unwrap();
    assert!(page["panels"].as_array().is_some_and(|p| !p.is_empty()));
    let missing = client.get_json("/api/state/missing").await.unwrap_err();
    assert!(
        missing
            .to_string()
            .starts_with("GET /api/state/missing: HTTP/1.1 404"),
        "{missing}"
    );
    let add = serde_json::json!({"action":"add","target":{"kind":"event","seq":1},"text":"Boot"});
    let applied = client.command("labels", "add", add).await.unwrap();
    assert_eq!(applied["status"], "applied");
    let rejected = client
        .command(
            "labels",
            "remove",
            serde_json::json!({"action":"remove","id":99}),
        )
        .await
        .unwrap();
    assert_eq!(rejected["status"], "rejected");
    let invalid = client
        .command("labels", "bad", serde_json::json!({"action":"rename"}))
        .await
        .unwrap_err();
    assert!(
        invalid
            .to_string()
            .starts_with("POST /api/command/labels: HTTP/1.1 400"),
        "{invalid}"
    );
    let labels = client
        .wait_for(
            "/api/state/labels",
            Duration::from_secs(5),
            Duration::from_millis(10),
            |state| Ok(state["value"][0]["text"] == "Boot"),
        )
        .await
        .unwrap();
    assert_eq!(labels["value"].as_array().unwrap().len(), 1);
    let never = client
        .wait_for(
            "/api/state/labels",
            Duration::from_millis(50),
            Duration::from_millis(10),
            |_| Ok(false),
        )
        .await
        .unwrap_err();
    assert_eq!(never.kind(), io::ErrorKind::TimedOut);
    let stopped = client
        .wait_for(
            "/api/state/labels",
            Duration::from_secs(5),
            Duration::from_millis(10),
            |_| Err(io::Error::other("the predicate stops the wait")),
        )
        .await
        .unwrap_err();
    assert_eq!(stopped.to_string(), "the predicate stops the wait");
    let event = client
        .wait_for_event(
            0,
            Duration::from_secs(5),
            Duration::from_millis(10),
            |event| Ok(event["source"] == "page" && event["kind"] == "label"),
        )
        .await
        .unwrap();
    let seq = event["seq"].as_u64().unwrap();
    let later = client
        .wait_for_event(
            seq,
            Duration::from_millis(50),
            Duration::from_millis(10),
            |event| Ok(event["source"] == "page" && event["kind"] == "label"),
        )
        .await
        .unwrap_err();
    assert_eq!(
        later.kind(),
        io::ErrorKind::TimedOut,
        "events after the cursor only"
    );
    let batch = client.events(0).await.unwrap();
    assert!(batch["last"].as_u64().unwrap() >= seq);
    assert_eq!(
        client.last_event().await.unwrap(),
        batch["last"].as_u64().unwrap()
    );
    let label =
        |event: &serde_json::Value| Ok(event["source"] == "page" && event["kind"] == "label");
    let mut cursor = 0;
    let found = client.find_event(&mut cursor, label).await.unwrap();
    assert_eq!(found.unwrap()["seq"], seq);
    assert_eq!(cursor, seq, "the cursor stops at the match");
    assert!(
        client
            .find_event(&mut cursor, label)
            .await
            .unwrap()
            .is_none()
    );
    assert!(cursor >= seq, "the cursor moves past every event read");
    let stopped = client
        .find_event(&mut 0, |_| {
            Err(io::Error::other("the predicate stops the read"))
        })
        .await
        .unwrap_err();
    assert_eq!(stopped.to_string(), "the predicate stops the read");
    let mut stream = client.state_stream(&["labels"]).await.unwrap();
    let streamed = stream
        .next("labels", |snapshot| snapshot["value"][0]["text"] == "Boot")
        .await
        .unwrap();
    assert_eq!(streamed["value"], labels["value"]);
    assert!(client.state_stream(&["labels,leases"]).await.is_err());
    assert!(client.state_stream(&[]).await.is_err());
    fixture.run.shutdown().await.unwrap();
}

#[tokio::test]
async fn gate_checks_cover_access_the_terminal_and_a_settled_screen() {
    use client::Capability;
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut fixture = PageFixture::new().await;
        fixture
            .peer
            .ready
            .store(true, std::sync::atomic::Ordering::SeqCst);
        fixture.network();
        fixture.connect();
        let client = &fixture.client;
        gate::bearer_required(client).await.unwrap();
        gate::single_use_ticket(client, "workstation", Capability::Screen)
            .await
            .unwrap();
        assert!(
            !String::from_utf8_lossy(gate::HOSTNAME_LINE).contains("name:workstation:end"),
            "an echo of the typed line must not pass the terminal check"
        );
        gate::terminal_runs_on(client, "workstation").await.unwrap();
        let out = fixture.run.path().join("settled.png");
        let (capture, settled) = fixture
            .run
            .settled_screen("workstation", &out)
            .await
            .unwrap();
        assert_eq!((capture.width, capture.colors), (64, 256));
        assert_eq!(settled, Some(2), "an unchanging screen settles at once");
        assert_eq!(capture.png, out);
        fixture.run.shutdown().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn terminal_reads_until_the_expected_output() {
    use client::Capability;
    use tokio::io::AsyncWriteExt;
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut fixture = PageFixture::new().await;
        fixture.connect();
        let open = || async {
            let ticket = fixture
                .client
                .ticket("workstation", Capability::Terminal)
                .await
                .unwrap();
            fixture
                .client
                .open("workstation", Capability::Terminal, Some(&ticket.ticket))
                .await
                .unwrap()
        };
        let mut socket = open().await;
        socket.read_until(b"ready", 64 << 10).await.unwrap();
        socket.write_all(b"name:workstation:end\r").await.unwrap();
        socket
            .read_until(b"name:workstation:end", 64 << 10)
            .await
            .unwrap();
        let mut socket = open().await;
        socket.write_all(b"large-output\r").await.unwrap();
        let error = socket.read_until(b"absent", 64 << 10).await.unwrap_err();
        assert!(error.to_string().contains("without \"absent\""), "{error}");
        fixture.run.shutdown().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cloud_init_wait_and_diagnostics_use_the_guest_session() {
    let mut fixture = PageFixture::new().await;
    let offline = fixture.run.guests[0].diagnostics().await;
    assert!(offline.contains("No SSH session"), "{offline}");
    fixture.connect();
    let guest = &fixture.run.guests[0];
    let error = guest
        .wait_cloud_init(Duration::from_secs(5))
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "workstation: cloud-init exit 7\nwindow manager is not running"
    );
    fixture
        .peer
        .ready
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let ready = guest.wait_cloud_init(Duration::from_secs(5)).await.unwrap();
    assert!(ready <= guest.boot.elapsed());
    let report = guest.diagnostics().await;
    for command in gate_commands() {
        assert!(report.contains(&format!("guest$ {command}\n")), "{report}");
    }
    assert_eq!(report.matches("[exit 0]").count(), gate_commands().len());
    // Readiness and containment probes share the session; keep this test's commands.
    let wait = "sudo cloud-init status --wait --long";
    let mut sent = Vec::new();
    while let Ok(event) = fixture.peer.events.try_recv() {
        sent.extend(
            event
                .strip_prefix("exec ")
                .filter(|command| *command == wait || gate_commands().contains(command))
                .map(str::to_owned),
        );
    }
    assert_eq!(sent[..2], [wait; 2]);
    assert_eq!(sent[2..], gate_commands());
    fixture.run.shutdown().await.unwrap();
}

fn gate_commands() -> Vec<&'static str> {
    vec![
        "cloud-init status --long",
        "sudo tail -n 30 /var/log/cloud-init-output.log",
        "systemctl is-active vnc",
        "tail -n 15 /tmp/xvnc.log /tmp/xfce.log",
        "tail -n 40 /tmp/firefox.log",
        "env DISPLAY=:1 sh -c 'xdotool search --onlyvisible --class firefox | head -n1 | xargs -r xdotool getwindowname'",
    ]
}
