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
            guest,
            resources,
            addr,
            vm: None,
            ssh: None,
            backend: None,
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
