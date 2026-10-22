use super::*;
use serde_json::Value;
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};

fn test_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("web-{name}-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    dir
}

#[test]
fn corrupt_record() {
    let dir = test_dir("corrupt-record");
    let path = dir.join("addresses.jsonl");
    let fixed = HashMap::from([(
        "fixed.com".into(),
        (Ipv4Addr::new(142, 250, 180, 4), "seed"),
    )]);
    let first = "{\"host\":\"first.com\",\"addr\":\"104.21.48.57\"}\n";
    for bad in [
        "garbage",
        "",
        "null",
        "[]",
        "{}",
        r#"{"host":1,"addr":"104.21.48.58"}"#,
        r#"{"host":"second.com","addr":"not an address"}"#,
        r#"{"host":"first.com","addr":"104.21.48.58"}"#,
        r#"{"host":"second.com","addr":"104.21.48.57"}"#,
        r#"{"host":"fixed.com","addr":"104.21.48.58"}"#,
        r#"{"host":"second.com","addr":"142.250.180.4"}"#,
        r#"{"host":"partial.com","addr":"104.21."#,
    ] {
        std::fs::write(&path, format!("{first}{bad}\n")).unwrap();
        let error = Addresses::new(fixed.clone(), Some(&dir)).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{bad}");
        let reason = error.to_string();
        assert!(reason.contains(path.to_str().unwrap()), "{reason}");
        assert!(reason.contains("line 2"), "{reason}");
    }
    std::fs::write(&path, format!("{first}{first}")).unwrap();
    let addresses = Addresses::new(fixed, Some(&dir)).unwrap();
    assert_eq!(
        addresses.assign("first.com").unwrap(),
        Some((Ipv4Addr::new(104, 21, 48, 57), "recorded"))
    );
    let fixed = HashMap::from([
        ("first.com".into(), (Ipv4Addr::new(104, 21, 48, 57), "seed")),
        (
            "second.com".into(),
            (Ipv4Addr::new(104, 21, 48, 57), "seed"),
        ),
    ]);
    assert!(Addresses::new(fixed.clone(), Some(&dir)).is_ok());
    std::fs::write(
        &path,
        format!("{first}{}", first.replace("first.com", "second.com")),
    )
    .unwrap();
    let error = Addresses::new(fixed, Some(&dir)).err().unwrap();
    assert!(error.to_string().contains("line 2"));
    std::fs::remove_dir_all(dir).unwrap();
}

/// Worlds on one store read what the others recorded before they
/// assign, so each address goes to one host and every world agrees.
#[test]
fn worlds_sharing_a_record_agree() {
    let dir = test_dir("shared-record");
    let a = Addresses::new(HashMap::new(), Some(&dir)).unwrap();
    let b = Addresses::new(HashMap::new(), Some(&dir)).unwrap();
    let first = a.assign("first.com").unwrap().unwrap().0;
    let second = b.assign("second.com").unwrap().unwrap().0;
    assert_ne!(first, second);
    assert_eq!(b.assign("first.com").unwrap(), Some((first, "recorded")));
    assert_eq!(a.assign("second.com").unwrap(), Some((second, "recorded")));
    let later = Addresses::new(HashMap::new(), Some(&dir)).unwrap();
    assert_eq!(
        later.assign("first.com").unwrap(),
        Some((first, "recorded"))
    );
    assert_eq!(
        later.assign("second.com").unwrap(),
        Some((second, "recorded"))
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn unreadable_record() {
    let dir = test_dir("unreadable-record");
    let path = dir.join("addresses.jsonl");
    std::fs::write(&path, [0xff]).unwrap();
    let error = Addresses::new(HashMap::new(), Some(&dir)).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(error.to_string().contains(path.to_str().unwrap()));
    assert_eq!(std::fs::read(&path).unwrap(), [0xff]);
    std::fs::remove_dir_all(dir).unwrap();
}

struct FailingWriter(Arc<AtomicUsize>);
impl Write for FailingWriter {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(io::Error::other("injected address write failure"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Addresses on a store in `dir` that append to `writer`.
fn writing_to(
    fixed: HashMap<String, (Ipv4Addr, &'static str)>,
    dir: &Path,
    writer: impl Write + Send + 'static,
) -> Addresses {
    let addresses = Addresses::new(fixed, Some(dir)).unwrap();
    let mut inner = addresses.inner.lock().unwrap();
    inner
        .record
        .as_mut()
        .unwrap()
        .lines
        .set_writer(Box::new(writer));
    drop(inner);
    addresses
}

#[test]
fn failing_writer() {
    let dir = test_dir("failing-writer");
    let fixed_addr = Ipv4Addr::new(142, 250, 180, 4);
    let recorded_addr = Ipv4Addr::new(172, 67, 48, 57);
    let fixed = HashMap::from([("fixed.com".into(), (fixed_addr, "seed"))]);
    std::fs::write(
        dir.join("addresses.jsonl"),
        "{\"host\":\"recorded.com\",\"addr\":\"172.67.48.57\"}\n",
    )
    .unwrap();
    let writes = Arc::new(AtomicUsize::new(0));
    let addresses = writing_to(fixed, &dir, FailingWriter(writes.clone()));
    let error = addresses.assign("first.com").unwrap_err();
    assert_eq!(error.to_string(), "injected address write failure");
    for host in ["first.com", "second.com"] {
        let later = addresses.assign(host).unwrap_err();
        assert_eq!(later.kind(), error.kind());
        assert_eq!(later.to_string(), error.to_string());
    }
    assert_eq!(writes.load(Ordering::SeqCst), 1);
    assert_eq!(
        addresses.assign("fixed.com").unwrap(),
        Some((fixed_addr, "seed"))
    );
    assert_eq!(
        addresses.assign("recorded.com").unwrap(),
        Some((recorded_addr, "recorded"))
    );
    let inner = addresses.inner.lock().unwrap();
    assert_eq!(inner.by_host.len(), 2);
    assert!(!inner.by_host.contains_key("first.com"));
    assert_eq!(inner.used, HashSet::from([fixed_addr, recorded_addr]));
    drop(inner);
    std::fs::remove_dir_all(dir).unwrap();
}

struct PartialWriter {
    file: std::fs::File,
    wrote: bool,
}
impl Write for PartialWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.wrote {
            return Err(io::Error::other("injected partial append failure"));
        }
        self.wrote = true;
        self.file.write(&bytes[..bytes.len() / 2])
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[test]
fn restart_after_failed_append() {
    let dir = test_dir("failed-append");
    let path = dir.join("addresses.jsonl");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .unwrap();
    let addresses = writing_to(HashMap::new(), &dir, PartialWriter { file, wrote: false });
    assert!(addresses.assign("first.com").is_err());
    assert!(addresses.inner.lock().unwrap().by_host.is_empty());
    let partial = std::fs::read(&path).unwrap();
    assert!(!partial.is_empty());
    assert!(addresses.assign("second.com").is_err());
    assert_eq!(std::fs::read(&path).unwrap(), partial);
    drop(addresses);
    let error = Addresses::new(HashMap::new(), Some(&dir)).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    let reason = error.to_string();
    assert!(reason.contains(path.to_str().unwrap()), "{reason}");
    assert!(reason.contains("line 1"), "{reason}");
    std::fs::remove_dir_all(dir).unwrap();
}

/// The store's lock is held while `addresses.jsonl` is read, so every
/// line in it is finished. One without its newline was cut short.
#[test]
fn a_record_without_its_newline_is_corrupt() {
    let dir = test_dir("record-without-newline");
    let path = dir.join("addresses.jsonl");
    let first = r#"{"host":"first.com","addr":"104.21.48.57"}"#;
    std::fs::write(&path, first).unwrap();
    let error = Addresses::new(HashMap::new(), Some(&dir)).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    let reason = error.to_string();
    assert!(
        reason.contains("line 1: the line is unfinished"),
        "{reason}"
    );
    std::fs::write(&path, format!("{first}\n")).unwrap();
    let addresses = Addresses::new(HashMap::new(), Some(&dir)).unwrap();
    assert_eq!(
        addresses.assign("first.com").unwrap(),
        Some((Ipv4Addr::new(104, 21, 48, 57), "recorded"))
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn serve_latches_a_failed_record() {
    use fictionet::stdlib::{
        protocols::dns::{op::ResponseCode, rr::RecordType},
        world::sandbox::machine,
    };

    let dir = test_dir("serve-failed-record");
    let path = dir.join("log.jsonl");
    let store = dir.join("store");
    std::fs::create_dir(&store).unwrap();
    let log = Arc::new(Log::new(
        Box::new(std::fs::File::create(&path).unwrap()),
        &[],
        |s| s,
    ));
    let output = log.clone();
    fictionet::block_on(fictionet::run(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(1))
            .observer(Arc::new(events::LogObserver { log: log.clone() })),
        move |fcx| async move {
            let failing = FailingWriter(Arc::new(AtomicUsize::new(0)));
            let addresses = Arc::new(writing_to(HashMap::new(), &store, failing));
            let start = SystemTime::UNIX_EPOCH;
            let ca = Arc::new(Ca {
                issuer: fictionet::stdlib::services::ca::Ca::new(&fcx, "Test CA")?,
                start,
            });
            let (attacher, attachments) = fictionet::attachments();
            let seed = pages::Seed::builtin("web")?;
            serve(
                &fcx,
                addresses.clone(),
                ca,
                Arc::new(Pages::new(seed)),
                output.clone(),
                start,
                attachments,
            )?;
            let m = machine(&fcx, attacher.attach("agent")?, Ipv4Addr::new(10, 0, 0, 2));
            let answer = m
                .lookup(&fcx, GATEWAY.into(), "new.com", RecordType::A)
                .await?;
            assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain);
            assert!(answer.answers.is_empty());
            assert!(addresses.inner.lock().unwrap().by_host.is_empty());
            assert!(output.health().is_err());
            fcx.cancel();
            Ok(())
        },
    ))
    .unwrap();
    assert_eq!(
        log.health().unwrap_err().to_string(),
        "cannot record the address: injected address write failure"
    );
    assert!(log.finish().is_err());
    let lines: Vec<Value> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(lines.iter().any(|line| line["type"] == "refused"
        && line["host"] == "new.com"
        && line["why"] == "cannot record the address: injected address write failure"));
    assert!(lines.iter().all(|line| line["type"] != "site"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn names_that_could_be_on_the_internet_get_a_site() {
    for name in [
        "example.com",
        "www.example.com",
        "a-b.co.uk",
        "xn--bcher-kva.xn--p1ai",
        "x.io",
    ] {
        assert_eq!(admit(name), Ok(()), "{name}");
    }
    for (name, why) in [
        ("rw-desktop", "single label"),
        ("printer.local", "reserved or private top-level domain"),
        ("db.internal", "reserved or private top-level domain"),
        (
            "4.3.2.1.in-addr.arpa",
            "reserved or private top-level domain",
        ),
        ("foo.test", "reserved or private top-level domain"),
        ("1.2.3.4", "not a top-level domain"),
        ("_dmarc.example.com", "not a host name"),
        ("-bad.com", "not a host name"),
    ] {
        assert_eq!(admit(name), Err(why), "{name}");
    }
}

#[test]
fn the_world_starts_on_the_seeds_day() {
    let start = time::OffsetDateTime::from(world_start("2026-03-14").unwrap());
    assert_eq!(
        (start.year(), start.month() as u8, start.day()),
        (2026, 3, 14)
    );
    assert!(world_start("2026-02-30").is_err());
    assert!(world_start("2026-257-01").is_err());
    assert!(world_start("2026-01-257").is_err());
    assert!(
        world_start("14/03/2026")
            .unwrap_err()
            .to_string()
            .contains("not a YYYY-MM-DD date")
    );
}

#[test]
fn exhausted_pool_refuses_without_allocating_or_recording() {
    let a = Addresses::new(HashMap::new(), None).unwrap();
    {
        let mut inner = a.inner.lock().unwrap();
        for [first, second] in POOLS {
            for third in 0..=255 {
                for fourth in 1..=254 {
                    inner
                        .used
                        .insert(Ipv4Addr::new(first, second, third, fourth));
                }
            }
        }
    }
    assert_eq!(a.assign("full.com").unwrap(), None);
    assert!(a.inner.lock().unwrap().by_host.is_empty());
    let freed = Ipv4Addr::new(104, 21, 0, 1);
    a.inner.lock().unwrap().used.remove(&freed);
    assert_eq!(a.assign("last.com").unwrap(), Some((freed, "pool")));
    assert_eq!(a.assign("last.com").unwrap(), Some((freed, "pool")));
    assert_eq!(a.assign("full.com").unwrap(), None);
}

#[test]
fn pool_addresses_are_distinct_and_recorded() {
    let dir = std::env::temp_dir().join(format!("web-addr-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("addresses.jsonl");
    let _ = std::fs::remove_file(&file);
    let fixed = HashMap::from([(
        "www.google.com".to_owned(),
        (Ipv4Addr::new(142, 250, 180, 4), "search engine"),
    )]);
    let a = Addresses::new(fixed.clone(), Some(&dir)).unwrap();
    assert_eq!(
        a.assign("www.google.com").unwrap(),
        Some((Ipv4Addr::new(142, 250, 180, 4), "search engine"))
    );
    let mut seen = HashSet::new();
    for i in 0..2000 {
        let (addr, why) = a.assign(&format!("host{i}.com")).unwrap().unwrap();
        assert_eq!(why, "pool");
        assert!(seen.insert(addr), "{addr} given twice");
    }
    let first = a.assign("host0.com").unwrap().unwrap().0;
    drop(a);
    let again = Addresses::new(fixed, Some(&dir)).unwrap();
    assert_eq!(
        again.assign("host0.com").unwrap(),
        Some((first, "recorded"))
    );
    assert!(!seen.contains(&again.assign("new.com").unwrap().unwrap().0));
    let _ = std::fs::remove_dir_all(&dir);
}
